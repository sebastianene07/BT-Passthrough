#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <errno.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>
#include <sys/uio.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>

#define BUFFER_SIZE							(4096)
#define PORT										(6001)

#define DIE(cond, ...)					\
do { if (cond) {								\
	printf(__VA_ARGS__);					\
	exit(-1);											\
	}															\
} while (0);										\

enum pollers_s {
	FD_BLUETOOTH,
	FD_NAMED_FIFO,
	FD_SERVER_LISTENING_SOCKET,
	NUM_FDS
} poller_t;

/* Poll HCI events flag */
static volatile int g_poll_hci_events = 1;

/* BT fifo name */
const char *fifo_name = "/tmp/bt_fifo";

static int open_hci_device(int device_id)
{
	int ret = 0, fd;
	struct sockaddr_hci local_bt;
	struct hci_filter flt;

	/* Create socket */
	ret = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	DIE(ret < 0, "Cannot open BT socket %s\n", strerror(errno));

	hci_filter_clear(&flt);
	hci_filter_all_ptypes(&flt);
	hci_filter_all_events(&flt);
	fd = ret;

	DIE(setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0, "Set HCI filter failed");
//	DIE(setsockopt(fd, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0, "Set data dir failed");

	/* Bind socket to HCI device */
	memset(&local_bt, 0, sizeof(struct sockaddr_hci));
	local_bt.hci_family = AF_BLUETOOTH;
	local_bt.hci_dev    = device_id;
	local_bt.hci_channel = HCI_CHANNEL_RAW;

	ret = bind(ret, (struct sockaddr *)&local_bt, sizeof(struct sockaddr_hci));
	DIE(ret < 0, "Cannot bind BT socket %s\n", strerror(errno));

	return fd;
}

static int open_named_fifo(void)
{
	int ret = 0;

	unlink(fifo_name);

	ret = mkfifo(fifo_name, 0666);
	DIE(ret < 0, "Cannot create FIFO %s\n", strerror(errno));

	ret = open(fifo_name, O_RDWR);
	DIE(ret < 0, "Cannot open FIFO %s\n", strerror(errno));

	return ret;
}

static int open_server_socket(void)
{
	int ret = 0, server_listen_fd;
	struct sockaddr_in server_addr;

	ret = socket(AF_INET, SOCK_STREAM, 0);
	DIE(ret < 0, "Cannot open server socket %s\n", strerror(errno));

	server_listen_fd = ret;
	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(PORT);

	int reuse = 1;

	if (setsockopt(server_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
		perror("setsockopt(SO_REUSEADDR) failed");

	/* Bind the socket to the IP address */
	ret = bind(server_listen_fd, (struct sockaddr *)&server_addr,
		sizeof(server_addr));
	DIE(ret < 0, "Cannot bind server socket %s\n", strerror(errno));

	/* Enter in the listening state */
	ret = listen(server_listen_fd, 1);
	DIE(ret < 0, "Failed to listen on the server socket %s\n", strerror(errno));

	printf("Server listening on port %u\n", PORT);

	return server_listen_fd;
}

static void sig_handler(int signo)
{
	if (signo == SIGINT) {
		g_poll_hci_events = 0;

		printf("Shutdown requested\n");
	}
}

static void show_help(void)
{
	printf("bt_passthrough <hci_device_id> <passthrough_interface>\n\n"
				 "Mandatory args:\n"
				 "hci_device_id - Integer number that specifies the id of the HCI dev\n"
				 "passthrough_interface - the interface that we expose the BT chip to\n"
				 "                        exterior. {pipe|socket}\n");
	exit(-1);
}

int main(int argc, char **argv)
{
	int ret = 0, skt_fd = -1, fifo_fd = -1, device_id = -1;
	int server_listen_fd = -1, server_data_fd = -1;
	struct pollfd pollers[NUM_FDS];
	size_t tx_waiting_to_send_len = 0, tx_already_sent_len = 0;
	size_t rx_waiting_to_send_len = 0, rx_already_sent_len = 0;
	uint8_t is_pipe_used = 0, is_server_used = 0;
	socklen_t client_addr_len;
	struct sockaddr_in client_addr;

 	if (argc != 3) {
		show_help();
	}

	/* Initialize the entire structure with -1. Negative fd's are ignored */
	memset(pollers, -1, sizeof(pollers));

	/* argv[1] contains the HCI device id */
	device_id = atoi(argv[1]);
	if (!strcmp(argv[2], "pipe")) {
		is_pipe_used 	 = 1;
	} else if (!strcmp(argv[2], "socket")) {
		is_server_used = 1;
	} else {
		printf("Unknown option:%s possible options {pipe|socket}\n", argv[2]);
		show_help();
	}

	skt_fd = open_hci_device(device_id);
	pollers[FD_BLUETOOTH].fd 		 = skt_fd;
	pollers[FD_BLUETOOTH].events = POLLIN | POLLHUP;
	pollers[FD_BLUETOOTH].revents = 0;

	if (is_pipe_used)
		fifo_fd = open_named_fifo();

	pollers[FD_NAMED_FIFO].fd 		= fifo_fd;
	pollers[FD_NAMED_FIFO].events = POLLIN | POLLHUP;
	pollers[FD_NAMED_FIFO].revents = 0;

	if (is_server_used)
		server_listen_fd = open_server_socket();

	pollers[FD_SERVER_LISTENING_SOCKET].fd = server_listen_fd;
	pollers[FD_SERVER_LISTENING_SOCKET].events = POLLIN | POLLHUP;
	pollers[FD_SERVER_LISTENING_SOCKET].revents = 0;

	DIE(signal(SIGINT, sig_handler), "Cannot register SIGINT handler\n");

	uint8_t *tx_buffer = malloc(BUFFER_SIZE);
	DIE(tx_buffer == NULL, "Failed to allocate TX buffer\n");

	uint8_t *rx_buffer = malloc(BUFFER_SIZE);
	DIE(rx_buffer == NULL, "Failed to allocate RX buffer\n");

	while (g_poll_hci_events) {

		ret = poll(pollers, NUM_FDS, -1);
		if (ret < 0) continue;

		for (int i = 0; i < NUM_FDS; i++) {
			if (pollers[i].revents & POLLOUT) {

				if (i == FD_NAMED_FIFO) {
					printf("Writing data from FIFO enabled\n");

					int available_for_write = 0;

					if (tx_waiting_to_send_len >= tx_already_sent_len) {
						available_for_write = tx_waiting_to_send_len - tx_already_sent_len;
					} else {
						available_for_write = BUFFER_SIZE - (tx_already_sent_len -
							tx_waiting_to_send_len);
					}

					if (available_for_write <= 0) {
						/* We have no data to write, let's disable POLLOUT events for the
             * moment.
						 */

						pollers[FD_NAMED_FIFO].events &= ~POLLOUT;
					} else {
						uint8_t *ptr = tx_buffer + (tx_already_sent_len % BUFFER_SIZE);

						ret = write(pollers[i].fd, ptr, available_for_write);
						if (ret >= 0) {
							printf("Wrote %d bytes from HCI socket to FIFO\n", ret);

							tx_already_sent_len = (tx_already_sent_len + ret) % BUFFER_SIZE;
						} else {
							printf("Error write from FIFO %s\n", strerror(errno));
						}
					}
				}

				if (i == FD_BLUETOOTH) {
					printf("Writing data from FIFO to HCI\n");

					int available_for_write = 0;

					if (rx_waiting_to_send_len >= rx_already_sent_len) {
						available_for_write = rx_waiting_to_send_len - rx_already_sent_len;
					} else {
						available_for_write = BUFFER_SIZE - (rx_already_sent_len -
							rx_waiting_to_send_len);
					}

					if (available_for_write <= 0) {
						/* We have no data to write, let's disable POLLOUT events for the
             * moment.
						 */
						printf("No data to write we disable POLLOUT on HCI socket\n");
						pollers[FD_BLUETOOTH].events &= ~POLLOUT;
					} else {
						uint8_t *ptr = rx_buffer + (rx_already_sent_len % BUFFER_SIZE);

						ret = write(pollers[i].fd, ptr, available_for_write);
						if (ret >= 0) {
							printf("Wrote %d bytes from FIFO to HCI scoket\n", ret);

							for (int j = 0; j < ret; j++) {
								printf("%02x, ", ptr[j]);
							}
							printf("\n");
							rx_already_sent_len = (rx_already_sent_len + ret) % BUFFER_SIZE;
						} else {
							printf("Error write from FIFO %s\n", strerror(errno));
						}
					}
				}
			}

			if (pollers[i].revents & POLLIN) {

				/* We have waiting data in FIFO that needs to be sent on the socket */
				if (i == FD_NAMED_FIFO) {
					printf("Waiting data in FIFO detected\n");

					/* Check if we have space in the circular buffer */

					int available_space = 0;

					if (rx_waiting_to_send_len >= rx_already_sent_len) {
						available_space = BUFFER_SIZE - (rx_waiting_to_send_len -
							rx_already_sent_len) - 1;
					} else if (rx_waiting_to_send_len < rx_already_sent_len) {
						available_space = rx_already_sent_len - rx_waiting_to_send_len - 1;
					}

					if (available_space <= 0) {
						/* We don't have space to pull the data out from the FIFO and we
  					 * wait for the HCI socket to consume it.
						 */
						printf("Wait for HCI socket to consume FIFO data\n");
						pollers[FD_BLUETOOTH].events |= POLLOUT;
					} else {
						uint8_t *ptr = rx_buffer + (rx_waiting_to_send_len % BUFFER_SIZE);
						ret = read(pollers[i].fd, ptr, available_space);
						if (ret >= 0) {
							printf("Received %d bytes from FIFO endpoint\n", ret);
							if (ret == 0 && is_server_used) {
								pollers[FD_BLUETOOTH].events &= ~POLLOUT;
								close(pollers[i].fd);
								pollers[i].fd = -1;
							} else {
								pollers[FD_BLUETOOTH].events |= POLLOUT;
							}

							rx_waiting_to_send_len =
								(rx_waiting_to_send_len + ret) % BUFFER_SIZE;

						} else {
							printf("Error read from FIFO %s\n", strerror(errno));
						}
					}
				}

				/* We have waiting data that needs to be sent from HCI to the pipe */
				if (i == FD_BLUETOOTH) {
					printf("Waiting data in HCI socket detected\n");

					/* Check if we have space in the circular buffer */

					int available_space = 0;

					if (tx_waiting_to_send_len >= tx_already_sent_len) {
						available_space = BUFFER_SIZE - (tx_waiting_to_send_len -
							tx_already_sent_len) - 1;
					} else if (tx_waiting_to_send_len < tx_already_sent_len) {
						available_space = tx_already_sent_len - tx_waiting_to_send_len - 1;
					}

					if (available_space <= 0) {
						/* We don't have space to pull the data out from the FIFO and we
  					 * wait for the HCI socket to consume it.
						 */
						printf("Wait for HCI socket to consume FIFO data\n");
					} else {
						uint8_t *ptr = tx_buffer + (tx_waiting_to_send_len % BUFFER_SIZE);

						ret = read(pollers[i].fd, ptr, available_space);
						if (ret >= 0) {
							printf("Received %d bytes from HCI socket\n", ret);

							tx_waiting_to_send_len =
								(tx_waiting_to_send_len + ret) % BUFFER_SIZE;

						} else {
							printf("Error read from HCI socket %s\n", strerror(errno));
						}
					}

					/* Enable writing to FIFO */
					pollers[FD_NAMED_FIFO].events |= POLLOUT;
				}
			}

			if (i == FD_SERVER_LISTENING_SOCKET && (pollers[i].revents & POLLIN)) {
				printf("Received event on server socket\n");
				ret = accept(pollers[FD_SERVER_LISTENING_SOCKET].fd,
										 (struct sockaddr *)&client_addr,
										 &client_addr_len);
				if (ret < 0) {
					printf("Failed to accept incomming connection\n");
					continue;
				}

				printf("Established connection with client\n");
				server_data_fd = ret;
#if 0
				/* Make socker non blocking */
				int saved_flags = fcntl(server_data_fd, F_GETFL);
				fcntl(server_data_fd, F_SETFL, saved_flags | O_NONBLOCK);
#endif

				/* We use the connection fd for IN/OUT data */
				pollers[FD_NAMED_FIFO].fd = server_data_fd;
			}

			if (pollers[i].revents & POLLHUP) {
				printf("Hangup requested\n");
			}
		}
	}

	close(skt_fd);
	close(fifo_fd);
	close(server_listen_fd);

	free(tx_buffer);
	free(rx_buffer);

	ret = unlink(fifo_name);
	printf("Cleanup finished status:%d\n", ret);

	return 0;
}
