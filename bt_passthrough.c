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

#include "hci.h"

#define BUFFER_SIZE             (65536)
#define PORT                    (6001)
#define SERVER_TEST_PORT        (6002)

#define DIE(cond, ...)          \
do { if (cond) {                \
  printf(__VA_ARGS__);          \
  exit(-1);                     \
  }                             \
} while (0);                    \

enum pollers_s {
  FD_BLUETOOTH,
  FD_NAMED_FIFO,
  FD_SERVER_LISTENING_SOCKET,
  NUM_FDS
} poller_t;

/* Poll HCI events flag */
static volatile int g_poll_hci_events = 1;

static int g_connection_id;

/* BT fifo name */
const char *fifo_name = "/tmp/bt_fifo";

static int open_hci_device(int device_id)
{
#ifndef TEST_PASSTHROUGH_INTERFACE
  int ret = 0, fd, opt = 1;
  struct sockaddr_hci local_bt;
  struct hci_filter flt;

  /* Create socket */
  ret = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
  DIE(ret < 0, "Cannot open BT socket %s\n", strerror(errno));

  hci_filter_clear(&flt);
  hci_filter_set_ptype(HCI_EVENT_PKT, &flt);
  hci_filter_set_ptype(HCI_VENDOR_PKT, &flt);
  hci_filter_set_ptype(HCI_ACLDATA_PKT, &flt);
  hci_filter_set_ptype(HCI_SCODATA_PKT, &flt);

  hci_filter_all_events(&flt);
  fd = ret;

  DIE(setsockopt(fd, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0, "Set HCI filter failed");
  DIE(setsockopt(fd, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0, "Set data dir failed");

  /* Bind socket to HCI device */
  memset(&local_bt, 0, sizeof(struct sockaddr_hci));
  local_bt.hci_family = AF_BLUETOOTH;
  local_bt.hci_dev    = device_id;
  local_bt.hci_channel = HCI_CHANNEL_RAW;

  ret = bind(ret, (struct sockaddr *)&local_bt, sizeof(struct sockaddr_hci));
  DIE(ret < 0, "Cannot bind BT socket %s\n", strerror(errno));
#else

  int ret = 0, fd;
  struct sockaddr_in test_server_address;

  fd = socket(AF_INET, SOCK_STREAM, 0);
  DIE(fd < 0, "Cannot open client socket %s\n", strerror(errno));

  test_server_address.sin_family = AF_INET;
  test_server_address.sin_port = htons(SERVER_TEST_PORT);
  test_server_address.sin_addr.s_addr = htonl(INADDR_ANY);

  ret = connect(fd, (struct sockaddr *)&test_server_address, sizeof(struct sockaddr));
  DIE(ret < 0, "Cannot connect to the test server %s\n", strerror(errno));
#endif
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

static const char *get_h4_type_name(h4_hci_type_t type)
{
  if (type == H4_HCI_TYPE_CMD)
    return "CMD";
  else if (type == H4_HCI_TYPE_ACL)
    return "ACL";
  else if (type == H4_HCI_TYPE_SCO)
    return "SCO";
  else if (type == H4_HCI_TYPE_EVT)
    return "EVT";
  else
    return "! INVALID H4 !";
}

static int write_hci_data_to_btcontroller(int fd, void *ptr, size_t write_len)
{
  h4_hci_pkt_t *pkt = (h4_hci_pkt_t *)ptr;
  size_t actual_write = 0;

  switch (pkt->h4_type) {
    case H4_HCI_TYPE_CMD:
      actual_write = pkt->pkt.cmd.param_len + sizeof(hci_cmd_packet_t);
      printf("[BtEmulator] Send %s (0x%02X|0x%04X) len:%d\n",
             get_h4_type_name(pkt->h4_type),
             pkt->pkt.cmd.op.opcode_t.ogf,
             pkt->pkt.cmd.op.opcode_t.ocf,
             pkt->pkt.cmd.param_len);
      break;

    case H4_HCI_TYPE_ACL:
      actual_write = pkt->pkt.acl.data_total_len + sizeof(hci_acl_packet_t);
      printf("[BtEmulator] Send %s Handle %d len:%d\n",
             get_h4_type_name(pkt->h4_type),
             pkt->pkt.acl.handle,
             pkt->pkt.acl.data_total_len);
      break;

    case H4_HCI_TYPE_SCO:
      actual_write = pkt->pkt.sco.data_total_len + sizeof(hci_sco_packet_t);
      printf("[BtEmulator] Send %s Handle %d len:%d\n",
             get_h4_type_name(pkt->h4_type),
             pkt->pkt.sco.conn_handle,
             pkt->pkt.sco.data_total_len);
      break;

    case H4_HCI_TYPE_EVT:
    default:
      DIE(1, "[BtEmulator] attempt to send H4 type %d\n", pkt->h4_type);
      break;
  }

  /* The header ;) */
  actual_write += sizeof(uint8_t);

  return write(fd, ptr, actual_write);
}

static int inject_hci_event_response(int fd, h4_hci_pkt_t *ptr, size_t write_len)
{
  if (ptr->h4_type == H4_HCI_TYPE_EVT &&
      ptr->pkt.evt.event_code == HCI_EVENT_COMMAND_COMPLETE) {

    hci_event_cmd_complete_t *evt_complete = (hci_event_cmd_complete_t *)(ptr->pkt.evt.params);
    printf("[BtController] Send %s type 0x%02X opcode: 0x%04X len %d\n", get_h4_type_name(ptr->h4_type),
           ptr->pkt.evt.event_code,
           evt_complete->opcode,
           ptr->pkt.evt.data_total_len);

    const char *injected_resp = HCI_GET_VENDOR_RESPONSE;
    if (evt_complete->opcode == HCI_GET_VENDOR_CAPABILITIES_OPCODE) {
      printf("\n\n ************\n");
      printf("[BtController] Injected response to opcode: 0x%04x with disabled filtering support\n", evt_complete->opcode);
      printf("\n\n ************\n");
      return write(fd, injected_resp, write_len);
    }

    return write(fd, ptr, write_len);
  }

  printf("[BtController] Send %s type 0x%02X len %d\n", get_h4_type_name(ptr->h4_type),
         ptr->pkt.evt.event_code,
         ptr->pkt.evt.data_total_len);

  return write(fd, ptr, write_len);
}

static int write_hci_data_to_btemulator(int fd, void *ptr, size_t write_len)
{
  h4_hci_pkt_t *pkt = (h4_hci_pkt_t *)ptr;
  uint16_t actual_write = 0;

  switch (pkt->h4_type) {
    case H4_HCI_TYPE_ACL:
      actual_write = pkt->pkt.acl.data_total_len + sizeof(hci_acl_packet_t);
      printf("[BtController] Send %s Handle %d len:%d\n",
             get_h4_type_name(pkt->h4_type),
             pkt->pkt.acl.handle,
             pkt->pkt.acl.data_total_len);
      break;

    case H4_HCI_TYPE_SCO:
      actual_write = pkt->pkt.sco.data_total_len + sizeof(hci_sco_packet_t);
      printf("[BtController] Send %s Handle %d len:%d\n",
             get_h4_type_name(pkt->h4_type),
             pkt->pkt.sco.conn_handle,
             pkt->pkt.sco.data_total_len);
      break;

    case H4_HCI_TYPE_EVT:
      actual_write = pkt->pkt.evt.data_total_len + sizeof(hci_event_packet_t);
      break;

    default:
      DIE(1, "[BtController] attempt to send H4 type %d\n", pkt->h4_type)
      break;
  }

  /* Offset with the H4 header */
  actual_write += sizeof(uint8_t);

  /* Write the size of the packet first */
  int ret = write(fd, &actual_write, sizeof(uint16_t));
  if (ret < 0) {
    printf("[BtController] Cannot write header errno: %d\n", -errno);
    return 0;
  }

  return inject_hci_event_response(fd, pkt, actual_write);
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

  client_addr_len = sizeof(socklen_t);

  if (argc != 3) {
    show_help();
  }

  /* Initialize the entire structure with -1. Negative fd's are ignored */
  memset(pollers, -1, sizeof(pollers));

  /* argv[1] contains the HCI device id */
  device_id = atoi(argv[1]);
  if (!strcmp(argv[2], "pipe")) {
    is_pipe_used   = 1;
  } else if (!strcmp(argv[2], "socket")) {
    is_server_used = 1;
  } else {
    printf("Unknown option:%s possible options {pipe|socket}\n", argv[2]);
    show_help();
  }

  skt_fd = open_hci_device(device_id);
  pollers[FD_BLUETOOTH].fd     = skt_fd;
  pollers[FD_BLUETOOTH].events = POLLIN | POLLHUP;
  pollers[FD_BLUETOOTH].revents = 0;

  if (is_pipe_used)
    fifo_fd = open_named_fifo();

  pollers[FD_NAMED_FIFO].fd     = fifo_fd;
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
//          printf("Writing data from FIFO enabled\n");

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

            ret = write_hci_data_to_btemulator(pollers[i].fd, ptr, available_for_write);
            if (ret >= 0) {
//              printf("Wrote %d bytes from HCI socket to FIFO\n", ret);

              tx_already_sent_len = (tx_already_sent_len + ret) % BUFFER_SIZE;
            } else {
//              printf("Error write from FIFO %s\n", strerror(errno));
            }
          }
        }

        if (i == FD_BLUETOOTH) {
//          printf("Writing data from FIFO to HCI\n");

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
//            printf("No data to write we disable POLLOUT on HCI socket\n");
            pollers[FD_BLUETOOTH].events &= ~POLLOUT;
          } else {
            uint8_t *ptr = rx_buffer + (rx_already_sent_len % BUFFER_SIZE);

            ret = write_hci_data_to_btcontroller(pollers[i].fd,
                                                 ptr,
                                                 available_for_write);
            if (ret >= 0) {
//              printf("Wrote %d bytes from FIFO to HCI scoket\n", ret);

//              for (int j = 0; j < ret; j++) {
//                printf("%02x, ", ptr[j]);
//              }
//              printf("\n");
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
//          printf("Waiting data in FIFO detected\n");

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
//            printf("Wait for HCI socket to consume FIFO data\n");
            pollers[FD_BLUETOOTH].events |= POLLOUT;
          } else {
            uint8_t *ptr = rx_buffer + (rx_waiting_to_send_len % BUFFER_SIZE);
            ret = read(pollers[i].fd, ptr, available_space);
            if (ret >= 0) {
//              printf("Received %d bytes from FIFO endpoint\n", ret);
              if (ret == 0 && is_server_used) {
                pollers[FD_BLUETOOTH].events &= ~POLLOUT;
                close(pollers[i].fd);
                printf("Connection reset bt peer - flush data\n");
                tx_waiting_to_send_len = 0; tx_already_sent_len = 0;
                rx_waiting_to_send_len = 0; rx_already_sent_len = 0;
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
//          printf("Waiting data in HCI socket detected\n");

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
//            printf("Wait for HCI socket to consume FIFO data\n");
          } else {
            uint8_t *ptr = tx_buffer + (tx_waiting_to_send_len % BUFFER_SIZE);

            ret = read(pollers[i].fd, ptr, available_space);
            if (ret >= 0) {
//              printf("Received %d bytes from HCI socket\n", ret);

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
//        printf("Received event on server socket\n");
        ret = accept(pollers[FD_SERVER_LISTENING_SOCKET].fd,
                     (struct sockaddr *)&client_addr,
                     &client_addr_len);
        if (ret < 0) {
          printf("Failed to accept incomming connection: %s\n", strerror(errno));
          continue;
        }

        printf("[%d] Established connection with client\n", g_connection_id++);
        tx_waiting_to_send_len = 0; tx_already_sent_len = 0;
        rx_waiting_to_send_len = 0; rx_already_sent_len = 0;
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
