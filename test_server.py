import socket
import sys
import threading
import time
import numpy as np
import random

class TestBtPassthrough:
    hci_event_test_data=b""
    hci_command_test_data=b""
    notify_receive_controller_sem=""
    notify_receive_emulator_sem=""

    def __init__(self):
        print "Run test"
        self.notify_receive_controller_sem = threading.Semaphore(0)
        self.notify_receive_emulator_sem   = threading.Semaphore(0)

    # THE SERVER SIMULATES THE CONTROLLER
    def test_server(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 6002)
        print >>sys.stderr, 'starting up on %s port %s' % server_address
        sock.bind(server_address)

        sock.listen(1)

        print >>sys.stderr, 'waiting for a connection'
        connection, client_address = sock.accept()

        while True:
            self.hci_event_test_data = np.random.bytes(random.randint(4, 256))
            connection.sendall(self.hci_event_test_data)
#            print >>sys.stderr, '[BTController] data: "%s"' % self.hci_event_test_data
            # wait to verify if data is good before sending something else
            self.notify_receive_emulator_sem.acquire()

            data = connection.recv(4096)
            if data != self.hci_command_test_data:
                print >>sys.stderr, '[BTController] data differs "%s"' % self.hci_command_test_data
                sys.exit()

            self.notify_receive_controller_sem.release()

    # The CLIENT SIMULATES THE EMULATOR
    def test_client(self):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 6001)
        print >>sys.stderr, 'connecting to %s port %s' % server_address
        sock.connect(server_address)

        while True :
            # The receiving side of this endpoint is what we get from the simulated
            # BT controller which is the test_server

            data = sock.recv(4096)
            if data != self.hci_event_test_data:
                print >>sys.stderr, '[BTEmulator] data differs "%s"' % self.hci_event_test_data
                sys.exit()

            self.notify_receive_emulator_sem.release()

            # Emulator simulates sending something

            self.hci_command_test_data=np.random.bytes(random.randint(4, 256))
            sock.sendall(self.hci_command_test_data)

            self.notify_receive_controller_sem.acquire()

x = TestBtPassthrough()
controller_thread = threading.Thread(target = x.test_server)
controller_thread.start()

print "Start the bt_passthrough tool"
time.sleep(5)
aosp_emulator_thread = threading.Thread(target = x.test_client)
aosp_emulator_thread.start()

controller_thread.join()
aosp_emulator_thread.join()
