from __future__ import print_function

import binascii
import os
import platform
import random
import socket
import subprocess
import sys
import threading

def fail(msg):
    print('FAIL')
    sys.exit(msg)

def pick_random_port():
    port = 0
    random.seed()

    for i in range(8):
        port = random.randint(10000, 60000)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex(('127.0.0.1', port)) == 0:
            s.close()
        else:
            break

    if port == 0:
        fail('Could not find a random free port between 10000 and 60000')

    return port

def hexstr_to_bin(hexstr):
    return binascii.unhexlify(''.join(hexstr.split()))

def recv_n(s, n):
    data = bytes()
    n_read = 0

    while n_read < n:
        chunk = s.recv(n - n_read)
        if chunk == '':
            s.close()
            raise RuntimeError("Cannot read from socket")

        data += chunk
        n_read += len(chunk)

    return data

def mock_server(expect_send1, recv1, expect_send2, recv2):
    expect_send1_bin = hexstr_to_bin(expect_send1)
    recv1_bin = hexstr_to_bin(recv1)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", socks_port))
    s.listen(5)

    (clientsocket, addr) = s.accept()

    assert recv_n(clientsocket, len(expect_send1_bin)) == expect_send1_bin

    clientsocket.sendall(recv1_bin)

    if expect_send2 != None and recv2 != None:
        expect_send2_bin = hexstr_to_bin(expect_send2)
        recv2_bin = hexstr_to_bin(recv2)

        assert recv_n(clientsocket, len(expect_send2_bin)) == expect_send2_bin

        clientsocket.sendall(recv2_bin)

    s.close()
    clientsocket.close()

class Testcase:
    def __init__(self, arguments, expect_send1,
            recv1, expect_final_stdout, expect_send2=None, recv2=None):
        self.arguments = arguments
        self.expect_send1 = expect_send1
        self.recv1 = recv1
        self.expect_send2 = expect_send2
        self.recv2 = recv2
        self.expect_final_stdout = expect_final_stdout

    def run(self):
        t = threading.Thread(target=mock_server, args=(self.expect_send1,
            self.recv1, self.expect_send2, self.recv2))

        t.daemon = True
        t.start()

        child_process = subprocess.Popen([tor_resolve_path] + self.arguments,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE)

        l = child_process.stdout.readline().decode('utf8')

        assert l == self.expect_final_stdout

if sys.hexversion < 0x02070000:
    fail("ERROR: unsupported Python version (should be >= 2.7)")

if sys.hexversion > 0x03000000 and sys.hexversion < 0x03010000:
    fail("ERROR: unsupported Python3 version (should be >= 3.1)")

tor_resolve_path = sys.argv[1]

socks_port = pick_random_port()

testcases = [
              Testcase(arguments=['-5', 'mit.edu', '127.0.0.1:'+str(socks_port)],
                        expect_send1 = '05 01 00 \n',
                        recv1 = '05 00\n',
                        expect_send2 = '05 f0 00 03 07 6d 69 74 2e 65 64 75 00 00 \n',
                        recv2 = '05 00 00 04 2a 02 26 f0 00 10 02 95 00 00 00 00 00 00 25 5e 00 00 \n',
                        expect_final_stdout = '2a02:26f0:10:295::255e\n'),
              Testcase(arguments=['-5', '-x', '8.8.8.8',
                  '127.0.0.1:'+str(socks_port)],
                        expect_send1 = '05 01 00 \n',
                        recv1 = '05 00\n',
                        expect_send2 = '05 f1 00 01 08 08 08 08 00 00 \n',
                        recv2 = '05 00 00 03 1e 67 6f 6f 67 6c 65 2d 70 75 62 6c 69 63 2d 64 6e 73 2d 61 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 00 00 \n',
                        expect_final_stdout = 'google-public-dns-a.google.com\n'),
              Testcase(arguments = ['-4', 'mit.edu',
                  '127.0.0.1:'+str(socks_port)],
                        expect_send1 = '04 f0 00 00 00 00 00 01 00 6d 69 74 2e 65 64 75 00 \n',
                        recv1 = '00 5a 00 00 17 42 10 80 \n',
                        expect_final_stdout = '23.66.16.128\n'),
              Testcase(arguments = ['-4', 'torproject.org',
                  '127.0.0.1:'+str(socks_port)],
                        expect_send1 = '04 f0 00 00 00 00 00 01 00 74 6f 72 70 72 6f 6a 65 63 74 2e 6f 72 67 00 \n',
                        recv1 = '00 5a 00 00 8a c9 0e c5 \n',
                        expect_final_stdout = '138.201.14.197\n'),
              ]

for t in testcases:
    t.run()
    print('.')

print('OK')

