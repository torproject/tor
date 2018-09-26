from __future__ import print_function

import sys
import subprocess
import os
import platform

class Testcase:
    def __init__(self, arguments, expect_connect_msg, expect_send1,
            recv1, expect_final_stdout, expect_send2=None, recv2=None):
        self.arguments = arguments
        self.expect_connect_msg = expect_connect_msg
        self.expect_send1 = expect_send1
        self.recv1 = recv1
        self.expect_send2 = expect_send2
        self.recv2 = recv2
        self.expect_final_stdout = expect_final_stdout

    def run(self):
        child_process = subprocess.Popen([tor_resolve_path] + self.arguments,
                                          env=test_env,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          stdin=subprocess.PIPE)

        l = child_process.stderr.readline().decode('utf8')
        assert l == self.expect_connect_msg

        l = child_process.stderr.readline().decode('utf8')

        assert l == self.expect_send1

        child_process.stdin.write(self.recv1.encode())
        child_process.stdin.flush()

        if self.expect_send2 != None and self.recv2 != None:
            l = child_process.stderr.readline().decode('utf8')
            assert l == self.expect_send2
            child_process.stdin.write(self.recv2.encode())
            child_process.stdin.flush()

        l = child_process.stdout.readline().decode('utf8')

        assert l == self.expect_final_stdout

if sys.hexversion < 0x02070000:
    sys.exit("ERROR: unsupported Python version (should be >= 2.7)")

if sys.hexversion > 0x03000000 and sys.hexversion < 0x03010000:
    sys.exit("ERROR: unsupported Python3 version (should be >= 3.1)")

libfakesocket_path = sys.argv[1]
tor_resolve_path = sys.argv[2]

test_env = os.environ.copy()

if platform.system() == 'Darwin':
    test_env["DYLD_INSERT_LIBRARIES"] = libfakesocket_path
    test_env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
else:
    test_env["LD_PRELOAD"] = libfakesocket_path

testcases = [
              Testcase(arguments=['-5', 'mit.edu'],
                        expect_connect_msg = 'connect() 127.0.0.1\n',
                        expect_send1 = '05 01 00 \n',
                        recv1 = '05 00\n',
                        expect_send2 = '05 f0 00 03 07 6d 69 74 2e 65 64 75 00 00 \n',
                        recv2 = '05 00 00 04 2a 02 26 f0 00 10 02 95 00 00 00 00 00 00 25 5e 00 00 \n',
                        expect_final_stdout = '2a02:26f0:10:295::255e\n'),
              Testcase(arguments=['-5', '-x', '8.8.8.8'],
                        expect_connect_msg = 'connect() 127.0.0.1\n',
                        expect_send1 = '05 01 00 \n',
                        recv1 = '05 00\n',
                        expect_send2 = '05 f1 00 01 08 08 08 08 00 00 \n',
                        recv2 = '05 00 00 03 1e 67 6f 6f 67 6c 65 2d 70 75 62 6c 69 63 2d 64 6e 73 2d 61 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 00 00 \n',
                        expect_final_stdout = 'google-public-dns-a.google.com\n'),
              Testcase(arguments = ['-4', 'mit.edu'],
                        expect_connect_msg = 'connect() 127.0.0.1\n',
                        expect_send1 = '04 f0 00 00 00 00 00 01 00 6d 69 74 2e 65 64 75 00 \n',
                        recv1 = '00 5a 00 00 17 42 10 80 \n',
                        expect_final_stdout = '23.66.16.128\n'),
              Testcase(arguments = ['-4', 'torproject.org'],
                        expect_connect_msg = 'connect() 127.0.0.1\n',
                        expect_send1 = '04 f0 00 00 00 00 00 01 00 74 6f 72 70 72 6f 6a 65 63 74 2e 6f 72 67 00 \n',
                        recv1 = '00 5a 00 00 8a c9 0e c5 \n',
                        expect_final_stdout = '138.201.14.197\n'),
              ]

for t in testcases:
    t.run()
    print('.')

