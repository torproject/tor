from __future__ import print_function

import sys
import subprocess
import socket
import os
import time
import random

def try_connecting_to_socksport():
    socks_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if socks_socket.connect_ex(('127.0.0.1', socks_port)):
        tor_process.terminate()
        print('FAIL')
        sys.exit('Cannot connect to SOCKSPort')
    socks_socket.close()

def wait_for_log(s):
    while True:
        l = tor_process.stdout.readline()
        if s in l:
            return

def pick_random_port():
    port = 0
    random.seed()

    for i in xrange(8):
        port = random.randint(10000, 60000)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if s.connect_ex(('127.0.0.1', port)) == 0:
            s.close()
        else:
            break

    return port

control_port = pick_random_port()
socks_port = pick_random_port()

assert control_port != 0
assert socks_port != 0

if not os.path.exists(sys.argv[1]):
    sys.exit('ERROR: cannot find tor at %s' % sys.argv[1])

tor_path = sys.argv[1]

tor_process = subprocess.Popen([tor_path,
                               '-ControlPort', '127.0.0.1:{}'.format(control_port),
                               '-SOCKSPort', '127.0.0.1:{}'.format(socks_port),
                               '-FetchServerDescriptors', '0'],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

if tor_process == None:
    sys.exit('ERROR: running tor failed')

if len(sys.argv) < 2:
     sys.exit('Usage: %s <path-to-tor>' % sys.argv[0])

wait_for_log('Opened Control listener on')

try_connecting_to_socksport()

control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if control_socket.connect_ex(('127.0.0.1', control_port)):
    tor_process.terminate()
    print('FAIL')
    sys.exit('Cannot connect to ControlPort')

control_socket.sendall('AUTHENTICATE \r\n')
control_socket.sendall('SETCONF SOCKSPort=0.0.0.0:{}\r\n'.format(socks_port))
wait_for_log('Opened Socks listener')

try_connecting_to_socksport()

control_socket.sendall('SETCONF SOCKSPort=127.0.0.1:{}\r\n'.format(socks_port))
wait_for_log('Opened Socks listener')

try_connecting_to_socksport()

control_socket.sendall('SIGNAL HALT\r\n')

time.sleep(0.1)
print('OK')
tor_process.terminate()
