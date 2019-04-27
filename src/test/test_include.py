from __future__ import print_function

import errno
import logging
import os
import random
import socket
import subprocess
import sys
import time
import re

CONTROL_SOCK_TIMEOUT = 10.0
LOG_TIMEOUT = 60.0
LOG_WAIT = 0.1

def fail(msg):
    logging.error('FAIL')
    sys.exit(msg)

def wait_for_log(s):
    cutoff = time.time() + LOG_TIMEOUT
    while time.time() < cutoff:
        l = tor_process.stdout.readline()
        l = l.decode('utf8')
        if s in l:
            logging.info('Tor logged: "{}"'.format(l.strip()))
            return
        logging.info('Tor logged: "{}", waiting for "{}"'.format(l.strip(), s))
        # readline() returns a blank string when there is no output
        # avoid busy-waiting
        if len(s) == 0:
            time.sleep(LOG_WAIT)
    fail('Could not find "{}" in logs after {} seconds'.format(s, LOG_TIMEOUT))

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

def check_control_list(control_out_file, expected, value_name):
    received_count = 0
    for e in expected:
        received = control_out_file.readline().strip()
        received_count += 1
        parts = re.split('[ =-]', received.strip())
        if len(parts) != 3 or parts[0] != '250' or parts[1] != value_name or parts[2] != e:
            fail('Unexpected value in response line "{}". Expected {} for value {}'.format(received, e, value_name))
        if received.startswith('250 '):
            break

    if received_count != len(expected):
        fail('Expected response with {} lines but received {} lines'.format(len(expected), received_count))


logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s.%(msecs)03d %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

if sys.hexversion < 0x02070000:
    fail("ERROR: unsupported Python version (should be >= 2.7)")

if sys.hexversion > 0x03000000 and sys.hexversion < 0x03010000:
    fail("ERROR: unsupported Python3 version (should be >= 3.1)")

control_port = pick_random_port()

assert control_port != 0

if len(sys.argv) < 4:
     fail('Usage: %s <path-to-tor> <data-dir> <torrc>' % sys.argv[0])

if not os.path.exists(sys.argv[1]):
    fail('ERROR: cannot find tor at %s' % sys.argv[1])
if not os.path.exists(sys.argv[2]):
    fail('ERROR: cannot find datadir at %s' % sys.argv[2])
if not os.path.exists(sys.argv[3]):
    fail('ERROR: cannot find torrcdir at %s' % sys.argv[3])

tor_path = sys.argv[1]
data_dir = sys.argv[2]
torrc_dir = sys.argv[3]
torrc = os.path.join(torrc_dir, 'torrc')

tor_process = subprocess.Popen([tor_path,
                               '-DataDirectory', data_dir,
                               '-ControlPort', '127.0.0.1:{}'.format(control_port),
                               '-Log', 'info stdout',
                               '-LogTimeGranularity', '1',
                               '-FetchServerDescriptors', '0',
                               '-DisableNetwork', '1',
                               '-f', torrc],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

if tor_process == None:
    fail('ERROR: running tor failed')

wait_for_log('Opened Control listener on')

control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if control_socket.connect_ex(('127.0.0.1', control_port)):
    tor_process.terminate()
    fail('Cannot connect to ControlPort')
control_socket.settimeout(CONTROL_SOCK_TIMEOUT)
control_out_file = control_socket.makefile('r')

control_socket.sendall('AUTHENTICATE \r\n'.encode('utf8'))
res = control_out_file.readline().strip()
if res != '250 OK':
    tor_process.terminate()
    fail('Cannot authenticate. Response was: {}'.format(res))

# test configuration file values and order
control_socket.sendall('GETCONF RecommendedVersions\r\n'.encode('utf8'))
check_control_list(control_out_file, ['1', '2', '3', '4', '5', '6', '4' , '5'], 'RecommendedVersions')

# test reloading the configuration file with seccomp sandbox enabled
foo_path = os.path.join(torrc_dir, 'torrc.d', 'foo')
with open(foo_path, 'a') as foo:
    foo.write('RecommendedVersions 7')

control_socket.sendall('SIGNAL RELOAD\r\n'.encode('utf8'))
wait_for_log('Reloading config and resetting internal state.')
res = control_out_file.readline().strip()
if res != '250 OK':
    tor_process.terminate()
    fail('Cannot reload configuration. Response was: {}'.format(res))


control_socket.sendall('GETCONF RecommendedVersions\r\n'.encode('utf8'))
check_control_list(control_out_file, ['1', '2', '3', '4', '5', '6', '7', '4' , '5'], 'RecommendedVersions')

# test that config-can-saveconf is 0 because we have a %include
control_socket.sendall('getinfo config-can-saveconf\r\n'.encode('utf8'))
res = control_out_file.readline().strip()
if res != '250-config-can-saveconf=0':
    tor_process.terminate()
    fail('getinfo config-can-saveconf returned wrong response: {}'.format(res))
else:
    res = control_out_file.readline().strip()
    if res != '250 OK':
        tor_process.terminate()
        fail('getinfo failed. Response was: {}'.format(res))

# test that saveconf returns error because we have a %include
control_socket.sendall('SAVECONF\r\n'.encode('utf8'))
res = control_out_file.readline().strip()
if res != '551 Unable to write configuration to disk.':
    tor_process.terminate()
    fail('SAVECONF returned wrong response. Response was: {}'.format(res))

control_socket.sendall('SIGNAL HALT\r\n'.encode('utf8'))

wait_for_log('exiting cleanly')
logging.info('OK')

try:
    tor_process.terminate()
except OSError as e:
    if e.errno == errno.ESRCH: # errno 3: No such process
        # assume tor has already exited due to SIGNAL HALT
        logging.warn("Tor has already exited")
    else:
        raise
