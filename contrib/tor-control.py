#!/usr/bin/python2
#$Id$

import socket
import struct
import sys

MSG_TYPE_SETCONF = 0x0002
MSG_TYPE_GETCONF = 0x0003
MSG_TYPE_AUTH    = 0x0007

def parseHostAndPort(h):
    host, port = "localhost", 9051
    if ":" in h:
        i = h.index(":")
        host = h[:i]
        try:
            port = int(h[i+1:])
        except ValueError:
            print "Bad hostname %r"%h
            sys.exit(1)
    elif h:
        try:
            port = int(h)
        except ValueError:
            host = h

    return host, port

def receive_message(s):
  body = ""
  header = s.recv(4)
  length,type = struct.unpack("!HH",header)
  print "Got response length %d, type %d"%(length,type)
  if length:
    body = s.recv(length)
  print "Got response length %d, type %d, body %s"%(length,type,body)
  return length,type,body

def pack_message(type, body=""):
  length = len(body)
  reqheader = struct.pack("!HH", length, type)
  return "%s%s"%(reqheader,body)

def authenticate(s):
  s.sendall(pack_message(MSG_TYPE_AUTH))
  length,type,body = receive_message(s)
  return

def get_option(s,name):
  s.sendall(pack_message(MSG_TYPE_GETCONF,name))
  length,type,body = receive_message(s)
  return

def set_option(s,msg):
  s.sendall(pack_message(MSG_TYPE_SETCONF,msg))
  length,type,body = receive_message(s)
  return

def do_main_loop(host,port):
  print "host is %s:%d"%(host,port)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((host,port))
  authenticate(s)
  get_option(s,"nickname")
  set_option(s,"runasdaemon 1")
#  get_option(s,"DirFetchPostPeriod\n")

  return

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print "Syntax: tor-control.py torhost:torport"
    sys.exit(0)
  sh,sp = parseHostAndPort(sys.argv[1])
  do_main_loop(sh,sp)

