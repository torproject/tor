#!/usr/bin/python2
#$Id$

import socket
import struct
import sys

MSG_TYPE_ERROR     = 0x0000
MSG_TYPE_DONE      = 0x0001
MSG_TYPE_SETCONF   = 0x0002
MSG_TYPE_GETCONF   = 0x0003
MSG_TYPE_CONFVALUE = 0x0004
MSG_TYPE_SETEVENTS = 0x0005
MSG_TYPE_EVENT     = 0x0006
MSG_TYPE_AUTH      = 0x0007
MSG_TYPE_SAVECONF  = 0x0008
MSG_TYPE_SIGNAL    = 0x0009
MSG_TYPE_MAPADDRESS     = 0x000A
MSG_TYPE_GETINFO        = 0x000B
MSG_TYPE_INFOVALUE      = 0x000C
MSG_TYPE_EXTENDCIRCUIT  = 0x000D
MSG_TYPE_ATTACHSTREAM   = 0x000E
MSG_TYPE_POSTDESCRIPTOR = 0x000F
MSG_TYPE_FRAGMENTHEADER = 0x0010
MSG_TYPE_FRAGMENT       = 0x0011
MSG_TYPE_REDIRECTSTREAM = 0x0012
MSG_TYPE_CLOSESTREAM    = 0x0013
MSG_TYPE_CLOSECIRCUIT   = 0x0014

EVENT_TYPE_CIRCSTATUS   = 0x0001
EVENT_TYPE_STREAMSTATUS = 0x0002
EVENT_TYPE_ORCONNSTATUS = 0x0003
EVENT_TYPE_BANDWIDTH    = 0x0004
EVENT_TYPE_WARN         = 0x0005
EVENT_TYPE_NEWDESC      = 0x0006

ERR_CODES = {
  0x0000 : "Unspecified error",
  0x0001 : "Internal error",
  0x0002 : "Unrecognized message type",
  0x0003 : "Syntax error",
  0x0004 : "Unrecognized configuration key",
  0x0005 : "Invalid configuration value",
  0x0006 : "Unrecognized byte code",
  0x0007 : "Unauthorized",
  0x0008 : "Failed authentication attempt",
  0x0009 : "Resource exhausted",
  0x000A : "No such stream",
  0x000B : "No such circuit",
  0x000C : "No such OR"
}

class TorCtlError(Exception):
  pass

class ProtocolError(TorCtlError):
  pass

class ErrorReply(TorCtlError):
  pass

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

def _receive_msg(s):
  body = ""
  header = s.recv(4)
  length,type = struct.unpack("!HH",header)
  if length:
    body = s.recv(length)
  return length,type,body

def receive_message(s):
  length, tp, body = _receive_msg(s)
  if tp != MSG_TYPE_FRAGMENTHEADER:
    return length, tp, body
  if length < 6:
    raise ProtocolError("FRAGMENTHEADER message too short")
  realType,realLength = struct.unpack("!HL", body[:6])
  data = [ body[6:] ]
  soFar = len(data[0])
  while 1:
    length, tp, body = _receive_msg(s)
    if tp != MSG_TYPE_FRAGMENT:
      raise ProtocolError("Missing FRAGMENT message")
    soFar += length
    data.append(body)
    if soFar == realLength:
      return realLength, realType, "".join(data)
    elif soFar > realLengtH:
      raise ProtocolError("FRAGMENT message too long!")

_event_handler = None
def receive_reply(s, expected=None):
  while 1:
    _, tp, body = receive_message(s)
    if tp == MSG_TYPE_EVENT:
      if _event_handler is not None:
        _event_handler(tp, body)
    elif tp == MSG_TYPE_ERROR:
      if len(body)<2:
        raise ProtocolError("(Truncated error message)")
      errCode, = struct.unpack("!H", body[:2])
      raise ErrorReply((errCode,
                        ERR_CODES.get(errCode,"[unrecognized]"),
                        body[2:]))
    elif (expected is not None) and (tp not in expected):
      raise ProtocolError("Unexpected message type 0x%04x"%tp)
    else:
      return tp, body

def pack_message(type, body=""):
  length = len(body)
  if length < 65536:
    reqheader = struct.pack("!HH", length, type)
    return "%s%s"%(reqheader,body)

  fragheader = struct.pack("!HHHL",
                           65535, MSG_TYPE_FRAGMENTHEADER, type, length)
  msgs = [ fragheader, body[:65535-6] ]
  body = body[65535-6:]
  while body:
    if len(body) > 65535:
      fl = 65535
    else:
      fl = len(body)
    fragheader = struct.pack("!HH", MSG_TYPE_FRAGMENT, fl)
    msgs.append(fragheader)
    msgs.append(body[:fl])
    body = body[fl:]

  return "".join(msgs)

def send_message(s, type, body=""):
  s.sendall(pack_message(type, body))

def authenticate(s):
  send_message(s,MSG_TYPE_AUTH)
  type,body = receive_reply(s)
  return

def _parseKV(body,sep=" ",term="\n"):
  res = []
  for line in body.split(term):
    if not line: continue
    print repr(line)
    k, v = line.split(sep,1)
    res.append((k,v))
  return res

def get_option(s,name):
  send_message(s,MSG_TYPE_GETCONF,name)
  tp,body = receive_reply(s,[MSG_TYPE_CONFVALUE])
  return _parseKV(body)

def set_option(s,msg):
  send_message(s,MSG_TYPE_SETCONF,msg)
  tp,body = receive_reply(s,[MSG_TYPE_DONE])

def get_info(s,name):
  send_message(s,MSG_TYPE_GETINFO,name)
  tp,body = receive_reply(s,[MSG_TYPE_INFOVALUE])
  kvs = body.split("\0")
  d = {}
  for i in xrange(0,len(kvs)-1,2):
    d[kvs[i]] = kvs[i+1]
  return d

def set_events(s,events):
  send_message(s,MSG_TYPE_SETEVENTS,
               "".join([struct.pack("!H", event) for event in events]))
  type,body = receive_reply(s,[MSG_TYPE_DONE])
  return

def save_conf(s):
  send_message(s,MSG_TYPE_SAVECONF)
  receive_reply(s,[MSG_TYPE_DONE])

def send_signal(s, sig):
  send_message(s,MSG_TYPE_SIGNAL,struct.pack("B",sig))
  receive_reply(s,[MSG_TYPE_DONE])

def map_address(s, kv):
  msg = [ "%s %s\n"%(k,v) for k,v in kv ]
  send_message(s,MSG_TYPE_MAPADDRESS,"".join(msg))
  tp, body = receive_reply(s,[MSG_TYPE_DONE])
  return _parseKV(body)

def listen_for_events(s):
  while(1):
    _,type,body = receive_message(s)
    print "event",type
  return

def do_main_loop(host,port):
  print "host is %s:%d"%(host,port)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((host,port))
  authenticate(s)
  print "nick",`get_option(s,"nickname")`
  print get_option(s,"DirFetchPeriod\n")
  print `get_info(s,"version")`
  #print `get_info(s,"desc/name/moria1")`
  #print `get_info(s,"network-status")`
  print `get_info(s,"addr-mappings/all")`
  print `get_info(s,"addr-mappings/config")`
  print `get_info(s,"addr-mappings/cache")`
  print `get_info(s,"addr-mappings/control")`
  print `map_address(s, [("0.0.0.0", "Foobar.com"),
                         ("1.2.3.4", "foobaz.com"),
                         ("frebnitz.com", "5.6.7.8"),
                         (".", "abacinator.onion")])`
  send_signal(s,1)
  #save_conf(s)


  #set_option(s,"1")
  #set_option(s,"bandwidthburstbytes 100000")
  #set_option(s,"runasdaemon 1")
  #set_events(s,[EVENT_TYPE_WARN])
  set_events(s,[EVENT_TYPE_WARN,EVENT_TYPE_STREAMSTATUS])

  listen_for_events(s)

  return

if __name__ == '__main__':
  if len(sys.argv) != 2:
    print "Syntax: tor-control.py torhost:torport"
    sys.exit(0)
  sh,sp = parseHostAndPort(sys.argv[1])
  do_main_loop(sh,sp)

