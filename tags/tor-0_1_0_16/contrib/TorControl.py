#!/usr/bin/python
# TorControl.py -- Python module to interface with Tor Control interface.
# Copyright 2005 Nick Mathewson -- See LICENSE for licensing information.
#$Id$

import socket
import struct
import sys

#__all__ = [ "MSG_TYPE", "" ]

class _Enum:
    # Helper: define an ordered dense name-to-number 1-1 mapping.
    def __init__(self, start, names):
        self.nameOf = {}
        idx = start
        for name in names:
            setattr(self,name,idx)
            self.nameOf[idx] = name
            idx += 1
class _Enum2:
    # Helper: define an ordered sparse name-to-number 1-1 mapping.
    def __init__(self, **args):
        self.__dict__.update(args)
        self.nameOf = {}
        for k,v in args.items():
            self.nameOf[v] = k

# Message types that client or server can send.
MSG_TYPE = _Enum(0x0000,
                 ["ERROR",
                  "DONE",
                  "SETCONF",
                  "GETCONF",
                  "CONFVALUE",
                  "SETEVENTS",
                  "EVENT",
                  "AUTH",
                  "SAVECONF",
                  "SIGNAL",
                  "MAPADDRESS",
                  "GETINFO",
                  "INFOVALUE",
                  "EXTENDCIRCUIT",
                  "ATTACHSTREAM",
                  "POSTDESCRIPTOR",
                  "FRAGMENTHEADER",
                  "FRAGMENT",
                  "REDIRECTSTREAM",
                  "CLOSESTREAM",
                  "CLOSECIRCUIT",
                  ])

# Make sure that the enumeration code is working.
assert MSG_TYPE.SAVECONF == 0x0008
assert MSG_TYPE.CLOSECIRCUIT == 0x0014

# Types of "EVENT" message.
EVENT_TYPE = _Enum(0x0001,
                   ["CIRCSTATUS",
                    "STREAMSTATUS",
                    "ORCONNSTATUS",
                    "BANDWIDTH",
                    "OBSOLETE_LOG",
                    "NEWDESC",
                    "DEBUG_MSG",
                    "INFO_MSG",
                    "NOTICE_MSG",
                    "WARN_MSG",
                    "ERR_MSG",
                    ])

assert EVENT_TYPE.ERR_MSG == 0x000B
assert EVENT_TYPE.OBSOLETE_LOG == 0x0005

# Status codes for "CIRCSTATUS" events.
CIRC_STATUS = _Enum(0x00,
                    ["LAUNCHED",
                     "BUILT",
                     "EXTENDED",
                     "FAILED",
                     "CLOSED"])

# Status codes for "STREAMSTATUS" events
STREAM_STATUS = _Enum(0x00,
                      ["SENT_CONNECT",
                       "SENT_RESOLVE",
                       "SUCCEEDED",
                       "FAILED",
                       "CLOSED",
                       "NEW_CONNECT",
                       "NEW_RESOLVE",
                       "DETACHED"])

# Status codes for "ORCONNSTATUS" events
OR_CONN_STATUS = _Enum(0x00,
                       ["LAUNCHED","CONNECTED","FAILED","CLOSED"])

# Signal codes for "SIGNAL" events.
SIGNAL = _Enum2(HUP=0x01,INT=0x02,USR1=0x0A,USR2=0x0C,TERM=0x0F)

# Error codes for "ERROR" events.
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
    "Generic error raised by TorControl code."
    pass

class ProtocolError(TorCtlError):
    "Raised on violations in Tor controller protocol"
    pass

class ErrorReply(TorCtlError):
    ""
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

def _unpack_msg(msg):
    "return None, minLength, body or type,body,rest"
    if len(msg) < 4:
        return None, 4, msg
    length,type = struct.unpack("!HH",msg)
    if len(msg) >= 4+length:
        return type,msg[4:4+length],msg[4+length:]
    else:
        return None,4+length,msg

def _minLengthToPack(bytes):
    whole,left = divmod(bytes,65535)
    if left:
        return whole*(65535+4)+4+left
    else:
        return whole*(65535+4)

def unpack_msg(msg):
    "returns as for _unpack_msg"
    tp,body,rest = _unpack_msg(msg)
    if tp != MSG_TYPE.FRAGMENTHEADER:
        return tp, body, rest

    if len(body) < 6:
        raise ProtocolError("FRAGMENTHEADER message too short")

    realType,realLength = struct.unpack("!HL", body[:6])

    # Okay; could the message _possibly_ be here?
    minLength = _minLengthToPack(realLength+6)
    if len(msg) < minLength:
        return None,  minLength, msg

    # Okay; optimistically try to build up the msg.
    soFar = [ body[6:] ]
    lenSoFarLen = len(body)-6
    while len(rest)>=4 and lenSoFar < realLength:
        ln, tp = struct.unpack("!HH", rest[:4])
        if tp != MSG_TYPE.FRAGMENT:
            raise ProtocolError("Missing FRAGMENT message")
        soFar.append(rest[4:4+ln])
        lenSoFar += ln
        if 4+ln > len(rest):
            rest = ""
            leftInPacket = 4+ln-len(rest)
        else:
            rest = rest[4+ln:]
            leftInPacket=0

    if lenSoFar == realLength:
        return realType, "".join(soFar), rest
    elif lenSoFar > realLength:
        raise ProtocolError("Bad fragmentation: message longer than declared")
    else:
        inOtherPackets = realLength-lenSoFar-leftInPacket
        minLength = _minLengthToPack(inOtherPackets)
        return None, len(msg)+leftInPacket+inOtherPackets, msg

def _receive_msg(s):
  body = ""
  header = s.recv(4)
  length,type = struct.unpack("!HH",header)
  if length:
    while length > len(body):
      body += s.recv(length-len(body))
  return length,type,body

def receive_message(s):
    length, tp, body = _receive_msg(s)
    if tp != MSG_TYPE.FRAGMENTHEADER:
        return length, tp, body
    if length < 6:
        raise ProtocolError("FRAGMENTHEADER message too short")
    realType,realLength = struct.unpack("!HL", body[:6])
    data = [ body[6:] ]
    soFar = len(data[0])
    while 1:
        length, tp, body = _receive_msg(s)
        if tp != MSG_TYPE.FRAGMENT:
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
        if tp == MSG_TYPE.EVENT:
            if _event_handler is not None:
                _event_handler(body)
        elif tp == MSG_TYPE.ERROR:
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
                             65535, MSG_TYPE.FRAGMENTHEADER, type, length)
    msgs = [ fragheader, body[:65535-6] ]
    body = body[65535-6:]
    while body:
        if len(body) > 65535:
            fl = 65535
        else:
            fl = len(body)
        fragheader = struct.pack("!HH", MSG_TYPE.FRAGMENT, fl)
        msgs.append(fragheader)
        msgs.append(body[:fl])
        body = body[fl:]

    return "".join(msgs)

def send_message(s, type, body=""):
    s.sendall(pack_message(type, body))

def authenticate(s):
    send_message(s,MSG_TYPE.AUTH)
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
    send_message(s,MSG_TYPE.GETCONF,name)
    tp,body = receive_reply(s,[MSG_TYPE.CONFVALUE])
    return _parseKV(body)

def set_option(s,msg):
    send_message(s,MSG_TYPE.SETCONF,msg)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])

def get_info(s,name):
    send_message(s,MSG_TYPE.GETINFO,name)
    tp,body = receive_reply(s,[MSG_TYPE.INFOVALUE])
    kvs = body.split("\0")
    d = {}
    for i in xrange(0,len(kvs)-1,2):
        d[kvs[i]] = kvs[i+1]
    return d

def set_events(s,events):
    send_message(s,MSG_TYPE.SETEVENTS,
                 "".join([struct.pack("!H", event) for event in events]))
    type,body = receive_reply(s,[MSG_TYPE.DONE])
    return

def save_conf(s):
    send_message(s,MSG_TYPE.SAVECONF)
    receive_reply(s,[MSG_TYPE.DONE])

def send_signal(s, sig):
    send_message(s,MSG_TYPE.SIGNAL,struct.pack("B",sig))
    receive_reply(s,[MSG_TYPE.DONE])

def map_address(s, kv):
    msg = [ "%s %s\n"%(k,v) for k,v in kv ]
    send_message(s,MSG_TYPE.MAPADDRESS,"".join(msg))
    tp, body = receive_reply(s,[MSG_TYPE.DONE])
    return _parseKV(body)

def extend_circuit(s, circid, hops):
    msg = struct.pack("!L",circid) + ",".join(hops) + "\0"
    send_message(s,MSG_TYPE.EXTENDCIRCUIT,msg)
    tp, body = receive_reply(s,[MSG_TYPE.DONE])
    if len(body) != 4:
        raise ProtocolError("Extendcircuit reply too short or long")
    return struct.unpack("!L",body)[0]

def redirect_stream(s, streamid, newtarget):
    msg = struct.pack("!L",streamid) + newtarget + "\0"
    send_message(s,MSG_TYPE.REDIRECTSTREAM,msg)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])

def attach_stream(s, streamid, circid):
    msg = struct.pack("!LL",streamid, circid)
    send_message(s,MSG_TYPE.ATTACHSTREAM,msg)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])

def close_stream(s, streamid, reason=0, flags=0):
    msg = struct.pack("!LBB",streamid,reason,flags)
    send_message(s,MSG_TYPE.CLOSESTREAM,msg)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])

def close_circuit(s, circid, flags=0):
    msg = struct.pack("!LB",circid,flags)
    send_message(s,MSG_TYPE.CLOSECIRCUIT,msg)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])

def post_descriptor(s, descriptor):
    send_message(s,MSG_TYPE.POSTDESCRIPTOR,descriptor)
    tp,body = receive_reply(s,[MSG_TYPE.DONE])


def _unterminate(s):
    if s[-1] == '\0':
        return s[:-1]
    else:
        return s

def unpack_event(body):
    if len(body)<2:
        raise ProtocolError("EVENT body too short.")
    evtype, = struct.unpack("!H", body[:2])
    body = body[2:]
    if evtype == EVENT_TYPE.CIRCSTATUS:
        if len(body)<5:
            raise ProtocolError("CIRCUITSTATUS event too short.")
        status,ident = struct.unpack("!BL", body[:5])
        path = _unterminate(body[5:]).split(",")
        args = status, ident, path
    elif evtype == EVENT_TYPE.STREAMSTATUS:
        if len(body)<5:
            raise ProtocolError("CIRCUITSTATUS event too short.")
        status,ident = struct.unpack("!BL", body[:5])
        target = _unterminate(body[5:])
        args = status, ident, target
    elif evtype == EVENT_TYPE.ORCONNSTATUS:
        if len(body)<2:
            raise ProtocolError("CIRCUITSTATUS event too short.")
        status = ord(body[0])
        target = _unterminate(body[1:])
        args = status, target
    elif evtype == EVENT_TYPE.BANDWIDTH:
        if len(body)<8:
            raise ProtocolError("BANDWIDTH event too short.")
        read, written = struct.unpack("!LL",body[:8])
        args = read, written
    elif evtype == EVENT_TYPE.OBSOLETE_LOG:
        args = (_unterminate(body),)
    elif evtype == EVENT_TYPE.NEWDESC:
        args = (_unterminate(body).split(","),)
    elif EVENT_TYPE.DEBUG_MSG <= evtype <= EVENT_TYPE.ERR_MSG:
        args = (EVENT_TYPE.nameOf(evtype), _unterminate(body))
    else:
        args = (body,)

    return evtype, args

def listen_for_events(s):
    while(1):
        _,type,body = receive_message(s)
        print unpack_event(body)
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
    print `get_info(s,"network-status")`
    print `get_info(s,"addr-mappings/all")`
    print `get_info(s,"addr-mappings/config")`
    print `get_info(s,"addr-mappings/cache")`
    print `get_info(s,"addr-mappings/control")`
    print `map_address(s, [("0.0.0.0", "Foobar.com"),
                           ("1.2.3.4", "foobaz.com"),
                           ("frebnitz.com", "5.6.7.8"),
                           (".", "abacinator.onion")])`
    print `extend_circuit(s,0,["moria1"])`
    print '========'
    print `extend_circuit(s,0,[""])`
    print '========'
    #send_signal(s,1)
    #save_conf(s)


    #set_option(s,"1")
    #set_option(s,"bandwidthburstbytes 100000")
    #set_option(s,"runasdaemon 1")
    #set_events(s,[EVENT_TYPE.WARN])
    set_events(s,[EVENT_TYPE.OBSOLETE_LOG])

    listen_for_events(s)

    return

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Syntax: TorControl.py torhost:torport"
        sys.exit(0)
    sh,sp = parseHostAndPort(sys.argv[1])
    do_main_loop(sh,sp)

