#!/usr/bin/python
#$Id$

import socket
import struct
import sys

def socks4AResolveRequest(hostname):
    version = 4
    command = 0xF0
    port = 0
    addr = 0x0000001
    username = ""
    reqheader = struct.pack("!BBHL", version, command, port, addr)
    return "%s%s\x00%s\x00"%(reqheader,username,hostname)

def socks4AParseResponse(response):
    RESPONSE_LEN = 8
    if len(response) < RESPONSE_LEN:
        return None
    assert len(response) >= RESPONSE_LEN
    version,status,port = struct.unpack("!BBH",response[:4])
    assert version == 0
    assert port == 0
    if status == 90:
        return "%d.%d.%d.%d"%tuple(map(ord, response[4:]))
    else:
        return "ERROR (status %d)"%status

def socks5Hello():
    return "\x05\x01\x00"
def socks5ParseHello(response):
    if response != "\x05\x00":
        raise ValueError("Bizarre socks5 response")
def socks5ResolveRequest(hostname):
    version = 5
    command = 0xF0
    rsv = 0
    port = 0
    atype = 0x03
    reqheader = struct.pack("!BBBBB",version, command, rsv, atype, len(hostname))
    portstr = struct.pack("!H",port)
    return "%s%s%s"%(reqheader,hostname,portstr)
def socks5ParseResponse(r):
    if len(r)<8:
        return None
    version, reply, rsv, atype = struct.unpack("!BBBB",r[:4])
    assert version==5
    assert rsv==0
    if reply != 0x00:
        return "ERROR",reply
    assert atype in (0x01,0x04)
    expected_len = 4 + ({1:4,4:16}[atype]) + 2
    if len(r) < expected_len:
        return None
    elif len(r) > expected_len:
        raise ValueError("Overlong socks5 reply!")
    addr = r[4:-2]
    if atype == 0x01:
        return "%d.%d.%d.%d"%tuple(map(ord,addr))
    else:
        # not really the right way to format IPv6
        return "IPv6: %s"%(":".join([hex(ord(c)) for c in addr]))

def parseHostAndPort(h):
    host, port = "localhost", 9050
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

def resolve(hostname, sockshost, socksport, socksver=4):
    assert socksver in (4,5)
    if socksver == 4:
        fmt = socks4AResolveRequest
        parse = socks4AParseResponse
    else:
        fmt = socks5ResolveRequest
        parse = socks5ParseResponse
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((sockshost,socksport))
    if socksver == 5:
        s.send(socks5Hello())
        socks5ParseHello(s.recv(2))
    print len(fmt(hostname)), len(hostname)
    s.send(fmt(hostname))
    answer = s.recv(6)
    result = parse(answer)
    while result is None:
        more = s.recv(1)
        if not more:
            return None
        answer += more
        result = parse(answer)
    print "Got answer",result
    m = s.recv(1)
    if m:
        print "Got extra data too: %r"%m
    return result

if __name__ == '__main__':
    if len(sys.argv) not in (2,3,4):
        print "Syntax: resolve.py [-4|-5] hostname [sockshost:socksport]"
        sys.exit(0)
    socksver = 4
    if sys.argv[1] in ("-4", "-5"):
        socksver = int(sys.argv[1][1])
        del sys.argv[1]
    if len(sys.argv) == 4:
        print "Syntax: resolve.py [-4|-5] hostname [sockshost:socksport]"
        sys.exit(0)
    if len(sys.argv) == 3:
        sh,sp = parseHostAndPort(sys.argv[2])
    else:
        sh,sp = parseHostAndPort("")
    resolve(sys.argv[1], sh, sp, socksver)
