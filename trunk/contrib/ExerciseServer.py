#!/usr/bin/python

import TorControl
import threading
import socket
import struct
import random

SOCKS_PORT=9050
CONTROL_PORT=9051

def runSocks4A(nonce, targetHost, targetPort, targetURL):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", SOCKS_PORT))
    socksheader = struct.pack("!BBHL", 4, 0x01, targetPort, 1)
    username = ""
    socksheader = "%s%s\x00%s\x00" %(socksheader, username, nonce)
    s.send(socksheader)
    response = s.recv(8)
    version,status,port=struct.unpack("!BBH",response[:4])
    if status != 90:
        print "Error: non-successful SOCKS status"
        s.close()
        return 0

    s.send("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n"%(targetURL,targetHost))
    while 1:
        r = s.recv(1024)
        if not r:
            s.close()
            return 1

HOSTS_TO_TEST = [ "moria1", "mordor", "tor26"]
EXITS_TO_TEST = [ "pvt", ]
TARGETS = [ ("www.seul.org", "/"), ]

CIRCS_AT_A_TIME = 3
CIRC_LEN = 3

def launchCirc(s):
    htt = HOSTS_TO_TEST[:]
    random.shuffle(htt)
    path = htt[:CIRC_LEN-1]+[random.choice(EXITS_TO_TEST)]
    circid = TorControl.extend_circuit(s, 0, path)
    return circid, path

def runControl(s):
    circs = {}
    streams = {}
    _h = lambda body,circs=circs,streams=streams,s=s:handleEvent(s,body,
                                                                circs,streams)
    TorControl._event_handler = _h
    TorControl.set_events(s,
                          [TorControl.EVENT_TYPE.CIRCSTATUS,
                           TorControl.EVENT_TYPE.STREAMSTATUS])
    TorControl.set_option(s,"__LeaveStreamsUnattached 1")
    while 1:
        while len(circs) < CIRCS_AT_A_TIME:
            c,p = launchCirc(s)
            print "launching circuit %s to %s"%(c,p)
            circs[c]=p
        _, tp, body = TorControl.receive_message(s)
        if tp == TorControl.MSG_TYPE.EVENT:
            handleEvent(s, body, circs, streams)

def handleEvent(s, body, circs, streams):
    event, args = TorControl.unpack_event(body)
    if event == TorControl.EVENT_TYPE.STREAMSTATUS:
        status, ident, target = args
        print "Got stream event:",TorControl.STREAM_STATUS.nameOf[status],\
              ident,target
        if status in (TorControl.STREAM_STATUS.NEW_CONNECT,
                      TorControl.STREAM_STATUS.NEW_RESOLVE,
                      TorControl.STREAM_STATUS.DETACHED):
            if not target.endswith(".exnonce"):
                TorControl.attach_stream(s, ident, 0)
            else:
                circid, (host,url) = streams[target]
                TorControl.redirect_stream(s, ident, host)
                TorControl.attach_stream(s, ident, circid)
    elif event == TorControl.EVENT_TYPE.CIRCSTATUS:
        status, ident, path = args
        print "Got circuit event",TorControl.CIRC_STATUS.nameOf[status],\
              ident,path
        if status in (TorControl.CIRC_STATUS.CLOSED,
                      TorControl.CIRC_STATUS.FAILED):
            if circs.has_key(ident):
                print "Circuit failed."
                del circs[ident]
        elif status == TorControl.CIRC_STATUS.BUILT:
            nonce = random.randint(1,100000000)
            nonce = "%s.exnonce" % nonce
            host,url = random.choice(TARGETS)
            streams[nonce] = ident, (host,url)
            print "Launching socks4a connection"
            t = threading.Thread(target=runSocks4A, args=(nonce, host, 80, url))
            t.setDaemon(1)
            t.start()


def run():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", CONTROL_PORT))
    TorControl.authenticate(s)
    runControl(s)

if __name__ == '__main__':
    run()
    
