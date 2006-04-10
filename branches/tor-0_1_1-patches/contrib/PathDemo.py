#!/usr/bin/python

import TorControl
import threading
import socket
import struct
import random

circuits = {}
streams = {}

def runControl(s):
    pendingEvents = [] #XXX This tric. should become standard
    TorControl._event_handler = pendingEvents.append
    TorControl.set_events(s,
                          [TorControl.EVENT_TYPE.CIRCSTATUS,
                           TorControl.EVENT_TYPE.STREAMSTATUS])
    TorControl.set_option(s,"__LeaveStreamsUnattached 1")
    while 1:
        e = pendingEvents[:]
        del pendingEvents[:]
        for ev in e:
            handleEvent(s, ev)
        _, tp, body = TorControl.receive_message(s)
        if tp == TorControl.MSG_TYPE.EVENT:
            handleEvent(s, body)


def parsePath(name):
    assert name.endswith(".path")
    items = name.split(".")
    try:
        n = int(items[-2])
    except:
        return None,None
    path = items[-(2+n):-2]
    host = items[:-(2+n)]
    print path,host
    return path,".".join(host)

def handleEvent(s,body):
    event, args = TorControl.unpack_event(body)
    if event == TorControl.EVENT_TYPE.STREAMSTATUS:
        status, ident, target = args
        print "Got stream event:",TorControl.STREAM_STATUS.nameOf[status],\
              ident,target
        if status in (TorControl.STREAM_STATUS.NEW_CONNECT,
                      TorControl.STREAM_STATUS.NEW_RESOLVE):
            target,port=target.split(":")
            if not target.endswith(".path"):
                TorControl.attach_stream(s, ident, 0)
            else:
                path,host = parsePath(target)
                #XXXX Don't launch so many circuits!
                streams[ident] = path,host
                circid = TorControl.extend_circuit(s, 0, path)
                circuits[circid] = path
        elif status == TorControl.STREAM_STATUS.DETACHED:
            if not streams.has_key(ident):
                TorControl.attach_stream(s, ident, 0)
            else:
                TorControl.close_stream(s, ident, 1)
    elif event == TorControl.EVENT_TYPE.CIRCSTATUS:
        status, ident, path = args
        print "Got circuit event",TorControl.CIRC_STATUS.nameOf[status],\
              ident,path
        if not circuits.has_key(ident):
            return
        if status in (TorControl.CIRC_STATUS.CLOSED,
                      TorControl.CIRC_STATUS.FAILED):
            ok = 0
        elif status == TorControl.CIRC_STATUS.BUILT:
            ok = 1
        else:
            return

        ids = [ streamID for (streamID, (path,host)) in streams.items()
                if path == circuits[ident] ]

        for streamID in ids:
            if ok:
                _,host = streams[streamID]
                TorControl.redirect_stream(s, streamID, host)
                TorControl.attach_stream(s, streamID, ident)
                #XXXX Don't do this twice.
            else:
                TorControl.close_stream(s, streamID, 1)
        if not ok:
            del circuits[ident]


def run():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", 9051))
    TorControl.authenticate(s)
    runControl(s)

if __name__ == '__main__':
    run()
