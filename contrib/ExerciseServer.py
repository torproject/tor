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
            print "WOOT! Got a web page."
            s.close()
            return 1

HOSTS_TO_TEST = [ "serifos", "chaoscomputerclub", "NetWorkXXIII", "caethaver2",
                  "theoryorg", "samaire", "alrua", "ihopethisisunique",
                  "xolotl", "cacophony", "ghettocluster", "torserverzillion",
                  "ned", "richhomednsorg", "subzeronet"]
EXITS_TO_TEST = [ "pvt", ]

HOSTS_THAT_WORK = [ "serifos", "rodos", "moria2", "chaoscomputerclub"]
EXITS_THAT_WORK = [ "serifos", "rodos"]

TARGETS = [ ("belegost.mit.edu", "/"),
            ("seul.org", "/")]

N_CIRCS_TO_TRY = 5*len(HOSTS_TO_TEST)
CIRCS_AT_A_TIME = 3
CIRC_LEN = 3

HOST_STATUS = {}
N_CIRCS_DONE = 0
def launchCirc(s):
    htw = HOSTS_THAT_WORK[:]
    random.shuffle(htw)
    path = htw[:CIRC_LEN-2] + \
           [random.choice(HOSTS_TO_TEST)] + \
           [random.choice(EXITS_THAT_WORK)]
    circid = TorControl.extend_circuit(s, 0, path)

    for name in path:
        lst = HOST_STATUS.setdefault(name,[0,0])
        lst[0] += 1
    return circid, path

def runControl(s):
    circs = {}
    s1,s2 = {},{}
    _h = lambda body,circs=circs,s1=s1,s2=s2,s=s:handleEvent(s,body,
                                                             circs,s1,s2)
    TorControl._event_handler = _h
    TorControl.set_events(s,
                          [TorControl.EVENT_TYPE.CIRCSTATUS,
                           TorControl.EVENT_TYPE.STREAMSTATUS])
    TorControl.set_option(s,"__LeaveStreamsUnattached 1")
    global N_CIRCS_DONE
    while N_CIRCS_DONE < N_CIRCS_TO_TRY:
        while len(circs) < CIRCS_AT_A_TIME:
            c,p = launchCirc(s)
            print "launching circuit %s to %s"%(c,p)
            circs[c]=p
        _, tp, body = TorControl.receive_message(s)
        if tp == TorControl.MSG_TYPE.EVENT:
            handleEvent(s, body, circs, s1,s2)
    i = HOST_STATUS.items()
    i.sort()
    for n,(all,good) in i:
        print "%s in %s circuits; %s/%s ok"%(n,all,good,all)

def handleEvent(s, body, circs, streamsByNonce, streamsByIdent):
    global N_CIRCS_DONE
    event, args = TorControl.unpack_event(body)
    if event == TorControl.EVENT_TYPE.STREAMSTATUS:
        status, ident, target = args
        print "Got stream event:",TorControl.STREAM_STATUS.nameOf[status],\
              ident,target
        if status in (TorControl.STREAM_STATUS.NEW_CONNECT,
                      TorControl.STREAM_STATUS.NEW_RESOLVE,
                      TorControl.STREAM_STATUS.DETACHED):
            target,port=target.split(":")
            if not target.endswith(".exnonce"):
                TorControl.attach_stream(s, ident, 0)
            else:
                circid, (host,url) = streamsByNonce[target]
                streamsByIdent[ident] = circid,(host,url)
                print "Redirecting circuit",circid,"to",host
                TorControl.redirect_stream(s, ident, host)
                TorControl.attach_stream(s, ident, circid)
        elif status in (TorControl.STREAM_STATUS.CLOSED,
                        TorControl.STREAM_STATUS.FAILED):
            circid, (host,url) = streamsByIdent[ident]
            if circs.has_key(circid):
                for name in circs[circid]:
                    HOST_STATUS[name][1] += 1
                del circs[circid]
                N_CIRCS_DONE += 1
                print N_CIRCS_DONE, "circuit attempts done"
            del streamsByIdent[ident]
    elif event == TorControl.EVENT_TYPE.CIRCSTATUS:
        status, ident, path = args
        print "Got circuit event",TorControl.CIRC_STATUS.nameOf[status],\
              ident,path
        if status in (TorControl.CIRC_STATUS.CLOSED,
                      TorControl.CIRC_STATUS.FAILED):
            if circs.has_key(ident):
                print "Circuit failed."
                del circs[ident]
                N_CIRCS_DONE += 1
                print N_CIRCS_DONE, "circuit attempts done"
        elif status == TorControl.CIRC_STATUS.BUILT:
            nonce = random.randint(1,100000000)
            nonce = "%s.exnonce" % nonce
            host,url = random.choice(TARGETS)
            streamsByNonce[nonce] = ident, (host,url)
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
    
