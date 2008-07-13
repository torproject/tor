#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
"""

 gettor.py by Jacob Appelbaum <jacob@appelbaum.net>
 This program will hand out Tor via email to supported systems.
 This program is Free Software released under the GPLv3.

 It is intended to be used in a .forward file as part of a pipe like so:

     cat <<'EOF'> .forward
     |/usr/local/bin/gettor.py
     EOF

 You should have a dist/current/ mirror in a directory that gettor can read.
 Such a mirror can be created like so:

     cd /usr/local/
     rsync -av rsync://rsync.torproject.org/tor/dist/current tor-dist-current/

 You can keep it updated with a cronjob like so:

     MirrorDir=/usr/local/tor-dist-current/
     0 3 * * * rsync -a rsync://rsync.torproject.org/tor/dist/current/ $MirrorDir
 
 You should ensure that for each file and signature pair you wish to 
 distribute, you have created a zip file containing both.

 While this program isn't written in a threaded manner per se, it is designed to function 
 as if it will be called as a pipe many times at once. There is a slight 
 desynchronization with blacklist entry checking and may result in false 
 negatives. This isn't perfect but it is designed to be lightweight. It could 
 be fixed easily with a shared locking system but this isn't implemented yet.

"""

__program__ = 'gettor.py'
__version__ = '20080713.00'
__url__ = 'https://tor-svn.freehaven.net/svn/tor/trunk/contrib/gettor/'
__author__ = 'Jacob Appelbaum <jacob@appelbaum.net>'
__copyright__ = 'Copyright (c) 2008, Jacob Appelbaum'
__license__ = 'See LICENSE for licensing information'

try:
    from future import antigravity
except ImportError:
    antigravity = None

import syslog
import gettor_blacklist
import gettor_requests
import gettor_responses

if __name__ == "__main__":

    rawMessage = gettor_requests.getMessage()
    parsedMessage = gettor_requests.parseMessage(rawMessage)

    if not parsedMessage:
        syslog.syslog("gettor: No parsed message. Dropping message.")
        print "gettor: No parsed message. Dropping message."
        exit(1)

    signature = False
    signature = gettor_requests.verifySignature(rawMessage)
    print "Signature is : " + str(signature)
    replyTo = False
    srcEmail = "gettor@torproject.org"

    # TODO XXX:
    # Make the zip files and ensure they match packageList
    # Make each zip file like so:
    # zip -9 windows-bindle.z \
    #   vidalia-bundle-0.2.0.29-rc-0.1.6.exe \
    #   vidalia-bundle-0.2.0.29-rc-0.1.6.exe.asc
    #
    packageList = {
        "windows-bundle": "/tmp/windows-bundle.z",
        "macosx-bundle": "/tmp/macosx-bundle.z",
        "linux-bundle": "/tmp/linux-bundle.z",
        "source-bundle": "/tmp/source-bundle.z"
        }

    # XXX TODO: Ensure we have a proper replyTO or bail out (majorly malformed mail).
    replyTo = gettor_requests.parseReply(parsedMessage)
    
    if not signature:
        # Check to see if we've helped them to understand that they need DKIM in the past
        previouslyHelped = gettor_blacklist.blackList(replyTo)
    
    if not replyTo:
        syslog.syslog("No help dispatched. Invalid reply address for user.")
        print "No help dispatched. Invalid reply address for user."
        exit(1)

    if not signature and previouslyHelped:
        syslog.syslog("gettor: Unsigned messaged to gettor by blacklisted user dropped.")
        print "No help dispatched. Unsigned and unhelped for blacklisted user."
        exit(1)

    if not signature and not previouslyHelped:
        # Reply with some help and bail out
        # Someday call blackList(replyTo)
        message = """
        You should try your request again with a provider that implements DKIM. Sorry.
        """
        gettor_responses.sendHelp(message, srcEmail, replyTo)
        print "attempting to send email from: " + srcEmail + "The mail is sent to: " + replyTo
        syslog.syslog("gettor: Unsigned messaged to gettor. We issued some help about using DKIM.")
        print "gettor: Unsigned messaged to gettor. We issued some help about using DKIM."
        exit(0)

    if signature:
        syslog.syslog("gettor: Signed messaged to gettor.")
        print "gettor: Signed messaged to gettor."
        
        try:
            print "gettor: Parsing now."
            package = gettor_requests.parseRequest(parsedMessage, packageList)
        except:
            package = None

        if package == "windows-bundle":
            print "gettor: " + package + " selected."
            syslog.syslog("gettor: " + package + " selected.")
            message = "Here's your requested software as a zip file. Please \
            verify the signature."
            print "attempting to send email from: " +
            srcEmail + "The mail is sent to: " + replyTo
            gettor_responses.sendPackage(message, srcEmail, replyTo, packageList[package])  
            exit(0)
        else:
            print "Package request is unknown: " + package 
            message = " Your request was misunderstood. Please select one of the \
            following packages: " + packageList.keys()

            gettor_responses.sendHelp(message, srcEmail, replyTo)
            print "attempting to send email from: " + srcEmail + "The mail is sent to: " + replyTo
            syslog.syslog("gettor: Signed messaged to gettor. We issued some help about proper email formatting.")
            print "gettor: Signed messaged to gettor. We issued some help about proper email formatting."
            exit(0)
