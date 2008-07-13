#!/usr/bin/python2.5
# -*- coding: utf-8 -*-
""" This library implements all of the email replying features needed for gettor. """

import smtplib
import MimeWriter
import syslog
import StringIO
import base64

def sendHelp(message, source, destination):
    """ Send a helpful message to the user interacting with us """
    help = constructMessage(message, source, destination)
    try:
        print "Attempting to send the following message: "
        status = sendMessage(help, source, destination)
    except:
        print "Message sending failed."
        status = False
    return status

def sendPackage(message, source, destination, filelist):
    """ Send a message with an attachment to the user interacting with us """
    package = constructMessage(message, source, destination, filelist)
    try:
        print "Attempting to send the following message: "
        status = sendMessage(package, destination)
    except:
        print "Message sending failed."
        status = False
    return status

def constructMessage(messageText, ourAddress, recipient, fileList=None, fileName="requested-files.z"):
    """ Construct a multi-part mime message, including only the first part
    with plaintext."""

    message = StringIO.StringIO()
    mime = MimeWriter.MimeWriter(message)
    mime.addheader('MIME-Version', '1.0')
    mime.addheader('Subject', 'Your request has been processed')
    mime.addheader('To', recipient)
    mime.addheader('From', ourAddress)
    mime.startmultipartbody('mixed')

    firstPart = mime.nextpart()
    emailBody = firstPart.startbody('text/plain')
    emailBody.write(messageText)

    # Add a file if we have one
    if fileList:
        # XXX TODO: Iterate over each file eventually
        filePart = mime.nextpart()
        filePart.addheader('Content-Transfer-Encoding', 'base64')
        emailBody = filePart.startbody('application/zip; name=%s' % fileName)
        base64.encode(open(fileList, 'rb'), emailBody)

    # Now end the mime messsage
    mime.lastpart()
    return message

def sendMessage(message, dst, src="gettor@torproject.org", smtpserver="localhost:2700"):
    try:
        smtp = smtplib.SMTP(smtpserver)
        smtp.sendmail(src, dst, message.getvalue())
        smtp.quit()
        status = True
    except:
        return False

    return status


