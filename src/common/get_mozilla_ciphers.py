#!/usr/bin/python
# coding=utf-8
# Copyright 2011, The Tor Project, Inc
# original version by Arturo Filastò

# This script parses Firefox and OpenSSL sources, and uses this information
# to generate a ciphers.inc file.

import re

#####
# Read the cpp file to understand what Ciphers map to what name :
# Make "ciphers" a map from name used in the javascript to a cipher macro name
fileA = open('security/manager/ssl/src/nsNSSComponent.cpp','r')

# The input format is a file containing exactly one section of the form:
# static CipherPref CipherPrefs[] = {
#  {"name", MACRO_NAME}, // comment
#  ...
#  {NULL, 0}
# }

inCipherSection = False
cipherLines = []
for line in fileA:
    if line.startswith('static CipherPref CipherPrefs'):
        # Get the starting boundary of the Cipher Preferences
        inCipherSection = True
    elif inCipherSection:
        line = line.strip()
        if line.startswith('{NULL, 0}'):
            # At the ending boundary of the Cipher Prefs
            break
        else:
            cipherLines.append(line)
fileA.close()

# Parse the lines and put them into a dict
ciphers = {}
for line in cipherLines:
    m = re.search(r'^{\s*\"([^\"]+)\",\s*(\S*)\s*}', line)
    if m:
        key,value = m.groups()
        ciphers[key] = value

#####
# Read the JS file to understand what ciphers are enabled.  The format is
#  pref("name", true/false);
# Build a map enabled_ciphers from javascript name to "true" or "false",
# and an (unordered!) list of the macro names for those ciphers that are
# enabled.
fileB = open('netwerk/base/public/security-prefs.js', 'r')

enabled_ciphers = {}
for line in fileB:
    m = re.match(r'pref\(\"([^\"]+)\"\s*,\s*(\S*)\s*\)', line)
    if not m:
        continue
    key, val = m.groups()
    if key.startswith("security.ssl3"):
        enabled_ciphers[key] = val
fileB.close()

used_ciphers = []
for k, v in enabled_ciphers.items():
    if v == "true":
        used_ciphers.append(ciphers[k])

oSSLinclude = ('/usr/include/openssl/ssl3.h', '/usr/include/openssl/ssl.h',
               '/usr/include/openssl/ssl2.h', '/usr/include/openssl/ssl23.h',
               '/usr/include/openssl/tls1.h')

#####
# This reads the hex code for the ciphers that are used by firefox.
# sslProtoD is set to a map from macro name to macro value in sslproto.h;
# cipher_codes is set to an (unordered!) list of these hex values.
sslProto = open('security/nss/lib/ssl/sslproto.h', 'r')
sslProtoD = {}

for line in sslProto:
    m = re.match('#define\s+(\S+)\s+(\S+)', line)
    if m:
        key, value = m.groups()
        sslProtoD[key] = value
sslProto.close()

cipher_codes = []
for x in used_ciphers:
    cipher_codes.append(sslProtoD[x].lower())

####
# Now read through all the openssl include files, and try to find the openssl
# macro names for those files.
cipher_hex = {}
for fl in oSSLinclude:
    fp = open(fl, 'r')
    for line in fp.readlines():
        m = re.match('#define\s+(\S+)\s+(\S+)', line)
        if m:
            value,key = m.groups()
            if key.startswith('0x'):
                key = key.replace('0x0300','0x').lower()
                #print "%s %s" % (key, value)
                cipher_hex[key] = value
    fp.close()

# Now generate the output.
for x in cipher_codes:
    try:
        res = """#ifdef %s
        CIPHER(%s, %s)
    #else
       XCIPHER(%s, %s)
    #endif""" % (cipher_hex[x], x, cipher_hex[x], x, cipher_hex[x])
        print res
    except KeyError:
        print "Not found %s" % x

