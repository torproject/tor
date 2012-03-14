#!/usr/bin/python
# Copyright 2011, The Tor Project, Inc
# original version by Arturo Filastò

# This script parses Firefox and OpenSSL sources, and uses this information
# to generate a ciphers.inc file.

# Read the cpp file to understand what Ciphers map to what name
fileA = open('security/manager/ssl/src/nsNSSComponent.cpp','r')

start = None
lines = fileA.readlines()
for i, line in enumerate(lines):
    if line.strip().startswith('static CipherPref CipherPrefs'):
        # Get the starting boundary of the Cipher Preferences
        start = i

    if start and line.strip().startswith('{NULL, 0}'):
        # Get the ending boundary of the Cipher Prefs
        end = i
        break
fileA.close()

# Parse the lines and put them into a dict
ciphers = {}
for x in lines[start:end]:
    line = x.strip()
    if line.startswith('{'):
        for i, y in enumerate(line):
            if y == '}':
                parsed = line[1:i]
        key, value = parsed.split(',')
        ciphers[key.replace("\"","")] = value.strip()

# Read the JS file to understand what ciphers are enabled
fileB = open('netwerk/base/public/security-prefs.js', 'r')

enabled_ciphers = {}
for x in fileB.readlines():
    start = None
    line = x.strip()
    for i, y in enumerate(line):
        if y == "(":
            start = i
        if start and y == ")":
            end = i
    if start:
        inner = line[start+1:end]
        key, value = inner.replace("\"","").split(",")
        if key.startswith('security.ssl3'):
            enabled_ciphers[key.strip()] = value.strip()
fileB.close()

used_ciphers = []
for k, v in enabled_ciphers.items():
    if v == "true":
        used_ciphers.append(ciphers[k])


oSSLinclude = ('/usr/include/openssl/ssl3.h', '/usr/include/openssl/ssl.h',
               '/usr/include/openssl/ssl2.h', '/usr/include/openssl/ssl23.h',
               '/usr/include/openssl/tls1.h')

sslProto = open('security/nss/lib/ssl/sslproto.h', 'r')
sslProtoD = {}

# This reads the HEX code for the ciphers that are used
# by firefox.
for x in sslProto.readlines():
    line = x.strip()
    if line.lower().startswith("#define"):
        # If I ever see somebody putting mixed tab
        # and spaces I will cut their fingers :)
        line = line.replace('\t', ' ')
        key = line.split(' ')[1]
        value = line.split(' ')[-1]
        key = key.strip()
        value = value.strip()
        print "%s %s\n\n" % (key, value)
        sslProtoD[key] = value
sslProto.close()

cipher_codes = []
for x in used_ciphers:
    cipher_codes.append(sslProtoD[x].lower())

cipher_hex = {}
for fl in oSSLinclude:
    fp = open(fl, 'r')
    for x in fp.readlines():
        line = x.strip()
        if line.lower().startswith("#define"):
            line = line.replace('\t', ' ')
            value = line.split(' ')[1]
            key = line.split(' ')[-1]
            key = key.strip()
            value = value.strip()
            if key.startswith('0x'):
                key = key.replace('0x0300','0x').lower()
                #print "%s %s" % (key, value)
                cipher_hex[key] = value
    fp.close()

for x in cipher_codes:
    try:
        res = """#ifdef %s
        CIPHER(%s, %s)
    #else
       XCIPHER(%s, %s)
    #endif""" % (cipher_hex[x], x, cipher_hex[x], x, cipher_hex[x])
        print res
    except:
        print "Not found %s" % x


#print enabled_ciphers
#print ciphers
