#!/usr/bin/python
# coding=utf-8
# Copyright 2011-2017, The Tor Project, Inc
# original version by Arturo Filastò
# See LICENSE for licensing information

# This script parses Firefox and OpenSSL sources, and uses this information
# to generate a ciphers.inc file.
#
# It takes two arguments: the location of a firefox source directory, and the
# location of an openssl source directory.

import os
import re
import sys

if len(sys.argv) != 3:
    print >>sys.stderr, "Syntax: get_mozilla_ciphers.py <firefox-source-dir> <openssl-source-dir>"
    sys.exit(1)

ff_root = sys.argv[1]
ossl_root = sys.argv[2]

def ff(s):
    return os.path.join(ff_root, s)
def ossl(s):
    return os.path.join(ossl_root, s)

#####
# Read the cpp file to understand what Ciphers map to what name :
# Make "ciphers" a map from name used in the javascript to a cipher macro name
fileA = open(ff('security/manager/ssl/nsNSSComponent.cpp'),'r')

# The input format is a file containing exactly one section of the form:
# static CipherPref CipherPrefs[] = {
#  {"name", MACRO_NAME}, // comment
#  ...
#  {NULL, 0}
# }

inCipherSection = False
cipherLines = []
for line in fileA:
    if line.startswith('static const CipherPref sCipherPrefs[]'):
        # Get the starting boundary of the Cipher Preferences
        inCipherSection = True
    elif inCipherSection:
        line = line.strip()
        if line.startswith('{ nullptr, 0}'):
            # At the ending boundary of the Cipher Prefs
            break
        else:
            cipherLines.append(line)
fileA.close()

# Parse the lines and put them into a dict
ciphers = {}
cipher_pref = {}
key_pending = None
for line in cipherLines:
    m = re.search(r'^{\s*\"([^\"]+)\",\s*(\S+)\s*(?:,\s*(true|false))?\s*}', line)
    if m:
        assert not key_pending
        key,value,enabled = m.groups()
        if enabled == 'true':
            ciphers[key] = value
            cipher_pref[value] = key
        continue
    m = re.search(r'^{\s*\"([^\"]+)\",', line)
    if m:
        assert not key_pending
        key_pending = m.group(1)
        continue
    m = re.search(r'^\s*(\S+)(?:,\s*(true|false))+\s*}', line)
    if m:
        assert key_pending
        key = key_pending
        value,enabled = m.groups()
        key_pending = None
        if enabled == 'true':
            ciphers[key] = value
            cipher_pref[value] = key

####
# Now find the correct order for the ciphers
fileC = open(ff('security/nss/lib/ssl/ssl3con.c'), 'r')
firefox_ciphers = []
inEnum=False
for line in fileC:
    if not inEnum:
        if "ssl3CipherSuiteCfg cipherSuites[" in line:
            inEnum = True
        continue

    if line.startswith("};"):
        break

    m = re.match(r'^\s*\{\s*([A-Z_0-9]+),', line)
    if m:
        firefox_ciphers.append(m.group(1))

fileC.close()

#####
# Read the JS file to understand what ciphers are enabled.  The format is
#  pref("name", true/false);
# Build a map enabled_ciphers from javascript name to "true" or "false",
# and an (unordered!) list of the macro names for those ciphers that are
# enabled.
fileB = open(ff('netwerk/base/security-prefs.js'), 'r')

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

#oSSLinclude = ('/usr/include/openssl/ssl3.h', '/usr/include/openssl/ssl.h',
#               '/usr/include/openssl/ssl2.h', '/usr/include/openssl/ssl23.h',
#               '/usr/include/openssl/tls1.h')
oSSLinclude = ['ssl3.h', 'ssl.h'
               'ssl2.h', 'ssl23.h',
               'tls1.h']

#####
# This reads the hex code for the ciphers that are used by firefox.
# sslProtoD is set to a map from macro name to macro value in sslproto.h;
# cipher_codes is set to an (unordered!) list of these hex values.
sslProto = open(ff('security/nss/lib/ssl/sslproto.h'), 'r')
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
openssl_macro_by_hex = {}
all_openssl_macros = {}
for fl in oSSLinclude:
    fname = ossl("include/openssl/"+fl)
    if not os.path.exists(fname):
        continue
    fp = open(fname, 'r')
    for line in fp.readlines():
        m = re.match('# *define\s+(\S+)\s+(\S+)', line)
        if m:
            value,key = m.groups()
            if key.startswith('0x') and "_CK_" in value:
                key = key.replace('0x0300','0x').lower()
                #print "%s %s" % (key, value)
                openssl_macro_by_hex[key] = value
            all_openssl_macros[value]=key
    fp.close()

# Now generate the output.
print """\
/* This is an include file used to define the list of ciphers clients should
 * advertise.  Before including it, you should define the CIPHER and XCIPHER
 * macros.
 *
 * This file was automatically generated by get_mozilla_ciphers.py.
 */"""
# Go in order by the order in CipherPrefs
for firefox_macro in firefox_ciphers:

    try:
        js_cipher_name = cipher_pref[firefox_macro]
    except KeyError:
        # This one has no javascript preference.
        continue

    # The cipher needs to be enabled in security-prefs.js
    if enabled_ciphers.get(js_cipher_name, 'false') != 'true':
        continue

    hexval = sslProtoD[firefox_macro].lower()

    try:
        openssl_macro = openssl_macro_by_hex[hexval.lower()]
        openssl_macro = openssl_macro.replace("_CK_", "_TXT_")
        if openssl_macro not in all_openssl_macros:
            raise KeyError()
        format = {'hex':hexval, 'macro':openssl_macro, 'note':""}
    except KeyError:
        # openssl doesn't have a macro for this.
        format = {'hex':hexval, 'macro':firefox_macro,
                  'note':"/* No openssl macro found for "+hexval+" */\n"}

    res = """\
%(note)s#ifdef %(macro)s
    CIPHER(%(hex)s, %(macro)s)
#else
   XCIPHER(%(hex)s, %(macro)s)
#endif""" % format
    print res
