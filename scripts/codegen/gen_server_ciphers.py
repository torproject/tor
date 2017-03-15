#!/usr/bin/python
# Copyright 2014-2017, The Tor Project, Inc
# See LICENSE for licensing information

# This script parses openssl headers to find ciphersuite names, determines
# which ones we should be willing to use as a server, and sorts them according
# to preference rules.
#
# Run it on all the files in your openssl include directory.

import re
import sys

EPHEMERAL_INDICATORS = [ "_EDH_", "_DHE_", "_ECDHE_" ]
BAD_STUFF = [ "_DES_40_", "MD5", "_RC4_", "_DES_64_",
              "_SEED_", "_CAMELLIA_", "_NULL",
              "_CCM_8", "_DES_", ]

# these never get #ifdeffed.
MANDATORY = [
    "TLS1_TXT_DHE_RSA_WITH_AES_256_SHA",
    "TLS1_TXT_DHE_RSA_WITH_AES_128_SHA",
]

def find_ciphers(filename):
    with open(filename) as f:
        for line in f:
            m = re.search(r'(?:SSL3|TLS1)_TXT_\w+', line)
            if m:
                yield m.group(0)

def usable_cipher(ciph):
    ephemeral = False
    for e in EPHEMERAL_INDICATORS:
        if e in ciph:
            ephemeral = True
    if not ephemeral:
        return False

    if "_RSA_" not in ciph:
        return False

    for b in BAD_STUFF:
        if b in ciph:
            return False
    return True

# All fields we sort on, in order of priority.
FIELDS = [ 'cipher', 'fwsec', 'mode',  'digest', 'bitlength' ]
# Map from sorted fields to recognized value in descending order of goodness
FIELD_VALS = { 'cipher' : [ 'AES', 'CHACHA20' ],
               'fwsec' : [ 'ECDHE', 'DHE' ],
               'mode' : [ 'POLY1305', 'GCM', 'CCM', 'CBC', ],
               'digest' : [ 'n/a', 'SHA384', 'SHA256', 'SHA', ],
               'bitlength' : [ '256', '128', '192' ],
}

class Ciphersuite(object):
    def __init__(self, name, fwsec, cipher, bitlength, mode, digest):
        if fwsec == 'EDH':
            fwsec = 'DHE'

        if mode in [ '_CBC3', '_CBC', '' ]:
            mode = 'CBC'
        elif mode == '_GCM':
            mode = 'GCM'

        self.name = name
        self.fwsec = fwsec
        self.cipher = cipher
        self.bitlength = bitlength
        self.mode = mode
        self.digest = digest

        for f in FIELDS:
            assert(getattr(self, f) in FIELD_VALS[f])

    def sort_key(self):
        return tuple(FIELD_VALS[f].index(getattr(self,f)) for f in FIELDS)


def parse_cipher(ciph):
    m = re.match('(?:TLS1|SSL3)_TXT_(EDH|DHE|ECDHE)_RSA(?:_WITH)?_(AES|DES)_(256|128|192)(|_CBC|_CBC3|_GCM)_(SHA|SHA256|SHA384)$', ciph)

    if m:
        fwsec, cipher, bits, mode, digest = m.groups()
        return Ciphersuite(ciph, fwsec, cipher, bits, mode, digest)

    m = re.match('(?:TLS1|SSL3)_TXT_(EDH|DHE|ECDHE)_RSA(?:_WITH)?_(AES|DES)_(256|128|192)_CCM', ciph)
    if m:
        fwsec, cipher, bits = m.groups()
        return Ciphersuite(ciph, fwsec, cipher, bits, "CCM", "n/a")

    m = re.match('(?:TLS1|SSL3)_TXT_(EDH|DHE|ECDHE)_RSA(?:_WITH)?_CHACHA20_POLY1305', ciph)
    if m:
        fwsec, = m.groups()
        return Ciphersuite(ciph, fwsec, "CHACHA20", "256", "POLY1305", "n/a")

    print "/* Couldn't parse %s ! */"%ciph
    return None


ALL_CIPHERS = []

for fname in sys.argv[1:]:
    for c in find_ciphers(fname):
        if usable_cipher(c):
            parsed = parse_cipher(c)
            if parsed != None:
                ALL_CIPHERS.append(parsed)

ALL_CIPHERS.sort(key=Ciphersuite.sort_key)

indent = " "*7

for c in ALL_CIPHERS:
    if c is ALL_CIPHERS[-1]:
        colon = ''
    else:
        colon = ' ":"'

    if c.name in MANDATORY:
        print "%s/* Required */"%indent
        print '%s%s%s'%(indent,c.name,colon)
    else:
        print "#ifdef %s"%c.name
        print '%s%s%s'%(indent,c.name,colon)
        print "#endif"

print '%s;'%indent

