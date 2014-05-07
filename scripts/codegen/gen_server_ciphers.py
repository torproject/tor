#!/usr/bin/python
# Copyright 2014, The Tor Project, Inc
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
              "_SEED_", "_CAMELLIA_", "_NULL" ]

# these never get #ifdeffed.
MANDATORY = [
    "TLS1_TXT_DHE_RSA_WITH_AES_256_SHA",
    "TLS1_TXT_DHE_RSA_WITH_AES_128_SHA",
    "SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA",
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
FIELD_VALS = { 'cipher' : [ 'AES', 'DES'],
               'fwsec' : [ 'ECDHE', 'DHE' ],
               'mode' : [ 'GCM', 'CBC' ],
               'digest' : [ 'SHA384', 'SHA256', 'SHA' ],
               'bitlength' : [ '256', '128', '192' ],
}

class Ciphersuite(object):
    def __init__(self, name, fwsec, cipher, bitlength, mode, digest):
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

    if not m:
        print "/* Couldn't parse %s ! */"%ciph
        return None

    fwsec, cipher, bits, mode, digest = m.groups()
    if fwsec == 'EDH':
        fwsec = 'DHE'

    if mode in [ '_CBC3', '_CBC', '' ]:
        mode = 'CBC'
    elif mode == '_GCM':
        mode = 'GCM'

    return Ciphersuite(ciph, fwsec, cipher, bits, mode, digest)

ALL_CIPHERS = []

for fname in sys.argv[1:]:
    ALL_CIPHERS += (parse_cipher(c)
                           for c in find_ciphers(fname)
                           if usable_cipher(c) )

ALL_CIPHERS.sort(key=Ciphersuite.sort_key)

for c in ALL_CIPHERS:
    if c is ALL_CIPHERS[-1]:
        colon = ';'
    else:
        colon = ' ":"'

    if c.name in MANDATORY:
        print "       /* Required */"
        print '       %s%s'%(c.name,colon)
    else:
        print "#ifdef %s"%c.name
        print '       %s%s'%(c.name,colon)
        print "#endif"


