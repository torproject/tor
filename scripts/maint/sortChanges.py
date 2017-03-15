#!/usr/bin/python
# Copyright (c) 2014-2017, The Tor Project, Inc.
# See LICENSE for licensing information

"""This script sorts a bunch of changes files listed on its command
   line into roughly the order in which they should appear in the
   changelog.
"""

import re
import sys

def fetch(fn):
    with open(fn) as f:
        s = f.read()
        s = "%s\n" % s.rstrip()
        return s

CSR='Code simplification and refactoring'

REPLACEMENTS = {
    # plurals
    'Minor bugfix' : 'Minor bugfixes',
    'Major bugfix' : 'Major bugfixes',
    'Minor feature' : 'Minor features',
    'Major feature' : 'Major features',
    'Removed feature' : 'Removed features',
    'Code simplification and refactorings' : CSR,
    'Code simplifications and refactoring' : CSR,
    'Code simplifications and refactorings' : CSR,

    # wrong words
    'Minor fix' : 'Minor bugfixes',
    'Major fix' : 'Major bugfixes',
    'Minor fixes' : 'Minor bugfixes',
    'Major fixes' : 'Major bugfixes',
    'Minor enhancement' : 'Minor features',
    'Minor enhancements' : 'Minor features',
    'Major enhancement' : 'Major features',
    'Major enhancements' : 'Major features',
}

def score(s,fname=None):
    m = re.match(r'^ +o ([^\n]*)\n(.*)', s, re.M|re.S)
    if not m:
        print >>sys.stderr, "Can't score %r from %s"%(s,fname)
    heading = m.group(1)
    heading = REPLACEMENTS.get(heading, heading)
    lw = m.group(1).lower()
    if lw.startswith("major feature"):
        score = 0
    elif lw.startswith("major bug"):
        score = 1
    elif lw.startswith("major"):
        score = 2
    elif lw.startswith("minor feature"):
        score = 10
    elif lw.startswith("minor bug"):
        score = 11
    elif lw.startswith("minor"):
        score = 12
    else:
        score = 100

    return (score, lw, heading, m.group(2))

def splitChanges(s):
    this_entry = []
    for line in s.split("\n"):
        if line.strip() == "":
            continue
        if re.match(r" +o ", line):
            if len(this_entry) > 2:
                yield "".join(this_entry)
            curHeader = line
            this_entry = [ curHeader, "\n" ]
            continue
        elif re.match(r" +- ", line):
            if len(this_entry) > 2:
                yield "".join(this_entry)
            this_entry = [ curHeader, "\n" ]

        this_entry.append(line)
        this_entry.append("\n")

    if len(this_entry) > 2:
        yield "".join(this_entry)


changes = []

for fn in sys.argv[1:]:
    if fn.endswith('~'):
        continue
    for change in splitChanges(fetch(fn)):
        changes.append(score(change,fn))

changes.sort()

last_lw = "this is not a header"
for _, lw, header, rest in changes:
    if lw == last_lw:
        print rest,
    else:
        print
        print "  o",header
        print rest,
        last_lw = lw
