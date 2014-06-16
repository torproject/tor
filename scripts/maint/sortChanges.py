#!/usr/bin/python
# Copyright (c) 2014, The Tor Project, Inc.
# See LICENSE for licensing information

"""This script sorts a bunch of changes files listed on its command
   line into roughly the order in which they should appear in the
   changelog.

   TODO: collation support.
"""

import re
import sys

def fetch(fn):
    with open(fn) as f:
        s = f.read()
        s = "%s\n" % s.rstrip()
        return s

def score(s):
    m = re.match(r'^ +o (.*)', s)
    if not m:
        print >>sys.stderr, "Can't score %r"%s
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

    return (score,  lw, s)


changes = [ score(fetch(fn)) for fn in sys.argv[1:] if not fn.endswith('~') ]

changes.sort()

for _, _, s in changes:
    print s
