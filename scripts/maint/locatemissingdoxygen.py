#!/usr/bin/env python

"""
  This script parses the stderr output of doxygen and looks for undocumented
  stuff.  By default, it just counts the undocumented things per file.  But with
  the -A option, it rewrites the files to stick in /*DOCDOC*/ comments
  to highlight the undocumented stuff.
"""

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import shutil
import sys

warning_pattern = re.compile(r'^([^:]+):(\d+): warning: (.*) is not documented')

def readDoxygenOutput(f):
    " yields (cfilename, lineno, thingname) "
    for line in f:
        m = warning_pattern.match(line)
        if m:
            yield m.groups()

warnings = {}

def buildWarnings():
    for fn, lineno, what in list(readDoxygenOutput(sys.stdin)):
        warnings.setdefault(fn, []).append( (int(lineno), what) )

def count(fn):
    if os.path.abspath(fn) not in warnings:
        print("0\t%s"%fn)
    else:
        n = len(warnings[os.path.abspath(fn)])
        print("%d\t%s"%(n,fn))

def getIndentation(line):
    s = line.lstrip()
    return line[:len(line)-len(s)]

def annotate(filename):
    if os.path.abspath(filename) not in warnings:
        return
    with open(filename) as f:
        lines = f.readlines()
    w = warnings[os.path.abspath(filename)][:]
    w.sort()
    w.reverse()

    for lineno, what in w:
        lineno -= 1 # list is 0-indexed.
        if 'DOCDOC' in lines[lineno]:
            continue
        ind = getIndentation(lines[lineno])
        lines.insert(lineno, "%s/* DOCDOC %s */\n"%(ind,what))

    shutil.copy(filename, filename+".orig")
    with open(filename, 'w') as f:
        for l in lines:
            f.write(l)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Usage: locatemissingdoxygen.py [-A] filename... <doxygen_log")
        sys.exit(1)
    buildWarnings()
    if sys.argv[1] == '-A':
        del sys.argv[1]
        func = annotate
    else:
        func = count
    for fname in sys.argv[1:]:
        func(fname)
