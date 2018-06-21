#!/usr/bin/python3
# Copyright 2018 The Tor Project, Inc.  See LICENSE file for licensing info.

import fnmatch
import os
import re
import sys

trouble = False

def err(msg):
    global trouble
    trouble = True
    print(msg, file=sys.stderr)

def fname_is_c(fname):
    return fname.endswith(".h") or fname.endswith(".c")

INCLUDE_PATTERN = re.compile(r'\s*#\s*include\s+"([^"]*)"')
RULES_FNAME = ".may_include"

class Rules(object):
    def __init__(self):
        self.patterns = []

    def addPattern(self, pattern):
        self.patterns.append(pattern)

    def includeOk(self, path):
        for pattern in self.patterns:
            if fnmatch.fnmatchcase(path, pattern):
                return True
        return False

    def applyToLines(self, lines, context=""):
        lineno = 0
        for line in lines:
            lineno += 1
            m = INCLUDE_PATTERN.match(line)
            if m:
                include = m.group(1)
                if not self.includeOk(include):
                    err("Forbidden include of {} on line {}{}".format(
                        include, lineno, context))

    def applyToFile(self, fname):
        with open(fname, 'r') as f:
            #print(fname)
            self.applyToLines(iter(f), " of {}".format(fname))

def load_include_rules(fname):
    result = Rules()
    with open(fname, 'r') as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            result.addPattern(line)
    return result

for dirpath, dirnames, fnames in os.walk("src"):
    if ".may_include" in fnames:
        rules = load_include_rules(os.path.join(dirpath, RULES_FNAME))
        for fname in fnames:
            if fname_is_c(fname):
                rules.applyToFile(os.path.join(dirpath,fname))

if trouble:
    err(
"""To change which includes are allowed in a C file, edit the {} files in its
enclosing directory.""".format(RULES_FNAME))
    sys.exit(1)
