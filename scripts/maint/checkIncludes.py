#!/usr/bin/python
# Copyright 2018 The Tor Project, Inc.  See LICENSE file for licensing info.

"""This script looks through all the directories for files matching *.c or
   *.h, and checks their #include directives to make sure that only "permitted"
   headers are included.

   Any #include directives with angle brackets (like #include <stdio.h>) are
   ignored -- only directives with quotes (like #include "foo.h") are
   considered.

   To decide what includes are permitted, this script looks at a .may_include
   file in each directory.  This file contains empty lines, #-prefixed
   comments, filenames (like "lib/foo/bar.h") and file globs (like lib/*/*.h)
   for files that are permitted.
"""


from __future__ import print_function

import fnmatch
import os
import re
import sys

# Global: Have there been any errors?
trouble = False

if sys.version_info[0] <= 2:
    def open_file(fname):
        return open(fname, 'r')
else:
    def open_file(fname):
        return open(fname, 'r', encoding='utf-8')

def warn(msg):
    print(msg, file=sys.stderr)

def err(msg):
    """ Declare that an error has happened, and remember that there has
        been an error. """
    global trouble
    trouble = True
    print(msg, file=sys.stderr)

def fname_is_c(fname):
    """ Return true iff 'fname' is the name of a file that we should
        search for possibly disallowed #include directives. """
    return fname.endswith(".h") or fname.endswith(".c")

INCLUDE_PATTERN = re.compile(r'\s*#\s*include\s+"([^"]*)"')
RULES_FNAME = ".may_include"

ALLOWED_PATTERNS = [
    re.compile(r'^.*\*\.(h|inc)$'),
    re.compile(r'^.*/.*\.h$'),
    re.compile(r'^ext/.*\.c$'),
    re.compile(r'^orconfig.h$'),
    re.compile(r'^micro-revision.i$'),
]

def pattern_is_normal(s):
    for p in ALLOWED_PATTERNS:
        if p.match(s):
            return True
    return False

class Rules(object):
    """ A 'Rules' object is the parsed version of a .may_include file. """
    def __init__(self, dirpath):
        self.dirpath = dirpath
        if dirpath.startswith("src/"):
            self.incpath = dirpath[4:]
        else:
            self.incpath = dirpath
        self.patterns = []
        self.usedPatterns = set()

    def addPattern(self, pattern):
        if not pattern_is_normal(pattern):
            warn("Unusual pattern {} in {}".format(pattern, self.dirpath))
        self.patterns.append(pattern)

    def includeOk(self, path):
        for pattern in self.patterns:
            if fnmatch.fnmatchcase(path, pattern):
                self.usedPatterns.add(pattern)
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
        with open_file(fname) as f:
            #print(fname)
            self.applyToLines(iter(f), " of {}".format(fname))

    def noteUnusedRules(self):
        for p in self.patterns:
            if p not in self.usedPatterns:
                print("Pattern {} in {} was never used.".format(p, self.dirpath))

    def getAllowedDirectories(self):
        allowed = []
        for p in self.patterns:
            m = re.match(r'^(.*)/\*\.(h|inc)$', p)
            if m:
                allowed.append(m.group(1))
                continue
            m = re.match(r'^(.*)/[^/]*$', p)
            if m:
                allowed.append(m.group(1))
                continue

        return allowed

def load_include_rules(fname):
    """ Read a rules file from 'fname', and return it as a Rules object. """
    result = Rules(os.path.split(fname)[0])
    with open_file(fname) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            result.addPattern(line)
    return result

list_unused = False
log_sorted_levels = False

uses_dirs = { }

for dirpath, dirnames, fnames in os.walk("src"):
    if ".may_include" in fnames:
        rules = load_include_rules(os.path.join(dirpath, RULES_FNAME))
        for fname in fnames:
            if fname_is_c(fname):
                rules.applyToFile(os.path.join(dirpath,fname))
        if list_unused:
            rules.noteUnusedRules()

        uses_dirs[rules.incpath] = rules.getAllowedDirectories()

if trouble:
    err(
"""To change which includes are allowed in a C file, edit the {}
files in its enclosing directory.""".format(RULES_FNAME))
    sys.exit(1)

all_levels = []

n = 0
while uses_dirs:
    n += 0
    cur_level = []
    for k in list(uses_dirs):
        uses_dirs[k] = [ d for d in uses_dirs[k]
                         if (d in uses_dirs and d != k)]
        if uses_dirs[k] == []:
            cur_level.append(k)
    for k in cur_level:
        del uses_dirs[k]
    n += 1
    if cur_level and log_sorted_levels:
        print(n, cur_level)
    if n > 100:
        break

if uses_dirs:
    print("There are circular .may_include dependencies in here somewhere:",
          uses_dirs)
    sys.exit(1)
