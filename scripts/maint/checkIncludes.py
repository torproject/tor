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

if sys.version_info[0] <= 2:
    def open_file(fname):
        return open(fname, 'r')
else:
    def open_file(fname):
        return open(fname, 'r', encoding='utf-8')

def warn(msg):
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

class Error(object):
    def __init__(self, location, msg):
        self.location = location
        self.msg = msg

    def __str__(self):
        return "{} at {}".format(self.msg, self.location)

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

    def applyToLines(self, lines, loc_prefix=""):
        lineno = 0
        for line in lines:
            lineno += 1
            m = INCLUDE_PATTERN.match(line)
            if m:
                include = m.group(1)
                if not self.includeOk(include):
                    yield Error("{}{}".format(loc_prefix,str(lineno)),
                                "Forbidden include of {}".format(include))

    def applyToFile(self, fname):
        with open_file(fname) as f:
            #print(fname)
            for error in self.applyToLines(iter(f), "{}:".format(fname)):
                yield error

    def noteUnusedRules(self):
        for p in self.patterns:
            if p not in self.usedPatterns:
                warn("Pattern {} in {} was never used.".format(p, self.dirpath))

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

include_rules_cache = {}

def load_include_rules(fname):
    """ Read a rules file from 'fname', and return it as a Rules object.
        Return 'None' if fname does not exist.
    """
    if fname in include_rules_cache:
        return include_rules_cache[fname]
    if not os.path.exists(fname):
        include_rules_cache[fname] = None
        return None
    result = Rules(os.path.split(fname)[0])
    with open_file(fname) as f:
        for line in f:
            line = line.strip()
            if line.startswith("#") or not line:
                continue
            result.addPattern(line)
    include_rules_cache[fname] = result
    return result

def get_all_include_rules():
    """Return a list of all the Rules objects we have loaded so far,
       sorted by their directory names."""
    return [ rules for (fname,rules) in
             sorted(include_rules_cache.items())
             if rules is not None ]

def remove_self_edges(graph):
    """Takes a directed graph in as an adjacency mapping (a mapping from
       node to a list of the nodes to which it connects).

       Remove all edges from a node to itself."""

    for k in list(graph):
        graph[k] = [ d for d in graph[k] if d != k ]

def toposort(graph, limit=100):
    """Takes a directed graph in as an adjacency mapping (a mapping from
       node to a list of the nodes to which it connects).  Tries to
       perform a topological sort on the graph, arranging the nodes into
       "levels", such that every member of each level is only reachable
       by members of later levels.

       Returns a list of the members of each level.

       Modifies the input graph, removing every member that could be
       sorted.  If the graph does not become empty, then it contains a
       cycle.

       "limit" is the max depth of the graph after which we give up trying
       to sort it and conclude we have a cycle.
    """
    all_levels = []

    n = 0
    while graph:
        n += 0
        cur_level = []
        all_levels.append(cur_level)
        for k in list(graph):
            graph[k] = [ d for d in graph[k] if d in graph ]
            if graph[k] == []:
                cur_level.append(k)
        for k in cur_level:
            del graph[k]
        n += 1
        if n > limit:
            break

    return all_levels

def consider_include_rules(fname):
    dirpath = os.path.split(fname)[0]
    rules_fname = os.path.join(dirpath, RULES_FNAME)
    rules = load_include_rules(os.path.join(dirpath, RULES_FNAME))
    if rules is None:
        return

    for err in rules.applyToFile(fname):
        yield err

if __name__ == '__main__':
    list_unused = False
    log_sorted_levels = False

    trouble = False

    for dirpath, dirnames, fnames in os.walk("src"):
        for fname in fnames:
            if fname_is_c(fname):
                fullpath = os.path.join(dirpath,fname)
                for err in consider_include_rules(fullpath):
                    print(err, file=sys.stderr)
                    trouble = True

    if trouble:
        err(
    """To change which includes are allowed in a C file, edit the {}
    files in its enclosing directory.""".format(RULES_FNAME))
        sys.exit(1)

    if list_unused:
        for rules in get_all_include_rules():
            rules.noteUnusedRules()

    uses_dirs = { }
    for rules in get_all_include_rules():
        uses_dirs[rules.incpath] = rules.getAllowedDirectories()

    remove_self_edges(uses_dirs)
    all_levels = toposort(uses_dirs)

    if log_sorted_levels:
        for (n, cur_level) in enumerate(all_levels):
            if cur_level:
                print(n, cur_level)

    if uses_dirs:
        print("There are circular .may_include dependencies in here somewhere:",
              uses_dirs)
        sys.exit(1)
