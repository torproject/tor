#!/usr/bin/python
#
#  Copyright (c) 2008 The Tor Project, Inc.
#  See LICENSE for licensing information.
#
# Hi!
# I'm redox.py, the Tor redocumentation tool!
# I am a horrible hack!
# I read the output of doxygen from stderr, and add missing DOCDOC comments
#   to tell you where documentation should go!
# To use me, edit the stuff below...
#  ...and run 'make doxygen 2>doxygen.stderr' ...
#  ...and run ./contrib/redox.py < doxygen.stderr !
# I'll make a bunch of new files by adding missing DOCDOC comments to your
#    source.  Those files will have names like ./src/common/util.c.newdoc.
# You will want to look over the changes by hand before checking them in.

SKIP_FILES = [ "OpenBSD_malloc_Linux.c",
               "eventdns.c",
               "eventdns.h",
               "strlcat.c",
               "strlcpy.c",
               "aes.c",
               "aes.h" ]

SKIP_NAME_PATTERNS = [ r'^.*_c_id$' ]

ADD_DOCDOCS_TO_TYPES = [ 'function', 'type', 'typedef' ]
# ADD_DOCDOCS_TO_TYPES += [ 'variable', 'define' ]

# ====================
# The rest of this should not need hacking.

import re
import sys

KINDS = [ "type", "field", "typedef", "define", "function", "variable" ]

NODOC_LINE_RE = re.compile(r'^([^:]+):(\d+): (\w+): (.*) is not documented\.$')

THING_RE = re.compile(r'^Member ([a-zA-Z0-9_]+).*\((typedef|define|function|variable)\) of (file|class) ')

SKIP_NAMES = [re.compile(s) for s in SKIP_NAME_PATTERNS]

def parsething(thing):
    if thing.startswith("Compound "):
        tp, name = "type", thing.split()[1]
    else:
        m = THING_RE.match(thing)
        if not m:
            print thing
            return None, None
        else:
            name, tp, parent = m.groups()
            if parent == 'class':
                if tp == 'variable' or tp == 'function':
                    tp = 'field'

    return name, tp

def read():
    errs = {}
    for line in sys.stdin:
        m = NODOC_LINE_RE.match(line)
        if m:
            file, line, tp, thing = m.groups()
            assert tp == 'Warning'
            name, kind = parsething(thing)
            errs.setdefault(file, []).append((int(line), name, kind))

    return errs

def findline(lines, lineno, ident):
    for lineno in xrange(lineno, 0, -1):
        if ident in lines[lineno]:
            return lineno

    return None

FUNC_PAT = re.compile(r"^[A-Za-z0-9_]+\(")

def hascomment(lines, lineno, kind):
    if "*/" in lines[lineno-1]:
        return True
    if kind == 'function' and FUNC_PAT.match(lines[lineno]):
        if "*/" in lines[lineno-2]:
            return True
    return False

def hasdocdoc(lines, lineno, kind):
    if "DOCDOC" in lines[lineno] or "DOCDOC" in lines[lineno-1]:
        return True
    if kind == 'function' and FUNC_PAT.match(lines[lineno]):
        if "DOCDOC" in lines[lineno-2]:
            return True
    return False

def checkf(fn, errs, comments):

    for skip in SKIP_FILES:
        if fn.endswith(skip):
            print "Skipping",fn
            return

    lines = [ None ]
    try:
        lines.extend( open(fn, 'r').readlines() )
    except IOError:
        return

    for line, name, kind in errs:
        if any(pat.match(name) for pat in SKIP_NAMES):
            continue

        if kind not in ADD_DOCDOCS_TO_TYPES:
            continue

        ln = findline(lines, line, name)
        if ln == None:
            print "Couldn't find the definition of %s allegedly on %s of %s"%(
                name, line, fn)
        else:
            if hasdocdoc(lines, line, kind):
#                print "Has a DOCDOC"
#                print fn, line, name, kind
#                print "\t",lines[line-2],
#                print "\t",lines[line-1],
#                print "\t",lines[line],
#                print "-------"
                pass
            else:
                if kind == 'function' and FUNC_PAT.match(lines[ln]):
                    ln = ln - 1

                comments.setdefault(fn, []).append((ln, kind, name))

def applyComments(fn, entries):
    N = 0

    lines = [ None ]
    try:
        lines.extend( open(fn, 'r').readlines() )
    except IOError:
        return

    entries.sort()
    entries.reverse()

    for ln, kind, name in entries:

        lines.insert(ln, "/* DOCDOC %s */\n"%name)
        N += 1

    outf = open(fn+".newdoc", 'w')
    for line in lines[1:]:
        outf.write(line)
    outf.close()

    print "Added %s DOCDOCs to %s" %(N, fn)

e = read()
comments = {}

for fn, errs in e.iteritems():
    checkf(fn, errs, comments)

for fn, entries in comments.iteritems():
    applyComments(fn, entries)
