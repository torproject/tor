#!/usr/bin/python
#
#  Copyright (c) 2008-2015, The Tor Project, Inc.
#  See LICENSE for licensing information.
#
# Hi!
# I'm redox.py, the Tor redocumentation tool!
# I am a horrible hack!
# I read the output of doxygen from stderr, and add missing DOCDOC comments
#   to tell you where documentation should go!
# To use me, edit the stuff below...
#  ...and run 'make doxygen 2>doxygen.stderr' ...
#  ...and run ./scripts/maint/redox.py < doxygen.stderr !
# I'll make a bunch of new files by adding missing DOCDOC comments to your
#    source.  Those files will have names like ./src/common/util.c.newdoc.
# You will want to look over the changes by hand before checking them in.
#
# So, here's your workflow:
#
# 0. Make sure you're running a bourne shell for the redirects below.
# 1. make doxygen 1>doxygen.stdout 2>doxygen.stderr.
# 2. grep Warning doxygen.stderr | grep -v 'is not documented' | less
#      [This will tell you about all the bogus doxygen output you have]
# 3. python ./scripts/maint/redox.py <doxygen.stderr
#      [This will make lots of .newdoc files with DOCDOC comments for
#       whatever was missing documentation.]
# 4. Look over those .newdoc files, and see which docdoc comments you
#     want to merge into the main file.  If it's all good, just run
#     "mv fname.c.newdoc fname.c".  Otherwise, you'll need to merge
#     the parts you like by hand.

# Which files should we ignore warning from?  Mostly, these are external
# files that we've snarfed in from somebody else, whose C we do no intend
# to document for them.
SKIP_FILES = [ "OpenBSD_malloc_Linux.c",
               "eventdns.c",
               "eventdns.h",
               "strlcat.c",
               "strlcpy.c",
               "sha256.c",
               "sha256.h",
               "aes.c",
               "aes.h" ]

# What names of things never need javadoc
SKIP_NAME_PATTERNS = [ r'^.*_c_id$',
                       r'^.*_H_ID$' ]

# Which types of things should get DOCDOC comments added if they are
# missing documentation?  Recognized types are in KINDS below.
ADD_DOCDOCS_TO_TYPES = [ 'function', 'type', 'typedef' ]
ADD_DOCDOCS_TO_TYPES += [ 'variable', ]

# ====================
# The rest of this should not need hacking.

import re
import sys

KINDS = [ "type", "field", "typedef", "define", "function", "variable",
          "enumeration" ]

NODOC_LINE_RE = re.compile(r'^([^:]+):(\d+): (\w+): (.*) is not documented\.$')

THING_RE = re.compile(r'^Member ([a-zA-Z0-9_]+).*\((typedef|define|function|variable|enumeration|macro definition)\) of (file|class) ')

SKIP_NAMES = [re.compile(s) for s in SKIP_NAME_PATTERNS]

def parsething(thing):
    """I figure out what 'foobar baz in quux quum is not documented' means,
       and return: the name of the foobar, and the kind of the foobar.
    """
    if thing.startswith("Compound "):
        tp, name = "type", thing.split()[1]
    else:
        m = THING_RE.match(thing)
        if not m:
            print thing, "???? Format didn't match."
            return None, None
        else:
            name, tp, parent = m.groups()
            if parent == 'class':
                if tp == 'variable' or tp == 'function':
                    tp = 'field'

    return name, tp

def read():
    """I snarf doxygen stderr from stdin, and parse all the "foo has no
       documentation messages.  I return a map from filename to lists
       of tuples of (alleged line number, name of thing, kind of thing)
    """
    errs = {}
    for line in sys.stdin:
        m = NODOC_LINE_RE.match(line)
        if m:
            file, line, tp, thing = m.groups()
            assert tp.lower() == 'warning'
            name, kind = parsething(thing)
            errs.setdefault(file, []).append((int(line), name, kind))

    return errs

def findline(lines, lineno, ident):
    """Given a list of all the lines in the file (adjusted so 1-indexing works),
       a line number that ident is alledgedly on, and ident, I figure out
       the line where ident was really declared."""
    lno = lineno
    for lineno in xrange(lineno, 0, -1):
        try:
            if ident in lines[lineno]:
                return lineno
        except IndexError:
            continue

    return None

FUNC_PAT = re.compile(r"^[A-Za-z0-9_]+\(")

def hascomment(lines, lineno, kind):
    """I return true if it looks like there's already a good comment about
       the thing on lineno of lines of type kind. """
    if "*/" in lines[lineno-1]:
        return True
    if kind == 'function' and FUNC_PAT.match(lines[lineno]):
        if "*/" in lines[lineno-2]:
            return True
    return False

def hasdocdoc(lines, lineno, kind):
    """I return true if it looks like there's already a docdoc comment about
       the thing on lineno of lines of type kind."""
    try:
        if "DOCDOC" in lines[lineno]:
            return True
    except IndexError:
        pass
    try:
        if "DOCDOC" in lines[lineno-1]:
            return True
    except IndexError:
        pass
    if kind == 'function' and FUNC_PAT.match(lines[lineno]):
        if "DOCDOC" in lines[lineno-2]:
            return True
    return False

def checkf(fn, errs):
    """I go through the output of read() for a single file, and build a list
       of tuples of things that want DOCDOC comments.  Each tuple has:
       the line number where the comment goes; the kind of thing; its name.
    """
    for skip in SKIP_FILES:
        if fn.endswith(skip):
            print "Skipping",fn
            return

    comments = []
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

                comments.append((ln, kind, name))

    return comments

def applyComments(fn, entries):
    """I apply lots of comments to the file in fn, making a new .newdoc file.
    """
    N = 0

    lines = [ None ]
    try:
        lines.extend( open(fn, 'r').readlines() )
    except IOError:
        return

    # Process the comments in reverse order by line number, so that
    # the line numbers for the ones we haven't added yet remain valid
    # until we add them.  Standard trick.
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

for fn, errs in e.iteritems():
    print `(fn, errs)`
    comments = checkf(fn, errs)
    if comments:
        applyComments(fn, comments)
