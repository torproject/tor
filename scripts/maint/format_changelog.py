#!/usr/bin/python
# Copyright (c) 2014, The Tor Project, Inc.
# See LICENSE for licensing information
#
# This script reformats a section of the changelog to wrap everything to
# the right width and put blank lines in the right places.  Eventually,
# it might include a linter.
#
# To run it, pipe a section of the changelog (starting with "Changes
# in Tor 0.x.y.z-alpha" through the script.)

import os
import re
import sys

# ==============================
# Oh, look!  It's a cruddy approximation to Knuth's elegant text wrapping
# algorithm, with totally ad hoc parameters!
#
# We're trying to minimize:
#    The total of the cubes of ragged space on underflowed intermediate lines,
#  PLUS
#    100 * the fourth power of overflowed characters
#  PLUS
#    .1 * a bit more than the cube of ragged space on the last line.
#  PLUS
#    OPENPAREN_PENALTY for each line that starts with (
#
# We use an obvious dynamic programming algorithm to sorta approximate this.
# It's not coded right or optimally, but it's fast enough for changelogs
#
# (Code found in an old directory of mine, lightly cleaned. -NM)

NO_HYPHENATE=set("""
pf-divert
""".split())

LASTLINE_UNDERFLOW_EXPONENT = 1
LASTLINE_UNDERFLOW_PENALTY = 1

UNDERFLOW_EXPONENT = 3
UNDERFLOW_PENALTY = 1

OVERFLOW_EXPONENT = 4
OVERFLOW_PENALTY = 2000

ORPHAN_PENALTY = 10000

OPENPAREN_PENALTY = 200

def generate_wrapping(words, divisions):
    lines = []
    last = 0
    for i in divisions:
        w = words[last:i]
        last = i
        line = " ".join(w).replace("\xff ","-").replace("\xff","-")
        lines.append(line)
    return lines

def wrapping_quality(words, divisions, width1, width2):
    total = 0.0

    lines = generate_wrapping(words, divisions)
    for line in lines:
        length = len(line)
        if line is lines[0]:
            width = width1
        else:
            width = width2

        if line[0:1] == '(':
            total += OPENPAREN_PENALTY

        if length > width:
            total += OVERFLOW_PENALTY * (
                (length - width) ** OVERFLOW_EXPONENT )
        else:
            if line is lines[-1]:
                e,p = (LASTLINE_UNDERFLOW_EXPONENT, LASTLINE_UNDERFLOW_PENALTY)
                if " " not in line:
                    total += ORPHAN_PENALTY
            else:
                e,p = (UNDERFLOW_EXPONENT, UNDERFLOW_PENALTY)

            total += p * ((width - length) ** e)

    return total

def wrap_graf(words, prefix_len1=0, prefix_len2=0, width=72):
    wrapping_after = [ (0,), ]

    w1 = width - prefix_len1
    w2 = width - prefix_len2

    for i in range(1, len(words)+1):
        best_so_far = None
        best_score = 1e300
        for j in range(i):
            t = wrapping_after[j]
            t1 = t[:-1] + (i,)
            t2 = t + (i,)
            wq1 = wrapping_quality(words, t1, w1, w2)
            wq2 = wrapping_quality(words, t2, w1, w2)

            if wq1 < best_score:
                best_so_far = t1
                best_score = wq1
            if wq2 < best_score:
                best_so_far = t2
                best_score = wq2
        wrapping_after.append( best_so_far )

    lines = generate_wrapping(words, wrapping_after[-1])

    return lines

def hyphenateable(word):
    if re.match(r'^[^\d\-]\D*-', word):
        stripped = re.sub(r'^\W+','',word)
        stripped = re.sub(r'\W+$','',word)
        return stripped not in NO_HYPHENATE
    else:
        return False

def split_paragraph(s):
    "Split paragraph into words; tuned for Tor."

    r = []
    for word in s.split():
        if hyphenateable(word):
            while "-" in word:
                a,word = word.split("-",1)
                r.append(a+"\xff")
        r.append(word)
    return r

def fill(text, width, initial_indent, subsequent_indent):
    words = split_paragraph(text)
    lines = wrap_graf(words, len(initial_indent), len(subsequent_indent),
                      width)
    res = [ initial_indent, lines[0], "\n" ]
    for line in lines[1:]:
        res.append(subsequent_indent)
        res.append(line)
        res.append("\n")
    return "".join(res)

# ==============================


TP_MAINHEAD = 0
TP_HEADTEXT = 1
TP_BLANK = 2
TP_SECHEAD = 3
TP_ITEMFIRST = 4
TP_ITEMBODY = 5
TP_END = 6
TP_PREHEAD = 7

def head_parser(line):
    if re.match(r'^Changes in', line):
        return TP_MAINHEAD
    elif re.match(r'^[A-Za-z]', line):
        return TP_PREHEAD
    elif re.match(r'^  o ', line):
        return TP_SECHEAD
    elif re.match(r'^\s*$', line):
        return TP_BLANK
    else:
        return TP_HEADTEXT

def body_parser(line):
    if re.match(r'^  o ', line):
        return TP_SECHEAD
    elif re.match(r'^    -',line):
        return TP_ITEMFIRST
    elif re.match(r'^      \S', line):
        return TP_ITEMBODY
    elif re.match(r'^\s*$', line):
        return TP_BLANK
    elif re.match(r'^Changes in', line):
        return TP_END
    elif re.match(r'^\s+\S', line):
        return TP_HEADTEXT
    else:
        print "Weird line %r"%line

class ChangeLog(object):
    def __init__(self):
        self.prehead = []
        self.mainhead = None
        self.headtext = []
        self.curgraf = None
        self.sections = []
        self.cursection = None
        self.lineno = 0

    def addLine(self, tp, line):
        self.lineno += 1

        if tp == TP_MAINHEAD:
            assert not self.mainhead
            self.mainhead = line

        elif tp == TP_PREHEAD:
            self.prehead.append(line)

        elif tp == TP_HEADTEXT:
            if self.curgraf is None:
                self.curgraf = []
                self.headtext.append(self.curgraf)
            self.curgraf.append(line)

        elif tp == TP_BLANK:
            self.curgraf = None

        elif tp == TP_SECHEAD:
            self.cursection = [ self.lineno, line, [] ]
            self.sections.append(self.cursection)

        elif tp == TP_ITEMFIRST:
            item = ( self.lineno, [ [line] ])
            self.curgraf = item[1][0]
            self.cursection[2].append(item)

        elif tp == TP_ITEMBODY:
            if self.curgraf is None:
                self.curgraf = []
                self.cursection[2][-1][1].append(self.curgraf)
            self.curgraf.append(line)

        else:
            assert "This" is "unreachable"

    def lint_head(self, line, head):
        m = re.match(r'^ *o ([^\(]+)((?:\([^\)]+\))?):', head)
        if not m:
            print >>sys.stderr, "Weird header format on line %s"%line

    def lint_item(self, line, grafs, head_type):
        pass

    def lint(self):
        self.head_lines = {}
        for sec_line, sec_head, items in self.sections:
            head_type = self.lint_head(sec_line, sec_head)
            for item_line, grafs in items:
                self.lint_item(item_line, grafs, head_type)

    def dumpGraf(self,par,indent1,indent2=-1):
        if indent2 == -1:
            indent2 = indent1
        text = " ".join(re.sub(r'\s+', ' ', line.strip()) for line in par)

        sys.stdout.write(fill(text,
                              width=72,
                              initial_indent=" "*indent1,
                              subsequent_indent=" "*indent2))

    def dump(self):
        if self.prehead:
            self.dumpGraf(self.prehead, 0)
            print
        print self.mainhead
        for par in self.headtext:
            self.dumpGraf(par, 2)
            print
        for _,head,items in self.sections:
            if not head.endswith(':'):
                print >>sys.stderr, "adding : to %r"%head
                head = head + ":"
            print head
            for _,grafs in items:
                self.dumpGraf(grafs[0],4,6)
                for par in grafs[1:]:
                    print
                    self.dumpGraf(par,6,6)
            print
        print

CL = ChangeLog()
parser = head_parser

if len(sys.argv) == 1:
    fname = 'ChangeLog'
else:
    fname = sys.argv[1]

fname_new = fname+".new"

sys.stdin = open(fname, 'r')

nextline = None

for line in sys.stdin:
    line = line.rstrip()
    tp = parser(line)

    if tp == TP_SECHEAD:
        parser = body_parser
    elif tp == TP_END:
        nextline = line
        break

    CL.addLine(tp,line)

CL.lint()

sys.stdout = open(fname_new, 'w')

CL.dump()

if nextline is not None:
    print nextline

for line in sys.stdin:
    sys.stdout.write(line)

os.rename(fname_new, fname)
