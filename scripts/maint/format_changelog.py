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
import optparse

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
tor-resolve
tor-gencert
tor-fw-helper
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

def hyphenatable(word):
    if "--" in word:
        return False

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
        if hyphenatable(word):
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

def clean_head(head):
    return head

def head_score(s):
    m = re.match(r'^ +o (.*)', s)
    if not m:
        print >>sys.stderr, "Can't score %r"%s
        return 99999
    lw = m.group(1).lower()
    if lw.startswith("security") and "feature" not in lw:
        score = -300
    elif lw.startswith("deprecated version"):
        score = -200
    elif (('new' in lw and 'requirement' in lw) or
          ('new' in lw and 'dependenc' in lw) or
          ('build' in lw and 'requirement' in lw) or
          ('removed' in lw and 'platform' in lw)):
        score = -100
    elif lw.startswith("major feature"):
        score = 00
    elif lw.startswith("major bug"):
        score = 50
    elif lw.startswith("major"):
        score = 70
    elif lw.startswith("minor feature"):
        score = 200
    elif lw.startswith("minor bug"):
        score = 250
    elif lw.startswith("minor"):
        score = 270
    else:
        score = 1000

    if 'secur' in lw:
        score -= 2

    if "(other)" in lw:
        score += 2

    if '(' not in lw:
        score -= 1

    return score

class ChangeLog(object):
    def __init__(self, wrapText=True, blogOrder=True):
        self.prehead = []
        self.mainhead = None
        self.headtext = []
        self.curgraf = None
        self.sections = []
        self.cursection = None
        self.lineno = 0
        self.wrapText = wrapText
        self.blogOrder = blogOrder

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
        if not self.wrapText:
            for line in par:
                print line
            return

        if indent2 == -1:
            indent2 = indent1
        text = " ".join(re.sub(r'\s+', ' ', line.strip()) for line in par)

        sys.stdout.write(fill(text,
                              width=72,
                              initial_indent=" "*indent1,
                              subsequent_indent=" "*indent2))

    def dumpPreheader(self, graf):
        self.dumpGraf(graf, 0)
        print

    def dumpMainhead(self, head):
        print head

    def dumpHeadGraf(self, graf):
        self.dumpGraf(graf, 2)
        print

    def dumpSectionHeader(self, header):
        print header

    def dumpStartOfSections(self):
        pass

    def dumpEndOfSections(self):
        pass

    def dumpEndOfSection(self):
        print

    def dumpEndOfChangelog(self):
        print

    def dumpItem(self, grafs):
        self.dumpGraf(grafs[0],4,6)
        for par in grafs[1:]:
            print
            self.dumpGraf(par,6,6)

    def collateAndSortSections(self):
        heads = []
        sectionsByHead = { }
        for _, head, items in self.sections:
            head = clean_head(head)
            try:
                s = sectionsByHead[head]
            except KeyError:
                s = sectionsByHead[head] = []
                heads.append( (head_score(head), head.lower(), head, s) )

            s.extend(items)

        heads.sort()
        self.sections = [ (0, head, items) for _1,_2,head,items in heads ]

    def dump(self):
        if self.prehead:
            self.dumpPreheader(self.prehead)

        if not self.blogOrder:
            self.dumpMainhead(self.mainhead)

        for par in self.headtext:
            self.dumpHeadGraf(par)

        if self.blogOrder:
            self.dumpMainhead(self.mainhead)

        self.dumpStartOfSections()
        for _,head,items in self.sections:
            if not head.endswith(':'):
                print >>sys.stderr, "adding : to %r"%head
                head = head + ":"
            self.dumpSectionHeader(head)
            for _,grafs in items:
                self.dumpItem(grafs)
            self.dumpEndOfSection()
        self.dumpEndOfSections()
        self.dumpEndOfChangelog()

class HTMLChangeLog(ChangeLog):
    def __init__(self, *args, **kwargs):
        ChangeLog.__init__(self, *args, **kwargs)

    def htmlText(self, graf):
        for line in graf:
            line = line.rstrip().replace("&","&amp;")
            line = line.rstrip().replace("<","&lt;").replace(">","&gt;")
            sys.stdout.write(line.strip())
            sys.stdout.write(" ")

    def htmlPar(self, graf):
        sys.stdout.write("<p>")
        self.htmlText(graf)
        sys.stdout.write("</p>\n")

    def dumpPreheader(self, graf):
        self.htmlPar(graf)

    def dumpMainhead(self, head):
        sys.stdout.write("<h2>%s</h2>"%head)

    def dumpHeadGraf(self, graf):
        self.htmlPar(graf)

    def dumpSectionHeader(self, header):
        header = header.replace(" o ", "", 1).lstrip()
        sys.stdout.write("  <li>%s\n"%header)
        sys.stdout.write("  <ul>\n")

    def dumpEndOfSection(self):
        sys.stdout.write("  </ul>\n\n")

    def dumpEndOfChangelog(self):
        pass

    def dumpStartOfSections(self):
        print "<ul>\n"

    def dumpEndOfSections(self):
        print "</ul>\n"

    def dumpItem(self, grafs):
        grafs[0][0] = grafs[0][0].replace(" - ", "", 1).lstrip()
        sys.stdout.write("  <li>")
        if len(grafs) > 1:
            for par in grafs:
                self.htmlPar(par)
        else:
            self.htmlText(grafs[0])
        print

op = optparse.OptionParser(usage="usage: %prog [options] [filename]")
op.add_option('-W', '--no-wrap', action='store_false',
              dest='wrapText', default=True,
              help='Do not re-wrap paragraphs')
op.add_option('-S', '--no-sort', action='store_false',
              dest='sort', default=True,
              help='Do not sort or collate sections')
op.add_option('-o', '--output', dest='output',
              default=None, metavar='FILE', help="write output to FILE")
op.add_option('-H', '--html', action='store_true',
              dest='html', default=False,
              help="generate an HTML fragment")
op.add_option('-1', '--first', action='store_true',
              dest='firstOnly', default=False,
              help="write only the first section")
op.add_option('-b', '--blog-format', action='store_true',
              dest='blogOrder', default=False,
              help="Write the header in blog order")

options,args = op.parse_args()

if len(args) > 1:
    op.error("Too many arguments")
elif len(args) == 0:
    fname = 'ChangeLog'
else:
    fname = args[0]

if options.output == None:
    options.output = fname

if fname != '-':
    sys.stdin = open(fname, 'r')

nextline = None

if options.html:
    ChangeLogClass = HTMLChangeLog
else:
    ChangeLogClass = ChangeLog

CL = ChangeLogClass(wrapText=options.wrapText, blogOrder=options.blogOrder)
parser = head_parser

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

if options.output != '-':
    fname_new = options.output+".new"
    fname_out = options.output
    sys.stdout = open(fname_new, 'w')
else:
    fname_new = fname_out = None

if options.sort:
    CL.collateAndSortSections()

CL.dump()

if options.firstOnly:
    sys.exit(0)

if nextline is not None:
    print nextline

for line in sys.stdin:
    sys.stdout.write(line)

if fname_new is not None:
    os.rename(fname_new, fname_out)
