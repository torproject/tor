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

import re
import sys
import textwrap

TP_MAINHEAD = 0
TP_HEADTEXT = 1
TP_BLANK = 2
TP_SECHEAD = 3
TP_ITEMFIRST = 4
TP_ITEMBODY = 5

def head_parser(line):
    if re.match(r'^[A-Z]', line):
        return TP_MAINHEAD
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
    else:
        print "Weird line %r"%line

class ChangeLog(object):
    def __init__(self):
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
                self.cursection[2][1][-1].append(self.curgraf)
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
        print textwrap.fill(text, width=72,
                            initial_indent=" "*indent1,
                            subsequent_indent=" "*indent2)

    def dump(self):
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

for line in sys.stdin:
    line = line.rstrip()
    tp = parser(line)

    CL.addLine(tp,line)
    if tp == TP_SECHEAD:
        parser = body_parser

CL.lint()
CL.dump()
