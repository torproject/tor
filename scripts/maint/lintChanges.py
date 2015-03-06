#!/usr/bin/python

from __future__ import print_function
from __future__ import with_statement
import sys
import re
import os


def lintfile(fname):
    have_warned = []

    def warn(s):
        if not have_warned:
            have_warned.append(1)
            print("{}:".format(fname))
        print("\t{}".format(s))

    m = re.search(r'(\d{3,})', os.path.basename(fname))
    if m:
        bugnum = m.group(1)
    else:
        bugnum = None

    with open(fname) as f:
        contents = f.read()

    if bugnum and bugnum not in contents:
        warn("bug number {} does not appear".format(bugnum))

    lines = contents.split("\n")
    isBug = ("bug" in lines[0] or "fix" in lines[0])

    if not re.match(r'^[ ]{2}o (.*)', contents):
        warn("header not in format expected")

    contents = " ".join(contents.split())

    if re.search(r'\#\d{2,}', contents):
        warn("don't use a # before ticket numbers")

    if isBug and not re.search(r'(\d+)', contents):
        warn("bugfix does not mention a number")
    elif isBug and not re.search(r'Fixes ([a-z ]*)bug (\d+)', contents):
        warn("bugfix does not say 'Fixes bug XXX'")

    if re.search(r'[bB]ug (\d+)', contents):
        if not re.search(r'[Bb]ugfix on ', contents):
            warn("bugfix does not say 'bugfix on X.Y.Z'")
        elif not re.search('[fF]ixes ([a-z ]*)bug (\d+); bugfix on ',
                           contents):
            warn("bugfix incant is not semicoloned")


if __name__ == '__main__':
    for fname in sys.argv[1:]:
        if fname.endswith("~"):
            continue
        lintfile(fname)
