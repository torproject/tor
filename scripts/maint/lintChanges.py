#!/usr/bin/python

import sys
import re



def lintfile(fname):
    have_warned = []
    def warn(s):
        if not have_warned:
            have_warned.append(1)
            print fname,":"
        print "\t",s

    m = re.search(r'(\d{3,})', fname)
    if m:
        bugnum = m.group(1)
    else:
        bugnum = None

    with open(fname) as f:
        contents = f.read()

    if bugnum and bugnum not in contents:
        warn("bug number %s does not appear"%bugnum)

    lines = contents.split("\n")
    isBug = ("bug" in lines[0] or "fix" in lines[0])

    if not re.match(r'^ +o (.*)', contents):
        warn("header not in format expected")

    contents = " ".join(contents.split())

    if isBug and not re.search(r'(\d+)', contents):
        warn("bugfix does not mention a number")
    elif isBug and not re.search(r'Fixes ([a-z ]*)bug (\d+)', contents):
        warn("bugfix does not say 'Fixes bug XXX'")

    if re.search(r'[bB]ug (\d+)', contents):
        if not re.search(r'[Bb]ugfix on ', contents):
            warn("bugfix does not say 'bugfix on X.Y.Z'")
        elif not re.search('[fF]ixes ([a-z ]*)bug (\d+); bugfix on ', contents):
            warn("bugfix incant is not semicoloned")


if __name__=='__main__':
    for fname in sys.argv[1:]:
        if fname.endswith("~"):
            continue
        lintfile(fname)
