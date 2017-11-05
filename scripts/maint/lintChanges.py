#!/usr/bin/python

from __future__ import print_function
from __future__ import with_statement
import sys
import re
import os


KNOWN_GROUPS = set([
    "Minor bugfix",
    "Minor bugfixes",
    "Major bugfix",
    "Major bugfixes",
    "Minor feature",
    "Minor features",
    "Major feature",
    "Major features",
    "New system requirements",
    "Testing",
    "Documentation",
    "Code simplification and refactoring",
    "Removed features",
    "Deprecated features",
    "Directory authority changes"])

NEEDS_SUBCATEGORIES = set([
    "Minor bugfix",
    "Minor bugfixes",
    "Major bugfix",
    "Major bugfixes",
    "Minor feature",
    "Minor features",
    "Major feature",
    "Major features",
    ])

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

    m = re.match(r'^[ ]{2}o ([^\(:]*)([^:]*):', contents)
    if not m:
        warn("Header not in format expected. ('  o Foo:' or '  o Foo (Bar):')")
    elif m.group(1).strip() not in KNOWN_GROUPS:
        warn("Unrecognized header: %r" % m.group(1))
    elif (m.group(1) in NEEDS_SUBCATEGORIES and '(' not in m.group(2)):
        warn("Missing subcategory on %r" % m.group(1))

    if m:
        isBug = ("bug" in m.group(1).lower() or "fix" in m.group(1).lower())
    else:
        isBug = False

    contents = " ".join(contents.split())

    if re.search(r'\#\d{2,}', contents):
        warn("Don't use a # before ticket numbers. ('bug 1234' not '#1234')")

    if isBug and not re.search(r'(\d+)', contents):
        warn("Ticket marked as bugfix, but does not mention a number.")
    elif isBug and not re.search(r'Fixes ([a-z ]*)bugs? (\d+)', contents):
        warn("Ticket marked as bugfix, but does not say 'Fixes bug XXX'")

    if re.search(r'[bB]ug (\d+)', contents):
        if not re.search(r'[Bb]ugfix on ', contents):
            warn("Bugfix does not say 'bugfix on X.Y.Z'")
        elif not re.search('[fF]ixes ([a-z ]*)bugs? (\d+)((, \d+)* and \d+)?; bugfix on ',
                           contents):
            warn("Bugfix does not say 'Fixes bug X; bugfix on Y'")
        elif re.search('tor-([0-9]+)', contents):
            warn("Do not prefix versions with 'tor-'. ('0.1.2', not 'tor-0.1.2'.)")

    return have_warned != []

def files(args):
    """Walk through the arguments: for directories, yield their contents;
       for files, just yield the files. Only search one level deep, because
       that's how the changes directory is laid out."""
    for f in args:
        if os.path.isdir(f):
            for item in os.listdir(f):
                if item.startswith("."): #ignore dotfiles
                    continue
                yield os.path.join(f, item)
        else:
            yield f

if __name__ == '__main__':
    problems = 0
    for fname in files(sys.argv[1:]):
        if fname.endswith("~"):
            continue
        if lintfile(fname):
            problems += 1

    if problems:
        sys.exit(1)
    else:
        sys.exit(0)
