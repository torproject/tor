#!/usr/bin/env python

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
    "Directory authority changes",

    # These aren't preferred, but sortChanges knows how to clean them up.
    "Code simplifications and refactoring",
    "Code simplification and refactorings",
    "Code simplifications and refactorings"])

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

def split_tor_version(version):
    '''
    Return the initial numeric components of the Tor version as a list of ints.
    For versions earlier than 0.1.0, returns MAJOR, MINOR, and MICRO.
    For versions 0.1.0 and later, returns MAJOR, MINOR, MICRO, and PATCHLEVEL if present.

    If the version is malformed, returns None.
    '''
    version_match = re.match('([0-9]+)\.([0-9]+)\.([0-9]+)(\.([0-9]+))?', version)
    if version_match is None:
        return None

    version_groups = version_match.groups()
    if version_groups is None:
        return None
    if len(version_groups) < 3:
        return None

    if len(version_groups) != 5:
        return None
    version_components = version_groups[0:3]
    version_components += version_groups[4:5]

    try:
        version_list = [int(v) for v in version_components if v is not None]
    except ValueError:
        return None

    return version_list

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
        else:
            bugfix_match = re.search('bugfix on ([0-9]+\.[0-9]+\.[0-9]+)', contents)
            if bugfix_match is None:
                warn("Versions must have at least 3 digits. ('0.1.2', '0.3.4.8', or '0.3.5.1-alpha'.)")
            elif bugfix_match.group(0) is None:
                warn("Versions must have at least 3 digits. ('0.1.2', '0.3.4.8', or '0.3.5.1-alpha'.)")
            else:
                bugfix_match = re.search('bugfix on ([0-9a-z][-.0-9a-z]+[0-9a-z])', contents)
                bugfix_group = bugfix_match.groups() if bugfix_match is not None else None
                bugfix_version = bugfix_group[0] if bugfix_group is not None else None
                package_version = os.environ.get('PACKAGE_VERSION', None)
                if bugfix_version is None:
                    # This should be unreachable, unless the patterns are out of sync
                    warn("Malformed bugfix version.")
                elif package_version is not None:
                    # If $PACKAGE_VERSION isn't set, skip this check
                    bugfix_split = split_tor_version(bugfix_version)
                    package_split = split_tor_version(package_version)
                    if bugfix_split is None:
                        # This should be unreachable, unless the patterns are out of sync
                        warn("Malformed bugfix version: '{}'.".format(bugfix_version))
                    elif package_split is None:
                        # This should be unreachable, unless the patterns are out of sync, or the package versioning scheme has changed
                        warn("Malformed $PACKAGE_VERSION: '{}'.".format(package_version))
                    elif bugfix_split > package_split:
                        warn("Bugfixes must be made on earlier versions (or this version). (Bugfix on version: '{}', current tor package version: '{}'.)".format(bugfix_version, package_version))

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
