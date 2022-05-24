#!/usr/bin/env python

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import io
import os
import re
import sys
import time

def P(path):
    """
    Give 'path' as a path relative to the abs_top_srcdir environment
    variable.
    """
    return os.path.join(
        os.environ.get('abs_top_srcdir', "."),
        path)

def warn(msg):
    """
    Print an warning message.
    """
    print("WARNING: {}".format(msg), file=sys.stderr)

def find_version(infile):
    """
    Given an open file (or some other iterator of lines) holding a
    configure.ac file, find the current version line.
    """
    for line in infile:
        m = re.search(r'AC_INIT\(\[tor\],\s*\[([^\]]*)\]\)', line)
        if m:
            return m.group(1)

    return None

def update_version_in(infile, outfile, regex, versionline):
    """
    Copy every line from infile to outfile. If any line matches 'regex',
    replace it with 'versionline'.  Return True if any line was changed;
    false otherwise.

    'versionline' is either a string -- in which case it is used literally,
    or a function that receives the output of 'regex.match'.
    """
    found = False
    have_changed = False
    for line in infile:
        m = regex.match(line)
        if m:
            found = True
            oldline = line
            if type(versionline) == type(u""):
                line = versionline
            else:
                line = versionline(m)
            if not line.endswith("\n"):
                line += "\n"
            if oldline != line:
                have_changed = True
        outfile.write(line)

    if not found:
        warn("didn't find any version line to replace in {}".format(infile.name))

    return have_changed

def replace_on_change(fname, change):
    """
    If "change" is true, replace fname with fname.tmp.  Otherwise,
    delete fname.tmp.  Log what we're doing to stderr.
    """
    if not change:
        print("No change in {}".format(fname))
        os.unlink(fname+".tmp")
    else:
        print("Updating {}".format(fname))
        os.rename(fname+".tmp", fname)


def update_file(fname,
                regex,
                versionline,
                encoding="utf-8"):
    """
    Replace any line matching 'regex' in 'fname' with 'versionline'.
    Do not modify 'fname' if there are no changes made.  Use the
    provided encoding to read and write.
    """
    with io.open(fname, "r", encoding=encoding) as f, \
         io.open(fname+".tmp", "w", encoding=encoding) as outf:
        have_changed = update_version_in(f, outf, regex, versionline)

    replace_on_change(fname, have_changed)

# Find out our version
with open(P("configure.ac")) as f:
    version = find_version(f)

# If we have no version, we can't proceed.
if version == None:
    print("No version found in configure.ac", file=sys.stderr())
    sys.exit(1)

print("The version is {}".format(version))

today = time.strftime("%Y-%m-%d", time.gmtime())

# In configure.ac, we replace the definition of APPROX_RELEASE_DATE
# with "{today} for {version}", but only if the version does not match
# what is already there.
def replace_fn(m):
    if m.group(1) != version:
        # The version changed -- we change the date.
        return u'AC_DEFINE(APPROX_RELEASE_DATE, ["{}"], # for {}'.format(today, version)
    else:
        # No changes.
        return m.group(0)
update_file(P("configure.ac"),
            re.compile(r'AC_DEFINE\(APPROX_RELEASE_DATE.* for (.*)'),
            replace_fn)

# In tor-mingw.nsi.in, we replace the definition of VERSION.
update_file(P("contrib/win32build/tor-mingw.nsi.in"),
            re.compile(r'!define VERSION .*'),
            u'!define VERSION "{}"'.format(version),
            encoding="iso-8859-1")
