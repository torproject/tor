#!/usr/bin/env python3

"""
   Add a C file with matching header to the Tor codebase.  Creates
   both files from templates, and adds them to the right include.am file.

   This script takes paths relative to the top-level tor directory. It
   expects to be run from that directory.

   This script creates files, and inserts them into include.am, also
   relative to the top-level tor directory.

   But the template content in those files is relative to tor's src
   directory. (This script strips "src" from the paths used to create
   templated comments and macros.)

   This script expects posix paths, so it should be run with a python
   where os.path is posixpath. (Rather than ntpath.) This probably means
   Linux, macOS, or BSD, although it might work on Windows if your python
   was compiled with mingw, MSYS, or cygwin.

   Example usage:

   % add_c_file.py ./src/feature/dirauth/ocelot.c
"""

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import re
import time

def tordir_file(fname):
    """Make fname relative to the current directory, which should be the
       top-level tor directory. Also performs basic path simplifications."""
    return os.path.normpath(os.path.relpath(fname))

def srcdir_file(tor_fname):
    """Make tor_fname relative to tor's "src" directory.
       Also performs basic path simplifications.
       (This function takes paths relative to the top-level tor directory,
       but outputs a path that is relative to tor's src directory.)"""
    return os.path.normpath(os.path.relpath(tor_fname, 'src'))

def guard_macro(src_fname):
    """Return the guard macro that should be used for the header file
       'src_fname'. This function takes paths relative to tor's src directory.
    """
    td = src_fname.replace(".", "_").replace("/", "_").upper()
    return "TOR_{}".format(td)

def makeext(fname, new_extension):
    """Replace the extension for the file called 'fname' with 'new_extension'.
       This function takes and returns paths relative to either the top-level
       tor directory, or tor's src directory, and returns the same kind
       of path.
    """
    base = os.path.splitext(fname)[0]
    return base + "." + new_extension

def instantiate_template(template, tor_fname):
    """
    Fill in a template with string using the fields that should be used
    for 'tor_fname'.

    This function takes paths relative to the top-level tor directory,
    but the paths in the completed template are relative to tor's src
    directory. (Except for one of the fields, which is just a basename).
    """
    src_fname = srcdir_file(tor_fname)
    names = {
        # The relative location of the header file.
        'header_path' : makeext(src_fname, "h"),
        # The relative location of the C file file.
        'c_file_path' : makeext(src_fname, "c"),
        # The truncated name of the file.
        'short_name' : os.path.basename(src_fname),
        # The current year, for the copyright notice
        'this_year' : time.localtime().tm_year,
        # An appropriate guard macro, for the header.
        'guard_macro' : guard_macro(src_fname),
    }

    return template.format(**names)

# This template operates on paths relative to tor's src directory
HEADER_TEMPLATE = """\
/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-{this_year}, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file {short_name}
 * @brief Header for {c_file_path}
 **/

#ifndef {guard_macro}
#define {guard_macro}

#endif /* !defined({guard_macro}) */
"""

# This template operates on paths relative to the tor's src directory
C_FILE_TEMPLATE = """\
/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-{this_year}, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file {short_name}
 * @brief DOCDOC
 **/

#include "orconfig.h"
#include "{header_path}"
"""

class AutomakeChunk:
    """
    Represents part of an automake file.  If it is decorated with
    an ADD_C_FILE comment, it has a "kind" based on what to add to it.
    Otherwise, it only has a bunch of lines in it.

    This class operates on paths relative to the top-level tor directory.
    """
    pat = re.compile(r'# ADD_C_FILE: INSERT (\S*) HERE', re.I)

    def __init__(self):
        self.lines = []
        self.kind = ""
        self.hasBlank = False # true if we end with a blank line.

    def addLine(self, line):
        """
        Insert a line into this chunk while parsing the automake file.

        Return True if we have just read the last line in the chunk, and
        False otherwise.
        """
        m = self.pat.match(line)
        if m:
            if self.lines:
                raise ValueError("control line not preceded by a blank line")
            self.kind = m.group(1)

        if line.strip() == "":
            self.hasBlank = True
            return True

        self.lines.append(line)

        return False

    def insertMember(self, new_tor_fname):
        """
        Add a new file name new_tor_fname to this chunk.  Try to insert it in
        alphabetical order with matching indentation, but don't freak out too
        much if the source isn't consistent.

        Assumes that this chunk is of the form:
           FOOBAR = \
              X     \
              Y     \
              Z

        This function operates on paths relative to the top-level tor
        directory.
        """
        prespace = "\t"
        postspace = "\t\t"
        for lineno, line in enumerate(self.lines):
            m = re.match(r'(\s+)(\S+)(\s+)\\', line)
            if not m:
                continue
            prespace, cur_tor_fname, postspace = m.groups()
            if cur_tor_fname > new_tor_fname:
                self.insert_before(lineno, new_tor_fname, prespace, postspace)
                return
        self.insert_at_end(new_tor_fname, prespace, postspace)

    def insert_before(self, lineno, new_tor_fname, prespace, postspace):
        self.lines.insert(lineno,
                          "{}{}{}\\\n".format(prespace, new_tor_fname,
                                              postspace))

    def insert_at_end(self, new_tor_fname, prespace, postspace):
        lastline = self.lines[-1].strip()
        self.lines[-1] = '{}{}{}\\\n'.format(prespace, lastline, postspace)
        self.lines.append("{}{}\n".format(prespace, new_tor_fname))

    def dump(self, f):
        """Write all the lines in this chunk to the file 'f'."""
        for line in self.lines:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")

        if self.hasBlank:
            f.write("\n")

class ParsedAutomake:
    """A sort-of-parsed automake file, with identified chunks into which
       headers and c files can be inserted.

       This class operates on paths relative to the top-level tor directory.
    """
    def __init__(self):
        self.chunks = []
        self.by_type = {}

    def addChunk(self, chunk):
        """Add a newly parsed AutomakeChunk to this file."""
        self.chunks.append(chunk)
        self.by_type[chunk.kind.lower()] = chunk

    def add_file(self, tor_fname, kind):
        """Insert a file tor_fname of kind 'kind' to the appropriate
           section of this file. Return True if we added it.

           This function operates on paths relative to the top-level tor
           directory.
        """
        if kind.lower() in self.by_type:
            self.by_type[kind.lower()].insertMember(tor_fname)
            return True
        else:
            return False

    def dump(self, f):
        """Write this file into a file 'f'."""
        for chunk in self.chunks:
            chunk.dump(f)

def get_include_am_location(tor_fname):
    """Find the right include.am file for introducing a new file
       tor_fname.  Return None if we can't guess one.

       Note that this function is imperfect because our include.am layout is
       not (yet) consistent.

       This function operates on paths relative to the top-level tor directory.
    """
    # Strip src for pattern matching, but add it back when returning the path
    src_fname = srcdir_file(tor_fname)
    m = re.match(r'^(lib|core|feature|app)/([a-z0-9_]*)/', src_fname)
    if m:
        return "src/{}/{}/include.am".format(m.group(1),m.group(2))

    if re.match(r'^test/', src_fname):
        return "src/test/include.am"

    return None

def run(fname):
    """
    Create a new C file and H file corresponding to the filename "fname",
    and add them to the corresponding include.am.

    This function operates on paths relative to the top-level tor directory.
    """

    # Make sure we're in the top-level tor directory,
    # which contains the src directory
    if not os.path.isdir("src"):
        raise RuntimeError("Could not find './src/'. "
                           "Run this script from the top-level tor source "
                           "directory.")

    # And it looks like a tor/src directory
    if not os.path.isfile("src/include.am"):
        raise RuntimeError("Could not find './src/include.am'. "
                           "Run this script from the top-level tor source "
                           "directory.")

    # Make the file name relative to the top-level tor directory
    tor_fname = tordir_file(fname)
    # And check that we're adding files to the "src" directory,
    # with canonical paths
    if tor_fname[:4] != "src/":
        raise ValueError("Requested file path '{}' canonicalized to '{}', "
                         "but the canonical path did not start with 'src/'. "
                         "Please add files to the src directory."
                         .format(fname, tor_fname))

    c_tor_fname = makeext(tor_fname, "c")
    h_tor_fname = makeext(tor_fname, "h")

    if os.path.exists(c_tor_fname):
        print("{} already exists".format(c_tor_fname))
        return 1
    if os.path.exists(h_tor_fname):
        print("{} already exists".format(h_tor_fname))
        return 1

    with open(c_tor_fname, 'w') as f:
        f.write(instantiate_template(C_FILE_TEMPLATE, c_tor_fname))

    with open(h_tor_fname, 'w') as f:
        f.write(instantiate_template(HEADER_TEMPLATE, h_tor_fname))

    iam = get_include_am_location(c_tor_fname)
    if iam is None or not os.path.exists(iam):
        print("Made files successfully but couldn't identify include.am for {}"
              .format(c_tor_fname))
        return 1

    amfile = ParsedAutomake()
    cur_chunk = AutomakeChunk()
    with open(iam) as f:
        for line in f:
            if cur_chunk.addLine(line):
                amfile.addChunk(cur_chunk)
                cur_chunk = AutomakeChunk()
        amfile.addChunk(cur_chunk)

    amfile.add_file(c_tor_fname, "sources")
    amfile.add_file(h_tor_fname, "headers")

    with open(iam+".tmp", 'w') as f:
        amfile.dump(f)

    os.rename(iam+".tmp", iam)

if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1]))
