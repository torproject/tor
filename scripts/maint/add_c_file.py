#!/usr/bin/env python3

"""
   Add a C file with matching header to the Tor codebase.  Creates
   both files from templates, and adds them to the right include.am file.

   Example usage:

   % add_c_file.py ./src/feature/dirauth/ocelot.c
"""

import os
import re
import time

def topdir_file(name):
    """Strip opening "src" from a filename"""
    if name.startswith("src/"):
        name = name[4:]
    return name

def guard_macro(name):
    """Return the guard macro that should be used for the header file 'name'.
    """
    td = topdir_file(name).replace(".", "_").replace("/", "_").upper()
    return "TOR_{}".format(td)

def makeext(name, new_extension):
    """Replace the extension for the file called 'name' with 'new_extension'.
    """
    base = os.path.splitext(name)[0]
    return base + "." + new_extension

def instantiate_template(template, output_fname):
    """
    Fill in a template with string using the fields that should be used
    for 'output_fname'.
    """
    names = {
        # The relative location of the header file.
        'header_path' : makeext(topdir_file(output_fname), "h"),
        # The relative location of the C file file.
        'c_file_path' : makeext(topdir_file(output_fname), "c"),
        # The truncated name of the file.
        'short_name' : os.path.basename(output_fname),
        # The current year, for the copyright notice
        'this_year' : time.localtime().tm_year,
        # An appropriate guard macro, for the header.
        'guard_macro' : guard_macro(output_fname),
    }

    return template.format(**names)

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
    """
    pat = re.compile(r'# ADD_C_FILE: INSERT (\S*) HERE', re.I)

    def __init__(self):
        self.lines = []
        self.kind = ""

    def addLine(self, line):
        """
        Insert a line into this chunk while parsing the automake file.
        """
        m = self.pat.match(line)
        if m:
            if self.lines:
                raise ValueError("control line not preceded by a blank line")
            self.kind = m.group(1)

        self.lines.append(line)
        if line.strip() == "":
            return True

        return False

    def insertMember(self, member):
        """
        Add a new member to this chunk.  Try to insert it in alphabetical
        order with matching indentation, but don't freak out too much if the
        source isn't consistent.

        Assumes that this chunk is of the form:
           FOOBAR = \
              X     \
              Y     \
              Z
        """
        prespace = "\t"
        postspace = "\t\t"
        for lineno, line in enumerate(self.lines):
            m = re.match(r'(\s+)(\S+)(\s+)\\', line)
            if not m:
                continue
            prespace, fname, postspace = m.groups()
            if fname > member:
                self.insert_before(lineno, member, prespace, postspace)
                return
        self.insert_at_end(member, prespace, postspace)

    def insert_before(self, lineno, member, prespace, postspace):
        self.lines.insert(lineno,
                          "{}{}{}\\\n".format(prespace, member, postspace))

    def insert_at_end(self, member, prespace, postspace):
        lastline = self.lines[-1]
        self.lines[-1] += '{}\\\n'.format(postspace)
        self.lines.append("{}{}\n".format(prespace, member))

    def dump(self, f):
        """Write all the lines in this chunk to the file 'f'."""
        for line in self.lines:
            f.write(line)
            if not line.endswith("\n"):
                f.write("\n")

class ParsedAutomake:
    """A sort-of-parsed automake file, with identified chunks into which
       headers and c files can be inserted.
    """
    def __init__(self):
        self.chunks = []
        self.by_type = {}

    def addChunk(self, chunk):
        """Add a newly parsed AutomakeChunk to this file."""
        self.chunks.append(chunk)
        self.by_type[chunk.kind.lower()] = chunk

    def add_file(self, fname, kind):
        """Insert a file of kind 'kind' to the appropriate section of this
           file. Return True if we added it.
        """
        if kind.lower() in self.by_type:
            self.by_type[kind.lower()].insertMember(fname)
            return True
        else:
            return False

    def dump(self, f):
        """Write this file into a file 'f'."""
        for chunk in self.chunks:
            chunk.dump(f)

def get_include_am_location(fname):
    """Find the right include.am file for introducing a new file.  Return None
       if we can't guess one.

       Note that this function is imperfect because our include.am layout is
       not (yet) consistent.
    """
    td = topdir_file(fname)
    m = re.match(r'^lib/([a-z0-9_]*)/', td)
    if m:
        return "src/lib/{}/include.am".format(m.group(1))

    if re.match(r'^(core|feature|app)/', td):
        return "src/core/include.am"

    if re.match(r'^test/', td):
        return "src/test/include.am"

    return None

def run(fn):
    """
    Create a new C file and H file corresponding to the filename "fn", and
    add them to include.am.
    """

    cf = makeext(fn, "c")
    hf = makeext(fn, "h")

    if os.path.exists(cf):
        print("{} already exists".format(cf))
        return 1
    if os.path.exists(hf):
        print("{} already exists".format(hf))
        return 1

    with open(cf, 'w') as f:
        f.write(instantiate_template(C_FILE_TEMPLATE, cf))

    with open(hf, 'w') as f:
        f.write(instantiate_template(HEADER_TEMPLATE, hf))

    iam = get_include_am_location(cf)
    if iam is None or not os.path.exists(iam):
        print("Made files successfully but couldn't identify include.am for {}"
              .format(cf))
        return 1

    amfile = ParsedAutomake()
    cur_chunk = AutomakeChunk()
    with open(iam) as f:
        for line in f:
            if cur_chunk.addLine(line):
                amfile.addChunk(cur_chunk)
                cur_chunk = AutomakeChunk()
        amfile.addChunk(cur_chunk)

    amfile.add_file(cf, "sources")
    amfile.add_file(hf, "headers")

    with open(iam+".tmp", 'w') as f:
        amfile.dump(f)

    os.rename(iam+".tmp", iam)

if __name__ == '__main__':
    import sys
    sys.exit(run(sys.argv[1]))
