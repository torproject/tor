#!/usr/bin/python
# Make all tor header includes into a canonical form.
#
# Find all of tor's C headers (".h" and ".inc" files).
# Generate a canonical path for each header.
#
# Find all user-editable C source files (".c" and ".h" files).
# Replace each *_PRIVATE and *_INTERNAL_ define with a canonical form.
# Replace each user include of a tor header with its canonical form.

import os
import os.path
import re
import sys

def warn(msg):
    '''Log a warning to stderr with msg.'''
    sys.stderr.write("WARNING: %s\n"%msg)

def exclude(paths, dirnames):
    '''Exclude any strings in dirnames that are equal to an item in paths.'''
    for p in paths:
        if p in dirnames:
            dirnames.remove(p)

DUPLICATE = object()

def get_include_map():
    '''Find all the include files, map them to their real names.'''
    includes = { }

    for dirpath,dirnames,fnames in os.walk("src"):
        exclude(["ext", "win32"], dirnames)

        for fname in fnames:
            if fname.endswith(".h") or fname.endswith(".inc"):
                if fname in includes:
                    warn("Multiple headers named %s"%fname)
                    includes[fname] = DUPLICATE
                    continue
                include = os.path.join(dirpath, fname)
                assert include.startswith("src/")
                includes[fname] = include[4:]

    return includes

# Patterns for preprocessor directives
DEFINE_PRIVATE_PAT = re.compile(r'( *# *define +)([A-Z_]+)(_PRIVATE.*)')
DEFINE_INTERNAL_PAT = re.compile(r'( *# *define +)([A-Z_]+)(_INTERNAL_.*)')
DEFINE_START = '#define '

INCLUDE_H_PAT = re.compile(r'( *# *include +")([^"]+\.h)(".*)')
INCLUDE_INC_PAT = re.compile(r'( *# *include +")([^"]+\.inc)(".*)')
INCLUDE_START = '#include "'

def get_base_header_name(hdr):
    '''Return the file name part of the path hdr.'''
    return os.path.split(hdr)[1]

def fix_line(line, pat, out, std_directive=None, mapping=None):
    '''If line matches pat, reformat it into a canonical string.
       Optionally, use std_directive instead of the first part of pat.
       Optionally, use mapping to lookup the canonical form of the second
       part of pat, and modify the line if the lookup succeeds.
       Leave the third part of pat unmodified.
       Finally, if the line was modified, write it to out.
       Returns True if line was written to out, otherwise returns False.
       '''
    m = pat.match(line)
    if m:
        directive,prefix,rest = m.groups()
        if std_directive:
            directive = std_directive
        if mapping:
            basehdr = get_base_header_name(prefix)
            if basehdr in mapping and mapping[basehdr] is not DUPLICATE:
                out.write('{}{}{}\n'.format(directive,mapping[basehdr],rest))
                return True
        else:
            out.write('{}{}{}\n'.format(directive,prefix,rest))
            return True
    return False

def fix_includes(inp, out, mapping):
    '''Fix every line in inp using mapping, and write the result to out.'''
    for line in inp:

        # match #define *_PRIVATE*
        if fix_line(line,
                    DEFINE_PRIVATE_PAT,
                    out,
                    std_directive=DEFINE_START):
            continue

        # match #define *_INTERNAL_*
        if fix_line(line,
                    DEFINE_INTERNAL_PAT,
                    out,
                    std_directive=DEFINE_START):
            continue

        # match #include "*.h"*
        if fix_line(line,
                    INCLUDE_H_PAT,
                    out,
                    std_directive=INCLUDE_START,
                    mapping=mapping):
            continue

        # match #include "*.inc"*
        if fix_line(line,
                    INCLUDE_INC_PAT,
                    out,
                    std_directive=INCLUDE_START,
                    mapping=mapping):
            continue

        out.write(line)

# Main entry point
incs = get_include_map()

for dirpath,dirnames,fnames in os.walk("src"):
    exclude(["trunnel"], dirnames)

    for fname in fnames:
        if fname.endswith(".c") or fname.endswith(".h"):
            fname = os.path.join(dirpath, fname)
            tmpfile = fname+".tmp"
            f_in = open(fname, 'r')
            f_out = open(tmpfile, 'w')
            fix_includes(f_in, f_out, incs)
            f_in.close()
            f_out.close()
            os.rename(tmpfile, fname)
