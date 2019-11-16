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
    sys.stderr.write("WARNING: %s\n"%msg)

# Find all the include files, map them to their real names.

def exclude(paths, dirnames):
    for p in paths:
        if p in dirnames:
            dirnames.remove(p)

DUPLICATE = object()

def get_include_map():
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

DEFINE_PRIVATE_PAT = re.compile(r'( *# *define +)([A-Z_]+)(_PRIVATE.*)')
DEFINE_INTERNAL_PAT = re.compile(r'( *# *define +)([A-Z_]+)(_INTERNAL_.*)')
DEFINE_START = '#define '

INCLUDE_H_PAT = re.compile(r'( *# *include +")([^"]+\.h)(".*)')
INCLUDE_INC_PAT = re.compile(r'( *# *include +")([^"]+\.inc)(".*)')
INCLUDE_START = '#include "'

def get_base_header_name(hdr):
    return os.path.split(hdr)[1]

def fix_includes(inp, out, mapping):
    for line in inp:

        # match #define *_PRIVATE*
        m = DEFINE_PRIVATE_PAT.match(line)
        if m:
            define,prefix,rest = m.groups()
            out.write('{}{}{}\n'.format(DEFINE_START,prefix,rest))
            continue

        # match #define *_INTERNAL_*
        m = DEFINE_INTERNAL_PAT.match(line)
        if m:
            define,prefix,rest = m.groups()
            out.write('{}{}{}\n'.format(DEFINE_START,prefix,rest))
            continue

        # match #include "*.h"*
        m = INCLUDE_H_PAT.match(line)
        if m:
            include,hdr,rest = m.groups()
            basehdr = get_base_header_name(hdr)
            if basehdr in mapping and mapping[basehdr] is not DUPLICATE:
                out.write('{}{}{}\n'.format(INCLUDE_START,mapping[basehdr],rest))
                continue

        # match #include "*.inc"*
        m = INCLUDE_INC_PAT.match(line)
        if m:
            include,hdr,rest = m.groups()
            basehdr = get_base_header_name(hdr)
            if basehdr in mapping and mapping[basehdr] is not DUPLICATE:
                out.write('{}{}{}\n'.format(INCLUDE_START,mapping[basehdr],rest))
                continue

        out.write(line)

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
