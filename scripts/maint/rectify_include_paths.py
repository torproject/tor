#!/usr/bin/env python

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
            # Avoid editor temporary files
            if fname.startswith("."):
                continue
            if fname.startswith("#"):
                continue

            if fname.endswith(".h"):
                if fname in includes:
                    warn("Multiple headers named %s"%fname)
                    includes[fname] = DUPLICATE
                    continue
                include = os.path.join(dirpath, fname)
                assert include.startswith("src/")
                includes[fname] = include[4:]

    return includes

INCLUDE_PAT = re.compile(r'( *# *include +")([^"]+)(".*)')

def get_base_header_name(hdr):
    return os.path.split(hdr)[1]

def fix_includes(inp, out, mapping):
    for line in inp:
        m = INCLUDE_PAT.match(line)
        if m:
            include,hdr,rest = m.groups()
            basehdr = get_base_header_name(hdr)
            if basehdr in mapping and mapping[basehdr] is not DUPLICATE:
                out.write('{}{}{}\n'.format(include,mapping[basehdr],rest))
                continue

        out.write(line)

incs = get_include_map()

for dirpath,dirnames,fnames in os.walk("src"):
    exclude(["trunnel"], dirnames)

    for fname in fnames:
        # Avoid editor temporary files
        if fname.startswith("."):
            continue
        if fname.startswith("#"):
            continue

        if fname.endswith(".c") or fname.endswith(".h"):
            fname = os.path.join(dirpath, fname)
            tmpfile = fname+".tmp"
            f_in = open(fname, 'r')
            f_out = open(tmpfile, 'w')
            fix_includes(f_in, f_out, incs)
            f_in.close()
            f_out.close()
            os.rename(tmpfile, fname)
