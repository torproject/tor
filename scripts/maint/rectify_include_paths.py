#!/usr/bin/python3

import os
import os.path
import re

# Find all the include files, map them to their real names.

def exclude(paths, dirnames):
    for p in paths:
        if p in dirnames:
            dirnames.remove(p)

def get_include_map():
    includes = { }

    for dirpath,dirnames,fnames in os.walk("src"):
        exclude(["ext", "win32"], dirnames)

        for fname in fnames:
            if fname.endswith(".h"):
                assert fname not in includes
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
            if basehdr in mapping:
                out.write('{}{}{}\n'.format(include,mapping[basehdr],rest))
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
