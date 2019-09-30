#!/usr/bin/python3

from __future__ import print_function
import re
import sys

# Not every subsystem is initialized in a place corresponding to its
# name.  These are the locations of the ones that are not.
LOCATIONS = {
    "btrack" : "feature/control",
    "network" : "lib/net",
    "ocirc_event" : "core/or",
    "orconn_event" : "core/or",
    "relay" : "feature/relay",
    "threads" : "lib/thread",
    "tortls" : "lib/tls",
    "winprocess" : "lib/process",
}

def fn_to_dir(fn):
    o = fn
    if fn.startswith("src/"):
        fn = fn[4:]
    fn = re.sub(r'/[^/]*\.c', '', fn)
    return fn

def parse_list(lines):
    result = list()

    for line in lines:
        line = line.strip()
        parts = line.split()
        if len(parts) == 2:
            level, system = parts
        elif len(parts) == 3:
            level, _, name = parts
            system = fn_to_dir(name)
        else:
            print("Weird line %r"%line, file=sys.stderr)
            continue
        level = int(level)
        result.append((level, system))

    return result

def get_topological_level(system, sorting):
    location = LOCATIONS.get(system)

    for level, path in sorting:
        if path.endswith("/"+system) or path == location or path == system:
            return level

    if location:
        print("No topological level found for %s in %s"%(system,location),
              file=sys.stderr)
    else:
        print("No path found for %s"%system, file=sys.stderr)
    return None

n_violations = 0

def require(prop, warning):
    global n_violations

    if not prop:
        print(warning, file=sys.stderr)
        n_violations += 1

def check_compatibility(sorting, subsystems):
    last_level = None

    # Require that subsystem levels are numerically ascending.
    for level, s in subsystems:
        if last_level != None:
            require(last_level <= level,
                    "Levels are decreasing, starting with "+s)
        last_level = level

    # Require that, for every subsystem whose location can be found,
    # its topological level is numerically ascending.
    last_topolevel = None
    for _, s in subsystems:
        topolevel = get_topological_level(s, sorting)
        if None not in (last_topolevel, topolevel):
            require(last_topolevel <= topolevel,
                    "Topological levels are mismatched with system levels, "+
                    "starting with "+s)
        if topolevel != None:
            last_topolevel = topolevel

def main(argv):
    import argparse

    progname = argv[0]
    parser = argparse.ArgumentParser(prog=progname)
    parser.add_argument("subsys_list",
                        help="The output of tor --dbg-dump-subsystem-list")
    parser.add_argument("toposort",
                        help="The output of practracker.includes --toposort-verbose")

    args = parser.parse_args(argv[1:])

    with open(args.subsys_list) as f:
        subsystems = parse_list(f.readlines())

    with open(args.toposort) as f:
        sorting = parse_list(f.readlines())

    check_compatibility(sorting, subsystems)

    return n_violations == 0

if __name__ == '__main__':
    import sys
    if main(sys.argv):
        sys.exit(0)
    else:
        sys.exit(1)
