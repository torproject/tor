#!/usr/bin/python

"""
Best-practices tracker for Tor source code.

Go through the various .c files and collect metrics about them. If the metrics
violate some of our best practices and they are not found in the optional
exceptions file, then log a problem about them.

We currently do metrics about file size, function size and number of includes.

practracker.py should be run with its second argument pointing to the Tor
top-level source directory like this:
  $ python3 ./scripts/maint/practracker/practracker.py .

To regenerate the exceptions file so that it allows all current
problems in the Tor source, use the --regen flag:
  $ python3 --regen ./scripts/maint/practracker/practracker.py .
"""

from __future__ import print_function

import os, sys

import metrics
import util
import problem

# The filename of the exceptions file (it should be placed in the practracker directory)
EXCEPTIONS_FNAME = "./exceptions.txt"

# Recommended file size
MAX_FILE_SIZE = 3000 # lines
# Recommended function size
MAX_FUNCTION_SIZE = 100 # lines
# Recommended number of #includes
MAX_INCLUDE_COUNT = 50

#######################################################

# ProblemVault singleton
ProblemVault = None

# The Tor source code topdir
TOR_TOPDIR = None

#######################################################

if sys.version_info[0] <= 2:
    def open_file(fname):
        return open(fname, 'r')
else:
    def open_file(fname):
        return open(fname, 'r', encoding='utf-8')

def consider_file_size(fname, f):
    """Consider file size issues for 'f' and return True if a new issue was found"""
    file_size = metrics.get_file_len(f)
    if file_size > MAX_FILE_SIZE:
        p = problem.FileSizeProblem(fname, file_size)
        return ProblemVault.register_problem(p)
    return False

def consider_includes(fname, f):
    """Consider #include issues for 'f' and return True if a new issue was found"""
    include_count = metrics.get_include_count(f)

    if include_count > MAX_INCLUDE_COUNT:
        p = problem.IncludeCountProblem(fname, include_count)
        return ProblemVault.register_problem(p)
    return False

def consider_function_size(fname, f):
    """Consider the function sizes for 'f' and return True if a new issue was found"""
    found_new_issues = False

    for name, lines in metrics.get_function_lines(f):
        # Don't worry about functions within our limits
        if lines <= MAX_FUNCTION_SIZE:
            continue

        # That's a big function! Issue a problem!
        canonical_function_name = "%s:%s()" % (fname, name)
        p = problem.FunctionSizeProblem(canonical_function_name, lines)
        found_new_issues |= ProblemVault.register_problem(p)

    return found_new_issues

#######################################################

def consider_all_metrics(files_list):
    """Consider metrics for all files, and return True if new issues were found"""
    found_new_issues = False
    for fname in files_list:
        with open_file(fname) as f:
            found_new_issues |= consider_metrics_for_file(fname, f)
    return found_new_issues

def consider_metrics_for_file(fname, f):
    """
    Consider the various metrics for file with filename 'fname' and file descriptor 'f'.
    Return True if we found new issues.
    """
    # Strip the useless part of the path
    if fname.startswith(TOR_TOPDIR):
        fname = fname[len(TOR_TOPDIR):]

    found_new_issues = False

    # Get file length
    found_new_issues |= consider_file_size(fname, f)

    # Consider number of #includes
    f.seek(0)
    found_new_issues |= consider_includes(fname, f)

    # Get function length
    f.seek(0)
    found_new_issues |= consider_function_size(fname, f)

    return found_new_issues

HEADER="""\
# Welcome to the exceptions file for Tor's best-practices tracker!
#
# Each line of this file represents a single violation of Tor's best
# practices -- typically, a violation that we had before practracker.py
# first existed.
#
# There are three kinds of problems that we recognize right now:
#   function-size -- a function of more than {MAX_FUNCTION_SIZE} lines.
#   file-size -- a file of more than {MAX_FILE_SIZE} lines.
#   include-count -- a file with more than {MAX_INCLUDE_COUNT} #includes.
#
# Each line below represents a single exception that practracker should
# _ignore_. Each line has four parts:
#  1. The word "problem".
#  2. The kind of problem.
#  3. The location of the problem: either a filename, or a
#     filename:functionname pair.
#  4. The magnitude of the problem to ignore.
#
# So for example, consider this line:
#    problem file-size /src/core/or/connection_or.c 3200
#
# It tells practracker to allow the mentioned file to be up to 3200 lines
# long, even though ordinarily it would warn about any file with more than
# {MAX_FILE_SIZE} lines.
#
# You can either edit this file by hand, or regenerate it completely by
# running `make practracker-regen`.
#
# Remember: It is better to fix the problem than to add a new exception!

""".format(**globals())

def main(argv):
    import argparse

    progname = argv[0]
    parser = argparse.ArgumentParser(prog=progname)
    parser.add_argument("--regen", action="store_true",
                        help="Regenerate the exceptions file")
    parser.add_argument("--exceptions",
                        help="Override the location for the exceptions file")
    parser.add_argument("topdir", default=".", nargs="?",
                        help="Top-level directory for the tor source")
    args = parser.parse_args(argv[1:])

    global TOR_TOPDIR
    TOR_TOPDIR = args.topdir
    if args.exceptions:
        exceptions_file = args.exceptions
    else:
        exceptions_file = os.path.join(TOR_TOPDIR, "scripts/maint/practracker", EXCEPTIONS_FNAME)

    # 1) Get all the .c files we care about
    files_list = util.get_tor_c_files(TOR_TOPDIR)

    # 2) Initialize problem vault and load an optional exceptions file so that
    # we don't warn about the past
    global ProblemVault

    if args.regen:
        tmpname = exceptions_file + ".tmp"
        tmpfile = open(tmpname, "w")
        sys.stdout = tmpfile
        sys.stdout.write(HEADER)
        ProblemVault = problem.ProblemVault()
    else:
        ProblemVault = problem.ProblemVault(exceptions_file)

    # 3) Go through all the files and report problems if they are not exceptions
    found_new_issues = consider_all_metrics(files_list)

    if args.regen:
        tmpfile.close()
        os.rename(tmpname, exceptions_file)
        sys.exit(0)

    # If new issues were found, try to give out some advice to the developer on how to resolve it.
    if found_new_issues and not args.regen:
        new_issues_str = """\
FAILURE: practracker found new problems in the code: see warnings above.

Please fix the problems if you can, and update the exceptions file
({}) if you can't.

See doc/HACKING/HelpfulTools.md for more information on using practracker.\
""".format(exceptions_file)
        print(new_issues_str)

    sys.exit(found_new_issues)

if __name__ == '__main__':
    main(sys.argv)
