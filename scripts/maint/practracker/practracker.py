#!/usr/bin/python3

"""
Tor code best-practices tracker

Go through the various .c files and collect metrics about them. If the metrics
violate some of our best practices and they are not found in the optional
exceptions file ("./exceptions.txt"), then log a problem about them.

The exceptions file is meant to be initialized with the current state of the
source code as follows: ./practracker.py > ./exceptions.txt

We currently do metrics about file size, function size and number of includes.

TODO:
    - How is this tool supposed to be used? How should the exception file work?
      How should the UI work? Does it need special exit codes?
    - Fix the function_length function so that practracker_tests.py passes.
"""

import os, sys

import metrics
import util
import problem

# We don't want to run metrics for unittests, automatically-generated C files,
# external libraries or git leftovers.
EXCLUDE_SOURCE_DIRS = ["/src/test/", "/src/trunnel/", "/src/ext/", "/.git/"]

# Where the Tor source code is
TOR_TOPDIR = "../../../"
# An optional exceptions_file
EXCEPTIONS_FILE = "./exceptions.txt"

# Recommended file size
MAX_FILE_SIZE = 3000 # lines
# Recommended function size
MAX_FUNCTION_SIZE = 100 # lines
# Recommended number of #includes
MAX_INCLUDE_COUNT = 50

#######################################################

ProblemVault = None

#######################################################

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
        with open(fname, 'r') as f:
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

def main():
    # 1) Get all the .c files we care about
    files_list = util.get_tor_c_files(TOR_TOPDIR, EXCLUDE_SOURCE_DIRS)

    # 2) Initialize problem vault and load an optional exceptions file so that
    # we don't warn about the past
    global ProblemVault
    ProblemVault = problem.ProblemVault(EXCEPTIONS_FILE)

    # 3) Go through all the files and report problems if they are not exceptions
    found_new_issues = consider_all_metrics(files_list)

    if found_new_issues:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == '__main__':
    main()
