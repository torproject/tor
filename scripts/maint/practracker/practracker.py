#!/usr/bin/python

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
    file_size = metrics.file_len(f)
    if file_size > MAX_FILE_SIZE:
        v = problem.FileSizeProblem(fname, file_size)
        ProblemVault.register_problem(v)

def consider_includes(fname, f):
    include_count = metrics.get_include_count(f)

    if include_count > MAX_INCLUDE_COUNT:
        v = problem.IncludeCountProblem(fname, include_count)
        ProblemVault.register_problem(v)

def consider_function_size(fname, f):
    for name, lines in metrics.function_lines(f):
        # Don't worry about functions within our limits
        if lines <= MAX_FUNCTION_SIZE:
            continue

        # That's a big function! Issue a problem!
        canonical_function_name = "%s:%s()" % (fname,name)
        v = problem.FunctionSizeProblem(canonical_function_name, lines)
        ProblemVault.register_problem(v)

#######################################################

def consider_all_metrics(files_list):
    """Consider metrics for all files"""
    for fname in files_list:
        with open(fname, 'r') as f:
            consider_metrics_for_file(fname, f)

def consider_metrics_for_file(fname, f):
    """
    Get metrics for file with filename 'fname' and file descriptor 'f'.
    """
    # Get file length
    consider_file_size(fname, f)

    # Consider number of #includes
    f.seek(0)
    consider_includes(fname, f)

    # Get function length
    f.seek(0)
    consider_function_size(fname, f)

def main():
    global ProblemVault

    # 1) Get all the .c files we care about
    files_list = util.get_tor_c_files(TOR_TOPDIR, EXCLUDE_SOURCE_DIRS)

    # 2) Initialize problem vault and load an optional exceptions file so that
    # we don't warn about the past
    try:
        with open(EXCEPTIONS_FILE, 'r') as exception_f:
            ProblemVault = problem.ProblemVault(exception_f)
    except IOError:
        print "No exception file provided"
        ProblemVault = problem.ProblemVault(None)

    # 3) Go through all the files and report problems if they are not exceptions
    consider_all_metrics(files_list)

if __name__ == '__main__':
    main()
