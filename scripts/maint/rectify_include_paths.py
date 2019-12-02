#!/usr/bin/python
# Reformat tor header includes into a consistent style.
#
# Find all of tor's C headers (".h" and ".inc" files).
# Generate a canonical path for each header.
#
# Find user-editable C source files (".c" and ".h" files).
# Replace the following lines with their canonical forms:
#   - *_PRIVATE, *_INTERNAL_, and EXPOSE_* defines
#   - conditional macro directives
#   - user includes of tor headers
# Delete:
#   - unused *_PRIVATE, *_INTERNAL_, and EXPOSE_* defines
#   - duplicate user includes of tor headers
#   - double newlines created by other deletions
#
# Supports command-line arguments, use `rectify_include_paths.py -h`
# or see the argparse declarations below for details.

import argparse
import os
import os.path
import re
import sys

## Fix modes

# Read source, build data structures, but don't write files
READ_ONLY      = "read-only"
# Write out ".tmp" files, but don't replace the originals
DRY_RUN        = "dry-run"
# Rewrite lines, but keep unmodified lines the same
FIX_LINES      = "fix-lines"
# Drop duplicate lines, but keep the same line order
FIX_DUPLICATES = "fix-duplicates"

# List of modes that don't modify original files
SAFE_MODE_LIST = [READ_ONLY, DRY_RUN]
# All modes
ALL_MODE_LIST = [READ_ONLY, DRY_RUN, FIX_LINES, FIX_DUPLICATES]

# Default run mode
DEFAULT_FIX_MODE = FIX_DUPLICATES

## Command-line arguments

def parse_arguments(argv=sys.argv):
    '''Parse the command-line arguments.'''
    parser = argparse.ArgumentParser(
        description="Reformat tor header includes into a consistent style.")

    parser.add_argument("--fix-mode", "-f",
                        dest="fix_mode",
                        default=DEFAULT_FIX_MODE,
                        help=("fixes to apply to tor C code: {}"
                              .format(", ".join(ALL_MODE_LIST))))
    parser.add_argument("--verbose", "-v",
                        dest="debug_mode",
                        action="store_true",
                        default=False,
                        help="log debug information")
    parser.add_argument("--tor-dir", "-t",
                        dest="tor_dir",
                        default=".",
                        help="path to the tor source distribution directory")
    parser.add_argument("files",
                        nargs="*",
                        default=None,
                        help="list of tor files with C code to fix")

    return parser.parse_args()

## Directory paths
# All these paths assume we are in the tor directory

# Where is src from the root?
SRC_ROOT = "src"

# Which paths don't get included in the header maps?
# donna/fuzz contains a duplicate header name
# win32 contains orconfig.h, which is auto-generated on other platforms
NO_MAP_PATHS = ["ext/ed25519/donna/fuzz", "win32"]

# Which paths do not get modified?
# ext is out of our control, we should not keep modifying it
# trunnel is auto-generated, we should fix the generator instead
NO_FIX_PATHS = ["ext", "trunnel"]

## String constants

NEWLINE = "\n"

## Patterns for preprocessor directives

# We can spell 'PRIVATE' 3 different ways
PRIVATE_PAT_LIST = [ r'[A-Z0-9_]+_PRIVATE_?',
                     r'[A-Z0-9_]+_INTERNAL_?',
                     r'EXPOSE_[A-Z0-9_]+' ]

IF_PRIVATE_PAT_LIST = [ re.compile(
    r'( *# *)(if|ifdef|ifndef)( +)(.*defined[(])?(' + private + r')(.*)')
    for private in PRIVATE_PAT_LIST]

DEFINE_PRIVATE_PAT_LIST = [ re.compile(
    r'( *# *define +)(' + private + r')($| */[/*].*)')
    for private in PRIVATE_PAT_LIST]
DEFINE_START = '#define '

INCLUDE_H_FNAME_PAT = re.compile(r'( *# *include +")([^"]+/)([^"]+\.h)(".*)')

INCLUDE_H_PAT   = re.compile(r'( *# *include +")([^"]+\.h)(".*)')
INCLUDE_INC_PAT = re.compile(r'( *# *include +")([^"]+\.inc)(".*)')
INCLUDE_START   = '#include "'

IF_PAT    = re.compile(r'( *)(#)( *)(if.*)')
IFDEF_PAT = re.compile(r'( *)(#)( *)(if[n]?def.*)')
ELIF_PAT  = re.compile(r'( *)(#)( *)(elif.*)')
ELSE_PAT  = re.compile(r'( *)(#)( *)(else.*)')
ENDIF_PAT = re.compile(r'( *)(#)( *)(endif.*)')

## Logging

# Do we log debug()?
debug_mode = False
# What is the current file?
current_file = None

## Functions that access globals

def set_debug_mode(new_debug_mode=True):
    '''Set the global debug_mode to new_debug_mode.
       '''
    global debug_mode
    debug_mode = new_debug_mode

def get_debug_mode():
    '''Get the global debug_mode.
       '''
    global debug_mode
    return debug_mode

def set_current_file(new_current_file):
    '''Set the global current_file to new_current_file.
       '''
    global current_file
    current_file = new_current_file

def format_current_file():
    '''Format the global current_file, handling None correctly.
       Returns a string.
       '''
    global current_file
    if current_file:
        return " in '{}'".format(current_file)
    else:
        return ""

## Other logging functions

def debug(msg):
    '''Log debug to stdout with msg, if get_debug_mode() is True.'''
    if get_debug_mode():
        sys.stdout.write("DEBUG: {}\n".format(msg,
                                              format_current_file()))

def debug_map(map_dict, name):
    '''Log debug map_dict called name.'''
    # skip iteration and formatting on large maps
    if get_debug_mode():
        debug("{}:".format(name))
        for key in map_dict:
            debug("{}: {}".format(key, map_dict[key]))

def level_for_exit_error(exit_error):
    '''Return the default level for exit_error.'''
    if exit_error:
        return "ERROR"
    else:
        return "WARNING"

def warn(msg, exit_error=None, log_level=None):
    '''Log msg and current_file to stderr.
       If log_level, log at that level, otherwise, check exit_error.
       If exit_error, log an error, and exit with that status.
       Otherwise, log a warning.
       '''
    if not log_level:
        log_level = level_for_exit_error(exit_error)
    sys.stderr.write("{}: {}{}\n".format(log_level,
                                         msg,
                                         format_current_file()))
    if exit_error:
        sys.exit(exit_error)

def warn_with_context(line,
                      action="Bad",
                      context="",
                      exit_error=None,
                      log_level=None):
    '''Warn about action on line, in context.
       context is optional.
       Handle exit_error and log_level like warn().
       '''
    if not log_level:
        log_level = level_for_exit_error(exit_error)
    if context:
        context = " {}".format(context)
    else:
        context = ""
    warn("{}{}: '{}'".format(action, context, line.strip()),
         exit_error=exit_error,
         log_level=log_level)

def warn_ignored(line,
                 context="",
                 exit_error=None,
                 log_level=None):
    '''Warn about ignoring line in context.
       context is optional.
       Pass exit_error and log_level to warn_with_context().
       '''
    warn_with_context(line,
                      action="Ignoring",
                      context=context,
                      exit_error=exit_error,
                      log_level=log_level)

## Scanning the tree

# Singleton object to mark duplicates
DUPLICATE = object()

def exclude(paths, dirpath, dirnames):
    '''Remove any strings from dirnames that are equal to an item in paths.
       If dirpath is equal to an item in paths, clear dirnames,
       and return True. os.walk() will not scan any deeper in this directory,
       and the caller should skip all fnames at this level.
       Otherwise, return False. The caller should continue using fnames
       and using os.walk() to scan the tree.
       '''
    for p in paths:
        if os.path.join(SRC_ROOT, p) == dirpath:
            del dirnames[:]
            return True
        if p in dirnames:
            dirnames.remove(p)
    return False

def get_base_file_name(hdr):
    '''Return the file name part of the path hdr.'''
    return os.path.split(hdr)[1]

def get_private_from_if_pat(line, pat_list=IF_PRIVATE_PAT_LIST):
    '''If any pattern in pat_list matches, return a string containing the
       PRIVATE macro name. Otherwise, return None.
       '''
    for pat in pat_list:
        m = pat.match(line)
        if m:
            _, _, _, _, private, _ = m.groups()
            return private
    return None

def get_private_from_define_pat(line, pat_list=DEFINE_PRIVATE_PAT_LIST):
    '''If any pattern in pat_list matches, return a string containing
       the PRIVATE macro name. Otherwise, return None.
       '''
    for pat in pat_list:
        m = pat.match(line)
        if m:
            _, private, _ = m.groups()
            return private
    return None

def get_fname_from_include_pat(line, pat=INCLUDE_H_FNAME_PAT):
    '''If pat matches, return a string containing the header name.
       Otherwise, return None.
       '''
    m = pat.match(line)
    if m:
        _, dirname, fname, _ = m.groups()
        return fname
    return None

def add_include_to_map(fullname, fname, inc_map):
    '''If fullname is the first path for fname, add it to inc_map,
       and return True. Otherwise, add a duplicate marker to inc_map,
       and return False.
       '''
    assert fullname.startswith(SRC_ROOT + "/")
    include = fullname[4:]
    if fname in inc_map:
        warn("Multiple headers named {}: '{}', '{}', ..."
             .format(fname, inc_map[fname], include))
        inc_map[fname] = DUPLICATE
        return False
    else:
        inc_map[fname] = include
        return True

def add_to_set_map(set_map, key, value):
    '''Add value to the set in set_map for key.'''
    if key not in set_map:
        set_map[key] = set()
    set_map[key].add(value)

def add_private_to_map(fullname, fname, priv_inc_map):
    '''If fullname uses a PRIVATE macro, and it is the first header
       to do so, add it to priv_inc_map.
       '''
    with open(fullname, 'r') as header:
        for line in header:
            priv_name = get_private_from_if_pat(line)
            if priv_name:
                # We allow:
                #   - Multiple references in the same header
                #   - Multiple headers using the same PRIVATE
                #   - Multiple PRIVATEs in the same header
                add_to_set_map(priv_inc_map, priv_name, fname)

def get_include_private_maps():
    '''Find all the include files, map them to their real names.
       Also map each PRIVATE directive to the set of headers
       that use it.
       '''
    inc_map = { }
    priv_inc_map = { }

    for dirpath, dirnames, fnames in os.walk(SRC_ROOT):


        if exclude(NO_MAP_PATHS, dirpath, dirnames):
            continue

        for fname in fnames:
            fullname = os.path.join(dirpath, fname)
            assert fname == get_base_file_name(fullname)
            # map path -> base name
            if fname.endswith(".h") or fname.endswith(".inc"):
                if not add_include_to_map(fullname, fname, inc_map):
                    continue

            # map PRIVATE -> set(base name)
            if fname.endswith(".h"):
                add_private_to_map(fullname, fname,
                                   priv_inc_map)

    return (inc_map, priv_inc_map)

## Fixing lines

def fix_line(line, pat, std_directive=None, inc_map=None):
    '''If line matches pat, reformat it into a canonical string.
       Optionally, use std_directive instead of the first part of pat.
       Optionally, use inc_map to lookup the canonical form of the second
       part of pat, and modify the line if the lookup succeeds.
       Leave the third part of pat unmodified.
       If pat matches, returns a possibly modified line,
       otherwise returns None.
       '''
    m = pat.match(line)
    if m:
        directive, prefix, rest = m.groups()
        if std_directive:
            directive = std_directive
        if inc_map:
            basehdr = get_base_file_name(prefix)
            if basehdr in inc_map and inc_map[basehdr] is not DUPLICATE:
                return '{}{}{}\n'.format(directive, inc_map[basehdr], rest)
        else:
            return '{}{}{}\n'.format(directive, prefix, rest)
    return None

def fix_macro_cond_line(line, pat):
    '''If line matches pat, reformat it into a canonical string.
       Parts 1 and 3 are whitespace, move them after part 2, which is '#'.
       Then leave part 4 umodified.
       If pat matches, returns a possibly modified line,
       otherwise returns None.
       '''
    m = pat.match(line)
    if m:
        s1,  start,  s2,  rest = m.groups()
        return '{}{}{}{}\n'.format(start, s1, s2, rest)
    return None

def fix_private(line, pat_list=DEFINE_PRIVATE_PAT_LIST):
    '''Fix PRIVATE defines in line, using the first matching pattern in
       pat_list. If the line was matched, returns a possibly modified line,
       otherwise returns None.
       '''
    for pat in pat_list:
        mod_line = fix_line(line,
                            pat,
                            std_directive=DEFINE_START)
        if mod_line is not None:
            return mod_line

    return None

def fix_cond(line):
    '''Fix #if, #ifdef, #elif, #else, and #endif macro directives in line.
       If pat matches, returns a pair with a possibly modified line,
       and a nesting increment.
       Otherwise, returns None.
       '''
    # match #if *
    mod_line = fix_macro_cond_line(line,
                                   IF_PAT)
    if mod_line is not None:
        return (mod_line, +1)

    # match #if[n]def *
    mod_line = fix_macro_cond_line(line,
                                   IFDEF_PAT)
    if mod_line is not None:
        return (mod_line, +1)

    # match #elif *
    mod_line = fix_macro_cond_line(line,
                                   ELIF_PAT)
    if mod_line is not None:
        return (mod_line, 0)

    # match #else*
    mod_line = fix_macro_cond_line(line,
                                   ELSE_PAT)
    if mod_line is not None:
        return (mod_line, 0)

    # match #endif*
    mod_line = fix_macro_cond_line(line,
                                   ENDIF_PAT)
    if mod_line is not None:
        return (mod_line, -1)

    return (None, None)

def fix_include_h(line, inc_map):
    '''Fix #include .h macro directives in line, and write to private_groups
       Use inc_map to map headers to canonical names.
       If the line was matched, returns a possibly modified line,
       otherwise returns None.
       '''
    # match #include "*.h"*
    mod_line = fix_line(line,
                        INCLUDE_H_PAT,
                        std_directive=INCLUDE_START,
                        inc_map=inc_map)
    if mod_line is not None:
        return mod_line

    return None

def fix_include_inc(line, inc_map):
    '''Fix #include .inc macro directives in line.
       Use inc_map to map headers to canonical names.
       If pat matches, returns a possibly modified line,
       otherwise returns None.
       '''
    # match #include "*.inc"*
    return fix_line(line,
                    INCLUDE_INC_PAT,
                    std_directive=INCLUDE_START,
                    inc_map=inc_map)

def ignore_duplicate(key, used_set, line, context="duplicate"):
    '''Check if key is already in used_set.
       If it is, warn_ignored() using line and context, and return None.
       Otherwise, add key to used_set, and return line.
       '''
    if key in used_set:
        warn_ignored(line,
                     context=context)
        return None
    else:
        used_set.add(key)
        return line

def fix_line_helper(line, inc_map,
                    priv_inc_map=None,
                    used_priv=None,
                    used_inc=None):
    '''Fix line using inc_map, and return the result.

       If priv_inc_map is not None, check for unused PRIVATE defines.
       If used_priv is not None, check for duplicate PRIVATE defines.
       If used_inc is not None, check for duplicate includes.

       Returns None if line is unused or duplicate.
       Otherwise, returns a fixed version of line.
       '''
    # Create placeholder variables for FIX_LINES mode
    if priv_inc_map is None:
        priv_inc_map = {}
    if used_priv is None:
        used_priv = set()
    if used_inc is None:
        used_inc = set()

    # match #if, ... , or #endif
    (mod_line, _) = fix_cond(line)
    if mod_line is not None:
        return mod_line

    # match #define PRIVATE
    mod_line = fix_private(line)
    if mod_line is not None:
        private = get_private_from_define_pat(mod_line)
        # If there's nothing in priv_inc_map, skip unused checks
        if not priv_inc_map:
            return ignore_duplicate(private,
                                    used_priv,
                                    mod_line,
                                    context=("duplicate PRIVATE define " +
                                             "(no priv_inc_map)"))
        elif private in priv_inc_map:
            return ignore_duplicate(private,
                                    used_priv,
                                    mod_line,
                                    context=("duplicate PRIVATE define " +
                                             "(private in priv_inc_map)"))
        else:
            warn_ignored(mod_line,
                         context="unused PRIVATE define")
            return None

    # match #include .h
    mod_line = fix_include_h(line, inc_map)
    if mod_line is not None:
        fname = get_fname_from_include_pat(mod_line)
        return ignore_duplicate(fname, used_inc,
                                mod_line,
                                context="duplicate include")

    # match #include .inc
    mod_line = fix_include_inc(line, inc_map)
    if mod_line is not None:
        return mod_line

    # Other lines are returned unmodified
    return line

## Fixing files

def fix_file_lines(inp, out, inc_map):
    '''Fix every line in inp using inc_map, and write the result to out.
       Rewrites lines, but keeps unmodified lines the same.
       Does not delete any lines.
       Implements FIX_LINES mode.
       '''
    # Since we're not re-ordering any lines, we can just process
    # the file line-by-line.
    for line in inp:

        # Some lines will be passed through unmodified
        mod_line = fix_line_helper(line,
                                   inc_map)

        # We don't delete any lines in this mode
        assert mod_line is not None
        out.write(mod_line)

def fix_file_duplicates(inp, out, inc_map, priv_inc_map):
    '''Fix every line in inp using inc_map, and write the result to out.

       Rewrites lines, and removes duplicate includes and PRIVATE defines,
       based on inc_map.keys() and priv_inc_map.keys().
       Also removes unused PRIVATE defines, based on priv_inc_map.keys().
       (And removes any double newlines created by the deletions.)

       Any comments that are directly before deleted lines are retained.
       The user should move or delete them manually.

       Implements FIX_DUPLICATES mode.
       '''
    # The private DEFINES that have been used already in this file
    used_priv = set()
    # The includes that have been used already in this file
    used_inc = set()

    # Used to skip double newlines
    last_line = None

    # Since we're not re-ordering any lines, we can just process
    # the file line-by-line.
    for line in inp:

        # Some lines will be passed through unmodified
        mod_line = fix_line_helper(line,
                                   inc_map,
                                   priv_inc_map=priv_inc_map,
                                   used_priv=used_priv,
                                   used_inc=used_inc)

        # Skip deleted lines
        if mod_line is None:
            continue

        # Don't write double newlines
        if mod_line == NEWLINE and last_line == NEWLINE:
            pass
        else:
            out.write(mod_line)
        last_line = mod_line

def fix_file(fix_mode, inp, out,
             inc_map=None, priv_inc_map=None):
    '''Fix every line in inp using the mappings, and write the result to out.
       Use fix_mode to limit the fixes applied to the file.
       '''
    if fix_mode == FIX_LINES:
        fix_file_lines(inp, out,
                       inc_map)
    elif fix_mode == FIX_DUPLICATES or fix_mode in SAFE_MODE_LIST:
        # In read-only or dry-run modes, we want to try as many fixes as
        # possible (but without actually applying the changes)
        fix_file_duplicates(inp, out,
                            inc_map,
                            priv_inc_map)
    else:
        warn("Unexpected run mode: '{}'".format(fix_mode),
             exit_error=1)

## Fixing directories

def fix_tree(fix_mode,
             root, exclude_list=[], target_file_list=None,
             inc_map=None, priv_inc_map=None):
    '''Fix the tree at root, using the fixes from fix_mode.
       Exclude directories in exclude_list.
       If target_file_list is not None, only fix files in that list.
       The file names in the list must be the base name, not the path.
       Use the supplied mappings to do the fixes.
       '''
    for dirpath, dirnames, fnames in os.walk(root):

        if exclude(exclude_list, dirpath, dirnames):
            continue

        for fname in fnames:
            # Only process standard C files
            if fname.endswith(".c") or fname.endswith(".h"):
                # Use the target file list, if supplied
                if target_file_list:
                    if fname not in target_file_list:
                        continue
                set_current_file(fname)
                fname = os.path.join(dirpath, fname)

                # Don't write at all in READ_ONLY mode
                if fix_mode == READ_ONLY:
                    tmpfile = os.devnull
                else:
                    tmpfile = fname + ".tmp"
                # Fix the file, but write to another location
                with open(fname, 'r') as f_in:
                    with open(tmpfile, 'w') as f_out:
                        fix_file(fix_mode,
                                 f_in,
                                 f_out,
                                 inc_map=inc_map,
                                 priv_inc_map=priv_inc_map)
                # Atomically modify the file
                if fix_mode not in SAFE_MODE_LIST:
                    os.rename(tmpfile, fname)
                set_current_file(None)

## Entry points

def main(argv=sys.argv):
    '''Main function entry point, using argument list argv.'''

    args = parse_arguments(argv=argv)
    set_debug_mode(args.debug_mode)
    os.chdir(args.tor_dir)

    if args.files is not None:
        target_file_list = [get_base_file_name(fullname)
                            for fullname in args.files]
    else:
        target_file_list = None

    # We scan all the source files in every run mode
    (inc_map, priv_inc_map) = get_include_private_maps()
    debug_map(inc_map,
              "inc_map")
    debug_map(priv_inc_map,
              "priv_inc_map")

    fix_tree(args.fix_mode,
             SRC_ROOT,
             exclude_list=NO_FIX_PATHS,
             target_file_list=target_file_list,
             inc_map=inc_map,
             priv_inc_map=priv_inc_map)

# If we're running as a script, run main()
if __name__ == "__main__":
    main()
