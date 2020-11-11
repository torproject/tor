#!/usr/bin/env python3
# Copyright (c) 2020, The Tor Project, Inc.
# See LICENSE for licensing information.

#
# DO NOT COMMIT OR MERGE CODE THAT IS RUN THROUGH THIS TOOL YET.
#
# WE ARE STILL DISCUSSING OUR DESIRED STYLE AND ITERATING ON IT,
# ALONG WITH THE TOOLS THAT ACHIEVE IT.
#     (12 Feb 2020)
#

"""
   This program uses a set of pluggable filters to inspect and transform
   our C code.
"""

import os
import re
import sys

class Filter:
    """A Filter transforms a string containing a C program."""
    def __init__(self):
        pass

    def transform(self, s):
        return s

class CompoundFilt(Filter):
    """A CompoundFilt runs another set of filters, in sequence."""
    def __init__(self, items=()):
        super().__init__()
        self._filters = list(items)

    def add(self, filt):
        self._filters.append(filt)
        return self

    def transform(self, s):
        for f in self._filters:
            s = f.transform(s)

        return s

class SplitError(Exception):
    """Exception: raised if split_comments() can't understand a C file."""
    pass

def split_comments(s):
    r"""Iterate over the C code in 's', and yield a sequence of (code,
       comment) pairs.  Each pair will contain either a nonempty piece
       of code, a nonempty comment, or both.

       >>> list(split_comments("hello // world\n"))
       [('hello ', '// world'), ('\n', '')]

       >>> list(split_comments("a /* b cd */ efg // hi"))
       [('a ', '/* b cd */'), (' efg ', '// hi')]
    """

    # Matches a block of code without any comments.
    PAT_CODE = re.compile(r'''^(?: [^/"']+ |
                                   "(?:[^\\"]+|\\.)*" |
                                   '(?:[^\\']+|\\.)*' |
                                   /[^/*]
                               )*''', re.VERBOSE|re.DOTALL)

    # Matches a C99 "//" comment.
    PAT_C99_COMMENT = re.compile(r'^//.*$', re.MULTILINE)

    # Matches a C "/*  */" comment.
    PAT_C_COMMENT = re.compile(r'^/\*(?:[^*]|\*+[^*/])*\*+/', re.DOTALL)

    while True:
        # Find some non-comment code at the start of the string.
        m = PAT_CODE.match(s)

        # If we found some code here, save it and advance the string.
        # Otherwise set 'code' to "".
        if m:
            code = m.group(0)
            s = s[m.end():]
        else:
            code = ""

        # Now we have a comment, or the end of the string.  Find out which
        # one, and how long it is.
        if s.startswith("//"):
            m = PAT_C99_COMMENT.match(s)
        else:
            m = PAT_C_COMMENT.match(s)

        # If we got a comment, save it and advance the string.  Otherwise
        # set 'comment' to "".
        if m:
            comment = m.group(0)
            s = s[m.end():]
        else:
            comment = ""

        # If we found no code and no comment, we should be at the end of
        # the string...
        if code == "" and comment == "":
            if s:
                # But in case we *aren't* at the end of the string, raise
                # an error.
                raise SplitError()
            # ... all is well, we're done scanning the code.
            return

        yield (code, comment)

class IgnoreCommentsFilt(Filter):
    """Wrapper: applies another filter to C code only, excluding comments.
    """
    def __init__(self, filt):
        super().__init__()
        self._filt = filt

    def transform(self, s):
        result = []
        for code, comment in split_comments(s):
            result.append(self._filt.transform(code))
            result.append(comment)
        return "".join(result)


class RegexFilt(Filter):
    """A regex filter applies a regular expression to some C code."""
    def __init__(self, pat, replacement, flags=0):
        super().__init__()
        self._pat = re.compile(pat, flags)
        self._replacement = replacement

    def transform(self, s):
        s, _ = self._pat.subn(self._replacement, s)
        return s

def revise(fname, filt):
    """Run 'filt' on the contents of the file in 'fname'.  If any
       changes are made, then replace the file with its new contents.
       Otherwise, leave the file alone.
    """
    contents = open(fname, 'r').read()
    result = filt.transform(contents)
    if result == contents:
        return

    tmpname = "{}_codetool_tmp".format(fname)
    try:
        with open(tmpname, 'w') as f:
            f.write(result)
            os.rename(tmpname, fname)
    except:
        os.unlink(tmpname)
        raise

##############################
# Filtering rules.
##############################

# Make sure that there is a newline after the first comma in a MOCK_IMPL()
BREAK_MOCK_IMPL = RegexFilt(
    r'^MOCK_IMPL\(([^,]+),\s*(\S+)',
    r'MOCK_IMPL(\1,\n\2',
    re.MULTILINE)

# Make sure there is no newline between } and a loop iteration terminator.
RESTORE_SMARTLIST_END = RegexFilt(
    r'}\s*(SMARTLIST|DIGESTMAP|DIGEST256MAP|STRMAP|MAP)_FOREACH_END\s*\(',
    r'} \1_FOREACH_END (',
    re.MULTILINE)

F = CompoundFilt()
F.add(IgnoreCommentsFilt(CompoundFilt([
    RESTORE_SMARTLIST_END,
    BREAK_MOCK_IMPL])))

if __name__ == '__main__':
    for fname in sys.argv[1:]:
        revise(fname, F)
