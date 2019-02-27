#!/usr/bin/python

import re

def file_len(f):
    """Get file length of file"""
    for i, l in enumerate(f):
        pass
    return i + 1

def function_lines(f):
    """
    Return iterator which iterates over functions and returns (function name, function lines)
    """

    # XXX Buggy! Doesn't work with MOCK_IMPL and ENABLE_GCC_WARNINGS
    in_function = False
    for lineno, line in enumerate(f):
        if not in_function:
            # find the start of a function
            m = re.match(r'^([a-zA-Z_][a-zA-Z_0-9]*),?\(', line)
            if m:
                func_name = m.group(1)
                func_start = lineno
                in_function = True
        else:
            # Fund the end of a function
            if line.startswith("}"):
                n_lines = lineno - func_start
                in_function = False
                yield (func_name, n_lines)
