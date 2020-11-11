#!/usr/bin/env python
# Copyright (c) 2017-2019, The Tor Project, Inc.
# See LICENSE for licensing information

r"""
This script iterates over a list of C files. For each file, it looks at the
#if/#else C macros, and annotates them with comments explaining what they
match.

For example, it replaces this kind of input...

>>> INPUT = '''
... #ifdef HAVE_OCELOT
...   C code here
... #if MIMSY == BOROGROVE
...   block 1
...   block 1
...   block 1
...   block 1
... #else
...   block 2
...   block 2
...   block 2
...   block 2
... #endif
... #endif
... '''

With this kind of output:
>>> EXPECTED_OUTPUT = '''
... #ifdef HAVE_OCELOT
...   C code here
... #if MIMSY == BOROGROVE
...   block 1
...   block 1
...   block 1
...   block 1
... #else /* !(MIMSY == BOROGROVE) */
...   block 2
...   block 2
...   block 2
...   block 2
... #endif /* MIMSY == BOROGROVE */
... #endif /* defined(HAVE_OCELOT) */
... '''

Here's how to use it:
>>> import sys
>>> if sys.version_info.major < 3: from cStringIO import StringIO
>>> if sys.version_info.major >= 3: from io import StringIO

>>> OUTPUT = StringIO()
>>> translate(StringIO(INPUT), OUTPUT)
>>> assert OUTPUT.getvalue() == EXPECTED_OUTPUT

Note that only #else and #endif lines are annotated.  Existing comments
on those lines are removed.
"""

# Future imports for Python 2.7, mandatory in 3.0
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re

# Any block with fewer than this many lines does not need annotations.
LINE_OBVIOUSNESS_LIMIT = 4

# Maximum line width.  This includes a terminating newline character.
#
# (This is the maximum before encoding, so that if the the operating system
# uses multiple characters to encode newline, that's still okay.)
LINE_WIDTH=80

class Problem(Exception):
    pass

def close_parens_needed(expr):
    """Return the number of left-parentheses needed to make 'expr'
       balanced.

    >>> close_parens_needed("1+2")
    0
    >>> close_parens_needed("(1 + 2)")
    0
    >>> close_parens_needed("(1 + 2")
    1
    >>> close_parens_needed("(1 + (2 *")
    2
    >>> close_parens_needed("(1 + (2 * 3) + (4")
    2
    """
    return expr.count("(") - expr.count(")")

def truncate_expression(expr, new_width):
    """Given a parenthesized C expression in 'expr', try to return a new
       expression that is similar to 'expr', but no more than 'new_width'
       characters long.

       Try to return an expression with balanced parentheses.

    >>> truncate_expression("1+2+3", 8)
    '1+2+3'
    >>> truncate_expression("1+2+3+4+5", 8)
    '1+2+3...'
    >>> truncate_expression("(1+2+3+4)", 8)
    '(1+2...)'
    >>> truncate_expression("(1+(2+3+4))", 8)
    '(1+...)'
    >>> truncate_expression("(((((((((", 8)
    '((...))'
    """
    if len(expr) <= new_width:
        # The expression is already short enough.
        return expr

    ellipsis = "..."

    # Start this at the minimum that we might truncate.
    n_to_remove = len(expr) + len(ellipsis) - new_width

    # Try removing characters, one by one, until we get something where
    # re-balancing the parentheses still fits within the limit.
    while n_to_remove < len(expr):
        truncated = expr[:-n_to_remove] + ellipsis
        truncated += ")" * close_parens_needed(truncated)
        if len(truncated) <= new_width:
            return truncated
        n_to_remove += 1

    return ellipsis

def commented_line(fmt, argument, maxwidth=LINE_WIDTH):
    # (This is a raw docstring so that our doctests can use \.)
    r"""
    Return fmt%argument, for use as a commented line.  If the line would
    be longer than maxwidth, truncate argument but try to keep its
    parentheses balanced.

    Requires that fmt%"..." will fit into maxwidth characters.

    Requires that fmt ends with a newline.

    >>> commented_line("/* %s */\n", "hello world", 32)
    '/* hello world */\n'
    >>> commented_line("/* %s */\n", "hello world", 15)
    '/* hello... */\n'
    >>> commented_line("#endif /* %s */\n", "((1+2) && defined(FOO))", 32)
    '#endif /* ((1+2) && defi...) */\n'


    The default line limit is 80 characters including the newline:

    >>> long_argument = "long " * 100
    >>> long_line = commented_line("#endif /* %s */\n", long_argument)
    >>> len(long_line)
    80

    >>> long_line[:40]
    '#endif /* long long long long long long '
    >>> long_line[40:]
    'long long long long long long lon... */\n'

    If a line works out to being 80 characters naturally, it isn't truncated,
    and no ellipsis is added.

    >>> medium_argument = "a"*66
    >>> medium_line = commented_line("#endif /* %s */\n", medium_argument)
    >>> len(medium_line)
    80
    >>> "..." in medium_line
    False
    >>> medium_line[:40]
    '#endif /* aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    >>> medium_line[40:]
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa */\n'


    """
    assert fmt.endswith("\n")
    result = fmt % argument
    if len(result) <= maxwidth:
        return result
    else:
        # How long can we let the argument be?  Try filling in the
        # format with an empty argument to find out.
        max_arg_width = maxwidth - len(fmt % "")
        result = fmt % truncate_expression(argument, max_arg_width)
        assert len(result) <= maxwidth
        return result

def negate(expr):
    """Return a negated version of expr; try to avoid double-negation.

    We usually wrap expressions in parentheses and add a "!".
    >>> negate("A && B")
    '!(A && B)'

    But if we recognize the expression as negated, we can restore it.
    >>> negate(negate("A && B"))
    'A && B'

    The same applies for defined(FOO).
    >>> negate("defined(FOO)")
    '!defined(FOO)'
    >>> negate(negate("defined(FOO)"))
    'defined(FOO)'

    Internal parentheses don't confuse us:
    >>> negate("!(FOO) && !(BAR)")
    '!(!(FOO) && !(BAR))'

    """
    expr = expr.strip()
    # See whether we match !(...), with no intervening close-parens.
    m = re.match(r'^!\s*\(([^\)]*)\)$', expr)
    if m:
        return m.group(1)


    # See whether we match !?defined(...), with no intervening close-parens.
    m = re.match(r'^(!?)\s*(defined\([^\)]*\))$', expr)
    if m:
        if m.group(1) == "!":
            prefix = ""
        else:
            prefix = "!"
        return prefix + m.group(2)

    return "!(%s)" % expr

def uncomment(s):
    """
    Remove existing trailing comments from an #else or #endif line.
    """
    s = re.sub(r'//.*','',s)
    s = re.sub(r'/\*.*','',s)
    return s.strip()

def translate(f_in, f_out):
    """
    Read a file from f_in, and write its annotated version to f_out.
    """
    # A stack listing our current if/else state.  Each member of the stack
    # is a list of directives.  Each directive is a 3-tuple of
    #    (command, rest, lineno)
    # where "command" is one of if/ifdef/ifndef/else/elif, and where
    # "rest" is an expression in a format suitable for use with #if, and where
    # lineno is the line number where the directive occurred.
    stack = []
    # the stack element corresponding to the top level of the file.
    whole_file = []
    cur_level = whole_file
    lineno = 0
    for line in f_in:
        lineno += 1
        m = re.match(r'\s*#\s*(if|ifdef|ifndef|else|endif|elif)\b\s*(.*)',
                     line)
        if not m:
            # no directive, so we can just write it out.
            f_out.write(line)
            continue
        command,rest = m.groups()
        if command in ("if", "ifdef", "ifndef"):
            # The #if directive pushes us one level lower on the stack.
            if command == 'ifdef':
                rest = "defined(%s)"%uncomment(rest)
            elif command == 'ifndef':
                rest = "!defined(%s)"%uncomment(rest)
            elif rest.endswith("\\"):
                rest = rest[:-1]+"..."

            rest = uncomment(rest)

            new_level = [ (command, rest, lineno) ]
            stack.append(cur_level)
            cur_level = new_level
            f_out.write(line)
        elif command in ("else", "elif"):
            # We stay at the same level on the stack.  If we have an #else,
            # we comment it.
            if len(cur_level) == 0 or cur_level[-1][0] == 'else':
                raise Problem("Unexpected #%s on %d"% (command,lineno))
            if (len(cur_level) == 1 and command == 'else' and
                lineno > cur_level[0][2] + LINE_OBVIOUSNESS_LIMIT):
                f_out.write(commented_line("#else /* %s */\n",
                                           negate(cur_level[0][1])))
            else:
                f_out.write(line)
            cur_level.append((command, rest, lineno))
        else:
            # We pop one element on the stack, and comment an endif.
            assert command == 'endif'
            if len(stack) == 0:
                raise Problem("Unmatched #%s on %s"% (command,lineno))
            if lineno <= cur_level[0][2] + LINE_OBVIOUSNESS_LIMIT:
                f_out.write(line)
            elif len(cur_level) == 1 or (
                    len(cur_level) == 2 and cur_level[1][0] == 'else'):
                f_out.write(commented_line("#endif /* %s */\n",
                                           cur_level[0][1]))
            else:
                f_out.write(commented_line("#endif /* %s || ... */\n",
                                           cur_level[0][1]))
            cur_level = stack.pop()
    if len(stack) or cur_level != whole_file:
        raise Problem("Missing #endif")

if __name__ == '__main__':

    import sys,os

    if sys.argv[1] == "--self-test":
        import doctest
        doctest.testmod()
        sys.exit(0)

    for fn in sys.argv[1:]:
        with open(fn+"_OUT", 'w') as output_file:
            translate(open(fn, 'r'), output_file)
        os.rename(fn+"_OUT", fn)
