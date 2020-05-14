// Script to edit control_*.c for refactored control reply output functions

@ initialize:python @
@@
import re
from coccilib.report import *

# reply strings "NNN-foo", "NNN+foo", "NNN foo", etc.
r = re.compile(r'^"(\d+)([ +-])(.*)\\r\\n"$')

# Generate name of function to call based on which separator character
# comes between the numeric code and the text
def idname(sep, base):
    if sep == '+':
        return base + "datareply"
    elif sep == '-':
        return base + "midreply"
    else:
        return base + "endreply"

# Generate the actual replacements used by the rules
def gen(s, base, p):
    pos = p[0]
    print_report(pos, "%s %s" % (base, s))
    m = r.match(s)
    if m is None:
        # String not correct format, so fail match
        cocci.include_match(False)
        print_report(pos, "BAD STRING %s" % s)
        return

    code, sep, s1 = m.groups()

    if r'\r\n' in s1:
        # Extra CRLF in string, so fail match
        cocci.include_match(False)
        print_report(pos, "extra CRLF in string %s" % s)
        return

    coccinelle.code = code
    # Need a string that is a single C token, because Coccinelle only allows
    # "identifiers" to be output from Python scripts?
    coccinelle.body = '"%s"' % s1
    coccinelle.id = idname(sep, base)
    return

@ match @
identifier f;
position p;
expression E;
constant s;
@@
(
 connection_printf_to_buf@f@p(E, s, ...)
|
 connection_write_str_to_buf@f@p(s, E)
)

@ script:python sc1 @
s << match.s;
p << match.p;
f << match.f;
id;
body;
code;
@@
if f == 'connection_printf_to_buf':
    gen(s, 'control_printf_', p)
elif f == 'connection_write_str_to_buf':
    gen(s, 'control_write_', p)
else:
    raise(ValueError("%s: %s" % (f, s)))

@ replace @
constant match.s;
expression match.E;
identifier match.f;
identifier sc1.body, sc1.id, sc1.code;
@@
(
-connection_write_str_to_buf@f(s, E)
+id(E, code, body)
|
-connection_printf_to_buf@f(E, s
+id(E, code, body
 , ...)
)
