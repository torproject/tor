// Script to clean up after ctrl-reply.cocci -- run as a separate step
// because cleanup_write2 (even when disabled) somehow prevents the
// match rule in ctrl-reply.cocci from matching.

// If it doesn't have to be a printf, turn it into a write

@ cleanup_write @
expression E;
constant code, s;
@@
-control_printf_endreply(E, code, s)
+control_write_endreply(E, code, s)

// Use send_control_done() instead of explicitly writing it out
@ cleanup_send_done @
type T;
identifier f != send_control_done;
expression E;
@@
 T f(...) {
<...
-control_write_endreply(E, 250, "OK")
+send_control_done(E)
 ...>
 }

// Clean up more printfs that could be writes
//
// For some reason, including this rule, even disabled, causes the
// match rule in ctrl-reply.cocci to fail to match some code that has
// %s in its format strings

@ cleanup_write2 @
expression E1, E2;
constant code;
@@
(
-control_printf_endreply(E1, code, "%s", E2)
+control_write_endreply(E1, code, E2)
|
-control_printf_midreply(E1, code, "%s", E2)
+control_write_midreply(E1, code, E2)
)
