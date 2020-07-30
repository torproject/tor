// Look for use of expressions with side-effects inside of debug logs.
//
// This script detects expressions like ++E, --E, E++, and E-- inside of
// calls to log_debug().
//
// The log_debug() macro exits early if debug logging is not enabled,
// potentially causing problems if its arguments have side-effects.

@@
expression E;
@@
*log_debug(... , <+...  --E ...+>, ... );


@@
expression E;
@@
*log_debug(... , <+...  ++E ...+>, ... );

@@
expression E;
@@
*log_debug(... , <+...  E-- ...+>, ... );


@@
expression E;
@@
*log_debug(... , <+...  E++ ...+>, ... );
