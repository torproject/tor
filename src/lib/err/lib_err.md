@dir /lib/err
@brief lib/err: Lowest-level error handling code.

This module is responsible for generating stack traces, handling raw
assertion failures, and otherwise reporting problems that might not be
safe to report via the regular logging module.

There are three kinds of users for the functions in this module:
  * Code that needs a way to assert(), but which cannot use the regular
    `tor_assert()` macros in logging module.
  * Code that needs signal-safe error reporting.
  * Higher-level error handling code.

