@dir /lib/subsys
@brief lib/subsys: Types for declaring a "subsystem".

## Subsystems in Tor

A subsystem is a module with support for initialization, shutdown,
configuration, and so on.

Many parts of Tor can be initialized, cleaned up, and configured somewhat
independently through a table-driven mechanism.  Each such part is called a
"subsystem".

To declare a subsystem, make a global `const` instance of the `subsys_fns_t`
type, filling in the function pointer fields that you require with ones
corresponding to your subsystem.  Any function pointers left as "NULL" will
be a no-op.  Each system must have a name and a "level", which corresponds to
the order in which it is initialized.  (See `app/main/subsystem_list.c` for a
list of current subsystems and their levels.)

Then, insert your subsystem in the list in `app/main/subsystem_list.c`.  It
will need to occupy a position corresponding to its level.

At this point, your subsystem will be handled like the others: it will get
initialized at startup, torn down at exit, and so on.

Historical note: Not all of Tor's code is currently handled as
subsystems. As you work with older code, you may see some parts of the code
that are initialized from `tor_init()` or `run_tor_main_loop()` or
`tor_run_main()`; and torn down from `tor_cleanup()`.  We aim to migrate
these to subsystems over time; please don't add any new code that follows
this pattern.

