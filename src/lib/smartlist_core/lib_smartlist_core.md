@dir /lib/smartlist_core
@brief lib/smartlist_core: Minimal dynamic array implementation

A `smartlist_t` is a dynamic array type for holding `void *`.  We use it
throughout the rest of the codebase.

There are higher-level pieces in \refdir{lib/container} but
the ones in lib/smartlist_core are used by the logging code, and therefore
cannot use the logging code.

