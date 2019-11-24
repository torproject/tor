@dir /lib/string
@brief lib/string: Low-level string manipulation.

We have a number of compatibility functions here: some are for handling
functionality that is not implemented (or not implemented the same) on every
platform; some are for providing locale-independent versions of libc
functions that would otherwise be defined differently for different users.

Other functions here are for common string-manipulation operations that we do
in the rest of the codebase.

Any string function high-level enough to need logging belongs in a
higher-level module.
