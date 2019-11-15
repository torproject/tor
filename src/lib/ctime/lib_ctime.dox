@dir /lib/ctime
@brief lib/ctime: Constant-time code to avoid side-channels.

This module contains constant-time implementations of various
data comparison and table lookup functions.  We use these in preference to
memcmp() and so forth, since memcmp() can leak information about its inputs
based on how fast it returns.  In general, your code should call tor_memeq()
and tor_memneq(), not memcmp().

We also define some _non_-constant-time wrappers for memcmp() here: Since we
consider calls to memcmp() to be in error, we require that code that actually
doesn't need to be constant-time to use the fast_memeq() / fast_memneq() /
fast_memcmp() aliases instead.

