@dir /lib/llharden
@brief lib/llharden: low-level unconditional process hardening

This module contains process hardening code that we want to run before any
other code, including configuration.  It needs to be self-contained, since
nothing else will be initialized at this point.
