@dir /lib/sandbox
@brief lib/sandbox: Linux seccomp2-based sandbox.

This module uses Linux's seccomp2 facility via the
[`libseccomp` library](https://github.com/seccomp/libseccomp), to restrict
the set of system calls that Tor is allowed to invoke while it is running.

Because there are many libc versions that invoke different system calls, and
because handling strings is quite complex, this module is more complex and
less portable than it needs to be.

A better architecture would put the responsibility for invoking tricky system
calls (like open()) in another, less restricted process, and give that
process responsibility for enforcing our sandbox rules.

