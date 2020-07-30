
## Utility code in Tor

Most of Tor's utility code is in modules in the src/common subdirectory.

These are divided, broadly, into _compatibility_ functions, _utility_
functions, _containers_, and _cryptography_.  (Someday in the future, it
would be great to split these modules into separate directories.  Also, some
functions are probably put in the wrong modules)

### Compatibility code

These functions live in src/common/compat\*.c; some corresponding macros live
in src/common/compat\*.h.  They serve as wrappers around platform-specific or
compiler-specific logic functionality.

In general, the rest of the Tor code *should not* be calling platform-specific
or otherwise non-portable functions.  Instead, they should call wrappers from
compat.c, which implement a common cross-platform API.  (If you don't know
whether a function is portable, it's usually good enough to see whether it
exists on OSX, Linux, and Windows.)

Other compatibility modules include backtrace.c, which generates stack traces
for crash reporting; sandbox.c, which implements the Linux seccomp2 sandbox;
and procmon.c, which handles monitoring a child process.

Parts of address.c are compatibility code for handling network addressing
issues; other parts are in util.c.

Notable compatibility areas are:

   * mmap support for mapping files into the address space (read-only)

   * Code to work around the intricacies

   * Workaround code for Windows's horrible winsock incompatibilities and
     Linux's intricate socket extensions.

   * Helpful string functions like memmem, memstr, asprintf, strlcpy, and
     strlcat that not all platforms have.

   * Locale-ignoring variants of the ctypes functions.

   * Time-manipulation functions

   * File locking function

   * IPv6 functions for platforms that don't have enough IPv6 support

   * Endianness functions

   * OS functions

   * Threading and locking functions.

=== Utility functions

General-purpose utilities are in util.c; they include higher-level wrappers
around many of the compatibility functions to provide things like
file-at-once access, memory management functions, math, string manipulation,
time manipulation, filesystem manipulation, etc.

(Some functionality, like daemon-launching, would be better off in a
compatibility module.)

In util_format.c, we have code to implement stuff like base-32 and base-64
encoding.

The address.c module interfaces with the system resolver and implements
address parsing and formatting functions.  It converts sockaddrs to and from
a more compact tor_addr_t type.

The di_ops.c module provides constant-time comparison and associative-array
operations, for side-channel avoidance.

The logging subsystem in log.c supports logging to files, to controllers, to
stdout/stderr, or to the system log.

The abstraction in memarea.c is used in cases when a large amount of
temporary objects need to be allocated, and they can all be freed at the same
time.

The torgzip.c module wraps the zlib library to implement compression.

Workqueue.c provides a simple multithreaded work-queue implementation.

### Containers

The container.c module defines these container types, used throughout the Tor
codebase.

There is a dynamic array called **smartlist**, used as our general resizeable
array type.  It supports sorting, searching, common set operations, and so
on.  It has specialized functions for smartlists of strings, and for
heap-based priority queues.

There's a bit-array type.

A set of mapping types to map strings, 160-bit digests, and 256-bit digests
to void \*.  These are what we generally use when we want O(1) lookup.

Additionally, for containers, we use the ht.h and tor_queue.h headers, in
src/ext.  These provide intrusive hashtable and linked-list macros.

###  Cryptography

Once, we tried to keep our cryptography code in a single "crypto.c" file,
with an "aes.c" module containing an AES implementation for use with older
OpenSSLs.

Now, our practice has become to introduce crypto_\*.c modules when adding new
cryptography backend code.  We have modules for Ed25519, Curve25519,
secret-to-key algorithms, and password-based boxed encryption.

Our various TLS compatibility code, wrappers, and hacks are kept in
tortls.c, which is probably too full of Tor-specific kludges.  I'm
hoping we can eliminate most of those kludges when we finally remove
support for older versions of our TLS handshake.



