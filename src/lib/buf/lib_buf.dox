@dir /lib/buf
@brief lib/buf: An efficient byte queue.

This module defines the buf_t type, which is used throughout our networking
code.  The implementation is a singly-linked queue of buffer chunks, similar
to the BSD kernel's
["mbuf"](https://www.freebsd.org/cgi/man.cgi?query=mbuf&sektion=9) structure.

The buf_t type is also reasonable for use in constructing long strings.

See \refdir{lib/net} for networking code that uses buf_t, and
\refdir{lib/tls} for cryptographic code that uses buf_t.

