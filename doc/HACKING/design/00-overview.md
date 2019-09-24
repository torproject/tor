
## Overview ##

This document describes the general structure of the Tor codebase, how
it fits together, what functionality is available for extending Tor,
and gives some notes on how Tor got that way.

Tor remains a work in progress: We've been working on it for more than a
decade, and we've learned a lot about good coding since we first
started.  This means, however, that some of the older pieces of Tor will
have some "code smell" in them that could sure stand a brisk
refactoring.  So when I describe a piece of code, I'll sometimes give a
note on how it got that way, and whether I still think that's a good
idea.

The first drafts of this document were written in the Summer and Fall of
2015, when Tor 0.2.6 was the most recent stable version, and Tor 0.2.7
was under development.  If you're reading this far in the future, some
things may have changed.  Caveat haxxor!

This document is not an overview of the Tor protocol.  For that, see the
design paper and the specifications at https://spec.torproject.org/ .

For more information about Tor's coding standards and some helpful
development tools, see doc/HACKING in the Tor repository.

For more information about writing tests, see doc/HACKING/WritingTests.txt
in the Tor repository.

### The very high level ###

Ultimately, Tor runs as an event-driven network daemon: it responds to
network events, signals, and timers by sending and receiving things over
the network.  Clients, relays, and directory authorities all use the
same codebase: the Tor process will run as a client, relay, or authority
depending on its configuration.

Tor has a few major dependencies, including Libevent (used to tell which
sockets are readable and writable), OpenSSL (used for many encryption
functions, and to implement the TLS protocol), and zlib (used to
compress and uncompress directory information).

Most of Tor's work today is done in a single event-driven main thread.
Tor also spawns one or more worker threads to handle CPU-intensive
tasks.  (Right now, this only includes circuit encryption.)

On startup, Tor initializes its libraries, reads and responds to its
configuration files, and launches a main event loop.  At first, the only
events that Tor listens for are a few signals (like TERM and HUP), and
one or more listener sockets (for different kinds of incoming
connections).  Tor also configures a timer function to run once per
second to handle periodic events.  As Tor runs over time, other events
will open, and new events will be scheduled.

The codebase is divided into a few main subdirectories:

   src/common -- utility functions, not necessarily tor-specific.

   src/or -- implements the Tor protocols.

   src/test -- unit and regression tests

   src/ext -- Code maintained elsewhere that we include in the Tor
   source distribution.

   src/trunnel -- automatically generated code (from the Trunnel)
   tool: used to parse and encode binary formats.

### Some key high-level abstractions ###

The most important abstractions at Tor's high-level are Connections,
Channels, Circuits, and Nodes.

A 'Connection' represents a stream-based information flow.  Most
connections are TCP connections to remote Tor servers and clients. (But
as a shortcut, a relay will sometimes make a connection to itself
without actually using a TCP connection.  More details later on.)
Connections exist in different varieties, depending on what
functionality they provide.  The principle types of connection are
"edge" (eg a socks connection or a connection from an exit relay to a
destination), "OR" (a TLS stream connecting to a relay), "Directory" (an
HTTP connection to learn about the network), and "Control" (a connection
from a controller).

A 'Circuit' is persistent tunnel through the Tor network, established
with public-key cryptography, and used to send cells one or more hops.
Clients keep track of multi-hop circuits, and the cryptography
associated with each hop.  Relays, on the other hand, keep track only of
their hop of each circuit.

A 'Channel' is an abstract view of sending cells to and from a Tor
relay.  Currently, all channels are implemented using OR connections.
If we switch to other strategies in the future, we'll have more
connection types.

A 'Node' is a view of a Tor instance's current knowledge and opinions
about a Tor relay orbridge.

### The rest of this document. ###

> **Note**: This section describes the eventual organization of this
> document, which is not yet complete.

We'll begin with an overview of the various utility functions available
in Tor's 'common' directory.  Knowing about these is key to writing
portable, simple code in Tor.

Then we'll go on and talk about the main data-flow of the Tor network:
how Tor generates and responds to network traffic.  This will occupy a
chapter for the main overview, with other chapters for special topics.

After that, we'll mention the main modules in Tor, and describe the
function of each.

We'll cover the directory subsystem next: how Tor learns about other
relays, and how relays advertise themselves.

Then we'll cover a few specialized modules, such as hidden services,
sandboxing, hibernation, accounting, statistics, guards, path
generation, pluggable transports, and how they integrate with the rest of Tor.

We'll close with a meandering overview of important pending issues in
the Tor codebase, and how they affect the future of the Tor software.

