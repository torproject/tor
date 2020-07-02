@mainpage Tor source reference

@tableofcontents

@section welcome Welcome to Tor

(For an up-to-date rendered copy of this documentation, see
https://src-ref.docs.torproject.org/tor/index.html .)

This documentation describes the general structure of the Tor codebase, how
it fits together, what functionality is available for extending Tor, and
gives some notes on how Tor got that way.  It also includes a reference for
nearly every function, type, file, and module in the Tor source code.  The
high-level documentation is a work in progress.

Tor itself remains a work in progress too: We've been working on it for
nearly two decades, and we've learned a lot about good coding since we first
started.  This means, however, that some of the older pieces of Tor will have
some "code smell" in them that could stand a brisk refactoring.  So when we
describe a piece of code, we'll sometimes give a note on how it got that way,
and whether we still think that's a good idea.

This document is not an overview of the Tor protocol.  For that, see the
design paper and the specifications at https://spec.torproject.org/ .

For more information about Tor's coding standards and some helpful
development tools, see
[doc/HACKING](https://gitweb.torproject.org/tor.git/tree/doc/HACKING) in the
Tor repository.

@section topics Topic-related documentation

@subpage intro

@subpage arch_goals

@subpage initialization

@subpage dataflow

@subpage certificates

@subpage threading

@subpage strings

@subpage time_periodic

@subpage configuration

@subpage publish_subscribe

@page intro A high-level overview

@tableofcontents

@section highlevel The very high level

Ultimately, Tor runs as an event-driven network daemon: it responds to
network events, signals, and timers by sending and receiving things over
the network.  Clients, relays, and directory authorities all use the
same codebase: the Tor process will run as a client, relay, or authority
depending on its configuration.

Tor has a few major dependencies, including Libevent (used to tell which
sockets are readable and writable), OpenSSL or NSS (used for many encryption
functions, and to implement the TLS protocol), and zlib (used to
compress and uncompress directory information).

Most of Tor's work today is done in a single event-driven main thread.
Tor also spawns one or more worker threads to handle CPU-intensive
tasks.  (Right now, this only includes circuit encryption and the more
expensive compression algorithms.)

On startup, Tor initializes its libraries, reads and responds to its
configuration files, and launches a main event loop.  At first, the only
events that Tor listens for are a few signals (like TERM and HUP), and
one or more listener sockets (for different kinds of incoming
connections).  Tor also configures several timers to handle periodic
events.  As Tor runs over time, other events will open, and new events
will be scheduled.

The codebase is divided into a few top-level subdirectories, each of
which contains several sub-modules.

   - \refdir{ext} -- Code maintained elsewhere that we include in the Tor
     source distribution.  You should not edit this code if you can
     avoid it: we try to keep it identical to the upstream versions.

   - \refdir{lib} -- Lower-level utility code, not necessarily
     tor-specific.

   - `trunnel` -- Automatically generated code (from the Trunnel
     tool): used to parse and encode binary formats.

   - \refdir{core} -- Networking code that is implements the central
     parts of the Tor protocol and main loop.

   - \refdir{feature} -- Aspects of Tor (like directory management,
     running a relay, running a directory authorities, managing a list of
     nodes, running and using onion services) that are built on top of the
     mainloop code.

   - \refdir{app} -- Highest-level functionality; responsible for setting
     up and configuring the Tor daemon, making sure all the lower-level
     modules start up when required, and so on.

   - \refdir{tools} -- Binaries other than Tor that we produce.
      Currently this is tor-resolve, tor-gencert, and the tor_runner.o helper
      module.

   - `test` -- unit tests, regression tests, and a few integration
     tests.

In theory, the above parts of the codebase are sorted from highest-level to
lowest-level, where high-level code is only allowed to invoke lower-level
code, and lower-level code never includes or depends on code of a higher
level.  In practice, this refactoring is incomplete: The modules in
\refdir{lib} are well-factored, but there are many layer violations ("upward
dependencies") in \refdir{core} and \refdir{feature}.
We aim to eliminate those over time.

@section keyabstractions Some key high-level abstractions

The most important abstractions at Tor's high-level are Connections,
Channels, Circuits, and Nodes.

A 'Connection' (connection_t) represents a stream-based information flow.
Most connections are TCP connections to remote Tor servers and clients. (But
as a shortcut, a relay will sometimes make a connection to itself without
actually using a TCP connection.  More details later on.)  Connections exist
in different varieties, depending on what functionality they provide.  The
principle types of connection are edge_connection_t (eg a socks connection or
a connection from an exit relay to a destination), or_connection_t (a TLS
stream connecting to a relay), dir_connection_t (an HTTP connection to learn
about the network), and control_connection_t (a connection from a
controller).

A 'Circuit' (circuit_t) is persistent tunnel through the Tor network,
established with public-key cryptography, and used to send cells one or more
hops.  Clients keep track of multi-hop circuits (origin_circuit_t), and the
cryptography associated with each hop.  Relays, on the other hand, keep track
only of their hop of each circuit (or_circuit_t).

A 'Channel' (channel_t) is an abstract view of sending cells to and from a
Tor relay.  Currently, all channels are implemented using OR connections
(channel_tls_t).  If we switch to other strategies in the future, we'll have
more connection types.

A 'Node' (node_t) is a view of a Tor instance's current knowledge and opinions
about a Tor relay or bridge.
