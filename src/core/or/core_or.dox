@dir core/or
@brief core/or: **Onion routing happens here!**

This is the central part of Tor that handles the core tasks of onion routing:
building circuit, handling circuits, attaching circuit to streams, moving
data around, and so forth.

Some aspects of this module should probably be refactored into others.

Notable files here include:

`channel.c`
: Generic channel implementation. Channels handle sending and receiving cells
among tor nodes.

`channeltls.c`
: Channel implementation for TLS-based OR connections. Uses `connection_or.c`.

`circuitbuild.c`
: Code for constructing circuits and choosing their paths.  (*Note*:
this module could plausibly be split into handling the client side,
the server side, and the path generation aspects of circuit building.)

`circuitlist.c`
: Code for maintaining and navigating the global list of circuits.

`circuitmux.c`
: Generic circuitmux implementation. A circuitmux handles deciding, for a
particular channel, which circuit should write next.

`circuitmux_ewma.c`
: A circuitmux implementation based on the EWMA (exponentially
weighted moving average) algorithm.

`circuituse.c`
: Code to actually send and receive data on circuits.

`command.c`
: Handles incoming cells on channels.

`connection.c`
: Generic and common connection tools, and implementation for the simpler
connection types.

`connection_edge.c`
: Implementation for entry and exit connections.

`connection_or.c`
: Implementation for OR connections (the ones that send cells over TLS).

`onion.c`
: Generic code for generating and responding to CREATE and CREATED
cells, and performing the appropriate onion handshakes. Also contains
code to manage the server-side onion queue.

`relay.c`
: Handles particular types of relay cells, and provides code to receive,
encrypt, route, and interpret relay cells.

`scheduler.c`
: Decides which channel/circuit pair is ready to receive the next cell.

