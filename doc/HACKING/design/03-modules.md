
## Tor's modules ##

### Generic modules ###

`buffers.c`
: Implements the `buf_t` buffered data type for connections, and several
low-level data handling functions to handle network protocols on it.

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

`config.c`
: Parses options from torrc, and uses them to configure the rest of Tor.

`confparse.c`
: Generic torrc-style parser. Used to parse torrc and state files.

`connection.c`
: Generic and common connection tools, and implementation for the simpler
connection types.

`connection_edge.c`
: Implementation for entry and exit connections.

`connection_or.c`
: Implementation for OR connections (the ones that send cells over TLS).

`main.c`
: Principal entry point, main loops, scheduled events, and network
management for Tor.

`ntmain.c`
: Implements Tor as a Windows service. (Not very well.)

`onion.c`
: Generic code for generating and responding to CREATE and CREATED
cells, and performing the appropriate onion handshakes. Also contains
code to manage the server-side onion queue.

`onion_fast.c`
: Implements the old SHA1-based CREATE_FAST/CREATED_FAST circuit
creation handshake. (Now deprecated.)

`onion_ntor.c`
: Implements the Curve25519-based NTOR circuit creation handshake.

`onion_tap.c`
: Implements the old RSA1024/DH1024-based TAP circuit creation handshake. (Now
deprecated.)

`relay.c`
: Handles particular types of relay cells, and provides code to receive,
encrypt, route, and interpret relay cells.

`scheduler.c`
: Decides which channel/circuit pair is ready to receive the next cell.

`statefile.c`
: Handles loading and storing Tor's state file.

`tor_main.c`
: Contains the actual `main()` function.  (This is placed in a separate
file so that the unit tests can have their own `main()`.)


### Node-status modules ###

`directory.c`
: Implements the HTTP-based directory protocol, including sending,
receiving, and handling most request types.  (*Note*: The client parts
of this, and the generic-HTTP parts of this, could plausibly be split
off.)

`microdesc.c`
: Implements the compact "microdescriptor" format for keeping track of
what we know about a router.

`networkstatus.c`
: Code for fetching, storing, and interpreting consensus vote documents.

`nodelist.c`
: Higher-level view of our knowledge of which Tor servers exist.  Each
`node_t` corresponds to a router we know about.

`routerlist.c`
: Code for storing and retrieving router descriptors and extrainfo
documents.

`routerparse.c`
: Generic and specific code for parsing all Tor directory information
types.

`routerset.c`
: Parses and interprets a specification for a set of routers (by IP
range, fingerprint, nickname (deprecated), or country).


### Client modules ###

`addressmap.c`
: Handles client-side associations between one address and another.
These are used to implement client-side DNS caching (NOT RECOMMENDED),
MapAddress directives, Automapping, and more.

`circpathbias.c`
: Path bias attack detection for circuits: tracks whether
connections made through a particular guard have an unusually high failure rate.

`circuitstats.c`
: Code to track circuit performance statistics in order to adapt our behavior.
Notably includes an algorithm to track circuit build times.

`dnsserv.c`
: Implements DNSPort for clients. (Note that in spite of the word
"server" in this module's name, it is used for Tor clients.  It
implements a DNS server, not DNS for servers.)

`entrynodes.c`
: Chooses, monitors, and remembers guard nodes.  Also contains some
bridge-related code.

`torcert.c`
: Code to interpret and generate Ed25519-based certificates.

### Server modules ###

`dns.c`
: Server-side DNS code.  Handles sending and receiving DNS requests on
exit nodes, and implements the server-side DNS cache.

`dirserv.c`
: Implements part of directory caches that handles responding to
client requests.

`ext_orport.c`
: Implements the extended ORPort protocol for communication between
server-side pluggable transports and Tor servers.

`hibernate.c`
: Performs bandwidth accounting, and puts Tor relays into hibernation
when their bandwidth is exhausted.

`router.c`
: Management code for running a Tor server. In charge of RSA key
maintenance, descriptor generation and uploading.

`routerkeys.c`
: Key handling code for a Tor server. (Currently handles only the
Ed25519 keys, but the RSA keys could be moved here too.)


### Onion service modules ###

`rendcache.c`
: Stores onion service descriptors.

`rendclient.c`
: Client-side implementation of the onion service protocol.

`rendcommon.c`
: Parts of the onion service protocol that are shared by clients,
services, and/or Tor servers.

`rendmid.c`
: Tor-server-side implementation of the onion service protocol. (Handles
acting as an introduction point or a rendezvous point.)

`rendservice.c`
: Service-side implementation of the onion service protocol.

`replaycache.c`
: Backend to check introduce2 requests for replay attempts.


### Authority modules ###

`dircollate.c`
: Helper for `dirvote.c`: Given a set of votes, each containing a list
of Tor nodes, determines which entries across all the votes correspond
to the same nodes, and yields them in a useful order.

`dirvote.c`
: Implements the directory voting algorithms that authorities use.

`keypin.c`
: Implements a persistent key-pinning mechanism to tie RSA1024
identities to ed25519 identities.

### Miscellaneous modules ###

`control.c`
: Implements the Tor controller protocol.

`cpuworker.c`
: Implements the inner work queue function.  We use this to move the
work of circuit creation (on server-side) to other CPUs.

`fp_pair.c`
: Types for handling 2-tuples of 20-byte fingerprints.

`geoip.c`
: Parses geoip files (which map IP addresses to country codes), and
performs lookups on the internal geoip table.  Also stores some
geoip-related statistics.

`policies.c`
: Parses and implements Tor exit policies.

`reasons.c`
: Maps internal reason-codes to human-readable strings.

`rephist.c`
: Tracks Tor servers' performance over time.

`status.c`
: Writes periodic "heartbeat" status messages about the state of the Tor
process.

`transports.c`
: Implements management for the pluggable transports subsystem.
