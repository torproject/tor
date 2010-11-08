/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file or.h
 * \brief Master header file for Tor-specific functionality.
 **/

#ifndef _TOR_OR_H
#define _TOR_OR_H

#include "orconfig.h"

#ifdef __COVERITY__
/* If we're building for a static analysis, turn on all the off-by-default
 * features. */
#ifndef INSTRUMENT_DOWNLOADS
#define INSTRUMENT_DOWNLOADS 1
#endif
#endif

#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include "torint.h"
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ASSERT_H
#include <assert.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef MS_WINDOWS
#include <io.h>
#include <process.h>
#include <direct.h>
#include <windows.h>
#define snprintf _snprintf
#endif

#ifdef USE_BUFFEREVENTS
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/util.h>
#endif

#include "crypto.h"
#include "tortls.h"
#include "../common/torlog.h"
#include "container.h"
#include "torgzip.h"
#include "address.h"
#include "compat_libevent.h"
#include "ht.h"

/* These signals are defined to help control_signal_act work.
 */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif
#ifndef SIGUSR2
#define SIGUSR2 12
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
/* Controller signals start at a high number so we don't
 * conflict with system-defined signals. */
#define SIGNEWNYM 129
#define SIGCLEARDNSCACHE 130

#if (SIZEOF_CELL_T != 0)
/* On Irix, stdlib.h defines a cell_t type, so we need to make sure
 * that our stuff always calls cell_t something different. */
#define cell_t tor_cell_t
#endif

/** Length of longest allowable configured nickname. */
#define MAX_NICKNAME_LEN 19
/** Length of a router identity encoded as a hexadecimal digest, plus
 * possible dollar sign. */
#define MAX_HEX_NICKNAME_LEN (HEX_DIGEST_LEN+1)
/** Maximum length of verbose router identifier: dollar sign, hex ID digest,
 * equal sign or tilde, nickname. */
#define MAX_VERBOSE_NICKNAME_LEN (1+HEX_DIGEST_LEN+1+MAX_NICKNAME_LEN)

/** Maximum size, in bytes, for resized buffers. */
#define MAX_BUF_SIZE ((1<<24)-1) /* 16MB-1 */
/** Maximum size, in bytes, for any directory object that we've downloaded. */
#define MAX_DIR_DL_SIZE MAX_BUF_SIZE

/** For HTTP parsing: Maximum number of bytes we'll accept in the headers
 * of an HTTP request or response. */
#define MAX_HEADERS_SIZE 50000
/** Maximum size, in bytes, for any directory object that we're accepting
 * as an upload. */
#define MAX_DIR_UL_SIZE MAX_BUF_SIZE

/** Maximum size, in bytes, of a single router descriptor uploaded to us
 * as a directory authority. Caches and clients fetch whatever descriptors
 * the authorities tell them to fetch, and don't care about size. */
#define MAX_DESCRIPTOR_UPLOAD_SIZE 20000

/** Maximum size of a single extrainfo document, as above. */
#define MAX_EXTRAINFO_UPLOAD_SIZE 50000

/** How long do we keep DNS cache entries before purging them (regardless of
 * their TTL)? */
#define MAX_DNS_ENTRY_AGE (30*60)
/** How long do we cache/tell clients to cache DNS records when no TTL is
 * known? */
#define DEFAULT_DNS_TTL (30*60)
/** How long can a TTL be before we stop believing it? */
#define MAX_DNS_TTL (3*60*60)
/** How small can a TTL be before we stop believing it?  Provides rudimentary
 * pinning. */
#define MIN_DNS_TTL 60

/** How often do we rotate onion keys? */
#define MIN_ONION_KEY_LIFETIME (7*24*60*60)
/** How often do we rotate TLS contexts? */
#define MAX_SSL_KEY_LIFETIME (2*60*60)

/** How old do we allow a router to get before removing it
 * from the router list? In seconds. */
#define ROUTER_MAX_AGE (60*60*48)
/** How old can a router get before we (as a server) will no longer
 * consider it live? In seconds. */
#define ROUTER_MAX_AGE_TO_PUBLISH (60*60*20)
/** How old do we let a saved descriptor get before force-removing it? */
#define OLD_ROUTER_DESC_MAX_AGE (60*60*24*5)

/** Possible rules for generating circuit IDs on an OR connection. */
typedef enum {
  CIRC_ID_TYPE_LOWER=0, /**< Pick from 0..1<<15-1. */
  CIRC_ID_TYPE_HIGHER=1, /**< Pick from 1<<15..1<<16-1. */
  /** The other side of a connection is an OP: never create circuits to it,
   * and let it use any circuit ID it wants. */
  CIRC_ID_TYPE_NEITHER=2
} circ_id_type_t;

#define _CONN_TYPE_MIN 3
/** Type for sockets listening for OR connections. */
#define CONN_TYPE_OR_LISTENER 3
/** A bidirectional TLS connection transmitting a sequence of cells.
 * May be from an OR to an OR, or from an OP to an OR. */
#define CONN_TYPE_OR 4
/** A TCP connection from an onion router to a stream's destination. */
#define CONN_TYPE_EXIT 5
/** Type for sockets listening for SOCKS connections. */
#define CONN_TYPE_AP_LISTENER 6
/** A SOCKS proxy connection from the user application to the onion
 * proxy. */
#define CONN_TYPE_AP 7
/** Type for sockets listening for HTTP connections to the directory server. */
#define CONN_TYPE_DIR_LISTENER 8
/** Type for HTTP connections to the directory server. */
#define CONN_TYPE_DIR 9
/** Connection from the main process to a CPU worker process. */
#define CONN_TYPE_CPUWORKER 10
/** Type for listening for connections from user interface process. */
#define CONN_TYPE_CONTROL_LISTENER 11
/** Type for connections from user interface process. */
#define CONN_TYPE_CONTROL 12
/** Type for sockets listening for transparent connections redirected by pf or
 * netfilter. */
#define CONN_TYPE_AP_TRANS_LISTENER 13
/** Type for sockets listening for transparent connections redirected by
 * natd. */
#define CONN_TYPE_AP_NATD_LISTENER 14
/** Type for sockets listening for DNS requests. */
#define CONN_TYPE_AP_DNS_LISTENER 15
#define _CONN_TYPE_MAX 15
/* !!!! If _CONN_TYPE_MAX is ever over 15, we must grow the type field in
 * connection_t. */

/* Proxy client types */
#define PROXY_NONE 0
#define PROXY_CONNECT 1
#define PROXY_SOCKS4 2
#define PROXY_SOCKS5 3

/* Proxy client handshake states */
#define PROXY_HTTPS_WANT_CONNECT_OK 1
#define PROXY_SOCKS4_WANT_CONNECT_OK 2
#define PROXY_SOCKS5_WANT_AUTH_METHOD_NONE 3
#define PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929 4
#define PROXY_SOCKS5_WANT_AUTH_RFC1929_OK 5
#define PROXY_SOCKS5_WANT_CONNECT_OK 6
#define PROXY_CONNECTED 7

/** True iff <b>x</b> is an edge connection. */
#define CONN_IS_EDGE(x) \
  ((x)->type == CONN_TYPE_EXIT || (x)->type == CONN_TYPE_AP)

/** State for any listener connection. */
#define LISTENER_STATE_READY 0

#define _CPUWORKER_STATE_MIN 1
/** State for a connection to a cpuworker process that's idle. */
#define CPUWORKER_STATE_IDLE 1
/** State for a connection to a cpuworker process that's processing a
 * handshake. */
#define CPUWORKER_STATE_BUSY_ONION 2
#define _CPUWORKER_STATE_MAX 2

#define CPUWORKER_TASK_ONION CPUWORKER_STATE_BUSY_ONION

#define _OR_CONN_STATE_MIN 1
/** State for a connection to an OR: waiting for connect() to finish. */
#define OR_CONN_STATE_CONNECTING 1
/** State for a connection to an OR: waiting for proxy handshake to complete */
#define OR_CONN_STATE_PROXY_HANDSHAKING 2
/** State for a connection to an OR or client: SSL is handshaking, not done
 * yet. */
#define OR_CONN_STATE_TLS_HANDSHAKING 3
/** State for a connection to an OR: We're doing a second SSL handshake for
 * renegotiation purposes. */
#define OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING 4
/** State for a connection at an OR: We're waiting for the client to
 * renegotiate. */
#define OR_CONN_STATE_TLS_SERVER_RENEGOTIATING 5
/** State for a connection to an OR: We're done with our SSL handshake, but we
 * haven't yet negotiated link protocol versions and sent a netinfo cell.
 */
#define OR_CONN_STATE_OR_HANDSHAKING 6
/** State for a connection to an OR: Ready to send/receive cells. */
#define OR_CONN_STATE_OPEN 7
#define _OR_CONN_STATE_MAX 7

#define _EXIT_CONN_STATE_MIN 1
/** State for an exit connection: waiting for response from DNS farm. */
#define EXIT_CONN_STATE_RESOLVING 1
/** State for an exit connection: waiting for connect() to finish. */
#define EXIT_CONN_STATE_CONNECTING 2
/** State for an exit connection: open and ready to transmit data. */
#define EXIT_CONN_STATE_OPEN 3
/** State for an exit connection: waiting to be removed. */
#define EXIT_CONN_STATE_RESOLVEFAILED 4
#define _EXIT_CONN_STATE_MAX 4

/* The AP state values must be disjoint from the EXIT state values. */
#define _AP_CONN_STATE_MIN 5
/** State for a SOCKS connection: waiting for SOCKS request. */
#define AP_CONN_STATE_SOCKS_WAIT 5
/** State for a SOCKS connection: got a y.onion URL; waiting to receive
 * rendezvous descriptor. */
#define AP_CONN_STATE_RENDDESC_WAIT 6
/** The controller will attach this connection to a circuit; it isn't our
 * job to do so. */
#define AP_CONN_STATE_CONTROLLER_WAIT 7
/** State for a SOCKS connection: waiting for a completed circuit. */
#define AP_CONN_STATE_CIRCUIT_WAIT 8
/** State for a SOCKS connection: sent BEGIN, waiting for CONNECTED. */
#define AP_CONN_STATE_CONNECT_WAIT 9
/** State for a SOCKS connection: sent RESOLVE, waiting for RESOLVED. */
#define AP_CONN_STATE_RESOLVE_WAIT 10
/** State for a SOCKS connection: ready to send and receive. */
#define AP_CONN_STATE_OPEN 11
/** State for a transparent natd connection: waiting for original
 * destination. */
#define AP_CONN_STATE_NATD_WAIT 12
#define _AP_CONN_STATE_MAX 12

/** True iff the AP_CONN_STATE_* value <b>s</b> means that the corresponding
 * edge connection is not attached to any circuit. */
#define AP_CONN_STATE_IS_UNATTACHED(s) \
  ((s) <= AP_CONN_STATE_CIRCUIT_WAIT || (s) == AP_CONN_STATE_NATD_WAIT)

#define _DIR_CONN_STATE_MIN 1
/** State for connection to directory server: waiting for connect(). */
#define DIR_CONN_STATE_CONNECTING 1
/** State for connection to directory server: sending HTTP request. */
#define DIR_CONN_STATE_CLIENT_SENDING 2
/** State for connection to directory server: reading HTTP response. */
#define DIR_CONN_STATE_CLIENT_READING 3
/** State for connection to directory server: happy and finished. */
#define DIR_CONN_STATE_CLIENT_FINISHED 4
/** State for connection at directory server: waiting for HTTP request. */
#define DIR_CONN_STATE_SERVER_COMMAND_WAIT 5
/** State for connection at directory server: sending HTTP response. */
#define DIR_CONN_STATE_SERVER_WRITING 6
#define _DIR_CONN_STATE_MAX 6

/** True iff the purpose of <b>conn</b> means that it's a server-side
 * directory connection. */
#define DIR_CONN_IS_SERVER(conn) ((conn)->purpose == DIR_PURPOSE_SERVER)

#define _CONTROL_CONN_STATE_MIN 1
/** State for a control connection: Authenticated and accepting v1 commands. */
#define CONTROL_CONN_STATE_OPEN 1
/** State for a control connection: Waiting for authentication; speaking
 * protocol v1. */
#define CONTROL_CONN_STATE_NEEDAUTH 2
#define _CONTROL_CONN_STATE_MAX 2

#define _DIR_PURPOSE_MIN 3
/** A connection to a directory server: download a rendezvous
 * descriptor. */
#define DIR_PURPOSE_FETCH_RENDDESC 3
/** A connection to a directory server: set after a rendezvous
 * descriptor is downloaded. */
#define DIR_PURPOSE_HAS_FETCHED_RENDDESC 4
/** A connection to a directory server: download one or more v2
 * network-status objects */
#define DIR_PURPOSE_FETCH_V2_NETWORKSTATUS 5
/** A connection to a directory server: download one or more server
 * descriptors. */
#define DIR_PURPOSE_FETCH_SERVERDESC 6
/** A connection to a directory server: download one or more extra-info
 * documents. */
#define DIR_PURPOSE_FETCH_EXTRAINFO 7
/** A connection to a directory server: upload a server descriptor. */
#define DIR_PURPOSE_UPLOAD_DIR 8
/** A connection to a directory server: upload a rendezvous
 * descriptor. */
#define DIR_PURPOSE_UPLOAD_RENDDESC 9
/** A connection to a directory server: upload a v3 networkstatus vote. */
#define DIR_PURPOSE_UPLOAD_VOTE 10
/** A connection to a directory server: upload a v3 consensus signature */
#define DIR_PURPOSE_UPLOAD_SIGNATURES 11
/** A connection to a directory server: download one or more v3 networkstatus
 * votes. */
#define DIR_PURPOSE_FETCH_STATUS_VOTE 12
/** A connection to a directory server: download a v3 detached signatures
 * object for a consensus. */
#define DIR_PURPOSE_FETCH_DETACHED_SIGNATURES 13
/** A connection to a directory server: download a v3 networkstatus
 * consensus. */
#define DIR_PURPOSE_FETCH_CONSENSUS 14
/** A connection to a directory server: download one or more directory
 * authority certificates. */
#define DIR_PURPOSE_FETCH_CERTIFICATE 15

/** Purpose for connection at a directory server. */
#define DIR_PURPOSE_SERVER 16
/** A connection to a hidden service directory server: upload a v2 rendezvous
 * descriptor. */
#define DIR_PURPOSE_UPLOAD_RENDDESC_V2 17
/** A connection to a hidden service directory server: download a v2 rendezvous
 * descriptor. */
#define DIR_PURPOSE_FETCH_RENDDESC_V2 18
/** A connection to a directory server: download a microdescriptor. */
#define DIR_PURPOSE_FETCH_MICRODESC 19
#define _DIR_PURPOSE_MAX 19

/** True iff <b>p</b> is a purpose corresponding to uploading data to a
 * directory server. */
#define DIR_PURPOSE_IS_UPLOAD(p)                \
  ((p)==DIR_PURPOSE_UPLOAD_DIR ||               \
   (p)==DIR_PURPOSE_UPLOAD_RENDDESC ||          \
   (p)==DIR_PURPOSE_UPLOAD_VOTE ||              \
   (p)==DIR_PURPOSE_UPLOAD_SIGNATURES)

#define _EXIT_PURPOSE_MIN 1
/** This exit stream wants to do an ordinary connect. */
#define EXIT_PURPOSE_CONNECT 1
/** This exit stream wants to do a resolve (either normal or reverse). */
#define EXIT_PURPOSE_RESOLVE 2
#define _EXIT_PURPOSE_MAX 2

/* !!!! If any connection purpose is ever over 31, we must grow the type
 * field in connection_t. */

/** Circuit state: I'm the origin, still haven't done all my handshakes. */
#define CIRCUIT_STATE_BUILDING 0
/** Circuit state: Waiting to process the onionskin. */
#define CIRCUIT_STATE_ONIONSKIN_PENDING 1
/** Circuit state: I'd like to deliver a create, but my n_conn is still
 * connecting. */
#define CIRCUIT_STATE_OR_WAIT 2
/** Circuit state: onionskin(s) processed, ready to send/receive cells. */
#define CIRCUIT_STATE_OPEN 3

#define _CIRCUIT_PURPOSE_MIN 1

/* these circuits were initiated elsewhere */
#define _CIRCUIT_PURPOSE_OR_MIN 1
/** OR-side circuit purpose: normal circuit, at OR. */
#define CIRCUIT_PURPOSE_OR 1
/** OR-side circuit purpose: At OR, from Bob, waiting for intro from Alices. */
#define CIRCUIT_PURPOSE_INTRO_POINT 2
/** OR-side circuit purpose: At OR, from Alice, waiting for Bob. */
#define CIRCUIT_PURPOSE_REND_POINT_WAITING 3
/** OR-side circuit purpose: At OR, both circuits have this purpose. */
#define CIRCUIT_PURPOSE_REND_ESTABLISHED 4
#define _CIRCUIT_PURPOSE_OR_MAX 4

/* these circuits originate at this node */

/* here's how circ client-side purposes work:
 *   normal circuits are C_GENERAL.
 *   circuits that are c_introducing are either on their way to
 *     becoming open, or they are open and waiting for a
 *     suitable rendcirc before they send the intro.
 *   circuits that are c_introduce_ack_wait have sent the intro,
 *     but haven't gotten a response yet.
 *   circuits that are c_establish_rend are either on their way
 *     to becoming open, or they are open and have sent the
 *     establish_rendezvous cell but haven't received an ack.
 *   circuits that are c_rend_ready are open and have received a
 *     rend ack, but haven't heard from bob yet. if they have a
 *     buildstate->pending_final_cpath then they're expecting a
 *     cell from bob, else they're not.
 *   circuits that are c_rend_ready_intro_acked are open, and
 *     some intro circ has sent its intro and received an ack.
 *   circuits that are c_rend_joined are open, have heard from
 *     bob, and are talking to him.
 */
/** Client-side circuit purpose: Normal circuit, with cpath. */
#define CIRCUIT_PURPOSE_C_GENERAL 5
/** Client-side circuit purpose: at Alice, connecting to intro point. */
#define CIRCUIT_PURPOSE_C_INTRODUCING 6
/** Client-side circuit purpose: at Alice, sent INTRODUCE1 to intro point,
 * waiting for ACK/NAK. */
#define CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT 7
/** Client-side circuit purpose: at Alice, introduced and acked, closing. */
#define CIRCUIT_PURPOSE_C_INTRODUCE_ACKED 8
/** Client-side circuit purpose: at Alice, waiting for ack. */
#define CIRCUIT_PURPOSE_C_ESTABLISH_REND 9
/** Client-side circuit purpose: at Alice, waiting for Bob. */
#define CIRCUIT_PURPOSE_C_REND_READY 10
/** Client-side circuit purpose: at Alice, waiting for Bob, INTRODUCE
 * has been acknowledged. */
#define CIRCUIT_PURPOSE_C_REND_READY_INTRO_ACKED 11
/** Client-side circuit purpose: at Alice, rendezvous established. */
#define CIRCUIT_PURPOSE_C_REND_JOINED 12
/** This circuit is used for build time measurement only */
#define CIRCUIT_PURPOSE_C_MEASURE_TIMEOUT 13
#define _CIRCUIT_PURPOSE_C_MAX 13
/** Hidden-service-side circuit purpose: at Bob, waiting for introductions. */
#define CIRCUIT_PURPOSE_S_ESTABLISH_INTRO 14
/** Hidden-service-side circuit purpose: at Bob, successfully established
 * intro. */
#define CIRCUIT_PURPOSE_S_INTRO 15
/** Hidden-service-side circuit purpose: at Bob, connecting to rend point. */
#define CIRCUIT_PURPOSE_S_CONNECT_REND 16
/** Hidden-service-side circuit purpose: at Bob, rendezvous established. */
#define CIRCUIT_PURPOSE_S_REND_JOINED 17
/** A testing circuit; not meant to be used for actual traffic. */
#define CIRCUIT_PURPOSE_TESTING 18
/** A controller made this circuit and Tor should not use it. */
#define CIRCUIT_PURPOSE_CONTROLLER 19
#define _CIRCUIT_PURPOSE_MAX 19
/** A catch-all for unrecognized purposes. Currently we don't expect
 * to make or see any circuits with this purpose. */
#define CIRCUIT_PURPOSE_UNKNOWN 255

/** True iff the circuit purpose <b>p</b> is for a circuit that
 * originated at this node. */
#define CIRCUIT_PURPOSE_IS_ORIGIN(p) ((p)>_CIRCUIT_PURPOSE_OR_MAX)
/** True iff the circuit purpose <b>p</b> is for a circuit that originated
 * here to serve as a client.  (Hidden services don't count here.) */
#define CIRCUIT_PURPOSE_IS_CLIENT(p)  \
  ((p)> _CIRCUIT_PURPOSE_OR_MAX &&    \
   (p)<=_CIRCUIT_PURPOSE_C_MAX)
/** True iff the circuit_t <b>c</b> is actually an origin_circuit_t. */
#define CIRCUIT_IS_ORIGIN(c) (CIRCUIT_PURPOSE_IS_ORIGIN((c)->purpose))
/** True iff the circuit purpose <b>p</b> is for an established rendezvous
 * circuit. */
#define CIRCUIT_PURPOSE_IS_ESTABLISHED_REND(p) \
  ((p) == CIRCUIT_PURPOSE_C_REND_JOINED ||     \
   (p) == CIRCUIT_PURPOSE_S_REND_JOINED)

/** How many circuits do we want simultaneously in-progress to handle
 * a given stream? */
#define MIN_CIRCUITS_HANDLING_STREAM 2

/* These RELAY_COMMAND constants define values for relay cell commands, and
* must match those defined in tor-spec.txt. */
#define RELAY_COMMAND_BEGIN 1
#define RELAY_COMMAND_DATA 2
#define RELAY_COMMAND_END 3
#define RELAY_COMMAND_CONNECTED 4
#define RELAY_COMMAND_SENDME 5
#define RELAY_COMMAND_EXTEND 6
#define RELAY_COMMAND_EXTENDED 7
#define RELAY_COMMAND_TRUNCATE 8
#define RELAY_COMMAND_TRUNCATED 9
#define RELAY_COMMAND_DROP 10
#define RELAY_COMMAND_RESOLVE 11
#define RELAY_COMMAND_RESOLVED 12
#define RELAY_COMMAND_BEGIN_DIR 13

#define RELAY_COMMAND_ESTABLISH_INTRO 32
#define RELAY_COMMAND_ESTABLISH_RENDEZVOUS 33
#define RELAY_COMMAND_INTRODUCE1 34
#define RELAY_COMMAND_INTRODUCE2 35
#define RELAY_COMMAND_RENDEZVOUS1 36
#define RELAY_COMMAND_RENDEZVOUS2 37
#define RELAY_COMMAND_INTRO_ESTABLISHED 38
#define RELAY_COMMAND_RENDEZVOUS_ESTABLISHED 39
#define RELAY_COMMAND_INTRODUCE_ACK 40

/* Reasons why an OR connection is closed. */
#define END_OR_CONN_REASON_DONE           1
#define END_OR_CONN_REASON_REFUSED        2 /* connection refused */
#define END_OR_CONN_REASON_OR_IDENTITY    3
#define END_OR_CONN_REASON_CONNRESET      4 /* connection reset by peer */
#define END_OR_CONN_REASON_TIMEOUT        5
#define END_OR_CONN_REASON_NO_ROUTE       6 /* no route to host/net */
#define END_OR_CONN_REASON_IO_ERROR       7 /* read/write error */
#define END_OR_CONN_REASON_RESOURCE_LIMIT 8 /* sockets, buffers, etc */
#define END_OR_CONN_REASON_MISC           9

/* Reasons why we (or a remote OR) might close a stream. See tor-spec.txt for
 * documentation of these.  The values must match. */
#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_CONNECTREFUSED 3
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_TIMEOUT 7
#define END_STREAM_REASON_NOROUTE 8
#define END_STREAM_REASON_HIBERNATING 9
#define END_STREAM_REASON_INTERNAL 10
#define END_STREAM_REASON_RESOURCELIMIT 11
#define END_STREAM_REASON_CONNRESET 12
#define END_STREAM_REASON_TORPROTOCOL 13
#define END_STREAM_REASON_NOTDIRECTORY 14
#define END_STREAM_REASON_ENTRYPOLICY 15

/* These high-numbered end reasons are not part of the official spec,
 * and are not intended to be put in relay end cells. They are here
 * to be more informative when sending back socks replies to the
 * application. */
/* XXXX 256 is no longer used; feel free to reuse it. */
/** We were unable to attach the connection to any circuit at all. */
/* XXXX the ways we use this one don't make a lot of sense. */
#define END_STREAM_REASON_CANT_ATTACH 257
/** We can't connect to any directories at all, so we killed our streams
 * before they can time out. */
#define END_STREAM_REASON_NET_UNREACHABLE 258
/** This is a SOCKS connection, and the client used (or misused) the SOCKS
 * protocol in a way we couldn't handle. */
#define END_STREAM_REASON_SOCKSPROTOCOL 259
/** This is a transparent proxy connection, but we can't extract the original
 * target address:port. */
#define END_STREAM_REASON_CANT_FETCH_ORIG_DEST 260
/** This is a connection on the NATD port, and the destination IP:Port was
 * either ill-formed or out-of-range. */
#define END_STREAM_REASON_INVALID_NATD_DEST 261

/** Bitwise-and this value with endreason to mask out all flags. */
#define END_STREAM_REASON_MASK 511

/** Bitwise-or this with the argument to control_event_stream_status
 * to indicate that the reason came from an END cell. */
#define END_STREAM_REASON_FLAG_REMOTE 512
/** Bitwise-or this with the argument to control_event_stream_status
 * to indicate that we already sent a CLOSED stream event. */
#define END_STREAM_REASON_FLAG_ALREADY_SENT_CLOSED 1024
/** Bitwise-or this with endreason to indicate that we already sent
 * a socks reply, and no further reply needs to be sent from
 * connection_mark_unattached_ap(). */
#define END_STREAM_REASON_FLAG_ALREADY_SOCKS_REPLIED 2048

/** Reason for remapping an AP connection's address: we have a cached
 * answer. */
#define REMAP_STREAM_SOURCE_CACHE 1
/** Reason for remapping an AP connection's address: the exit node told us an
 * answer. */
#define REMAP_STREAM_SOURCE_EXIT 2

/* 'type' values to use in RESOLVED cells.  Specified in tor-spec.txt. */
#define RESOLVED_TYPE_HOSTNAME 0
#define RESOLVED_TYPE_IPV4 4
#define RESOLVED_TYPE_IPV6 6
#define RESOLVED_TYPE_ERROR_TRANSIENT 0xF0
#define RESOLVED_TYPE_ERROR 0xF1

/* Negative reasons are internal: we never send them in a DESTROY or TRUNCATE
 * call; they only go to the controller for tracking  */
/** Our post-timeout circuit time measurement period expired.
 * We must give up now */
#define END_CIRC_REASON_MEASUREMENT_EXPIRED -3

/** We couldn't build a path for this circuit. */
#define END_CIRC_REASON_NOPATH          -2
/** Catch-all "other" reason for closing origin circuits. */
#define END_CIRC_AT_ORIGIN              -1

/* Reasons why we (or a remote OR) might close a circuit. See tor-spec.txt for
 * documentation of these. */
#define _END_CIRC_REASON_MIN            0
#define END_CIRC_REASON_NONE            0
#define END_CIRC_REASON_TORPROTOCOL     1
#define END_CIRC_REASON_INTERNAL        2
#define END_CIRC_REASON_REQUESTED       3
#define END_CIRC_REASON_HIBERNATING     4
#define END_CIRC_REASON_RESOURCELIMIT   5
#define END_CIRC_REASON_CONNECTFAILED   6
#define END_CIRC_REASON_OR_IDENTITY     7
#define END_CIRC_REASON_OR_CONN_CLOSED  8
#define END_CIRC_REASON_FINISHED        9
#define END_CIRC_REASON_TIMEOUT         10
#define END_CIRC_REASON_DESTROYED       11
#define END_CIRC_REASON_NOSUCHSERVICE   12
#define _END_CIRC_REASON_MAX            12

/** Bitwise-OR this with the argument to circuit_mark_for_close() or
 * control_event_circuit_status() to indicate that the reason was
 * passed through from a destroy or truncate cell. */
#define END_CIRC_REASON_FLAG_REMOTE     512

/** Length of 'y' portion of 'y.onion' URL. */
#define REND_SERVICE_ID_LEN_BASE32 16

/** Length of 'y.onion' including '.onion' URL. */
#define REND_SERVICE_ADDRESS_LEN (16+1+5)

/** Length of a binary-encoded rendezvous service ID. */
#define REND_SERVICE_ID_LEN 10

/** Time period for which a v2 descriptor will be valid. */
#define REND_TIME_PERIOD_V2_DESC_VALIDITY (24*60*60)

/** Time period within which two sets of v2 descriptors will be uploaded in
 * parallel. */
#define REND_TIME_PERIOD_OVERLAPPING_V2_DESCS (60*60)

/** Number of non-consecutive replicas (i.e. distributed somewhere
 * in the ring) for a descriptor. */
#define REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS 2

/** Number of consecutive replicas for a descriptor. */
#define REND_NUMBER_OF_CONSECUTIVE_REPLICAS 3

/** Length of v2 descriptor ID (32 base32 chars = 160 bits). */
#define REND_DESC_ID_V2_LEN_BASE32 32

/** Length of the base32-encoded secret ID part of versioned hidden service
 * descriptors. */
#define REND_SECRET_ID_PART_LEN_BASE32 32

/** Length of the base32-encoded hash of an introduction point's
 * identity key. */
#define REND_INTRO_POINT_ID_LEN_BASE32 32

/** Length of the descriptor cookie that is used for client authorization
 * to hidden services. */
#define REND_DESC_COOKIE_LEN 16

/** Length of the base64-encoded descriptor cookie that is used for
 * exchanging client authorization between hidden service and client. */
#define REND_DESC_COOKIE_LEN_BASE64 22

/** Length of client identifier in encrypted introduction points for hidden
 * service authorization type 'basic'. */
#define REND_BASIC_AUTH_CLIENT_ID_LEN 4

/** Multiple of the number of clients to which the real number of clients
 * is padded with fake clients for hidden service authorization type
 * 'basic'. */
#define REND_BASIC_AUTH_CLIENT_MULTIPLE 16

/** Length of client entry consisting of client identifier and encrypted
 * session key for hidden service authorization type 'basic'. */
#define REND_BASIC_AUTH_CLIENT_ENTRY_LEN (REND_BASIC_AUTH_CLIENT_ID_LEN \
                                          + CIPHER_KEY_LEN)

/** Maximum size of v2 hidden service descriptors. */
#define REND_DESC_MAX_SIZE (20 * 1024)

/** Legal characters for use in authorized client names for a hidden
 * service. */
#define REND_LEGAL_CLIENTNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-_"

/** Maximum length of authorized client names for a hidden service. */
#define REND_CLIENTNAME_MAX_LEN 16

/** Length of the rendezvous cookie that is used to connect circuits at the
 * rendezvous point. */
#define REND_COOKIE_LEN DIGEST_LEN

/** Client authorization type that a hidden service performs. */
typedef enum rend_auth_type_t {
  REND_NO_AUTH      = 0,
  REND_BASIC_AUTH   = 1,
  REND_STEALTH_AUTH = 2,
} rend_auth_type_t;

/** Client-side configuration of authorization for a hidden service. */
typedef struct rend_service_authorization_t {
  char descriptor_cookie[REND_DESC_COOKIE_LEN];
  char onion_address[REND_SERVICE_ADDRESS_LEN+1];
  rend_auth_type_t auth_type;
} rend_service_authorization_t;

/** Client- and server-side data that is used for hidden service connection
 * establishment. Not all fields contain data depending on where this struct
 * is used. */
typedef struct rend_data_t {
  /** Onion address (without the .onion part) that a client requests. */
  char onion_address[REND_SERVICE_ID_LEN_BASE32+1];

  /** (Optional) descriptor cookie that is used by a client. */
  char descriptor_cookie[REND_DESC_COOKIE_LEN];

  /** Authorization type for accessing a service used by a client. */
  rend_auth_type_t auth_type;

  /** Hash of the hidden service's PK used by a service. */
  char rend_pk_digest[DIGEST_LEN];

  /** Rendezvous cookie used by both, client and service. */
  char rend_cookie[REND_COOKIE_LEN];
} rend_data_t;

/** Time interval for tracking possible replays of INTRODUCE2 cells.
 * Incoming cells with timestamps half of this interval in the past or
 * future are dropped immediately. */
#define REND_REPLAY_TIME_INTERVAL (60 * 60)

/** Used to indicate which way a cell is going on a circuit. */
typedef enum {
  CELL_DIRECTION_IN=1, /**< The cell is moving towards the origin. */
  CELL_DIRECTION_OUT=2, /**< The cell is moving away from the origin. */
} cell_direction_t;

/** Initial value for both sides of a circuit transmission window when the
 * circuit is initialized.  Measured in cells. */
#define CIRCWINDOW_START 1000
/** Amount to increment a circuit window when we get a circuit SENDME. */
#define CIRCWINDOW_INCREMENT 100
/** Initial value on both sides of a stream transmission window when the
 * stream is initialized.  Measured in cells. */
#define STREAMWINDOW_START 500
/** Amount to increment a stream window when we get a stream SENDME. */
#define STREAMWINDOW_INCREMENT 50

/* Cell commands.  These values are defined in tor-spec.txt. */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_CREATED 2
#define CELL_RELAY 3
#define CELL_DESTROY 4
#define CELL_CREATE_FAST 5
#define CELL_CREATED_FAST 6
#define CELL_VERSIONS 7
#define CELL_NETINFO 8
#define CELL_RELAY_EARLY 9

/** True iff the cell command <b>x</b> is one that implies a variable-length
 * cell. */
#define CELL_COMMAND_IS_VAR_LENGTH(x) ((x) == CELL_VERSIONS)

/** How long to test reachability before complaining to the user. */
#define TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT (20*60)

/** Legal characters in a nickname. */
#define LEGAL_NICKNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/** Name to use in client TLS certificates if no nickname is given. Once
 * Tor 0.1.2.x is obsolete, we can remove this. */
#define DEFAULT_CLIENT_NICKNAME "client"

/** Name chosen by routers that don't configure nicknames */
#define UNNAMED_ROUTER_NICKNAME "Unnamed"

/** Number of bytes in a SOCKS4 header. */
#define SOCKS4_NETWORK_LEN 8

/*
 * Relay payload:
 *         Relay command           [1 byte]
 *         Recognized              [2 bytes]
 *         Stream ID               [2 bytes]
 *         Partial SHA-1           [4 bytes]
 *         Length                  [2 bytes]
 *         Relay payload           [498 bytes]
 */

/** Number of bytes in a cell, minus cell header. */
#define CELL_PAYLOAD_SIZE 509
/** Number of bytes in a cell transmitted over the network. */
#define CELL_NETWORK_SIZE 512

/** Length of a header on a variable-length cell. */
#define VAR_CELL_HEADER_SIZE 5

/** Number of bytes in a relay cell's header (not including general cell
 * header). */
#define RELAY_HEADER_SIZE (1+2+2+4+2)
/** Largest number of bytes that can fit in a relay cell payload. */
#define RELAY_PAYLOAD_SIZE (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE)

/** Identifies a circuit on an or_connection */
typedef uint16_t circid_t;
/** Identifies a stream on a circuit */
typedef uint16_t streamid_t;

/** Parsed onion routing cell.  All communication between nodes
 * is via cells. */
typedef struct cell_t {
  circid_t circ_id; /**< Circuit which received the cell. */
  uint8_t command; /**< Type of the cell: one of CELL_PADDING, CELL_CREATE,
                    * CELL_DESTROY, etc */
  char payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
} cell_t;

/** Parsed variable-length onion routing cell. */
typedef struct var_cell_t {
  uint8_t command;
  circid_t circ_id;
  uint16_t payload_len;
  char payload[1];
} var_cell_t;

/** A cell as packed for writing to the network. */
typedef struct packed_cell_t {
  struct packed_cell_t *next; /**< Next cell queued on this circuit. */
  char body[CELL_NETWORK_SIZE]; /**< Cell as packed for network. */
} packed_cell_t;

/** Number of cells added to a circuit queue including their insertion
 * time on 10 millisecond detail; used for buffer statistics. */
typedef struct insertion_time_elem_t {
  struct insertion_time_elem_t *next; /**< Next element in queue. */
  uint32_t insertion_time; /**< When were cells inserted (in 10 ms steps
                             * starting at 0:00 of the current day)? */
  unsigned counter; /**< How many cells were inserted? */
} insertion_time_elem_t;

/** Queue of insertion times. */
typedef struct insertion_time_queue_t {
  struct insertion_time_elem_t *first; /**< First element in queue. */
  struct insertion_time_elem_t *last; /**< Last element in queue. */
} insertion_time_queue_t;

/** A queue of cells on a circuit, waiting to be added to the
 * or_connection_t's outbuf. */
typedef struct cell_queue_t {
  packed_cell_t *head; /**< The first cell, or NULL if the queue is empty. */
  packed_cell_t *tail; /**< The last cell, or NULL if the queue is empty. */
  int n; /**< The number of cells in the queue. */
  insertion_time_queue_t *insertion_times; /**< Insertion times of cells. */
} cell_queue_t;

/** Beginning of a RELAY cell payload. */
typedef struct {
  uint8_t command; /**< The end-to-end relay command. */
  uint16_t recognized; /**< Used to tell whether cell is for us. */
  streamid_t stream_id; /**< Which stream is this cell associated with? */
  char integrity[4]; /**< Used to tell whether cell is corrupted. */
  uint16_t length; /**< How long is the payload body? */
} relay_header_t;

typedef struct buf_t buf_t;
typedef struct socks_request_t socks_request_t;

/* Values for connection_t.magic: used to make sure that downcasts (casts from
* connection_t to foo_connection_t) are safe. */
#define BASE_CONNECTION_MAGIC 0x7C3C304Eu
#define OR_CONNECTION_MAGIC 0x7D31FF03u
#define EDGE_CONNECTION_MAGIC 0xF0374013u
#define DIR_CONNECTION_MAGIC 0x9988ffeeu
#define CONTROL_CONNECTION_MAGIC 0x8abc765du

/** Description of a connection to another host or process, and associated
 * data.
 *
 * A connection is named based on what it's connected to -- an "OR
 * connection" has a Tor node on the other end, an "exit
 * connection" has a website or other server on the other end, and an
 * "AP connection" has an application proxy (and thus a user) on the
 * other end.
 *
 * Every connection has a type and a state.  Connections never change
 * their type, but can go through many state changes in their lifetime.
 *
 * Every connection has two associated input and output buffers.
 * Listeners don't use them.  For non-listener connections, incoming
 * data is appended to conn->inbuf, and outgoing data is taken from
 * conn->outbuf.  Connections differ primarily in the functions called
 * to fill and drain these buffers.
 */
typedef struct connection_t {
  uint32_t magic; /**< For memory debugging: must equal one of
                   * *_CONNECTION_MAGIC. */

  uint8_t state; /**< Current state of this connection. */
  unsigned int type:4; /**< What kind of connection is this? */
  unsigned int purpose:5; /**< Only used for DIR and EXIT types currently. */

  /* The next fields are all one-bit booleans. Some are only applicable to
   * connection subtypes, but we hold them here anyway, to save space.
   */
  unsigned int read_blocked_on_bw:1; /**< Boolean: should we start reading
                            * again once the bandwidth throttler allows it? */
  unsigned int write_blocked_on_bw:1; /**< Boolean: should we start writing
                             * again once the bandwidth throttler allows
                             * writes? */
  unsigned int hold_open_until_flushed:1; /**< Despite this connection's being
                                      * marked for close, do we flush it
                                      * before closing it? */
  unsigned int inbuf_reached_eof:1; /**< Boolean: did read() return 0 on this
                                     * conn? */
  /** Set to 1 when we're inside connection_flushed_some to keep us from
   * calling connection_handle_write() recursively. */
  unsigned int in_flushed_some:1;

  /* For linked connections:
   */
  unsigned int linked:1; /**< True if there is, or has been, a linked_conn. */
  /** True iff we'd like to be notified about read events from the
   * linked conn. */
  unsigned int reading_from_linked_conn:1;
  /** True iff we're willing to write to the linked conn. */
  unsigned int writing_to_linked_conn:1;
  /** True iff we're currently able to read on the linked conn, and our
   * read_event should be made active with libevent. */
  unsigned int active_on_link:1;
  /** True iff we've called connection_close_immediate() on this linked
   * connection. */
  unsigned int linked_conn_is_closed:1;

  /** CONNECT/SOCKS proxy client handshake state (for outgoing connections). */
  unsigned int proxy_state:4;

  /** Our socket; -1 if this connection is closed, or has no socket. */
  evutil_socket_t s;
  int conn_array_index; /**< Index into the global connection array. */

  struct event *read_event; /**< Libevent event structure. */
  struct event *write_event; /**< Libevent event structure. */
  buf_t *inbuf; /**< Buffer holding data read over this connection. */
  buf_t *outbuf; /**< Buffer holding data to write over this connection. */
  size_t outbuf_flushlen; /**< How much data should we try to flush from the
                           * outbuf? */
  time_t timestamp_lastread; /**< When was the last time libevent said we could
                              * read? */
  time_t timestamp_lastwritten; /**< When was the last time libevent said we
                                 * could write? */

#ifdef USE_BUFFEREVENTS
  struct bufferevent *bufev; /**< A Libevent buffered IO structure. */
#endif

  time_t timestamp_created; /**< When was this connection_t created? */

  /* XXXX_IP6 make this IPv6-capable */
  int socket_family; /**< Address family of this connection's socket.  Usually
                      * AF_INET, but it can also be AF_UNIX, or in the future
                      * AF_INET6 */
  tor_addr_t addr; /**< IP of the other side of the connection; used to
                    * identify routers, along with port. */
  uint16_t port; /**< If non-zero, port on the other end
                  * of the connection. */
  uint16_t marked_for_close; /**< Should we close this conn on the next
                              * iteration of the main loop? (If true, holds
                              * the line number where this connection was
                              * marked.) */
  const char *marked_for_close_file; /**< For debugging: in which file were
                                      * we marked for close? */
  char *address; /**< FQDN (or IP) of the guy on the other end.
                  * strdup into this, because free_connection() frees it. */
  /** Another connection that's connected to this one in lieu of a socket. */
  struct connection_t *linked_conn;

  /** Unique identifier for this connection on this Tor instance. */
  uint64_t global_identifier;

  /* XXXX022 move this field, and all the listener-only fields (just
     socket_family, I think), into a new listener_connection_t subtype. */
  /** If the connection is a CONN_TYPE_AP_DNS_LISTENER, this field points
   * to the evdns_server_port is uses to listen to and answer connections. */
  struct evdns_server_port *dns_server_port;

  /** Unique ID for measuring tunneled network status requests. */
  uint64_t dirreq_id;
} connection_t;

/** Stores flags and information related to the portion of a v2 Tor OR
 * connection handshake that happens after the TLS handshake is finished.
 */
typedef struct or_handshake_state_t {
  /** When was the VERSIONS cell sent on this connection?  Used to get
   * an estimate of the skew in the returning NETINFO reply. */
  time_t sent_versions_at;
  /** True iff we originated this connection */
  unsigned int started_here : 1;
  /** True iff we have received and processed a VERSIONS cell. */
  unsigned int received_versions : 1;
} or_handshake_state_t;

/** Subtype of connection_t for an "OR connection" -- that is, one that speaks
 * cells over TLS. */
typedef struct or_connection_t {
  connection_t _base;

  /** Hash of the public RSA key for the other side's identity key, or zeroes
   * if the other side hasn't shown us a valid identity key. */
  char identity_digest[DIGEST_LEN];
  char *nickname; /**< Nickname of OR on other side (if any). */

  tor_tls_t *tls; /**< TLS connection state. */
  int tls_error; /**< Last tor_tls error code. */
  /** When we last used this conn for any client traffic. If not
   * recent, we can rate limit it further. */
  time_t client_used;

  tor_addr_t real_addr; /**< The actual address that this connection came from
                       * or went to.  The <b>addr</b> field is prone to
                       * getting overridden by the address from the router
                       * descriptor matching <b>identity_digest</b>. */

  circ_id_type_t circ_id_type:2; /**< When we send CREATE cells along this
                                  * connection, which half of the space should
                                  * we use? */
  /** Should this connection be used for extending circuits to the server
   * matching the <b>identity_digest</b> field?  Set to true if we're pretty
   * sure we aren't getting MITMed, either because we're connected to an
   * address listed in a server descriptor, or because an authenticated
   * NETINFO cell listed the address we're connected to as recognized. */
  unsigned int is_canonical:1;
  /** True iff this connection shouldn't get any new circs attached to it,
   * because the connection is too old, or because there's a better one.
   * More generally, this flag is used to note an unhealthy connection;
   * for example, if a bad connection fails we shouldn't assume that the
   * router itself has a problem.
   */
  unsigned int is_bad_for_new_circs:1;
  uint8_t link_proto; /**< What protocol version are we using? 0 for
                       * "none negotiated yet." */
  circid_t next_circ_id; /**< Which circ_id do we try to use next on
                          * this connection?  This is always in the
                          * range 0..1<<15-1. */

  or_handshake_state_t *handshake_state; /**< If we are setting this connection
                                          * up, state information to do so. */
  time_t timestamp_lastempty; /**< When was the outbuf last completely empty?*/
  time_t timestamp_last_added_nonpadding; /** When did we last add a
                                           * non-padding cell to the outbuf? */

  /* bandwidth* and *_bucket only used by ORs in OPEN state: */
  int bandwidthrate; /**< Bytes/s added to the bucket. (OPEN ORs only.) */
  int bandwidthburst; /**< Max bucket size for this conn. (OPEN ORs only.) */
#ifndef USE_BUFFEREVENTS
  int read_bucket; /**< When this hits 0, stop receiving. Every second we
                    * add 'bandwidthrate' to this, capping it at
                    * bandwidthburst. (OPEN ORs only) */
  int write_bucket; /**< When this hits 0, stop writing. Like read_bucket. */
#else
  /** DOCDOC */
  /* XXXX we could share this among all connections. */
  struct ev_token_bucket_cfg *bucket_cfg;
#endif
  int n_circuits; /**< How many circuits use this connection as p_conn or
                   * n_conn ? */

  /** Double-linked ring of circuits with queued cells waiting for room to
   * free up on this connection's outbuf.  Every time we pull cells from a
   * circuit, we advance this pointer to the next circuit in the ring. */
  struct circuit_t *active_circuits;
  /** Priority queue of cell_ewma_t for circuits with queued cells waiting for
   * room to free up on this connection's outbuf.  Kept in heap order
   * according to EWMA.
   *
   * This is redundant with active_circuits; if we ever decide only to use the
   * cell_ewma algorithm for choosing circuits, we can remove active_circuits.
   */
  smartlist_t *active_circuit_pqueue;
  /** The tick on which the cell_ewma_ts in active_circuit_pqueue last had
   * their ewma values rescaled. */
  unsigned active_circuit_pqueue_last_recalibrated;
  struct or_connection_t *next_with_same_id; /**< Next connection with same
                                              * identity digest as this one. */
} or_connection_t;

/** Subtype of connection_t for an "edge connection" -- that is, a socks (ap)
 * connection, or an exit. */
typedef struct edge_connection_t {
  connection_t _base;

  struct edge_connection_t *next_stream; /**< Points to the next stream at this
                                          * edge, if any */
  struct crypt_path_t *cpath_layer; /**< A pointer to which node in the circ
                                     * this conn exits at. */
  int package_window; /**< How many more relay cells can I send into the
                       * circuit? */
  int deliver_window; /**< How many more relay cells can end at me? */

  /** Nickname of planned exit node -- used with .exit support. */
  char *chosen_exit_name;

  socks_request_t *socks_request; /**< SOCKS structure describing request (AP
                                   * only.) */
  struct circuit_t *on_circuit; /**< The circuit (if any) that this edge
                                 * connection is using. */

  uint32_t address_ttl; /**< TTL for address-to-addr mapping on exit
                         * connection.  Exit connections only. */

  streamid_t stream_id; /**< The stream ID used for this edge connection on its
                         * circuit */

  /** The reason why this connection is closing; passed to the controller. */
  uint16_t end_reason;

  /** Bytes read since last call to control_event_stream_bandwidth_used() */
  uint32_t n_read;

  /** Bytes written since last call to control_event_stream_bandwidth_used() */
  uint32_t n_written;

  /** What rendezvous service are we querying for? (AP only) */
  rend_data_t *rend_data;

  /** Number of times we've reassigned this application connection to
   * a new circuit. We keep track because the timeout is longer if we've
   * already retried several times. */
  uint8_t num_socks_retries;

  /** True iff this connection is for a DNS request only. */
  unsigned int is_dns_request:1;

  /** True iff this stream must attach to a one-hop circuit (e.g. for
   * begin_dir). */
  unsigned int want_onehop:1;
  /** True iff this stream should use a BEGIN_DIR relay command to establish
   * itself rather than BEGIN (either via onehop or via a whole circuit). */
  unsigned int use_begindir:1;

  unsigned int edge_has_sent_end:1; /**< For debugging; only used on edge
                         * connections.  Set once we've set the stream end,
                         * and check in connection_about_to_close_connection().
                         */
  /** True iff we've blocked reading until the circuit has fewer queued
   * cells. */
  unsigned int edge_blocked_on_circ:1;
  /** For AP connections only. If 1, and we fail to reach the chosen exit,
   * stop requiring it. */
  unsigned int chosen_exit_optional:1;
  /** For AP connections only. If non-zero, this exit node was picked as
   * a result of the TrackHostExit, and the value decrements every time
   * we fail to complete a circuit to our chosen exit -- if it reaches
   * zero, abandon the associated mapaddress. */
  unsigned int chosen_exit_retries:3;

  /** If this is a DNSPort connection, this field holds the pending DNS
   * request that we're going to try to answer.  */
  struct evdns_server_request *dns_server_request;

} edge_connection_t;

/** Subtype of connection_t for an "directory connection" -- that is, an HTTP
 * connection to retrieve or serve directory material. */
typedef struct dir_connection_t {
  connection_t _base;

 /** Which 'resource' did we ask the directory for? This is typically the part
  * of the URL string that defines, relative to the directory conn purpose,
  * what thing we want.  For example, in router descriptor downloads by
  * descriptor digest, it contains "d/", then one ore more +-separated
  * fingerprints.
  **/
  char *requested_resource;
  unsigned int dirconn_direct:1; /**< Is this dirconn direct, or via Tor? */

  /* Used only for server sides of some dir connections, to implement
   * "spooling" of directory material to the outbuf.  Otherwise, we'd have
   * to append everything to the outbuf in one enormous chunk. */
  /** What exactly are we spooling right now? */
  enum {
    DIR_SPOOL_NONE=0, DIR_SPOOL_SERVER_BY_DIGEST, DIR_SPOOL_SERVER_BY_FP,
    DIR_SPOOL_EXTRA_BY_DIGEST, DIR_SPOOL_EXTRA_BY_FP,
    DIR_SPOOL_CACHED_DIR, DIR_SPOOL_NETWORKSTATUS,
    DIR_SPOOL_MICRODESC, /* NOTE: if we add another entry, add another bit. */
  } dir_spool_src : 3;
  /** If we're fetching descriptors, what router purpose shall we assign
   * to them? */
  uint8_t router_purpose;
  /** List of fingerprints for networkstatuses or descriptors to be spooled. */
  smartlist_t *fingerprint_stack;
  /** A cached_dir_t object that we're currently spooling out */
  struct cached_dir_t *cached_dir;
  /** The current offset into cached_dir. */
  off_t cached_dir_offset;
  /** The zlib object doing on-the-fly compression for spooled data. */
  tor_zlib_state_t *zlib_state;

  /** What rendezvous service are we querying for? */
  rend_data_t *rend_data;

  char identity_digest[DIGEST_LEN]; /**< Hash of the public RSA key for
                                     * the directory server's signing key. */

} dir_connection_t;

/** Subtype of connection_t for an connection to a controller. */
typedef struct control_connection_t {
  connection_t _base;

  uint32_t event_mask; /**< Bitfield: which events does this controller
                        * care about? */

  /** True if we have sent a protocolinfo reply on this connection. */
  unsigned int have_sent_protocolinfo:1;

  /** Amount of space allocated in incoming_cmd. */
  uint32_t incoming_cmd_len;
  /** Number of bytes currently stored in incoming_cmd. */
  uint32_t incoming_cmd_cur_len;
  /** A control command that we're reading from the inbuf, but which has not
   * yet arrived completely. */
  char *incoming_cmd;
} control_connection_t;

/** Cast a connection_t subtype pointer to a connection_t **/
#define TO_CONN(c) (&(((c)->_base)))
/** Helper macro: Given a pointer to to._base, of type from*, return &to. */
#define DOWNCAST(to, ptr) ((to*)SUBTYPE_P(ptr, to, _base))

/** Convert a connection_t* to an or_connection_t*; assert if the cast is
 * invalid. */
static or_connection_t *TO_OR_CONN(connection_t *);
/** Convert a connection_t* to a dir_connection_t*; assert if the cast is
 * invalid. */
static dir_connection_t *TO_DIR_CONN(connection_t *);
/** Convert a connection_t* to an edge_connection_t*; assert if the cast is
 * invalid. */
static edge_connection_t *TO_EDGE_CONN(connection_t *);
/** Convert a connection_t* to an control_connection_t*; assert if the cast is
 * invalid. */
static control_connection_t *TO_CONTROL_CONN(connection_t *);

static INLINE or_connection_t *TO_OR_CONN(connection_t *c)
{
  tor_assert(c->magic == OR_CONNECTION_MAGIC);
  return DOWNCAST(or_connection_t, c);
}
static INLINE dir_connection_t *TO_DIR_CONN(connection_t *c)
{
  tor_assert(c->magic == DIR_CONNECTION_MAGIC);
  return DOWNCAST(dir_connection_t, c);
}
static INLINE edge_connection_t *TO_EDGE_CONN(connection_t *c)
{
  tor_assert(c->magic == EDGE_CONNECTION_MAGIC);
  return DOWNCAST(edge_connection_t, c);
}
static INLINE control_connection_t *TO_CONTROL_CONN(connection_t *c)
{
  tor_assert(c->magic == CONTROL_CONNECTION_MAGIC);
  return DOWNCAST(control_connection_t, c);
}

/* Conditional macros to help write code that works whether bufferevents are
   disabled or not.

   We can't just write:
      if (conn->bufev) {
        do bufferevent stuff;
      } else {
        do other stuff;
      }
   because the bufferevent stuff won't even compile unless we have a fairly
   new version of Libevent.  Instead, we say:
      IF_HAS_BUFFEREVENT(conn, { do_bufferevent_stuff } );
   or:
      IF_HAS_BUFFEREVENT(conn, {
        do bufferevent stuff;
      }) ELSE_IF_NO_BUFFEREVENT {
        do non-bufferevent stuff;
      }
   If we're compiling with bufferevent support, then the macros expand more or
   less to:
      if (conn->bufev) {
        do_bufferevent_stuff;
      } else {
        do non-bufferevent stuff;
      }
   and if we aren't using bufferevents, they expand more or less to:
      { do non-bufferevent stuff; }
*/
#ifdef USE_BUFFEREVENTS
#define HAS_BUFFEREVENT(c) (((c)->bufev) != NULL)
#define IF_HAS_BUFFEREVENT(c, stmt)                \
  if ((c)->bufev) do {                             \
      stmt ;                                       \
  } while (0)
#define ELSE_IF_NO_BUFFEREVENT ; else
#define IF_HAS_NO_BUFFEREVENT(c)                   \
  if (NULL == (c)->bufev)
#else
#define HAS_BUFFEREVENT(c) (0)
#define IF_HAS_BUFFEREVENT(c, stmt) (void)0
#define ELSE_IF_NO_BUFFEREVENT ;
#define IF_HAS_NO_BUFFEREVENT(c)                \
  if (1)
#endif

/** What action type does an address policy indicate: accept or reject? */
typedef enum {
  ADDR_POLICY_ACCEPT=1,
  ADDR_POLICY_REJECT=2,
} addr_policy_action_t;

/** A reference-counted address policy rule. */
typedef struct addr_policy_t {
  int refcnt; /**< Reference count */
  addr_policy_action_t policy_type:2;/**< What to do when the policy matches.*/
  unsigned int is_private:1; /**< True iff this is the pseudo-address,
                              * "private". */
  unsigned int is_canonical:1; /**< True iff this policy is the canonical
                                * copy (stored in a hash table to avoid
                                * duplication of common policies) */
  maskbits_t maskbits; /**< Accept/reject all addresses <b>a</b> such that the
                 * first <b>maskbits</b> bits of <b>a</b> match
                 * <b>addr</b>. */
  tor_addr_t addr; /**< Base address to accept or reject. */
  uint16_t prt_min; /**< Lowest port number to accept/reject. */
  uint16_t prt_max; /**< Highest port number to accept/reject. */
} addr_policy_t;

/** A cached_dir_t represents a cacheable directory object, along with its
 * compressed form. */
typedef struct cached_dir_t {
  char *dir; /**< Contents of this object, NUL-terminated. */
  char *dir_z; /**< Compressed contents of this object. */
  size_t dir_len; /**< Length of <b>dir</b> (not counting its NUL). */
  size_t dir_z_len; /**< Length of <b>dir_z</b>. */
  time_t published; /**< When was this object published. */
  digests_t digests; /**< Digests of this object (networkstatus only) */
  int refcnt; /**< Reference count for this cached_dir_t. */
} cached_dir_t;

/** Enum used to remember where a signed_descriptor_t is stored and how to
 * manage the memory for signed_descriptor_body.  */
typedef enum {
  /** The descriptor isn't stored on disk at all: the copy in memory is
   * canonical; the saved_offset field is meaningless. */
  SAVED_NOWHERE=0,
  /** The descriptor is stored in the cached_routers file: the
   * signed_descriptor_body is meaningless; the signed_descriptor_len and
   * saved_offset are used to index into the mmaped cache file. */
  SAVED_IN_CACHE,
  /** The descriptor is stored in the cached_routers.new file: the
   * signed_descriptor_body and saved_offset fields are both set. */
  /* FFFF (We could also mmap the file and grow the mmap as needed, or
   * lazy-load the descriptor text by using seek and read.  We don't, for
   * now.)
   */
  SAVED_IN_JOURNAL
} saved_location_t;

/** Enumeration: what kind of download schedule are we using for a given
 * object? */
typedef enum {
  DL_SCHED_GENERIC = 0,
  DL_SCHED_CONSENSUS = 1,
  DL_SCHED_BRIDGE = 2,
} download_schedule_t;

/** Information about our plans for retrying downloads for a downloadable
 * object. */
typedef struct download_status_t {
  time_t next_attempt_at; /**< When should we try downloading this descriptor
                           * again? */
  uint8_t n_download_failures; /**< Number of failures trying to download the
                                * most recent descriptor. */
  download_schedule_t schedule : 8;
} download_status_t;

/** If n_download_failures is this high, the download can never happen. */
#define IMPOSSIBLE_TO_DOWNLOAD 255

/** The max size we expect router descriptor annotations we create to
 * be. We'll accept larger ones if we see them on disk, but we won't
 * create any that are larger than this. */
#define ROUTER_ANNOTATION_BUF_LEN 256

/** Information need to cache an onion router's descriptor. */
typedef struct signed_descriptor_t {
  /** Pointer to the raw server descriptor, preceded by annotations.  Not
   * necessarily NUL-terminated.  If saved_location is SAVED_IN_CACHE, this
   * pointer is null. */
  char *signed_descriptor_body;
  /** Length of the annotations preceding the server descriptor. */
  size_t annotations_len;
  /** Length of the server descriptor. */
  size_t signed_descriptor_len;
  /** Digest of the server descriptor, computed as specified in
   * dir-spec.txt. */
  char signed_descriptor_digest[DIGEST_LEN];
  /** Identity digest of the router. */
  char identity_digest[DIGEST_LEN];
  /** Declared publication time of the descriptor. */
  time_t published_on;
  /** For routerdescs only: digest of the corresponding extrainfo. */
  char extra_info_digest[DIGEST_LEN];
  /** For routerdescs only: Status of downloading the corresponding
   * extrainfo. */
  download_status_t ei_dl_status;
  /** Where is the descriptor saved? */
  saved_location_t saved_location;
  /** If saved_location is SAVED_IN_CACHE or SAVED_IN_JOURNAL, the offset of
   * this descriptor in the corresponding file. */
  off_t saved_offset;
  /** What position is this descriptor within routerlist->routers or
   * routerlist->old_routers? -1 for none. */
  int routerlist_index;
  /** The valid-until time of the most recent consensus that listed this
   * descriptor, or a bit after the publication time of the most recent v2
   * networkstatus that listed it.  0 for "never listed in a consensus or
   * status, so far as we know." */
  time_t last_listed_as_valid_until;
#ifdef TRACK_SERVED_TIME
  /** The last time we served anybody this descriptor.  Used for internal
   * testing to see whether we're holding on to descriptors too long. */
  time_t last_served_at; /*XXXX remove if not useful. */
#endif
  /* If true, we do not ever try to save this object in the cache. */
  unsigned int do_not_cache : 1;
  /* If true, this item is meant to represent an extrainfo. */
  unsigned int is_extrainfo : 1;
  /* If true, we got an extrainfo for this item, and the digest was right,
   * but it was incompatible. */
  unsigned int extrainfo_is_bogus : 1;
  /* If true, we are willing to transmit this item unencrypted. */
  unsigned int send_unencrypted : 1;
} signed_descriptor_t;

/** A signed integer representing a country code. */
typedef int16_t country_t;

/** Information about another onion router in the network. */
typedef struct {
  signed_descriptor_t cache_info;
  char *address; /**< Location of OR: either a hostname or an IP address. */
  char *nickname; /**< Human-readable OR name. */

  uint32_t addr; /**< IPv4 address of OR, in host order. */
  uint16_t or_port; /**< Port for TLS connections. */
  uint16_t dir_port; /**< Port for HTTP directory connections. */

  crypto_pk_env_t *onion_pkey; /**< Public RSA key for onions. */
  crypto_pk_env_t *identity_pkey;  /**< Public RSA key for signing. */

  char *platform; /**< What software/operating system is this OR using? */

  /* link info */
  uint32_t bandwidthrate; /**< How many bytes does this OR add to its token
                           * bucket per second? */
  uint32_t bandwidthburst; /**< How large is this OR's token bucket? */
  /** How many bytes/s is this router known to handle? */
  uint32_t bandwidthcapacity;
  smartlist_t *exit_policy; /**< What streams will this OR permit
                             * to exit?  NULL for 'reject *:*'. */
  long uptime; /**< How many seconds the router claims to have been up */
  smartlist_t *declared_family; /**< Nicknames of router which this router
                                 * claims are its family. */
  char *contact_info; /**< Declared contact info for this router. */
  unsigned int is_hibernating:1; /**< Whether the router claims to be
                                  * hibernating */
  unsigned int caches_extra_info:1; /**< Whether the router says it caches and
                                     * serves extrainfo documents. */
  unsigned int allow_single_hop_exits:1;  /**< Whether the router says
                                           * it allows single hop exits. */

  unsigned int wants_to_be_hs_dir:1; /**< True iff this router claims to be
                                      * a hidden service directory. */
  unsigned int policy_is_reject_star:1; /**< True iff the exit policy for this
                                         * router rejects everything. */
  /** True if, after we have added this router, we should re-launch
   * tests for it. */
  unsigned int needs_retest_if_added:1;

/** Tor can use this router for general positions in circuits; we got it
 * from a directory server as usual, or we're an authority and a server
 * uploaded it. */
#define ROUTER_PURPOSE_GENERAL 0
/** Tor should avoid using this router for circuit-building: we got it
 * from a crontroller.  If the controller wants to use it, it'll have to
 * ask for it by identity. */
#define ROUTER_PURPOSE_CONTROLLER 1
/** Tor should use this router only for bridge positions in circuits: we got
 * it via a directory request from the bridge itself, or a bridge
 * authority. x*/
#define ROUTER_PURPOSE_BRIDGE 2
/** Tor should not use this router; it was marked in cached-descriptors with
 * a purpose we didn't recognize. */
#define ROUTER_PURPOSE_UNKNOWN 255

  /* In what way did we find out about this router?  One of ROUTER_PURPOSE_*.
   * Routers of different purposes are kept segregated and used for different
   * things; see notes on ROUTER_PURPOSE_* macros above.
   */
  uint8_t purpose;

  /* The below items are used only by authdirservers for
   * reachability testing. */

  /** When was the last time we could reach this OR? */
  time_t last_reachable;
  /** When did we start testing reachability for this OR? */
  time_t testing_since;

} routerinfo_t;

/** Information needed to keep and cache a signed extra-info document. */
typedef struct extrainfo_t {
  signed_descriptor_t cache_info;
  /** The router's nickname. */
  char nickname[MAX_NICKNAME_LEN+1];
  /** True iff we found the right key for this extra-info, verified the
   * signature, and found it to be bad. */
  unsigned int bad_sig : 1;
  /** If present, we didn't have the right key to verify this extra-info,
   * so this is a copy of the signature in the document. */
  char *pending_sig;
  /** Length of pending_sig. */
  size_t pending_sig_len;
} extrainfo_t;

/** Contents of a single router entry in a network status object.
 */
typedef struct routerstatus_t {
  time_t published_on; /**< When was this router published? */
  char nickname[MAX_NICKNAME_LEN+1]; /**< The nickname this router says it
                                      * has. */
  char identity_digest[DIGEST_LEN]; /**< Digest of the router's identity
                                     * key. */
  /** Digest of the router's most recent descriptor or microdescriptor.
   * If it's a descriptor, we only use the first DIGEST_LEN bytes. */
  char descriptor_digest[DIGEST256_LEN];
  uint32_t addr; /**< IPv4 address for this router. */
  uint16_t or_port; /**< OR port for this router. */
  uint16_t dir_port; /**< Directory port for this router. */
  unsigned int is_authority:1; /**< True iff this router is an authority. */
  unsigned int is_exit:1; /**< True iff this router is a good exit. */
  unsigned int is_stable:1; /**< True iff this router stays up a long time. */
  unsigned int is_fast:1; /**< True iff this router has good bandwidth. */
  /** True iff this router is called 'running' in the consensus. We give it
   * this funny name so that we don't accidentally use this bit as a view of
   * whether we think the router is *currently* running.  If that's what you
   * want to know, look at is_running in node_t. */
  unsigned int is_flagged_running:1;
  unsigned int is_named:1; /**< True iff "nickname" belongs to this router. */
  unsigned int is_unnamed:1; /**< True iff "nickname" belongs to another
                              * router. */
  unsigned int is_valid:1; /**< True iff this router isn't invalid. */
  unsigned int is_v2_dir:1; /**< True iff this router can serve directory
                             * information with v2 of the directory
                             * protocol. (All directory caches cache v1
                             * directories.)  */
  unsigned int is_possible_guard:1; /**< True iff this router would be a good
                                     * choice as an entry guard. */
  unsigned int is_bad_exit:1; /**< True iff this node is a bad choice for
                               * an exit node. */
  unsigned int is_bad_directory:1; /**< Do we think this directory is junky,
                                    * underpowered, or otherwise useless? */
  unsigned int is_hs_dir:1; /**< True iff this router is a v2-or-later hidden
                             * service directory. */
  /** True iff we know version info for this router. (i.e., a "v" entry was
   * included.)  We'll replace all these with a big tor_version_t or a char[]
   * if the number of traits we care about ever becomes incredibly big. */
  unsigned int version_known:1;
  /** True iff this router is a version that supports BEGIN_DIR cells. */
  unsigned int version_supports_begindir:1;
  /** True iff this router is a version that supports conditional consensus
   *  downloads (signed by list of authorities). */
  unsigned int version_supports_conditional_consensus:1;
  /** True iff this router is a version that we can post extrainfo docs to. */
  unsigned int version_supports_extrainfo_upload:1;
  /** True iff this router is a version that, if it caches directory info,
   * we can get v3 downloads from. */
  unsigned int version_supports_v3_dir:1;

  unsigned int has_bandwidth:1; /**< The vote/consensus had bw info */
  unsigned int has_exitsummary:1; /**< The vote/consensus had exit summaries */
  unsigned int has_measured_bw:1; /**< The vote/consensus had a measured bw */

  uint32_t measured_bw; /**< Measured bandwidth (capacity) of the router */

  uint32_t bandwidth; /**< Bandwidth (capacity) of the router as reported in
                       * the vote/consensus, in kilobytes/sec. */
  char *exitsummary; /**< exit policy summary -
                      * XXX weasel: this probably should not stay a string. */

  /* ---- The fields below aren't derived from the networkstatus; they
   * hold local information only. */

  /** True if we, as a directory mirror, want to download the corresponding
   * routerinfo from the authority who gave us this routerstatus.  (That is,
   * if we don't have the routerinfo, and if we haven't already tried to get it
   * from this authority.)  Applies in v2 networkstatus document only.
   */
  unsigned int need_to_mirror:1;
  time_t last_dir_503_at; /**< When did this router last tell us that it
                           * was too busy to serve directory info? */
  download_status_t dl_status;

} routerstatus_t;

/** A single entry in a parsed policy summary, describing a range of ports. */
typedef struct short_policy_entry_t {
  uint16_t min_port, max_port;
} short_policy_entry_t;

/** A short_poliy_t is the parsed version of a policy summary. */
typedef struct short_policy_t {
  /** True if the members of 'entries' are port ranges to accept; false if
   * they are port ranges to reject */
  unsigned int is_accept : 1;
  /** The actual number of values in 'entries'. */
  unsigned int n_entries : 31;
  /** An array of (probably more than 1!) short_policy_entry_t values,
   * each descriping a range of ports that this policy accepts or rejects
   * (depending on the value of is_accept).
   */
  short_policy_entry_t entries[1];
} short_policy_t;

/** A microdescriptor is the smallest amount of information needed to build a
 * circuit through a router.  They are generated by the directory authorities,
 * using information from the uploaded routerinfo documents.  They are not
 * self-signed, but are rather authenticated by having their hash in a signed
 * networkstatus document. */
typedef struct microdesc_t {
  /** Hashtable node, used to look up the microdesc by its digest. */
  HT_ENTRY(microdesc_t) node;

  /* Cache information */

  /**  When was this microdescriptor last listed in a consensus document?
   * Once a microdesc has been unlisted long enough, we can drop it.
   */
  time_t last_listed;
  /** Where is this microdescriptor currently stored? */
  saved_location_t saved_location : 3;
  /** If true, do not attempt to cache this microdescriptor on disk. */
  unsigned int no_save : 1;
  /** If saved_location == SAVED_IN_CACHE, this field holds the offset of the
   * microdescriptor in the cache. */
  off_t off;

  /* The string containing the microdesc. */

  /** A pointer to the encoded body of the microdescriptor.  If the
   * saved_location is SAVED_IN_CACHE, then the body is a pointer into an
   * mmap'd region.  Otherwise, it is a malloc'd string.  The string might not
   * be NUL-terminated; take the length from <b>bodylen</b>. */
  char *body;
  /** The length of the microdescriptor in <b>body</b>. */
  size_t bodylen;
  /** A SHA256-digest of the microdescriptor. */
  char digest[DIGEST256_LEN];

  /* Fields in the microdescriptor. */

  /** As routerinfo_t.onion_pkey */
  crypto_pk_env_t *onion_pkey;
  /** As routerinfo_t.family */
  smartlist_t *family;
  /** Exit policy summary */
  short_policy_t *exit_policy;
} microdesc_t;

/** A node_t represents a Tor router.
 *
 * Specifically, a node_t is a Tor router as we are using it: a router that
 * we are considering for circuits, connections, and so on.  A node_t is a
 * thin wrapper around the routerstatus, routerinfo, and microdesc for a
 * single wrapper, and provides a consistent interface for all of them.
 *
 * Also, a node_t has mutable state.  While a routerinfo, a routerstatus,
 * and a microdesc have[*] only the information read from a router
 * descriptor, a consensus entry, and a microdescriptor (respectively)...
 * a node_t has flags based on *our own current opinion* of the node.
 *
 * [*] Actually, there is some leftover information in each that is mutable.
 *  We should try to excise that.
 */
typedef struct node_t {
  /* Indexing information */

  /** Used to look up the node_t by its identity digest. */
  HT_ENTRY(node_t) ht_ent;
  /** Position of the node within the list of nodes */
  int nodelist_idx;

  /** The identity digest of this node_t.  No more than one node_t per
   * identity may exist at a time. */
  char identity[DIGEST_LEN];

  microdesc_t *md;
  routerinfo_t *ri;
  routerstatus_t *rs;

  /* local info: copied from routerstatus, then possibly frobbed based
   * on experience.  Authorities set this stuff directly. */

  unsigned int is_running:1; /**< As far as we know, is this OR currently
                              * running? */
  unsigned int is_valid:1; /**< Has a trusted dirserver validated this OR?
                               *  (For Authdir: Have we validated this OR?)
                               */
  unsigned int is_fast:1; /** Do we think this is a fast OR? */
  unsigned int is_stable:1; /** Do we think this is a stable OR? */
  unsigned int is_possible_guard:1; /**< Do we think this is an OK guard? */
  unsigned int is_exit:1; /**< Do we think this is an OK exit? */
  unsigned int is_bad_exit:1; /**< Do we think this exit is censored, borked,
                               * or otherwise nasty? */
  unsigned int is_bad_directory:1; /**< Do we think this directory is junky,
                                    * underpowered, or otherwise useless? */
  unsigned int is_hs_dir:1; /**< True iff this router is a hidden service
                             * directory according to the authorities. */

  /* Local info: warning state. */

  unsigned int name_lookup_warned:1; /**< Have we warned the user for referring
                                      * to this (unnamed) router by nickname?
                                      */

  /** Local info: we treat this node as if it rejects everything */
  unsigned int rejects_all:1;

  /* Local info: derived. */

  /** According to the geoip db what country is this router in? */
  country_t country;
} node_t;

/** How many times will we try to download a router's descriptor before giving
 * up? */
#define MAX_ROUTERDESC_DOWNLOAD_FAILURES 8

/** How many times will we try to download a microdescriptor before giving
 * up? */
#define MAX_MICRODESC_DOWNLOAD_FAILURES 8

/** Contents of a v2 (non-consensus, non-vote) network status object. */
typedef struct networkstatus_v2_t {
  /** When did we receive the network-status document? */
  time_t received_on;

  /** What was the digest of the document? */
  char networkstatus_digest[DIGEST_LEN];

  /* These fields come from the actual network-status document.*/
  time_t published_on; /**< Declared publication date. */

  char *source_address; /**< Canonical directory server hostname. */
  uint32_t source_addr; /**< Canonical directory server IP. */
  uint16_t source_dirport; /**< Canonical directory server dirport. */

  unsigned int binds_names:1; /**< True iff this directory server binds
                               * names. */
  unsigned int recommends_versions:1; /**< True iff this directory server
                                       * recommends client and server software
                                       * versions. */
  unsigned int lists_bad_exits:1; /**< True iff this directory server marks
                                   * malfunctioning exits as bad. */
  /** True iff this directory server marks malfunctioning directories as
   * bad. */
  unsigned int lists_bad_directories:1;

  char identity_digest[DIGEST_LEN]; /**< Digest of signing key. */
  char *contact; /**< How to contact directory admin? (may be NULL). */
  crypto_pk_env_t *signing_key; /**< Key used to sign this directory. */
  char *client_versions; /**< comma-separated list of recommended client
                          * versions. */
  char *server_versions; /**< comma-separated list of recommended server
                          * versions. */

  smartlist_t *entries; /**< List of routerstatus_t*.   This list is kept
                         * sorted by identity_digest. */
} networkstatus_v2_t;

typedef struct vote_microdesc_hash_t {
  struct vote_microdesc_hash_t *next;
  char *microdesc_hash_line;
} vote_microdesc_hash_t;

/** The claim about a single router, made in a vote. */
typedef struct vote_routerstatus_t {
  routerstatus_t status; /**< Underlying 'status' object for this router.
                          * Flags are redundant. */
  uint64_t flags; /**< Bit-field for all recognized flags; index into
                   * networkstatus_t.known_flags. */
  char *version; /**< The version that the authority says this router is
                  * running. */
  vote_microdesc_hash_t *microdesc;
} vote_routerstatus_t;

/** A signature of some document by an authority. */
typedef struct document_signature_t {
  /** Declared SHA-1 digest of this voter's identity key */
  char identity_digest[DIGEST_LEN];
  /** Declared SHA-1 digest of signing key used by this voter. */
  char signing_key_digest[DIGEST_LEN];
  /** Algorithm used to compute the digest of the document. */
  digest_algorithm_t alg;
  /** Signature of the signed thing. */
  char *signature;
  /** Length of <b>signature</b> */
  int signature_len;
  unsigned int bad_signature : 1; /**< Set to true if we've tried to verify
                                   * the sig, and we know it's bad. */
  unsigned int good_signature : 1; /**< Set to true if we've verified the sig
                                     * as good. */
} document_signature_t;

/** Information about a single voter in a vote or a consensus. */
typedef struct networkstatus_voter_info_t {
  /** Declared SHA-1 digest of this voter's identity key */
  char identity_digest[DIGEST_LEN];
  char *nickname; /**< Nickname of this voter */
  /** Digest of this voter's "legacy" identity key, if any.  In vote only; for
   * consensuses, we treat legacy keys as additional signers. */
  char legacy_id_digest[DIGEST_LEN];
  char *address; /**< Address of this voter, in string format. */
  uint32_t addr; /**< Address of this voter, in IPv4, in host order. */
  uint16_t dir_port; /**< Directory port of this voter */
  uint16_t or_port; /**< OR port of this voter */
  char *contact; /**< Contact information for this voter. */
  char vote_digest[DIGEST_LEN]; /**< Digest of this voter's vote, as signed. */

  /* Nothing from here on is signed. */
  /** The signature of the document and the signature's status. */
  smartlist_t *sigs;
} networkstatus_voter_info_t;

/** Enumerates the possible seriousness values of a networkstatus document. */
typedef enum {
  NS_TYPE_VOTE,
  NS_TYPE_CONSENSUS,
  NS_TYPE_OPINION,
} networkstatus_type_t;

/** Enumerates recognized flavors of a consensus networkstatus document.  All
 * flavors of a consensus are generated from the same set of votes, but they
 * present different types information to different versions of Tor. */
typedef enum {
  FLAV_NS = 0,
  FLAV_MICRODESC = 1,
} consensus_flavor_t;

/** Which consensus flavor do we actually want to use to build circuits? */
#define USABLE_CONSENSUS_FLAVOR FLAV_NS

/** How many different consensus flavors are there? */
#define N_CONSENSUS_FLAVORS ((int)(FLAV_MICRODESC)+1)

/** A common structure to hold a v3 network status vote, or a v3 network
 * status consensus. */
typedef struct networkstatus_t {
  networkstatus_type_t type : 8; /**< Vote, consensus, or opinion? */
  consensus_flavor_t flavor : 8; /**< If a consensus, what kind? */
  time_t published; /**< Vote only: Time when vote was written. */
  time_t valid_after; /**< Time after which this vote or consensus applies. */
  time_t fresh_until; /**< Time before which this is the most recent vote or
                       * consensus. */
  time_t valid_until; /**< Time after which this vote or consensus should not
                       * be used. */

  /** Consensus only: what method was used to produce this consensus? */
  int consensus_method;
  /** Vote only: what methods is this voter willing to use? */
  smartlist_t *supported_methods;

  /** How long does this vote/consensus claim that authorities take to
   * distribute their votes to one another? */
  int vote_seconds;
  /** How long does this vote/consensus claim that authorities take to
   * distribute their consensus signatures to one another? */
  int dist_seconds;

  /** Comma-separated list of recommended client software, or NULL if this
   * voter has no opinion. */
  char *client_versions;
  char *server_versions;
  /** List of flags that this vote/consensus applies to routers.  If a flag is
   * not listed here, the voter has no opinion on what its value should be. */
  smartlist_t *known_flags;

  /** List of key=value strings for the parameters in this vote or
   * consensus, sorted by key. */
  smartlist_t *net_params;

  /** List of key=value strings for the bw weight parameters in the
   * consensus. */
  smartlist_t *weight_params;

  /** List of networkstatus_voter_info_t.  For a vote, only one element
   * is included.  For a consensus, one element is included for every voter
   * whose vote contributed to the consensus. */
  smartlist_t *voters;

  struct authority_cert_t *cert; /**< Vote only: the voter's certificate. */

  /** Digests of this document, as signed. */
  digests_t digests;

  /** List of router statuses, sorted by identity digest.  For a vote,
   * the elements are vote_routerstatus_t; for a consensus, the elements
   * are routerstatus_t. */
  smartlist_t *routerstatus_list;

  /** If present, a map from descriptor digest to elements of
   * routerstatus_list. */
  digestmap_t *desc_digest_map;
} networkstatus_t;

/** A set of signatures for a networkstatus consensus.  Unless otherwise
 * noted, all fields are as for networkstatus_t. */
typedef struct ns_detached_signatures_t {
  time_t valid_after;
  time_t fresh_until;
  time_t valid_until;
  strmap_t *digests; /**< Map from flavor name to digestset_t */
  strmap_t *signatures; /**< Map from flavor name to list of
                         * document_signature_t */
} ns_detached_signatures_t;

/** Allowable types of desc_store_t. */
typedef enum store_type_t {
  ROUTER_STORE = 0,
  EXTRAINFO_STORE = 1
} store_type_t;

/** A 'store' is a set of descriptors saved on disk, with accompanying
 * journal, mmaped as needed, rebuilt as needed. */
typedef struct desc_store_t {
  /** Filename (within DataDir) for the store.  We append .tmp to this
   * filename for a temporary file when rebuilding the store, and .new to this
   * filename for the journal. */
  const char *fname_base;
  /** Alternative (obsolete) value for fname_base: if the file named by
   * fname_base isn't present, we read from here instead, but we never write
   * here. */
  const char *fname_alt_base;
  /** Human-readable description of what this store contains. */
  const char *description;

  tor_mmap_t *mmap; /**< A mmap for the main file in the store. */

  store_type_t type; /**< What's stored in this store? */

  /** The size of the router log, in bytes. */
  size_t journal_len;
  /** The size of the router store, in bytes. */
  size_t store_len;
  /** Total bytes dropped since last rebuild: this is space currently
   * used in the cache and the journal that could be freed by a rebuild. */
  size_t bytes_dropped;
} desc_store_t;

/** Contents of a directory of onion routers. */
typedef struct {
  /** Map from server identity digest to a member of routers. */
  struct digest_ri_map_t *identity_map;
  /** Map from server descriptor digest to a signed_descriptor_t from
   * routers or old_routers. */
  struct digest_sd_map_t *desc_digest_map;
  /** Map from extra-info digest to an extrainfo_t.  Only exists for
   * routers in routers or old_routers. */
  struct digest_ei_map_t *extra_info_map;
  /** Map from extra-info digests to a signed_descriptor_t for a router
   * descriptor having that extra-info digest.  Only exists for
   * routers in routers or old_routers. */
  struct digest_sd_map_t *desc_by_eid_map;
  /** List of routerinfo_t for all currently live routers we know. */
  smartlist_t *routers;
  /** List of signed_descriptor_t for older router descriptors we're
   * caching. */
  smartlist_t *old_routers;
  /** Store holding server descriptors.  If present, any router whose
   * cache_info.saved_location == SAVED_IN_CACHE is stored in this file
   * starting at cache_info.saved_offset */
  desc_store_t desc_store;
  /** Store holding extra-info documents. */
  desc_store_t extrainfo_store;
} routerlist_t;

/** Information on router used when extending a circuit. We don't need a
 * full routerinfo_t to extend: we only need addr:port:keyid to build an OR
 * connection, and onion_key to create the onionskin. Note that for onehop
 * general-purpose tunnels, the onion_key is NULL. */
typedef struct extend_info_t {
  char nickname[MAX_HEX_NICKNAME_LEN+1]; /**< This router's nickname for
                                          * display. */
  char identity_digest[DIGEST_LEN]; /**< Hash of this router's identity key. */
  uint16_t port; /**< OR port. */
  tor_addr_t addr; /**< IP address. */
  crypto_pk_env_t *onion_key; /**< Current onionskin key. */
} extend_info_t;

/** Certificate for v3 directory protocol: binds long-term authority identity
 * keys to medium-term authority signing keys. */
typedef struct authority_cert_t {
  /** Information relating to caching this cert on disk and looking it up. */
  signed_descriptor_t cache_info;
  /** This authority's long-term authority identity key. */
  crypto_pk_env_t *identity_key;
  /** This authority's medium-term signing key. */
  crypto_pk_env_t *signing_key;
  /** The digest of <b>signing_key</b> */
  char signing_key_digest[DIGEST_LEN];
  /** The listed expiration time of this certificate. */
  time_t expires;
  /** This authority's IPv4 address, in host order. */
  uint32_t addr;
  /** This authority's directory port. */
  uint16_t dir_port;
  /** True iff this certificate was cross-certified by signing the identity
   * key with the signing key. */
  uint8_t is_cross_certified;
} authority_cert_t;

/** Bitfield enum type listing types of directory authority/directory
 * server.  */
typedef enum {
  NO_AUTHORITY      = 0,
  /** Serves/signs v1 directory information: Big lists of routers, and short
   * routerstatus documents. */
  V1_AUTHORITY      = 1 << 0,
  /** Serves/signs v2 directory information: i.e. v2 networkstatus documents */
  V2_AUTHORITY      = 1 << 1,
  /** Serves/signs v3 directory information: votes, consensuses, certs */
  V3_AUTHORITY      = 1 << 2,
  /** Serves hidden service descriptors. */
  HIDSERV_AUTHORITY = 1 << 3,
  /** Serves bridge descriptors. */
  BRIDGE_AUTHORITY  = 1 << 4,
  /** Serves extrainfo documents. (XXX Not precisely an authority type)*/
  EXTRAINFO_CACHE   = 1 << 5,
} authority_type_t;

#define CRYPT_PATH_MAGIC 0x70127012u

/** Holds accounting information for a single step in the layered encryption
 * performed by a circuit.  Used only at the client edge of a circuit. */
typedef struct crypt_path_t {
  uint32_t magic;

  /* crypto environments */
  /** Encryption key and counter for cells heading towards the OR at this
   * step. */
  crypto_cipher_env_t *f_crypto;
  /** Encryption key and counter for cells heading back from the OR at this
   * step. */
  crypto_cipher_env_t *b_crypto;

  /** Digest state for cells heading towards the OR at this step. */
  crypto_digest_env_t *f_digest; /* for integrity checking */
  /** Digest state for cells heading away from the OR at this step. */
  crypto_digest_env_t *b_digest;

  /** Current state of Diffie-Hellman key negotiation with the OR at this
   * step. */
  crypto_dh_env_t *dh_handshake_state;
  /** Current state of 'fast' (non-PK) key negotiation with the OR at this
   * step. Used to save CPU when TLS is already providing all the
   * authentication, secrecy, and integrity we need, and we're already
   * distinguishable from an OR.
   */
  char fast_handshake_state[DIGEST_LEN];
  /** Negotiated key material shared with the OR at this step. */
  char handshake_digest[DIGEST_LEN];/* KH in tor-spec.txt */

  /** Information to extend to the OR at this step. */
  extend_info_t *extend_info;

  /** Is the circuit built to this step?  Must be one of:
   *    - CPATH_STATE_CLOSED (The circuit has not been extended to this step)
   *    - CPATH_STATE_AWAITING_KEYS (We have sent an EXTEND/CREATE to this step
   *      and not received an EXTENDED/CREATED)
   *    - CPATH_STATE_OPEN (The circuit has been extended to this step) */
  uint8_t state;
#define CPATH_STATE_CLOSED 0
#define CPATH_STATE_AWAITING_KEYS 1
#define CPATH_STATE_OPEN 2
  struct crypt_path_t *next; /**< Link to next crypt_path_t in the circuit.
                              * (The list is circular, so the last node
                              * links to the first.) */
  struct crypt_path_t *prev; /**< Link to previous crypt_path_t in the
                              * circuit. */

  int package_window; /**< How many cells are we allowed to originate ending
                       * at this step? */
  int deliver_window; /**< How many cells are we willing to deliver originating
                       * at this step? */
} crypt_path_t;

#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)

#define DH_KEY_LEN DH_BYTES
#define ONIONSKIN_CHALLENGE_LEN (PKCS1_OAEP_PADDING_OVERHEAD+\
                                 CIPHER_KEY_LEN+\
                                 DH_KEY_LEN)
#define ONIONSKIN_REPLY_LEN (DH_KEY_LEN+DIGEST_LEN)

/** Information used to build a circuit. */
typedef struct {
  /** Intended length of the final circuit. */
  int desired_path_len;
  /** How to extend to the planned exit node. */
  extend_info_t *chosen_exit;
  /** Whether every node in the circ must have adequate uptime. */
  int need_uptime;
  /** Whether every node in the circ must have adequate capacity. */
  int need_capacity;
  /** Whether the last hop was picked with exiting in mind. */
  int is_internal;
  /** Did we pick this as a one-hop tunnel (not safe for other conns)?
   * These are for encrypted connections that exit to this router, not
   * for arbitrary exits from the circuit. */
  int onehop_tunnel;
  /** The crypt_path_t to append after rendezvous: used for rendezvous. */
  crypt_path_t *pending_final_cpath;
  /** How many times has building a circuit for this task failed? */
  int failure_count;
  /** At what time should we give up on this task? */
  time_t expiry_time;
} cpath_build_state_t;

/**
 * The cell_ewma_t structure keeps track of how many cells a circuit has
 * transferred recently.  It keeps an EWMA (exponentially weighted moving
 * average) of the number of cells flushed from the circuit queue onto a
 * connection in connection_or_flush_from_first_active_circuit().
 */
typedef struct {
  /** The last 'tick' at which we recalibrated cell_count.
   *
   * A cell sent at exactly the start of this tick has weight 1.0. Cells sent
   * since the start of this tick have weight greater than 1.0; ones sent
   * earlier have less weight. */
  unsigned last_adjusted_tick;
  /** The EWMA of the cell count. */
  double cell_count;
  /** True iff this is the cell count for a circuit's previous
   * connection. */
  unsigned int is_for_p_conn : 1;
  /** The position of the circuit within the OR connection's priority
   * queue. */
  int heap_index;
} cell_ewma_t;

#define ORIGIN_CIRCUIT_MAGIC 0x35315243u
#define OR_CIRCUIT_MAGIC 0x98ABC04Fu

/**
 * A circuit is a path over the onion routing
 * network. Applications can connect to one end of the circuit, and can
 * create exit connections at the other end of the circuit. AP and exit
 * connections have only one circuit associated with them (and thus these
 * connection types are closed when the circuit is closed), whereas
 * OR connections multiplex many circuits at once, and stay standing even
 * when there are no circuits running over them.
 *
 * A circuit_t structure can fill one of two roles.  First, a or_circuit_t
 * links two connections together: either an edge connection and an OR
 * connection, or two OR connections.  (When joined to an OR connection, a
 * circuit_t affects only cells sent to a particular circID on that
 * connection.  When joined to an edge connection, a circuit_t affects all
 * data.)

 * Second, an origin_circuit_t holds the cipher keys and state for sending data
 * along a given circuit.  At the OP, it has a sequence of ciphers, each
 * of which is shared with a single OR along the circuit.  Separate
 * ciphers are used for data going "forward" (away from the OP) and
 * "backward" (towards the OP).  At the OR, a circuit has only two stream
 * ciphers: one for data going forward, and one for data going backward.
 */
typedef struct circuit_t {
  uint32_t magic; /**< For memory and type debugging: must equal
                   * ORIGIN_CIRCUIT_MAGIC or OR_CIRCUIT_MAGIC. */

  /** Queue of cells waiting to be transmitted on n_conn. */
  cell_queue_t n_conn_cells;
  /** The OR connection that is next in this circuit. */
  or_connection_t *n_conn;
  /** The circuit_id used in the next (forward) hop of this circuit. */
  circid_t n_circ_id;

  /** The hop to which we want to extend this circuit.  Should be NULL if
   * the circuit has attached to a connection. */
  extend_info_t *n_hop;

  /** True iff we are waiting for n_conn_cells to become less full before
   * allowing p_streams to add any more cells. (Origin circuit only.) */
  unsigned int streams_blocked_on_n_conn : 1;
  /** True iff we are waiting for p_conn_cells to become less full before
   * allowing n_streams to add any more cells. (OR circuit only.) */
  unsigned int streams_blocked_on_p_conn : 1;

  uint8_t state; /**< Current status of this circuit. */
  uint8_t purpose; /**< Why are we creating this circuit? */

  /** How many relay data cells can we package (read from edge streams)
   * on this circuit before we receive a circuit-level sendme cell asking
   * for more? */
  int package_window;
  /** How many relay data cells will we deliver (write to edge streams)
   * on this circuit? When deliver_window gets low, we send some
   * circuit-level sendme cells to indicate that we're willing to accept
   * more. */
  int deliver_window;

  /** For storage while n_conn is pending
    * (state CIRCUIT_STATE_OR_WAIT). When defined, it is always
    * length ONIONSKIN_CHALLENGE_LEN. */
  char *n_conn_onionskin;

  /** When was this circuit created?  We keep this timestamp with a higher
   * resolution than most so that the circuit-build-time tracking code can
   * get millisecond resolution. */
  struct timeval timestamp_created;
  time_t timestamp_dirty; /**< When the circuit was first used, or 0 if the
                           * circuit is clean. */

  uint16_t marked_for_close; /**< Should we close this circuit at the end of
                              * the main loop? (If true, holds the line number
                              * where this circuit was marked.) */
  const char *marked_for_close_file; /**< For debugging: in which file was this
                                      * circuit marked for close? */

  /** Next circuit in the doubly-linked ring of circuits waiting to add
   * cells to n_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  struct circuit_t *next_active_on_n_conn;
  /** Previous circuit in the doubly-linked ring of circuits waiting to add
   * cells to n_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  struct circuit_t *prev_active_on_n_conn;
  struct circuit_t *next; /**< Next circuit in linked list of all circuits. */

  /** Unique ID for measuring tunneled network status requests. */
  uint64_t dirreq_id;

  /** The EWMA count for the number of cells flushed from the
   * n_conn_cells queue.  Used to determine which circuit to flush from next.
   */
  cell_ewma_t n_cell_ewma;
} circuit_t;

/** Largest number of relay_early cells that we can send on a given
 * circuit. */
#define MAX_RELAY_EARLY_CELLS_PER_CIRCUIT 8

/** An origin_circuit_t holds data necessary to build and use a circuit.
 */
typedef struct origin_circuit_t {
  circuit_t _base;

  /** Linked list of AP streams (or EXIT streams if hidden service)
   * associated with this circuit. */
  edge_connection_t *p_streams;
  /** Build state for this circuit. It includes the intended path
   * length, the chosen exit router, rendezvous information, etc.
   */
  cpath_build_state_t *build_state;
  /** The doubly-linked list of crypt_path_t entries, one per hop,
   * for this circuit. This includes ciphers for each hop,
   * integrity-checking digests for each hop, and package/delivery
   * windows for each hop.
   */
  crypt_path_t *cpath;

  /** Holds all rendezvous data on either client or service side. */
  rend_data_t *rend_data;

  /** How many more relay_early cells can we send on this circuit, according
   * to the specification? */
  unsigned int remaining_relay_early_cells : 4;

  /** Set if this circuit is insanely old and we already informed the user */
  unsigned int is_ancient : 1;

  /** Set if this circuit has already been opened. Used to detect
   * cannibalized circuits. */
  unsigned int has_opened : 1;

  /** What commands were sent over this circuit that decremented the
   * RELAY_EARLY counter? This is for debugging task 878. */
  uint8_t relay_early_commands[MAX_RELAY_EARLY_CELLS_PER_CIRCUIT];

  /** How many RELAY_EARLY cells have been sent over this circuit? This is
   * for debugging task 878, too. */
  int relay_early_cells_sent;

  /** The next stream_id that will be tried when we're attempting to
   * construct a new AP stream originating at this circuit. */
  streamid_t next_stream_id;

  /* The intro key replaces the hidden service's public key if purpose is
   * S_ESTABLISH_INTRO or S_INTRO, provided that no unversioned rendezvous
   * descriptor is used. */
  crypto_pk_env_t *intro_key;

  /** Quasi-global identifier for this circuit; used for control.c */
  /* XXXX NM This can get re-used after 2**32 circuits. */
  uint32_t global_identifier;

} origin_circuit_t;

/** An or_circuit_t holds information needed to implement a circuit at an
 * OR. */
typedef struct or_circuit_t {
  circuit_t _base;

  /** Next circuit in the doubly-linked ring of circuits waiting to add
   * cells to p_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  struct circuit_t *next_active_on_p_conn;
  /** Previous circuit in the doubly-linked ring of circuits waiting to add
   * cells to p_conn.  NULL if we have no cells pending, or if we're not
   * linked to an OR connection. */
  struct circuit_t *prev_active_on_p_conn;

  /** The circuit_id used in the previous (backward) hop of this circuit. */
  circid_t p_circ_id;
  /** Queue of cells waiting to be transmitted on p_conn. */
  cell_queue_t p_conn_cells;
  /** The OR connection that is previous in this circuit. */
  or_connection_t *p_conn;
  /** Linked list of Exit streams associated with this circuit. */
  edge_connection_t *n_streams;
  /** Linked list of Exit streams associated with this circuit that are
   * still being resolved. */
  edge_connection_t *resolving_streams;
  /** The cipher used by intermediate hops for cells heading toward the
   * OP. */
  crypto_cipher_env_t *p_crypto;
  /** The cipher used by intermediate hops for cells heading away from
   * the OP. */
  crypto_cipher_env_t *n_crypto;

  /** The integrity-checking digest used by intermediate hops, for
   * cells packaged here and heading towards the OP.
   */
  crypto_digest_env_t *p_digest;
  /** The integrity-checking digest used by intermediate hops, for
   * cells packaged at the OP and arriving here.
   */
  crypto_digest_env_t *n_digest;

  /** Points to spliced circuit if purpose is REND_ESTABLISHED, and circuit
   * is not marked for close. */
  struct or_circuit_t *rend_splice;

#if REND_COOKIE_LEN >= DIGEST_LEN
#define REND_TOKEN_LEN REND_COOKIE_LEN
#else
#define REND_TOKEN_LEN DIGEST_LEN
#endif

  /** A hash of location-hidden service's PK if purpose is INTRO_POINT, or a
   * rendezvous cookie if purpose is REND_POINT_WAITING. Filled with zeroes
   * otherwise.
   * ???? move to a subtype or adjunct structure? Wastes 20 bytes. -NM
   */
  char rend_token[REND_TOKEN_LEN];

  /* ???? move to a subtype or adjunct structure? Wastes 20 bytes -NM */
  char handshake_digest[DIGEST_LEN]; /**< Stores KH for the handshake. */

  /** How many more relay_early cells can we send on this circuit, according
   * to the specification? */
  unsigned int remaining_relay_early_cells : 4;

  /** True iff this circuit was made with a CREATE_FAST cell. */
  unsigned int is_first_hop : 1;

  /** Number of cells that were removed from circuit queue; reset every
   * time when writing buffer stats to disk. */
  uint32_t processed_cells;

  /** Total time in milliseconds that cells spent in both app-ward and
   * exit-ward queues of this circuit; reset every time when writing
   * buffer stats to disk. */
  uint64_t total_cell_waiting_time;

  /** The EWMA count for the number of cells flushed from the
   * p_conn_cells queue. */
  cell_ewma_t p_cell_ewma;
} or_circuit_t;

/** Convert a circuit subtype to a circuit_t.*/
#define TO_CIRCUIT(x)  (&((x)->_base))

/** Convert a circuit_t* to a pointer to the enclosing or_circuit_t.  Asserts
 * if the cast is impossible. */
static or_circuit_t *TO_OR_CIRCUIT(circuit_t *);
/** Convert a circuit_t* to a pointer to the enclosing origin_circuit_t.
 * Asserts if the cast is impossible. */
static origin_circuit_t *TO_ORIGIN_CIRCUIT(circuit_t *);

static INLINE or_circuit_t *TO_OR_CIRCUIT(circuit_t *x)
{
  tor_assert(x->magic == OR_CIRCUIT_MAGIC);
  return DOWNCAST(or_circuit_t, x);
}
static INLINE origin_circuit_t *TO_ORIGIN_CIRCUIT(circuit_t *x)
{
  tor_assert(x->magic == ORIGIN_CIRCUIT_MAGIC);
  return DOWNCAST(origin_circuit_t, x);
}

/** Bitfield type: things that we're willing to use invalid routers for. */
typedef enum invalid_router_usage_t {
  ALLOW_INVALID_ENTRY       =1,
  ALLOW_INVALID_EXIT        =2,
  ALLOW_INVALID_MIDDLE      =4,
  ALLOW_INVALID_RENDEZVOUS  =8,
  ALLOW_INVALID_INTRODUCTION=16,
} invalid_router_usage_t;

/* limits for TCP send and recv buffer size used for constrained sockets */
#define MIN_CONSTRAINED_TCP_BUFFER 2048
#define MAX_CONSTRAINED_TCP_BUFFER 262144  /* 256k */

/** A linked list of lines in a config file. */
typedef struct config_line_t {
  char *key;
  char *value;
  struct config_line_t *next;
} config_line_t;

typedef struct routerset_t routerset_t;

/** Configuration options for a Tor process. */
typedef struct {
  uint32_t _magic;

  /** What should the tor process actually do? */
  enum {
    CMD_RUN_TOR=0, CMD_LIST_FINGERPRINT, CMD_HASH_PASSWORD,
    CMD_VERIFY_CONFIG, CMD_RUN_UNITTESTS
  } command;
  const char *command_arg; /**< Argument for command-line option. */

  config_line_t *Logs; /**< New-style list of configuration lines
                        * for logs */
  int LogTimeGranularity; /**< Log resolution in milliseconds. */

  char *DebugLogFile; /**< Where to send verbose log messages. */
  char *DataDirectory; /**< OR only: where to store long-term data. */
  char *Nickname; /**< OR only: nickname of this onion router. */
  char *Address; /**< OR only: configured address for this onion router. */
  char *PidFile; /**< Where to store PID of Tor process. */

  routerset_t *ExitNodes; /**< Structure containing nicknames, digests,
                           * country codes and IP address patterns of ORs to
                           * consider as exits. */
  routerset_t *EntryNodes;/**< Structure containing nicknames, digests,
                           * country codes and IP address patterns of ORs to
                           * consider as entry points. */
  int StrictNodes; /**< Boolean: When none of our EntryNodes or ExitNodes
                    * are up, or we need to access a node in ExcludeNodes,
                    * do we just fail instead? */
  routerset_t *ExcludeNodes;/**< Structure containing nicknames, digests,
                             * country codes and IP address patterns of ORs
                             * not to use in circuits. But see StrictNodes
                             * above. */
  routerset_t *ExcludeExitNodes;/**< Structure containing nicknames, digests,
                                 * country codes and IP address patterns of
                                 * ORs not to consider as exits. */

  /** Union of ExcludeNodes and ExcludeExitNodes */
  struct routerset_t *_ExcludeExitNodesUnion;

  int DisableAllSwap; /**< Boolean: Attempt to call mlockall() on our
                       * process for all current and future memory. */

  /** List of "entry", "middle", "exit", "introduction", "rendezvous". */
  smartlist_t *AllowInvalidNodes;
  /** Bitmask; derived from AllowInvalidNodes. */
  invalid_router_usage_t _AllowInvalid;
  config_line_t *ExitPolicy; /**< Lists of exit policy components. */
  int ExitPolicyRejectPrivate; /**< Should we not exit to local addresses? */
  config_line_t *SocksPolicy; /**< Lists of socks policy components */
  config_line_t *DirPolicy; /**< Lists of dir policy components */
  /** Addresses to bind for listening for SOCKS connections. */
  config_line_t *SocksListenAddress;
  /** Addresses to bind for listening for transparent pf/netfilter
   * connections. */
  config_line_t *TransListenAddress;
  /** Addresses to bind for listening for transparent natd connections */
  config_line_t *NatdListenAddress;
  /** Addresses to bind for listening for SOCKS connections. */
  config_line_t *DNSListenAddress;
  /** Addresses to bind for listening for OR connections. */
  config_line_t *ORListenAddress;
  /** Addresses to bind for listening for directory connections. */
  config_line_t *DirListenAddress;
  /** Addresses to bind for listening for control connections. */
  config_line_t *ControlListenAddress;
  /** Local address to bind outbound sockets */
  char *OutboundBindAddress;
  /** Directory server only: which versions of
   * Tor should we tell users to run? */
  config_line_t *RecommendedVersions;
  config_line_t *RecommendedClientVersions;
  config_line_t *RecommendedServerVersions;
  /** Whether dirservers refuse router descriptors with private IPs. */
  int DirAllowPrivateAddresses;
  char *User; /**< Name of user to run Tor as. */
  char *Group; /**< Name of group to run Tor as. */
  int ORPort; /**< Port to listen on for OR connections. */
  int SocksPort; /**< Port to listen on for SOCKS connections. */
  /** Port to listen on for transparent pf/netfilter connections. */
  int TransPort;
  int NatdPort; /**< Port to listen on for transparent natd connections. */
  int ControlPort; /**< Port to listen on for control connections. */
  config_line_t *ControlSocket; /**< List of Unix Domain Sockets to listen on
                                 * for control connections. */
  int DirPort; /**< Port to listen on for directory connections. */
  int DNSPort; /**< Port to listen on for DNS requests. */
  int AssumeReachable; /**< Whether to publish our descriptor regardless. */
  int AuthoritativeDir; /**< Boolean: is this an authoritative directory? */
  int V1AuthoritativeDir; /**< Boolean: is this an authoritative directory
                           * for version 1 directories? */
  int V2AuthoritativeDir; /**< Boolean: is this an authoritative directory
                           * for version 2 directories? */
  int V3AuthoritativeDir; /**< Boolean: is this an authoritative directory
                           * for version 3 directories? */
  int HSAuthoritativeDir; /**< Boolean: does this an authoritative directory
                           * handle hidden service requests? */
  int NamingAuthoritativeDir; /**< Boolean: is this an authoritative directory
                               * that's willing to bind names? */
  int VersioningAuthoritativeDir; /**< Boolean: is this an authoritative
                                   * directory that's willing to recommend
                                   * versions? */
  int BridgeAuthoritativeDir; /**< Boolean: is this an authoritative directory
                               * that aggregates bridge descriptors? */

  /** If set on a bridge authority, it will answer requests on its dirport
   * for bridge statuses -- but only if the requests use this password.
   * If set on a bridge user, request bridge statuses, and use this password
   * when doing so. */
  char *BridgePassword;

  int UseBridges; /**< Boolean: should we start all circuits with a bridge? */
  config_line_t *Bridges; /**< List of bootstrap bridge addresses. */

  int BridgeRelay; /**< Boolean: are we acting as a bridge relay? We make
                    * this explicit so we can change how we behave in the
                    * future. */

  /** Boolean: if we know the bridge's digest, should we get new
   * descriptors from the bridge authorities or from the bridge itself? */
  int UpdateBridgesFromAuthority;

  int AvoidDiskWrites; /**< Boolean: should we never cache things to disk?
                        * Not used yet. */
  int ClientOnly; /**< Boolean: should we never evolve into a server role? */
  /** Boolean: should we never publish a descriptor? Deprecated. */
  int NoPublish;
  /** To what authority types do we publish our descriptor? Choices are
   * "v1", "v2", "v3", "bridge", or "". */
  smartlist_t *PublishServerDescriptor;
  /** An authority type, derived from PublishServerDescriptor. */
  authority_type_t _PublishServerDescriptor;
  /** Boolean: do we publish hidden service descriptors to the HS auths? */
  int PublishHidServDescriptors;
  int FetchServerDescriptors; /**< Do we fetch server descriptors as normal? */
  int FetchHidServDescriptors; /** and hidden service descriptors? */
  int HidServDirectoryV2; /**< Do we participate in the HS DHT? */

  int MinUptimeHidServDirectoryV2; /**< As directory authority, accept hidden
                                    * service directories after what time? */
  int FetchUselessDescriptors; /**< Do we fetch non-running descriptors too? */
  int AllDirActionsPrivate; /**< Should every directory action be sent
                             * through a Tor circuit? */

  int ConnLimit; /**< Demanded minimum number of simultaneous connections. */
  int _ConnLimit; /**< Maximum allowed number of simultaneous connections. */
  int RunAsDaemon; /**< If true, run in the background. (Unix only) */
  int FascistFirewall; /**< Whether to prefer ORs reachable on open ports. */
  smartlist_t *FirewallPorts; /**< Which ports our firewall allows
                               * (strings). */
  config_line_t *ReachableAddresses; /**< IP:ports our firewall allows. */
  config_line_t *ReachableORAddresses; /**< IP:ports for OR conns. */
  config_line_t *ReachableDirAddresses; /**< IP:ports for Dir conns. */

  int ConstrainedSockets; /**< Shrink xmit and recv socket buffers. */
  uint64_t ConstrainedSockSize; /**< Size of constrained buffers. */

  /** Whether we should drop exit streams from Tors that we don't know are
   * relays.  One of "0" (never refuse), "1" (always refuse), or "auto" (do
   * what the consensus says, defaulting to 'refuse' if the consensus says
   * nothing). */
  char *RefuseUnknownExits;
  /** Parsed version of RefuseUnknownExits. -1 for auto. */
  int RefuseUnknownExits_;

  /** Application ports that require all nodes in circ to have sufficient
   * uptime. */
  smartlist_t *LongLivedPorts;
  /** Application ports that are likely to be unencrypted and
   * unauthenticated; we reject requests for them to prevent the
   * user from screwing up and leaking plaintext secrets to an
   * observer somewhere on the Internet. */
  smartlist_t *RejectPlaintextPorts;
  /** Related to RejectPlaintextPorts above, except this config option
   * controls whether we warn (in the log and via a controller status
   * event) every time a risky connection is attempted. */
  smartlist_t *WarnPlaintextPorts;
  /** Should we try to reuse the same exit node for a given host */
  smartlist_t *TrackHostExits;
  int TrackHostExitsExpire; /**< Number of seconds until we expire an
                             * addressmap */
  config_line_t *AddressMap; /**< List of address map directives. */
  int AutomapHostsOnResolve; /**< If true, when we get a resolve request for a
                              * hostname ending with one of the suffixes in
                              * <b>AutomapHostsSuffixes</b>, map it to a
                              * virtual address. */
  smartlist_t *AutomapHostsSuffixes; /**< List of suffixes for
                                      * <b>AutomapHostsOnResolve</b>. */
  int RendPostPeriod; /**< How often do we post each rendezvous service
                       * descriptor? Remember to publish them independently. */
  int KeepalivePeriod; /**< How often do we send padding cells to keep
                        * connections alive? */
  int SocksTimeout; /**< How long do we let a socks connection wait
                     * unattached before we fail it? */
  int LearnCircuitBuildTimeout; /**< If non-zero, we attempt to learn a value
                                 * for CircuitBuildTimeout based on timeout
                                 * history */
  int CircuitBuildTimeout; /**< Cull non-open circuits that were born at
                            * least this many seconds ago. Used until
                            * adaptive algorithm learns a new value. */
  int CircuitIdleTimeout; /**< Cull open clean circuits that were born
                           * at least this many seconds ago. */
  int CircuitStreamTimeout; /**< If non-zero, detach streams from circuits
                             * and try a new circuit if the stream has been
                             * waiting for this many seconds. If zero, use
                             * our default internal timeout schedule. */
  int MaxOnionsPending; /**< How many circuit CREATE requests do we allow
                         * to wait simultaneously before we start dropping
                         * them? */
  int NewCircuitPeriod; /**< How long do we use a circuit before building
                         * a new one? */
  int MaxCircuitDirtiness; /**< Never use circs that were first used more than
                                this interval ago. */
  uint64_t BandwidthRate; /**< How much bandwidth, on average, are we willing
                           * to use in a second? */
  uint64_t BandwidthBurst; /**< How much bandwidth, at maximum, are we willing
                            * to use in a second? */
  uint64_t MaxAdvertisedBandwidth; /**< How much bandwidth are we willing to
                                    * tell people we have? */
  uint64_t RelayBandwidthRate; /**< How much bandwidth, on average, are we
                                 * willing to use for all relayed conns? */
  uint64_t RelayBandwidthBurst; /**< How much bandwidth, at maximum, will we
                                 * use in a second for all relayed conns? */
  uint64_t PerConnBWRate; /**< Long-term bw on a single TLS conn, if set. */
  uint64_t PerConnBWBurst; /**< Allowed burst on a single TLS conn, if set. */
  int NumCpus; /**< How many CPUs should we try to use? */
  int RunTesting; /**< If true, create testing circuits to measure how well the
                   * other ORs are running. */
  config_line_t *RendConfigLines; /**< List of configuration lines
                                          * for rendezvous services. */
  config_line_t *HidServAuth; /**< List of configuration lines for client-side
                               * authorizations for hidden services */
  char *ContactInfo; /**< Contact info to be published in the directory. */

  char *HttpProxy; /**< hostname[:port] to use as http proxy, if any. */
  tor_addr_t HttpProxyAddr; /**< Parsed IPv4 addr for http proxy, if any. */
  uint16_t HttpProxyPort; /**< Parsed port for http proxy, if any. */
  char *HttpProxyAuthenticator; /**< username:password string, if any. */

  char *HttpsProxy; /**< hostname[:port] to use as https proxy, if any. */
  tor_addr_t HttpsProxyAddr; /**< Parsed addr for https proxy, if any. */
  uint16_t HttpsProxyPort; /**< Parsed port for https proxy, if any. */
  char *HttpsProxyAuthenticator; /**< username:password string, if any. */

  char *Socks4Proxy; /**< hostname:port to use as a SOCKS4 proxy, if any. */
  tor_addr_t Socks4ProxyAddr; /**< Derived from Socks4Proxy. */
  uint16_t Socks4ProxyPort; /**< Derived from Socks4Proxy. */

  char *Socks5Proxy; /**< hostname:port to use as a SOCKS5 proxy, if any. */
  tor_addr_t Socks5ProxyAddr; /**< Derived from Sock5Proxy. */
  uint16_t Socks5ProxyPort; /**< Derived from Socks5Proxy. */
  char *Socks5ProxyUsername; /**< Username for SOCKS5 authentication, if any */
  char *Socks5ProxyPassword; /**< Password for SOCKS5 authentication, if any */

  /** List of configuration lines for replacement directory authorities.
   * If you just want to replace one class of authority at a time,
   * use the "Alternate*Authority" options below instead. */
  config_line_t *DirServers;

  /** If set, use these main (currently v3) directory authorities and
   * not the default ones. */
  config_line_t *AlternateDirAuthority;

  /** If set, use these bridge authorities and not the default one. */
  config_line_t *AlternateBridgeAuthority;

  /** If set, use these HS authorities and not the default ones. */
  config_line_t *AlternateHSAuthority;

  char *MyFamily; /**< Declared family for this OR. */
  config_line_t *NodeFamilies; /**< List of config lines for
                                * node families */
  smartlist_t *NodeFamilySets; /**< List of parsed NodeFamilies values. */
  config_line_t *AuthDirBadDir; /**< Address policy for descriptors to
                                 * mark as bad dir mirrors. */
  config_line_t *AuthDirBadExit; /**< Address policy for descriptors to
                                  * mark as bad exits. */
  config_line_t *AuthDirReject; /**< Address policy for descriptors to
                                 * reject. */
  config_line_t *AuthDirInvalid; /**< Address policy for descriptors to
                                  * never mark as valid. */
  int AuthDirListBadDirs; /**< True iff we should list bad dirs,
                           * and vote for all other dir mirrors as good. */
  int AuthDirListBadExits; /**< True iff we should list bad exits,
                            * and vote for all other exits as good. */
  int AuthDirRejectUnlisted; /**< Boolean: do we reject all routers that
                              * aren't named in our fingerprint file? */
  int AuthDirMaxServersPerAddr; /**< Do not permit more than this
                                 * number of servers per IP address. */
  int AuthDirMaxServersPerAuthAddr; /**< Do not permit more than this
                                     * number of servers per IP address shared
                                     * with an authority. */

  char *AccountingStart; /**< How long is the accounting interval, and when
                          * does it start? */
  uint64_t AccountingMax; /**< How many bytes do we allow per accounting
                           * interval before hibernation?  0 for "never
                           * hibernate." */

  /** Base64-encoded hash of accepted passwords for the control system. */
  config_line_t *HashedControlPassword;
  /** As HashedControlPassword, but not saved. */
  config_line_t *HashedControlSessionPassword;

  int CookieAuthentication; /**< Boolean: do we enable cookie-based auth for
                             * the control system? */
  char *CookieAuthFile; /**< Location of a cookie authentication file. */
  int CookieAuthFileGroupReadable; /**< Boolean: Is the CookieAuthFile g+r? */
  int LeaveStreamsUnattached; /**< Boolean: Does Tor attach new streams to
                          * circuits itself (0), or does it expect a controller
                          * to cope? (1) */
  int DisablePredictedCircuits; /**< Boolean: does Tor preemptively
                                 * make circuits in the background (0),
                                 * or not (1)? */
  int ShutdownWaitLength; /**< When we get a SIGINT and we're a server, how
                           * long do we wait before exiting? */
  char *SafeLogging; /**< Contains "relay", "1", "0" (meaning no scrubbing). */

  /* Derived from SafeLogging */
  enum {
    SAFELOG_SCRUB_ALL, SAFELOG_SCRUB_RELAY, SAFELOG_SCRUB_NONE
  } _SafeLogging;

  int SafeSocks; /**< Boolean: should we outright refuse application
                  * connections that use socks4 or socks5-with-local-dns? */
#define LOG_PROTOCOL_WARN (get_options()->ProtocolWarnings ? \
                           LOG_WARN : LOG_INFO)
  int ProtocolWarnings; /**< Boolean: when other parties screw up the Tor
                         * protocol, is it a warn or an info in our logs? */
  int TestSocks; /**< Boolean: when we get a socks connection, do we loudly
                  * log whether it was DNS-leaking or not? */
  int HardwareAccel; /**< Boolean: Should we enable OpenSSL hardware
                      * acceleration where available? */
  char *AccelName; /**< Optional hardware acceleration engine name. */
  char *AccelDir; /**< Optional hardware acceleration engine search dir. */
  int UseEntryGuards; /**< Boolean: Do we try to enter from a smallish number
                       * of fixed nodes? */
  int NumEntryGuards; /**< How many entry guards do we try to establish? */
  int RephistTrackTime; /**< How many seconds do we keep rephist info? */
  int FastFirstHopPK; /**< If Tor believes it is safe, should we save a third
                       * of our PK time by sending CREATE_FAST cells? */
  /** Should we always fetch our dir info on the mirror schedule (which
   * means directly from the authorities) no matter our other config? */
  int FetchDirInfoEarly;

  /** Should we fetch our dir info at the start of the consensus period? */
  int FetchDirInfoExtraEarly;

  char *VirtualAddrNetwork; /**< Address and mask to hand out for virtual
                             * MAPADDRESS requests. */
  int ServerDNSSearchDomains; /**< Boolean: If set, we don't force exit
                      * addresses to be FQDNs, but rather search for them in
                      * the local domains. */
  int ServerDNSDetectHijacking; /**< Boolean: If true, check for DNS failure
                                 * hijacking. */
  int ServerDNSRandomizeCase; /**< Boolean: Use the 0x20-hack to prevent
                               * DNS poisoning attacks. */
  char *ServerDNSResolvConfFile; /**< If provided, we configure our internal
                     * resolver from the file here rather than from
                     * /etc/resolv.conf (Unix) or the registry (Windows). */
  char *DirPortFrontPage; /**< This is a full path to a file with an html
                    disclaimer. This allows a server administrator to show
                    that they're running Tor and anyone visiting their server
                    will know this without any specialized knowledge. */
  /** Boolean: if set, we start even if our resolv.conf file is missing
   * or broken. */
  int ServerDNSAllowBrokenConfig;

  smartlist_t *ServerDNSTestAddresses; /**< A list of addresses that definitely
                                        * should be resolvable. Used for
                                        * testing our DNS server. */
  int EnforceDistinctSubnets; /**< If true, don't allow multiple routers in the
                               * same network zone in the same circuit. */
  int TunnelDirConns; /**< If true, use BEGIN_DIR rather than BEGIN when
                       * possible. */
  int PreferTunneledDirConns; /**< If true, avoid dirservers that don't
                               * support BEGIN_DIR, when possible. */
  int PortForwarding; /**< If true, use NAT-PMP or UPnP to automatically
                       * forward the DirPort and ORPort on the NAT device */
  char *PortForwardingHelper; /** < Filename or full path of the port
                                  forwarding helper executable */
  int AllowNonRFC953Hostnames; /**< If true, we allow connections to hostnames
                                * with weird characters. */
  /** If true, we try resolving hostnames with weird characters. */
  int ServerDNSAllowNonRFC953Hostnames;

  /** If true, we try to download extra-info documents (and we serve them,
   * if we are a cache).  For authorities, this is always true. */
  int DownloadExtraInfo;

  /** If true, and we are acting as a relay, allow exit circuits even when
   * we are the first hop of a circuit. */
  int AllowSingleHopExits;
  /** If true, don't allow relays with AllowSingleHopExits=1 to be used in
   * circuits that we build. */
  int ExcludeSingleHopRelays;
  /** If true, and the controller tells us to use a one-hop circuit, and the
   * exit allows it, we use it. */
  int AllowSingleHopCircuits;

  /** If true, we convert "www.google.com.foo.exit" addresses on the
   * socks/trans/natd ports into "www.google.com" addresses that
   * exit from the node "foo". Disabled by default since attacking
   * websites and exit relays can use it to manipulate your path
   * selection. */
  int AllowDotExit;

  /** If true, we will warn if a user gives us only an IP address
   * instead of a hostname. */
  int WarnUnsafeSocks;

  /** If true, the user wants us to collect statistics on clients
   * requesting network statuses from us as directory. */
  int DirReqStatistics;

  /** If true, the user wants us to collect statistics on port usage. */
  int ExitPortStatistics;

  /** If true, the user wants us to collect cell statistics. */
  int CellStatistics;

  /** If true, the user wants us to collect statistics as entry node. */
  int EntryStatistics;

  /** If true, include statistics file contents in extra-info documents. */
  int ExtraInfoStatistics;

  /** If true, do not believe anybody who tells us that a domain resolves
   * to an internal address, or that an internal address has a PTR mapping.
   * Helps avoid some cross-site attacks. */
  int ClientDNSRejectInternalAddresses;

  /** The length of time that we think a consensus should be fresh. */
  int V3AuthVotingInterval;
  /** The length of time we think it will take to distribute votes. */
  int V3AuthVoteDelay;
  /** The length of time we think it will take to distribute signatures. */
  int V3AuthDistDelay;
  /** The number of intervals we think a consensus should be valid. */
  int V3AuthNIntervalsValid;

  /** Should advertise and sign consensuses with a legacy key, for key
   * migration purposes? */
  int V3AuthUseLegacyKey;

  /** Location of bandwidth measurement file */
  char *V3BandwidthsFile;

  /** Authority only: key=value pairs that we add to our networkstatus
   * consensus vote on the 'params' line. */
  char *ConsensusParams;

  /** The length of time that we think an initial consensus should be fresh.
   * Only altered on testing networks. */
  int TestingV3AuthInitialVotingInterval;

  /** The length of time we think it will take to distribute initial votes.
   * Only altered on testing networks. */
  int TestingV3AuthInitialVoteDelay;

  /** The length of time we think it will take to distribute initial
   * signatures.  Only altered on testing networks.*/
  int TestingV3AuthInitialDistDelay;

  /** If an authority has been around for less than this amount of time, it
   * does not believe its reachability information is accurate.  Only
   * altered on testing networks. */
  int TestingAuthDirTimeToLearnReachability;

  /** Clients don't download any descriptor this recent, since it will
   * probably not have propagated to enough caches.  Only altered on testing
   * networks. */
  int TestingEstimatedDescriptorPropagationTime;

  /** If true, we take part in a testing network. Change the defaults of a
   * couple of other configuration options and allow to change the values
   * of certain configuration options. */
  int TestingTorNetwork;

  /** File to check for a consensus networkstatus, if we don't have one
   * cached. */
  char *FallbackNetworkstatusFile;

  /** If true, and we have GeoIP data, and we're a bridge, keep a per-country
   * count of how many client addresses have contacted us so that we can help
   * the bridge authority guess which countries have blocked access to us. */
  int BridgeRecordUsageByCountry;

  /** Optionally, a file with GeoIP data. */
  char *GeoIPFile;

  /** If true, SIGHUP should reload the torrc.  Sometimes controllers want
   * to make this false. */
  int ReloadTorrcOnSIGHUP;

  /* The main parameter for picking circuits within a connection.
   *
   * If this value is positive, when picking a cell to relay on a connection,
   * we always relay from the circuit whose weighted cell count is lowest.
   * Cells are weighted exponentially such that if one cell is sent
   * 'CircuitPriorityHalflife' seconds before another, it counts for half as
   * much.
   *
   * If this value is zero, we're disabling the cell-EWMA algorithm.
   *
   * If this value is negative, we're using the default approach
   * according to either Tor or a parameter set in the consensus.
   */
  double CircuitPriorityHalflife;

  /** If true, do not enable IOCP on windows with bufferevents, even if
   * we think we could. */
  int DisableIOCP;

} or_options_t;

/** Persistent state for an onion router, as saved to disk. */
typedef struct {
  uint32_t _magic;
  /** The time at which we next plan to write the state to the disk.  Equal to
   * TIME_MAX if there are no savable changes, 0 if there are changes that
   * should be saved right away. */
  time_t next_write;

  /** When was the state last written to disk? */
  time_t LastWritten;

  /** Fields for accounting bandwidth use. */
  time_t AccountingIntervalStart;
  uint64_t AccountingBytesReadInInterval;
  uint64_t AccountingBytesWrittenInInterval;
  int AccountingSecondsActive;
  int AccountingSecondsToReachSoftLimit;
  time_t AccountingSoftLimitHitAt;
  uint64_t AccountingBytesAtSoftLimit;
  uint64_t AccountingExpectedUsage;

  /** A list of Entry Guard-related configuration lines. */
  config_line_t *EntryGuards;

  /** These fields hold information on the history of bandwidth usage for
   * servers.  The "Ends" fields hold the time when we last updated the
   * bandwidth usage. The "Interval" fields hold the granularity, in seconds,
   * of the entries of Values.  The "Values" lists hold decimal string
   * representations of the number of bytes read or written in each
   * interval. */
  time_t      BWHistoryReadEnds;
  int         BWHistoryReadInterval;
  smartlist_t *BWHistoryReadValues;
  time_t      BWHistoryWriteEnds;
  int         BWHistoryWriteInterval;
  smartlist_t *BWHistoryWriteValues;
  time_t      BWHistoryDirReadEnds;
  int         BWHistoryDirReadInterval;
  smartlist_t *BWHistoryDirReadValues;
  time_t      BWHistoryDirWriteEnds;
  int         BWHistoryDirWriteInterval;
  smartlist_t *BWHistoryDirWriteValues;

  /** Build time histogram */
  config_line_t * BuildtimeHistogram;
  unsigned int TotalBuildTimes;
  unsigned int CircuitBuildAbandonedCount;

  /** What version of Tor wrote this state file? */
  char *TorVersion;

  /** Holds any unrecognized values we found in the state file, in the order
   * in which we found them. */
  config_line_t *ExtraLines;

  /** When did we last rotate our onion key?  "0" for 'no idea'. */
  time_t LastRotatedOnionKey;
} or_state_t;

/** Change the next_write time of <b>state</b> to <b>when</b>, unless the
 * state is already scheduled to be written to disk earlier than <b>when</b>.
 */
static INLINE void or_state_mark_dirty(or_state_t *state, time_t when)
{
  if (state->next_write > when)
    state->next_write = when;
}

#define MAX_SOCKS_REPLY_LEN 1024
#define MAX_SOCKS_ADDR_LEN 256

/** Please open a TCP connection to this addr:port. */
#define SOCKS_COMMAND_CONNECT       0x01
/** Please turn this FQDN into an IP address, privately. */
#define SOCKS_COMMAND_RESOLVE       0xF0
/** Please turn this IP address into an FQDN, privately. */
#define SOCKS_COMMAND_RESOLVE_PTR   0xF1

#define SOCKS_COMMAND_IS_CONNECT(c) ((c)==SOCKS_COMMAND_CONNECT)
#define SOCKS_COMMAND_IS_RESOLVE(c) ((c)==SOCKS_COMMAND_RESOLVE || \
                                     (c)==SOCKS_COMMAND_RESOLVE_PTR)

/** State of a SOCKS request from a user to an OP.  Also used to encode other
 * information for non-socks user request (such as those on TransPort and
 * DNSPort) */
struct socks_request_t {
  /** Which version of SOCKS did the client use? One of "0, 4, 5" -- where
   * 0 means that no socks handshake ever took place, and this is just a
   * stub connection (e.g. see connection_ap_make_link()). */
  char socks_version;
  int command; /**< What is this stream's goal? One from the above list. */
  size_t replylen; /**< Length of <b>reply</b>. */
  char reply[MAX_SOCKS_REPLY_LEN]; /**< Write an entry into this string if
                                    * we want to specify our own socks reply,
                                    * rather than using the default socks4 or
                                    * socks5 socks reply. We use this for the
                                    * two-stage socks5 handshake.
                                    */
  char address[MAX_SOCKS_ADDR_LEN]; /**< What address did the client ask to
                                       connect to/resolve? */
  uint16_t port; /**< What port did the client ask to connect to? */
  unsigned int has_finished : 1; /**< Has the SOCKS handshake finished? Used to
                              * make sure we send back a socks reply for
                              * every connection. */
};

/********************************* circuitbuild.c **********************/

/** How many hops does a general-purpose circuit have by default? */
#define DEFAULT_ROUTE_LEN 3

/* Circuit Build Timeout "public" structures. */

/** Total size of the circuit timeout history to accumulate.
 * 1000 is approx 2.5 days worth of continual-use circuits. */
#define CBT_NCIRCUITS_TO_OBSERVE 1000

/** Width of the histogram bins in milliseconds */
#define CBT_BIN_WIDTH ((build_time_t)50)

/** Number of modes to use in the weighted-avg computation of Xm */
#define CBT_DEFAULT_NUM_XM_MODES 3

/** A build_time_t is milliseconds */
typedef uint32_t build_time_t;

/**
 * CBT_BUILD_ABANDONED is our flag value to represent a force-closed
 * circuit (Aka a 'right-censored' pareto value).
 */
#define CBT_BUILD_ABANDONED ((build_time_t)(INT32_MAX-1))
#define CBT_BUILD_TIME_MAX ((build_time_t)(INT32_MAX))

/** Save state every 10 circuits */
#define CBT_SAVE_STATE_EVERY 10

/* Circuit build times consensus parameters */

/**
 * How long to wait before actually closing circuits that take too long to
 * build in terms of CDF quantile.
 */
#define CBT_DEFAULT_CLOSE_QUANTILE 95

/**
 * How many circuits count as recent when considering if the
 * connection has gone gimpy or changed.
 */
#define CBT_DEFAULT_RECENT_CIRCUITS 20

/**
 * Maximum count of timeouts that finish the first hop in the past
 * RECENT_CIRCUITS before calculating a new timeout.
 *
 * This tells us whether to abandon timeout history and set
 * the timeout back to whatever circuit_build_times_get_initial_timeout()
 * gives us.
 */
#define CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT (CBT_DEFAULT_RECENT_CIRCUITS*9/10)

/** Minimum circuits before estimating a timeout */
#define CBT_DEFAULT_MIN_CIRCUITS_TO_OBSERVE 100

/** Cutoff percentile on the CDF for our timeout estimation. */
#define CBT_DEFAULT_QUANTILE_CUTOFF 80
double circuit_build_times_quantile_cutoff(void);

/** How often in seconds should we build a test circuit */
#define CBT_DEFAULT_TEST_FREQUENCY 60

/** Lowest allowable value for CircuitBuildTimeout in milliseconds */
#define CBT_DEFAULT_TIMEOUT_MIN_VALUE (1500)

/** Initial circuit build timeout in milliseconds */
#define CBT_DEFAULT_TIMEOUT_INITIAL_VALUE (60*1000)
int32_t circuit_build_times_initial_timeout(void);

#if CBT_DEFAULT_MAX_RECENT_TIMEOUT_COUNT < 1
#error "RECENT_CIRCUITS is set too low."
#endif

/** Information about the state of our local network connection */
typedef struct {
  /** The timestamp we last completed a TLS handshake or received a cell */
  time_t network_last_live;
  /** If the network is not live, how many timeouts has this caused? */
  int nonlive_timeouts;
  /** Circular array of circuits that have made it to the first hop. Slot is
   * 1 if circuit timed out, 0 if circuit succeeded */
  int8_t *timeouts_after_firsthop;
  /** Number of elements allocated for the above array */
  int num_recent_circs;
  /** Index into circular array. */
  int after_firsthop_idx;
} network_liveness_t;

/** Structure for circuit build times history */
typedef struct {
  /** The circular array of recorded build times in milliseconds */
  build_time_t circuit_build_times[CBT_NCIRCUITS_TO_OBSERVE];
  /** Current index in the circuit_build_times circular array */
  int build_times_idx;
  /** Total number of build times accumulated. Max CBT_NCIRCUITS_TO_OBSERVE */
  int total_build_times;
  /** Information about the state of our local network connection */
  network_liveness_t liveness;
  /** Last time we built a circuit. Used to decide to build new test circs */
  time_t last_circ_at;
  /** "Minimum" value of our pareto distribution (actually mode) */
  build_time_t Xm;
  /** alpha exponent for pareto dist. */
  double alpha;
  /** Have we computed a timeout? */
  int have_computed_timeout;
  /** The exact value for that timeout in milliseconds. Stored as a double
   * to maintain precision from calculations to and from quantile value. */
  double timeout_ms;
  /** How long we wait before actually closing the circuit. */
  double close_ms;
} circuit_build_times_t;

/********************************* config.c ***************************/

/** An error from options_trial_assign() or options_init_from_string(). */
typedef enum setopt_err_t {
  SETOPT_OK = 0,
  SETOPT_ERR_MISC = -1,
  SETOPT_ERR_PARSE = -2,
  SETOPT_ERR_TRANSITION = -3,
  SETOPT_ERR_SETTING = -4,
} setopt_err_t;

/********************************* connection_edge.c *************************/

/** Enumerates possible origins of a client-side address mapping. */
typedef enum {
  /** We're remapping this address because the controller told us to. */
  ADDRMAPSRC_CONTROLLER,
  /** We're remapping this address because our configuration (via torrc, the
   * command line, or a SETCONF command) told us to. */
  ADDRMAPSRC_TORRC,
  /** We're remapping this address because we have TrackHostExit configured,
   * and we want to remember to use the same exit next time. */
  ADDRMAPSRC_TRACKEXIT,
  /** We're remapping this address because we got a DNS resolution from a
   * Tor server that told us what its value was. */
  ADDRMAPSRC_DNS,
} addressmap_entry_source_t;

/********************************* control.c ***************************/

/** Used to indicate the type of a circuit event passed to the controller.
 * The various types are defined in control-spec.txt */
typedef enum circuit_status_event_t {
  CIRC_EVENT_LAUNCHED = 0,
  CIRC_EVENT_BUILT    = 1,
  CIRC_EVENT_EXTENDED = 2,
  CIRC_EVENT_FAILED   = 3,
  CIRC_EVENT_CLOSED   = 4,
} circuit_status_event_t;

/** Used to indicate the type of a stream event passed to the controller.
 * The various types are defined in control-spec.txt */
typedef enum stream_status_event_t {
  STREAM_EVENT_SENT_CONNECT = 0,
  STREAM_EVENT_SENT_RESOLVE = 1,
  STREAM_EVENT_SUCCEEDED    = 2,
  STREAM_EVENT_FAILED       = 3,
  STREAM_EVENT_CLOSED       = 4,
  STREAM_EVENT_NEW          = 5,
  STREAM_EVENT_NEW_RESOLVE  = 6,
  STREAM_EVENT_FAILED_RETRIABLE = 7,
  STREAM_EVENT_REMAP        = 8
} stream_status_event_t;

/** Used to indicate the type of an OR connection event passed to the
 * controller.  The various types are defined in control-spec.txt */
typedef enum or_conn_status_event_t {
  OR_CONN_EVENT_LAUNCHED     = 0,
  OR_CONN_EVENT_CONNECTED    = 1,
  OR_CONN_EVENT_FAILED       = 2,
  OR_CONN_EVENT_CLOSED       = 3,
  OR_CONN_EVENT_NEW          = 4,
} or_conn_status_event_t;

/** Used to indicate the type of a buildtime event */
typedef enum buildtimeout_set_event_t {
  BUILDTIMEOUT_SET_EVENT_COMPUTED  = 0,
  BUILDTIMEOUT_SET_EVENT_RESET     = 1,
  BUILDTIMEOUT_SET_EVENT_SUSPENDED = 2,
  BUILDTIMEOUT_SET_EVENT_DISCARD = 3,
  BUILDTIMEOUT_SET_EVENT_RESUME = 4
} buildtimeout_set_event_t;

/** Execute the statement <b>stmt</b>, which may log events concerning the
 * connection <b>conn</b>.  To prevent infinite loops, disable log messages
 * being sent to controllers if <b>conn</b> is a control connection.
 *
 * Stmt must not contain any return or goto statements.
 */
#define CONN_LOG_PROTECT(conn, stmt)                                    \
  STMT_BEGIN                                                            \
    int _log_conn_is_control = (conn && conn->type == CONN_TYPE_CONTROL); \
    if (_log_conn_is_control)                                           \
      disable_control_logging();                                        \
  STMT_BEGIN stmt; STMT_END;                                            \
    if (_log_conn_is_control)                                           \
      enable_control_logging();                                         \
  STMT_END

/** Enum describing various stages of bootstrapping, for use with controller
 * bootstrap status events. The values range from 0 to 100. */
typedef enum {
  BOOTSTRAP_STATUS_UNDEF=-1,
  BOOTSTRAP_STATUS_STARTING=0,
  BOOTSTRAP_STATUS_CONN_DIR=5,
  BOOTSTRAP_STATUS_HANDSHAKE=-2,
  BOOTSTRAP_STATUS_HANDSHAKE_DIR=10,
  BOOTSTRAP_STATUS_ONEHOP_CREATE=15,
  BOOTSTRAP_STATUS_REQUESTING_STATUS=20,
  BOOTSTRAP_STATUS_LOADING_STATUS=25,
  BOOTSTRAP_STATUS_LOADING_KEYS=40,
  BOOTSTRAP_STATUS_REQUESTING_DESCRIPTORS=45,
  BOOTSTRAP_STATUS_LOADING_DESCRIPTORS=50,
  BOOTSTRAP_STATUS_CONN_OR=80,
  BOOTSTRAP_STATUS_HANDSHAKE_OR=85,
  BOOTSTRAP_STATUS_CIRCUIT_CREATE=90,
  BOOTSTRAP_STATUS_DONE=100
} bootstrap_status_t;

/********************************* directory.c ***************************/

/** A pair of digests created by dir_split_resource_info_fingerprint_pairs() */
typedef struct {
  char first[DIGEST_LEN];
  char second[DIGEST_LEN];
} fp_pair_t;

/********************************* dirserv.c ***************************/
typedef enum {
  NS_V2, NS_V3_CONSENSUS, NS_V3_VOTE, NS_CONTROL_PORT,
  NS_V3_CONSENSUS_MICRODESC
} routerstatus_format_type_t;

#ifdef DIRSERV_PRIVATE
typedef struct measured_bw_line_t {
  char node_id[DIGEST_LEN];
  char node_hex[MAX_HEX_NICKNAME_LEN+1];
  long int bw;
} measured_bw_line_t;

#endif

/********************************* dirvote.c ************************/

/** Describes the schedule by which votes should be generated. */
typedef struct vote_timing_t {
  int vote_interval;
  int n_intervals_valid;
  int vote_delay;
  int dist_delay;
} vote_timing_t;

/********************************* geoip.c **************************/

/** Round all GeoIP results to the next multiple of this value, to avoid
 * leaking information. */
#define DIR_RECORD_USAGE_GRANULARITY 8
/** Time interval: Flush geoip data to disk this often. */
#define DIR_ENTRY_RECORD_USAGE_RETAIN_IPS (24*60*60)
/** How long do we have to have observed per-country request history before
 * we are willing to talk about it? */
#define DIR_RECORD_USAGE_MIN_OBSERVATION_TIME (12*60*60)

/** Indicates an action that we might be noting geoip statistics on.
 * Note that if we're noticing CONNECT, we're a bridge, and if we're noticing
 * the others, we're not.
 */
typedef enum {
  /** We've noticed a connection as a bridge relay or entry guard. */
  GEOIP_CLIENT_CONNECT = 0,
  /** We've served a networkstatus consensus as a directory server. */
  GEOIP_CLIENT_NETWORKSTATUS = 1,
  /** We've served a v2 networkstatus consensus as a directory server. */
  GEOIP_CLIENT_NETWORKSTATUS_V2 = 2,
} geoip_client_action_t;
/** Indicates either a positive reply or a reason for rejectng a network
 * status request that will be included in geoip statistics. */
typedef enum {
  /** Request is answered successfully. */
  GEOIP_SUCCESS = 0,
  /** V3 network status is not signed by a sufficient number of requested
   * authorities. */
  GEOIP_REJECT_NOT_ENOUGH_SIGS = 1,
  /** Requested network status object is unavailable. */
  GEOIP_REJECT_UNAVAILABLE = 2,
  /** Requested network status not found. */
  GEOIP_REJECT_NOT_FOUND = 3,
  /** Network status has not been modified since If-Modified-Since time. */
  GEOIP_REJECT_NOT_MODIFIED = 4,
  /** Directory is busy. */
  GEOIP_REJECT_BUSY = 5,
} geoip_ns_response_t;
#define GEOIP_NS_RESPONSE_NUM 6

/** Directory requests that we are measuring can be either direct or
 * tunneled. */
typedef enum {
  DIRREQ_DIRECT = 0,
  DIRREQ_TUNNELED = 1,
} dirreq_type_t;

/** Possible states for either direct or tunneled directory requests that
 * are relevant for determining network status download times. */
typedef enum {
  /** Found that the client requests a network status; applies to both
   * direct and tunneled requests; initial state of a request that we are
   * measuring. */
  DIRREQ_IS_FOR_NETWORK_STATUS = 0,
  /** Finished writing a network status to the directory connection;
   * applies to both direct and tunneled requests; completes a direct
   * request. */
  DIRREQ_FLUSHING_DIR_CONN_FINISHED = 1,
  /** END cell sent to circuit that initiated a tunneled request. */
  DIRREQ_END_CELL_SENT = 2,
  /** Flushed last cell from queue of the circuit that initiated a
    * tunneled request to the outbuf of the OR connection. */
  DIRREQ_CIRC_QUEUE_FLUSHED = 3,
  /** Flushed last byte from buffer of the OR connection belonging to the
    * circuit that initiated a tunneled request; completes a tunneled
    * request. */
  DIRREQ_OR_CONN_BUFFER_FLUSHED = 4
} dirreq_state_t;

#define WRITE_STATS_INTERVAL (24*60*60)

/********************************* microdesc.c *************************/

typedef struct microdesc_cache_t microdesc_cache_t;

/********************************* networkstatus.c *********************/

/** Location where we found a v2 networkstatus. */
typedef enum {
  NS_FROM_CACHE, NS_FROM_DIR_BY_FP, NS_FROM_DIR_ALL, NS_GENERATED
} v2_networkstatus_source_t;

/** Possible statuses of a version of Tor, given opinions from the directory
 * servers. */
typedef enum version_status_t {
  VS_RECOMMENDED=0, /**< This version is listed as recommended. */
  VS_OLD=1, /**< This version is older than any recommended version. */
  VS_NEW=2, /**< This version is newer than any recommended version. */
  VS_NEW_IN_SERIES=3, /**< This version is newer than any recommended version
                       * in its series, but later recommended versions exist.
                       */
  VS_UNRECOMMENDED=4, /**< This version is not recommended (general case). */
  VS_EMPTY=5, /**< The version list was empty; no agreed-on versions. */
  VS_UNKNOWN, /**< We have no idea. */
} version_status_t;

/********************************* policies.c ************************/

/** Outcome of applying an address policy to an address. */
typedef enum {
  /** The address was accepted */
  ADDR_POLICY_ACCEPTED=0,
  /** The address was rejected */
  ADDR_POLICY_REJECTED=-1,
  /** Part of the address was unknown, but as far as we can tell, it was
   * accepted. */
  ADDR_POLICY_PROBABLY_ACCEPTED=1,
  /** Part of the address was unknown, but as far as we can tell, it was
   * rejected. */
  ADDR_POLICY_PROBABLY_REJECTED=2,
} addr_policy_result_t;

/********************************* rephist.c ***************************/

/** Possible public/private key operations in Tor: used to keep track of where
 * we're spending our time. */
typedef enum {
  SIGN_DIR, SIGN_RTR,
  VERIFY_DIR, VERIFY_RTR,
  ENC_ONIONSKIN, DEC_ONIONSKIN,
  TLS_HANDSHAKE_C, TLS_HANDSHAKE_S,
  REND_CLIENT, REND_MID, REND_SERVER,
} pk_op_t;

/********************************* rendcommon.c ***************************/

/** Hidden-service side configuration of client authorization. */
typedef struct rend_authorized_client_t {
  char *client_name;
  char descriptor_cookie[REND_DESC_COOKIE_LEN];
  crypto_pk_env_t *client_key;
} rend_authorized_client_t;

/** ASCII-encoded v2 hidden service descriptor. */
typedef struct rend_encoded_v2_service_descriptor_t {
  char desc_id[DIGEST_LEN]; /**< Descriptor ID. */
  char *desc_str; /**< Descriptor string. */
} rend_encoded_v2_service_descriptor_t;

/** Introduction point information. */
typedef struct rend_intro_point_t {
  extend_info_t *extend_info; /**< Extend info of this introduction point. */
  crypto_pk_env_t *intro_key; /**< Introduction key that replaces the service
                               * key, if this descriptor is V2. */
} rend_intro_point_t;

/** Information used to connect to a hidden service. */
typedef struct rend_service_descriptor_t {
  crypto_pk_env_t *pk; /**< This service's public key. */
  int version; /**< Version of the descriptor format: 0 or 2. */
  time_t timestamp; /**< Time when the descriptor was generated. */
  uint16_t protocols; /**< Bitmask: which rendezvous protocols are supported?
                       * (We allow bits '0', '1', and '2' to be set.) */
  /** List of the service's introduction points.  Elements are removed if
   * introduction attempts fail. */
  smartlist_t *intro_nodes;
  /** Has descriptor been uploaded to all hidden service directories? */
  int all_uploads_performed;
  /** List of hidden service directories to which an upload request for
   * this descriptor could be sent. Smartlist exists only when at least one
   * of the previous upload requests failed (otherwise it's not important
   * to know which uploads succeeded and which not). */
  smartlist_t *successful_uploads;
} rend_service_descriptor_t;

/** A cached rendezvous descriptor. */
typedef struct rend_cache_entry_t {
  size_t len; /**< Length of <b>desc</b> */
  time_t received; /**< When was the descriptor received? */
  char *desc; /**< Service descriptor */
  rend_service_descriptor_t *parsed; /**< Parsed value of 'desc' */
} rend_cache_entry_t;

/********************************* routerlist.c ***************************/

/** Represents information about a single trusted directory server. */
typedef struct trusted_dir_server_t {
  char *description;
  char *nickname;
  char *address; /**< Hostname. */
  uint32_t addr; /**< IPv4 address. */
  uint16_t dir_port; /**< Directory port. */
  uint16_t or_port; /**< OR port: Used for tunneling connections. */
  char digest[DIGEST_LEN]; /**< Digest of identity key. */
  char v3_identity_digest[DIGEST_LEN]; /**< Digest of v3 (authority only,
                                        * high-security) identity key. */

  unsigned int is_running:1; /**< True iff we think this server is running. */

  /** True iff this server has accepted the most recent server descriptor
   * we tried to upload to it. */
  unsigned int has_accepted_serverdesc:1;

  /** What kind of authority is this? (Bitfield.) */
  authority_type_t type;

  download_status_t v2_ns_dl_status; /**< Status of downloading this server's
                               * v2 network status. */
  time_t addr_current_at; /**< When was the document that we derived the
                           * address information from published? */

  routerstatus_t fake_status; /**< Used when we need to pass this trusted
                               * dir_server_t to directory_initiate_command_*
                               * as a routerstatus_t.  Not updated by the
                               * router-status management code!
                               **/
} trusted_dir_server_t;

#define ROUTER_REQUIRED_MIN_BANDWIDTH (20*1024)

#define ROUTER_MAX_DECLARED_BANDWIDTH INT32_MAX

/* Flags for pick_directory_server and pick_trusteddirserver. */
/** Flag to indicate that we should not automatically be willing to use
 * ourself to answer a directory request.
 * Passed to router_pick_directory_server (et al).*/
#define PDS_ALLOW_SELF                 (1<<0)
/** Flag to indicate that if no servers seem to be up, we should mark all
 * directory servers as up and try again.
 * Passed to router_pick_directory_server (et al).*/
#define PDS_RETRY_IF_NO_SERVERS        (1<<1)
/** Flag to indicate that we should not exclude directory servers that
 * our ReachableAddress settings would exclude.  This usually means that
 * we're going to connect to the server over Tor, and so we don't need to
 * worry about our firewall telling us we can't.
 * Passed to router_pick_directory_server (et al).*/
#define PDS_IGNORE_FASCISTFIREWALL     (1<<2)
/** Flag to indicate that we should not use any directory authority to which
 * we have an existing directory connection for downloading server descriptors
 * or extrainfo documents.
 *
 * Passed to router_pick_directory_server (et al)
 *
 * [XXXX NOTE: This option is only implemented for pick_trusteddirserver,
 *  not pick_directory_server.  If we make it work on pick_directory_server
 *  too, we could conservatively make it only prevent multiple fetches to
 *  the same authority, or we could aggressively make it prevent multiple
 *  fetches to _any_ single directory server.]
 */
#define PDS_NO_EXISTING_SERVERDESC_FETCH (1<<3)
#define PDS_NO_EXISTING_MICRODESC_FETCH (1<<4)

#define _PDS_PREFER_TUNNELED_DIR_CONNS (1<<16)

/** Possible ways to weight routers when choosing one randomly.  See
 * routerlist_sl_choose_by_bandwidth() for more information.*/
typedef enum bandwidth_weight_rule_t {
  NO_WEIGHTING, WEIGHT_FOR_EXIT, WEIGHT_FOR_MID, WEIGHT_FOR_GUARD,
  WEIGHT_FOR_DIR
} bandwidth_weight_rule_t;

/** Flags to be passed to control router_choose_random_node() to indicate what
 * kind of nodes to pick according to what algorithm. */
typedef enum {
  CRN_NEED_UPTIME = 1<<0,
  CRN_NEED_CAPACITY = 1<<1,
  CRN_NEED_GUARD = 1<<2,
  CRN_ALLOW_INVALID = 1<<3,
  /* XXXX not used, apparently. */
  CRN_WEIGHT_AS_EXIT = 1<<5,
  CRN_NEED_DESC = 1<<6
} router_crn_flags_t;

/** Return value for router_add_to_routerlist() and dirserv_add_descriptor() */
typedef enum was_router_added_t {
  ROUTER_ADDED_SUCCESSFULLY = 1,
  ROUTER_ADDED_NOTIFY_GENERATOR = 0,
  ROUTER_BAD_EI = -1,
  ROUTER_WAS_NOT_NEW = -2,
  ROUTER_NOT_IN_CONSENSUS = -3,
  ROUTER_NOT_IN_CONSENSUS_OR_NETWORKSTATUS = -4,
  ROUTER_AUTHDIR_REJECTS = -5,
} was_router_added_t;

/********************************* routerparse.c ************************/

#define MAX_STATUS_TAG_LEN 32
/** Structure to hold parsed Tor versions.  This is a little messier
 * than we would like it to be, because we changed version schemes with 0.1.0.
 *
 * See version-spec.txt for the whole business.
 */
typedef struct tor_version_t {
  int major;
  int minor;
  int micro;
  /** Release status.  For version in the post-0.1 format, this is always
   * VER_RELEASE. */
  enum { VER_PRE=0, VER_RC=1, VER_RELEASE=2, } status;
  int patchlevel;
  char status_tag[MAX_STATUS_TAG_LEN];
  int svn_revision;

  int git_tag_len;
  char git_tag[DIGEST_LEN];
} tor_version_t;

#endif

