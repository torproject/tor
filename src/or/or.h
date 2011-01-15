/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
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
#ifndef ENABLE_GEOIP_STATS
#define ENABLE_GEOIP_STATS 1
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

#include "crypto.h"
#include "tortls.h"
#include "log.h"
#include "compat.h"
#include "container.h"
#include "util.h"
#include "torgzip.h"
#include "address.h"

#include <event.h>

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
#define MIN_DNS_TTL (60)

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
/** State for a connection to an OR: waiting for proxy command to flush. */
#define OR_CONN_STATE_PROXY_FLUSHING 2
/** State for a connection to an OR: waiting for proxy response. */
#define OR_CONN_STATE_PROXY_READING 3
/** State for a connection to an OR or client: SSL is handshaking, not done
 * yet. */
#define OR_CONN_STATE_TLS_HANDSHAKING 4
/** State for a connection to an OR: We're doing a second SSL handshake for
 * renegotiation purposes. */
#define OR_CONN_STATE_TLS_CLIENT_RENEGOTIATING 5
/** State for a connection at an OR: We're waiting for the client to
 * renegotiate. */
#define OR_CONN_STATE_TLS_SERVER_RENEGOTIATING 6
/** State for a connection to an OR: We're done with our SSL handshake, but we
 * haven't yet negotiated link protocol versions and sent a netinfo cell.
 */
#define OR_CONN_STATE_OR_HANDSHAKING 7
/** State for a connection to an OR: Ready to send/receive cells. */
#define OR_CONN_STATE_OPEN 8
#define _OR_CONN_STATE_MAX 8

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
#define _DIR_PURPOSE_MAX 18

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

#define _CIRCUIT_PURPOSE_C_MAX 12

/** Hidden-service-side circuit purpose: at Bob, waiting for introductions. */
#define CIRCUIT_PURPOSE_S_ESTABLISH_INTRO 13
/** Hidden-service-side circuit purpose: at Bob, successfully established
 * intro. */
#define CIRCUIT_PURPOSE_S_INTRO 14
/** Hidden-service-side circuit purpose: at Bob, connecting to rend point. */
#define CIRCUIT_PURPOSE_S_CONNECT_REND 15
/** Hidden-service-side circuit purpose: at Bob, rendezvous established. */
#define CIRCUIT_PURPOSE_S_REND_JOINED 16
/** A testing circuit; not meant to be used for actual traffic. */
#define CIRCUIT_PURPOSE_TESTING 17
/** A controller made this circuit and Tor should not use it. */
#define CIRCUIT_PURPOSE_CONTROLLER 18
#define _CIRCUIT_PURPOSE_MAX 18
/** A catch-all for unrecognized purposes. Currently we don't expect
 * to make or see any circuits with this purpose. */
#define CIRCUIT_PURPOSE_UNKNOWN 255

/** True iff the circuit purpose <b>p</b> is for a circuit that
 * originated at this node. */
#define CIRCUIT_PURPOSE_IS_ORIGIN(p) ((p)>_CIRCUIT_PURPOSE_OR_MAX)
/** True iff the circuit purpose <b>p</b> is for a circuit that originated
 * here to serve as a client.  (Hidden services don't count here.) */
#define CIRCUIT_PURPOSE_IS_CLIENT(p) \
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

/** How long after we receive a hidden service descriptor do we consider
 * it fresh? */
#define NUM_SECONDS_BEFORE_HS_REFETCH (60*15)

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

  /** Rendezvous descriptor version that is used by a service. Used to
   * distinguish introduction and rendezvous points belonging to the same
   * rendezvous service ID, but different descriptor versions.
   */
  uint8_t rend_desc_version;
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
  uint8_t payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
} cell_t;

/** Parsed variable-length onion routing cell. */
typedef struct var_cell_t {
  uint8_t command;
  circid_t circ_id;
  uint16_t payload_len;
  uint8_t payload[1];
} var_cell_t;

/** A cell as packed for writing to the network. */
typedef struct packed_cell_t {
  struct packed_cell_t *next; /**< Next cell queued on this circuit. */
  char body[CELL_NETWORK_SIZE]; /**< Cell as packed for network. */
} packed_cell_t;

/** A queue of cells on a circuit, waiting to be added to the
 * or_connection_t's outbuf. */
typedef struct cell_queue_t {
  packed_cell_t *head; /**< The first cell, or NULL if the queue is empty. */
  packed_cell_t *tail; /**< The last cell, or NULL if the queue is empty. */
  int n; /**< The number of cells in the queue. */
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
                             * reads? */
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

  int s; /**< Our socket; -1 if this connection is closed, or has no
          * socket. */
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
   * because the connection is too old, or because there's a better one, etc.
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

  /* bandwidth* and read_bucket only used by ORs in OPEN state: */
  int bandwidthrate; /**< Bytes/s added to the bucket. (OPEN ORs only.) */
  int bandwidthburst; /**< Max bucket size for this conn. (OPEN ORs only.) */
  int read_bucket; /**< When this hits 0, stop receiving. Every second we
                    * add 'bandwidthrate' to this, capping it at
                    * bandwidthburst. (OPEN ORs only) */
  int n_circuits; /**< How many circuits use this connection as p_conn or
                   * n_conn ? */

  /** Double-linked ring of circuits with queued cells waiting for room to
   * free up on this connection's outbuf.  Every time we pull cells from a
   * circuit, we advance this pointer to the next circuit in the ring. */
  struct circuit_t *active_circuits;
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

  char *requested_resource; /**< Which 'resource' did we ask the directory
                             * for? */
  unsigned int dirconn_direct:1; /**< Is this dirconn direct, or via Tor? */

  /* Used only for server sides of some dir connections, to implement
   * "spooling" of directory material to the outbuf.  Otherwise, we'd have
   * to append everything to the outbuf in one enormous chunk. */
  /** What exactly are we spooling right now? */
  enum {
    DIR_SPOOL_NONE=0, DIR_SPOOL_SERVER_BY_DIGEST, DIR_SPOOL_SERVER_BY_FP,
    DIR_SPOOL_EXTRA_BY_DIGEST, DIR_SPOOL_EXTRA_BY_FP,
    DIR_SPOOL_CACHED_DIR, DIR_SPOOL_NETWORKSTATUS
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
  unsigned int use_long_names:1; /**< True if we should use long nicknames
                                  * on this (v1) connection. Only settable
                                  * via v1 controllers. */
  /** For control connections only. If set, we send extended info with control
   * events as appropriate. */
  unsigned int use_extended_events:1;

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
  unsigned int has_old_dnsworkers:1; /**< Whether the router is using
                                      * dnsworker code. */
  unsigned int caches_extra_info:1; /**< Whether the router caches and serves
                                     * extrainfo documents. */
  unsigned int allow_single_hop_exits:1;  /**< Whether the router allows
                                     * single hop exits. */

  /* local info */
  unsigned int is_running:1; /**< As far as we know, is this OR currently
                              * running? */
  unsigned int is_valid:1; /**< Has a trusted dirserver validated this OR?
                               *  (For Authdir: Have we validated this OR?)
                               */
  unsigned int is_named:1; /**< Do we believe the nickname that this OR gives
                            * us? */
  unsigned int is_fast:1; /** Do we think this is a fast OR? */
  unsigned int is_stable:1; /** Do we think this is a stable OR? */
  unsigned int is_possible_guard:1; /**< Do we think this is an OK guard? */
  unsigned int is_exit:1; /**< Do we think this is an OK exit? */
  unsigned int is_bad_exit:1; /**< Do we think this exit is censored, borked,
                               * or otherwise nasty? */
  unsigned int is_bad_directory:1; /**< Do we think this directory is junky,
                                    * underpowered, or otherwise useless? */
  unsigned int wants_to_be_hs_dir:1; /**< True iff this router claims to be
                                      * a hidden service directory. */
  unsigned int is_hs_dir:1; /**< True iff this router is a hidden service
                             * directory according to the authorities. */
  unsigned int policy_is_reject_star:1; /**< True iff the exit policy for this
                                         * router rejects everything. */

/** Tor can use this router for general positions in circuits. */
#define ROUTER_PURPOSE_GENERAL 0
/** Tor should avoid using this router for circuit-building. */
#define ROUTER_PURPOSE_CONTROLLER 1
/** Tor should use this router only for bridge positions in circuits. */
#define ROUTER_PURPOSE_BRIDGE 2
/** Tor should not use this router; it was marked in cached-descriptors with
 * a purpose we didn't recognize. */
#define ROUTER_PURPOSE_UNKNOWN 255

  uint8_t purpose; /** What positions in a circuit is this router good for? */

  /* The below items are used only by authdirservers for
   * reachability testing. */
  /** When was the last time we could reach this OR? */
  time_t last_reachable;
  /** When did we start testing reachability for this OR? */
  time_t testing_since;
  /** According to the geoip db what country is this router in? */
  country_t country;
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
  char descriptor_digest[DIGEST_LEN]; /**< Digest of the router's most recent
                                       * descriptor. */
  uint32_t addr; /**< IPv4 address for this router. */
  uint16_t or_port; /**< OR port for this router. */
  uint16_t dir_port; /**< Directory port for this router. */
  unsigned int is_authority:1; /**< True iff this router is an authority. */
  unsigned int is_exit:1; /**< True iff this router is a good exit. */
  unsigned int is_stable:1; /**< True iff this router stays up a long time. */
  unsigned int is_fast:1; /**< True iff this router has good bandwidth. */
  unsigned int is_running:1; /**< True iff this router is up. */
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
  unsigned int name_lookup_warned:1; /**< Have we warned the user for referring
                                      * to this (unnamed) router by nickname?
                                      */
  time_t last_dir_503_at; /**< When did this router last tell us that it
                           * was too busy to serve directory info? */
  download_status_t dl_status;

} routerstatus_t;

/** How many times will we try to download a router's descriptor before giving
 * up? */
#define MAX_ROUTERDESC_DOWNLOAD_FAILURES 8

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

/** The claim about a single router, made in a vote. */
typedef struct vote_routerstatus_t {
  routerstatus_t status; /**< Underlying 'status' object for this router.
                          * Flags are redundant. */
  uint64_t flags; /**< Bit-field for all recognized flags; index into
                   * networkstatus_t.known_flags. */
  char *version; /**< The version that the authority says this router is
                  * running. */
} vote_routerstatus_t;

/** Information about a single voter in a vote or a consensus. */
typedef struct networkstatus_voter_info_t {
  char *nickname; /**< Nickname of this voter */
  char identity_digest[DIGEST_LEN]; /**< Digest of this voter's identity key */
  char *address; /**< Address of this voter, in string format. */
  uint32_t addr; /**< Address of this voter, in IPv4, in host order. */
  uint16_t dir_port; /**< Directory port of this voter */
  uint16_t or_port; /**< OR port of this voter */
  char *contact; /**< Contact information for this voter. */
  char vote_digest[DIGEST_LEN]; /**< Digest of this voter's vote, as signed. */
  /** Digest of this voter's "legacy" identity key, if any.  In vote only; for
   * consensuses, we treat legacy keys as additional signers. */
  char legacy_id_digest[DIGEST_LEN];

  /* Nothing from here on is signed. */
  char signing_key_digest[DIGEST_LEN]; /**< Declared digest of signing key
                                        * used by this voter. */
  char *signature; /**< Signature from this voter. */
  int signature_len; /**< Length of <b>signature</b> */
  unsigned int bad_signature : 1; /**< Set to true if we've tried to verify
                                   * the sig, and we know it's bad. */
  unsigned int good_signature : 1; /**< Set to true if we've verified the sig
                                     * as good. */
} networkstatus_voter_info_t;

/** Enumerates the possible seriousness values of a networkstatus document. */
typedef enum {
  NS_TYPE_VOTE,
  NS_TYPE_CONSENSUS,
  NS_TYPE_OPINION,
} networkstatus_type_t;

/** A common structure to hold a v3 network status vote, or a v3 network
 * status consensus. */
typedef struct networkstatus_t {
  networkstatus_type_t type; /**< Vote, consensus, or opinion? */
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

  /** List of networkstatus_voter_info_t.  For a vote, only one element
   * is included.  For a consensus, one element is included for every voter
   * whose vote contributed to the consensus. */
  smartlist_t *voters;

  struct authority_cert_t *cert; /**< Vote only: the voter's certificate. */

  /** Digest of this document, as signed. */
  char networkstatus_digest[DIGEST_LEN];

  /** List of router statuses, sorted by identity digest.  For a vote,
   * the elements are vote_routerstatus_t; for a consensus, the elements
   * are routerstatus_t. */
  smartlist_t *routerstatus_list;

  /** If present, a map from descriptor digest to elements of
   * routerstatus_list. */
  digestmap_t *desc_digest_map;
} networkstatus_t;

/** A set of signatures for a networkstatus consensus.  All fields are as for
 * networkstatus_t. */
typedef struct ns_detached_signatures_t {
  time_t valid_after;
  time_t fresh_until;
  time_t valid_until;
  char networkstatus_digest[DIGEST_LEN];
  smartlist_t *signatures; /* list of networkstatus_voter_info_t */
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
  uint8_t fast_handshake_state[DIGEST_LEN];
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

  time_t timestamp_created; /**< When was this circuit created? */
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
  int StrictExitNodes; /**< Boolean: When none of our ExitNodes are up, do we
                        * stop building circuits? */
  int StrictEntryNodes; /**< Boolean: When none of our EntryNodes are up, do we
                         * stop building circuits? */
  routerset_t *ExcludeNodes;/**< Structure containing nicknames, digests,
                             * country codes and IP address patterns of ORs
                             * not to use in circuits. */
  routerset_t *ExcludeExitNodes;/**< Structure containing nicknames, digests,
                                 * country codes and IP address patterns of
                                 * ORs not to consider as exits. */

  /** Union of ExcludeNodes and ExcludeExitNodes */
  struct routerset_t *_ExcludeExitNodesUnion;

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
  int HSAuthorityRecordStats; /**< Boolean: does this HS authoritative
                               * directory record statistics? */
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
  int CircuitBuildTimeout; /**< Cull non-open circuits that were born
                            * at least this many seconds ago. */
  int CircuitIdleTimeout; /**< Cull open clean circuits that were born
                           * at least this many seconds ago. */
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
  int NumCpus; /**< How many CPUs should we try to use? */
  int RunTesting; /**< If true, create testing circuits to measure how well the
                   * other ORs are running. */
  config_line_t *RendConfigLines; /**< List of configuration lines
                                          * for rendezvous services. */
  config_line_t *HidServAuth; /**< List of configuration lines for client-side
                               * authorizations for hidden services */
  char *ContactInfo; /**< Contact info to be published in the directory. */

  char *HttpProxy; /**< hostname[:port] to use as http proxy, if any. */
  uint32_t HttpProxyAddr; /**< Parsed IPv4 addr for http proxy, if any. */
  uint16_t HttpProxyPort; /**< Parsed port for http proxy, if any. */
  char *HttpProxyAuthenticator; /**< username:password string, if any. */

  char *HttpsProxy; /**< hostname[:port] to use as https proxy, if any. */
  uint32_t HttpsProxyAddr; /**< Parsed IPv4 addr for https proxy, if any. */
  uint16_t HttpsProxyPort; /**< Parsed port for https proxy, if any. */
  char *HttpsProxyAuthenticator; /**< username:password string, if any. */

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
  int SafeLogging; /**< Boolean: are we allowed to log sensitive strings
                    * such as addresses (0), or do we scrub them first (1)? */
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
  int UseEntryGuards; /**< Boolean: Do we try to enter from a smallish number
                       * of fixed nodes? */
  int NumEntryGuards; /**< How many entry guards do we try to establish? */
  int RephistTrackTime; /**< How many seconds do we keep rephist info? */
  int FastFirstHopPK; /**< If Tor believes it is safe, should we save a third
                       * of our PK time by sending CREATE_FAST cells? */
  /** Should we always fetch our dir info on the mirror schedule (which
   * means directly from the authorities) no matter our other config? */
  int FetchDirInfoEarly;

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

#ifdef ENABLE_GEOIP_STATS
  /** If true, and Tor is built with GEOIP_STATS support, and we're a
   * directory, record how many directory requests we get from each country. */
  int DirRecordUsageByCountry;
  /** Round all GeoIP results to the next multiple of this value, to avoid
   * leaking information. */
  int DirRecordUsageGranularity;
  /** Time interval: purge geoip stats after this long. */
  int DirRecordUsageRetainIPs;
  /** Time interval: Flush geoip data to disk this often. */
  int DirRecordUsageSaveInterval;
#endif

  /** Optionally, a file with GeoIP data. */
  char *GeoIPFile;

  /** If true, SIGHUP should reload the torrc.  Sometimes controllers want
   * to make this false. */
  int ReloadTorrcOnSIGHUP;

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

/* all the function prototypes go here */

/********************************* buffers.c ***************************/

buf_t *buf_new(void);
buf_t *buf_new_with_capacity(size_t size);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);
void buf_shrink(buf_t *buf);
void buf_shrink_freelists(int free_all);
void buf_dump_freelist_sizes(int severity);

size_t buf_datalen(const buf_t *buf);
size_t buf_allocation(const buf_t *buf);
size_t buf_slack(const buf_t *buf);
const char *_buf_peek_raw_buffer(const buf_t *buf);

int read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof,
                int *socket_error);
int read_to_buf_tls(tor_tls_t *tls, size_t at_most, buf_t *buf);

int flush_buf(int s, buf_t *buf, size_t sz, size_t *buf_flushlen);
int flush_buf_tls(tor_tls_t *tls, buf_t *buf, size_t sz, size_t *buf_flushlen);

int write_to_buf(const char *string, size_t string_len, buf_t *buf);
int write_to_buf_zlib(buf_t *buf, tor_zlib_state_t *state,
                      const char *data, size_t data_len, int done);
int move_buf_to_buf(buf_t *buf_out, buf_t *buf_in, size_t *buf_flushlen);
int fetch_from_buf(char *string, size_t string_len, buf_t *buf);
int fetch_var_cell_from_buf(buf_t *buf, var_cell_t **out, int linkproto);
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, size_t max_headerlen,
                        char **body_out, size_t *body_used, size_t max_bodylen,
                        int force_complete);
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req,
                         int log_sockstype, int safe_socks);
int fetch_from_buf_line(buf_t *buf, char *data_out, size_t *data_len);

int peek_buf_has_control0_command(buf_t *buf);

void assert_buf_ok(buf_t *buf);

#ifdef BUFFERS_PRIVATE
int buf_find_string_offset(const buf_t *buf, const char *s, size_t n);
#endif

/********************************* circuitbuild.c **********************/

char *circuit_list_path(origin_circuit_t *circ, int verbose);
char *circuit_list_path_for_controller(origin_circuit_t *circ);
void circuit_log_path(int severity, unsigned int domain,
                      origin_circuit_t *circ);
void circuit_rep_hist_note_result(origin_circuit_t *circ);
origin_circuit_t *origin_circuit_init(uint8_t purpose, int flags);
origin_circuit_t *circuit_establish_circuit(uint8_t purpose,
                                            extend_info_t *exit,
                                            int flags);
int circuit_handle_first_hop(origin_circuit_t *circ);
void circuit_n_conn_done(or_connection_t *or_conn, int status);
int inform_testing_reachability(void);
int circuit_send_next_onion_skin(origin_circuit_t *circ);
void circuit_note_clock_jumped(int seconds_elapsed);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_init_cpath_crypto(crypt_path_t *cpath, const char *key_data,
                              int reverse);
int circuit_finish_handshake(origin_circuit_t *circ, uint8_t cell_type,
                             const uint8_t *reply);
int circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer);
int onionskin_answer(or_circuit_t *circ, uint8_t cell_type,
                     const char *payload, const char *keys);
int circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                        int *need_capacity);

int circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *info);
int circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *info);
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);
extend_info_t *extend_info_alloc(const char *nickname, const char *digest,
                                 crypto_pk_env_t *onion_key,
                                 const tor_addr_t *addr, uint16_t port);
extend_info_t *extend_info_from_router(routerinfo_t *r);
extend_info_t *extend_info_dup(extend_info_t *info);
void extend_info_free(extend_info_t *info);
routerinfo_t *build_state_get_exit_router(cpath_build_state_t *state);
const char *build_state_get_exit_nickname(cpath_build_state_t *state);

void entry_guards_compute_status(void);
int entry_guard_register_connect_status(const char *digest, int succeeded,
                                        int mark_relay_status, time_t now);
void entry_nodes_should_be_added(void);
int entry_list_can_grow(or_options_t *options);
routerinfo_t *choose_random_entry(cpath_build_state_t *state);
int entry_guards_parse_state(or_state_t *state, int set, char **msg);
void entry_guards_update_state(or_state_t *state);
int getinfo_helper_entry_guards(control_connection_t *conn,
                                const char *question, char **answer);

void clear_bridge_list(void);
int routerinfo_is_a_configured_bridge(routerinfo_t *ri);
void bridge_add_from_config(const tor_addr_t *addr, uint16_t port,
                            char *digest);
void retry_bridge_descriptor_fetch_directly(const char *digest);
void fetch_bridge_descriptors(time_t now);
void learned_bridge_descriptor(routerinfo_t *ri, int from_cache);
int any_bridge_descriptors_known(void);
int any_pending_bridge_descriptor_fetches(void);
int bridges_known_but_down(void);
void bridges_retry_all(void);

void entry_guards_free_all(void);

/********************************* circuitlist.c ***********************/

circuit_t * _circuit_get_global_list(void);
const char *circuit_state_to_string(int state);
const char *circuit_purpose_to_controller_string(uint8_t purpose);
void circuit_dump_by_conn(connection_t *conn, int severity);
void circuit_set_p_circid_orconn(or_circuit_t *circ, circid_t id,
                                 or_connection_t *conn);
void circuit_set_n_circid_orconn(circuit_t *circ, circid_t id,
                                 or_connection_t *conn);
void circuit_set_state(circuit_t *circ, uint8_t state);
void circuit_close_all_marked(void);
int32_t circuit_initial_package_window(void);
origin_circuit_t *origin_circuit_new(void);
or_circuit_t *or_circuit_new(circid_t p_circ_id, or_connection_t *p_conn);
circuit_t *circuit_get_by_circid_orconn(circid_t circ_id,
                                        or_connection_t *conn);
int circuit_id_in_use_on_orconn(circid_t circ_id, or_connection_t *conn);
circuit_t *circuit_get_by_edge_conn(edge_connection_t *conn);
void circuit_unlink_all_from_or_conn(or_connection_t *conn, int reason);
origin_circuit_t *circuit_get_by_global_id(uint32_t id);
origin_circuit_t *circuit_get_by_rend_query_and_purpose(const char *rend_query,
                                                        uint8_t purpose);
origin_circuit_t *circuit_get_next_by_pk_and_purpose(origin_circuit_t *start,
                                         const char *digest, uint8_t purpose);
or_circuit_t *circuit_get_rendezvous(const char *cookie);
or_circuit_t *circuit_get_intro_point(const char *digest);
origin_circuit_t *circuit_find_to_cannibalize(uint8_t purpose,
                                              extend_info_t *info, int flags);
void circuit_mark_all_unused_circs(void);
void circuit_expire_all_dirty_circs(void);
void _circuit_mark_for_close(circuit_t *circ, int reason,
                             int line, const char *file);
int circuit_get_cpath_len(origin_circuit_t *circ);
crypt_path_t *circuit_get_cpath_hop(origin_circuit_t *circ, int hopnum);
void circuit_get_all_pending_on_or_conn(smartlist_t *out,
                                        or_connection_t *or_conn);
int circuit_count_pending_on_or_conn(or_connection_t *or_conn);

#define circuit_mark_for_close(c, reason)                               \
  _circuit_mark_for_close((c), (reason), __LINE__, _SHORT_FILE_)

void assert_cpath_layer_ok(const crypt_path_t *cp);
void assert_circuit_ok(const circuit_t *c);
void circuit_free_all(void);

/********************************* circuituse.c ************************/

void circuit_expire_building(time_t now);
void circuit_remove_handled_ports(smartlist_t *needed_ports);
int circuit_stream_is_being_handled(edge_connection_t *conn, uint16_t port,
                                    int min);
int circuit_conforms_to_options(const origin_circuit_t *circ,
                                const or_options_t *options);
void circuit_build_needed_circs(time_t now);
void circuit_detach_stream(circuit_t *circ, edge_connection_t *conn);

void circuit_expire_old_circuits_serverside(time_t now);

void reset_bandwidth_test(void);
int circuit_enough_testing_circs(void);

void circuit_has_opened(origin_circuit_t *circ);
void circuit_build_failed(origin_circuit_t *circ);

/** Flag to set when a circuit should have only a single hop. */
#define CIRCLAUNCH_ONEHOP_TUNNEL  (1<<0)
/** Flag to set when a circuit needs to be built of high-uptime nodes */
#define CIRCLAUNCH_NEED_UPTIME    (1<<1)
/** Flag to set when a circuit needs to be built of high-capacity nodes */
#define CIRCLAUNCH_NEED_CAPACITY  (1<<2)
/** Flag to set when the last hop of a circuit doesn't need to be an
 * exit node. */
#define CIRCLAUNCH_IS_INTERNAL    (1<<3)
origin_circuit_t *circuit_launch_by_extend_info(uint8_t purpose,
                                                extend_info_t *info,
                                                int flags);
origin_circuit_t *circuit_launch_by_router(uint8_t purpose,
                                           routerinfo_t *exit, int flags);
void circuit_reset_failure_count(int timeout);
int connection_ap_handshake_attach_chosen_circuit(edge_connection_t *conn,
                                                  origin_circuit_t *circ,
                                                  crypt_path_t *cpath);
int connection_ap_handshake_attach_circuit(edge_connection_t *conn);

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, or_connection_t *conn);
void command_process_var_cell(var_cell_t *cell, or_connection_t *conn);

extern uint64_t stats_n_padding_cells_processed;
extern uint64_t stats_n_create_cells_processed;
extern uint64_t stats_n_created_cells_processed;
extern uint64_t stats_n_relay_cells_processed;
extern uint64_t stats_n_destroy_cells_processed;

/********************************* config.c ***************************/

/** An error from options_trial_assign() or options_init_from_string(). */
typedef enum setopt_err_t {
  SETOPT_OK = 0,
  SETOPT_ERR_MISC = -1,
  SETOPT_ERR_PARSE = -2,
  SETOPT_ERR_TRANSITION = -3,
  SETOPT_ERR_SETTING = -4,
} setopt_err_t;

const char *get_dirportfrontpage(void);
or_options_t *get_options(void);
int set_options(or_options_t *new_val, char **msg);
void config_free_all(void);
const char *safe_str(const char *address);
const char *escaped_safe_str(const char *address);
const char *get_version(void);

int config_get_lines(const char *string, config_line_t **result);
void config_free_lines(config_line_t *front);
setopt_err_t options_trial_assign(config_line_t *list, int use_defaults,
                                  int clear_first, char **msg);
int resolve_my_address(int warn_severity, or_options_t *options,
                       uint32_t *addr, char **hostname_out);
int is_local_addr(const tor_addr_t *addr) ATTR_PURE;
void options_init(or_options_t *options);
int options_init_from_torrc(int argc, char **argv);
setopt_err_t options_init_from_string(const char *cf,
                            int command, const char *command_arg, char **msg);
int option_is_recognized(const char *key);
const char *option_get_canonical_name(const char *key);
config_line_t *option_get_assignment(or_options_t *options,
                                     const char *key);
int options_save_current(void);
const char *get_torrc_fname(void);
char *options_get_datadir_fname2_suffix(or_options_t *options,
                                        const char *sub1, const char *sub2,
                                        const char *suffix);
#define get_datadir_fname2_suffix(sub1, sub2, suffix) \
  options_get_datadir_fname2_suffix(get_options(), (sub1), (sub2), (suffix))
/** Return a newly allocated string containing datadir/sub1.  See
 * get_datadir_fname2_suffix.  */
#define get_datadir_fname(sub1) get_datadir_fname2_suffix((sub1), NULL, NULL)
/** Return a newly allocated string containing datadir/sub1/sub2.  See
 * get_datadir_fname2_suffix.  */
#define get_datadir_fname2(sub1,sub2) \
  get_datadir_fname2_suffix((sub1), (sub2), NULL)
/** Return a newly allocated string containing datadir/sub1suffix.  See
 * get_datadir_fname2_suffix. */
#define get_datadir_fname_suffix(sub1, suffix) \
  get_datadir_fname2_suffix((sub1), NULL, (suffix))

or_state_t *get_or_state(void);
int or_state_save(time_t now);

int options_need_geoip_info(or_options_t *options, const char **reason_out);
int getinfo_helper_config(control_connection_t *conn,
                          const char *question, char **answer);

uint32_t get_effective_bwrate(or_options_t *options);
uint32_t get_effective_bwburst(or_options_t *options);

#ifdef CONFIG_PRIVATE
/* Used only by config.c and test.c */
or_options_t *options_new(void);
#endif

/********************************* connection.c ***************************/

const char *conn_type_to_string(int type);
const char *conn_state_to_string(int type, int state);

dir_connection_t *dir_connection_new(int socket_family);
or_connection_t *or_connection_new(int socket_family);
edge_connection_t *edge_connection_new(int type, int socket_family);
control_connection_t *control_connection_new(int socket_family);
connection_t *connection_new(int type, int socket_family);

void connection_link_connections(connection_t *conn_a, connection_t *conn_b);
void connection_unregister_events(connection_t *conn);
void connection_free(connection_t *conn);
void connection_free_all(void);
void connection_about_to_close_connection(connection_t *conn);
void connection_close_immediate(connection_t *conn);
void _connection_mark_for_close(connection_t *conn,int line, const char *file);

#define connection_mark_for_close(c) \
  _connection_mark_for_close((c), __LINE__, _SHORT_FILE_)

void connection_expire_held_open(void);

int connection_connect(connection_t *conn, const char *address,
                       const tor_addr_t *addr,
                       uint16_t port, int *socket_error);
int retry_all_listeners(smartlist_t *replaced_conns,
                        smartlist_t *new_conns);

ssize_t connection_bucket_write_limit(connection_t *conn, time_t now);
int global_write_bucket_low(connection_t *conn, size_t attempt, int priority);
void connection_bucket_init(void);
void connection_bucket_refill(int seconds_elapsed, time_t now);

int connection_handle_read(connection_t *conn);

int connection_fetch_from_buf(char *string, size_t len, connection_t *conn);

int connection_wants_to_flush(connection_t *conn);
int connection_outbuf_too_full(connection_t *conn);
int connection_handle_write(connection_t *conn, int force);
void _connection_write_to_buf_impl(const char *string, size_t len,
                                   connection_t *conn, int zlib);
static void connection_write_to_buf(const char *string, size_t len,
                                    connection_t *conn);
static void connection_write_to_buf_zlib(const char *string, size_t len,
                                         dir_connection_t *conn, int done);
static INLINE void
connection_write_to_buf(const char *string, size_t len, connection_t *conn)
{
  _connection_write_to_buf_impl(string, len, conn, 0);
}
static INLINE void
connection_write_to_buf_zlib(const char *string, size_t len,
                             dir_connection_t *conn, int done)
{
  _connection_write_to_buf_impl(string, len, TO_CONN(conn), done ? -1 : 1);
}

connection_t *connection_get_by_global_id(uint64_t id);

connection_t *connection_get_by_type(int type);
connection_t *connection_get_by_type_purpose(int type, int purpose);
connection_t *connection_get_by_type_addr_port_purpose(int type,
                                                   const tor_addr_t *addr,
                                                   uint16_t port, int purpose);
connection_t *connection_get_by_type_state(int type, int state);
connection_t *connection_get_by_type_state_rendquery(int type, int state,
                                                     const char *rendquery,
                                                     int rendversion);

#define connection_speaks_cells(conn) ((conn)->type == CONN_TYPE_OR)
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);
int connection_state_is_connecting(connection_t *conn);

char *alloc_http_authenticator(const char *authenticator);

void assert_connection_ok(connection_t *conn, time_t now);
int connection_or_nonopen_was_started_here(or_connection_t *conn);
void connection_dump_buffer_mem_stats(int severity);
void remove_file_if_very_old(const char *fname, time_t now);

/********************************* connection_edge.c *************************/

#define connection_mark_unattached_ap(conn, endreason) \
  _connection_mark_unattached_ap((conn), (endreason), __LINE__, _SHORT_FILE_)

void _connection_mark_unattached_ap(edge_connection_t *conn, int endreason,
                                    int line, const char *file);
int connection_edge_reached_eof(edge_connection_t *conn);
int connection_edge_process_inbuf(edge_connection_t *conn,
                                  int package_partial);
int connection_edge_destroy(circid_t circ_id, edge_connection_t *conn);
int connection_edge_end(edge_connection_t *conn, uint8_t reason);
int connection_edge_end_errno(edge_connection_t *conn);
int connection_edge_finished_flushing(edge_connection_t *conn);
int connection_edge_finished_connecting(edge_connection_t *conn);

int connection_ap_handshake_send_begin(edge_connection_t *ap_conn);
int connection_ap_handshake_send_resolve(edge_connection_t *ap_conn);

edge_connection_t  *connection_ap_make_link(char *address, uint16_t port,
                                            const char *digest,
                                            int use_begindir, int want_onehop);
void connection_ap_handshake_socks_reply(edge_connection_t *conn, char *reply,
                                         size_t replylen,
                                         int endreason);
void connection_ap_handshake_socks_resolved(edge_connection_t *conn,
                                            int answer_type,
                                            size_t answer_len,
                                            const uint8_t *answer,
                                            int ttl,
                                            time_t expires);

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
int connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ);
void connection_exit_connect(edge_connection_t *conn);
int connection_edge_is_rendezvous_stream(edge_connection_t *conn);
int connection_ap_can_use_exit(edge_connection_t *conn, routerinfo_t *exit);
void connection_ap_expire_beginning(void);
void connection_ap_attach_pending(void);
void connection_ap_fail_onehop(const char *failed_digest,
                               cpath_build_state_t *build_state);
void circuit_discard_optional_exit_enclaves(extend_info_t *info);
int connection_ap_detach_retriable(edge_connection_t *conn,
                                   origin_circuit_t *circ,
                                   int reason);
int connection_ap_process_transparent(edge_connection_t *conn);

int address_is_invalid_destination(const char *address, int client);

void addressmap_init(void);
void addressmap_clean(time_t now);
void addressmap_clear_configured(void);
void addressmap_clear_transient(void);
void addressmap_free_all(void);
int addressmap_rewrite(char *address, size_t maxlen, time_t *expires_out);
int addressmap_have_mapping(const char *address, int update_timeout);
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
void addressmap_register(const char *address, char *new_address,
                         time_t expires, addressmap_entry_source_t source);
int parse_virtual_addr_network(const char *val, int validate_only,
                               char **msg);
int client_dns_incr_failures(const char *address);
void client_dns_clear_failures(const char *address);
void client_dns_set_addressmap(const char *address, uint32_t val,
                               const char *exitname, int ttl);
const char *addressmap_register_virtual_address(int type, char *new_address);
void addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                             time_t max_expires, int want_expiry);
int connection_ap_handshake_rewrite_and_attach(edge_connection_t *conn,
                                               origin_circuit_t *circ,
                                               crypt_path_t *cpath);
int hostname_is_noconnect_address(const char *address);

/** Possible return values for parse_extended_hostname. */
typedef enum hostname_type_t {
  NORMAL_HOSTNAME, ONION_HOSTNAME, EXIT_HOSTNAME, BAD_HOSTNAME
} hostname_type_t;
hostname_type_t parse_extended_hostname(char *address);

#if defined(HAVE_NET_IF_H) && defined(HAVE_NET_PFVAR_H)
int get_pf_socket(void);
#endif

/********************************* connection_or.c ***************************/

void connection_or_remove_from_identity_map(or_connection_t *conn);
void connection_or_clear_identity_map(void);
or_connection_t *connection_or_get_for_extend(const char *digest,
                                              const tor_addr_t *target_addr,
                                              const char **msg_out,
                                              int *launch_out);
void connection_or_set_bad_connections(void);

int connection_or_reached_eof(or_connection_t *conn);
int connection_or_process_inbuf(or_connection_t *conn);
int connection_or_flushed_some(or_connection_t *conn);
int connection_or_finished_flushing(or_connection_t *conn);
int connection_or_finished_connecting(or_connection_t *conn);

void connection_or_connect_failed(or_connection_t *conn,
                                  int reason, const char *msg);
or_connection_t *connection_or_connect(const tor_addr_t *addr, uint16_t port,
                                       const char *id_digest);

int connection_tls_start_handshake(or_connection_t *conn, int receiving);
int connection_tls_continue_handshake(or_connection_t *conn);

void or_handshake_state_free(or_handshake_state_t *state);
int connection_or_set_state_open(or_connection_t *conn);
void connection_or_write_cell_to_buf(const cell_t *cell,
                                     or_connection_t *conn);
void connection_or_write_var_cell_to_buf(const var_cell_t *cell,
                                         or_connection_t *conn);
int connection_or_send_destroy(circid_t circ_id, or_connection_t *conn,
                               int reason);
int connection_or_send_netinfo(or_connection_t *conn);
int connection_or_send_cert(or_connection_t *conn);
int connection_or_send_link_auth(or_connection_t *conn);
int connection_or_compute_link_auth_hmac(or_connection_t *conn,
                                         char *hmac_out);
int is_or_protocol_version_known(uint16_t version);

void cell_pack(packed_cell_t *dest, const cell_t *src);
void var_cell_pack_header(const var_cell_t *cell, char *hdr_out);
var_cell_t *var_cell_new(uint16_t payload_len);
void var_cell_free(var_cell_t *cell);

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

void control_update_global_event_mask(void);
void control_adjust_event_log_severity(void);

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

/** Log information about the connection <b>conn</b>, protecting it as with
 * CONN_LOG_PROTECT. Example:
 *
 * LOG_FN_CONN(conn, (LOG_DEBUG, "Socket %d wants to write", conn->s));
 **/
#define LOG_FN_CONN(conn, args)                 \
  CONN_LOG_PROTECT(conn, log_fn args)

int connection_control_finished_flushing(control_connection_t *conn);
int connection_control_reached_eof(control_connection_t *conn);
int connection_control_process_inbuf(control_connection_t *conn);

#define EVENT_AUTHDIR_NEWDESCS 0x000D
#define EVENT_NS 0x000F
int control_event_is_interesting(int event);

int control_event_circuit_status(origin_circuit_t *circ,
                                 circuit_status_event_t e, int reason);
int control_event_stream_status(edge_connection_t *conn,
                                stream_status_event_t e,
                                int reason);
int control_event_or_conn_status(or_connection_t *conn,
                                 or_conn_status_event_t e, int reason);
int control_event_bandwidth_used(uint32_t n_read, uint32_t n_written);
int control_event_stream_bandwidth(edge_connection_t *edge_conn);
int control_event_stream_bandwidth_used(void);
void control_event_logmsg(int severity, unsigned int domain, const char *msg);
int control_event_descriptors_changed(smartlist_t *routers);
int control_event_address_mapped(const char *from, const char *to,
                                 time_t expires, const char *error);
int control_event_or_authdir_new_descriptor(const char *action,
                                            const char *desc,
                                            size_t desclen,
                                            const char *msg);
int control_event_my_descriptor_changed(void);
int control_event_networkstatus_changed(smartlist_t *statuses);
int control_event_newconsensus(const networkstatus_t *consensus);
int control_event_networkstatus_changed_single(routerstatus_t *rs);
int control_event_general_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_client_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_server_status(int severity, const char *format, ...)
  CHECK_PRINTF(2,3);
int control_event_guard(const char *nickname, const char *digest,
                        const char *status);

int init_cookie_authentication(int enabled);
smartlist_t *decode_hashed_passwords(config_line_t *passwords);
void disable_control_logging(void);
void enable_control_logging(void);

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

void control_event_bootstrap(bootstrap_status_t status, int progress);
void control_event_bootstrap_problem(const char *warn, int reason);

void control_event_clients_seen(const char *timestarted,
                                const char *countries);

#ifdef CONTROL_PRIVATE
/* Used only by control.c and test.c */
size_t write_escaped_data(const char *data, size_t len, char **out);
size_t read_escaped_data(const char *data, size_t len, char **out);
#endif

/********************************* cpuworker.c *****************************/

void cpu_init(void);
void cpuworkers_rotate(void);
int connection_cpu_finished_flushing(connection_t *conn);
int connection_cpu_reached_eof(connection_t *conn);
int connection_cpu_process_inbuf(connection_t *conn);
int assign_onionskin_to_cpuworker(connection_t *cpuworker,
                                  or_circuit_t *circ,
                                  char *onionskin);

/********************************* directory.c ***************************/

int directories_have_accepted_server_descriptor(void);
char *authority_type_to_string(authority_type_t auth);
void directory_post_to_dirservers(uint8_t dir_purpose, uint8_t router_purpose,
                                  authority_type_t type, const char *payload,
                                  size_t payload_len, size_t extrainfo_len);
void directory_get_from_dirserver(uint8_t dir_purpose, uint8_t router_purpose,
                                  const char *resource,
                                  int pds_flags);
void directory_get_from_all_authorities(uint8_t dir_purpose,
                                        uint8_t router_purpose,
                                        const char *resource);
void directory_initiate_command_routerstatus(routerstatus_t *status,
                                             uint8_t dir_purpose,
                                             uint8_t router_purpose,
                                             int anonymized_connection,
                                             const char *resource,
                                             const char *payload,
                                             size_t payload_len,
                                             time_t if_modified_since);
void directory_initiate_command_routerstatus_rend(routerstatus_t *status,
                                                  uint8_t dir_purpose,
                                                  uint8_t router_purpose,
                                                  int anonymized_connection,
                                                  const char *resource,
                                                  const char *payload,
                                                  size_t payload_len,
                                                  time_t if_modified_since,
                                                const rend_data_t *rend_query);

int parse_http_response(const char *headers, int *code, time_t *date,
                        compress_method_t *compression, char **response);

int connection_dir_is_encrypted(dir_connection_t *conn);
int connection_dir_reached_eof(dir_connection_t *conn);
int connection_dir_process_inbuf(dir_connection_t *conn);
int connection_dir_finished_flushing(dir_connection_t *conn);
int connection_dir_finished_connecting(dir_connection_t *conn);
void connection_dir_request_failed(dir_connection_t *conn);
void directory_initiate_command(const char *address, const tor_addr_t *addr,
                                uint16_t or_port, uint16_t dir_port,
                                int supports_conditional_consensus,
                                int supports_begindir, const char *digest,
                                uint8_t dir_purpose, uint8_t router_purpose,
                                int anonymized_connection,
                                const char *resource,
                                const char *payload, size_t payload_len,
                                time_t if_modified_since);

int dir_split_resource_into_fingerprints(const char *resource,
                                    smartlist_t *fp_out, int *compresseed_out,
                                    int decode_hex, int sort_uniq);
/** A pair of digests created by dir_split_resource_info_fingerprint_pairs() */
typedef struct {
  char first[DIGEST_LEN];
  char second[DIGEST_LEN];
} fp_pair_t;
int dir_split_resource_into_fingerprint_pairs(const char *res,
                                              smartlist_t *pairs_out);
char *directory_dump_request_log(void);
void note_request(const char *key, size_t bytes);
int router_supports_extrainfo(const char *identity_digest, int is_authority);

time_t download_status_increment_failure(download_status_t *dls,
                                         int status_code, const char *item,
                                         int server, time_t now);
/** Increment the failure count of the download_status_t <b>dls</b>, with
 * the optional status code <b>sc</b>. */
#define download_status_failed(dls, sc)                                 \
  download_status_increment_failure((dls), (sc), NULL,                  \
                                    get_options()->DirPort, time(NULL))

void download_status_reset(download_status_t *dls);
static int download_status_is_ready(download_status_t *dls, time_t now,
                                    int max_failures);
/** Return true iff, as of <b>now</b>, the resource tracked by <b>dls</b> is
 * ready to get its download reattempted. */
static INLINE int
download_status_is_ready(download_status_t *dls, time_t now,
                         int max_failures)
{
  return (dls->n_download_failures <= max_failures
          && dls->next_attempt_at <= now);
}

static void download_status_mark_impossible(download_status_t *dl);
/** Mark <b>dl</b> as never downloadable. */
static INLINE void
download_status_mark_impossible(download_status_t *dl)
{
  dl->n_download_failures = IMPOSSIBLE_TO_DOWNLOAD;
}

/********************************* dirserv.c ***************************/
/** Maximum length of an exit policy summary. */
#define MAX_EXITPOLICY_SUMMARY_LEN (1000)

/** Maximum allowable length of a version line in a networkstatus. */
#define MAX_V_LINE_LEN 128
/** Length of "r Authority BadDirectory BadExit Exit Fast Guard HSDir Named
 * Running Stable Unnamed V2Dir Valid\n". */
#define MAX_FLAG_LINE_LEN 96
/** Length of "w" line for weighting.  Currently at most
 * "w Bandwidth=<uint32t>\n" */
#define MAX_WEIGHT_LINE_LEN (13+10)
/** Maximum length of an exit policy summary line. */
#define MAX_POLICY_LINE_LEN (3+MAX_EXITPOLICY_SUMMARY_LEN)
/** Amount of space to allocate for each entry: r, s, and v lines. */
#define RS_ENTRY_LEN                                                    \
  ( /* first line */                                                    \
   MAX_NICKNAME_LEN+BASE64_DIGEST_LEN*2+ISO_TIME_LEN+INET_NTOA_BUF_LEN+ \
   5*2 /* ports */ + 10 /* punctuation */ +                             \
   /* second line */                                                    \
   MAX_FLAG_LINE_LEN +                                                  \
   /* weight line */                                                    \
   MAX_WEIGHT_LINE_LEN +                                                \
   /* p line. */                                                        \
   MAX_POLICY_LINE_LEN +                                                \
   /* v line. */                                                        \
   MAX_V_LINE_LEN                                                       \
   )
#define UNNAMED_ROUTER_NICKNAME "Unnamed"

int connection_dirserv_flushed_some(dir_connection_t *conn);

int dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk);
int dirserv_load_fingerprint_file(void);
void dirserv_free_fingerprint_list(void);
const char *dirserv_get_nickname_by_digest(const char *digest);
enum was_router_added_t dirserv_add_multiple_descriptors(
                                     const char *desc, uint8_t purpose,
                                     const char *source,
                                     const char **msg);
enum was_router_added_t dirserv_add_descriptor(routerinfo_t *ri,
                                               const char **msg,
                                               const char *source);
int getinfo_helper_dirserv_unregistered(control_connection_t *conn,
                                        const char *question, char **answer);
void dirserv_free_descriptors(void);
void dirserv_set_router_is_running(routerinfo_t *router, time_t now);
int list_server_status_v1(smartlist_t *routers, char **router_status_out,
                          int for_controller);
int dirserv_dump_directory_to_string(char **dir_out,
                                     crypto_pk_env_t *private_key);

int directory_fetches_from_authorities(or_options_t *options);
int directory_fetches_dir_info_early(or_options_t *options);
int directory_fetches_dir_info_later(or_options_t *options);
int directory_caches_v2_dir_info(or_options_t *options);
#define directory_caches_v1_dir_info(o) directory_caches_v2_dir_info(o)
int directory_caches_dir_info(or_options_t *options);
int directory_permits_begindir_requests(or_options_t *options);
int directory_permits_controller_requests(or_options_t *options);
int directory_too_idle_to_fetch_descriptors(or_options_t *options, time_t now);

void directory_set_dirty(void);
cached_dir_t *dirserv_get_directory(void);
cached_dir_t *dirserv_get_runningrouters(void);
cached_dir_t *dirserv_get_consensus(void);
void dirserv_set_cached_directory(const char *directory, time_t when,
                                  int is_running_routers);
void dirserv_set_cached_networkstatus_v2(const char *directory,
                                         const char *identity,
                                         time_t published);
void dirserv_set_cached_networkstatus_v3(const char *consensus,
                                         time_t published);
void dirserv_clear_old_networkstatuses(time_t cutoff);
void dirserv_clear_old_v1_info(time_t now);
void dirserv_get_networkstatus_v2(smartlist_t *result, const char *key);
void dirserv_get_networkstatus_v2_fingerprints(smartlist_t *result,
                                               const char *key);
int dirserv_get_routerdesc_fingerprints(smartlist_t *fps_out, const char *key,
                                        const char **msg,
                                        int for_unencrypted_conn,
                                        int is_extrainfo);
int dirserv_get_routerdescs(smartlist_t *descs_out, const char *key,
                            const char **msg);
void dirserv_orconn_tls_done(const char *address,
                             uint16_t or_port,
                             const char *digest_rcvd,
                             int as_advertised);
void dirserv_test_reachability(time_t now, int try_all);
int authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                                   int complain);
int dirserv_would_reject_router(routerstatus_t *rs);
int dirserv_remove_old_statuses(smartlist_t *fps, time_t cutoff);
int dirserv_have_any_serverdesc(smartlist_t *fps, int spool_src);
size_t dirserv_estimate_data_size(smartlist_t *fps, int is_serverdescs,
                                  int compressed);
int routerstatus_format_entry(char *buf, size_t buf_len,
                              routerstatus_t *rs, const char *platform,
                              int first_line_only, int v2_format);
void dirserv_free_all(void);
void cached_dir_decref(cached_dir_t *d);
cached_dir_t *new_cached_dir(char *s, time_t published);

/********************************* dirvote.c ************************/

/** Lowest allowable value for VoteSeconds. */
#define MIN_VOTE_SECONDS 20
/** Lowest allowable value for DistSeconds. */
#define MIN_DIST_SECONDS 20
/** Smallest allowable voting interval. */
#define MIN_VOTE_INTERVAL 300

void dirvote_free_all(void);

/* vote manipulation */
char *networkstatus_compute_consensus(smartlist_t *votes,
                                      int total_authorities,
                                      crypto_pk_env_t *identity_key,
                                      crypto_pk_env_t *signing_key,
                                      const char *legacy_identity_key_digest,
                                      crypto_pk_env_t *legacy_signing_key);
int networkstatus_add_detached_signatures(networkstatus_t *target,
                                          ns_detached_signatures_t *sigs,
                                          const char **msg_out);
char *networkstatus_get_detached_signatures(networkstatus_t *consensus);
void ns_detached_signatures_free(ns_detached_signatures_t *s);

/* cert manipulation */
authority_cert_t *authority_cert_dup(authority_cert_t *cert);

/** Describes the schedule by which votes should be generated. */
typedef struct vote_timing_t {
  int vote_interval;
  int n_intervals_valid;
  int vote_delay;
  int dist_delay;
} vote_timing_t;
/* vote scheduling */
void dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out);
time_t dirvote_get_start_of_next_interval(time_t now, int interval);
void dirvote_recalculate_timing(or_options_t *options, time_t now);
void dirvote_act(or_options_t *options, time_t now);

/* invoked on timers and by outside triggers. */
struct pending_vote_t * dirvote_add_vote(const char *vote_body,
                                         const char **msg_out,
                                         int *status_out);
int dirvote_add_signatures(const char *detached_signatures_body,
                           const char *source,
                           const char **msg_out);

/* Item access */
const char *dirvote_get_pending_consensus(void);
const char *dirvote_get_pending_detached_signatures(void);
#define DGV_BY_ID 1
#define DGV_INCLUDE_PENDING 2
#define DGV_INCLUDE_PREVIOUS 4
const cached_dir_t *dirvote_get_vote(const char *fp, int flags);
void set_routerstatus_from_routerinfo(routerstatus_t *rs,
                                      routerinfo_t *ri, time_t now,
                                      int naming, int exits_can_be_guards,
                                      int listbadexits, int listbaddirs);
void router_clear_status_flags(routerinfo_t *ri);
networkstatus_t *
dirserv_generate_networkstatus_vote_obj(crypto_pk_env_t *private_key,
                                        authority_cert_t *cert);

#ifdef DIRVOTE_PRIVATE
char *format_networkstatus_vote(crypto_pk_env_t *private_key,
                                 networkstatus_t *v3_ns);
char *dirvote_compute_params(smartlist_t *votes);
#endif

/********************************* dns.c ***************************/

int dns_init(void);
int has_dns_init_failed(void);
void dns_free_all(void);
uint32_t dns_clip_ttl(uint32_t ttl);
int dns_reset(void);
void connection_dns_remove(edge_connection_t *conn);
void assert_connection_edge_not_dns_pending(edge_connection_t *conn);
void assert_all_pending_dns_resolves_ok(void);
void dns_cancel_pending_resolve(const char *question);
int dns_resolve(edge_connection_t *exitconn);
void dns_launch_correctness_checks(void);
int dns_seems_to_be_broken(void);
void dns_reset_correctness_checks(void);

/********************************* dnsserv.c ************************/

void dnsserv_configure_listener(connection_t *conn);
void dnsserv_close_listener(connection_t *conn);
void dnsserv_resolved(edge_connection_t *conn,
                      int answer_type,
                      size_t answer_len,
                      const char *answer,
                      int ttl);
void dnsserv_reject_request(edge_connection_t *conn);
int dnsserv_launch_request(const char *name, int is_reverse);

/********************************* geoip.c **************************/

#ifdef GEOIP_PRIVATE
int geoip_parse_entry(const char *line);
#endif
int should_record_bridge_info(or_options_t *options);
int geoip_load_file(const char *filename, or_options_t *options);
int geoip_get_country_by_ip(uint32_t ipaddr);
int geoip_get_n_countries(void);
const char *geoip_get_country_name(country_t num);
int geoip_is_loaded(void);
country_t geoip_get_country(const char *countrycode);
/** Indicates an action that we might be noting geoip statistics on.
 * Note that if we're noticing CONNECT, we're a bridge, and if we're noticing
 * the others, we're not.
 */
typedef enum {
  /** We've noticed a connection as a bridge relay. */
  GEOIP_CLIENT_CONNECT = 0,
  /** We've served a networkstatus consensus as a directory server. */
  GEOIP_CLIENT_NETWORKSTATUS = 1,
  /** We've served a v2 networkstatus consensus as a directory server. */
  GEOIP_CLIENT_NETWORKSTATUS_V2 = 2,
} geoip_client_action_t;
void geoip_note_client_seen(geoip_client_action_t action,
                            uint32_t addr, time_t now);
void geoip_remove_old_clients(time_t cutoff);
time_t geoip_get_history_start(void);
char *geoip_get_client_history(time_t now, geoip_client_action_t action);
char *geoip_get_request_history(time_t now, geoip_client_action_t action);
int getinfo_helper_geoip(control_connection_t *control_conn,
                         const char *question, char **answer);
void geoip_free_all(void);
void dump_geoip_stats(void);

/********************************* hibernate.c **********************/

int accounting_parse_options(or_options_t *options, int validate_only);
int accounting_is_enabled(or_options_t *options);
void configure_accounting(time_t now);
void accounting_run_housekeeping(time_t now);
void accounting_add_bytes(size_t n_read, size_t n_written, int seconds);
int accounting_record_bandwidth_usage(time_t now, or_state_t *state);
void hibernate_begin_shutdown(void);
int we_are_hibernating(void);
void consider_hibernation(time_t now);
int getinfo_helper_accounting(control_connection_t *conn,
                              const char *question, char **answer);
void accounting_set_bandwidth_usage_from_state(or_state_t *state);

/********************************* main.c ***************************/

extern int has_completed_circuit;

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
int connection_in_array(connection_t *conn);
void add_connection_to_closeable_list(connection_t *conn);
int connection_is_on_closeable_list(connection_t *conn);

smartlist_t *get_connection_array(void);

void connection_watch_events(connection_t *conn, short events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void connection_stop_reading_from_linked_conn(connection_t *conn);

void directory_all_unreachable(time_t now);
void directory_info_has_arrived(time_t now, int from_cache);

void ip_address_changed(int at_interface);
void dns_servers_relaunch_checks(void);

void control_signal_act(int the_signal);
void handle_signals(int is_parent);

int try_locking(or_options_t *options, int err_if_locked);
int have_lockfile(void);
void release_lockfile(void);

void tor_cleanup(void);
void tor_free_all(int postfork);

int tor_main(int argc, char *argv[]);

#ifdef MAIN_PRIVATE
int do_main_loop(void);
int do_list_fingerprint(void);
void do_hash_password(void);
int tor_init(int argc, char **argv);
#endif

/********************************* networkstatus.c *********************/

/** How old do we allow a v2 network-status to get before removing it
 * completely? */
#define MAX_NETWORKSTATUS_AGE (10*24*60*60)

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

void networkstatus_reset_warnings(void);
void networkstatus_reset_download_failures(void);
int router_reload_v2_networkstatus(void);
int router_reload_consensus_networkstatus(void);
void routerstatus_free(routerstatus_t *rs);
void networkstatus_v2_free(networkstatus_v2_t *ns);
void networkstatus_vote_free(networkstatus_t *ns);
networkstatus_voter_info_t *networkstatus_get_voter_by_id(
                                       networkstatus_t *vote,
                                       const char *identity);
int networkstatus_check_consensus_signature(networkstatus_t *consensus,
                                            int warn);
int networkstatus_check_voter_signature(networkstatus_t *consensus,
                                        networkstatus_voter_info_t *voter,
                                        authority_cert_t *cert);
char *networkstatus_get_cache_filename(const char *identity_digest);
int router_set_networkstatus_v2(const char *s, time_t arrived_at,
                             v2_networkstatus_source_t source,
                             smartlist_t *requested_fingerprints);
void networkstatus_v2_list_clean(time_t now);
routerstatus_t *networkstatus_v2_find_entry(networkstatus_v2_t *ns,
                                         const char *digest);
routerstatus_t *networkstatus_vote_find_entry(networkstatus_t *ns,
                                              const char *digest);
int networkstatus_vote_find_entry_idx(networkstatus_t *ns,
                                      const char *digest, int *found_out);
const smartlist_t *networkstatus_get_v2_list(void);
download_status_t *router_get_dl_status_by_descriptor_digest(const char *d);
routerstatus_t *router_get_consensus_status_by_id(const char *digest);
routerstatus_t *router_get_consensus_status_by_descriptor_digest(
                                                        const char *digest);
routerstatus_t *router_get_consensus_status_by_nickname(const char *nickname,
                                                       int warn_if_unnamed);
const char *networkstatus_get_router_digest_by_nickname(const char *nickname);
int networkstatus_nickname_is_unnamed(const char *nickname);
void networkstatus_consensus_download_failed(int status_code);
void update_consensus_networkstatus_fetch_time(time_t now);
int should_delay_dir_fetches(or_options_t *options);
void update_networkstatus_downloads(time_t now);
void update_certificate_downloads(time_t now);
int consensus_is_waiting_for_certs(void);
networkstatus_v2_t *networkstatus_v2_get_by_digest(const char *digest);
networkstatus_t *networkstatus_get_latest_consensus(void);
networkstatus_t *networkstatus_get_live_consensus(time_t now);
networkstatus_t *networkstatus_get_reasonably_live_consensus(time_t now);
#define NSSET_FROM_CACHE 1
#define NSSET_WAS_WAITING_FOR_CERTS 2
#define NSSET_DONT_DOWNLOAD_CERTS 4
#define NSSET_ACCEPT_OBSOLETE 8
int networkstatus_set_current_consensus(const char *consensus, unsigned flags);
void networkstatus_note_certs_arrived(void);
void routers_update_all_from_networkstatus(time_t now, int dir_version);
void routerstatus_list_update_from_consensus_networkstatus(time_t now);
void routers_update_status_from_consensus_networkstatus(smartlist_t *routers,
                                                        int reset_failures);
void signed_descs_update_status_from_consensus_networkstatus(
                                                         smartlist_t *descs);

char *networkstatus_getinfo_helper_single(routerstatus_t *rs);
char *networkstatus_getinfo_by_purpose(const char *purpose_string, time_t now);
void networkstatus_dump_bridge_status_to_file(time_t now);
int32_t networkstatus_get_param(networkstatus_t *ns, const char *param_name,
                                int32_t default_val);
int getinfo_helper_networkstatus(control_connection_t *conn,
                                 const char *question, char **answer);
void networkstatus_free_all(void);

/********************************* ntmain.c ***************************/
#ifdef MS_WINDOWS
#define NT_SERVICE
#endif

#ifdef NT_SERVICE
int nt_service_parse_options(int argc, char **argv, int *should_exit);
int nt_service_is_stopping(void);
void nt_service_set_state(DWORD state);
#else
#define nt_service_is_stopping() (0)
#endif

/********************************* onion.c ***************************/

int onion_pending_add(or_circuit_t *circ, char *onionskin);
or_circuit_t *onion_next_task(char **onionskin_out);
void onion_pending_remove(or_circuit_t *circ);

int onion_skin_create(crypto_pk_env_t *router_key,
                      crypto_dh_env_t **handshake_state_out,
                      char *onion_skin_out);

int onion_skin_server_handshake(const char *onion_skin,
                                crypto_pk_env_t *private_key,
                                crypto_pk_env_t *prev_private_key,
                                char *handshake_reply_out,
                                char *key_out,
                                size_t key_out_len);

int onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
                                const char *handshake_reply,
                                char *key_out,
                                size_t key_out_len);

int fast_server_handshake(const uint8_t *key_in,
                          uint8_t *handshake_reply_out,
                          uint8_t *key_out,
                          size_t key_out_len);

int fast_client_handshake(const uint8_t *handshake_state,
                          const uint8_t *handshake_reply_out,
                          uint8_t *key_out,
                          size_t key_out_len);

void clear_pending_onions(void);

/********************************* policies.c ************************/

/* (length of "accept 255.255.255.255/255.255.255.255:65535-65535\n" plus a
 * NUL.)
 */
#define POLICY_BUF_LEN 52

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
  ADDR_POLICY_PROBABLY_REJECTED=2
} addr_policy_result_t;

int firewall_is_fascist_or(void);
int fascist_firewall_allows_address_or(const tor_addr_t *addr, uint16_t port);
int fascist_firewall_allows_or(routerinfo_t *ri);
int fascist_firewall_allows_address_dir(const tor_addr_t *addr, uint16_t port);
int dir_policy_permits_address(const tor_addr_t *addr);
int socks_policy_permits_address(const tor_addr_t *addr);
int authdir_policy_permits_address(uint32_t addr, uint16_t port);
int authdir_policy_valid_address(uint32_t addr, uint16_t port);
int authdir_policy_baddir_address(uint32_t addr, uint16_t port);
int authdir_policy_badexit_address(uint32_t addr, uint16_t port);

int validate_addr_policies(or_options_t *options, char **msg);
void policy_expand_private(smartlist_t **policy);
int policies_parse_from_options(or_options_t *options);

addr_policy_t *addr_policy_get_canonical_entry(addr_policy_t *ent);
int cmp_addr_policies(smartlist_t *a, smartlist_t *b);
addr_policy_result_t compare_tor_addr_to_addr_policy(const tor_addr_t *addr,
                              uint16_t port, const smartlist_t *policy);
addr_policy_result_t compare_addr_to_addr_policy(uint32_t addr,
                              uint16_t port, const smartlist_t *policy);
int policies_parse_exit_policy(config_line_t *cfg, smartlist_t **dest,
                               int rejectprivate, const char *local_address);
void policies_set_router_exitpolicy_to_reject_all(routerinfo_t *exitrouter);
int exit_policy_is_general_exit(smartlist_t *policy);
int policy_is_reject_star(const smartlist_t *policy);
int getinfo_helper_policies(control_connection_t *conn,
                            const char *question, char **answer);
int policy_write_item(char *buf, size_t buflen, addr_policy_t *item,
                      int format_for_desc);

void addr_policy_list_free(smartlist_t *p);
void addr_policy_free(addr_policy_t *p);
void policies_free_all(void);

char *policy_summarize(smartlist_t *policy);

/********************************* reasons.c ***************************/

const char *stream_end_reason_to_control_string(int reason);
const char *stream_end_reason_to_string(int reason);
socks5_reply_status_t stream_end_reason_to_socks5_response(int reason);
uint8_t errno_to_stream_end_reason(int e);

const char *orconn_end_reason_to_control_string(int r);
int tls_error_to_orconn_end_reason(int e);
int errno_to_orconn_end_reason(int e);

const char *circuit_end_reason_to_control_string(int reason);

/********************************* relay.c ***************************/

extern uint64_t stats_n_relay_cells_relayed;
extern uint64_t stats_n_relay_cells_delivered;

int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               cell_direction_t cell_direction);

void relay_header_pack(uint8_t *dest, const relay_header_t *src);
void relay_header_unpack(relay_header_t *dest, const uint8_t *src);
int relay_send_command_from_edge(streamid_t stream_id, circuit_t *circ,
                               uint8_t relay_command, const char *payload,
                               size_t payload_len, crypt_path_t *cpath_layer);
int connection_edge_send_command(edge_connection_t *fromconn,
                                 uint8_t relay_command, const char *payload,
                                 size_t payload_len);
int connection_edge_package_raw_inbuf(edge_connection_t *conn,
                                      int package_partial);
void connection_edge_consider_sending_sendme(edge_connection_t *conn);

extern uint64_t stats_n_data_cells_packaged;
extern uint64_t stats_n_data_bytes_packaged;
extern uint64_t stats_n_data_cells_received;
extern uint64_t stats_n_data_bytes_received;

void init_cell_pool(void);
void free_cell_pool(void);
void clean_cell_pool(void);
void dump_cell_pool_usage(int severity);

void cell_queue_clear(cell_queue_t *queue);
void cell_queue_append(cell_queue_t *queue, packed_cell_t *cell);
void cell_queue_append_packed_copy(cell_queue_t *queue, const cell_t *cell);

void append_cell_to_circuit_queue(circuit_t *circ, or_connection_t *orconn,
                                  cell_t *cell, cell_direction_t direction);
void connection_or_unlink_all_active_circs(or_connection_t *conn);
int connection_or_flush_from_first_active_circuit(or_connection_t *conn,
                                                  int max, time_t now);
void assert_active_circuits_ok(or_connection_t *orconn);
void make_circuit_inactive_on_conn(circuit_t *circ, or_connection_t *conn);
void make_circuit_active_on_conn(circuit_t *circ, or_connection_t *conn);

int append_address_to_payload(uint8_t *payload_out, const tor_addr_t *addr);
const uint8_t *decode_address_from_payload(tor_addr_t *addr_out,
                                        const uint8_t *payload,
                                        int payload_len);

/********************************* rephist.c ***************************/

void rep_hist_init(void);
void rep_hist_note_connect_failed(const char* nickname, time_t when);
void rep_hist_note_connect_succeeded(const char* nickname, time_t when);
void rep_hist_note_disconnect(const char* nickname, time_t when);
void rep_hist_note_connection_died(const char* nickname, time_t when);
void rep_hist_note_extend_succeeded(const char *from_name,
                                    const char *to_name);
void rep_hist_note_extend_failed(const char *from_name, const char *to_name);
void rep_hist_dump_stats(time_t now, int severity);
void rep_hist_note_bytes_read(size_t num_bytes, time_t when);
void rep_hist_note_bytes_written(size_t num_bytes, time_t when);
int rep_hist_bandwidth_assess(void);
char *rep_hist_get_bandwidth_lines(int for_extrainfo);
void rep_hist_update_state(or_state_t *state);
int rep_hist_load_state(or_state_t *state, char **err);
void rep_history_clean(time_t before);

void rep_hist_note_router_reachable(const char *id, time_t when);
void rep_hist_note_router_unreachable(const char *id, time_t when);
int rep_hist_record_mtbf_data(time_t now, int missing_means_down);
int rep_hist_load_mtbf_data(time_t now);

time_t rep_hist_downrate_old_runs(time_t now);
double rep_hist_get_stability(const char *id, time_t when);
double rep_hist_get_weighted_fractional_uptime(const char *id, time_t when);
long rep_hist_get_weighted_time_known(const char *id, time_t when);
int rep_hist_have_measured_enough_stability(void);
const char *rep_hist_get_router_stability_doc(time_t now);

void rep_hist_note_used_port(time_t now, uint16_t port);
smartlist_t *rep_hist_get_predicted_ports(time_t now);
void rep_hist_note_used_resolve(time_t now);
void rep_hist_note_used_internal(time_t now, int need_uptime,
                                 int need_capacity);
int rep_hist_get_predicted_internal(time_t now, int *need_uptime,
                                    int *need_capacity);

int any_predicted_circuits(time_t now);
int rep_hist_circbuilding_dormant(time_t now);

/** Possible public/private key operations in Tor: used to keep track of where
 * we're spending our time. */
typedef enum {
  SIGN_DIR, SIGN_RTR,
  VERIFY_DIR, VERIFY_RTR,
  ENC_ONIONSKIN, DEC_ONIONSKIN,
  TLS_HANDSHAKE_C, TLS_HANDSHAKE_S,
  REND_CLIENT, REND_MID, REND_SERVER,
} pk_op_t;
void note_crypto_pk_op(pk_op_t operation);
void dump_pk_ops(int severity);

void rep_hist_free_all(void);

/* for hidden service usage statistics */
void hs_usage_note_publish_total(const char *service_id, time_t now);
void hs_usage_note_publish_novel(const char *service_id, time_t now);
void hs_usage_note_fetch_total(const char *service_id, time_t now);
void hs_usage_note_fetch_successful(const char *service_id, time_t now);
void hs_usage_write_statistics_to_file(time_t now);
void hs_usage_free_all(void);

/********************************* rendclient.c ***************************/

void rend_client_introcirc_has_opened(origin_circuit_t *circ);
void rend_client_rendcirc_has_opened(origin_circuit_t *circ);
int rend_client_introduction_acked(origin_circuit_t *circ,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_client_refetch_renddesc(const char *query);
void rend_client_refetch_v2_renddesc(const rend_data_t *rend_query);
int rend_client_remove_intro_point(extend_info_t *failed_intro,
                                   const rend_data_t *rend_query);
int rend_client_rendezvous_acked(origin_circuit_t *circ,
                                 const uint8_t *request,
                                 size_t request_len);
int rend_client_receive_rendezvous(origin_circuit_t *circ,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_client_desc_trynow(const char *query, int rend_version);

extend_info_t *rend_client_get_random_intro(const rend_data_t *rend_query);

int rend_client_send_introduction(origin_circuit_t *introcirc,
                                  origin_circuit_t *rendcirc);
int rend_parse_service_authorization(or_options_t *options,
                                     int validate_only);
rend_service_authorization_t *rend_client_lookup_service_authorization(
                                                const char *onion_address);
void rend_service_authorization_free_all(void);
rend_data_t *rend_data_dup(const rend_data_t *request);

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

/** Free all storage associated with <b>data</b> */
static INLINE void
rend_data_free(rend_data_t *data)
{
  tor_free(data);
}

int rend_cmp_service_ids(const char *one, const char *two);

void rend_process_relay_cell(circuit_t *circ, const crypt_path_t *layer_hint,
                             int command, size_t length,
                             const uint8_t *payload);

void rend_service_descriptor_free(rend_service_descriptor_t *desc);
int rend_encode_service_descriptor(rend_service_descriptor_t *desc,
                                   crypto_pk_env_t *key,
                                   char **str_out,
                                   size_t *len_out);
rend_service_descriptor_t *rend_parse_service_descriptor(const char *str,
                                                         size_t len);
int rend_get_service_id(crypto_pk_env_t *pk, char *out);
void rend_encoded_v2_service_descriptor_free(
                               rend_encoded_v2_service_descriptor_t *desc);
void rend_intro_point_free(rend_intro_point_t *intro);

/** A cached rendezvous descriptor. */
typedef struct rend_cache_entry_t {
  size_t len; /**< Length of <b>desc</b> */
  time_t received; /**< When was the descriptor received? */
  char *desc; /**< Service descriptor */
  rend_service_descriptor_t *parsed; /**< Parsed value of 'desc' */
} rend_cache_entry_t;

void rend_cache_init(void);
void rend_cache_clean(void);
void rend_cache_clean_v2_descs_as_dir(void);
void rend_cache_free_all(void);
int rend_valid_service_id(const char *query);
int rend_cache_lookup_desc(const char *query, int version, const char **desc,
                           size_t *desc_len);
int rend_cache_lookup_entry(const char *query, int version,
                            rend_cache_entry_t **entry_out);
int rend_cache_lookup_v2_desc_as_dir(const char *query, const char **desc);
int rend_cache_store(const char *desc, size_t desc_len, int published);
int rend_cache_store_v2_desc_as_client(const char *desc,
                                       const rend_data_t *rend_query);
int rend_cache_store_v2_desc_as_dir(const char *desc);
int rend_cache_size(void);
int rend_encode_v2_descriptors(smartlist_t *descs_out,
                               rend_service_descriptor_t *desc, time_t now,
                               uint8_t period, rend_auth_type_t auth_type,
                               crypto_pk_env_t *client_key,
                               smartlist_t *client_cookies);
int rend_compute_v2_desc_id(char *desc_id_out, const char *service_id,
                            const char *descriptor_cookie,
                            time_t now, uint8_t replica);
int rend_id_is_in_interval(const char *a, const char *b, const char *c);
void rend_get_descriptor_id_bytes(char *descriptor_id_out,
                                  const char *service_id,
                                  const char *secret_id_part);

/********************************* rendservice.c ***************************/

int num_rend_services(void);
int rend_config_services(or_options_t *options, int validate_only);
int rend_service_load_keys(void);
void rend_services_init(void);
void rend_services_introduce(void);
void rend_consider_services_upload(time_t now);
void rend_hsdir_routers_changed(void);
void rend_consider_descriptor_republication(void);

void rend_service_intro_has_opened(origin_circuit_t *circuit);
int rend_service_intro_established(origin_circuit_t *circuit,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_service_rendezvous_has_opened(origin_circuit_t *circuit);
int rend_service_introduce(origin_circuit_t *circuit, const uint8_t *request,
                           size_t request_len);
void rend_service_relaunch_rendezvous(origin_circuit_t *oldcirc);
int rend_service_set_connection_addr_port(edge_connection_t *conn,
                                          origin_circuit_t *circ);
void rend_service_dump_stats(int severity);
void rend_service_free_all(void);

/********************************* rendmid.c *******************************/
int rend_mid_establish_intro(or_circuit_t *circ, const uint8_t *request,
                             size_t request_len);
int rend_mid_introduce(or_circuit_t *circ, const uint8_t *request,
                       size_t request_len);
int rend_mid_establish_rendezvous(or_circuit_t *circ, const uint8_t *request,
                                  size_t request_len);
int rend_mid_rendezvous(or_circuit_t *circ, const uint8_t *request,
                        size_t request_len);

/********************************* router.c ***************************/

crypto_pk_env_t *get_onion_key(void);
time_t get_onion_key_set_at(void);
void set_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_identity_key(void);
int identity_key_is_set(void);
authority_cert_t *get_my_v3_authority_cert(void);
crypto_pk_env_t *get_my_v3_authority_signing_key(void);
authority_cert_t *get_my_v3_legacy_cert(void);
crypto_pk_env_t *get_my_v3_legacy_signing_key(void);
void dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last);
void rotate_onion_key(void);
crypto_pk_env_t *init_key_from_file(const char *fname, int generate,
                                    int severity);
void v3_authority_check_key_expiry(void);

int init_keys(void);

int check_whether_orport_reachable(void);
int check_whether_dirport_reachable(void);
void consider_testing_reachability(int test_or, int test_dir);
void router_orport_found_reachable(void);
void router_dirport_found_reachable(void);
void router_perform_bandwidth_test(int num_circs, time_t now);

int authdir_mode(or_options_t *options);
int authdir_mode_v1(or_options_t *options);
int authdir_mode_v2(or_options_t *options);
int authdir_mode_v3(or_options_t *options);
int authdir_mode_any_main(or_options_t *options);
int authdir_mode_any_nonhidserv(or_options_t *options);
int authdir_mode_handles_descs(or_options_t *options, int purpose);
int authdir_mode_publishes_statuses(or_options_t *options);
int authdir_mode_tests_reachability(or_options_t *options);
int authdir_mode_bridge(or_options_t *options);

int server_mode(or_options_t *options);
int advertised_server_mode(void);
int proxy_mode(or_options_t *options);
void consider_publishable_server(int force);

void router_upload_dir_desc_to_dirservers(int force);
void mark_my_descriptor_dirty_if_older_than(time_t when);
void mark_my_descriptor_dirty(void);
void check_descriptor_bandwidth_changed(time_t now);
void check_descriptor_ipaddress_changed(time_t now);
void router_new_address_suggestion(const char *suggestion,
                                   const dir_connection_t *d_conn);
int router_compare_to_my_exit_policy(edge_connection_t *conn);
routerinfo_t *router_get_my_routerinfo(void);
extrainfo_t *router_get_my_extrainfo(void);
const char *router_get_my_descriptor(void);
int router_digest_is_me(const char *digest);
int router_extrainfo_digest_is_me(const char *digest);
int router_is_me(routerinfo_t *router);
int router_fingerprint_is_me(const char *fp);
int router_pick_published_address(or_options_t *options, uint32_t *addr);
int router_rebuild_descriptor(int force);
int router_dump_router_to_string(char *s, size_t maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key);
int extrainfo_dump_to_string(char *s, size_t maxlen, extrainfo_t *extrainfo,
                             crypto_pk_env_t *ident_key);
char *extrainfo_get_client_geoip_summary(time_t);
int is_legal_nickname(const char *s);
int is_legal_nickname_or_hexdigest(const char *s);
int is_legal_hexdigest(const char *s);
void router_get_verbose_nickname(char *buf, const routerinfo_t *router);
void routerstatus_get_verbose_nickname(char *buf,
                                       const routerstatus_t *router);
void router_reset_warnings(void);
void router_reset_reachability(void);
void router_free_all(void);

const char *router_purpose_to_string(uint8_t p);
uint8_t router_purpose_from_string(const char *s);

#ifdef ROUTER_PRIVATE
/* Used only by router.c and test.c */
void get_platform_str(char *platform, size_t len);
#endif

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

int get_n_authorities(authority_type_t type);
int trusted_dirs_reload_certs(void);
int trusted_dirs_load_certs_from_string(const char *contents, int from_store,
                                        int flush);
void trusted_dirs_flush_certs_to_disk(void);
authority_cert_t *authority_cert_get_newest_by_id(const char *id_digest);
authority_cert_t *authority_cert_get_by_sk_digest(const char *sk_digest);
authority_cert_t *authority_cert_get_by_digests(const char *id_digest,
                                                const char *sk_digest);
void authority_cert_get_all(smartlist_t *certs_out);
void authority_cert_dl_failed(const char *id_digest, int status);
void authority_certs_fetch_missing(networkstatus_t *status, time_t now);
int router_reload_router_list(void);
smartlist_t *router_get_trusted_dir_servers(void);

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
#define _PDS_PREFER_TUNNELED_DIR_CONNS (1<<16)
routerstatus_t *router_pick_directory_server(authority_type_t type, int flags);
trusted_dir_server_t *router_get_trusteddirserver_by_digest(const char *d);
trusted_dir_server_t *trusteddirserver_get_by_v3_auth_digest(const char *d);
routerstatus_t *router_pick_trusteddirserver(authority_type_t type, int flags);
int router_get_my_share_of_directory_requests(double *v2_share_out,
                                              double *v3_share_out);
void router_reset_status_download_failures(void);
void routerlist_add_family(smartlist_t *sl, routerinfo_t *router);
int routers_in_same_family(routerinfo_t *r1, routerinfo_t *r2);
void add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                                    int must_be_running);
int router_nickname_is_in_list(routerinfo_t *router, const char *list);
routerinfo_t *routerlist_find_my_routerinfo(void);
routerinfo_t *router_find_exact_exit_enclave(const char *address,
                                             uint16_t port);
int router_is_unreliable(routerinfo_t *router, int need_uptime,
                         int need_capacity, int need_guard);
uint32_t router_get_advertised_bandwidth(routerinfo_t *router);
uint32_t router_get_advertised_bandwidth_capped(routerinfo_t *router);

/** Possible ways to weight routers when choosing one randomly.  See
 * routerlist_sl_choose_by_bandwidth() for more information.*/
typedef enum {
  NO_WEIGHTING, WEIGHT_FOR_EXIT, WEIGHT_FOR_GUARD
} bandwidth_weight_rule_t;
routerinfo_t *routerlist_sl_choose_by_bandwidth(smartlist_t *sl,
                                                bandwidth_weight_rule_t rule);
routerstatus_t *routerstatus_sl_choose_by_bandwidth(smartlist_t *sl);

/** Flags to be passed to control router_choose_random_node() to indicate what
 * kind of nodes to pick according to what algorithm. */
typedef enum {
  CRN_NEED_UPTIME = 1<<0,
  CRN_NEED_CAPACITY = 1<<1,
  CRN_NEED_GUARD = 1<<2,
  CRN_ALLOW_INVALID = 1<<3,
  /* XXXX not used, apparently. */
  CRN_STRICT_PREFERRED = 1<<4,
  /* XXXX not used, apparently. */
  CRN_WEIGHT_AS_EXIT = 1<<5
} router_crn_flags_t;

routerinfo_t *router_choose_random_node(const char *preferred,
                                        smartlist_t *excludedsmartlist,
                                        struct routerset_t *excludedset,
                                        router_crn_flags_t flags);

routerinfo_t *router_get_by_nickname(const char *nickname,
                                     int warn_if_unnamed);
int router_digest_version_as_new_as(const char *digest, const char *cutoff);
int router_digest_is_trusted_dir_type(const char *digest,
                                      authority_type_t type);
#define router_digest_is_trusted_dir(d) \
  router_digest_is_trusted_dir_type((d), NO_AUTHORITY)

int router_addr_is_trusted_dir(uint32_t addr);
int hexdigest_to_digest(const char *hexdigest, char *digest);
routerinfo_t *router_get_by_hexdigest(const char *hexdigest);
routerinfo_t *router_get_by_digest(const char *digest);
signed_descriptor_t *router_get_by_descriptor_digest(const char *digest);
signed_descriptor_t *router_get_by_extrainfo_digest(const char *digest);
signed_descriptor_t *extrainfo_get_by_descriptor_digest(const char *digest);
const char *signed_descriptor_get_body(signed_descriptor_t *desc);
const char *signed_descriptor_get_annotations(signed_descriptor_t *desc);
routerlist_t *router_get_routerlist(void);
void routerinfo_free(routerinfo_t *router);
void extrainfo_free(extrainfo_t *extrainfo);
void routerlist_free(routerlist_t *rl);
void dump_routerlist_mem_usage(int severity);
void routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int make_old,
                       time_t now);
void routerlist_free_all(void);
void routerlist_reset_warnings(void);
void router_set_status(const char *digest, int up);

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

static int WRA_WAS_ADDED(was_router_added_t s);
static int WRA_WAS_OUTDATED(was_router_added_t s);
static int WRA_WAS_REJECTED(was_router_added_t s);
/** Return true iff the descriptor was added. It might still be necessary to
 * check whether the descriptor generator should be notified.
 */
static INLINE int
WRA_WAS_ADDED(was_router_added_t s) {
  return s == ROUTER_ADDED_SUCCESSFULLY || s == ROUTER_ADDED_NOTIFY_GENERATOR;
}
/** Return true iff the descriptor was not added because it was either:
 * - not in the consensus
 * - neither in the consensus nor in any networkstatus document
 * - it was outdated.
 */
static INLINE int WRA_WAS_OUTDATED(was_router_added_t s)
{
  return (s == ROUTER_WAS_NOT_NEW ||
          s == ROUTER_NOT_IN_CONSENSUS ||
          s == ROUTER_NOT_IN_CONSENSUS_OR_NETWORKSTATUS);
}
/** Return true iff the descriptor rejected because it was malformed. */
static INLINE int WRA_WAS_REJECTED(was_router_added_t s)
{
  return (s == ROUTER_AUTHDIR_REJECTS);
}
was_router_added_t router_add_to_routerlist(routerinfo_t *router,
                                            const char **msg,
                                            int from_cache,
                                            int from_fetch);
was_router_added_t router_add_extrainfo_to_routerlist(
                                        extrainfo_t *ei, const char **msg,
                                        int from_cache, int from_fetch);
void routerlist_remove_old_routers(void);
int router_load_single_router(const char *s, uint8_t purpose, int cache,
                              const char **msg);
int router_load_routers_from_string(const char *s, const char *eos,
                                     saved_location_t saved_location,
                                     smartlist_t *requested_fingerprints,
                                     int descriptor_digests,
                                     const char *prepend_annotations);
void router_load_extrainfo_from_string(const char *s, const char *eos,
                                       saved_location_t saved_location,
                                       smartlist_t *requested_fingerprints,
                                       int descriptor_digests);
void routerlist_retry_directory_downloads(time_t now);
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime);
int router_exit_policy_rejects_all(routerinfo_t *router);
trusted_dir_server_t *add_trusted_dir_server(const char *nickname,
                           const char *address,
                           uint16_t dir_port, uint16_t or_port,
                           const char *digest, const char *v3_auth_digest,
                           authority_type_t type);
void authority_cert_free(authority_cert_t *cert);
void clear_trusted_dir_servers(void);
int any_trusted_dir_is_v1_authority(void);
void update_router_descriptor_downloads(time_t now);
void update_extrainfo_downloads(time_t now);
int router_have_minimum_dir_info(void);
void router_dir_info_changed(void);
const char *get_dir_info_status_string(void);
int count_loading_descriptors_progress(void);
void router_reset_descriptor_download_failures(void);
int router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2);
int routerinfo_incompatible_with_extrainfo(routerinfo_t *ri, extrainfo_t *ei,
                                           signed_descriptor_t *sd,
                                           const char **msg);
void routerlist_assert_ok(routerlist_t *rl);
const char *esc_router_info(routerinfo_t *router);
void routers_sort_by_identity(smartlist_t *routers);

routerset_t *routerset_new(void);
int routerset_parse(routerset_t *target, const char *s,
                    const char *description);
void routerset_union(routerset_t *target, const routerset_t *source);
int routerset_is_list(const routerset_t *set);
int routerset_needs_geoip(const routerset_t *set);
int routerset_contains_router(const routerset_t *set, routerinfo_t *ri);
int routerset_contains_routerstatus(const routerset_t *set,
                                    routerstatus_t *rs);
int routerset_contains_extendinfo(const routerset_t *set,
                                  const extend_info_t *ei);
void routerset_get_all_routers(smartlist_t *out, const routerset_t *routerset,
                               int running_only);
void routersets_get_disjunction(smartlist_t *target, const smartlist_t *source,
                                const routerset_t *include,
                                const routerset_t *exclude, int running_only);
void routerset_subtract_routers(smartlist_t *out,
                                const routerset_t *routerset);
char *routerset_to_string(const routerset_t *routerset);
void routerset_refresh_countries(routerset_t *target);
int routerset_equal(const routerset_t *old, const routerset_t *new);
void routerset_free(routerset_t *routerset);
void routerinfo_set_country(routerinfo_t *ri);
void routerlist_refresh_countries(void);
void refresh_all_country_info(void);

int hid_serv_get_responsible_directories(smartlist_t *responsible_dirs,
                                         const char *id);
int hid_serv_acting_as_directory(void);
int hid_serv_responsible_for_desc_id(const char *id);

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
} tor_version_t;

int router_get_router_hash(const char *s, size_t s_len, char *digest);
int router_get_dir_hash(const char *s, char *digest);
int router_get_runningrouters_hash(const char *s, char *digest);
int router_get_networkstatus_v2_hash(const char *s, char *digest);
int router_get_networkstatus_v3_hash(const char *s, char *digest);
int router_get_extrainfo_hash(const char *s, char *digest);
int router_append_dirobj_signature(char *buf, size_t buf_len,
                                   const char *digest,
                                   crypto_pk_env_t *private_key);
int router_parse_list_from_string(const char **s, const char *eos,
                                  smartlist_t *dest,
                                  saved_location_t saved_location,
                                  int is_extrainfo,
                                  int allow_annotations,
                                  const char *prepend_annotations);
int router_parse_routerlist_from_directory(const char *s,
                                           routerlist_t **dest,
                                           crypto_pk_env_t *pkey,
                                           int check_version,
                                           int write_to_cache);
int router_parse_runningrouters(const char *str);
int router_parse_directory(const char *str);
routerinfo_t *router_parse_entry_from_string(const char *s, const char *end,
                                             int cache_copy,
                                             int allow_annotations,
                                             const char *prepend_annotations);
extrainfo_t *extrainfo_parse_entry_from_string(const char *s, const char *end,
                         int cache_copy, struct digest_ri_map_t *routermap);
addr_policy_t *router_parse_addr_policy_item_from_string(const char *s,
                                                  int assume_action);
version_status_t tor_version_is_obsolete(const char *myversion,
                                         const char *versionlist);
int tor_version_parse(const char *s, tor_version_t *out);
int tor_version_as_new_as(const char *platform, const char *cutoff);
int tor_version_compare(tor_version_t *a, tor_version_t *b);
void sort_version_list(smartlist_t *lst, int remove_duplicates);
void assert_addr_policy_ok(smartlist_t *t);
void dump_distinct_digest_count(int severity);

networkstatus_v2_t *networkstatus_v2_parse_from_string(const char *s);
networkstatus_t *networkstatus_parse_vote_from_string(const char *s,
                                                 const char **eos_out,
                                                 networkstatus_type_t ns_type);
ns_detached_signatures_t *networkstatus_parse_detached_signatures(
                                          const char *s, const char *eos);

authority_cert_t *authority_cert_parse_from_string(const char *s,
                                                   const char **end_of_string);
int rend_parse_v2_service_descriptor(rend_service_descriptor_t **parsed_out,
                                     char *desc_id_out,
                                     char **intro_points_encrypted_out,
                                     size_t *intro_points_encrypted_size_out,
                                     size_t *encoded_size_out,
                                     const char **next_out, const char *desc);
int rend_decrypt_introduction_points(char **ipos_decrypted,
                                     size_t *ipos_decrypted_size,
                                     const char *descriptor_cookie,
                                     const char *ipos_encrypted,
                                     size_t ipos_encrypted_size);
int rend_parse_introduction_points(rend_service_descriptor_t *parsed,
                                   const char *intro_points_encoded,
                                   size_t intro_points_encoded_size);
int rend_parse_client_keys(strmap_t *parsed_clients, const char *str);

#endif

