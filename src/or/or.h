/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file or.h
 * \brief Master header file for Tor-specific functionality.
 **/

#ifndef TOR_OR_H
#define TOR_OR_H

#include "orconfig.h"

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
#include "lib/cc/torint.h"
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
#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#include <process.h>
#include <direct.h>
#include <windows.h>
#endif /* defined(_WIN32) */

#include "common/util.h"

#include "lib/container/map.h"
#include "lib/container/smartlist.h"
#include "lib/crypt_ops/crypto.h"
#include "lib/defs/dh_sizes.h"
#include "lib/encoding/binascii.h"
#include "lib/net/address.h"

#include "ht.h"

// These, more than other includes, are for keeping the other struct
// definitions working. We should remove them when we minimize our includes.
#include "or/entry_port_cfg_st.h"

struct ed25519_public_key_t;
struct curve25519_public_key_t;

/* These signals are defined to help handle_control_signal work.
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
#define SIGHEARTBEAT 131

#if (SIZEOF_CELL_T != 0)
/* On Irix, stdlib.h defines a cell_t type, so we need to make sure
 * that our stuff always calls cell_t something different. */
#define cell_t tor_cell_t
#endif

#ifdef ENABLE_TOR2WEB_MODE
#define NON_ANONYMOUS_MODE_ENABLED 1
#endif

/** Helper macro: Given a pointer to to.base_, of type from*, return &to. */
#define DOWNCAST(to, ptr) ((to*)SUBTYPE_P(ptr, to, base_))

/** Length of longest allowable configured nickname. */
#define MAX_NICKNAME_LEN 19
/** Length of a router identity encoded as a hexadecimal digest, plus
 * possible dollar sign. */
#define MAX_HEX_NICKNAME_LEN (HEX_DIGEST_LEN+1)
/** Maximum length of verbose router identifier: dollar sign, hex ID digest,
 * equal sign or tilde, nickname. */
#define MAX_VERBOSE_NICKNAME_LEN (1+HEX_DIGEST_LEN+1+MAX_NICKNAME_LEN)

/** For HTTP parsing: Maximum number of bytes we'll accept in the headers
 * of an HTTP request or response. */
#define MAX_HEADERS_SIZE 50000

/** Maximum size, in bytes, of a single router descriptor uploaded to us
 * as a directory authority. Caches and clients fetch whatever descriptors
 * the authorities tell them to fetch, and don't care about size. */
#define MAX_DESCRIPTOR_UPLOAD_SIZE 20000

/** Maximum size of a single extrainfo document, as above. */
#define MAX_EXTRAINFO_UPLOAD_SIZE 50000

/** Minimum lifetime for an onion key in days. */
#define MIN_ONION_KEY_LIFETIME_DAYS (1)

/** Maximum lifetime for an onion key in days. */
#define MAX_ONION_KEY_LIFETIME_DAYS (90)

/** Default lifetime for an onion key in days. */
#define DEFAULT_ONION_KEY_LIFETIME_DAYS (28)

/** Minimum grace period for acceptance of an onion key in days.
 * The maximum value is defined in proposal #274 as being the current network
 * consensus parameter for "onion-key-rotation-days". */
#define MIN_ONION_KEY_GRACE_PERIOD_DAYS (1)

/** Default grace period for acceptance of an onion key in days. */
#define DEFAULT_ONION_KEY_GRACE_PERIOD_DAYS (7)

/** How often we should check the network consensus if it is time to rotate or
 * expire onion keys. */
#define ONION_KEY_CONSENSUS_CHECK_INTERVAL (60*60)

/** How often do we rotate TLS contexts? */
#define MAX_SSL_KEY_LIFETIME_INTERNAL (2*60*60)

/** How old do we allow a router to get before removing it
 * from the router list? In seconds. */
#define ROUTER_MAX_AGE (60*60*48)
/** How old can a router get before we (as a server) will no longer
 * consider it live? In seconds. */
#define ROUTER_MAX_AGE_TO_PUBLISH (60*60*24)
/** How old do we let a saved descriptor get before force-removing it? */
#define OLD_ROUTER_DESC_MAX_AGE (60*60*24*5)

/* Proxy client types */
#define PROXY_NONE 0
#define PROXY_CONNECT 1
#define PROXY_SOCKS4 2
#define PROXY_SOCKS5 3
/* !!!! If there is ever a PROXY_* type over 3, we must grow the proxy_type
 * field in or_connection_t */

/* Pluggable transport proxy type. Don't use this in or_connection_t,
 * instead use the actual underlying proxy type (see above).  */
#define PROXY_PLUGGABLE 4

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
#define RELAY_COMMAND_EXTEND2 14
#define RELAY_COMMAND_EXTENDED2 15

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
#define END_OR_CONN_REASON_PT_MISSING     9 /* PT failed or not available */
#define END_OR_CONN_REASON_MISC           10

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
/** The target address is in a private network (like 127.0.0.1 or 10.0.0.1);
 * you don't want to do that over a randomly chosen exit */
#define END_STREAM_REASON_PRIVATE_ADDR 262
/** This is an HTTP tunnel connection and the client used or misused HTTP in a
 * way we can't handle.
 */
#define END_STREAM_REASON_HTTPPROTOCOL 263

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

/* 'type' values to use in RESOLVED cells.  Specified in tor-spec.txt. */
#define RESOLVED_TYPE_HOSTNAME 0
#define RESOLVED_TYPE_IPV4 4
#define RESOLVED_TYPE_IPV6 6
#define RESOLVED_TYPE_ERROR_TRANSIENT 0xF0
#define RESOLVED_TYPE_ERROR 0xF1

/* Negative reasons are internal: we never send them in a DESTROY or TRUNCATE
 * call; they only go to the controller for tracking  */

/* Closing introduction point that were opened in parallel. */
#define END_CIRC_REASON_IP_NOW_REDUNDANT -4

/** Our post-timeout circuit time measurement period expired.
 * We must give up now */
#define END_CIRC_REASON_MEASUREMENT_EXPIRED -3

/** We couldn't build a path for this circuit. */
#define END_CIRC_REASON_NOPATH          -2
/** Catch-all "other" reason for closing origin circuits. */
#define END_CIRC_AT_ORIGIN              -1

/* Reasons why we (or a remote OR) might close a circuit. See tor-spec.txt
 * section 5.4 for documentation of these. */
#define END_CIRC_REASON_MIN_            0
#define END_CIRC_REASON_NONE            0
#define END_CIRC_REASON_TORPROTOCOL     1
#define END_CIRC_REASON_INTERNAL        2
#define END_CIRC_REASON_REQUESTED       3
#define END_CIRC_REASON_HIBERNATING     4
#define END_CIRC_REASON_RESOURCELIMIT   5
#define END_CIRC_REASON_CONNECTFAILED   6
#define END_CIRC_REASON_OR_IDENTITY     7
#define END_CIRC_REASON_CHANNEL_CLOSED  8
#define END_CIRC_REASON_FINISHED        9
#define END_CIRC_REASON_TIMEOUT         10
#define END_CIRC_REASON_DESTROYED       11
#define END_CIRC_REASON_NOSUCHSERVICE   12
#define END_CIRC_REASON_MAX_            12

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
#define REND_DESC_ID_V2_LEN_BASE32 BASE32_DIGEST_LEN

/** Length of the base32-encoded secret ID part of versioned hidden service
 * descriptors. */
#define REND_SECRET_ID_PART_LEN_BASE32 BASE32_DIGEST_LEN

/** Length of the base32-encoded hash of an introduction point's
 * identity key. */
#define REND_INTRO_POINT_ID_LEN_BASE32 BASE32_DIGEST_LEN

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
  uint8_t descriptor_cookie[REND_DESC_COOKIE_LEN];
  char onion_address[REND_SERVICE_ADDRESS_LEN+1];
  rend_auth_type_t auth_type;
} rend_service_authorization_t;

/** Client- and server-side data that is used for hidden service connection
 * establishment. Not all fields contain data depending on where this struct
 * is used. */
typedef struct rend_data_t {
  /* Hidden service protocol version of this base object. */
  uint32_t version;

  /** List of HSDir fingerprints on which this request has been sent to. This
   * contains binary identity digest of the directory of size DIGEST_LEN. */
  smartlist_t *hsdirs_fp;

  /** Rendezvous cookie used by both, client and service. */
  char rend_cookie[REND_COOKIE_LEN];

  /** Number of streams associated with this rendezvous circuit. */
  int nr_streams;
} rend_data_t;

typedef struct rend_data_v2_t {
  /* Rendezvous base data. */
  rend_data_t base_;

  /** Onion address (without the .onion part) that a client requests. */
  char onion_address[REND_SERVICE_ID_LEN_BASE32+1];

  /** Descriptor ID for each replicas computed from the onion address. If
   * the onion address is empty, this array MUST be empty. We keep them so
   * we know when to purge our entry in the last hsdir request table. */
  char descriptor_id[REND_NUMBER_OF_NON_CONSECUTIVE_REPLICAS][DIGEST_LEN];

  /** (Optional) descriptor cookie that is used by a client. */
  char descriptor_cookie[REND_DESC_COOKIE_LEN];

  /** Authorization type for accessing a service used by a client. */
  rend_auth_type_t auth_type;

  /** Descriptor ID for a client request. The control port command HSFETCH
   * uses this. It's set if the descriptor query should only use this
   * descriptor ID. */
  char desc_id_fetch[DIGEST_LEN];

  /** Hash of the hidden service's PK used by a service. */
  char rend_pk_digest[DIGEST_LEN];
} rend_data_v2_t;

/* From a base rend_data_t object <b>d</d>, return the v2 object. */
static inline
rend_data_v2_t *TO_REND_DATA_V2(const rend_data_t *d)
{
  tor_assert(d);
  tor_assert(d->version == 2);
  return DOWNCAST(rend_data_v2_t, d);
}

/* Stub because we can't include hs_ident.h. */
struct hs_ident_edge_conn_t;
struct hs_ident_dir_conn_t;
struct hs_ident_circuit_t;

typedef struct hsdir_index_t hsdir_index_t;

/** Time interval for tracking replays of DH public keys received in
 * INTRODUCE2 cells.  Used only to avoid launching multiple
 * simultaneous attempts to connect to the same rendezvous point. */
#define REND_REPLAY_TIME_INTERVAL (5 * 60)

/** Used to indicate which way a cell is going on a circuit. */
typedef enum {
  CELL_DIRECTION_IN=1, /**< The cell is moving towards the origin. */
  CELL_DIRECTION_OUT=2, /**< The cell is moving away from the origin. */
} cell_direction_t;

/** Initial value for both sides of a circuit transmission window when the
 * circuit is initialized.  Measured in cells. */
#define CIRCWINDOW_START 1000
#define CIRCWINDOW_START_MIN 100
#define CIRCWINDOW_START_MAX 1000
/** Amount to increment a circuit window when we get a circuit SENDME. */
#define CIRCWINDOW_INCREMENT 100
/** Initial value on both sides of a stream transmission window when the
 * stream is initialized.  Measured in cells. */
#define STREAMWINDOW_START 500
#define STREAMWINDOW_START_MAX 500
/** Amount to increment a stream window when we get a stream SENDME. */
#define STREAMWINDOW_INCREMENT 50

/** Maximum number of queued cells on a circuit for which we are the
 * midpoint before we give up and kill it.  This must be >= circwindow
 * to avoid killing innocent circuits, and >= circwindow*2 to give
 * leaky-pipe a chance of working someday. The ORCIRC_MAX_MIDDLE_KILL_THRESH
 * ratio controls the margin of error between emitting a warning and
 * killing the circuit.
 */
#define ORCIRC_MAX_MIDDLE_CELLS (CIRCWINDOW_START_MAX*2)
/** Ratio of hard (circuit kill) to soft (warning) thresholds for the
 * ORCIRC_MAX_MIDDLE_CELLS tests.
 */
#define ORCIRC_MAX_MIDDLE_KILL_THRESH (1.1f)

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
#define CELL_CREATE2 10
#define CELL_CREATED2 11
#define CELL_PADDING_NEGOTIATE 12

#define CELL_VPADDING 128
#define CELL_CERTS 129
#define CELL_AUTH_CHALLENGE 130
#define CELL_AUTHENTICATE 131
#define CELL_AUTHORIZE 132
#define CELL_COMMAND_MAX_ 132

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
/** Number of bytes in a cell transmitted over the network, in the longest
 * form */
#define CELL_MAX_NETWORK_SIZE 514

/** Maximum length of a header on a variable-length cell. */
#define VAR_CELL_MAX_HEADER_SIZE 7

static int get_cell_network_size(int wide_circ_ids);
static inline int get_cell_network_size(int wide_circ_ids)
{
  return wide_circ_ids ? CELL_MAX_NETWORK_SIZE : CELL_MAX_NETWORK_SIZE - 2;
}
static int get_var_cell_header_size(int wide_circ_ids);
static inline int get_var_cell_header_size(int wide_circ_ids)
{
  return wide_circ_ids ? VAR_CELL_MAX_HEADER_SIZE :
    VAR_CELL_MAX_HEADER_SIZE - 2;
}
static int get_circ_id_size(int wide_circ_ids);
static inline int get_circ_id_size(int wide_circ_ids)
{
  return wide_circ_ids ? 4 : 2;
}

/** Number of bytes in a relay cell's header (not including general cell
 * header). */
#define RELAY_HEADER_SIZE (1+2+2+4+2)
/** Largest number of bytes that can fit in a relay cell payload. */
#define RELAY_PAYLOAD_SIZE (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE)

/** Identifies a circuit on an or_connection */
typedef uint32_t circid_t;
/** Identifies a stream on a circuit */
typedef uint16_t streamid_t;

/* channel_t typedef; struct channel_s is in channel.h */

typedef struct channel_s channel_t;

/* channel_listener_t typedef; struct channel_listener_s is in channel.h */

typedef struct channel_listener_s channel_listener_t;

/* TLS channel stuff */

typedef struct channel_tls_s channel_tls_t;

/* circuitmux_t typedef; struct circuitmux_s is in circuitmux.h */

typedef struct circuitmux_s circuitmux_t;

typedef struct cell_t cell_t;
typedef struct var_cell_t var_cell_t;
typedef struct packed_cell_t packed_cell_t;
typedef struct cell_queue_t cell_queue_t;
typedef struct destroy_cell_t destroy_cell_t;
typedef struct destroy_cell_queue_t destroy_cell_queue_t;
typedef struct ext_or_cmd_t ext_or_cmd_t;

/** Beginning of a RELAY cell payload. */
typedef struct {
  uint8_t command; /**< The end-to-end relay command. */
  uint16_t recognized; /**< Used to tell whether cell is for us. */
  streamid_t stream_id; /**< Which stream is this cell associated with? */
  char integrity[4]; /**< Used to tell whether cell is corrupted. */
  uint16_t length; /**< How long is the payload body? */
} relay_header_t;

typedef struct socks_request_t socks_request_t;
typedef struct entry_port_cfg_t entry_port_cfg_t;
typedef struct server_port_cfg_t server_port_cfg_t;

/** Minimum length of the random part of an AUTH_CHALLENGE cell. */
#define OR_AUTH_CHALLENGE_LEN 32

/**
 * @name Certificate types for CERTS cells.
 *
 * These values are defined by the protocol, and affect how an X509
 * certificate in a CERTS cell is interpreted and used.
 *
 * @{ */
/** A certificate that authenticates a TLS link key.  The subject key
 * must match the key used in the TLS handshake; it must be signed by
 * the identity key. */
#define OR_CERT_TYPE_TLS_LINK 1
/** A self-signed identity certificate. The subject key must be a
 * 1024-bit RSA key. */
#define OR_CERT_TYPE_ID_1024 2
/** A certificate that authenticates a key used in an AUTHENTICATE cell
 * in the v3 handshake.  The subject key must be a 1024-bit RSA key; it
 * must be signed by the identity key */
#define OR_CERT_TYPE_AUTH_1024 3
/* DOCDOC */
#define OR_CERT_TYPE_RSA_ED_CROSSCERT 7
/**@}*/

/** The first supported type of AUTHENTICATE cell.  It contains
 * a bunch of structures signed with an RSA1024 key.  The signed
 * structures include a HMAC using negotiated TLS secrets, and a digest
 * of all cells sent or received before the AUTHENTICATE cell (including
 * the random server-generated AUTH_CHALLENGE cell).
 */
#define AUTHTYPE_RSA_SHA256_TLSSECRET 1
/** As AUTHTYPE_RSA_SHA256_TLSSECRET, but instead of using the
 * negotiated TLS secrets, uses exported keying material from the TLS
 * session as described in RFC 5705.
 *
 * Not used by today's tors, since everything that supports this
 * also supports ED25519_SHA256_5705, which is better.
 **/
#define AUTHTYPE_RSA_SHA256_RFC5705 2
/** As AUTHTYPE_RSA_SHA256_RFC5705, but uses an Ed25519 identity key to
 * authenticate.  */
#define AUTHTYPE_ED25519_SHA256_RFC5705 3
/*
 * NOTE: authchallenge_type_is_better() relies on these AUTHTYPE codes
 * being sorted in order of preference.  If we someday add one with
 * a higher numerical value that we don't like as much, we should revise
 * authchallenge_type_is_better().
 */

/** The length of the part of the AUTHENTICATE cell body that the client and
 * server can generate independently (when using RSA_SHA256_TLSSECRET). It
 * contains everything except the client's timestamp, the client's randomly
 * generated nonce, and the signature. */
#define V3_AUTH_FIXED_PART_LEN (8+(32*6))
/** The length of the part of the AUTHENTICATE cell body that the client
 * signs. */
#define V3_AUTH_BODY_LEN (V3_AUTH_FIXED_PART_LEN + 8 + 16)

typedef struct or_handshake_certs_t or_handshake_certs_t;
typedef struct or_handshake_state_t or_handshake_state_t;

/** Length of Extended ORPort connection identifier. */
#define EXT_OR_CONN_ID_LEN DIGEST_LEN /* 20 */
/*
 * OR_CONN_HIGHWATER and OR_CONN_LOWWATER moved from connection_or.c so
 * channeltls.c can see them too.
 */

/** When adding cells to an OR connection's outbuf, keep adding until the
 * outbuf is at least this long, or we run out of cells. */
#define OR_CONN_HIGHWATER (32*1024)

/** Add cells to an OR connection's outbuf whenever the outbuf's data length
 * drops below this size. */
#define OR_CONN_LOWWATER (16*1024)

typedef struct connection_t connection_t;
typedef struct control_connection_t control_connection_t;
typedef struct dir_connection_t dir_connection_t;
typedef struct edge_connection_t edge_connection_t;
typedef struct entry_connection_t entry_connection_t;
typedef struct listener_connection_t listener_connection_t;
typedef struct or_connection_t or_connection_t;

/** Cast a connection_t subtype pointer to a connection_t **/
#define TO_CONN(c) (&(((c)->base_)))

/** Cast a entry_connection_t subtype pointer to a connection_t **/
#define ENTRY_TO_CONN(c) (TO_CONN(ENTRY_TO_EDGE_CONN(c)))

typedef struct addr_policy_t addr_policy_t;

typedef struct cached_dir_t cached_dir_t;

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
#define saved_location_bitfield_t ENUM_BF(saved_location_t)

/** Enumeration: what directory object is being downloaded?
 * This determines which schedule is selected to perform the download. */
typedef enum {
  DL_SCHED_GENERIC = 0,
  DL_SCHED_CONSENSUS = 1,
  DL_SCHED_BRIDGE = 2,
} download_schedule_t;
#define download_schedule_bitfield_t ENUM_BF(download_schedule_t)

/** Enumeration: is the download schedule for downloading from an authority,
 * or from any available directory mirror?
 * During bootstrap, "any" means a fallback (or an authority, if there
 * are no fallbacks).
 * When we have a valid consensus, "any" means any directory server. */
typedef enum {
  DL_WANT_ANY_DIRSERVER = 0,
  DL_WANT_AUTHORITY = 1,
} download_want_authority_t;
#define download_want_authority_bitfield_t \
                                        ENUM_BF(download_want_authority_t)

/** Enumeration: do we want to increment the schedule position each time a
 * connection is attempted (these attempts can be concurrent), or do we want
 * to increment the schedule position after a connection fails? */
typedef enum {
  DL_SCHED_INCREMENT_FAILURE = 0,
  DL_SCHED_INCREMENT_ATTEMPT = 1,
} download_schedule_increment_t;
#define download_schedule_increment_bitfield_t \
                                        ENUM_BF(download_schedule_increment_t)

typedef struct download_status_t download_status_t;

/** If n_download_failures is this high, the download can never happen. */
#define IMPOSSIBLE_TO_DOWNLOAD 255

/** The max size we expect router descriptor annotations we create to
 * be. We'll accept larger ones if we see them on disk, but we won't
 * create any that are larger than this. */
#define ROUTER_ANNOTATION_BUF_LEN 256

typedef struct signed_descriptor_t signed_descriptor_t;

/** A signed integer representing a country code. */
typedef int16_t country_t;

/** Flags used to summarize the declared protocol versions of a relay,
 * so we don't need to parse them again and again. */
typedef struct protover_summary_flags_t {
  /** True iff we have a proto line for this router, or a versions line
   * from which we could infer the protocols. */
  unsigned int protocols_known:1;

  /** True iff this router has a version or protocol list that allows it to
   * accept EXTEND2 cells. This requires Relay=2. */
  unsigned int supports_extend2_cells:1;

  /** True iff this router has a protocol list that allows it to negotiate
   * ed25519 identity keys on a link handshake with us. This
   * requires LinkAuth=3. */
  unsigned int supports_ed25519_link_handshake_compat:1;

  /** True iff this router has a protocol list that allows it to negotiate
   * ed25519 identity keys on a link handshake, at all. This requires some
   * LinkAuth=X for X >= 3. */
  unsigned int supports_ed25519_link_handshake_any:1;

  /** True iff this router has a protocol list that allows it to be an
   * introduction point supporting ed25519 authentication key which is part of
   * the v3 protocol detailed in proposal 224. This requires HSIntro=4. */
  unsigned int supports_ed25519_hs_intro : 1;

  /** True iff this router has a protocol list that allows it to be an hidden
   * service directory supporting version 3 as seen in proposal 224. This
   * requires HSDir=2. */
  unsigned int supports_v3_hsdir : 1;

  /** True iff this router has a protocol list that allows it to be an hidden
   * service rendezvous point supporting version 3 as seen in proposal 224.
   * This requires HSRend=2. */
  unsigned int supports_v3_rendezvous_point: 1;
} protover_summary_flags_t;

typedef struct routerinfo_t routerinfo_t;
typedef struct extrainfo_t extrainfo_t;
typedef struct routerstatus_t routerstatus_t;

typedef struct microdesc_t microdesc_t;
typedef struct node_t node_t;
typedef struct vote_microdesc_hash_t vote_microdesc_hash_t;
typedef struct vote_routerstatus_t vote_routerstatus_t;
typedef struct document_signature_t document_signature_t;
typedef struct networkstatus_voter_info_t networkstatus_voter_info_t;
typedef struct networkstatus_sr_info_t networkstatus_sr_info_t;

/** Enumerates recognized flavors of a consensus networkstatus document.  All
 * flavors of a consensus are generated from the same set of votes, but they
 * present different types information to different versions of Tor. */
typedef enum {
  FLAV_NS = 0,
  FLAV_MICRODESC = 1,
} consensus_flavor_t;

/** How many different consensus flavors are there? */
#define N_CONSENSUS_FLAVORS ((int)(FLAV_MICRODESC)+1)

typedef struct networkstatus_t networkstatus_t;
typedef struct ns_detached_signatures_t ns_detached_signatures_t;

/** Allowable types of desc_store_t. */
typedef enum store_type_t {
  ROUTER_STORE = 0,
  EXTRAINFO_STORE = 1
} store_type_t;

typedef struct desc_store_t desc_store_t;
typedef struct routerlist_t routerlist_t;
typedef struct extend_info_t extend_info_t;
typedef struct authority_cert_t authority_cert_t;

/** Bitfield enum type listing types of information that directory authorities
 * can be authoritative about, and that directory caches may or may not cache.
 *
 * Note that the granularity here is based on authority granularity and on
 * cache capabilities.  Thus, one particular bit may correspond in practice to
 * a few types of directory info, so long as every authority that pronounces
 * officially about one of the types prounounces officially about all of them,
 * and so long as every cache that caches one of them caches all of them.
 */
typedef enum {
  NO_DIRINFO      = 0,
  /** Serves/signs v3 directory information: votes, consensuses, certs */
  V3_DIRINFO      = 1 << 2,
  /** Serves bridge descriptors. */
  BRIDGE_DIRINFO  = 1 << 4,
  /** Serves extrainfo documents. */
  EXTRAINFO_DIRINFO=1 << 5,
  /** Serves microdescriptors. */
  MICRODESC_DIRINFO=1 << 6,
} dirinfo_type_t;

#define ALL_DIRINFO ((dirinfo_type_t)((1<<7)-1))

#define CRYPT_PATH_MAGIC 0x70127012u

struct fast_handshake_state_t;
struct ntor_handshake_state_t;
struct crypto_dh_t;
#define ONION_HANDSHAKE_TYPE_TAP  0x0000
#define ONION_HANDSHAKE_TYPE_FAST 0x0001
#define ONION_HANDSHAKE_TYPE_NTOR 0x0002
#define MAX_ONION_HANDSHAKE_TYPE 0x0002
typedef struct {
  uint16_t tag;
  union {
    struct fast_handshake_state_t *fast;
    struct crypto_dh_t *tap;
    struct ntor_handshake_state_t *ntor;
  } u;
} onion_handshake_state_t;

typedef struct relay_crypto_t relay_crypto_t;
typedef struct crypt_path_t crypt_path_t;
typedef struct crypt_path_reference_t crypt_path_reference_t;

#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)

typedef struct cpath_build_state_t cpath_build_state_t;

struct create_cell_t;

/** Entry in the cell stats list of a circuit; used only if CELL_STATS
 * events are enabled. */
typedef struct testing_cell_stats_entry_t {
  uint8_t command; /**< cell command number. */
  /** Waiting time in centiseconds if this event is for a removed cell,
   * or 0 if this event is for adding a cell to the queue.  22 bits can
   * store more than 11 hours, enough to assume that a circuit with this
   * delay would long have been closed. */
  unsigned int waiting_time:22;
  unsigned int removed:1; /**< 0 for added to, 1 for removed from queue. */
  unsigned int exitward:1; /**< 0 for app-ward, 1 for exit-ward. */
} testing_cell_stats_entry_t;

typedef struct circuit_t circuit_t;
typedef struct origin_circuit_t origin_circuit_t;
typedef struct or_circuit_t or_circuit_t;

/** Largest number of relay_early cells that we can send on a given
 * circuit. */
#define MAX_RELAY_EARLY_CELLS_PER_CIRCUIT 8

/**
 * Describes the circuit building process in simplified terms based
 * on the path bias accounting state for a circuit.
 *
 * NOTE: These state values are enumerated in the order for which we
 * expect circuits to transition through them. If you add states,
 * you need to preserve this overall ordering. The various pathbias
 * state transition and accounting functions (pathbias_mark_* and
 * pathbias_count_*) contain ordinal comparisons to enforce proper
 * state transitions for corrections.
 *
 * This state machine and the associated logic was created to prevent
 * miscounting due to unknown cases of circuit reuse. See also tickets
 * #6475 and #7802.
 */
typedef enum {
    /** This circuit is "new". It has not yet completed a first hop
     * or been counted by the path bias code. */
    PATH_STATE_NEW_CIRC = 0,
    /** This circuit has completed one/two hops, and has been counted by
     * the path bias logic. */
    PATH_STATE_BUILD_ATTEMPTED = 1,
    /** This circuit has been completely built */
    PATH_STATE_BUILD_SUCCEEDED = 2,
    /** Did we try to attach any SOCKS streams or hidserv introductions to
      * this circuit?
      *
      * Note: If we ever implement end-to-end stream timing through test
      * stream probes (#5707), we must *not* set this for those probes
      * (or any other automatic streams) because the adversary could
      * just tag at a later point.
      */
    PATH_STATE_USE_ATTEMPTED = 3,
    /** Did any SOCKS streams or hidserv introductions actually succeed on
      * this circuit?
      *
      * If any streams detatch/fail from this circuit, the code transitions
      * the circuit back to PATH_STATE_USE_ATTEMPTED to ensure we probe. See
      * pathbias_mark_use_rollback() for that.
      */
    PATH_STATE_USE_SUCCEEDED = 4,

    /**
     * This is a special state to indicate that we got a corrupted
     * relay cell on a circuit and we don't intend to probe it.
     */
    PATH_STATE_USE_FAILED = 5,

    /**
     * This is a special state to indicate that we already counted
     * the circuit. Used to guard against potential state machine
     * violations.
     */
    PATH_STATE_ALREADY_COUNTED = 6,
} path_state_t;
#define path_state_bitfield_t ENUM_BF(path_state_t)

#if REND_COOKIE_LEN != DIGEST_LEN
#error "The REND_TOKEN_LEN macro assumes REND_COOKIE_LEN == DIGEST_LEN"
#endif
#define REND_TOKEN_LEN DIGEST_LEN

/** Convert a circuit subtype to a circuit_t. */
#define TO_CIRCUIT(x)  (&((x)->base_))

/** @name Isolation flags

    Ways to isolate client streams

    @{
*/
/** Isolate based on destination port */
#define ISO_DESTPORT    (1u<<0)
/** Isolate based on destination address */
#define ISO_DESTADDR    (1u<<1)
/** Isolate based on SOCKS authentication */
#define ISO_SOCKSAUTH   (1u<<2)
/** Isolate based on client protocol choice */
#define ISO_CLIENTPROTO (1u<<3)
/** Isolate based on client address */
#define ISO_CLIENTADDR  (1u<<4)
/** Isolate based on session group (always on). */
#define ISO_SESSIONGRP  (1u<<5)
/** Isolate based on newnym epoch (always on). */
#define ISO_NYM_EPOCH   (1u<<6)
/** Isolate all streams (Internal only). */
#define ISO_STREAM      (1u<<7)
/**@}*/

/** Default isolation level for ports. */
#define ISO_DEFAULT (ISO_CLIENTADDR|ISO_SOCKSAUTH|ISO_SESSIONGRP|ISO_NYM_EPOCH)

/** Indicates that we haven't yet set a session group on a port_cfg_t. */
#define SESSION_GROUP_UNSET -1
/** Session group reserved for directory connections */
#define SESSION_GROUP_DIRCONN -2
/** Session group reserved for resolve requests launched by a controller */
#define SESSION_GROUP_CONTROL_RESOLVE -3
/** First automatically allocated session group number */
#define SESSION_GROUP_FIRST_AUTO -4

typedef struct port_cfg_t port_cfg_t;
typedef struct routerset_t routerset_t;

/** A magic value for the (Socks|OR|...)Port options below, telling Tor
 * to pick its own port. */
#define CFG_AUTO_PORT 0xc4005e

/** Enumeration of outbound address configuration types:
 * Exit-only, OR-only, or both */
typedef enum {OUTBOUND_ADDR_EXIT, OUTBOUND_ADDR_OR,
              OUTBOUND_ADDR_EXIT_AND_OR,
              OUTBOUND_ADDR_MAX} outbound_addr_t;

struct config_line_t;

/** Configuration options for a Tor process. */
typedef struct {
  uint32_t magic_;

  /** What should the tor process actually do? */
  enum {
    CMD_RUN_TOR=0, CMD_LIST_FINGERPRINT, CMD_HASH_PASSWORD,
    CMD_VERIFY_CONFIG, CMD_RUN_UNITTESTS, CMD_DUMP_CONFIG,
    CMD_KEYGEN,
    CMD_KEY_EXPIRATION,
  } command;
  char *command_arg; /**< Argument for command-line option. */

  struct config_line_t *Logs; /**< New-style list of configuration lines
                        * for logs */
  int LogTimeGranularity; /**< Log resolution in milliseconds. */

  int LogMessageDomains; /**< Boolean: Should we log the domain(s) in which
                          * each log message occurs? */
  int TruncateLogFile; /**< Boolean: Should we truncate the log file
                            before we start writing? */
  char *SyslogIdentityTag; /**< Identity tag to add for syslog logging. */
  char *AndroidIdentityTag; /**< Identity tag to add for Android logging. */

  char *DebugLogFile; /**< Where to send verbose log messages. */
  char *DataDirectory_option; /**< Where to store long-term data, as
                               * configured by the user. */
  char *DataDirectory; /**< Where to store long-term data, as modified. */
  int DataDirectoryGroupReadable; /**< Boolean: Is the DataDirectory g+r? */

  char *KeyDirectory_option; /**< Where to store keys, as
                               * configured by the user. */
  char *KeyDirectory; /**< Where to store keys data, as modified. */
  int KeyDirectoryGroupReadable; /**< Boolean: Is the KeyDirectory g+r? */

  char *CacheDirectory_option; /**< Where to store cached data, as
                               * configured by the user. */
  char *CacheDirectory; /**< Where to store cached data, as modified. */
  int CacheDirectoryGroupReadable; /**< Boolean: Is the CacheDirectory g+r? */

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
  routerset_t *ExcludeExitNodesUnion_;

  int DisableAllSwap; /**< Boolean: Attempt to call mlockall() on our
                       * process for all current and future memory. */

  struct config_line_t *ExitPolicy; /**< Lists of exit policy components. */
  int ExitPolicyRejectPrivate; /**< Should we not exit to reserved private
                                * addresses, and our own published addresses?
                                */
  int ExitPolicyRejectLocalInterfaces; /**< Should we not exit to local
                                        * interface addresses?
                                        * Includes OutboundBindAddresses and
                                        * configured ports. */
  int ReducedExitPolicy; /**<Should we use the Reduced Exit Policy? */
  struct config_line_t *SocksPolicy; /**< Lists of socks policy components */
  struct config_line_t *DirPolicy; /**< Lists of dir policy components */
  /** Local address to bind outbound sockets */
  struct config_line_t *OutboundBindAddress;
  /** Local address to bind outbound relay sockets */
  struct config_line_t *OutboundBindAddressOR;
  /** Local address to bind outbound exit sockets */
  struct config_line_t *OutboundBindAddressExit;
  /** Addresses derived from the various OutboundBindAddress lines.
   * [][0] is IPv4, [][1] is IPv6
   */
  tor_addr_t OutboundBindAddresses[OUTBOUND_ADDR_MAX][2];
  /** Directory server only: which versions of
   * Tor should we tell users to run? */
  struct config_line_t *RecommendedVersions;
  struct config_line_t *RecommendedClientVersions;
  struct config_line_t *RecommendedServerVersions;
  struct config_line_t *RecommendedPackages;
  /** Whether dirservers allow router descriptors with private IPs. */
  int DirAllowPrivateAddresses;
  /** Whether routers accept EXTEND cells to routers with private IPs. */
  int ExtendAllowPrivateAddresses;
  char *User; /**< Name of user to run Tor as. */
   /** Ports to listen on for OR connections. */
  struct config_line_t *ORPort_lines;
  /** Ports to listen on for extended OR connections. */
  struct config_line_t *ExtORPort_lines;
  /** Ports to listen on for SOCKS connections. */
  struct config_line_t *SocksPort_lines;
  /** Ports to listen on for transparent pf/netfilter connections. */
  struct config_line_t *TransPort_lines;
  char *TransProxyType; /**< What kind of transparent proxy
                         * implementation are we using? */
  /** Parsed value of TransProxyType. */
  enum {
    TPT_DEFAULT,
    TPT_PF_DIVERT,
    TPT_IPFW,
    TPT_TPROXY,
  } TransProxyType_parsed;
  /** Ports to listen on for transparent natd connections. */
  struct config_line_t *NATDPort_lines;
  /** Ports to listen on for HTTP Tunnel connections. */
  struct config_line_t *HTTPTunnelPort_lines;
  struct config_line_t *ControlPort_lines; /**< Ports to listen on for control
                               * connections. */
  /** List of Unix Domain Sockets to listen on for control connections. */
  struct config_line_t *ControlSocket;

  int ControlSocketsGroupWritable; /**< Boolean: Are control sockets g+rw? */
  int UnixSocksGroupWritable; /**< Boolean: Are SOCKS Unix sockets g+rw? */
  /** Ports to listen on for directory connections. */
  struct config_line_t *DirPort_lines;
  /** Ports to listen on for DNS requests. */
  struct config_line_t *DNSPort_lines;

  /* MaxMemInQueues value as input by the user. We clean this up to be
   * MaxMemInQueues. */
  uint64_t MaxMemInQueues_raw;
  uint64_t MaxMemInQueues;/**< If we have more memory than this allocated
                            * for queues and buffers, run the OOM handler */
  /** Above this value, consider ourselves low on RAM. */
  uint64_t MaxMemInQueues_low_threshold;

  /** @name port booleans
   *
   * Derived booleans: For server ports and ControlPort, true iff there is a
   * non-listener port on an AF_INET or AF_INET6 address of the given type
   * configured in one of the _lines options above.
   * For client ports, also true if there is a unix socket configured.
   * If you are checking for client ports, you may want to use:
   *   SocksPort_set || TransPort_set || NATDPort_set || DNSPort_set ||
   *   HTTPTunnelPort_set
   * rather than SocksPort_set.
   *
   * @{
   */
  unsigned int ORPort_set : 1;
  unsigned int SocksPort_set : 1;
  unsigned int TransPort_set : 1;
  unsigned int NATDPort_set : 1;
  unsigned int ControlPort_set : 1;
  unsigned int DirPort_set : 1;
  unsigned int DNSPort_set : 1;
  unsigned int ExtORPort_set : 1;
  unsigned int HTTPTunnelPort_set : 1;
  /**@}*/

  int AssumeReachable; /**< Whether to publish our descriptor regardless. */
  int AuthoritativeDir; /**< Boolean: is this an authoritative directory? */
  int V3AuthoritativeDir; /**< Boolean: is this an authoritative directory
                           * for version 3 directories? */
  int VersioningAuthoritativeDir; /**< Boolean: is this an authoritative
                                   * directory that's willing to recommend
                                   * versions? */
  int BridgeAuthoritativeDir; /**< Boolean: is this an authoritative directory
                               * that aggregates bridge descriptors? */

  /** If set on a bridge relay, it will include this value on a new
   * "bridge-distribution-request" line in its bridge descriptor. */
  char *BridgeDistribution;

  /** If set on a bridge authority, it will answer requests on its dirport
   * for bridge statuses -- but only if the requests use this password. */
  char *BridgePassword;
  /** If BridgePassword is set, this is a SHA256 digest of the basic http
   * authenticator for it. Used so we can do a time-independent comparison. */
  char *BridgePassword_AuthDigest_;

  int UseBridges; /**< Boolean: should we start all circuits with a bridge? */
  struct config_line_t *Bridges; /**< List of bootstrap bridge addresses. */

  struct config_line_t *ClientTransportPlugin; /**< List of client
                                           transport plugins. */

  struct config_line_t *ServerTransportPlugin; /**< List of client
                                           transport plugins. */

  /** List of TCP/IP addresses that transports should listen at. */
  struct config_line_t *ServerTransportListenAddr;

  /** List of options that must be passed to pluggable transports. */
  struct config_line_t *ServerTransportOptions;

  int BridgeRelay; /**< Boolean: are we acting as a bridge relay? We make
                    * this explicit so we can change how we behave in the
                    * future. */

  /** Boolean: if we know the bridge's digest, should we get new
   * descriptors from the bridge authorities or from the bridge itself? */
  int UpdateBridgesFromAuthority;

  int AvoidDiskWrites; /**< Boolean: should we never cache things to disk?
                        * Not used yet. */
  int ClientOnly; /**< Boolean: should we never evolve into a server role? */

  int ReducedConnectionPadding; /**< Boolean: Should we try to keep connections
                                  open shorter and pad them less against
                                  connection-level traffic analysis? */
  /** Autobool: if auto, then connection padding will be negotiated by client
   * and server. If 0, it will be fully disabled. If 1, the client will still
   * pad to the server regardless of server support. */
  int ConnectionPadding;

  /** To what authority types do we publish our descriptor? Choices are
   * "v1", "v2", "v3", "bridge", or "". */
  smartlist_t *PublishServerDescriptor;
  /** A bitfield of authority types, derived from PublishServerDescriptor. */
  dirinfo_type_t PublishServerDescriptor_;
  /** Boolean: do we publish hidden service descriptors to the HS auths? */
  int PublishHidServDescriptors;
  int FetchServerDescriptors; /**< Do we fetch server descriptors as normal? */
  int FetchHidServDescriptors; /**< and hidden service descriptors? */

  int MinUptimeHidServDirectoryV2; /**< As directory authority, accept hidden
                                    * service directories after what time? */

  int FetchUselessDescriptors; /**< Do we fetch non-running descriptors too? */
  int AllDirActionsPrivate; /**< Should every directory action be sent
                             * through a Tor circuit? */

  /** Run in 'tor2web mode'? (I.e. only make client connections to hidden
   * services, and use a single hop for all hidden-service-related
   * circuits.) */
  int Tor2webMode;

  /** A routerset that should be used when picking RPs for HS circuits. */
  routerset_t *Tor2webRendezvousPoints;

  /** A routerset that should be used when picking middle nodes for HS
   *  circuits. */
  routerset_t *HSLayer2Nodes;

  /** A routerset that should be used when picking third-hop nodes for HS
   *  circuits. */
  routerset_t *HSLayer3Nodes;

  /** Onion Services in HiddenServiceSingleHopMode make one-hop (direct)
   * circuits between the onion service server, and the introduction and
   * rendezvous points. (Onion service descriptors are still posted using
   * 3-hop paths, to avoid onion service directories blocking the service.)
   * This option makes every hidden service instance hosted by
   * this tor instance a Single Onion Service.
   * HiddenServiceSingleHopMode requires HiddenServiceNonAnonymousMode to be
   * set to 1.
   * Use rend_service_allow_non_anonymous_connection() or
   * rend_service_reveal_startup_time() instead of using this option directly.
   */
  int HiddenServiceSingleHopMode;
  /* Makes hidden service clients and servers non-anonymous on this tor
   * instance. Allows the non-anonymous HiddenServiceSingleHopMode. Enables
   * non-anonymous behaviour in the hidden service protocol.
   * Use rend_service_non_anonymous_mode_enabled() instead of using this option
   * directly.
   */
  int HiddenServiceNonAnonymousMode;

  int ConnLimit; /**< Demanded minimum number of simultaneous connections. */
  int ConnLimit_; /**< Maximum allowed number of simultaneous connections. */
  int ConnLimit_high_thresh; /**< start trying to lower socket usage if we
                              *   have this many. */
  int ConnLimit_low_thresh; /**< try to get down to here after socket
                             *   exhaustion. */
  int RunAsDaemon; /**< If true, run in the background. (Unix only) */
  int FascistFirewall; /**< Whether to prefer ORs reachable on open ports. */
  smartlist_t *FirewallPorts; /**< Which ports our firewall allows
                               * (strings). */
   /** IP:ports our firewall allows. */
  struct config_line_t *ReachableAddresses;
  struct config_line_t *ReachableORAddresses; /**< IP:ports for OR conns. */
  struct config_line_t *ReachableDirAddresses; /**< IP:ports for Dir conns. */

  int ConstrainedSockets; /**< Shrink xmit and recv socket buffers. */
  uint64_t ConstrainedSockSize; /**< Size of constrained buffers. */

  /** Whether we should drop exit streams from Tors that we don't know are
   * relays.  One of "0" (never refuse), "1" (always refuse), or "-1" (do
   * what the consensus says, defaulting to 'refuse' if the consensus says
   * nothing). */
  int RefuseUnknownExits;

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
  struct config_line_t *AddressMap; /**< List of address map directives. */
  int AutomapHostsOnResolve; /**< If true, when we get a resolve request for a
                              * hostname ending with one of the suffixes in
                              * <b>AutomapHostsSuffixes</b>, map it to a
                              * virtual address. */
  /** List of suffixes for <b>AutomapHostsOnResolve</b>.  The special value
   * "." means "match everything." */
  smartlist_t *AutomapHostsSuffixes;
  int RendPostPeriod; /**< How often do we post each rendezvous service
                       * descriptor? Remember to publish them independently. */
  int KeepalivePeriod; /**< How often do we send padding cells to keep
                        * connections alive? */
  int SocksTimeout; /**< How long do we let a socks connection wait
                     * unattached before we fail it? */
  int LearnCircuitBuildTimeout; /**< If non-zero, we attempt to learn a value
                                 * for CircuitBuildTimeout based on timeout
                                 * history. Use circuit_build_times_disabled()
                                 * rather than checking this value directly. */
  int CircuitBuildTimeout; /**< Cull non-open circuits that were born at
                            * least this many seconds ago. Used until
                            * adaptive algorithm learns a new value. */
  int CircuitsAvailableTimeout; /**< Try to have an open circuit for at
                                     least this long after last activity */
  int CircuitStreamTimeout; /**< If non-zero, detach streams from circuits
                             * and try a new circuit if the stream has been
                             * waiting for this many seconds. If zero, use
                             * our default internal timeout schedule. */
  int MaxOnionQueueDelay; /*< DOCDOC */
  int NewCircuitPeriod; /**< How long do we use a circuit before building
                         * a new one? */
  int MaxCircuitDirtiness; /**< Never use circs that were first used more than
                                this interval ago. */
  uint64_t BandwidthRate; /**< How much bandwidth, on average, are we willing
                           * to use in a second? */
  uint64_t BandwidthBurst; /**< How much bandwidth, at maximum, are we willing
                            * to use in a second? */
  uint64_t MaxAdvertisedBandwidth; /**< How much bandwidth are we willing to
                                    * tell other nodes we have? */
  uint64_t RelayBandwidthRate; /**< How much bandwidth, on average, are we
                                 * willing to use for all relayed conns? */
  uint64_t RelayBandwidthBurst; /**< How much bandwidth, at maximum, will we
                                 * use in a second for all relayed conns? */
  uint64_t PerConnBWRate; /**< Long-term bw on a single TLS conn, if set. */
  uint64_t PerConnBWBurst; /**< Allowed burst on a single TLS conn, if set. */
  int NumCPUs; /**< How many CPUs should we try to use? */
  struct config_line_t *RendConfigLines; /**< List of configuration lines
                                          * for rendezvous services. */
  struct config_line_t *HidServAuth; /**< List of configuration lines for
                               * client-side authorizations for hidden
                               * services */
  char *ContactInfo; /**< Contact info to be published in the directory. */

  int HeartbeatPeriod; /**< Log heartbeat messages after this many seconds
                        * have passed. */
  int MainloopStats; /**< Log main loop statistics as part of the
                      * heartbeat messages. */

  char *HTTPProxy; /**< hostname[:port] to use as http proxy, if any. */
  tor_addr_t HTTPProxyAddr; /**< Parsed IPv4 addr for http proxy, if any. */
  uint16_t HTTPProxyPort; /**< Parsed port for http proxy, if any. */
  char *HTTPProxyAuthenticator; /**< username:password string, if any. */

  char *HTTPSProxy; /**< hostname[:port] to use as https proxy, if any. */
  tor_addr_t HTTPSProxyAddr; /**< Parsed addr for https proxy, if any. */
  uint16_t HTTPSProxyPort; /**< Parsed port for https proxy, if any. */
  char *HTTPSProxyAuthenticator; /**< username:password string, if any. */

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
  struct config_line_t *DirAuthorities;

  /** List of fallback directory servers */
  struct config_line_t *FallbackDir;
  /** Whether to use the default hard-coded FallbackDirs */
  int UseDefaultFallbackDirs;

  /** Weight to apply to all directory authority rates if considering them
   * along with fallbackdirs */
  double DirAuthorityFallbackRate;

  /** If set, use these main (currently v3) directory authorities and
   * not the default ones. */
  struct config_line_t *AlternateDirAuthority;

  /** If set, use these bridge authorities and not the default one. */
  struct config_line_t *AlternateBridgeAuthority;

  struct config_line_t *MyFamily_lines; /**< Declared family for this OR. */
  struct config_line_t *MyFamily; /**< Declared family for this OR,
                                     normalized */
  struct config_line_t *NodeFamilies; /**< List of config lines for
                                * node families */
  smartlist_t *NodeFamilySets; /**< List of parsed NodeFamilies values. */
  struct config_line_t *AuthDirBadExit; /**< Address policy for descriptors to
                                  * mark as bad exits. */
  struct config_line_t *AuthDirReject; /**< Address policy for descriptors to
                                 * reject. */
  struct config_line_t *AuthDirInvalid; /**< Address policy for descriptors to
                                  * never mark as valid. */
  /** @name AuthDir...CC
   *
   * Lists of country codes to mark as BadExit, or Invalid, or to
   * reject entirely.
   *
   * @{
   */
  smartlist_t *AuthDirBadExitCCs;
  smartlist_t *AuthDirInvalidCCs;
  smartlist_t *AuthDirRejectCCs;
  /**@}*/

  int AuthDirListBadExits; /**< True iff we should list bad exits,
                            * and vote for all other exits as good. */
  int AuthDirMaxServersPerAddr; /**< Do not permit more than this
                                 * number of servers per IP address. */
  int AuthDirHasIPv6Connectivity; /**< Boolean: are we on IPv6?  */
  int AuthDirPinKeys; /**< Boolean: Do we enforce key-pinning? */

  /** If non-zero, always vote the Fast flag for any relay advertising
   * this amount of capacity or more. */
  uint64_t AuthDirFastGuarantee;

  /** If non-zero, this advertised capacity or more is always sufficient
   * to satisfy the bandwidth requirement for the Guard flag. */
  uint64_t AuthDirGuardBWGuarantee;

  char *AccountingStart; /**< How long is the accounting interval, and when
                          * does it start? */
  uint64_t AccountingMax; /**< How many bytes do we allow per accounting
                           * interval before hibernation?  0 for "never
                           * hibernate." */
  /** How do we determine when our AccountingMax has been reached?
   * "max" for when in or out reaches AccountingMax
   * "sum" for when in plus out reaches AccountingMax
   * "in"  for when in reaches AccountingMax
   * "out" for when out reaches AccountingMax */
  char *AccountingRule_option;
  enum { ACCT_MAX, ACCT_SUM, ACCT_IN, ACCT_OUT } AccountingRule;

  /** Base64-encoded hash of accepted passwords for the control system. */
  struct config_line_t *HashedControlPassword;
  /** As HashedControlPassword, but not saved. */
  struct config_line_t *HashedControlSessionPassword;

  int CookieAuthentication; /**< Boolean: do we enable cookie-based auth for
                             * the control system? */
  char *CookieAuthFile; /**< Filesystem location of a ControlPort
                         *   authentication cookie. */
  char *ExtORPortCookieAuthFile; /**< Filesystem location of Extended
                                 *   ORPort authentication cookie. */
  int CookieAuthFileGroupReadable; /**< Boolean: Is the CookieAuthFile g+r? */
  int ExtORPortCookieAuthFileGroupReadable; /**< Boolean: Is the
                                             * ExtORPortCookieAuthFile g+r? */
  int LeaveStreamsUnattached; /**< Boolean: Does Tor attach new streams to
                          * circuits itself (0), or does it expect a controller
                          * to cope? (1) */
  int DisablePredictedCircuits; /**< Boolean: does Tor preemptively
                                 * make circuits in the background (0),
                                 * or not (1)? */

  /** Process specifier for a controller that ‘owns’ this Tor
   * instance.  Tor will terminate if its owning controller does. */
  char *OwningControllerProcess;
  /** FD specifier for a controller that owns this Tor instance. */
  int OwningControllerFD;

  int ShutdownWaitLength; /**< When we get a SIGINT and we're a server, how
                           * long do we wait before exiting? */
  char *SafeLogging; /**< Contains "relay", "1", "0" (meaning no scrubbing). */

  /* Derived from SafeLogging */
  enum {
    SAFELOG_SCRUB_ALL, SAFELOG_SCRUB_RELAY, SAFELOG_SCRUB_NONE
  } SafeLogging_;

  int Sandbox; /**< Boolean: should sandboxing be enabled? */
  int SafeSocks; /**< Boolean: should we outright refuse application
                  * connections that use socks4 or socks5-with-local-dns? */
  int ProtocolWarnings; /**< Boolean: when other parties screw up the Tor
                         * protocol, is it a warn or an info in our logs? */
  int TestSocks; /**< Boolean: when we get a socks connection, do we loudly
                  * log whether it was DNS-leaking or not? */
  int HardwareAccel; /**< Boolean: Should we enable OpenSSL hardware
                      * acceleration where available? */
  /** Token Bucket Refill resolution in milliseconds. */
  int TokenBucketRefillInterval;
  char *AccelName; /**< Optional hardware acceleration engine name. */
  char *AccelDir; /**< Optional hardware acceleration engine search dir. */

  /** Boolean: Do we try to enter from a smallish number
   * of fixed nodes? */
  int UseEntryGuards_option;
  /** Internal variable to remember whether we're actually acting on
   * UseEntryGuards_option -- when we're a non-anonymous Tor2web client or
   * Single Onion Service, it is always false, otherwise we use the value of
   * UseEntryGuards_option. */
  int UseEntryGuards;

  int NumEntryGuards; /**< How many entry guards do we try to establish? */

  /** If 1, we use any guardfraction information we see in the
   * consensus.  If 0, we don't.  If -1, let the consensus parameter
   * decide. */
  int UseGuardFraction;

  int NumDirectoryGuards; /**< How many dir guards do we try to establish?
                           * If 0, use value from NumEntryGuards. */
  int NumPrimaryGuards; /**< How many primary guards do we want? */

  int RephistTrackTime; /**< How many seconds do we keep rephist info? */
  /** Should we always fetch our dir info on the mirror schedule (which
   * means directly from the authorities) no matter our other config? */
  int FetchDirInfoEarly;

  /** Should we fetch our dir info at the start of the consensus period? */
  int FetchDirInfoExtraEarly;

  int DirCache; /**< Cache all directory documents and accept requests via
                 * tunnelled dir conns from clients. If 1, enabled (default);
                 * If 0, disabled. */

  char *VirtualAddrNetworkIPv4; /**< Address and mask to hand out for virtual
                                 * MAPADDRESS requests for IPv4 addresses */
  char *VirtualAddrNetworkIPv6; /**< Address and mask to hand out for virtual
                                 * MAPADDRESS requests for IPv6 addresses */
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
  int DisableDebuggerAttachment; /**< Currently Linux only specific attempt to
                                      disable ptrace; needs BSD testing. */
  /** Boolean: if set, we start even if our resolv.conf file is missing
   * or broken. */
  int ServerDNSAllowBrokenConfig;
  /** Boolean: if set, then even connections to private addresses will get
   * rate-limited. */
  int CountPrivateBandwidth;
  smartlist_t *ServerDNSTestAddresses; /**< A list of addresses that definitely
                                        * should be resolvable. Used for
                                        * testing our DNS server. */
  int EnforceDistinctSubnets; /**< If true, don't allow multiple routers in the
                               * same network zone in the same circuit. */
  int AllowNonRFC953Hostnames; /**< If true, we allow connections to hostnames
                                * with weird characters. */
  /** If true, we try resolving hostnames with weird characters. */
  int ServerDNSAllowNonRFC953Hostnames;

  /** If true, we try to download extra-info documents (and we serve them,
   * if we are a cache).  For authorities, this is always true. */
  int DownloadExtraInfo;

  /** If true, we're configured to collect statistics on clients
   * requesting network statuses from us as directory. */
  int DirReqStatistics_option;
  /** Internal variable to remember whether we're actually acting on
   * DirReqStatistics_option -- yes if it's set and we're a server, else no. */
  int DirReqStatistics;

  /** If true, the user wants us to collect statistics on port usage. */
  int ExitPortStatistics;

  /** If true, the user wants us to collect connection statistics. */
  int ConnDirectionStatistics;

  /** If true, the user wants us to collect cell statistics. */
  int CellStatistics;

  /** If true, the user wants us to collect padding statistics. */
  int PaddingStatistics;

  /** If true, the user wants us to collect statistics as entry node. */
  int EntryStatistics;

  /** If true, the user wants us to collect statistics as hidden service
   * directory, introduction point, or rendezvous point. */
  int HiddenServiceStatistics_option;
  /** Internal variable to remember whether we're actually acting on
   * HiddenServiceStatistics_option -- yes if it's set and we're a server,
   * else no. */
  int HiddenServiceStatistics;

  /** If true, include statistics file contents in extra-info documents. */
  int ExtraInfoStatistics;

  /** If true, do not believe anybody who tells us that a domain resolves
   * to an internal address, or that an internal address has a PTR mapping.
   * Helps avoid some cross-site attacks. */
  int ClientDNSRejectInternalAddresses;

  /** If true, do not accept any requests to connect to internal addresses
   * over randomly chosen exits. */
  int ClientRejectInternalAddresses;

  /** If true, clients may connect over IPv4. If false, they will avoid
   * connecting over IPv4. We enforce this for OR and Dir connections. */
  int ClientUseIPv4;
  /** If true, clients may connect over IPv6. If false, they will avoid
   * connecting over IPv4. We enforce this for OR and Dir connections.
   * Use fascist_firewall_use_ipv6() instead of accessing this value
   * directly. */
  int ClientUseIPv6;
  /** If true, prefer an IPv6 OR port over an IPv4 one for entry node
   * connections. If auto, bridge clients prefer IPv6, and other clients
   * prefer IPv4. Use node_ipv6_or_preferred() instead of accessing this value
   * directly. */
  int ClientPreferIPv6ORPort;
  /** If true, prefer an IPv6 directory port over an IPv4 one for direct
   * directory connections. If auto, bridge clients prefer IPv6, and other
   * clients prefer IPv4. Use fascist_firewall_prefer_ipv6_dirport() instead of
   * accessing this value directly.  */
  int ClientPreferIPv6DirPort;

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

  /** Location of guardfraction file */
  char *GuardfractionFile;

  /** Authority only: key=value pairs that we add to our networkstatus
   * consensus vote on the 'params' line. */
  char *ConsensusParams;

  /** Authority only: minimum number of measured bandwidths we must see
   * before we only believe measured bandwidths to assign flags. */
  int MinMeasuredBWsForAuthToIgnoreAdvertised;

  /** The length of time that we think an initial consensus should be fresh.
   * Only altered on testing networks. */
  int TestingV3AuthInitialVotingInterval;

  /** The length of time we think it will take to distribute initial votes.
   * Only altered on testing networks. */
  int TestingV3AuthInitialVoteDelay;

  /** The length of time we think it will take to distribute initial
   * signatures.  Only altered on testing networks.*/
  int TestingV3AuthInitialDistDelay;

  /** Offset in seconds added to the starting time for consensus
      voting. Only altered on testing networks. */
  int TestingV3AuthVotingStartOffset;

  /** If an authority has been around for less than this amount of time, it
   * does not believe its reachability information is accurate.  Only
   * altered on testing networks. */
  int TestingAuthDirTimeToLearnReachability;

  /** Clients don't download any descriptor this recent, since it will
   * probably not have propagated to enough caches.  Only altered on testing
   * networks. */
  int TestingEstimatedDescriptorPropagationTime;

  /** Schedule for when servers should download things in general.  Only
   * altered on testing networks. */
  int TestingServerDownloadInitialDelay;

  /** Schedule for when clients should download things in general.  Only
   * altered on testing networks. */
  int TestingClientDownloadInitialDelay;

  /** Schedule for when servers should download consensuses.  Only altered
   * on testing networks. */
  int TestingServerConsensusDownloadInitialDelay;

  /** Schedule for when clients should download consensuses.  Only altered
   * on testing networks. */
  int TestingClientConsensusDownloadInitialDelay;

  /** Schedule for when clients should download consensuses from authorities
   * if they are bootstrapping (that is, they don't have a usable, reasonably
   * live consensus).  Only used by clients fetching from a list of fallback
   * directory mirrors.
   *
   * This schedule is incremented by (potentially concurrent) connection
   * attempts, unlike other schedules, which are incremented by connection
   * failures.  Only altered on testing networks. */
  int ClientBootstrapConsensusAuthorityDownloadInitialDelay;

  /** Schedule for when clients should download consensuses from fallback
   * directory mirrors if they are bootstrapping (that is, they don't have a
   * usable, reasonably live consensus). Only used by clients fetching from a
   * list of fallback directory mirrors.
   *
   * This schedule is incremented by (potentially concurrent) connection
   * attempts, unlike other schedules, which are incremented by connection
   * failures.  Only altered on testing networks. */
  int ClientBootstrapConsensusFallbackDownloadInitialDelay;

  /** Schedule for when clients should download consensuses from authorities
   * if they are bootstrapping (that is, they don't have a usable, reasonably
   * live consensus).  Only used by clients which don't have or won't fetch
   * from a list of fallback directory mirrors.
   *
   * This schedule is incremented by (potentially concurrent) connection
   * attempts, unlike other schedules, which are incremented by connection
   * failures.  Only altered on testing networks. */
  int ClientBootstrapConsensusAuthorityOnlyDownloadInitialDelay;

  /** Schedule for when clients should download bridge descriptors.  Only
   * altered on testing networks. */
  int TestingBridgeDownloadInitialDelay;

  /** Schedule for when clients should download bridge descriptors when they
   * have no running bridges.  Only altered on testing networks. */
  int TestingBridgeBootstrapDownloadInitialDelay;

  /** When directory clients have only a few descriptors to request, they
   * batch them until they have more, or until this amount of time has
   * passed.  Only altered on testing networks. */
  int TestingClientMaxIntervalWithoutRequest;

  /** How long do we let a directory connection stall before expiring
   * it?  Only altered on testing networks. */
  int TestingDirConnectionMaxStall;

  /** How many simultaneous in-progress connections will we make when trying
   * to fetch a consensus before we wait for one to complete, timeout, or
   * error out?  Only altered on testing networks. */
  int ClientBootstrapConsensusMaxInProgressTries;

  /** If true, we take part in a testing network. Change the defaults of a
   * couple of other configuration options and allow to change the values
   * of certain configuration options. */
  int TestingTorNetwork;

  /** Minimum value for the Exit flag threshold on testing networks. */
  uint64_t TestingMinExitFlagThreshold;

  /** Minimum value for the Fast flag threshold on testing networks. */
  uint64_t TestingMinFastFlagThreshold;

  /** Relays in a testing network which should be voted Exit
   * regardless of exit policy. */
  routerset_t *TestingDirAuthVoteExit;
  int TestingDirAuthVoteExitIsStrict;

  /** Relays in a testing network which should be voted Guard
   * regardless of uptime and bandwidth. */
  routerset_t *TestingDirAuthVoteGuard;
  int TestingDirAuthVoteGuardIsStrict;

  /** Relays in a testing network which should be voted HSDir
   * regardless of uptime and DirPort. */
  routerset_t *TestingDirAuthVoteHSDir;
  int TestingDirAuthVoteHSDirIsStrict;

  /** Enable CONN_BW events.  Only altered on testing networks. */
  int TestingEnableConnBwEvent;

  /** Enable CELL_STATS events.  Only altered on testing networks. */
  int TestingEnableCellStatsEvent;

  /** If true, and we have GeoIP data, and we're a bridge, keep a per-country
   * count of how many client addresses have contacted us so that we can help
   * the bridge authority guess which countries have blocked access to us. */
  int BridgeRecordUsageByCountry;

  /** Optionally, IPv4 and IPv6 GeoIP data. */
  char *GeoIPFile;
  char *GeoIPv6File;

  /** Autobool: if auto, then any attempt to Exclude{Exit,}Nodes a particular
   * country code will exclude all nodes in ?? and A1.  If true, all nodes in
   * ?? and A1 are excluded. Has no effect if we don't know any GeoIP data. */
  int GeoIPExcludeUnknown;

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

  /** Set to true if the TestingTorNetwork configuration option is set.
   * This is used so that options_validate() has a chance to realize that
   * the defaults have changed. */
  int UsingTestNetworkDefaults_;

  /** If 1, we try to use microdescriptors to build circuits.  If 0, we don't.
   * If -1, Tor decides. */
  int UseMicrodescriptors;

  /** File where we should write the ControlPort. */
  char *ControlPortWriteToFile;
  /** Should that file be group-readable? */
  int ControlPortFileGroupReadable;

#define MAX_MAX_CLIENT_CIRCUITS_PENDING 1024
  /** Maximum number of non-open general-purpose origin circuits to allow at
   * once. */
  int MaxClientCircuitsPending;

  /** If 1, we always send optimistic data when it's supported.  If 0, we
   * never use it.  If -1, we do what the consensus says. */
  int OptimisticData;

  /** If 1, we accept and launch no external network connections, except on
   * control ports. */
  int DisableNetwork;

  /**
   * Parameters for path-bias detection.
   * @{
   * These options override the default behavior of Tor's (**currently
   * experimental**) path bias detection algorithm. To try to find broken or
   * misbehaving guard nodes, Tor looks for nodes where more than a certain
   * fraction of circuits through that guard fail to get built.
   *
   * The PathBiasCircThreshold option controls how many circuits we need to
   * build through a guard before we make these checks.  The
   * PathBiasNoticeRate, PathBiasWarnRate and PathBiasExtremeRate options
   * control what fraction of circuits must succeed through a guard so we
   * won't write log messages.  If less than PathBiasExtremeRate circuits
   * succeed *and* PathBiasDropGuards is set to 1, we disable use of that
   * guard.
   *
   * When we have seen more than PathBiasScaleThreshold circuits through a
   * guard, we scale our observations by 0.5 (governed by the consensus) so
   * that new observations don't get swamped by old ones.
   *
   * By default, or if a negative value is provided for one of these options,
   * Tor uses reasonable defaults from the networkstatus consensus document.
   * If no defaults are available there, these options default to 150, .70,
   * .50, .30, 0, and 300 respectively.
   */
  int PathBiasCircThreshold;
  double PathBiasNoticeRate;
  double PathBiasWarnRate;
  double PathBiasExtremeRate;
  int PathBiasDropGuards;
  int PathBiasScaleThreshold;
  /** @} */

  /**
   * Parameters for path-bias use detection
   * @{
   * Similar to the above options, these options override the default behavior
   * of Tor's (**currently experimental**) path use bias detection algorithm.
   *
   * Where as the path bias parameters govern thresholds for successfully
   * building circuits, these four path use bias parameters govern thresholds
   * only for circuit usage. Circuits which receive no stream usage are not
   * counted by this detection algorithm. A used circuit is considered
   * successful if it is capable of carrying streams or otherwise receiving
   * well-formed responses to RELAY cells.
   *
   * By default, or if a negative value is provided for one of these options,
   * Tor uses reasonable defaults from the networkstatus consensus document.
   * If no defaults are available there, these options default to 20, .80,
   * .60, and 100, respectively.
   */
  int PathBiasUseThreshold;
  double PathBiasNoticeUseRate;
  double PathBiasExtremeUseRate;
  int PathBiasScaleUseThreshold;
  /** @} */

  int IPv6Exit; /**< Do we support exiting to IPv6 addresses? */

  /** Fraction: */
  double PathsNeededToBuildCircuits;

  /** What expiry time shall we place on our SSL certs? "0" means we
   * should guess a suitable value. */
  int SSLKeyLifetime;

  /** How long (seconds) do we keep a guard before picking a new one? */
  int GuardLifetime;

  /** Is this an exit node?  This is a tristate, where "1" means "yes, and use
   * the default exit policy if none is given" and "0" means "no; exit policy
   * is 'reject *'" and "auto" (-1) means "same as 1, but warn the user."
   *
   * XXXX Eventually, the default will be 0. */
  int ExitRelay;

  /** For how long (seconds) do we declare our signing keys to be valid? */
  int SigningKeyLifetime;
  /** For how long (seconds) do we declare our link keys to be valid? */
  int TestingLinkCertLifetime;
  /** For how long (seconds) do we declare our auth keys to be valid? */
  int TestingAuthKeyLifetime;

  /** How long before signing keys expire will we try to make a new one? */
  int TestingSigningKeySlop;
  /** How long before link keys expire will we try to make a new one? */
  int TestingLinkKeySlop;
  /** How long before auth keys expire will we try to make a new one? */
  int TestingAuthKeySlop;

  /** Force use of offline master key features: never generate a master
   * ed25519 identity key except from tor --keygen */
  int OfflineMasterKey;

  enum {
    FORCE_PASSPHRASE_AUTO=0,
    FORCE_PASSPHRASE_ON,
    FORCE_PASSPHRASE_OFF
  } keygen_force_passphrase;
  int use_keygen_passphrase_fd;
  int keygen_passphrase_fd;
  int change_key_passphrase;
  char *master_key_fname;

  /** Autobool: Do we try to retain capabilities if we can? */
  int KeepBindCapabilities;

  /** Maximum total size of unparseable descriptors to log during the
   * lifetime of this Tor process.
   */
  uint64_t MaxUnparseableDescSizeToLog;

  /** Bool (default: 1): Switch for the shared random protocol. Only
   * relevant to a directory authority. If off, the authority won't
   * participate in the protocol. If on (default), a flag is added to the
   * vote indicating participation. */
  int AuthDirSharedRandomness;

  /** If 1, we skip all OOS checks. */
  int DisableOOSCheck;

  /** Autobool: Should we include Ed25519 identities in extend2 cells?
   * If -1, we should do whatever the consensus parameter says. */
  int ExtendByEd25519ID;

  /** Bool (default: 1): When testing routerinfos as a directory authority,
   * do we enforce Ed25519 identity match? */
  /* NOTE: remove this option someday. */
  int AuthDirTestEd25519LinkKeys;

  /** Bool (default: 0): Tells if a %include was used on torrc */
  int IncludeUsed;

  /** The seconds after expiration which we as a relay should keep old
   * consensuses around so that we can generate diffs from them.  If 0,
   * use the default. */
  int MaxConsensusAgeForDiffs;

  /** Bool (default: 0). Tells Tor to never try to exec another program.
   */
  int NoExec;

  /** Have the KIST scheduler run every X milliseconds. If less than zero, do
   * not use the KIST scheduler but use the old vanilla scheduler instead. If
   * zero, do what the consensus says and fall back to using KIST as if this is
   * set to "10 msec" if the consensus doesn't say anything. */
  int KISTSchedRunInterval;

  /** A multiplier for the KIST per-socket limit calculation. */
  double KISTSockBufSizeFactor;

  /** The list of scheduler type string ordered by priority that is first one
   * has to be tried first. Default: KIST,KISTLite,Vanilla */
  smartlist_t *Schedulers;
  /* An ordered list of scheduler_types mapped from Schedulers. */
  smartlist_t *SchedulerTypes_;

  /** List of files that were opened by %include in torrc and torrc-defaults */
  smartlist_t *FilesOpenedByIncludes;

  /** If true, Tor shouldn't install any posix signal handlers, since it is
   * running embedded inside another process.
   */
  int DisableSignalHandlers;

  /** Autobool: Is the circuit creation DoS mitigation subsystem enabled? */
  int DoSCircuitCreationEnabled;
  /** Minimum concurrent connection needed from one single address before any
   * defense is used. */
  int DoSCircuitCreationMinConnections;
  /** Circuit rate used to refill the token bucket. */
  int DoSCircuitCreationRate;
  /** Maximum allowed burst of circuits. Reaching that value, the address is
   * detected as malicious and a defense might be used. */
  int DoSCircuitCreationBurst;
  /** When an address is marked as malicous, what defense should be used
   * against it. See the dos_cc_defense_type_t enum. */
  int DoSCircuitCreationDefenseType;
  /** For how much time (in seconds) the defense is applicable for a malicious
   * address. A random time delta is added to the defense time of an address
   * which will be between 1 second and half of this value. */
  int DoSCircuitCreationDefenseTimePeriod;

  /** Autobool: Is the DoS connection mitigation subsystem enabled? */
  int DoSConnectionEnabled;
  /** Maximum concurrent connection allowed per address. */
  int DoSConnectionMaxConcurrentCount;
  /** When an address is reaches the maximum count, what defense should be
   * used against it. See the dos_conn_defense_type_t enum. */
  int DoSConnectionDefenseType;

  /** Autobool: Do we refuse single hop client rendezvous? */
  int DoSRefuseSingleHopClientRendezvous;
} or_options_t;

#define LOG_PROTOCOL_WARN (get_protocol_warning_severity_level())

/** Persistent state for an onion router, as saved to disk. */
typedef struct {
  uint32_t magic_;
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

  /** A list of Entry Guard-related configuration lines. (pre-prop271) */
  struct config_line_t *EntryGuards;

  /** A list of guard-related configuration lines. (post-prop271) */
  struct config_line_t *Guard;

  struct config_line_t *TransportProxies;

  /** Cached revision counters for active hidden services on this host */
  struct config_line_t *HidServRevCounter;

  /** These fields hold information on the history of bandwidth usage for
   * servers.  The "Ends" fields hold the time when we last updated the
   * bandwidth usage. The "Interval" fields hold the granularity, in seconds,
   * of the entries of Values.  The "Values" lists hold decimal string
   * representations of the number of bytes read or written in each
   * interval. The "Maxima" list holds decimal strings describing the highest
   * rate achieved during the interval.
   */
  time_t      BWHistoryReadEnds;
  int         BWHistoryReadInterval;
  smartlist_t *BWHistoryReadValues;
  smartlist_t *BWHistoryReadMaxima;
  time_t      BWHistoryWriteEnds;
  int         BWHistoryWriteInterval;
  smartlist_t *BWHistoryWriteValues;
  smartlist_t *BWHistoryWriteMaxima;
  time_t      BWHistoryDirReadEnds;
  int         BWHistoryDirReadInterval;
  smartlist_t *BWHistoryDirReadValues;
  smartlist_t *BWHistoryDirReadMaxima;
  time_t      BWHistoryDirWriteEnds;
  int         BWHistoryDirWriteInterval;
  smartlist_t *BWHistoryDirWriteValues;
  smartlist_t *BWHistoryDirWriteMaxima;

  /** Build time histogram */
  struct config_line_t * BuildtimeHistogram;
  int TotalBuildTimes;
  int CircuitBuildAbandonedCount;

  /** What version of Tor wrote this state file? */
  char *TorVersion;

  /** Holds any unrecognized values we found in the state file, in the order
   * in which we found them. */
  struct config_line_t *ExtraLines;

  /** When did we last rotate our onion key?  "0" for 'no idea'. */
  time_t LastRotatedOnionKey;
} or_state_t;

#define MAX_SOCKS_ADDR_LEN 256

/********************************* circuitbuild.c **********************/

/** How many hops does a general-purpose circuit have by default? */
#define DEFAULT_ROUTE_LEN 3

/* Circuit Build Timeout "public" structures. */

/** Precision multiplier for the Bw weights */
#define BW_WEIGHT_SCALE   10000
#define BW_MIN_WEIGHT_SCALE 1
#define BW_MAX_WEIGHT_SCALE INT32_MAX

typedef struct circuit_build_times_s circuit_build_times_t;

/********************************* config.c ***************************/

/********************************* connection_edge.c *************************/

/** Enumerates possible origins of a client-side address mapping. */
typedef enum {
  /** We're remapping this address because the controller told us to. */
  ADDRMAPSRC_CONTROLLER,
  /** We're remapping this address because of an AutomapHostsOnResolve
   * configuration. */
  ADDRMAPSRC_AUTOMAP,
  /** We're remapping this address because our configuration (via torrc, the
   * command line, or a SETCONF command) told us to. */
  ADDRMAPSRC_TORRC,
  /** We're remapping this address because we have TrackHostExit configured,
   * and we want to remember to use the same exit next time. */
  ADDRMAPSRC_TRACKEXIT,
  /** We're remapping this address because we got a DNS resolution from a
   * Tor server that told us what its value was. */
  ADDRMAPSRC_DNS,

  /** No remapping has occurred.  This isn't a possible value for an
   * addrmap_entry_t; it's used as a null value when we need to answer "Why
   * did this remapping happen." */
  ADDRMAPSRC_NONE
} addressmap_entry_source_t;
#define addressmap_entry_source_bitfield_t ENUM_BF(addressmap_entry_source_t)

#define WRITE_STATS_INTERVAL (24*60*60)

/********************************* dirvote.c ************************/

typedef struct vote_timing_t vote_timing_t;

/********************************* microdesc.c *************************/

typedef struct microdesc_cache_t microdesc_cache_t;

/********************************* rendcommon.c ***************************/

typedef struct rend_authorized_client_t rend_authorized_client_t;
typedef struct rend_encoded_v2_service_descriptor_t
               rend_encoded_v2_service_descriptor_t;

/** The maximum number of non-circuit-build-timeout failures a hidden
 * service client will tolerate while trying to build a circuit to an
 * introduction point.  See also rend_intro_point_t.unreachable_count. */
#define MAX_INTRO_POINT_REACHABILITY_FAILURES 5

/** The minimum and maximum number of distinct INTRODUCE2 cells which a
 * hidden service's introduction point will receive before it begins to
 * expire. */
#define INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS 16384
/* Double the minimum value so the interval is [min, min * 2]. */
#define INTRO_POINT_MAX_LIFETIME_INTRODUCTIONS \
  (INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS * 2)

/** The minimum number of seconds that an introduction point will last
 * before expiring due to old age.  (If it receives
 * INTRO_POINT_LIFETIME_INTRODUCTIONS INTRODUCE2 cells, it may expire
 * sooner.)
 *
 * XXX Should this be configurable? */
#define INTRO_POINT_LIFETIME_MIN_SECONDS (18*60*60)
/** The maximum number of seconds that an introduction point will last
 * before expiring due to old age.
 *
 * XXX Should this be configurable? */
#define INTRO_POINT_LIFETIME_MAX_SECONDS (24*60*60)

/** The maximum number of circuit creation retry we do to an intro point
 * before giving up. We try to reuse intro point that fails during their
 * lifetime so this is a hard limit on the amount of time we do that. */
#define MAX_INTRO_POINT_CIRCUIT_RETRIES 3

typedef struct rend_intro_point_t rend_intro_point_t;
typedef struct rend_service_descriptor_t rend_service_descriptor_t;

/********************************* routerlist.c ***************************/

typedef struct dir_server_t dir_server_t;

#define RELAY_REQUIRED_MIN_BANDWIDTH (75*1024)
#define BRIDGE_REQUIRED_MIN_BANDWIDTH (50*1024)

#define ROUTER_MAX_DECLARED_BANDWIDTH INT32_MAX

typedef struct tor_version_t tor_version_t;

#endif /* !defined(TOR_OR_H) */
