/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file or.h
 *
 * \brief Master header file for Tor-specific functionality.
 */

#ifndef __OR_H
#define __OR_H

#include "orconfig.h"
#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#include "../common/torint.h"
#include "../common/fakepoll.h"
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#ifdef HAVE_SYS_LIMITS_H
#include <sys/limits.h>
#endif
#ifdef HAVE_MACHINE_LIMITS_H
#ifndef __FreeBSD__
  /* FreeBSD has a bug where it complains that this file is obsolete,
     and I should migrate to using sys/limits. It complains even when
     I include both. */
#include <machine/limits.h>
#endif
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h> /* Must be included before sys/stat.h for Ultrix */
#endif
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
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
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
#ifdef HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if _MSC_VER > 1300
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(_MSC_VER)
#include <winsock.h>
#endif

#ifdef MS_WINDOWS
#include <io.h>
#include <process.h>
#include <direct.h>
#include <windows.h>
#define snprintf _snprintf
#endif

#include "../common/crypto.h"
#include "../common/tortls.h"
#include "../common/log.h"
#include "../common/util.h"

/** Upper bound on maximum simultaneous connections; can be lowered by
 * config file. */
#define MAXCONNECTIONS 10000

#define DEFAULT_BANDWIDTH_OP (1024 * 1000)
#define MAX_NICKNAME_LEN 19
#define MAX_DIR_SIZE 500000

#ifdef TOR_PERF
/** How long do we keep DNS cache entries before purging them? */
#define MAX_DNS_ENTRY_AGE (150*60)
#else
#define MAX_DNS_ENTRY_AGE (15*60)
#endif

/** How often do we rotate onion keys? */
#define MIN_ONION_KEY_LIFETIME (120*60)
/** How often do we rotate TLS contexts? */
#define MAX_SSL_KEY_LIFETIME (120*60)

/** How old do we allow a router to get before removing it, either
 * from the descriptor list (for dirservers) or the router list (for others)?
 * In seconds. */
#define ROUTER_MAX_AGE (60*60*24)

#define CIRC_ID_TYPE_LOWER 0
#define CIRC_ID_TYPE_HIGHER 1

#define _CONN_TYPE_MIN 3
/** Type for sockets listening for OR connections. */
#define CONN_TYPE_OR_LISTENER 3
/** Type for OR-to-OR or OP-to-OR connections. */
#define CONN_TYPE_OR 4
/** Type for connections from final OR to chosen destination. */
#define CONN_TYPE_EXIT 5
/** Type for sockets listening for SOCKS connections. */
#define CONN_TYPE_AP_LISTENER 6
/** Type for SOCKS connections to OP. */
#define CONN_TYPE_AP 7
/** Type for sockets listening for HTTP connections to the directory server. */
#define CONN_TYPE_DIR_LISTENER 8
/** Type for HTTP connections to the directory server. */
#define CONN_TYPE_DIR 9
/** Type for connections to local dnsworker processes. */
#define CONN_TYPE_DNSWORKER 10
/** Type for connections to local cpuworker processes. */
#define CONN_TYPE_CPUWORKER 11
#define _CONN_TYPE_MAX 11

/** State for any listener connection. */
#define LISTENER_STATE_READY 0

#define _DNSWORKER_STATE_MIN 1
/** State for a connection to a dnsworker process that's idle. */
#define DNSWORKER_STATE_IDLE 1
/** State for a connection to a dnsworker process that's resolving a hostname. */
#define DNSWORKER_STATE_BUSY 2
#define _DNSWORKER_STATE_MAX 2

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
/** State for a connection to an OR: SSL is handshaking, not done yet. */
#define OR_CONN_STATE_HANDSHAKING 2
/** State for a connection to an OR: Ready to send/receive cells. */
#define OR_CONN_STATE_OPEN 3
#define _OR_CONN_STATE_MAX 3

#define _EXIT_CONN_STATE_MIN 1
/** State for an exit connection: waiting for response from dns farm. */
#define EXIT_CONN_STATE_RESOLVING 1
/** State for an exit connection: waiting for connect() to finish. */
#define EXIT_CONN_STATE_CONNECTING 2
/** State for an exit connection: open and ready to transmit data. */
#define EXIT_CONN_STATE_OPEN 3
/** State for an exit connection: waiting to be removed. */
#define EXIT_CONN_STATE_RESOLVEFAILED 4
#define _EXIT_CONN_STATE_MAX 4
#if 0
#define EXIT_CONN_STATE_CLOSE 3 /* flushing the buffer, then will close */
#define EXIT_CONN_STATE_CLOSE_WAIT 4 /* have sent a destroy, awaiting a confirmation */
#endif

/* the AP state values must be disjoint from the EXIT state values */
#define _AP_CONN_STATE_MIN 5
/** State for a SOCKS connection: waiting for SOCKS request. */
#define AP_CONN_STATE_SOCKS_WAIT 5
/** State for a SOCKS connection: got a y.onion URL; waiting to receive
 * rendezvous rescriptor. */
#define AP_CONN_STATE_RENDDESC_WAIT 6
/** State for a SOCKS connection: waiting for a completed circuit. */
#define AP_CONN_STATE_CIRCUIT_WAIT 7
/** State for a SOCKS connection: sent BEGIN, waiting for CONNECTED. */
#define AP_CONN_STATE_CONNECT_WAIT 8
/** State for a SOCKS connection: send RESOLVE, waiting for RESOLVED. */
#define AP_CONN_STATE_RESOLVE_WAIT 9
/** State for a SOCKS connection: ready to send and receive. */
#define AP_CONN_STATE_OPEN 10
#define _AP_CONN_STATE_MAX 10

#define _DIR_CONN_STATE_MIN 1
/** State for connection to directory server: waiting for connect(). */
#define DIR_CONN_STATE_CONNECTING 1
/** State for connection to directory server: sending HTTP request. */
#define DIR_CONN_STATE_CLIENT_SENDING 2
/** State for connection to directory server: reading HTTP response. */
#define DIR_CONN_STATE_CLIENT_READING 3
/** State for connection at directory server: waiting for HTTP request. */
#define DIR_CONN_STATE_SERVER_COMMAND_WAIT 4
/** State for connection at directory server: sending HTTP response. */
#define DIR_CONN_STATE_SERVER_WRITING 5
#define _DIR_CONN_STATE_MAX 5

#define _DIR_PURPOSE_MIN 1
/** Purpose for connection to directory server: download a directory. */
#define DIR_PURPOSE_FETCH_DIR 1
/** Purpose for connection to directory server: download just the list
 * of running routers. */
#define DIR_PURPOSE_FETCH_RUNNING_LIST 2
/** Purpose for connection to directory server: download a rendezvous
 * descriptor. */
#define DIR_PURPOSE_FETCH_RENDDESC 3
/** Purpose for connection to directory server: set after a rendezvous
 * descriptor is downloaded. */
#define DIR_PURPOSE_HAS_FETCHED_RENDDESC 4
/** Purpose for connection to directory server: upload a server descriptor. */
#define DIR_PURPOSE_UPLOAD_DIR 5
/** Purpose for connection to directory server: upload a rendezvous
 * descriptor. */
#define DIR_PURPOSE_UPLOAD_RENDDESC 6
/** Purpose for connection at a directory server. */
#define DIR_PURPOSE_SERVER 7
#define _DIR_PURPOSE_MAX 7

#define _EXIT_PURPOSE_MIN 1
#define EXIT_PURPOSE_CONNECT 1
#define EXIT_PURPOSE_RESOLVE 2
#define _EXIT_PURPOSE_MAX 2

/** Circuit state: I'm the OP, still haven't done all my handshakes. */
#define CIRCUIT_STATE_BUILDING 0
/** Circuit state: Waiting to process the onionskin. */
#define CIRCUIT_STATE_ONIONSKIN_PENDING 1
/** Circuit state: I'd like to deliver a create, but my n_conn is still connecting. */
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
/** Client-side circuit purpose: at Alice, sent INTRODUCE1 to intro point, waiting for ACK/NAK. */
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

/** Hidden-service-side circuit purpose: at Bob, waiting for introductions. */
#define CIRCUIT_PURPOSE_S_ESTABLISH_INTRO 13
/** Hidden-service-side circuit purpose: at Bob, successfully established
 * intro. */
#define CIRCUIT_PURPOSE_S_INTRO 14
/** Hidden-service-side circuit purpose: at Bob, connecting to rend point. */
#define CIRCUIT_PURPOSE_S_CONNECT_REND 15
/** Hidden-service-side circuit purpose: at Bob, rendezvous established. */
#define CIRCUIT_PURPOSE_S_REND_JOINED 16
#define _CIRCUIT_PURPOSE_MAX 16

/** True iff the circuit purpose <b>p</b> is for a circuit at the OP
 * that this OP has originated. */
#define CIRCUIT_PURPOSE_IS_ORIGIN(p) ((p)>_CIRCUIT_PURPOSE_OR_MAX)
#define CIRCUIT_IS_ORIGIN(c) (CIRCUIT_PURPOSE_IS_ORIGIN((c)->purpose))

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

#define RELAY_COMMAND_ESTABLISH_INTRO 32
#define RELAY_COMMAND_ESTABLISH_RENDEZVOUS 33
#define RELAY_COMMAND_INTRODUCE1 34
#define RELAY_COMMAND_INTRODUCE2 35
#define RELAY_COMMAND_RENDEZVOUS1 36
#define RELAY_COMMAND_RENDEZVOUS2 37
#define RELAY_COMMAND_INTRO_ESTABLISHED 38
#define RELAY_COMMAND_RENDEZVOUS_ESTABLISHED 39
#define RELAY_COMMAND_INTRODUCE_ACK 40

#define _MIN_END_STREAM_REASON 1
#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_CONNECTFAILED 3
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_TIMEOUT 7
#define _MAX_END_STREAM_REASON 7

#define RESOLVED_TYPE_IPV4 4
#define RESOLVED_TYPE_IPV6 6
#define RESOLVED_TYPE_ERROR_TRANSIENT 0xF0
#define RESOLVED_TYPE_ERROR 0xF1

/** Length of 'y' portion of 'y.onion' URL. */
#define REND_SERVICE_ID_LEN 16

#define CELL_DIRECTION_IN 1
#define CELL_DIRECTION_OUT 2

#ifdef TOR_PERF
#define CIRCWINDOW_START 10000
#define CIRCWINDOW_INCREMENT 1000
#define STREAMWINDOW_START 5000
#define STREAMWINDOW_INCREMENT 500
#else
#define CIRCWINDOW_START 1000
#define CIRCWINDOW_INCREMENT 100
#define STREAMWINDOW_START 500
#define STREAMWINDOW_INCREMENT 50
#endif

/* cell commands */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_CREATED 2
#define CELL_RELAY 3
#define CELL_DESTROY 4

/* legal characters in a nickname */
#define LEGAL_NICKNAME_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

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

#define CELL_PAYLOAD_SIZE 509
#define CELL_NETWORK_SIZE 512

#define RELAY_HEADER_SIZE (1+2+2+4+2)
#define RELAY_PAYLOAD_SIZE (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE)

/** Parsed onion routing cell.  All communication from OP-to-OR, or from
 * OR-to-OR, is via cells. */
typedef struct {
  uint16_t circ_id; /**< Circuit which received the cell. */
  unsigned char command; /**< Type of the cell: one of PADDING, CREATE, RELAY,
                          * or DESTROY. */
  unsigned char payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
} cell_t;

/** Beginning of a RELAY cell payload. */
typedef struct {
  uint8_t command; /**< The end-to-end relay command. */
  uint16_t recognized; /**< Used to tell whether cell is for us. */
  uint16_t stream_id; /**< Which stream is this cell associated with? */
  char integrity[4]; /**< Used to tell whether cell is corrupted. */
  uint16_t length; /**< How long is the payload body? */
} relay_header_t;

typedef struct buf_t buf_t;
typedef struct socks_request_t socks_request_t;

#define CONNECTION_MAGIC 0x7C3C304Eu
/** Description of a connection to another host or process, and associated
 * data. */
struct connection_t {
  uint32_t magic; /**< For memory debugging: must equal CONNECTION_MAGIC. */

  uint8_t type; /**< What kind of connection is this? */
  uint8_t state; /**< Current state of this connection. */
  uint8_t purpose; /**< Only used for DIR types currently. */
  uint8_t wants_to_read; /**< Boolean: should we start reading again once
                          * the bandwidth throttler allows it?
                          */
  uint8_t wants_to_write; /**< Boolean: should we start writing again once
                           * the bandwidth throttler allows reads?
                           */
  int s; /**< Our socket; -1 if this connection is closed. */
  int poll_index; /**< Index of this conn into the poll_array. */
  int marked_for_close; /**< Boolean: should we close this conn on the next
                         * iteration of the main loop?
                         */
  char *marked_for_close_file; /**< For debugging: in which file were we marked
                                * for close? */
  int hold_open_until_flushed; /**< Despite this connection's being marked
                                * for close, do we flush it before closing it?
                                */

  buf_t *inbuf; /**< Buffer holding data read over this connection. */
  int inbuf_reached_eof; /**< Boolean: did read() return 0 on this conn? */
  time_t timestamp_lastread; /**< When was the last time poll() said we could read? */

  buf_t *outbuf; /**< Buffer holding data to write over this connection. */
  int outbuf_flushlen; /**< How much data should we try to flush from the
                        * outbuf? */
  time_t timestamp_lastwritten; /**< When was the last time poll() said we could write? */

  time_t timestamp_created; /**< When was this connection_t created? */

  uint32_t addr; /**< IP of the other side of the connection; used to identify
                  * routers, along with port. */
  uint16_t port; /**< If non-zero, port  on the other end
                  * of the connection. */
  char *address; /**< FQDN (or IP) of the guy on the other end.
                  * strdup into this, because free_connection frees it.
                  */
  crypto_pk_env_t *identity_pkey; /**< Public RSA key for the other side's
                                   * signing key. */
  char identity_digest[DIGEST_LEN]; /**< Hash of identity_pkey */
  char *nickname; /**< Nickname of OR on other side (if any). */

/* Used only by OR connections: */
  tor_tls *tls; /**< TLS connection state (OR only.) */
  uint16_t next_circ_id; /**< Which circ_id do we try to use next on
                          * this connection?  This is always in the
                          * range 0..1<<15-1. (OR only.)*/

  /* bandwidth and receiver_bucket only used by ORs in OPEN state: */
  int bandwidth; /**< Connection bandwidth. (OPEN ORs only.) */
  int receiver_bucket; /**< When this hits 0, stop receiving. Every second we
                        * add 'bandwidth' to this, capping it at 10*bandwidth.
                        * (OPEN ORs only)
                        */

/* Used only by DIR and AP connections: */
  char rend_query[REND_SERVICE_ID_LEN+1]; /**< What rendezvous service are we
                                           * querying for? (DIR/AP only) */

/* Used only by edge connections: */
  uint16_t stream_id;
  struct connection_t *next_stream; /**< Points to the next stream at this
                                     * edge, if any (Edge only). */
  struct crypt_path_t *cpath_layer; /**< A pointer to which node in the circ
                                     * this conn exits at. (Edge only.) */
  int package_window; /**< How many more relay cells can i send into the
                       * circuit? (Edge only.) */
  int deliver_window; /**< How many more relay cells can end at me? (Edge
                       * only.) */

  int done_sending; /**< For half-open connections; not used currently. */
  int done_receiving; /**< For half-open connections; not used currently. */
  char has_sent_end; /**< For debugging: set once we've set the stream end,
                        and check in circuit_about_to_close_connection(). */
  char num_retries; /**< How many times have we re-tried beginning this stream?  (Edge only) */

  /* Used only by AP connections */
  socks_request_t *socks_request; /**< SOCKS structure describing request (AP
                                   * only.) */
};

typedef struct connection_t connection_t;

#define EXIT_POLICY_ACCEPT 1
#define EXIT_POLICY_REJECT 2

/** A linked list of exit policy rules */
struct exit_policy_t {
  char policy_type; /**< One of EXIT_POLICY_ACCEPT or EXIT_POLICY_REJECT. */
  char *string; /**< String representation of this rule. */
  uint32_t addr; /**< Base address to accept or reject. */
  uint32_t msk; /**< Accept/reject all addresses <b>a</b> such that a & msk ==
                 * <b>addr</b> & msk . */
  uint16_t prt_min; /**< Lowest port number to accept/reject. */
  uint16_t prt_max; /**< Highest port number to accept/reject. */

  struct exit_policy_t *next; /**< Next rule in list. */
};

/** Information about another onion router in the network. */
typedef struct {
  char *address; /**< Location of OR: either a hostname or an IP address. */
  char *nickname; /**< Human-readable OR name. */

  uint32_t addr; /**< IPv4 address of OR, in host order. */
  uint16_t or_port; /**< Port for OR-to-OR and OP-to-OR connections. */
  uint16_t socks_port; /**< Port for SOCKS connections. */
  uint16_t dir_port; /**< Port for HTTP directory connections. */

  time_t published_on; /**< When was the information in this routerinfo_t
                        * published? */

  crypto_pk_env_t *onion_pkey; /**< Public RSA key for onions. */
  crypto_pk_env_t *identity_pkey;  /**< Public RSA key for signing. */
  char identity_digest[DIGEST_LEN]; /**< Digest of identity key */

  char *platform; /**< What software/operating system is this OR using? */

  /* link info */
  uint32_t bandwidthrate; /**< How many bytes does this OR add to its token
                           * bucket per second? */
  uint32_t bandwidthburst; /**< How large is this OR's token bucket? */
  /** How many bytes/s is this router known to handle? */
  uint32_t advertisedbandwidth;
  struct exit_policy_t *exit_policy; /**< What streams will this OR permit
                                      * to exit? */
  /* local info */
  int is_running; /**< As far as we know, is this OR currently running? */
  time_t status_set_at; /**< When did we last update is_running? */
  int is_verified; /**< Has a trusted dirserver validated this OR? */
  int is_trusted_dir; /**< Do we trust this OR as a directory server? */

} routerinfo_t;

/** Contents of a directory of onion routers. */
typedef struct {
  /** List of routerinfo_t */
  smartlist_t *routers;
  /** Which versions of tor are recommended by this directory? */
  char *software_versions;
  /** When was the most recent directory that contributed to this list
   * published?
   */
  time_t published_on;
  time_t running_routers_updated_on;
  /** Which router is claimed to have signed it? */
  char *signing_router;
} routerlist_t;

/** Contents of a running-routers list */
typedef struct running_routers_t {
  time_t published_on; /**< When was the list marked as published? */
  /** Which ORs are on the list?  Entries may be prefixed with ! and $. */
  smartlist_t *running_routers;
} running_routers_t;

/** Holds accounting information for a single step in the layered encryption
 * performed by a circuit.  Used only at the client edge of a circuit. */
struct crypt_path_t {

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
  crypto_dh_env_t *handshake_state;
  /** Negotiated key material shared with the OR at this step. */
  char handshake_digest[DIGEST_LEN];/* KH in tor-spec.txt */

  /** IP4 address of the OR at this step. */
  uint32_t addr;
  /** Port of the OR at this step. */
  uint16_t port;
  /** Identity key digest of the OR at this step. */
  char identity_digest[DIGEST_LEN];

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

  int package_window; /**< How many bytes are we allowed to originate ending
                       * at this step? */
  int deliver_window; /**< How many bytes are we willing to deliver originating
                       * at this step? */
};

#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)

#define DH_KEY_LEN DH_BYTES
#define ONIONSKIN_CHALLENGE_LEN (PKCS1_OAEP_PADDING_OVERHEAD+\
                                 CIPHER_KEY_LEN+\
                                 DH_KEY_LEN)
#define ONIONSKIN_REPLY_LEN (DH_KEY_LEN+DIGEST_LEN)
#define REND_COOKIE_LEN DIGEST_LEN

typedef struct crypt_path_t crypt_path_t;

/** Information used to build a circuit. */
typedef struct {
  /** Intended length of the final circuit. */
  int desired_path_len;
  /** Nickname of planned exit node. */
  char *chosen_exit_name;
  /** Identity of planned exit node. */
  char chosen_exit_digest[DIGEST_LEN];
  /** The crypt_path_t to append after rendezvous: used for rendezvous. */
  struct crypt_path_t *pending_final_cpath;
  /** How many times has building a circuit for this task failed? */
  int failure_count;
} cpath_build_state_t;


#define CIRCUIT_MAGIC 0x35315243u
/** Struct for a path (circuit) through the onion routing network. */
struct circuit_t {
  uint32_t magic; /**< For memory debugging: must equal CIRCUIT_MAGIC. */

  int marked_for_close; /**< Should we close this circuit at the end of the
                         * main loop? */
  char *marked_for_close_file; /**< For debugging: in which file was this
                                * circuit marked for close? */

  /** The IPv4 address of the OR that is next in this circuit. */
  uint32_t n_addr;
  /** The port for the OR that is next in this circuit. */
  uint16_t n_port;
  /** The OR connection that is previous in this circuit. */
  connection_t *p_conn;
  /** The OR connection that is next in this circuit. */
  connection_t *n_conn;
  /** The identity hash of n_conn. */
  char n_conn_id_digest[DIGEST_LEN];
  /** Linked list of AP streams associated with this circuit. */
  connection_t *p_streams;
  /** Linked list of Exit streams associated with this circuit. */
  connection_t *n_streams;
  /** Linked list of Exit streams associated with this circuit that are
   * still being resolved. */
  connection_t *resolving_streams;
  /** The next stream_id that will be tried when we're attempting to
   * construct a new AP stream originating at this circuit. */
  uint16_t next_stream_id;
  /** How many relay data cells can we package (read from edge streams)
   * on this circuit before we receive a circuit-level sendme cell asking
   * for more? */
  int package_window;
  /** How many relay data cells will we deliver (write to edge streams)
   * on this circuit? When deliver_window gets low, we send some
   * circuit-level sendme cells to indicate that we're willing to accept
   * more. */
  int deliver_window;

  /** The circuit_id used in the previous (backward) hop of this circuit. */
  uint16_t p_circ_id;
  /** The circuit_id used in the next (forward) hop of this circuit. */
  uint16_t n_circ_id;

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

  /** Build state for this circuit. It includes the intended path
   * length, the chosen exit router, rendezvous information, etc.
   */
  cpath_build_state_t *build_state;
  /** The doubly-linked list of crypt_path_t entries, one per hop,
   * for this circuit. This includes ciphers for each hop,
   * integrity-checking digests for each hop, and package/delivery
   * windows for each hop.
   *
   * The cpath field is defined only when we are the circuit's origin.
   */
  crypt_path_t *cpath;

  /** For storage while passing to cpuworker, or while n_conn is pending. */
  char onionskin[ONIONSKIN_CHALLENGE_LEN];

  char handshake_digest[DIGEST_LEN]; /**< Stores KH for intermediate hops. */

  time_t timestamp_created; /**< When was this circuit created? */
  time_t timestamp_dirty; /**< When the circuit was first used, or 0 if the
                           * circuit is clean. */

  uint8_t state; /**< Current status of this circuit. */
  uint8_t purpose; /**< Why are we creating this circuit? */

  /**
   * The rend_query field holds y portion of y.onion (nul-terminated)
   * if purpose is C_INTRODUCING or C_ESTABLISH_REND, or is a C_GENERAL
   * for a hidden service, or is S_*.
   */
  char rend_query[REND_SERVICE_ID_LEN+1];

  /** The rend_pk_digest field holds a hash of location-hidden service's
   * PK if purpose is INTRO_POINT or S_ESTABLISH_INTRO or S_RENDEZVOUSING.
   */
  char rend_pk_digest[DIGEST_LEN];

  /** Holds rendezvous cookie if purpose is REND_POINT_WAITING or
   * C_ESTABLISH_REND. Filled with zeroes otherwise.
   */
  char rend_cookie[REND_COOKIE_LEN];

  /** Points to spliced circuit if purpose is REND_ESTABLISHED, and circuit
   * is not marked for close. */
  struct circuit_t *rend_splice;

  struct circuit_t *next; /**< Next circuit in linked list. */
};

typedef struct circuit_t circuit_t;

/** Configuration options for a Tor process */
typedef struct {
  struct config_line_t *LogOptions; /**< List of configuration lines
                                     * for logfiles */

  char *DebugLogFile; /**< Where to send verbose log messages. */
  char *DataDirectory; /**< OR only: where to store long-term data. */
  char *RouterFile; /**< Where to find starting list of ORs. */
  char *Nickname; /**< OR only: nickname of this onion router. */
  char *Address; /**< OR only: configured address for this onion router. */
  char *PidFile; /**< Where to store PID of Tor process. */

  char *ExitNodes; /**< Comma-separated list of nicknames of ORs to consider
                    * as exits. */
  char *EntryNodes; /**< Comma-separated list of nicknames of ORs to consider
                     * as entry points. */
  char *ExcludeNodes; /**< Comma-separated list of nicknames of ORs not to
                       * use in circuits. */

  char *RendNodes; /**< Comma-separated list of nicknames used as introduction
                    * points. */
  char *RendExcludeNodes; /**< Comma-separated list of nicknames not to use
                           * as introduction points. */

  struct config_line_t *ExitPolicy; /**< Lists of exit policy components. */
  struct config_line_t *SocksPolicy; /**< Lists of socks policy components */
  struct config_line_t *SocksBindAddress;
  /**< Addresses to bind for listening for SOCKS connections. */
  struct config_line_t *ORBindAddress;
  /**< Addresses to bind for listening for OR connections. */
  struct config_line_t *DirBindAddress;
  /**< Addresses to bind for listening for directory connections. */
  char *RecommendedVersions; /**< Directory server only: which versions of
                              * Tor should we tell users to run? */
  char *User; /**< Name of user to run Tor as. */
  char *Group; /**< Name of group to run Tor as. */
  double PathlenCoinWeight; /**< Parameter used to configure average path
                             * length (alpha in geometric distribution). */
  int ORPort; /**< Port to listen on for OR connections. */
  int SocksPort; /**< Port to listen on for SOCKS connections. */
  int DirPort; /**< Port to listen on for directory connections. */
  int AuthoritativeDir; /**< Boolean: is this an authoritative directory? */
  int ClientOnly; /**< Boolean: should we never evolve into a server role? */
  int MaxConn; /**< Maximum number of simultaneous connections. */
  int TrafficShaping; /**< Unused. */
  int LinkPadding; /**< Unused. */
  int IgnoreVersion; /**< If true, run no matter what versions of Tor the
                      * directory recommends. */
  int RunAsDaemon; /**< If true, run in the background. (Unix only) */
  int DirFetchPostPeriod; /**< How often do we fetch new directories
                           * and post server descriptros to the directory
                           * server? */
  int KeepalivePeriod; /**< How often do we send padding cells to keep
                        * connections alive? */
  int MaxOnionsPending; /**< How many circuit CREATE requests do we allow
                         * to wait simultaneously before we start dropping
                         * them? */
  int NewCircuitPeriod; /**< How long do we use a circuit before building
                         * a new one? */
  int BandwidthRate; /**< How much bandwidth, on average, are we willing to
                      * use in a second? */
  int BandwidthBurst; /**< How much bandwidth, at maximum, are we willing to
                       * use in a second? */
  int NumCpus; /**< How many CPUs should we try to use? */
  int RunTesting; /**< If true, create testing circuits to measure how well the
                   * other ORs are running. */
  struct config_line_t *RendConfigLines; /**< List of configuration lines
                                          * for rendezvous services. */
  char *ContactInfo; /** Contact info to be published in the directory */
} or_options_t;

/* XXX are these good enough defaults? */
#define MAX_SOCKS_REPLY_LEN 1024
#define MAX_SOCKS_ADDR_LEN 256
#define SOCKS_COMMAND_CONNECT 0x01
#define SOCKS_COMMAND_RESOLVE 0xF0
/** State of a SOCKS request from a user to an OP */
struct socks_request_t {
  char socks_version; /**< Which version of SOCKS did the client use? */
  int command; /**< What has the user requested? One of CONNECT or RESOLVE. */
  int replylen; /**< Length of <b>reply</b>. */
  char reply[MAX_SOCKS_REPLY_LEN]; /**< Write an entry into this string if
                                    * we want to specify our own socks reply,
                                    * rather than using the default socks4 or
                                    * socks5 socks reply. We use this for the
                                    * two-stage socks5 handshake.
                                    */
  int has_finished; /**< Has the SOCKS handshake finished? */
  char address[MAX_SOCKS_ADDR_LEN]; /**< What address did the client ask to connect to? */
  uint16_t port; /**< What port did the client ask to connect to? */
};

/* all the function prototypes go here */

/********************************* buffers.c ***************************/

buf_t *buf_new();
buf_t *buf_new_with_capacity(size_t size);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);

size_t buf_datalen(const buf_t *buf);
size_t buf_capacity(const buf_t *buf);
const char *_buf_peek_raw_buffer(const buf_t *buf);

int read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof);
int read_to_buf_tls(tor_tls *tls, size_t at_most, buf_t *buf);

int flush_buf(int s, buf_t *buf, int *buf_flushlen);
int flush_buf_tls(tor_tls *tls, buf_t *buf, int *buf_flushlen);

int write_to_buf(const char *string, int string_len, buf_t *buf);
int fetch_from_buf(char *string, size_t string_len, buf_t *buf);
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, int max_headerlen,
                        char **body_out, int *body_used, int max_bodylen);
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req);

void assert_buf_ok(buf_t *buf);

/********************************* circuitbuild.c **********************/

void circuit_log_path(int severity, circuit_t *circ);
void circuit_rep_hist_note_result(circuit_t *circ);
void circuit_dump_by_conn(connection_t *conn, int severity);
circuit_t *circuit_establish_circuit(uint8_t purpose,
                                     const char *exit_digest);
void circuit_n_conn_done(connection_t *or_conn, int success);
int circuit_send_next_onion_skin(circuit_t *circ);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data, int reverse);
int circuit_finish_handshake(circuit_t *circ, char *reply);
int circuit_truncated(circuit_t *circ, crypt_path_t *layer);
int onionskin_answer(circuit_t *circ, unsigned char *payload, unsigned char *keys);
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);

/********************************* circuitlist.c ***********************/

extern char *circuit_state_to_string[];
void circuit_close_all_marked(void);
circuit_t *circuit_new(uint16_t p_circ_id, connection_t *p_conn);
void circuit_free_cpath_node(crypt_path_t *victim);
circuit_t *circuit_get_by_circ_id_conn(uint16_t circ_id, connection_t *conn);
circuit_t *circuit_get_by_conn(connection_t *conn);
circuit_t *circuit_get_by_rend_query_and_purpose(const char *rend_query, uint8_t purpose);
circuit_t *circuit_get_next_by_pk_and_purpose(circuit_t *start,
                                         const char *digest, uint8_t purpose);
circuit_t *circuit_get_rendezvous(const char *cookie);
int circuit_count_building(uint8_t purpose);
circuit_t *circuit_get_youngest_clean_open(uint8_t purpose);
int _circuit_mark_for_close(circuit_t *circ);

#define circuit_mark_for_close(c)                                       \
  do {                                                                  \
    if (_circuit_mark_for_close(c)<0) {                                 \
      log(LOG_WARN,"Duplicate call to circuit_mark_for_close at %s:%d (first at %s:%d)", \
          __FILE__,__LINE__,c->marked_for_close_file,c->marked_for_close); \
    } else {                                                            \
      c->marked_for_close_file = __FILE__;                              \
      c->marked_for_close = __LINE__;                                   \
    }                                                                   \
  } while (0)

void assert_cpath_layer_ok(const crypt_path_t *cp);
void assert_circuit_ok(const circuit_t *c);

/********************************* circuituse.c ************************/

void circuit_expire_building(time_t now);
int circuit_stream_is_being_handled(connection_t *conn);
void circuit_build_needed_circs(time_t now);
void circuit_detach_stream(circuit_t *circ, connection_t *conn);
void circuit_about_to_close_connection(connection_t *conn);
void circuit_has_opened(circuit_t *circ);
void circuit_build_failed(circuit_t *circ);
circuit_t *circuit_launch_by_nickname(uint8_t purpose, const char *exit_nickname);
circuit_t *circuit_launch_by_identity(uint8_t purpose, const char *exit_digest);
void circuit_reset_failure_count(void);
int connection_ap_handshake_attach_circuit(connection_t *conn);

int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data,int reverse);
int circuit_finish_handshake(circuit_t *circ, char *reply);
int circuit_truncated(circuit_t *circ, crypt_path_t *layer);

void assert_cpath_layer_ok(const crypt_path_t *c);
void assert_circuit_ok(const circuit_t *c);

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, connection_t *conn);

extern unsigned long stats_n_padding_cells_processed;
extern unsigned long stats_n_create_cells_processed;
extern unsigned long stats_n_created_cells_processed;
extern unsigned long stats_n_relay_cells_processed;
extern unsigned long stats_n_destroy_cells_processed;

/********************************* config.c ***************************/

struct config_line_t {
  char *key;
  char *value;
  struct config_line_t *next;
};

int config_assign_default_dirservers(void);
int getconfig(int argc, char **argv, or_options_t *options);
int config_init_logs(or_options_t *options);
void config_parse_exit_policy(struct config_line_t *cfg,
                              struct exit_policy_t **dest);
void exit_policy_free(struct exit_policy_t *p);
const char *get_data_directory(or_options_t *options);

/********************************* connection.c ***************************/

#define CONN_TYPE_TO_STRING(t) (((t) < _CONN_TYPE_MIN || (t) > _CONN_TYPE_MAX) ? \
  "Unknown" : conn_type_to_string[(t)])

extern char *conn_type_to_string[];
extern char *conn_state_to_string[][_CONN_TYPE_MAX+1];

connection_t *connection_new(int type);
void connection_free(connection_t *conn);
void connection_free_all(void);
void connection_about_to_close_connection(connection_t *conn);
void connection_close_immediate(connection_t *conn);
int _connection_mark_for_close(connection_t *conn);

#define connection_mark_for_close(c)                                    \
  do {                                                                  \
    if (_connection_mark_for_close(c)<0) {                              \
      log(LOG_WARN,"Duplicate call to connection_mark_for_close at %s:%d (first at %s:%d)", \
          __FILE__,__LINE__,c->marked_for_close_file,c->marked_for_close); \
    } else {                                                            \
      c->marked_for_close_file = __FILE__;                              \
      c->marked_for_close = __LINE__;                                   \
    }                                                                   \
  } while (0)

void connection_expire_held_open(void);

int connection_connect(connection_t *conn, char *address, uint32_t addr, uint16_t port);
int retry_all_listeners(void);

void connection_bucket_init(void);
void connection_bucket_refill(struct timeval *now);

int connection_handle_read(connection_t *conn);

int connection_fetch_from_buf(char *string, int len, connection_t *conn);

int connection_wants_to_flush(connection_t *conn);
int connection_outbuf_too_full(connection_t *conn);
int connection_handle_write(connection_t *conn);
void connection_write_to_buf(const char *string, int len, connection_t *conn);

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port);
connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port);
connection_t *connection_get_by_identity_digest(const char *digest, int type);

connection_t *connection_get_by_type(int type);
connection_t *connection_get_by_type_state(int type, int state);
connection_t *connection_get_by_type_state_lastwritten(int type, int state);
connection_t *connection_get_by_type_rendquery(int type, const char *rendquery);

#define connection_speaks_cells(conn) ((conn)->type == CONN_TYPE_OR)
#define connection_has_pending_tls_data(conn) \
  ((conn)->type == CONN_TYPE_OR && \
   (conn)->state == OR_CONN_STATE_OPEN && \
   tor_tls_get_pending_bytes((conn)->tls))
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);
int connection_state_is_connecting(connection_t *conn);

int connection_send_destroy(uint16_t circ_id, connection_t *conn);

void assert_connection_ok(connection_t *conn, time_t now);

/********************************* connection_edge.c ***************************/

int connection_edge_process_inbuf(connection_t *conn);
int connection_edge_destroy(uint16_t circ_id, connection_t *conn);
int connection_edge_end(connection_t *conn, char reason, crypt_path_t *cpath_layer);
int connection_edge_finished_flushing(connection_t *conn);
int connection_edge_finished_connecting(connection_t *conn);

int connection_ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ);
int connection_ap_handshake_send_resolve(connection_t *ap_conn, circuit_t *circ);

int connection_ap_make_bridge(char *address, uint16_t port);
void connection_ap_handshake_socks_reply(connection_t *conn, char *reply,
                                         int replylen, char success);
void connection_ap_handshake_socks_resolved(connection_t *conn,
                                            int answer_type,
                                            int answer_len,
                                            const char *answer);

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
int connection_exit_begin_resolve(cell_t *cell, circuit_t *circ);
void connection_exit_connect(connection_t *conn);
int connection_edge_is_rendezvous_stream(connection_t *conn);
int connection_ap_can_use_exit(connection_t *conn, routerinfo_t *exit);
void connection_ap_expire_beginning(void);
void connection_ap_attach_pending(void);

int socks_policy_permits_address(uint32_t addr);

void client_dns_init(void);
uint32_t client_dns_lookup_entry(const char *address);
int client_dns_incr_failures(const char *address);
void client_dns_set_entry(const char *address, uint32_t val);
void client_dns_clean(void);

/********************************* connection_or.c ***************************/

int connection_or_process_inbuf(connection_t *conn);
int connection_or_finished_flushing(connection_t *conn);
int connection_or_finished_connecting(connection_t *conn);

connection_t *connection_or_connect(uint32_t addr, uint16_t port,
                                    const char *id_digest);

int connection_tls_start_handshake(connection_t *conn, int receiving);
int connection_tls_continue_handshake(connection_t *conn);

void connection_or_write_cell_to_buf(const cell_t *cell, connection_t *conn);

/********************************* cpuworker.c *****************************/

void cpu_init(void);
void cpuworkers_rotate(void);
int connection_cpu_finished_flushing(connection_t *conn);
int connection_cpu_process_inbuf(connection_t *conn);
int assign_to_cpuworker(connection_t *cpuworker, unsigned char question_type,
                        void *task);

/********************************* directory.c ***************************/

void directory_post_to_dirservers(uint8_t purpose, const char *payload,
                                  int payload_len);
void directory_get_from_dirserver(uint8_t purpose, const char *payload,
                                  int payload_len);
int connection_dir_process_inbuf(connection_t *conn);
int connection_dir_finished_flushing(connection_t *conn);
int connection_dir_finished_connecting(connection_t *conn);

/********************************* dirserv.c ***************************/

int dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk);
int dirserv_parse_fingerprint_file(const char *fname);
int dirserv_router_fingerprint_is_known(const routerinfo_t *router);
void dirserv_free_fingerprint_list();
int dirserv_add_descriptor(const char **desc);
int dirserv_load_from_directory_string(const char *dir);
void dirserv_free_descriptors();
void dirserv_remove_old_servers(void);
int dirserv_dump_directory_to_string(char *s, unsigned int maxlen,
                                     crypto_pk_env_t *private_key);
void directory_set_dirty(void);
size_t dirserv_get_directory(const char **cp);
size_t dirserv_get_runningrouters(const char **rr);
void dirserv_set_cached_directory(const char *directory, time_t when);

/********************************* dns.c ***************************/

void dns_init(void);
int connection_dns_finished_flushing(connection_t *conn);
int connection_dns_process_inbuf(connection_t *conn);
void dnsworkers_rotate(void);
void connection_dns_remove(connection_t *conn);
void assert_connection_edge_not_dns_pending(connection_t *conn);
void assert_all_pending_dns_resolves_ok(void);
void dns_cancel_pending_resolve(char *question);
int dns_resolve(connection_t *exitconn);

/********************************* main.c ***************************/

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
int connection_in_array(connection_t *conn);

void get_connection_array(connection_t ***array, int *n);

void connection_watch_events(connection_t *conn, short events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void directory_has_arrived(void);
int authdir_mode(void);
int clique_mode(void);
int server_mode(void);
int advertised_server_mode(void);
int proxy_mode(void);

int main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int onion_pending_add(circuit_t *circ);
circuit_t *onion_next_task(void);
void onion_pending_remove(circuit_t *circ);

int onion_skin_create(crypto_pk_env_t *router_key,
                      crypto_dh_env_t **handshake_state_out,
                      char *onion_skin_out);

int onion_skin_server_handshake(char *onion_skin,
                                crypto_pk_env_t *private_key,
                                crypto_pk_env_t *prev_private_key,
                                char *handshake_reply_out,
                                char *key_out,
                                int key_out_len);

int onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
                             char *handshake_reply,
                             char *key_out,
                             int key_out_len);

/********************************* relay.c ***************************/

extern unsigned long stats_n_relay_cells_relayed;
extern unsigned long stats_n_relay_cells_delivered;

int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction);

void relay_header_pack(char *dest, const relay_header_t *src);
void relay_header_unpack(relay_header_t *dest, const char *src);
int connection_edge_send_command(connection_t *fromconn, circuit_t *circ,
                                 int relay_command, const char *payload,
                                 int payload_len, crypt_path_t *cpath_layer);
int connection_edge_package_raw_inbuf(connection_t *conn);
void connection_edge_consider_sending_sendme(connection_t *conn);

extern uint64_t stats_n_data_cells_packaged;
extern uint64_t stats_n_data_bytes_packaged;
extern uint64_t stats_n_data_cells_received;
extern uint64_t stats_n_data_bytes_received;

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
void rep_hist_note_bytes_read(int num_bytes, time_t when);
void rep_hist_note_bytes_written(int num_bytes, time_t when);
int rep_hist_bandwidth_assess(time_t when);

/********************************* rendclient.c ***************************/

void rend_client_introcirc_has_opened(circuit_t *circ);
void rend_client_rendcirc_has_opened(circuit_t *circ);
int rend_client_introduction_acked(circuit_t *circ, const char *request, int request_len);
void rend_client_refetch_renddesc(const char *query);
int rend_client_remove_intro_point(char *failed_intro, const char *query);
int rend_client_rendezvous_acked(circuit_t *circ, const char *request, int request_len);
int rend_client_receive_rendezvous(circuit_t *circ, const char *request, int request_len);
void rend_client_desc_fetched(char *query, int success);

char *rend_client_get_random_intro(char *query);
int rend_parse_rendezvous_address(char *address);

int rend_client_send_introduction(circuit_t *introcirc, circuit_t *rendcirc);

/********************************* rendcommon.c ***************************/

typedef struct rend_service_descriptor_t {
  crypto_pk_env_t *pk;
  time_t timestamp;
  int n_intro_points;
  char **intro_points;
} rend_service_descriptor_t;

int rend_cmp_service_ids(const char *one, const char *two);

void rend_process_relay_cell(circuit_t *circ, int command, int length,
                             const char *payload);

void rend_service_descriptor_free(rend_service_descriptor_t *desc);
int rend_encode_service_descriptor(rend_service_descriptor_t *desc,
                                   crypto_pk_env_t *key,
                                   char **str_out,
                                   int *len_out);
rend_service_descriptor_t *rend_parse_service_descriptor(const char *str, int len);
int rend_get_service_id(crypto_pk_env_t *pk, char *out);

typedef struct rend_cache_entry_t {
  int len; /* Length of desc */
  time_t received; /* When did we get the descriptor? */
  char *desc; /* Service descriptor */
  rend_service_descriptor_t *parsed; /* Parsed value of 'desc' */
} rend_cache_entry_t;

void rend_cache_init(void);
void rend_cache_clean(void);
int rend_valid_service_id(const char *query);
int rend_cache_lookup_desc(const char *query, const char **desc, int *desc_len);
int rend_cache_lookup_entry(const char *query, rend_cache_entry_t **entry_out);
int rend_cache_store(const char *desc, int desc_len);

/********************************* rendservice.c ***************************/

int rend_config_services(or_options_t *options);
int rend_service_load_keys(void);
void rend_services_init(void);
void rend_services_introduce(void);
void rend_services_upload(int force);

void rend_service_intro_has_opened(circuit_t *circuit);
int rend_service_intro_established(circuit_t *circuit, const char *request, int request_len);
void rend_service_rendezvous_has_opened(circuit_t *circuit);
int rend_service_introduce(circuit_t *circuit, const char *request, int request_len);
void rend_service_relaunch_rendezvous(circuit_t *oldcirc);
int rend_service_set_connection_addr_port(connection_t *conn, circuit_t *circ);
void rend_service_dump_stats(int severity);

/********************************* rendmid.c *******************************/
int rend_mid_establish_intro(circuit_t *circ, const char *request, int request_len);
int rend_mid_introduce(circuit_t *circ, const char *request, int request_len);
int rend_mid_establish_rendezvous(circuit_t *circ, const char *request, int request_len);
int rend_mid_rendezvous(circuit_t *circ, const char *request, int request_len);

/********************************* router.c ***************************/

void set_onion_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_onion_key(void);
crypto_pk_env_t *get_previous_onion_key(void);
time_t get_onion_key_set_at(void);
void set_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_identity_key(void);
void dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last);
int init_keys(void);
crypto_pk_env_t *init_key_from_file(const char *fname);
void rotate_onion_key(void);
void router_set_advertised_bandwidth(int bw);
int router_get_advertised_bandwidth(void);

void router_retry_connections(void);
int router_is_clique_mode(routerinfo_t *router);
void router_upload_dir_desc_to_dirservers(void);
int router_compare_to_my_exit_policy(connection_t *conn);
routerinfo_t *router_get_my_routerinfo(void);
const char *router_get_my_descriptor(void);
int router_is_me(routerinfo_t *router);
int router_rebuild_descriptor(void);
int router_dump_router_to_string(char *s, int maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key);

/********************************* routerlist.c ***************************/

routerinfo_t *router_pick_directory_server(int requireauth, int requireothers);
int all_directory_servers_down(void);
struct smartlist_t;
void add_nickname_list_to_smartlist(struct smartlist_t *sl, const char *list);
void router_add_running_routers_to_smartlist(struct smartlist_t *sl);
int router_nickname_matches(routerinfo_t *router, const char *nickname);
routerinfo_t *router_choose_random_node(char *preferred, char *excluded,
                                        struct smartlist_t *excludedsmartlist);
routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port);
routerinfo_t *router_get_by_nickname(const char *nickname);
routerinfo_t *router_get_by_hexdigest(const char *hexdigest);
routerinfo_t *router_get_by_digest(const char *digest);
int router_digest_is_trusted_dir(const char *digest);
void router_get_routerlist(routerlist_t **prouterlist);
void routerlist_free(routerlist_t *routerlist);
void routerlist_clear_trusted_directories(void);
void routerinfo_free(routerinfo_t *router);
routerinfo_t *routerinfo_copy(const routerinfo_t *router);
void router_mark_as_down(const char *digest);
void routerlist_remove_old_routers(void);
int router_load_routerlist_from_file(char *routerfile, int trusted);
int router_load_routerlist_from_string(const char *s, int trusted);
int router_load_routerlist_from_directory(const char *s,crypto_pk_env_t *pkey);
int router_compare_addr_to_exit_policy(uint32_t addr, uint16_t port,
                                       struct exit_policy_t *policy);
#define ADDR_POLICY_ACCEPTED 0
#define ADDR_POLICY_REJECTED -1
#define ADDR_POLICY_UNKNOWN 1
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port);
int router_exit_policy_rejects_all(routerinfo_t *router);
void running_routers_free(running_routers_t *rr);
void routerlist_update_from_runningrouters(routerlist_t *list,
                                           running_routers_t *rr);
void router_update_status_from_smartlist(routerinfo_t *r,
                                         time_t list_time,
                                         smartlist_t *running_list);

/********************************* routerparse.c ************************/

typedef struct tor_version_t {
  int major;
  int minor;
  int micro;
  enum { VER_PRE=0, VER_RC=1, VER_RELEASE=2 } status;
  int patchlevel;
  enum { IS_CVS=0, IS_NOT_CVS=1} cvs;
} tor_version_t;

int router_get_router_hash(const char *s, char *digest);
int router_get_dir_hash(const char *s, char *digest);
int router_get_runningrouters_hash(const char *s, char *digest);
int router_parse_list_from_string(const char **s,
                                  routerlist_t **dest,
                                  smartlist_t *good_nickname_list,
                                  time_t published);
int router_parse_routerlist_from_directory(const char *s,
                                           routerlist_t **dest,
                                           crypto_pk_env_t *pkey);
running_routers_t *router_parse_runningrouters(const char *str);
routerinfo_t *router_parse_entry_from_string(const char *s, const char *end);
int router_add_exit_policy_from_string(routerinfo_t *router, const char *s);
struct exit_policy_t *router_parse_exit_policy_from_string(const char *s);
int check_software_version_against_directory(const char *directory,
                                             int ignoreversion);
int tor_version_parse(const char *s, tor_version_t *out);
int tor_version_compare(tor_version_t *a, tor_version_t *b);
int tor_version_compare_to_mine(const char *s);

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
