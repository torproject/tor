/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file or.h
 * \brief Master header file for Tor-specific functionality.
 **/

#ifndef __OR_H
#define __OR_H
#define OR_H_ID "$Id$"

#include "orconfig.h"
#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdlib.h>
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
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include "../common/torint.h"
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

/** Upper bound on maximum simultaneous connections; can be lowered by
 * config file. */
#ifdef CYGWIN
/* http://archives.seul.org/or/talk/Aug-2006/msg00210.html */
#define MAXCONNECTIONS 3200
#else
/* very high by default. "nobody should need more than this..." */
#define MAXCONNECTIONS 15000
#endif

#ifdef MS_WINDOWS
/* No, we don't need to redefine FD_SETSIZE before including winsock:
 * we use libevent now, and libevent handles the select() stuff.  Yes,
 * some documents imply that we need to redefine anyway if we're using
 * select() anywhere in our application or in anything it links to: these
 * documents are either the holy texts of a cargo cult of network
 * programmers, or more likely a simplification of what's going on for
 * people who haven't read winsock[2].c for themselves.
 */
#if (_MSC_VER <= 1300)
#include <winsock.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif
#endif

#ifdef MS_WINDOWS
#include <io.h>
#include <process.h>
#include <direct.h>
#include <windows.h>
#define snprintf _snprintf
#endif

#ifdef HAVE_EVENT_H
#include <event.h>
#else
#error "Tor requires libevent to build."
#endif

#include "../common/crypto.h"
#include "../common/tortls.h"
#include "../common/log.h"
#include "../common/compat.h"
#include "../common/container.h"
#include "../common/util.h"
#include "../common/torgzip.h"

/* These signals are defined to help control_signal_act work.
 * XXXX Move into compat.h ?
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

#if (SIZEOF_CELL_T != 0)
/* On Irix, stdlib.h defines a cell_t type, so we need to make sure
 * that our stuff always calls cell_t something different. */
#define cell_t tor_cell_t
#endif

#define MAX_NICKNAME_LEN 19
/* Hex digest plus dollar sign. */
#define MAX_HEX_NICKNAME_LEN (HEX_DIGEST_LEN+1)
/** Maximum size, in bytes, for resized buffers. */
#define MAX_BUF_SIZE ((1<<24)-1)
#define MAX_DIR_SIZE MAX_BUF_SIZE

/* For http parsing */
#define MAX_HEADERS_SIZE 50000
#define MAX_BODY_SIZE 500000

/** How long do we keep DNS cache entries before purging them (regardless of
 * their TTL)? */
#define MAX_DNS_ENTRY_AGE (30*60)
#define DEFAULT_DNS_TTL (30*60)
/** How long can a TTL be before we stop believing it? */
#define MAX_DNS_TTL (3*60*60)
/** How small can a TTL be before we stop believing it? */
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
/** How old do we let a saved descriptor get before removing it? */
#define OLD_ROUTER_DESC_MAX_AGE (60*60*60)
/** How old do we let a networkstatus get before ignoring it? */
#define NETWORKSTATUS_MAX_AGE (60*60*24)

typedef enum {
  CIRC_ID_TYPE_LOWER=0,
  CIRC_ID_TYPE_HIGHER=1
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
/** Connection from the main process to a DNS worker process. */
#define CONN_TYPE_DNSWORKER 10
/** Connection from the main process to a CPU worker process. */
#define CONN_TYPE_CPUWORKER 11
/** Type for listening for connections from user interface process. */
#define CONN_TYPE_CONTROL_LISTENER 12
/** Type for connections from user interface process. */
#define CONN_TYPE_CONTROL 13
/** Type for sockets listening for transparent proxy connections. */
#define CONN_TYPE_AP_TRANS_LISTENER 14
#define _CONN_TYPE_MAX 14

#define CONN_IS_EDGE(x) \
  ((x)->type == CONN_TYPE_EXIT || (x)->type == CONN_TYPE_AP)

/** State for any listener connection. */
#define LISTENER_STATE_READY 0

#define _DNSWORKER_STATE_MIN 1
/** State for a connection to a dnsworker process that's idle. */
#define DNSWORKER_STATE_IDLE 1
/** State for a connection to a dnsworker process that's resolving a
 * hostname. */
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
/** State for a connection to an OR: waiting for proxy command to flush. */
#define OR_CONN_STATE_PROXY_FLUSHING 2
/** State for a connection to an OR: waiting for proxy response. */
#define OR_CONN_STATE_PROXY_READING 3
/** State for a connection to an OR: SSL is handshaking, not done yet. */
#define OR_CONN_STATE_HANDSHAKING 4
/** State for a connection to an OR: Ready to send/receive cells. */
#define OR_CONN_STATE_OPEN 5
#define _OR_CONN_STATE_MAX 5

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

/* the AP state values must be disjoint from the EXIT state values */
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
/** State for a SOCKS connection: send RESOLVE, waiting for RESOLVED. */
#define AP_CONN_STATE_RESOLVE_WAIT 10
/** State for a SOCKS connection: ready to send and receive. */
#define AP_CONN_STATE_OPEN 11
/** State for a transparent proxy connection: waiting for original
 * destination. */
#define AP_CONN_STATE_ORIGDST_WAIT 12
#define _AP_CONN_STATE_MAX 12

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

#define DIR_CONN_IS_SERVER(conn) ((conn)->purpose == DIR_PURPOSE_SERVER)

#define _CONTROL_CONN_STATE_MIN 1
#define CONTROL_CONN_STATE_OPEN_V0 1
#define CONTROL_CONN_STATE_OPEN_V1 2
#define CONTROL_CONN_STATE_NEEDAUTH_V0 3
#define CONTROL_CONN_STATE_NEEDAUTH_V1 4
#define _CONTROL_CONN_STATE_MAX 4

#define _DIR_PURPOSE_MIN 1
/** A connection to a directory server: download a directory. */
#define DIR_PURPOSE_FETCH_DIR 1
/** A connection to a directory server: download just the list
 * of running routers. */
#define DIR_PURPOSE_FETCH_RUNNING_LIST 2
/** A connection to a directory server: download a rendezvous
 * descriptor. */
#define DIR_PURPOSE_FETCH_RENDDESC 3
/** A connection to a directory server: set after a rendezvous
 * descriptor is downloaded. */
#define DIR_PURPOSE_HAS_FETCHED_RENDDESC 4
/** A connection to a directory server: download one or more network-status
 * objects */
#define DIR_PURPOSE_FETCH_NETWORKSTATUS 5
/** A connection to a directory server: download one or more server
 * descriptors. */
#define DIR_PURPOSE_FETCH_SERVERDESC 6
/** A connection to a directory server: upload a server descriptor. */
#define DIR_PURPOSE_UPLOAD_DIR 7
/** A connection to a directory server: upload a rendezvous
 * descriptor. */
#define DIR_PURPOSE_UPLOAD_RENDDESC 8
/** Purpose for connection at a directory server. */
#define DIR_PURPOSE_SERVER 9
#define _DIR_PURPOSE_MAX 9

#define _EXIT_PURPOSE_MIN 1
/** This exit stream wants to do an ordinary connect. */
#define EXIT_PURPOSE_CONNECT 1
/** This exit stream wants to do a resolve (either normal or reverse). */
#define EXIT_PURPOSE_RESOLVE 2
#define _EXIT_PURPOSE_MAX 2

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

/** True iff the circuit purpose <b>p</b> is for a circuit that
 * originated at this node. */
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

#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_CONNECTREFUSED 3
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_TIMEOUT 7
/* 8 is unallocated. */
#define END_STREAM_REASON_HIBERNATING 9
#define END_STREAM_REASON_INTERNAL 10
#define END_STREAM_REASON_RESOURCELIMIT 11
#define END_STREAM_REASON_CONNRESET 12
#define END_STREAM_REASON_TORPROTOCOL 13

/* These high-numbered end reasons are not part of the official spec,
 * and are not intended to be put in relay end cells. They are here
 * to be more informative when sending back socks replies to the
 * application. */
#define END_STREAM_REASON_ALREADY_SOCKS_REPLIED 256
#define END_STREAM_REASON_CANT_ATTACH 257
#define END_STREAM_REASON_NET_UNREACHABLE 258

#define RESOLVED_TYPE_HOSTNAME 0
#define RESOLVED_TYPE_IPV4 4
#define RESOLVED_TYPE_IPV6 6
#define RESOLVED_TYPE_ERROR_TRANSIENT 0xF0
#define RESOLVED_TYPE_ERROR 0xF1

/* XXX We should document the meaning of these. */
#define END_CIRC_AT_ORIGIN           -1
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
#define _END_CIRC_REASON_MAX            8

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
#define CELL_CREATE_FAST 5
#define CELL_CREATED_FAST 6

/** How long to test reachability before complaining to the user. */
#define TIMEOUT_UNTIL_UNREACHABILITY_COMPLAINT (20*60)

/* legal characters in a nickname */
#define LEGAL_NICKNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/** Name to use in client TLS certificates if no nickname is given.*/
#define DEFAULT_CLIENT_NICKNAME "client"

#define SOCKS4_NETWORK_LEN 8

typedef enum {
  SOCKS5_SUCCEEDED                  = 0x00,
  SOCKS5_GENERAL_ERROR              = 0x01,
  SOCKS5_NOT_ALLOWED                = 0x02,
  SOCKS5_NET_UNREACHABLE            = 0x03,
  SOCKS5_HOST_UNREACHABLE           = 0x04,
  SOCKS5_CONNECTION_REFUSED         = 0x05,
  SOCKS5_TTL_EXPIRED                = 0x06,
  SOCKS5_COMMAND_NOT_SUPPORTED      = 0x07,
  SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
} socks5_reply_status_t;

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

/** Parsed onion routing cell.  All communication between nodes
 * is via cells. */
typedef struct {
  uint16_t circ_id; /**< Circuit which received the cell. */
  uint8_t command; /**< Type of the cell: one of PADDING, CREATE, RELAY,
                    * or DESTROY. */
  char payload[CELL_PAYLOAD_SIZE]; /**< Cell body. */
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

  uint8_t type; /**< What kind of connection is this? */
  uint8_t state; /**< Current state of this connection. */
  uint8_t purpose; /**< Only used for DIR and EXIT types currently. */

  /* The next fields are all one-bit booleans. Some are only applicable
   * to connection subtypes, but we hold them here anyway, to save space.
   * (Currently, they all fit into a single byte.) */
  unsigned wants_to_read:1; /**< Boolean: should we start reading again once
                            * the bandwidth throttler allows it? */
  unsigned wants_to_write:1; /**< Boolean: should we start writing again once
                             * the bandwidth throttler allows reads? */
  unsigned hold_open_until_flushed:1; /**< Despite this connection's being
                                      * marked for close, do we flush it
                                      * before closing it? */
  unsigned int inbuf_reached_eof:1; /**< Boolean: did read() return 0 on this
                                     * conn? */
  unsigned edge_has_sent_end:1; /**< For debugging; only used on edge
                         * connections.  Set once we've set the stream end,
                         * and check in circuit_about_to_close_connection(). */
  /** For control connections only. If set, we send extended info with control
   * events as appropriate. */
  unsigned int control_events_are_extended:1;
  /** Used for OR conns that shouldn't get any new circs attached to them. */
  unsigned int or_is_obsolete:1;
  /** For AP connections only. If 1, and we fail to reach the chosen exit,
   * stop requiring it. */
  unsigned int chosen_exit_optional:1;

  int s; /**< Our socket; -1 if this connection is closed. */
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

  uint32_t addr; /**< IP of the other side of the connection; used to identify
                  * routers, along with port. */
  uint16_t port; /**< If non-zero, port  on the other end
                  * of the connection. */
  uint16_t marked_for_close; /**< Should we close this conn on the next
                              * iteration of the main loop? (If true, holds
                              * the line number where this connection was
                              * marked.) */
  const char *marked_for_close_file; /**< For debugging: in which file were
                                      * we marked for close? */
  char *address; /**< FQDN (or IP) of the guy on the other end.
                  * strdup into this, because free_connection frees it. */

} connection_t;

/** Subtype of connection_t for an "OR connection" -- that is, one that speaks
 * cells over TLS. */
typedef struct or_connection_t {
  connection_t _base;

  char identity_digest[DIGEST_LEN]; /**< Hash of the public RSA key for
                                     * the other side's signing key. */
  char *nickname; /**< Nickname of OR on other side (if any). */

  tor_tls_t *tls; /**< TLS connection state */

  time_t timestamp_lastempty; /**< When was the outbuf last completely empty?*/

  /* bandwidth* and receiver_bucket only used by ORs in OPEN state: */
  int bandwidthrate; /**< Bytes/s added to the bucket. (OPEN ORs only.) */
  int bandwidthburst; /**< Max bucket size for this conn. (OPEN ORs only.) */
  int receiver_bucket; /**< When this hits 0, stop receiving. Every second we
                        * add 'bandwidthrate' to this, capping it at
                        * bandwidthburst. (OPEN ORs only) */
  circ_id_type_t circ_id_type; /**< When we send CREATE cells along this
                                * connection, which half of the space should
                                * we use? */
  int n_circuits; /**< How many circuits use this connection as p_conn or
                   * n_conn ? */
  struct or_connection_t *next_with_same_id; /**< Next connection with same
                                           * identity digest as this one. */
  uint16_t next_circ_id; /**< Which circ_id do we try to use next on
                          * this connection?  This is always in the
                          * range 0..1<<15-1. */
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

  uint16_t stream_id; /**< The stream ID used for this edge connection on its
                       * circuit */

  /** Quasi-global identifier for this connection; used for control.c */
  /* XXXX NM This can get re-used after 2**32 streams */
  uint32_t global_identifier;

  char rend_query[REND_SERVICE_ID_LEN+1]; /**< What rendezvous service are we
                                           * querying for? (AP only) */

  /** Number of times we've reassigned this application connection to
   * a new circuit. We keep track because the timeout is longer if we've
   * already retried several times. */
  uint8_t num_socks_retries;

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
  enum {
    DIR_SPOOL_NONE=0, DIR_SPOOL_SERVER_BY_DIGEST, DIR_SPOOL_SERVER_BY_FP,
    DIR_SPOOL_CACHED_DIR, DIR_SPOOL_NETWORKSTATUS
  } dir_spool_src;
  smartlist_t *fingerprint_stack;
  struct cached_dir_t *cached_dir;
  off_t cached_dir_offset;
  tor_zlib_state_t *zlib_state;

  char rend_query[REND_SERVICE_ID_LEN+1]; /**< What rendezvous service are we
                                           * querying for? */

  char identity_digest[DIGEST_LEN]; /**< Hash of the public RSA key for
                                     * the directory server's signing key. */
} dir_connection_t;

/** Subtype of connection_t for an connection to a controller. */
typedef struct control_connection_t {
  connection_t _base;

  uint32_t event_mask; /**< Bitfield: which events does this controller
                        * care about? */
  uint32_t incoming_cmd_len;
  uint32_t incoming_cmd_cur_len;
  char *incoming_cmd;
  /* Used only by control v0 connections */
  uint16_t incoming_cmd_type;
} control_connection_t;

/** Cast a connection_t subtype pointer to a connection_t **/
#define TO_CONN(c) &(((c)->_base))
/** Helper macro: Given a pointer to to._base, of type from*, return &to. */
#define DOWNCAST(to, ptr) \
  (to*) (((char*)(ptr)) - STRUCT_OFFSET(to, _base))

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

typedef enum {
  ADDR_POLICY_ACCEPT=1,
  ADDR_POLICY_REJECT=2,
} addr_policy_action_t;

/** A linked list of policy rules */
typedef struct addr_policy_t {
  addr_policy_action_t policy_type; /**< What to do when the policy matches.*/
  char *string; /**< String representation of this rule. */
  uint32_t addr; /**< Base address to accept or reject. */
  uint32_t msk; /**< Accept/reject all addresses <b>a</b> such that
                 * a &amp; msk == <b>addr</b> &amp; msk . */
  uint16_t prt_min; /**< Lowest port number to accept/reject. */
  uint16_t prt_max; /**< Highest port number to accept/reject. */

  struct addr_policy_t *next; /**< Next rule in list. */
} addr_policy_t;

/** A cached_dir_t represents a cacheable directory object, along with its
 * compressed form. */
typedef struct cached_dir_t {
  char *dir; /**< Contents of this object */
  char *dir_z; /**< Compressed contents of this object. */
  size_t dir_len; /**< Length of <b>dir</b> */
  size_t dir_z_len; /**< Length of <b>dir_z</b> */
  time_t published; /**< When was this object published */
  int refcnt; /**< Reference count for this cached_dir_t. */
} cached_dir_t;

typedef enum {
   SAVED_NOWHERE=0, SAVED_IN_CACHE, SAVED_IN_JOURNAL
} saved_location_t;

/** Information need to cache an onion router's descriptor. */
typedef struct signed_descriptor_t {
  char *signed_descriptor_body;
  size_t signed_descriptor_len;
  char signed_descriptor_digest[DIGEST_LEN];
  char identity_digest[DIGEST_LEN];
  time_t published_on;
  saved_location_t saved_location;
  off_t saved_offset;
} signed_descriptor_t;

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
  addr_policy_t *exit_policy; /**< What streams will this OR permit
                                      * to exit? */
  long uptime; /**< How many seconds the router claims to have been up */
  smartlist_t *declared_family; /**< Nicknames of router which this router
                                 * claims are its family. */
  char *contact_info; /**< Declared contact info for this router. */
  unsigned int is_hibernating:1; /**< Whether the router claims to be
                                  * hibernating */
  unsigned int has_old_dnsworkers:1; /**< Whether the router is using
                                      * dnsworker code. */

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

/** Tor can use this desc for circuit-building. */
#define ROUTER_PURPOSE_GENERAL 0
/** Tor should avoid using this desc for circuit-building. */
#define ROUTER_PURPOSE_CONTROLLER 1
  uint8_t purpose; /** Should Tor use this desc for circuit-building? */

  /* The below items are used only by authdirservers for
   * reachability testing. */
  /** When was the last time we could reach this OR? */
  time_t last_reachable;
  /** When did we start testing reachability for this OR? */
  time_t testing_since;
  /** How many times has a descriptor been posted and we believed
   * this router to be unreachable? We only actually warn on the third. */
  int num_unreachable_notifications;

  /** What position is this descriptor within routerlist->routers? -1 for
   * none. */
  int routerlist_index;
} routerinfo_t;

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
  unsigned int is_exit:1; /**< True iff this router is a good exit. */
  unsigned int is_stable:1; /**< True iff this router stays up a long time. */
  unsigned int is_fast:1; /**< True iff this router has good bandwidth. */
  unsigned int is_running:1; /**< True iff this router is up. */
  unsigned int is_named:1; /**< True iff "nickname" belongs to this router. */
  unsigned int is_valid:1; /**< True iff this router is validated. */
  unsigned int is_v2_dir:1; /**< True iff this router can serve directory
                             * information with v2 of the directory
                             * protocol. (All directory caches cache v1
                             * directories.)  */
  unsigned int is_possible_guard:1; /**< True iff this router would be a good
                                     * choice as an entry guard. */

  /** True if we, as a directory mirror, want to download the corresponding
   * routerinfo from the authority who gave us this routerstatus.  (That is,
   * if we don't have the routerinfo, and if we haven't already tried to get it
   * from this authority.)
   */
  unsigned int need_to_mirror:1;
} routerstatus_t;

/** Our "local" or combined view of the info from all networkstatus objects
 * about a single router. */
typedef struct local_routerstatus_t {
  /** What do we believe to be the case about this router?  In this field,
   * descriptor_digest represents the descriptor we would most like to use for
   * this router. */
  routerstatus_t status;
  time_t next_attempt_at; /**< When should we try this descriptor again? */
  uint8_t n_download_failures; /**< Number of failures trying to download the
                                * most recent descriptor. */
  unsigned int name_lookup_warned:1; /**< Have we warned the user for referring
                                      * to this (unnamed) router by nickname?
                                      */
} local_routerstatus_t;

/** How many times will we try to download a router's descriptor before giving
 * up? */
#define MAX_ROUTERDESC_DOWNLOAD_FAILURES 8

/** Contents of a (v2 or later) network status object. */
typedef struct networkstatus_t {
  /** When did we receive the network-status document? */
  time_t received_on;

  /** What was the digest of the document? */
  char networkstatus_digest[DIGEST_LEN];

  unsigned int is_recent; /**< Is this recent enough to influence running
                           * status? */

  /* These fields come from the actual network-status document.*/
  time_t published_on; /**< Declared publication date. */

  char *source_address; /**< Canonical directory server hostname. */
  uint32_t source_addr; /**< Canonical directory server IP. */
  uint16_t source_dirport; /**< Canonical directory server dirport. */

  char identity_digest[DIGEST_LEN]; /**< Digest of signing key. */
  char *contact; /**< How to contact directory admin? (may be NULL). */
  crypto_pk_env_t *signing_key; /**< Key used to sign this directory. */
  char *client_versions; /**< comma-separated list of recommended client
                          * versions. */
  char *server_versions; /**< comma-separated list of recommended server
                          * versions. */

  unsigned int binds_names:1; /**< True iff this directory server binds
                               * names. */
  unsigned int recommends_versions:1; /**< True iff this directory server
                                       * recommends client and server software
                                       * versions. */

  smartlist_t *entries; /**< List of routerstatus_t*.   This list is kept
                         * sorted by identity_digest. */
} networkstatus_t;

/** Contents of a directory of onion routers. */
typedef struct {
  /** Map from server identity digest to a member of routers. */
  digestmap_t *identity_map;
  /** Map from server descriptor digest to a signed_descriptor_t from
   * routers or old_routers. */
  digestmap_t *desc_digest_map;
  /** List of routerinfo_t for all currently live routers we know. */
  smartlist_t *routers;
  /** List of signed_descriptor_t for older router descriptors we're
   * caching. */
  smartlist_t *old_routers;
  /** DOCDOC */
  tor_mmap_t *mmap_descriptors;
} routerlist_t;

/** Information on router used when extending a circuit.  (We don't need a
 * full routerinfo_t to extend: we only need addr:port:keyid to build an OR
 * connection, and onion_key to create the onionskin.) */
typedef struct extend_info_t {
  char nickname[MAX_HEX_NICKNAME_LEN+1]; /**< This router's nickname for
                                          * display. */
  char identity_digest[DIGEST_LEN]; /**< Hash of this router's identity key. */
  uint32_t addr; /**< IP address in host order. */
  uint16_t port; /**< OR port. */
  crypto_pk_env_t *onion_key; /**< Current onionskin key. */
} extend_info_t;

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

  int package_window; /**< How many bytes are we allowed to originate ending
                       * at this step? */
  int deliver_window; /**< How many bytes are we willing to deliver originating
                       * at this step? */
} crypt_path_t;

#define CPATH_KEY_MATERIAL_LEN (20*2+16*2)

#define DH_KEY_LEN DH_BYTES
#define ONIONSKIN_CHALLENGE_LEN (PKCS1_OAEP_PADDING_OVERHEAD+\
                                 CIPHER_KEY_LEN+\
                                 DH_KEY_LEN)
#define ONIONSKIN_REPLY_LEN (DH_KEY_LEN+DIGEST_LEN)
#define REND_COOKIE_LEN DIGEST_LEN

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
  /** The crypt_path_t to append after rendezvous: used for rendezvous. */
  crypt_path_t *pending_final_cpath;
  /** How many times has building a circuit for this task failed? */
  int failure_count;
  /** At what time should we give up on this task? */
  time_t expiry_time;
} cpath_build_state_t;

#define ORIGIN_CIRCUIT_MAGIC 0x35315243u
#define OR_CIRCUIT_MAGIC 0x98ABC04Fu

typedef uint16_t circid_t;

/**
 * A circuit is a path over the onion routing
 * network. Applications can connect to one end of the circuit, and can
 * create exit connections at the other end of the circuit. AP and exit
 * connections have only one circuit associated with them (and thus these
 * connection types are closed when the circuit is closed), whereas
 * OR connections multiplex many circuits at once, and stay standing even
 * when there are no circuits running over them.
 *
 * A circuit_t structure cann fill one of two roles.  First, a or_circuit_t
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

  /** The OR connection that is next in this circuit. */
  or_connection_t *n_conn;
  /** The identity hash of n_conn. */
  char n_conn_id_digest[DIGEST_LEN];
  /** The circuit_id used in the next (forward) hop of this circuit. */
  uint16_t n_circ_id;
  /** The port for the OR that is next in this circuit. */
  uint16_t n_port;
  /** The IPv4 address of the OR that is next in this circuit. */
  uint32_t n_addr;
  /** How many relay data cells can we package (read from edge streams)
   * on this circuit before we receive a circuit-level sendme cell asking
   * for more? */
  int package_window;
  /** How many relay data cells will we deliver (write to edge streams)
   * on this circuit? When deliver_window gets low, we send some
   * circuit-level sendme cells to indicate that we're willing to accept
   * more. */
  int deliver_window;

  /** For storage while passing to cpuworker (state
    * CIRCUIT_STATE_ONIONSKIN_PENDING), or while n_conn is pending
    * (state CIRCUIT_STATE_OR_WAIT). When defined, it is always
    * length ONIONSKIN_CHALLENGE_LEN. */
  char *onionskin;

  time_t timestamp_created; /**< When was this circuit created? */
  time_t timestamp_dirty; /**< When the circuit was first used, or 0 if the
                           * circuit is clean. */

  uint8_t state; /**< Current status of this circuit. */
  uint8_t purpose; /**< Why are we creating this circuit? */

  uint16_t marked_for_close; /**< Should we close this circuit at the end of
                              * the main loop? (If true, holds the line number
                              * where this circuit was marked.) */
  const char *marked_for_close_file; /**< For debugging: in which file was this
                                      * circuit marked for close? */

  struct circuit_t *next; /**< Next circuit in linked list. */
} circuit_t;

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
   *
   * The cpath field is defined only when we are the circuit's origin.
   */
  crypt_path_t *cpath;

  /** The rend_pk_digest field holds a hash of location-hidden service's
   * PK if purpose is S_ESTABLISH_INTRO or S_RENDEZVOUSING.
   */
  char rend_pk_digest[DIGEST_LEN];

  /** Holds rendezvous cookie if purpose is C_ESTABLISH_REND. Filled with
   * zeroes otherwise.
   */
  char rend_cookie[REND_COOKIE_LEN];

  /**
   * The rend_query field holds the y portion of y.onion (nul-terminated)
   * if purpose is C_INTRODUCING or C_ESTABLISH_REND, or is a C_GENERAL
   * for a hidden service, or is S_*.
   */
  char rend_query[REND_SERVICE_ID_LEN+1];

  /** The next stream_id that will be tried when we're attempting to
   * construct a new AP stream originating at this circuit. */
  uint16_t next_stream_id;

  /** Quasi-global identifier for this circuit; used for control.c */
  /* XXXX NM This can get re-used after 2**32 circuits. */
  uint32_t global_identifier;

} origin_circuit_t;

/** An or_circuit_t holds information needed to implement a circuit at an
 * OR. */
typedef struct or_circuit_t {
  circuit_t _base;

  /** The circuit_id used in the previous (backward) hop of this circuit. */
  circid_t p_circ_id;
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
   */
  char rend_token[REND_TOKEN_LEN];

  char handshake_digest[DIGEST_LEN]; /**< Stores KH for the handshake. */
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
  //return (or_circuit_t*) (((char*)x) - STRUCT_OFFSET(or_circuit_t, _base));
  return DOWNCAST(or_circuit_t, x);
}
static INLINE origin_circuit_t *TO_ORIGIN_CIRCUIT(circuit_t *x)
{
  tor_assert(x->magic == ORIGIN_CIRCUIT_MAGIC);
  //return (origin_circuit_t*)
  //  (((char*)x) - STRUCT_OFFSET(origin_circuit_t, _base));
  return DOWNCAST(origin_circuit_t, x);
}

#define ALLOW_INVALID_ENTRY        1
#define ALLOW_INVALID_EXIT         2
#define ALLOW_INVALID_MIDDLE       4
#define ALLOW_INVALID_RENDEZVOUS   8
#define ALLOW_INVALID_INTRODUCTION 16

/** An entry specifying a set of addresses and ports that should be remapped
 * to another address and port before exiting this exit node. */
typedef struct exit_redirect_t {
  uint32_t addr;
  uint32_t mask;
  uint16_t port_min;
  uint16_t port_max;

  uint32_t addr_dest;
  uint16_t port_dest;
  unsigned is_redirect:1;
} exit_redirect_t;

/** A linked list of lines in a config file. */
typedef struct config_line_t {
  char *key;
  char *value;
  struct config_line_t *next;
} config_line_t;

/** Configuration options for a Tor process. */
typedef struct {
  uint32_t _magic;

  /** What should the tor process actually do? */
  enum {
    CMD_RUN_TOR=0, CMD_LIST_FINGERPRINT, CMD_HASH_PASSWORD,
    CMD_VERIFY_CONFIG, CMD_RUN_UNITTESTS
  } command;
  const char *command_arg; /**< Argument for command-line option. */

  config_line_t *OldLogOptions; /**< List of configuration lines
                                 * for logfiles, old style. */

  config_line_t *Logs; /**< New-style list of configuration lines
                        * for logs */

  char *DebugLogFile; /**< Where to send verbose log messages. */
  char *DataDirectory; /**< OR only: where to store long-term data. */
  char *Nickname; /**< OR only: nickname of this onion router. */
  char *Address; /**< OR only: configured address for this onion router. */
  char *PidFile; /**< Where to store PID of Tor process. */

  char *ExitNodes; /**< Comma-separated list of nicknames of ORs to consider
                    * as exits. */
  char *EntryNodes; /**< Comma-separated list of nicknames of ORs to consider
                     * as entry points. */
  int StrictExitNodes; /**< Boolean: When none of our ExitNodes are up, do we
                        * stop building circuits? */
  int StrictEntryNodes; /**< Boolean: When none of our EntryNodes are up, do we
                         * stop building circuits? */
  char *ExcludeNodes; /**< Comma-separated list of nicknames of ORs not to
                       * use in circuits. */

  char *RendNodes; /**< Comma-separated list of nicknames used as introduction
                    * points. */
  char *RendExcludeNodes; /**< Comma-separated list of nicknames not to use
                           * as introduction points. */

  smartlist_t *AllowInvalidNodes; /**< List of "entry", "middle", "exit" */
  int _AllowInvalid; /**< Bitmask; derived from AllowInvalidNodes; */
  config_line_t *ExitPolicy; /**< Lists of exit policy components. */
  int ExitPolicyRejectPrivate; /**< Should we not exit to local addresses? */
  config_line_t *SocksPolicy; /**< Lists of socks policy components */
  config_line_t *DirPolicy; /**< Lists of dir policy components */
  /** Addresses to bind for listening for SOCKS connections. */
  config_line_t *SocksListenAddress;
  /** Addresses to bind for listening for transparent connections. */
  config_line_t *TransListenAddress;
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
  double PathlenCoinWeight; /**< Parameter used to configure average path
                             * length (alpha in geometric distribution). */
  int ORPort; /**< Port to listen on for OR connections. */
  int SocksPort; /**< Port to listen on for SOCKS connections. */
  int TransPort; /**< Port to listen on for transparent connections. */
  int ControlPort; /**< Port to listen on for control connections. */
  int DirPort; /**< Port to listen on for directory connections. */
  int AssumeReachable; /**< Whether to publish our descriptor regardless. */
  int AuthoritativeDir; /**< Boolean: is this an authoritative directory? */
  int V1AuthoritativeDir; /**< Boolean: is this an authoritative directory?
                           * for version 1 directories? */
  int NamingAuthoritativeDir; /**< Boolean: is this an authoritative directory
                               * that's willing to bind names? */
  int VersioningAuthoritativeDir; /**< Boolean: is this an authoritative
                                   * directory that's willing to recommend
                                   * versions? */
  int AvoidDiskWrites; /**< Boolean: should we never cache things to disk?
                        * Not used yet. */
  int ClientOnly; /**< Boolean: should we never evolve into a server role? */
  int NoPublish; /**< Boolean: should we never publish a descriptor? */
  int PublishServerDescriptor; /**< Do we publish our descriptor as normal? */
  int PublishHidServDescriptors; /**< and our hidden service descriptors? */
  int FetchServerDescriptors; /**< Do we fetch server descriptors as normal? */
  int FetchHidServDescriptors; /** and hidden service descriptors? */
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

  /** Application ports that require all nodes in circ to have sufficient
   * uptime. */
  smartlist_t *LongLivedPorts;
  /** Should we try to reuse the same exit node for a given host */
  smartlist_t *TrackHostExits;
  int TrackHostExitsExpire; /**< Number of seconds until we expire an
                             * addressmap */
  config_line_t *AddressMap; /**< List of address map directives. */
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
  char *TestVia; /**< When reachability testing, use these as middle hop. */
  config_line_t *RendConfigLines; /**< List of configuration lines
                                          * for rendezvous services. */
  char *ContactInfo; /**< Contact info to be published in the directory */

  char *HttpProxy; /**< hostname[:port] to use as http proxy, if any */
  uint32_t HttpProxyAddr; /**< Parsed IPv4 addr for http proxy, if any */
  uint16_t HttpProxyPort; /**< Parsed port for http proxy, if any */
  char *HttpProxyAuthenticator; /**< username:password string, if any */

  char *HttpsProxy; /**< hostname[:port] to use as https proxy, if any */
  uint32_t HttpsProxyAddr; /**< Parsed IPv4 addr for https proxy, if any */
  uint16_t HttpsProxyPort; /**< Parsed port for https proxy, if any */
  char *HttpsProxyAuthenticator; /**< username:password string, if any */

  config_line_t *DirServers; /**< List of configuration lines
                                     * for directory servers. */
  char *MyFamily; /**< Declared family for this OR. */
  config_line_t *NodeFamilies; /**< List of config lines for
                                       * node families */
  config_line_t *RedirectExit; /**< List of config lines for simple
                                       * addr/port redirection */
  smartlist_t *RedirectExitList; /**< List of exit_redirect_t */
  config_line_t *AuthDirReject; /**< Address policy for descriptors to
                                 * reject. */
  config_line_t *AuthDirInvalid; /**< Address policy for descriptors to
                                  * never mark as valid. */
  int AuthDirRejectUnlisted; /**< Boolean: do we reject all routers that
                              * aren't named in our fingerprint file? */
  char *AccountingStart; /**< How long is the accounting interval, and when
                          * does it start? */
  uint64_t AccountingMax; /**< How many bytes do we allow per accounting
                           * interval before hibernation?  0 for "never
                           * hibernate." */
  int _AccountingMaxKB; /**< How many KB do we allow per accounting
                         * interval before hibernation?  0 for "never
                         * hibernate."  (Based on a deprecated option)*/

  char *HashedControlPassword; /**< Base64-encoded hash of a password for
                                * the control system. */
  int CookieAuthentication; /**< Boolean: do we enable cookie-based auth for
                             * the control system? */
  int LeaveStreamsUnattached; /**< Boolean: Does Tor attach new streams to
                          * circuits itself (0), or does it expect a controller
                          * to cope? (1) */
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

  addr_policy_t *reachable_addr_policy; /**< Parsed from ReachableAddresses */

  char *VirtualAddrNetwork; /**< Address and mask to hand out for virtual
                             * MAPADDRESS requests. */
  int ServerDNSSearchDomains; /**< Boolean: If set, we don't force exit
                      * addresses to be FQDNs, but rather search for them in
                      * the local domains. */
  int ServerDNSDetectHijacking; /**< Boolean: If true, check for DNS failure
                                 * hijacking. */
  char *ServerDNSResolvConfFile; /**< If provided, we configure our internal
                     * resolver from the file here rather than from
                     * /etc/resolv.conf (Unix) or the registry (Windows). */
  int EnforceDistinctSubnets; /** If true, don't allow multiple routers in the
                               * same network zone in the same circuit. */
} or_options_t;

/** Persistent state for an onion router, as saved to disk. */
typedef struct {
  uint32_t _magic;
  int dirty;

  /* XXXX These options aren't actually attached to anything yet. */
  time_t LastWritten;
  time_t AccountingIntervalStart;
  uint64_t AccountingBytesReadInInterval;
  uint64_t AccountingBytesWrittenInInterval;
  int AccountingSecondsActive;
  uint64_t AccountingExpectedUsage;

  config_line_t *EntryGuards;

  time_t      BWHistoryReadEnds;
  int         BWHistoryReadInterval;
  smartlist_t *BWHistoryReadValues;
  time_t      BWHistoryWriteEnds;
  int         BWHistoryWriteInterval;
  smartlist_t *BWHistoryWriteValues;

  char *TorVersion;

  config_line_t *ExtraLines;
} or_state_t;

#define MAX_SOCKS_REPLY_LEN 1024
#define MAX_SOCKS_ADDR_LEN 256
#define SOCKS_COMMAND_CONNECT 0x01
#define SOCKS_COMMAND_RESOLVE 0xF0
#define SOCKS_COMMAND_RESOLVE_PTR 0xF1
/** State of a SOCKS request from a user to an OP */
struct socks_request_t {
  char socks_version; /**< Which version of SOCKS did the client use? */
  int command; /**< What has the user requested? One of CONNECT or RESOLVE. */
  size_t replylen; /**< Length of <b>reply</b>. */
  char reply[MAX_SOCKS_REPLY_LEN]; /**< Write an entry into this string if
                                    * we want to specify our own socks reply,
                                    * rather than using the default socks4 or
                                    * socks5 socks reply. We use this for the
                                    * two-stage socks5 handshake.
                                    */
  int has_finished; /**< Has the SOCKS handshake finished? */
  char address[MAX_SOCKS_ADDR_LEN]; /**< What address did the client ask to
                                       connect to? */
  uint16_t port; /**< What port did the client ask to connect to? */
};

/* all the function prototypes go here */

/********************************* buffers.c ***************************/

buf_t *buf_new(void);
buf_t *buf_new_with_capacity(size_t size);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);
void buf_shrink(buf_t *buf);

size_t buf_datalen(const buf_t *buf);
size_t buf_capacity(const buf_t *buf);
const char *_buf_peek_raw_buffer(const buf_t *buf);

int read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof);
int read_to_buf_tls(tor_tls_t *tls, size_t at_most, buf_t *buf);

int flush_buf(int s, buf_t *buf, size_t sz, size_t *buf_flushlen);
int flush_buf_tls(tor_tls_t *tls, buf_t *buf, size_t sz, size_t *buf_flushlen);

int write_to_buf(const char *string, size_t string_len, buf_t *buf);
int write_to_buf_zlib(buf_t *buf, tor_zlib_state_t *state,
                      const char *data, size_t data_len, int done);
int fetch_from_buf(char *string, size_t string_len, buf_t *buf);
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, size_t max_headerlen,
                        char **body_out, size_t *body_used, size_t max_bodylen,
                        int force_complete);
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req,
                         int log_sockstype, int safe_socks);
int fetch_from_buf_control0(buf_t *buf, uint32_t *len_out, uint16_t *type_out,
                            char **body_out, int check_for_v1);
int fetch_from_buf_line(buf_t *buf, char *data_out, size_t *data_len);

void assert_buf_ok(buf_t *buf);

/********************************* circuitbuild.c **********************/

char *circuit_list_path(origin_circuit_t *circ, int verbose);
void circuit_log_path(int severity, unsigned int domain,
                      origin_circuit_t *circ);
void circuit_rep_hist_note_result(origin_circuit_t *circ);
origin_circuit_t *origin_circuit_init(uint8_t purpose, int need_uptime,
                                      int need_capacity, int internal);
origin_circuit_t *circuit_establish_circuit(uint8_t purpose,
                                     extend_info_t *exit,
                                     int need_uptime, int need_capacity,
                                     int internal);
int circuit_handle_first_hop(origin_circuit_t *circ);
void circuit_n_conn_done(or_connection_t *or_conn, int status);
int inform_testing_reachability(void);
int circuit_send_next_onion_skin(origin_circuit_t *circ);
void circuit_note_clock_jumped(int seconds_elapsed);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_init_cpath_crypto(crypt_path_t *cpath, char *key_data,
                              int reverse);
int circuit_finish_handshake(origin_circuit_t *circ, uint8_t cell_type,
                             char *reply);
int circuit_truncated(origin_circuit_t *circ, crypt_path_t *layer);
int onionskin_answer(or_circuit_t *circ, uint8_t cell_type, char *payload,
                     char *keys);
int circuit_all_predicted_ports_handled(time_t now, int *need_uptime,
                                        int *need_capacity);

int circuit_append_new_exit(origin_circuit_t *circ, extend_info_t *info);
int circuit_extend_to_new_exit(origin_circuit_t *circ, extend_info_t *info);
void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop);
extend_info_t *extend_info_from_router(routerinfo_t *r);
extend_info_t *extend_info_dup(extend_info_t *info);
void extend_info_free(extend_info_t *info);
routerinfo_t *build_state_get_exit_router(cpath_build_state_t *state);
const char *build_state_get_exit_nickname(cpath_build_state_t *state);

void entry_guards_set_status_from_directory(void);
int entry_guard_set_status(const char *digest, int succeeded);
void entry_nodes_should_be_added(void);
void entry_guards_prepend_from_config(void);
void entry_guards_update_state(or_state_t *state);
int entry_guards_parse_state(or_state_t *state, int set, char **msg);
int entry_guards_getinfo(const char *question, char **answer);
void entry_guards_free_all(void);

/********************************* circuitlist.c ***********************/

circuit_t * _circuit_get_global_list(void);
const char *circuit_state_to_string(int state);
void circuit_dump_by_conn(connection_t *conn, int severity);
void circuit_set_p_circid_orconn(or_circuit_t *circ, uint16_t id,
                                 or_connection_t *conn);
void circuit_set_n_circid_orconn(circuit_t *circ, uint16_t id,
                                 or_connection_t *conn);
void circuit_set_state(circuit_t *circ, int state);
void circuit_close_all_marked(void);
origin_circuit_t *origin_circuit_new(void);
or_circuit_t *or_circuit_new(uint16_t p_circ_id, or_connection_t *p_conn);
circuit_t *circuit_get_by_circid_orconn(uint16_t circ_id,
                                        or_connection_t *conn);
int circuit_id_used_on_conn(uint16_t circ_id, or_connection_t *conn);
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
                                       extend_info_t *info,
                                       int need_uptime,
                                       int need_capacity, int internal);
void circuit_mark_all_unused_circs(void);
void circuit_expire_all_dirty_circs(void);
void _circuit_mark_for_close(circuit_t *circ, int reason,
                             int line, const char *file);

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
void circuit_build_needed_circs(time_t now);
void circuit_detach_stream(circuit_t *circ, edge_connection_t *conn);
void circuit_about_to_close_connection(connection_t *conn);

void reset_bandwidth_test(void);
int circuit_enough_testing_circs(void);

void circuit_has_opened(origin_circuit_t *circ);
void circuit_build_failed(origin_circuit_t *circ);
origin_circuit_t *circuit_launch_by_nickname(uint8_t purpose,
                                      const char *exit_nickname,
                                      int need_uptime, int need_capacity,
                                      int is_internal);
origin_circuit_t *circuit_launch_by_extend_info(uint8_t purpose,
                                         extend_info_t *info,
                                         int need_uptime, int need_capacity,
                                         int is_internal);
origin_circuit_t *circuit_launch_by_router(uint8_t purpose, routerinfo_t *exit,
                                    int need_uptime, int need_capacity,
                                    int is_internal);
void circuit_reset_failure_count(int timeout);
int connection_ap_handshake_attach_chosen_circuit(edge_connection_t *conn,
                                                  origin_circuit_t *circ);
int connection_ap_handshake_attach_circuit(edge_connection_t *conn);

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, or_connection_t *conn);

extern uint64_t stats_n_padding_cells_processed;
extern uint64_t stats_n_create_cells_processed;
extern uint64_t stats_n_created_cells_processed;
extern uint64_t stats_n_relay_cells_processed;
extern uint64_t stats_n_destroy_cells_processed;

/********************************* config.c ***************************/

or_options_t *get_options(void);
int set_options(or_options_t *new_val, char **msg);
void config_free_all(void);
const char *safe_str(const char *address);
const char *escaped_safe_str(const char *address);

int config_get_lines(char *string, config_line_t **result);
void config_free_lines(config_line_t *front);
int options_trial_assign(config_line_t *list, int use_defaults,
                         int clear_first, char **msg);
int resolve_my_address(int warn_severity, or_options_t *options,
                       uint32_t *addr, char **hostname_out);
void options_init(or_options_t *options);
int options_init_from_torrc(int argc, char **argv);
int options_init_logs(or_options_t *options, int validate_only);
int option_is_recognized(const char *key);
const char *option_get_canonical_name(const char *key);
config_line_t *option_get_assignment(or_options_t *options,
                                     const char *key);
char *options_dump(or_options_t *options, int minimal);
int options_save_current(void);
const char *get_torrc_fname(void);

or_state_t *get_or_state(void);
int or_state_load(void);
int or_state_save(void);

int config_getinfo_helper(const char *question, char **answer);

/********************************* connection.c ***************************/

const char *conn_type_to_string(int type);
const char *conn_state_to_string(int type, int state);

connection_t *connection_new(int type);
void connection_unregister(connection_t *conn);
void connection_free(connection_t *conn);
void connection_free_all(void);
void connection_about_to_close_connection(connection_t *conn);
void connection_close_immediate(connection_t *conn);
void _connection_mark_for_close(connection_t *conn,int line, const char *file);

#define connection_mark_for_close(c) \
  _connection_mark_for_close((c), __LINE__, _SHORT_FILE_)

void connection_expire_held_open(void);

int connection_connect(connection_t *conn, char *address, uint32_t addr,
                       uint16_t port);
int retry_all_listeners(int force, smartlist_t *replaced_conns,
                        smartlist_t *new_conns);

int connection_bucket_write_limit(connection_t *conn);
int global_write_bucket_empty(void);
void connection_bucket_init(void);
void connection_bucket_refill(struct timeval *now);

int connection_handle_read(connection_t *conn);

int connection_fetch_from_buf(char *string, size_t len, connection_t *conn);

int connection_wants_to_flush(connection_t *conn);
int connection_outbuf_too_full(connection_t *conn);
int connection_handle_write(connection_t *conn);
void _connection_controller_force_write(control_connection_t *conn);
void connection_write_to_buf(const char *string, size_t len,
                             connection_t *conn);
void connection_write_to_buf_zlib(dir_connection_t *conn,
                                  const char *data, size_t data_len,
                                  int done);

or_connection_t *connection_or_exact_get_by_addr_port(uint32_t addr,
                                                   uint16_t port);
edge_connection_t *connection_get_by_global_id(uint32_t id);

connection_t *connection_get_by_type(int type);
connection_t *connection_get_by_type_purpose(int type, int purpose);
connection_t *connection_get_by_type_addr_port_purpose(int type, uint32_t addr,
                                                   uint16_t port, int purpose);
connection_t *connection_get_by_type_state(int type, int state);
connection_t *connection_get_by_type_state_lastwritten(int type, int state);
connection_t *connection_get_by_type_state_rendquery(int type, int state,
                                                     const char *rendquery);

#define connection_speaks_cells(conn) ((conn)->type == CONN_TYPE_OR)
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);
int connection_state_is_connecting(connection_t *conn);

char *alloc_http_authenticator(const char *authenticator);

void assert_connection_ok(connection_t *conn, time_t now);
int connection_or_nonopen_was_started_here(or_connection_t *conn);

/********************************* connection_edge.c *************************/

#define connection_mark_unattached_ap(conn, endreason) \
  _connection_mark_unattached_ap((conn), (endreason), __LINE__, _SHORT_FILE_)

void _connection_mark_unattached_ap(edge_connection_t *conn, int endreason,
                                    int line, const char *file);
int connection_edge_reached_eof(edge_connection_t *conn);
int connection_edge_process_inbuf(edge_connection_t *conn,
                                  int package_partial);
int connection_edge_destroy(uint16_t circ_id, edge_connection_t *conn);
int connection_edge_end(edge_connection_t *conn, char reason,
                        crypt_path_t *cpath_layer);
int connection_edge_end_errno(edge_connection_t *conn,
                              crypt_path_t *cpath_layer);
int connection_edge_finished_flushing(edge_connection_t *conn);
int connection_edge_finished_connecting(edge_connection_t *conn);

int connection_ap_handshake_send_begin(edge_connection_t *ap_conn,
                                       origin_circuit_t *circ);
int connection_ap_handshake_send_resolve(edge_connection_t *ap_conn,
                                         origin_circuit_t *circ);

int connection_ap_make_bridge(char *address, uint16_t port);
void connection_ap_handshake_socks_reply(edge_connection_t *conn, char *reply,
                                         size_t replylen,
                                         socks5_reply_status_t status);
void connection_ap_handshake_socks_resolved(edge_connection_t *conn,
                                            int answer_type,
                                            size_t answer_len,
                                            const char *answer,
                                            int ttl);

int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);
int connection_exit_begin_resolve(cell_t *cell, or_circuit_t *circ);
void connection_exit_connect(edge_connection_t *conn);
int connection_edge_is_rendezvous_stream(edge_connection_t *conn);
int connection_ap_can_use_exit(edge_connection_t *conn, routerinfo_t *exit);
void connection_ap_expire_beginning(void);
void connection_ap_attach_pending(void);
int connection_ap_detach_retriable(edge_connection_t *conn,
                                   origin_circuit_t *circ);

void addressmap_init(void);
void addressmap_clean(time_t now);
void addressmap_clear_configured(void);
void addressmap_clear_transient(void);
void addressmap_free_all(void);
void addressmap_rewrite(char *address, size_t maxlen);
int addressmap_have_mapping(const char *address);
void addressmap_register(const char *address, char *new_address,
                         time_t expires);
int parse_virtual_addr_network(const char *val, int validate_only,
                               char **msg);
int client_dns_incr_failures(const char *address);
void client_dns_clear_failures(const char *address);
void client_dns_set_addressmap(const char *address, uint32_t val,
                               const char *exitname, int ttl);
int address_is_in_virtual_range(const char *addr);
const char *addressmap_register_virtual_address(int type, char *new_address);
void addressmap_get_mappings(smartlist_t *sl, time_t min_expires,
                             time_t max_expires);
int connection_ap_handshake_rewrite_and_attach(edge_connection_t *conn,
                                               origin_circuit_t *circ);

void set_exit_redirects(smartlist_t *lst);
typedef enum hostname_type_t {
  NORMAL_HOSTNAME, ONION_HOSTNAME, EXIT_HOSTNAME, BAD_HOSTNAME
} hostname_type_t;
hostname_type_t parse_extended_hostname(char *address);

/********************************* connection_or.c ***************************/

void connection_or_remove_from_identity_map(or_connection_t *conn);
void connection_or_clear_identity_map(void);
or_connection_t *connection_or_get_by_identity_digest(const char *digest);

int connection_or_reached_eof(or_connection_t *conn);
int connection_or_process_inbuf(or_connection_t *conn);
int connection_or_finished_flushing(or_connection_t *conn);
int connection_or_finished_connecting(or_connection_t *conn);

or_connection_t *connection_or_connect(uint32_t addr, uint16_t port,
                                    const char *id_digest);

int connection_tls_start_handshake(or_connection_t *conn, int receiving);
int connection_tls_continue_handshake(or_connection_t *conn);

void connection_or_write_cell_to_buf(const cell_t *cell,
                                     or_connection_t *conn);
int connection_or_send_destroy(uint16_t circ_id, or_connection_t *conn,
                               int reason);

/********************************* control.c ***************************/

typedef enum circuit_status_event_t {
  CIRC_EVENT_LAUNCHED = 0,
  CIRC_EVENT_BUILT    = 1,
  CIRC_EVENT_EXTENDED = 2,
  CIRC_EVENT_FAILED   = 3,
  CIRC_EVENT_CLOSED   = 4,
} circuit_status_event_t;

typedef enum stream_status_event_t {
  STREAM_EVENT_SENT_CONNECT = 0,
  STREAM_EVENT_SENT_RESOLVE = 1,
  STREAM_EVENT_SUCCEEDED    = 2,
  STREAM_EVENT_FAILED       = 3,
  STREAM_EVENT_CLOSED       = 4,
  STREAM_EVENT_NEW          = 5,
  STREAM_EVENT_NEW_RESOLVE  = 6,
  STREAM_EVENT_FAILED_RETRIABLE = 7
} stream_status_event_t;

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
  do {                                                                  \
    int _log_conn_is_control = (conn && conn->type == CONN_TYPE_CONTROL); \
    if (_log_conn_is_control)                                           \
      disable_control_logging();                                        \
    do {stmt;} while (0);                                               \
    if (_log_conn_is_control)                                           \
      enable_control_logging();                                         \
  } while (0)

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

int control_event_circuit_status(origin_circuit_t *circ,
                                 circuit_status_event_t e);
int control_event_stream_status(edge_connection_t *conn,
                                stream_status_event_t e);
int control_event_or_conn_status(or_connection_t *conn,
                                 or_conn_status_event_t e);
int control_event_bandwidth_used(uint32_t n_read, uint32_t n_written);
void control_event_logmsg(int severity, unsigned int domain, const char *msg);
int control_event_descriptors_changed(smartlist_t *routers);
int control_event_address_mapped(const char *from, const char *to,
                                 time_t expires);
int control_event_or_authdir_new_descriptor(const char *action,
                                            const char *descriptor,
                                            const char *msg);

int init_cookie_authentication(int enabled);
int decode_hashed_password(char *buf, const char *hashed);
void disable_control_logging(void);
void enable_control_logging(void);

/********************************* cpuworker.c *****************************/

void cpu_init(void);
void cpuworkers_rotate(void);
int connection_cpu_finished_flushing(connection_t *conn);
int connection_cpu_reached_eof(connection_t *conn);
int connection_cpu_process_inbuf(connection_t *conn);
int assign_to_cpuworker(connection_t *cpuworker, uint8_t question_type,
                        void *task);

/********************************* directory.c ***************************/

void directory_post_to_dirservers(uint8_t purpose, const char *payload,
                                  size_t payload_len);
void directory_get_from_dirserver(uint8_t purpose, const char *resource,
                                  int retry_if_no_servers);
void directory_initiate_command_router(routerinfo_t *router, uint8_t purpose,
                                       int private_connection,
                                       const char *resource,
                                       const char *payload,
                                       size_t payload_len);
void directory_initiate_command_routerstatus(routerstatus_t *status,
                                             uint8_t purpose,
                                             int private_connection,
                                             const char *resource,
                                             const char *payload,
                                             size_t payload_len);

int parse_http_response(const char *headers, int *code, time_t *date,
                        int *compression, char **response);

int connection_dir_reached_eof(dir_connection_t *conn);
int connection_dir_process_inbuf(dir_connection_t *conn);
int connection_dir_finished_flushing(dir_connection_t *conn);
int connection_dir_finished_connecting(dir_connection_t *conn);
void connection_dir_request_failed(dir_connection_t *conn);
int dir_split_resource_into_fingerprints(const char *resource,
                                    smartlist_t *fp_out, int *compresseed_out,
                                    int decode_hex, int sort_uniq);
char *directory_dump_request_log(void);

/********************************* dirserv.c ***************************/

int connection_dirserv_flushed_some(dir_connection_t *conn);
int dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk);
int dirserv_load_fingerprint_file(void);
void dirserv_free_fingerprint_list(void);
const char *dirserv_get_nickname_by_digest(const char *digest);
int dirserv_add_descriptor(const char *desc, const char **msg);
char *dirserver_getinfo_unregistered(const char *question);
void dirserv_free_descriptors(void);
int dirserv_thinks_router_is_blatantly_unreachable(routerinfo_t *router,
                                                   time_t now);
int list_server_status(smartlist_t *routers, char **router_status_out);
int dirserv_dump_directory_to_string(char **dir_out,
                                     crypto_pk_env_t *private_key,
                                     int complete);
void directory_set_dirty(void);
cached_dir_t *dirserv_get_directory(void);
size_t dirserv_get_runningrouters(const char **rr, int compress);
void dirserv_set_cached_directory(const char *directory, time_t when,
                                  int is_running_routers);
void dirserv_set_cached_networkstatus_v2(const char *directory,
                                         const char *identity,
                                         time_t published);
void dirserv_get_networkstatus_v2(smartlist_t *result, const char *key);
void dirserv_get_networkstatus_v2_fingerprints(smartlist_t *result,
                                               const char *key);
int dirserv_get_routerdesc_fingerprints(smartlist_t *fps_out, const char *key,
                                        const char **msg);
int dirserv_get_routerdescs(smartlist_t *descs_out, const char *key,
                            const char **msg);
void dirserv_orconn_tls_done(const char *address,
                             uint16_t or_port,
                             const char *digest_rcvd,
                             const char *nickname,
                             int as_advertised);
void dirserv_test_reachability(int try_all);
int authdir_wants_to_reject_router(routerinfo_t *ri, const char **msg,
                                   int complain);
int dirserv_would_reject_router(routerstatus_t *rs);
void dirserv_free_all(void);
void cached_dir_decref(cached_dir_t *d);

/********************************* dns.c ***************************/

int dns_init(void);
void dns_free_all(void);
uint32_t dns_clip_ttl(uint32_t ttl);
int connection_dns_finished_flushing(connection_t *conn);
int connection_dns_reached_eof(connection_t *conn);
int connection_dns_process_inbuf(connection_t *conn);
void dns_reset(void);
void connection_dns_remove(edge_connection_t *conn);
void assert_connection_edge_not_dns_pending(edge_connection_t *conn);
void assert_all_pending_dns_resolves_ok(void);
void dns_cancel_pending_resolve(const char *question);
int dns_resolve(edge_connection_t *exitconn, or_circuit_t *circ);
void dns_launch_wildcard_checks(void);

/********************************* hibernate.c **********************/

int accounting_parse_options(or_options_t *options, int validate_only);
int accounting_is_enabled(or_options_t *options);
void configure_accounting(time_t now);
void accounting_run_housekeeping(time_t now);
void accounting_add_bytes(size_t n_read, size_t n_written, int seconds);
int accounting_record_bandwidth_usage(time_t now);
void hibernate_begin_shutdown(void);
int we_are_hibernating(void);
void consider_hibernation(time_t now);
int accounting_getinfo_helper(const char *question, char **answer);
void accounting_set_bandwidth_usage_from_state(or_state_t *state);

/********************************* main.c ***************************/

extern int has_completed_circuit;

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
int connection_in_array(connection_t *conn);
void add_connection_to_closeable_list(connection_t *conn);
int connection_is_on_closeable_list(connection_t *conn);

void get_connection_array(connection_t ***array, int *n);

void connection_watch_events(connection_t *conn, short events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void directory_all_unreachable(time_t now);
void directory_info_has_arrived(time_t now, int from_cache);

int control_signal_check(int the_signal);
void control_signal_act(int the_signal);
void handle_signals(int is_parent);
void tor_cleanup(void);
void tor_free_all(int postfork);

int tor_main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int onion_pending_add(or_circuit_t *circ);
or_circuit_t *onion_next_task(void);
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

int fast_server_handshake(const char *key_in,
                          char *handshake_reply_out,
                          char *key_out,
                          size_t key_out_len);

int fast_client_handshake(const char *handshake_state,
                          const char *handshake_reply_out,
                          char *key_out,
                          size_t key_out_len);

void clear_pending_onions(void);

/********************************* policies.c ************************/

typedef enum {
  ADDR_POLICY_ACCEPTED=0,
  ADDR_POLICY_REJECTED=-1,
  ADDR_POLICY_PROBABLY_ACCEPTED=1,
  ADDR_POLICY_PROBABLY_REJECTED=2
} addr_policy_result_t;

int firewall_is_fascist_or(void);
int fascist_firewall_allows_address_or(uint32_t addr, uint16_t port);
int fascist_firewall_allows_address_dir(uint32_t addr, uint16_t port);
int dir_policy_permits_address(uint32_t addr);
int socks_policy_permits_address(uint32_t addr);
int authdir_policy_permits_address(uint32_t addr, uint16_t port);
int authdir_policy_valid_address(uint32_t addr, uint16_t port);

int validate_addr_policies(or_options_t *options, char **msg);
void policies_parse_from_options(or_options_t *options);

int cmp_addr_policies(addr_policy_t *a, addr_policy_t *b);
addr_policy_result_t compare_addr_to_addr_policy(uint32_t addr,
                              uint16_t port, addr_policy_t *policy);
int policies_parse_exit_policy(config_line_t *cfg,
                               addr_policy_t **dest,
                               int rejectprivate);
int exit_policy_is_general_exit(addr_policy_t *policy);
int policy_is_reject_star(addr_policy_t *policy);
int policies_getinfo_helper(const char *question, char **answer);

void addr_policy_free(addr_policy_t *p);
void policies_free_all(void);

/********************************* relay.c ***************************/

extern uint64_t stats_n_relay_cells_relayed;
extern uint64_t stats_n_relay_cells_delivered;

int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction);

void relay_header_pack(char *dest, const relay_header_t *src);
void relay_header_unpack(relay_header_t *dest, const char *src);
int connection_edge_send_command(edge_connection_t *fromconn, circuit_t *circ,
                                 int relay_command, const char *payload,
                                 size_t payload_len,
                                 crypt_path_t *cpath_layer);
int connection_edge_package_raw_inbuf(edge_connection_t *conn,
                                      int package_partial);
void connection_edge_consider_sending_sendme(edge_connection_t *conn);
socks5_reply_status_t connection_edge_end_reason_socks5_response(int reason);
int errno_to_end_reason(int e);

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
int rep_hist_bandwidth_assess(void);
char *rep_hist_get_bandwidth_lines(void);
void rep_hist_update_state(or_state_t *state);
int rep_hist_load_state(or_state_t *state, char **err);
void rep_history_clean(time_t before);

void rep_hist_note_used_port(uint16_t port, time_t now);
smartlist_t *rep_hist_get_predicted_ports(time_t now);
void rep_hist_note_used_resolve(time_t now);
void rep_hist_note_used_internal(time_t now, int need_uptime,
                                 int need_capacity);
int rep_hist_get_predicted_internal(time_t now, int *need_uptime,
                                    int *need_capacity);

int any_predicted_circuits(time_t now);
int rep_hist_circbuilding_dormant(time_t now);

void rep_hist_free_all(void);

/********************************* rendclient.c ***************************/

void rend_client_introcirc_has_opened(origin_circuit_t *circ);
void rend_client_rendcirc_has_opened(origin_circuit_t *circ);
int rend_client_introduction_acked(origin_circuit_t *circ, const char *request,
                                   size_t request_len);
void rend_client_refetch_renddesc(const char *query);
int rend_client_remove_intro_point(extend_info_t *failed_intro,
                                   const char *query);
int rend_client_rendezvous_acked(origin_circuit_t *circ, const char *request,
                                 size_t request_len);
int rend_client_receive_rendezvous(origin_circuit_t *circ, const char *request,
                                   size_t request_len);
void rend_client_desc_here(const char *query);

extend_info_t *rend_client_get_random_intro(const char *query);

int rend_client_send_introduction(origin_circuit_t *introcirc,
                                  origin_circuit_t *rendcirc);

/********************************* rendcommon.c ***************************/

/** Information used to connect to a hidden service. */
typedef struct rend_service_descriptor_t {
  crypto_pk_env_t *pk; /**< This service's public key. */
  int version; /**< 0 or 1. */
  time_t timestamp; /**< Time when the descriptor was generated. */
  uint16_t protocols; /**< Bitmask: which rendezvous protocols are supported?
                       * (We allow bits '0', '1', and '2' to be set.) */
  int n_intro_points; /**< Number of introduction points. */
  /** Array of n_intro_points elements for this service's introduction points'
   * nicknames.  Elements are removed from this array if introduction attempts
   * fail. */
  char **intro_points;
  /** Array of n_intro_points elements for this service's introduction points'
   * extend_infos, or NULL if this descriptor is V0.  Elements are removed
   * from this array if introduction attempts fail.  If this array is present,
   * its elements correspond to the elements of intro_points. */
  extend_info_t **intro_point_extend_info;
} rend_service_descriptor_t;

int rend_cmp_service_ids(const char *one, const char *two);

void rend_process_relay_cell(circuit_t *circ, int command, size_t length,
                             const char *payload);

void rend_service_descriptor_free(rend_service_descriptor_t *desc);
int rend_encode_service_descriptor(rend_service_descriptor_t *desc,
                                   int version,
                                   crypto_pk_env_t *key,
                                   char **str_out,
                                   size_t *len_out);
rend_service_descriptor_t *rend_parse_service_descriptor(const char *str,
                                                         size_t len);
int rend_get_service_id(crypto_pk_env_t *pk, char *out);

/** A cached rendezvous descriptor. */
typedef struct rend_cache_entry_t {
  size_t len; /** Length of <b>desc</b> */
  time_t received; /** When was the descriptor received? */
  char *desc; /** Service descriptor */
  rend_service_descriptor_t *parsed; /* Parsed value of 'desc' */
} rend_cache_entry_t;

void rend_cache_init(void);
void rend_cache_clean(void);
void rend_cache_free_all(void);
int rend_valid_service_id(const char *query);
int rend_cache_lookup_desc(const char *query, int version, const char **desc,
                           size_t *desc_len);
int rend_cache_lookup_entry(const char *query, int version,
                            rend_cache_entry_t **entry_out);
int rend_cache_store(const char *desc, size_t desc_len);

/********************************* rendservice.c ***************************/

int num_rend_services(void);
int rend_config_services(or_options_t *options, int validate_only);
int rend_service_load_keys(void);
void rend_services_init(void);
void rend_services_introduce(void);
void rend_consider_services_upload(time_t now);

void rend_service_intro_has_opened(origin_circuit_t *circuit);
int rend_service_intro_established(origin_circuit_t *circuit,
                                   const char *request,
                                   size_t request_len);
void rend_service_rendezvous_has_opened(origin_circuit_t *circuit);
int rend_service_introduce(origin_circuit_t *circuit, const char *request,
                           size_t request_len);
void rend_service_relaunch_rendezvous(origin_circuit_t *oldcirc);
int rend_service_set_connection_addr_port(edge_connection_t *conn,
                                          origin_circuit_t *circ);
void rend_service_dump_stats(int severity);
void rend_service_free_all(void);

/********************************* rendmid.c *******************************/
int rend_mid_establish_intro(or_circuit_t *circ, const char *request,
                             size_t request_len);
int rend_mid_introduce(or_circuit_t *circ, const char *request,
                       size_t request_len);
int rend_mid_establish_rendezvous(or_circuit_t *circ, const char *request,
                                  size_t request_len);
int rend_mid_rendezvous(or_circuit_t *circ, const char *request,
                        size_t request_len);

/********************************* router.c ***************************/

void set_onion_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_onion_key(void);
time_t get_onion_key_set_at(void);
void set_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_identity_key(void);
int identity_key_is_set(void);
void dup_onion_keys(crypto_pk_env_t **key, crypto_pk_env_t **last);
void rotate_onion_key(void);
crypto_pk_env_t *init_key_from_file(const char *fname);
int init_keys(void);

int check_whether_orport_reachable(void);
int check_whether_dirport_reachable(void);
void consider_testing_reachability(int test_or, int test_dir);
void router_orport_found_reachable(void);
void router_dirport_found_reachable(void);
void server_has_changed_ip(void);
void router_perform_bandwidth_test(int num_circs, time_t now);

int authdir_mode(or_options_t *options);
int clique_mode(or_options_t *options);
int server_mode(or_options_t *options);
int advertised_server_mode(void);
int proxy_mode(or_options_t *options);
void consider_publishable_server(int force);

int router_is_clique_mode(routerinfo_t *router);
void router_upload_dir_desc_to_dirservers(int force);
void mark_my_descriptor_dirty_if_older_than(time_t when);
void mark_my_descriptor_dirty(void);
void check_descriptor_bandwidth_changed(time_t now);
void check_descriptor_ipaddress_changed(time_t now);
void router_new_address_suggestion(const char *suggestion);
int router_compare_to_my_exit_policy(edge_connection_t *conn);
routerinfo_t *router_get_my_routerinfo(void);
const char *router_get_my_descriptor(void);
int router_digest_is_me(const char *digest);
int router_is_me(routerinfo_t *router);
int router_fingerprint_is_me(const char *fp);
int router_pick_published_address(or_options_t *options, uint32_t *addr);
int router_rebuild_descriptor(int force);
int router_dump_router_to_string(char *s, size_t maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key);
int is_legal_nickname(const char *s);
int is_legal_nickname_or_hexdigest(const char *s);
int is_legal_hexdigest(const char *s);
void router_reset_warnings(void);
void router_free_all(void);

/********************************* routerlist.c ***************************/

/** Represents information about a single trusted directory server. */
typedef struct trusted_dir_server_t {
  char *description;
  char *nickname;
  char *address; /**< Hostname */
  uint32_t addr; /**< IPv4 address */
  uint16_t dir_port; /**< Directory port */
  char digest[DIGEST_LEN]; /**< Digest of identity key */
  unsigned int is_running:1; /**< True iff we think this server is running. */
  /** True iff this server is an authority for the older ("v1") directory
   * protocol.  (All authorities are v2 authorities.) */
  unsigned int is_v1_authority:1;
  int n_networkstatus_failures; /**< How many times have we asked for this
                                 * server's network-status unsuccessfully? */
  routerstatus_t fake_status; /**< Used when we need to pass this trusted
                               * dir_server_t to directory_initiate_command_*
                               * as a routerstatus_t.  Not updated by the
                               * router-status management code!
                               **/
} trusted_dir_server_t;

int router_reload_router_list(void);
int router_reload_networkstatus(void);
smartlist_t *router_get_trusted_dir_servers(void);
routerstatus_t *router_pick_directory_server(int requireother,
                                             int fascistfirewall,
                                             int for_v2_directory,
                                             int retry_if_no_servers);
routerstatus_t *router_pick_trusteddirserver(int need_v1_authority,
                                             int requireother,
                                             int fascistfirewall,
                                             int retry_if_no_servers);
trusted_dir_server_t *router_get_trusteddirserver_by_digest(
     const char *digest);
void routerlist_add_family(smartlist_t *sl, routerinfo_t *router);
void add_nickname_list_to_smartlist(smartlist_t *sl, const char *list,
                                    int must_be_running,
                                    int warn_if_down, int warn_if_unnamed);
routerinfo_t *routerlist_find_my_routerinfo(void);
routerinfo_t *router_find_exact_exit_enclave(const char *address,
                                             uint16_t port);

#define ROUTER_REQUIRED_MIN_BANDWIDTH 10000
int router_is_unreliable(routerinfo_t *router, int need_uptime,
                         int need_capacity, int need_guard);
uint32_t router_get_advertised_bandwidth(routerinfo_t *router);
routerinfo_t *routerlist_sl_choose_by_bandwidth(smartlist_t *sl);
routerinfo_t *router_choose_random_node(const char *preferred,
                                        const char *excluded,
                                        smartlist_t *excludedsmartlist,
                                        int need_uptime, int need_bandwidth,
                                        int need_guard,
                                        int allow_invalid, int strict);
routerinfo_t *router_get_by_nickname(const char *nickname,
                                     int warn_if_unnamed);
routerinfo_t *router_get_by_hexdigest(const char *hexdigest);
routerinfo_t *router_get_by_digest(const char *digest);
signed_descriptor_t *router_get_by_descriptor_digest(const char *digest);
const char *signed_descriptor_get_body(signed_descriptor_t *desc);
int router_digest_version_as_new_as(const char *digest, const char *cutoff);
int router_digest_is_trusted_dir(const char *digest);
routerlist_t *router_get_routerlist(void);
void routerlist_reset_warnings(void);
void routerlist_free(routerlist_t *routerlist);
void dump_routerlist_mem_usage(int severity);
void routerlist_remove(routerlist_t *rl, routerinfo_t *ri, int idx,
                       int make_old);
void routerinfo_free(routerinfo_t *router);
void routerstatus_free(routerstatus_t *routerstatus);
void networkstatus_free(networkstatus_t *networkstatus);
void routerlist_free_all(void);
routerinfo_t *routerinfo_copy(const routerinfo_t *router);
void router_set_status(const char *digest, int up);
void routerlist_remove_old_routers(void);
void networkstatus_list_clean(time_t now);
int router_add_to_routerlist(routerinfo_t *router, const char **msg,
                             int from_cache, int from_fetch);
int router_load_single_router(const char *s, uint8_t purpose,
                              const char **msg);
void router_load_routers_from_string(const char *s,
                                     saved_location_t saved_location,
                                     smartlist_t *requested_fingerprints);
typedef enum {
  NS_FROM_CACHE, NS_FROM_DIR_BY_FP, NS_FROM_DIR_ALL, NS_GENERATED
} networkstatus_source_t;
int router_set_networkstatus(const char *s, time_t arrived_at,
                             networkstatus_source_t source,
                             smartlist_t *requested_fingerprints);

int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port,
                                          int need_uptime);
int router_exit_policy_rejects_all(routerinfo_t *router);

void add_trusted_dir_server(const char *nickname,
                            const char *address, uint16_t port,
                            const char *digest, int is_v1_authority);
void clear_trusted_dir_servers(void);
int any_trusted_dir_is_v1_authority(void);
networkstatus_t *networkstatus_get_by_digest(const char *digest);
local_routerstatus_t *router_get_combined_status_by_digest(const char *digest);
void update_networkstatus_downloads(time_t now);
void update_router_descriptor_downloads(time_t now);
void routers_update_all_from_networkstatus(void);
void routers_update_status_from_networkstatus(smartlist_t *routers,
                                              int reset_failures);
smartlist_t *router_list_superseded(void);
int router_have_minimum_dir_info(void);
void networkstatus_list_update_recent(time_t now);
void router_reset_descriptor_download_failures(void);
void router_reset_status_download_failures(void);
int router_differences_are_cosmetic(routerinfo_t *r1, routerinfo_t *r2);
const char *esc_router_info(routerinfo_t *router);

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
} tor_version_t;

typedef enum version_status_t {
  VS_RECOMMENDED=0, /**< This version is listed as recommended. */
  VS_OLD=1, /**< This version is older than any recommended version. */
  VS_NEW=2, /**< This version is newer than any recommended version. */
  VS_NEW_IN_SERIES=3, /**< This version is newer than any recommended version
                       * in its series, and such recommended versions exist. */
  VS_UNRECOMMENDED=4 /**< This version is not recommended (general case) */
} version_status_t;

int router_get_router_hash(const char *s, char *digest);
int router_get_dir_hash(const char *s, char *digest);
int router_get_runningrouters_hash(const char *s, char *digest);
int router_get_networkstatus_v2_hash(const char *s, char *digest);
int router_append_dirobj_signature(char *buf, size_t buf_len,
                                   const char *digest,
                                   crypto_pk_env_t *private_key);
int router_parse_list_from_string(const char **s,
                                  smartlist_t *dest,
                                  saved_location_t saved_location);
int router_parse_routerlist_from_directory(const char *s,
                                           routerlist_t **dest,
                                           crypto_pk_env_t *pkey,
                                           int check_version,
                                           int write_to_cache);
int router_parse_runningrouters(const char *str);
int router_parse_directory(const char *str);
routerinfo_t *router_parse_entry_from_string(const char *s, const char *end,
                                             int cache_copy);
addr_policy_t *router_parse_addr_policy_from_string(const char *s,
                                                    int assume_action);
version_status_t tor_version_is_obsolete(const char *myversion,
                                         const char *versionlist);
version_status_t version_status_join(version_status_t a, version_status_t b);
int tor_version_parse(const char *s, tor_version_t *out);
int tor_version_as_new_as(const char *platform, const char *cutoff);
int tor_version_compare(tor_version_t *a, tor_version_t *b);
void sort_version_list(smartlist_t *lst, int remove_duplicates);
void assert_addr_policy_ok(addr_policy_t *t);

networkstatus_t *networkstatus_parse_from_string(const char *s);

#endif

