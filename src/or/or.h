/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __OR_H
#define __OR_H

#include "orconfig.h"
#ifdef MS_WINDOWS
#define WIN32_WINNT 0x400
#define _WIN32_WINNT 0x400
#define WIN32_LEAN_AND_MEAN
/* Number of fds that select will accept; default is 64. */
#define FD_SETSIZE 512
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
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
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

#define MAXCONNECTIONS 1000 /* upper bound on max connections.
                              can be lowered by config file */

#define DEFAULT_BANDWIDTH_OP (1024 * 1000)
#define MAX_NICKNAME_LEN 32
#define MAX_DIR_SIZE 500000

#ifdef TOR_PERF
#define MAX_DNS_ENTRY_AGE (150*60)
#else
#define MAX_DNS_ENTRY_AGE (15*60)
#endif

#define CIRC_ID_TYPE_LOWER 0
#define CIRC_ID_TYPE_HIGHER 1

#define _CONN_TYPE_MIN 3
#define CONN_TYPE_OR_LISTENER 3
#define CONN_TYPE_OR 4
#define CONN_TYPE_EXIT 5
#define CONN_TYPE_AP_LISTENER 6
#define CONN_TYPE_AP 7
#define CONN_TYPE_DIR_LISTENER 8
#define CONN_TYPE_DIR 9
#define CONN_TYPE_DNSWORKER 10
#define CONN_TYPE_CPUWORKER 11
#define _CONN_TYPE_MAX 11

#define LISTENER_STATE_READY 0

#define _DNSWORKER_STATE_MIN 1
#define DNSWORKER_STATE_IDLE 1
#define DNSWORKER_STATE_BUSY 2
#define _DNSWORKER_STATE_MAX 2

#define _CPUWORKER_STATE_MIN 1
#define CPUWORKER_STATE_IDLE 1
#define CPUWORKER_STATE_BUSY_ONION 2
#define CPUWORKER_STATE_BUSY_HANDSHAKE 3
#define _CPUWORKER_STATE_MAX 3

#define CPUWORKER_TASK_ONION CPUWORKER_STATE_BUSY_ONION

#define _OR_CONN_STATE_MIN 1
#define OR_CONN_STATE_CONNECTING 1 /* waiting for connect() to finish */
#define OR_CONN_STATE_HANDSHAKING 2 /* SSL is handshaking, not done yet */
#define OR_CONN_STATE_OPEN 3 /* ready to send/receive cells. */
#define _OR_CONN_STATE_MAX 3

#define _EXIT_CONN_STATE_MIN 1
#define EXIT_CONN_STATE_RESOLVING 1 /* waiting for response from dns farm */
#define EXIT_CONN_STATE_CONNECTING 2 /* waiting for connect() to finish */
#define EXIT_CONN_STATE_OPEN 3
#define EXIT_CONN_STATE_RESOLVEFAILED 4 /* waiting to be removed */
#define _EXIT_CONN_STATE_MAX 4
#if 0
#define EXIT_CONN_STATE_CLOSE 3 /* flushing the buffer, then will close */
#define EXIT_CONN_STATE_CLOSE_WAIT 4 /* have sent a destroy, awaiting a confirmation */
#endif

/* the AP state values must be disjoint from the EXIT state values */
#define _AP_CONN_STATE_MIN 5
#define AP_CONN_STATE_SOCKS_WAIT 5
#define AP_CONN_STATE_CIRCUIT_WAIT 6
#define AP_CONN_STATE_CONNECT_WAIT 7
#define AP_CONN_STATE_OPEN 8
#define _AP_CONN_STATE_MAX 8

#define _DIR_CONN_STATE_MIN 1
#define DIR_CONN_STATE_CONNECTING 1
#define DIR_CONN_STATE_CLIENT_SENDING 2
#define DIR_CONN_STATE_CLIENT_READING 3
#define DIR_CONN_STATE_SERVER_COMMAND_WAIT 4
#define DIR_CONN_STATE_SERVER_WRITING 5
#define _DIR_CONN_STATE_MAX 5

#define _DIR_PURPOSE_MIN 1
#define DIR_PURPOSE_FETCH_DIR 1
#define DIR_PURPOSE_FETCH_HIDSERV 2
#define DIR_PURPOSE_UPLOAD_DIR 3
#define DIR_PURPOSE_UPLOAD_HIDSERV 4
#define DIR_PURPOSE_SERVER 5
#define _DIR_PURPOSE_MAX 5

#define CIRCUIT_STATE_BUILDING 0 /* I'm the OP, still haven't done all my handshakes */
#define CIRCUIT_STATE_ONIONSKIN_PENDING 1 /* waiting to process the onionskin */
#define CIRCUIT_STATE_OR_WAIT 2 /* I'm the OP, my firsthop is still connecting */
#define CIRCUIT_STATE_OPEN 3 /* onionskin(s) processed, ready to send/receive cells */

#define _CIRCUIT_PURPOSE_MIN 1
/* these circuits were initiated elsewhere */
#define CIRCUIT_PURPOSE_INTERMEDIATE 1 /* normal circuit, at OR. */
#define CIRCUIT_PURPOSE_INTRO_POINT 2 /* At OR, from Bob, waiting for intro from Alices */
#define CIRCUIT_PURPOSE_REND_POINT_WAITING 3 /* At OR, from Alice, waiting for Bob */
#define CIRCUIT_PURPOSE_REND_ESTABLISHED 4 /* At OR, both circuits have this purpose */
/* these circuits originate at this node */
#define CIRCUIT_PURPOSE_C_GENERAL 5 /* normal circuit, with cpath */
#define CIRCUIT_PURPOSE_S_ESTABLISH_INTRO 6 /* at Bob, waiting for introductions */
#define CIRCUIT_PURPOSE_C_INTRODUCING 7 /* at Alice, connecting to intro point */
#define CIRCUIT_PURPOSE_C_ESTABLISH_REND 8 /* at Alice, waiting for Bob */
#define CIRCUIT_PURPOSE_S_RENDEZVOUSING 9 /* at Bob, connecting to rend point */
#define _CIRCUIT_PURPOSE_MAX 9

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

#define _MIN_END_STREAM_REASON 1
#define END_STREAM_REASON_MISC 1
#define END_STREAM_REASON_RESOLVEFAILED 2
#define END_STREAM_REASON_CONNECTFAILED 3
#define END_STREAM_REASON_EXITPOLICY 4
#define END_STREAM_REASON_DESTROY 5
#define END_STREAM_REASON_DONE 6
#define END_STREAM_REASON_TIMEOUT 7
#define _MAX_END_STREAM_REASON 7

/* Reasons used by connection_mark_for_close */
#define CLOSE_REASON_UNUSED_OR_CONN 100

/* default cipher function */
#define DEFAULT_CIPHER CRYPTO_CIPHER_AES_CTR
/* Used to en/decrypt onion skins */
#define ONION_CIPHER      DEFAULT_CIPHER
/* Used to en/decrypt RELAY cells */
#define CIRCUIT_CIPHER    DEFAULT_CIPHER

#define CELL_DIRECTION_IN 1
#define CELL_DIRECTION_OUT 2
#define EDGE_EXIT CONN_TYPE_EXIT
#define EDGE_AP CONN_TYPE_AP
#define CELL_DIRECTION(x) ((x) == EDGE_EXIT ? CELL_DIRECTION_IN : CELL_DIRECTION_OUT)

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

/* legal characters in a filename */
#define CONFIG_LEGAL_FILENAME_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/"
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

#if 0
#define CELL_RELAY_COMMAND(c)         (*(uint8_t*)((c).payload))
#define SET_CELL_RELAY_COMMAND(c,cmd) (*(uint8_t*)((c).payload) = (cmd))

#define CELL_RELAY_RECOGNIZED(c)       (ntohs(*(uint16_t*)((c).payload+1)))
#define SET_CELL_RELAY_RECOGNIZED(c,r) (*(uint16_t*)((c).payload+1) = htons(r))

#define STREAM_ID_SIZE 2
//#define SET_CELL_STREAM_ID(c,id)      memcpy((c).payload+1,(id),STREAM_ID_SIZE)
#define CELL_RELAY_STREAM_ID(c)        (ntohs(*(uint16_t*)((c).payload+3)))
#define SET_CELL_RELAY_STREAM_ID(c,id) (*(uint16_t*)((c).payload+3) = htons(id))
#define ZERO_STREAM 0

/* integrity is the first 32 bits (in network order) of a sha-1 of all
 * cell payloads that are relay cells that have been sent / delivered
 * to the hop on the * circuit (the integrity is zeroed while doing
 * each calculation)
 */
#define CELL_RELAY_INTEGRITY(c)       (ntohl(*(uint32_t*)((c).payload+5)))
#define SET_CELL_RELAY_INTEGRITY(c,i) (*(uint32_t*)((c).payload+5) = htonl(i))

/* relay length is how many bytes are used in the cell payload past relay_header_size */
#define CELL_RELAY_LENGTH(c)         (ntohs(*(uint16_t*)((c).payload+9)))
#define SET_CELL_RELAY_LENGTH(c,len) (*(uint16_t*)((c).payload+9) = htons(len))
#endif

#define CELL_PAYLOAD_SIZE 509
#define CELL_NETWORK_SIZE 512

#define RELAY_HEADER_SIZE (1+2+2+4+2)
#define RELAY_PAYLOAD_SIZE (CELL_PAYLOAD_SIZE-RELAY_HEADER_SIZE)

/* cell definition */
typedef struct {
  uint16_t circ_id;
  unsigned char command;
  unsigned char payload[CELL_PAYLOAD_SIZE];
} cell_t;

typedef struct {
  uint8_t command;
  uint16_t recognized;
  uint16_t stream_id;
  char integrity[4];
  uint16_t length;
} relay_header_t;

typedef struct buf_t buf_t;
typedef struct socks_request_t socks_request_t;

#define CONNECTION_MAGIC 0x7C3C304Eu
struct connection_t {
  uint32_t magic; /* for memory debugging */

  uint8_t type;
  uint8_t state;
  uint8_t purpose; /* only used for DIR types currently */
  uint8_t wants_to_read; /* should we start reading again once
                          * the bandwidth throttler allows it?
                          */
  uint8_t wants_to_write; /* should we start writing again once
                           * the bandwidth throttler allows reads?
                           */
  int s; /* our socket */
  int poll_index; /* index of this conn into the poll_array */
  int marked_for_close; /* should we close this conn on the next
                         * iteration of the main loop?
                         */
  char *marked_for_close_file; /* for debugging: in which file were we marked
                                * for close? */
  int hold_open_until_flushed;

  buf_t *inbuf;
  int inbuf_reached_eof; /* did read() return 0 on this conn? */
  time_t timestamp_lastread; /* when was the last time poll() said we could read? */

  buf_t *outbuf;
  int outbuf_flushlen; /* how much data should we try to flush from the outbuf? */
  time_t timestamp_lastwritten; /* when was the last time poll() said we could write? */

  time_t timestamp_created; /* when was this connection_t created? */

  uint32_t addr; /* these two uniquely identify a router. Both in host order. */
  uint16_t port; /* if non-zero, they identify the guy on the other end
                  * of the connection. */
  char *address; /* FQDN (or IP) of the guy on the other end.
                  * strdup into this, because free_connection frees it
                  */
  crypto_pk_env_t *onion_pkey; /* public RSA key for the other side's onions */
  crypto_pk_env_t *link_pkey; /* public RSA key for the other side's TLS */
  crypto_pk_env_t *identity_pkey; /* public RSA key for the other side's signing */
  char *nickname;

/* Used only by OR connections: */
  tor_tls *tls;
  uint16_t next_circ_id; /* Which circ_id do we try to use next on this connection?
                          * This is always in the range 0..1<<15-1.*/

  /* bandwidth and receiver_bucket only used by ORs in OPEN state: */
  int bandwidth; /* connection bandwidth. */
  int receiver_bucket; /* when this hits 0, stop receiving. Every second we
                        * add 'bandwidth' to this, capping it at 10*bandwidth.
                        */

/* Used only by edge connections: */
  uint16_t stream_id;
  struct connection_t *next_stream; /* points to the next stream at this edge, if any */
  struct crypt_path_t *cpath_layer; /* a pointer to which node in the circ this conn exits at */
  int package_window; /* how many more relay cells can i send into the circuit? */
  int deliver_window; /* how many more relay cells can end at me? */

  int done_sending; /* for half-open connections; not used currently */
  int done_receiving;
  char has_sent_end; /* for debugging: set once we've set the stream end,
                        and check in circuit_about_to_close_connection() */
  char num_retries; /* how many times have we re-tried beginning this stream? */

  /* Used only by AP connections */
  socks_request_t *socks_request;
};

typedef struct connection_t connection_t;

#define EXIT_POLICY_ACCEPT 1
#define EXIT_POLICY_REJECT 2

struct exit_policy_t {
  char policy_type;
  char *string;
  uint32_t addr;
  uint32_t msk;
  uint16_t prt_min;
  uint16_t prt_max;

  struct exit_policy_t *next;
};

/* config stuff we know about the other ORs in the network */
typedef struct {
  char *address;
  char *nickname;

  uint32_t addr; /* all host order */
  uint16_t or_port;
  uint16_t socks_port;
  uint16_t dir_port;

  time_t published_on;

  crypto_pk_env_t *onion_pkey; /* public RSA key for onions */
  crypto_pk_env_t *link_pkey;  /* public RSA key for TLS */
  crypto_pk_env_t *identity_pkey;  /* public RSA key for signing */

  int is_running;

  /* link info */
  uint32_t bandwidthrate;
  uint32_t bandwidthburst;
  struct exit_policy_t *exit_policy;
} routerinfo_t;

#define MAX_ROUTERS_IN_DIR 1024
typedef struct {
  routerinfo_t **routers;
  int n_routers;
  char *software_versions;
  time_t published_on;
} routerlist_t;

struct crypt_path_t {

  /* crypto environments */
  crypto_cipher_env_t *f_crypto;
  crypto_cipher_env_t *b_crypto;

  crypto_digest_env_t *f_digest; /* for integrity checking */
  crypto_digest_env_t *b_digest;

  crypto_dh_env_t *handshake_state;

  uint32_t addr;
  uint16_t port;

  uint8_t state;
#define CPATH_STATE_CLOSED 0
#define CPATH_STATE_AWAITING_KEYS 1
#define CPATH_STATE_OPEN 2
  struct crypt_path_t *next;
  struct crypt_path_t *prev; /* doubly linked list */

  int package_window;
  int deliver_window;
};

#define DH_KEY_LEN CRYPTO_DH_SIZE
#define ONIONSKIN_CHALLENGE_LEN (16+DH_KEY_LEN)
#define ONIONSKIN_REPLY_LEN (DH_KEY_LEN+20)
#define REND_COOKIE_LEN CRYPTO_SHA1_DIGEST_LEN

typedef struct crypt_path_t crypt_path_t;

typedef struct {
  int desired_path_len;
  char *chosen_exit; /* nickname of planned exit node */
  crypto_dh_env_t *rend_handshake_state; /*XXXXDOCDOC*/
  unsigned char rend_key_material[52]; /*XXXXDOCDOC*/
} cpath_build_state_t;

/* struct for a path (circuit) through the network */
#define CIRCUIT_MAGIC 0x35315243u
struct circuit_t {
  uint32_t magic; /* for memory debugging. */

  int marked_for_close; /* Should we close this circuit at the end of the main
                         * loop? */
  char *marked_for_close_file;

  uint32_t n_addr;
  uint16_t n_port;
  connection_t *p_conn;
  connection_t *n_conn; /* for the OR conn, if there is one */
  connection_t *p_streams;
  connection_t *n_streams;
  uint16_t next_stream_id;
  int package_window;
  int deliver_window;

  uint16_t p_circ_id; /* circuit identifiers */
  uint16_t n_circ_id;

  crypto_cipher_env_t *p_crypto; /* used only for intermediate hops */
  crypto_cipher_env_t *n_crypto;

  crypto_digest_env_t *p_digest; /* for integrity checking, */
  crypto_digest_env_t *n_digest; /* intermediate hops only */

  cpath_build_state_t *build_state;
  crypt_path_t *cpath;

  char onionskin[ONIONSKIN_CHALLENGE_LEN]; /* for storage while onionskin pending */
  time_t timestamp_created;
  time_t timestamp_dirty; /* when the circuit was first used, or 0 if clean */

  uint8_t state;
  uint8_t purpose;

  /* The field rend_sevice:
   *  holds hash of location-hidden service's PK if purpose is INTRO_POINT
   *     or S_ESTABLISH_INTRO or S_RENDEZVOUSING;
   *  holds y portion of y.onion (zero-padded) if purpose is C_INTRODUCING or
   *     C_ESTABLISH_REND, or is a C_GENERAL for a hidden service.
   *  is filled with zeroes otherwise.
   */
  char rend_service[CRYPTO_SHA1_DIGEST_LEN];

  /* Holds rendezvous cookie if purpose is REND_POINT_WAITING or
   * S_RENDEZVOUSING.  Filled with zeroes otherwise.
  */
  char rend_cookie[REND_COOKIE_LEN];

  /* Points to spliced circuit if purpose is REND_ESTABLISHED, and circuit
   * is not marked for close. */
  struct circuit_t *rend_splice;

  struct circuit_t *next;
};

typedef struct circuit_t circuit_t;

typedef struct circuit_data_rend_point_t {
  /* for CIRCUIT_PURPOSE_INTRO_POINT (at OR, from Bob, waiting for intro) */
  char rend_cookie[20];
} circuit_data_intro_point_t;

typedef struct {
  char *LogLevel;
  char *LogFile;
  char *DebugLogFile;
  char *DataDirectory;
  char *RouterFile;
  char *Nickname;
  char *Address;
  char *PidFile;
  char *ExitNodes;
  char *EntryNodes;
  char *ExcludeNodes;
  char *ExitPolicy;
  char *SocksBindAddress;
  char *ORBindAddress;
  char *DirBindAddress;
  char *RecommendedVersions;
  char *User;
  char *Group;
  double PathlenCoinWeight;
  int ORPort;
  int SocksPort;
  int DirPort;
  int MaxConn;
  int TrafficShaping;
  int LinkPadding;
  int IgnoreVersion;
  int RunAsDaemon;
  int DirRebuildPeriod;
  int DirFetchPostPeriod;
  int KeepalivePeriod;
  int MaxOnionsPending;
  int NewCircuitPeriod;
  int BandwidthRate;
  int BandwidthBurst;
  int NumCpus;
  int loglevel;
  int RunTesting;
  struct config_line_t *RendConfigLines;
} or_options_t;

/* XXX are these good enough defaults? */
#define MAX_SOCKS_REPLY_LEN 1024
#define MAX_SOCKS_ADDR_LEN 256
struct socks_request_t {
  char socks_version;
  int replylen;
  char reply[MAX_SOCKS_REPLY_LEN];
  int has_finished; /* has the socks handshake finished? */
  char address[MAX_SOCKS_ADDR_LEN];
  uint16_t port;
};

/* all the function prototypes go here */

/********************************* buffers.c ***************************/

int find_on_inbuf(char *string, int string_len, buf_t *buf);

buf_t *buf_new();
buf_t *buf_new_with_capacity(size_t size);
void buf_free(buf_t *buf);
void buf_clear(buf_t *buf);

size_t buf_datalen(const buf_t *buf);
size_t buf_capacity(const buf_t *buf);
const char *_buf_peek_raw_buffer(const buf_t *buf);

int read_to_buf(int s, int at_most, buf_t *buf, int *reached_eof);
int read_to_buf_tls(tor_tls *tls, int at_most, buf_t *buf);

int flush_buf(int s, buf_t *buf, int *buf_flushlen);
int flush_buf_tls(tor_tls *tls, buf_t *buf, int *buf_flushlen);

int write_to_buf(const char *string, int string_len, buf_t *buf);
int fetch_from_buf(char *string, int string_len, buf_t *buf);
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, int max_headerlen,
                        char **body_out, int *body_used, int max_bodylen);
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req);

void assert_buf_ok(buf_t *buf);

/********************************* circuit.c ***************************/

void circuit_add(circuit_t *circ);
void circuit_remove(circuit_t *circ);
circuit_t *circuit_new(uint16_t p_circ_id, connection_t *p_conn);
void circuit_close_all_marked(void);
void circuit_free(circuit_t *circ);
void circuit_free_cpath(crypt_path_t *cpath);
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


circuit_t *circuit_get_by_circ_id_conn(uint16_t circ_id, connection_t *conn);
circuit_t *circuit_get_by_conn(connection_t *conn);
circuit_t *circuit_get_newest(connection_t *conn,
                              int must_be_open, int must_be_clean);
circuit_t *circuit_get_by_service_and_purpose(const char *servid, int purpose);

void circuit_expire_building(void);
int circuit_count_building(void);
int circuit_stream_is_being_handled(connection_t *conn);

int circuit_receive_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction);
int circuit_package_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction, crypt_path_t *layer_hint);

void circuit_resume_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint);
int circuit_consider_stop_edge_reading(circuit_t *circ, int edge_type, crypt_path_t *layer_hint);
void circuit_consider_sending_sendme(circuit_t *circ, int edge_type, crypt_path_t *layer_hint);

void circuit_detach_stream(circuit_t *circ, connection_t *conn);
void circuit_about_to_close_connection(connection_t *conn);

void circuit_log_path(int severity, circuit_t *circ);
void circuit_dump_by_conn(connection_t *conn, int severity);

void circuit_expire_unused_circuits(void);
circuit_t *circuit_launch_new(uint8_t purpose, const char *exit_nickname);
void circuit_increment_failure_count(void);
void circuit_reset_failure_count(void);
void circuit_n_conn_open(connection_t *or_conn);
int circuit_send_next_onion_skin(circuit_t *circ);
int circuit_extend(cell_t *cell, circuit_t *circ);
int circuit_finish_handshake(circuit_t *circ, char *reply);
int circuit_truncated(circuit_t *circ, crypt_path_t *layer);

void assert_cpath_ok(const crypt_path_t *c);
void assert_cpath_layer_ok(const crypt_path_t *c);
void assert_circuit_ok(const circuit_t *c);

extern unsigned long stats_n_relay_cells_relayed;
extern unsigned long stats_n_relay_cells_delivered;

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

/********************************* connection.c ***************************/

#define CONN_TYPE_TO_STRING(t) (((t) < _CONN_TYPE_MIN || (t) > _CONN_TYPE_MAX) ? \
  "Unknown" : conn_type_to_string[(t)])

extern char *conn_type_to_string[];

connection_t *connection_new(int type);
void connection_free(connection_t *conn);
void connection_free_all(void);
void connection_close_immediate(connection_t *conn);
int _connection_mark_for_close(connection_t *conn, char reason);

#define connection_mark_for_close(c,r)                                  \
  do {                                                                  \
    if (_connection_mark_for_close(c,r)<0) {                            \
      log(LOG_WARN,"Duplicate call to connection_mark_for_close at %s:%d (first at %s:%d)", \
          __FILE__,__LINE__,c->marked_for_close_file,c->marked_for_close); \
    } else {                                                            \
      c->marked_for_close_file = __FILE__;                              \
      c->marked_for_close = __LINE__;                                   \
    }                                                                   \
  } while (0)

void connection_expire_held_open(void);

int connection_create_listener(char *bindaddress, uint16_t bindport, int type);

int connection_connect(connection_t *conn, char *address, uint32_t addr, uint16_t port);
int retry_all_connections(void);

void connection_bucket_init(void);
void connection_bucket_refill(struct timeval *now);

int connection_handle_read(connection_t *conn);
int connection_read_to_buf(connection_t *conn);

int connection_fetch_from_buf(char *string, int len, connection_t *conn);
int connection_find_on_inbuf(char *string, int len, connection_t *conn);

int connection_wants_to_flush(connection_t *conn);
int connection_outbuf_too_full(connection_t *conn);
int connection_handle_write(connection_t *conn);
void connection_write_to_buf(const char *string, int len, connection_t *conn);

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port);
connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port);

connection_t *connection_get_by_type(int type);
connection_t *connection_get_by_type_state(int type, int state);
connection_t *connection_get_by_type_state_lastwritten(int type, int state);

#define connection_speaks_cells(conn) ((conn)->type == CONN_TYPE_OR)
#define connection_has_pending_tls_data(conn) \
  ((conn)->type == CONN_TYPE_OR && \
   (conn)->state == OR_CONN_STATE_OPEN && \
   tor_tls_get_pending_bytes((conn)->tls))
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);

int connection_send_destroy(uint16_t circ_id, connection_t *conn);

int connection_process_inbuf(connection_t *conn);
int connection_finished_flushing(connection_t *conn);

void assert_connection_ok(connection_t *conn, time_t now);

/********************************* connection_edge.c ***************************/

void relay_header_pack(char *dest, const relay_header_t *src);
void relay_header_unpack(relay_header_t *dest, const char *src);
int connection_edge_process_inbuf(connection_t *conn);
int connection_edge_destroy(uint16_t circ_id, connection_t *conn);
int connection_edge_end(connection_t *conn, char reason, crypt_path_t *cpath_layer);
int connection_edge_send_command(connection_t *fromconn, circuit_t *circ,
                                 int relay_command, void *payload,
                                 int payload_len, crypt_path_t *cpath_layer);
int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ,
                                       connection_t *conn, int edge_type,
                                       crypt_path_t *layer_hint);
int connection_edge_finished_flushing(connection_t *conn);

int connection_edge_package_raw_inbuf(connection_t *conn);

int connection_ap_make_bridge(char *address, uint16_t port);

void connection_ap_handshake_socks_reply(connection_t *conn, char *reply,
                                         int replylen, char success);

void connection_exit_connect(connection_t *conn);
int connection_ap_can_use_exit(connection_t *conn, routerinfo_t *exit);
void connection_ap_expire_beginning(void);
void connection_ap_attach_pending(void);

extern uint64_t stats_n_data_cells_packaged;
extern uint64_t stats_n_data_bytes_packaged;
extern uint64_t stats_n_data_cells_received;
extern uint64_t stats_n_data_bytes_received;

void client_dns_init(void);
void client_dns_clean(void);

/********************************* connection_or.c ***************************/

int connection_or_process_inbuf(connection_t *conn);
int connection_or_finished_flushing(connection_t *conn);

void connection_or_init_conn_from_router(connection_t *conn, routerinfo_t *router);
connection_t *connection_or_connect(routerinfo_t *router);

int connection_tls_start_handshake(connection_t *conn, int receiving);
int connection_tls_continue_handshake(connection_t *conn);

void connection_or_write_cell_to_buf(const cell_t *cell, connection_t *conn);

/********************************* cpuworker.c *****************************/

void cpu_init(void);
int connection_cpu_finished_flushing(connection_t *conn);
int connection_cpu_process_inbuf(connection_t *conn);
int cpuworker_main(void *data);
int assign_to_cpuworker(connection_t *cpuworker, unsigned char question_type,
                        void *task);

/********************************* directory.c ***************************/

void directory_initiate_command(routerinfo_t *router, int purpose,
                                const char *payload, int payload_len);
int connection_dir_process_inbuf(connection_t *conn);
int connection_dir_finished_flushing(connection_t *conn);

/********************************* dns.c ***************************/

void dns_init(void);
int connection_dns_finished_flushing(connection_t *conn);
int connection_dns_process_inbuf(connection_t *conn);
void connection_dns_remove(connection_t *conn);
void assert_connection_edge_not_dns_pending(connection_t *conn);
void dns_cancel_pending_resolve(char *question);
int dns_resolve(connection_t *exitconn);

/********************************* main.c ***************************/

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_set_poll_socket(connection_t *conn);

void get_connection_array(connection_t ***array, int *n);

void connection_watch_events(connection_t *conn, short events);
int connection_is_reading(connection_t *conn);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);

int connection_is_writing(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void directory_has_arrived(void);

int main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int decide_circ_id_type(char *local_nick, char *remote_nick);

int onion_pending_add(circuit_t *circ);
circuit_t *onion_next_task(void);
void onion_pending_remove(circuit_t *circ);

int onionskin_answer(circuit_t *circ, unsigned char *payload, unsigned char *keys);

int onion_extend_cpath(crypt_path_t **head_ptr, cpath_build_state_t *state,
                       routerinfo_t **router_out);

int onion_skin_create(crypto_pk_env_t *router_key,
                      crypto_dh_env_t **handshake_state_out,
                      char *onion_skin_out);

int onion_skin_server_handshake(char *onion_skin,
                                crypto_pk_env_t *private_key,
                                char *handshake_reply_out,
                                char *key_out,
                                int key_out_len);

int onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
                             char *handshake_reply,
                             char *key_out,
                             int key_out_len);

cpath_build_state_t *onion_new_cpath_build_state(const char *exit_nickname);

/********************************* router.c ***************************/

void set_onion_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_onion_key(void);
void set_identity_key(crypto_pk_env_t *k);
crypto_pk_env_t *get_identity_key(void);
crypto_pk_env_t *get_link_key(void);
int init_keys(void);
crypto_pk_env_t *init_key_from_file(const char *fname);

void router_retry_connections(void);
void router_upload_dir_desc_to_dirservers(void);
void router_post_to_dirservers(uint8_t purpose, const char *payload, int payload_len);
int router_compare_to_my_exit_policy(connection_t *conn);
const char *router_get_my_descriptor(void);
int router_rebuild_descriptor(void);
int router_dump_router_to_string(char *s, int maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key);

/********************************* routerlist.c ***************************/

routerinfo_t *router_pick_directory_server(void);
routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port);
routerinfo_t *router_get_by_link_pk(crypto_pk_env_t *pk);
routerinfo_t *router_get_by_nickname(char *nickname);
void router_get_routerlist(routerlist_t **prouterlist);
void routerinfo_free(routerinfo_t *router);
void router_mark_as_down(char *nickname);
int router_set_routerlist_from_file(char *routerfile);
int router_set_routerlist_from_string(const char *s);
int router_get_dir_hash(const char *s, char *digest);
int router_get_router_hash(const char *s, char *digest);
int router_set_routerlist_from_directory(const char *s, crypto_pk_env_t *pkey);
routerinfo_t *router_get_entry_from_string(const char *s, const char *end);
int router_add_exit_policy_from_string(routerinfo_t *router, const char *s);
int router_compare_addr_to_exit_policy(uint32_t addr, uint16_t port,
                                       struct exit_policy_t *policy);
#define ADDR_POLICY_ACCEPTED 0
#define ADDR_POLICY_REJECTED -1
#define ADDR_POLICY_UNKNOWN 1
int router_exit_policy_all_routers_reject(uint32_t addr, uint16_t port);
int router_exit_policy_rejects_all(routerinfo_t *router);

/********************************* dirserv.c ***************************/
int dirserv_add_own_fingerprint(const char *nickname, crypto_pk_env_t *pk);
int dirserv_parse_fingerprint_file(const char *fname);
int dirserv_router_fingerprint_is_known(const routerinfo_t *router);
void dirserv_free_fingerprint_list();
int dirserv_add_descriptor(const char **desc);
int dirserv_init_from_directory_string(const char *dir);
void dirserv_free_descriptors();
int dirserv_dump_directory_to_string(char *s, int maxlen,
                                     crypto_pk_env_t *private_key);
void directory_set_dirty(void);
size_t dirserv_get_directory(const char **cp);
void dirserv_remove_old_servers(void);


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

/********************************* rendcommon.c ***************************/

/* length of 'y' portion of 'y.onion' URL. */
#define REND_SERVICE_ID_LEN 16

typedef struct rend_service_descriptor_t {
  crypto_pk_env_t *pk;
  time_t timestamp;
  int n_intro_points;
  char **intro_points;
} rend_service_descriptor_t;

void rend_service_descriptor_free(rend_service_descriptor_t *desc);
int rend_encode_service_descriptor(rend_service_descriptor_t *desc,
                                   crypto_pk_env_t *key,
                                   char **str_out,
                                   int *len_out);
rend_service_descriptor_t *rend_parse_service_descriptor(const char *str, int len);
int rend_get_service_id(crypto_pk_env_t *pk, char *out);

void rend_cache_init(void);
void rend_cache_clean(void);
int rend_cache_lookup(char *query, const char **desc, int *desc_len);
int rend_cache_store(char *desc, int desc_len);

int rend_parse_rendezvous_address(char *address);

/********************************* rendservice.c ***************************/

int rend_config_services(or_options_t *options);
int rend_service_init_keys(void);
int rend_services_init(void);

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
