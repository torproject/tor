/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __OR_H
#define __OR_H

#include "orconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_POLL_H
#include <sys/poll.h>
#elif HAVE_POLL_H
#include <poll.h>
#else
#include "../common/fakepoll.h"
#endif
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <time.h>

#define free_func zlib_free_func
#include <zlib.h>
#undef free_func


#include "../common/crypto.h"
#include "../common/log.h"
#include "../common/ss.h"
#include "../common/version.h"
#include "../common/util.h"

#define MAXCONNECTIONS 1000 /* upper bound on max connections.
                              can be lowered by config file */

#define MAX_BUF_SIZE (640*1024)
#define DEFAULT_BANDWIDTH_OP (1024 * 1000)

#define ACI_TYPE_LOWER 0
#define ACI_TYPE_HIGHER 1
#define ACI_TYPE_BOTH 2

#define CONN_TYPE_OP_LISTENER 1
#define CONN_TYPE_OP 2
#define CONN_TYPE_OR_LISTENER 3
#define CONN_TYPE_OR 4
#define CONN_TYPE_EXIT 5
#define CONN_TYPE_AP_LISTENER 6
#define CONN_TYPE_AP 7
#define CONN_TYPE_DIR_LISTENER 8
#define CONN_TYPE_DIR 9
#define CONN_TYPE_DNSMASTER 10

#define LISTENER_STATE_READY 0

#define DNSMASTER_STATE_OPEN 0

#define OP_CONN_STATE_AWAITING_KEYS 0
#define OP_CONN_STATE_OPEN 1
#if 0
#define OP_CONN_STATE_CLOSE 2 /* flushing the buffer, then will close */
#define OP_CONN_STATE_CLOSE_WAIT 3 /* have sent a destroy, awaiting a confirmation */
#endif

/* how to read these states:
 * foo_CONN_STATE_bar_baz:
 * "I am acting as a bar, currently in stage baz of talking with a foo."
 */
#define OR_CONN_STATE_OP_CONNECTING 0 /* an application proxy wants me to connect to this OR */
#define OR_CONN_STATE_OP_SENDING_KEYS 1
#define OR_CONN_STATE_CLIENT_CONNECTING 2 /* I'm connecting to this OR as an OR */
#define OR_CONN_STATE_CLIENT_SENDING_AUTH 3 /* sending address and info */
#define OR_CONN_STATE_CLIENT_AUTH_WAIT 4 /* have sent address and info, waiting */
#define OR_CONN_STATE_CLIENT_SENDING_NONCE 5 /* sending nonce, last piece of handshake */
#define OR_CONN_STATE_SERVER_AUTH_WAIT 6 /* waiting for address and info */
#define OR_CONN_STATE_SERVER_SENDING_AUTH 7 /* writing auth and nonce */
#define OR_CONN_STATE_SERVER_NONCE_WAIT 8 /* waiting for confirmation of nonce */
#define OR_CONN_STATE_OPEN 9 /* ready to send/receive cells. */

#define EXIT_CONN_STATE_RESOLVING 0 /* waiting for response from dnsmaster */
#define EXIT_CONN_STATE_CONNECTING 1 /* waiting for connect() to finish */
#define EXIT_CONN_STATE_OPEN 2
#if 0
#define EXIT_CONN_STATE_CLOSE 3 /* flushing the buffer, then will close */
#define EXIT_CONN_STATE_CLOSE_WAIT 4 /* have sent a destroy, awaiting a confirmation */
#endif

#define AP_CONN_STATE_SOCKS_WAIT 3
#define AP_CONN_STATE_OR_WAIT 4
#define AP_CONN_STATE_OPEN 5

#define DIR_CONN_STATE_CONNECTING 0
#define DIR_CONN_STATE_SENDING_COMMAND 1
#define DIR_CONN_STATE_READING 2
#define DIR_CONN_STATE_COMMAND_WAIT 3
#define DIR_CONN_STATE_WRITING 4

#define CIRCUIT_STATE_ONION_WAIT 0 /* receiving the onion */
#define CIRCUIT_STATE_ONION_PENDING 1 /* waiting to process the onion */
#define CIRCUIT_STATE_OR_WAIT 2 /* I'm at the beginning of the path, my firsthop is still connecting */
#define CIRCUIT_STATE_OPEN 3 /* onion processed, ready to send data along the connection */
//#define CIRCUIT_STATE_CLOSE_WAIT1 4 /* sent two "destroy" signals, waiting for acks */
//#define CIRCUIT_STATE_CLOSE_WAIT2 5 /* received one ack, waiting for one more 
//                                       (or if just one was sent, waiting for that one */
//#define CIRCUIT_STATE_CLOSE 4 /* both acks received, connection is dead */ /* NOT USED */

#define RELAY_COMMAND_BEGIN 1
#define RELAY_COMMAND_DATA 2
#define RELAY_COMMAND_END 3
#define RELAY_COMMAND_CONNECTED 4
#define RELAY_COMMAND_SENDME 5

#define RELAY_HEADER_SIZE 8

#define RELAY_STATE_RESOLVING

/* available cipher functions */
#if 0
#define ONION_CIPHER_IDENTITY 0
#define ONION_CIPHER_DES 1
#define ONION_CIPHER_RC4 2
#define ONION_CIPHER_3DES 3
#endif

/* default cipher function */
#if 0
#define ONION_DEFAULT_CIPHER ONION_CIPHER_3DES
#endif
#define DEFAULT_CIPHER CRYPTO_CIPHER_3DES

#define CELL_DIRECTION_IN 1
#define CELL_DIRECTION_OUT 2
#define EDGE_EXIT CONN_TYPE_EXIT
#define EDGE_AP CONN_TYPE_AP

#define CIRCWINDOW_START 1000
#define CIRCWINDOW_INCREMENT 100

#define STREAMWINDOW_START 500
#define STREAMWINDOW_INCREMENT 50

/* cell commands */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_RELAY 2
#define CELL_DESTROY 3
#define CELL_SENDME 4

#define CELL_PAYLOAD_SIZE 248
#define CELL_NETWORK_SIZE 256

/* enumeration of types which option values can take */
#define CONFIG_TYPE_STRING  0
#define CONFIG_TYPE_CHAR    1
#define CONFIG_TYPE_INT     2
#define CONFIG_TYPE_LONG    3
#define CONFIG_TYPE_DOUBLE  4
#define CONFIG_TYPE_BOOL    5

#define CONFIG_LINE_MAXLEN 1024

/* legal characters in a filename */
#define CONFIG_LEGAL_FILENAME_CHARACTERS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/"

typedef z_stream z_compression;
typedef z_stream z_decompression;

struct config_line {
  char *key;
  char *value;
  struct config_line *next;
};

typedef uint16_t aci_t;

/* cell definition */
typedef struct { 
  aci_t aci; /* Anonymous Connection Identifier */
  unsigned char command;
  unsigned char length; /* of payload if relay cell */
  uint32_t seq; /* sequence number */

  unsigned char payload[CELL_PAYLOAD_SIZE];
} cell_t;
#define CELL_RELAY_COMMAND(c)         (*(uint8_t*)((c).payload))
#define SET_CELL_RELAY_COMMAND(c,cmd) (*(uint8_t*)((c).payload) = (cmd))
#define STREAM_ID_SIZE 7
#define SET_CELL_STREAM_ID(c,id)      memcpy((c).payload+1,(id),STREAM_ID_SIZE)

#define ZERO_STREAM "\0\0\0\0\0\0\0\0"

#define SOCKS4_REQUEST_GRANTED          90
#define SOCKS4_REQUEST_REJECT           91
#define SOCKS4_REQUEST_IDENT_FAILED     92
#define SOCKS4_REQUEST_IDENT_CONFLICT   93

/* structure of a socks client operation */
typedef struct {
   unsigned char version;     /* socks version number */
   unsigned char command;     /* command code */
   unsigned char destport[2]; /* destination port, network order */
   unsigned char destip[4];   /* destination address */
   /* userid follows, terminated by a NULL */
   /* dest host follows, terminated by a NULL */
} socks4_t;

struct connection_t { 

/* Used by all types: */

  unsigned char type;
  int state;
  int s; /* our socket */
  int poll_index;
  int marked_for_close;

  char *inbuf;
  int inbuflen;
  int inbuf_datalen;
  int inbuf_reached_eof;
  long timestamp_lastread;

  char *outbuf;
  int outbuflen; /* how many bytes are allocated for the outbuf? */
  int outbuf_flushlen; /* how much data should we try to flush from the outbuf? */
  int outbuf_datalen; /* how much data is there total on the outbuf? */
  long timestamp_lastwritten;

  long timestamp_created;

  int onions_handled_this_second;

/* used by OR and OP: */

  uint32_t bandwidth; /* connection bandwidth */
  int receiver_bucket; /* when this hits 0, stop receiving. Every second we
                        * add 'bandwidth' to this, capping it at 10*bandwidth.
                        */
  struct timeval send_timeval; /* for determining when to send the next cell */

  /* link encryption */
  crypto_cipher_env_t *f_crypto;
  crypto_cipher_env_t *b_crypto;

//  struct timeval lastsend; /* time of last transmission to the client */
//  struct timeval interval; /* transmission interval */

  uint32_t addr; /* these two uniquely identify a router. Both in host order. */
  uint16_t port;

/* used by exit and ap: */
  char stream_id[STREAM_ID_SIZE];
  struct connection_t *next_stream;
  struct crypt_path_t *cpath_layer; /* a pointer to which node in the circ this conn exits at */
  int n_receive_streamwindow;
  int p_receive_streamwindow;
  int done_sending;
  int done_receiving;
#ifdef USE_ZLIB
  char *z_outbuf;
  int z_outbuflen;
  int z_outbuf_datalen;

  z_stream *compression;
  z_stream *decompression;
#endif

/* Used by ap: */
  char socks_version; 
  char read_username;

/* Used by exit and ap: */
  char *dest_addr;
  uint16_t dest_port; /* host order */

/* Used by ap: */
  char dest_tmp[512];
  int dest_tmplen;
  
/* Used by everyone */
  char *address; /* strdup into this, because free_connection frees it */
/* Used for cell connections */
  crypto_pk_env_t *pkey; /* public RSA key for the other side */

/* Used while negotiating OR/OR connections */
  char nonce[8];
 
};

typedef struct connection_t connection_t;

#define EXIT_POLICY_ACCEPT 1
#define EXIT_POLICY_REJECT 2

struct exit_policy_t {
  char policy_type;
  char *string;
  char *address;
  char *port;

  struct exit_policy_t *next;
};

/* config stuff we know about the other ORs in the network */
typedef struct {
  char *address;
 
  uint32_t addr; /* all host order */
  uint16_t or_port;
  uint16_t op_port;
  uint16_t ap_port;
  uint16_t dir_port;
 
  crypto_pk_env_t *pkey; /* public RSA key */
 
  /* link info */
  uint32_t bandwidth;
  struct exit_policy_t *exit_policy;

  void *next;
} routerinfo_t;

struct crypt_path_t { 
  char digest2[20]; /* second SHA output for onion_layer_t.keyseed */
  char digest3[20]; /* third SHA output for onion_layer_t.keyseed */

  /* crypto environments */
  crypto_cipher_env_t *f_crypto;
  crypto_cipher_env_t *b_crypto;

  char state;
#define CPATH_STATE_CLOSED 0
#define CPATH_STATE_AWAITING_KEY 1
#define CPATH_STATE_OPEN 2
  struct crypt_path_t *next;
  struct crypt_path_t *prev; /* doubly linked list */

};

typedef struct crypt_path_t crypt_path_t;

struct relay_queue_t {
  cell_t *cell;
  crypt_path_t *layer_hint;
  struct relay_queue_t *next;
};

/* struct for a path (circuit) through the network */
typedef struct {
  uint32_t n_addr;
  uint16_t n_port;
  connection_t *p_conn;
  connection_t *n_conn; /* convention: first conn is the OR conn, if there is one */
  int n_receive_circwindow;
  int p_receive_circwindow;

  aci_t p_aci; /* connection identifiers */
  aci_t n_aci;

  struct relay_queue_t *relay_queue; /* for queueing cells at the edges */

  crypto_cipher_env_t *p_crypto; /* used only for intermediate hops */
  crypto_cipher_env_t *n_crypto;

  crypt_path_t *cpath;

  uint32_t expire; /* expiration time for the corresponding onion */
  long timestamp_created;
  char dirty; /* whether this circuit has been used yet */

  int state;

  unsigned char *onion; /* stores the onion when state is CONN_STATE_OPEN_WAIT */
  uint32_t onionlen; /* total onion length */
  uint32_t recvlen; /* length of the onion so far */

  void *next;
} circuit_t;

struct onion_queue_t {
  circuit_t *circ;
  struct relay_queue_t *relay_cells;
  struct onion_queue_t *next;
};

#define ONION_KEYSEED_LEN 16

typedef struct {
  uint8_t version; 
  uint16_t port;
  uint32_t addr;
  uint32_t expire;
  unsigned char keyseed[ONION_KEYSEED_LEN];
} onion_layer_t;
/* ugly hack XXXX */
#define ONION_KEYSEED_OFFSET 11

#define ONION_LAYER_SIZE 27
#define ONION_PADDING_SIZE (128-ONION_LAYER_SIZE)

typedef struct {
   char *LogLevel;
   char *RouterFile;
   char *PrivateKeyFile;
   double CoinWeight;
   int Daemon;
   int ORPort;
   int OPPort;
   int APPort;
   int DirPort;
   int MaxConn;
   int TrafficShaping;
   int LinkPadding;
   int DirRebuildPeriod;
   int DirFetchPeriod;
   int KeepalivePeriod;
   int MaxOnionsPending;
   int NewCircuitPeriod;
   int Role;
   int loglevel;
} or_options_t;

    /* all the function prototypes go here */

/********************************* buffers.c ***************************/

int buf_new(char **buf, int *buflen, int *buf_datalen);

void buf_free(char *buf);

int read_to_buf(int s, int at_most, char **buf, int *buflen, int *buf_datalen, int *reached_eof);
  /* grab from s, put onto buf, return how many bytes read */

int flush_buf(int s, char **buf, int *buflen, int *buf_flushlen, int *buf_datalen);
  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain on the buf */

int write_to_buf(char *string, int string_len,
                 char **buf, int *buflen, int *buf_datalen);
  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */


int fetch_from_buf(char *string, int string_len,
                   char **buf, int *buflen, int *buf_datalen);
  /* if there is string_len bytes in buf, write them onto string,
   * then memmove buf back (that is, remove them from buf)
   */

z_compression* compression_new();
z_decompression* decompression_new();
void compression_free(z_compression *);
void decompression_free(z_decompression *);

int compress_from_buf(char *string, int string_len, 
                      char **buf_in, int *buflen_in, int *buf_datalen_in,
                      z_compression *compression, int flush);
  /* read and compress as many characters as possible from buf, writing up to
   * string_len of them onto string, then memmove buf back.  Return number of
   * characters written.
   */

int decompress_buf_to_buf(char **buf_in, int *buflen_in, int *buf_datalen_in,
                          char **buf_out, int *buflen_out, int *buf_datalen_out,
                          z_decompression *decompression, int flush);
  /* XXX document this NM
   */

int find_on_inbuf(char *string, int string_len,
                  char *buf, int buf_datalen);
  /* find first instance of needle 'string' on haystack 'buf'. return how
   * many bytes from the beginning of buf to the end of string.
   * If it's not there, return -1.
   */

/********************************* cell.c ***************************/

int pack_create(uint16_t aci, unsigned char *onion, uint32_t onionlen, unsigned char **cellbuf, unsigned int *cellbuflen);

/********************************* circuit.c ***************************/

void circuit_add(circuit_t *circ);
void circuit_remove(circuit_t *circ);

circuit_t *circuit_new(aci_t p_aci, connection_t *p_conn);

/* internal */
aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type);

circuit_t *circuit_get_by_aci_conn(aci_t aci, connection_t *conn);
circuit_t *circuit_get_by_conn(connection_t *conn);
circuit_t *circuit_get_newest_ap(void);
circuit_t *circuit_enumerate_by_naddr_nport(circuit_t *start, uint32_t naddr, uint16_t nport);

int circuit_deliver_relay_cell_from_edge(cell_t *cell, circuit_t *circ,
                                         char edge_type, crypt_path_t *layer_hint);
int circuit_deliver_relay_cell(cell_t *cell, circuit_t *circ,
                               int cell_direction, crypt_path_t *layer_hint);
int relay_crypt(circuit_t *circ, char *in, int inlen, char cell_direction,
                crypt_path_t *layer_hint, char *recognized, connection_t **conn);
int relay_check_recognized(circuit_t *circ, int cell_direction, char *stream, connection_t **conn);

void circuit_resume_edge_reading(circuit_t *circ, int edge_type);
int circuit_consider_stop_edge_reading(circuit_t *circ, int edge_type);
int circuit_consider_sending_sendme(circuit_t *circ, int edge_type);

int circuit_init(circuit_t *circ, int aci_type, onion_layer_t *layer);
void circuit_free(circuit_t *circ);
void circuit_free_cpath(crypt_path_t *cpath);
void circuit_free_cpath_node(crypt_path_t *victim);

void circuit_close(circuit_t *circ);

void circuit_about_to_close_connection(connection_t *conn);
  /* flush and send destroys for all circuits using conn */

void circuit_dump_by_conn(connection_t *conn);

void circuit_expire_unused_circuits(void);
void circuit_launch_new(int failure_status);
int circuit_create_onion(void);
int circuit_establish_circuit(unsigned int *route, int routelen, char *onion,
                                   int onionlen, crypt_path_t *cpath);
void circuit_n_conn_open(connection_t *or_conn);
int circuit_send_onion(connection_t *or_conn, circuit_t *circ);

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, connection_t *conn);

void command_process_create_cell(cell_t *cell, connection_t *conn);
void command_process_sendme_cell(cell_t *cell, connection_t *conn);
void command_process_relay_cell(cell_t *cell, connection_t *conn);
void command_process_destroy_cell(cell_t *cell, connection_t *conn);
void command_process_connected_cell(cell_t *cell, connection_t *conn);

/********************************* config.c ***************************/

const char *basename(const char *filename);

/* open configuration file for reading */
FILE *config_open(const unsigned char *filename);

/* close configuration file */
int config_close(FILE *f);

struct config_line *config_get_commandlines(int argc, char **argv);

/* parse the config file and strdup into key/value strings. Return list.
 *  *  * Warn and ignore mangled lines. */
struct config_line *config_get_lines(FILE *f);

void config_free_lines(struct config_line *front);

int config_compare(struct config_line *c, char *key, int type, void *arg);

void config_assign(or_options_t *options, struct config_line *list);

/* return 0 if success, <0 if failure. */
int getconfig(int argc, char **argv, or_options_t *options);

/********************************* connection.c ***************************/

int tv_cmp(struct timeval *a, struct timeval *b);

connection_t *connection_new(int type);

void connection_free(connection_t *conn);

int connection_create_listener(struct sockaddr_in *bindaddr, int type);

int connection_handle_listener_read(connection_t *conn, int new_type, int new_state);

/* start all connections that should be up but aren't */
int retry_all_connections(uint16_t or_listenport,
  uint16_t op_listenport, uint16_t ap_listenport, uint16_t dir_listenport);

int connection_read_to_buf(connection_t *conn);

int connection_fetch_from_buf(char *string, int len, connection_t *conn);

#ifdef USE_ZLIB
int connection_compress_from_buf(char *string, int len, connection_t *conn,
                                 int flush);
int connection_decompress_to_buf(char *string, int len, connection_t *conn,
                                 int flush);
#endif

int connection_outbuf_too_full(connection_t *conn);
int connection_find_on_inbuf(char *string, int len, connection_t *conn);
int connection_wants_to_flush(connection_t *conn);
int connection_flush_buf(connection_t *conn);

int connection_write_to_buf(char *string, int len, connection_t *conn);
void connection_send_cell(connection_t *conn);

int connection_receiver_bucket_should_increase(connection_t *conn);
void connection_increment_receiver_bucket (connection_t *conn);

void connection_increment_send_timeval(connection_t *conn);
void connection_init_timeval(connection_t *conn);

int connection_speaks_cells(connection_t *conn);
int connection_is_listener(connection_t *conn);
int connection_state_is_open(connection_t *conn);

int connection_send_destroy(aci_t aci, connection_t *conn);
int connection_send_connected(aci_t aci, connection_t *conn);
int connection_encrypt_cell(char *cellp, connection_t *conn);
int connection_write_cell_to_buf(const cell_t *cellp, connection_t *conn);

int connection_process_inbuf(connection_t *conn);
int connection_package_raw_inbuf(connection_t *conn);
int connection_process_cell_from_inbuf(connection_t *conn);

int connection_consider_sending_sendme(connection_t *conn, int edge_type);
int connection_finished_flushing(connection_t *conn);

void cell_pack(char *dest, const cell_t *src);
void cell_unpack(cell_t *dest, const char *src);

/********************************* connection_ap.c ****************************/

int ap_handshake_process_socks(connection_t *conn);

int ap_handshake_send_begin(connection_t *ap_conn, circuit_t *circ);

int ap_handshake_socks_reply(connection_t *conn, char result);

int connection_ap_create_listener(struct sockaddr_in *bindaddr);

int connection_ap_handle_listener_read(connection_t *conn);

/********************************* connection_edge.c ***************************/

int connection_edge_process_inbuf(connection_t *conn);
int connection_edge_send_command(connection_t *conn, circuit_t *circ, int relay_command);
int connection_edge_process_relay_cell(cell_t *cell, circuit_t *circ, connection_t *conn, int edge_type);
int connection_edge_finished_flushing(connection_t *conn);

/********************************* connection_exit.c ***************************/

int connection_exit_send_connected(connection_t *conn);
int connection_exit_begin_conn(cell_t *cell, circuit_t *circ);

int connection_exit_connect(connection_t *conn);

/********************************* connection_op.c ***************************/

int op_handshake_process_keys(connection_t *conn);

int connection_op_process_inbuf(connection_t *conn);

int connection_op_finished_flushing(connection_t *conn);

int connection_op_create_listener(struct sockaddr_in *bindaddr);

int connection_op_handle_listener_read(connection_t *conn);

/********************************* connection_or.c ***************************/

int connection_or_process_inbuf(connection_t *conn);
int connection_or_finished_flushing(connection_t *conn);

void connection_or_set_open(connection_t *conn);
void conn_or_init_crypto(connection_t *conn);

int or_handshake_op_send_keys(connection_t *conn);
int or_handshake_op_finished_sending_keys(connection_t *conn);

int or_handshake_client_process_auth(connection_t *conn);
int or_handshake_client_send_auth(connection_t *conn);

int or_handshake_server_process_auth(connection_t *conn);
int or_handshake_server_process_nonce(connection_t *conn);

connection_t *connect_to_router_as_or(routerinfo_t *router);
connection_t *connection_or_connect_as_or(routerinfo_t *router);
connection_t *connection_or_connect_as_op(routerinfo_t *router);

int connection_or_create_listener(struct sockaddr_in *bindaddr);
int connection_or_handle_listener_read(connection_t *conn);

/********************************* directory.c ***************************/

void directory_initiate_fetch(routerinfo_t *router);
int directory_send_command(connection_t *conn);
void directory_set_dirty(void);
void directory_rebuild(void);
int connection_dir_process_inbuf(connection_t *conn);
int directory_handle_command(connection_t *conn);
int directory_handle_reading(connection_t *conn);
int connection_dir_finished_flushing(connection_t *conn);
int connection_dir_create_listener(struct sockaddr_in *bindaddr);
int connection_dir_handle_listener_read(connection_t *conn);

/********************************* dns.c ***************************/

int connection_dns_finished_flushing(connection_t *conn);
int connection_dns_process_inbuf(connection_t *conn);
void init_cache_tree(void);
int dns_resolve(connection_t *exitconn);
int dns_master_start(void);

/********************************* main.c ***************************/

void setprivatekey(crypto_pk_env_t *k);
crypto_pk_env_t *getprivatekey(void);
int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_set_poll_socket(connection_t *conn);

connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port);
connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port);

connection_t *connection_get_by_type(int type);

void connection_watch_events(connection_t *conn, short events);
void connection_stop_reading(connection_t *conn);
void connection_start_reading(connection_t *conn);
void connection_stop_writing(connection_t *conn);
void connection_start_writing(connection_t *conn);

void check_conn_read(int i);
void check_conn_marked(int i);
void check_conn_write(int i);

int prepare_for_poll(int *timeout);

int do_main_loop(void);

void dumpstats(void);
void dump_directory_to_string(char *s, int maxlen);

int main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port);

int onion_pending_add(circuit_t *circ);
int onion_pending_check(void);
void onion_pending_process_one(void);
void onion_pending_remove(circuit_t *circ);
struct relay_queue_t *relay_queue_add(struct relay_queue_t *list, cell_t *cell, crypt_path_t *layer_hint);
void onion_pending_relay_add(circuit_t *circ, cell_t *cell);

/* uses a weighted coin with weight cw to choose a route length */
int chooselen(double cw);

/* returns an array of pointers to routent that define a new route through the OR network
 * int cw is the coin weight to use when choosing the route 
 * order of routers is from last to first
 */
unsigned int *new_route(double cw, routerinfo_t **rarray, int rarray_len, int *routelen);

/* creates a new onion from route, stores it and its length into bufp and lenp respectively */
unsigned char *create_onion(routerinfo_t **rarray, int rarray_len, unsigned int *route, int routelen, int *len, crypt_path_t **cpath);

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
int encrypt_onion(unsigned char *onion, uint32_t onionlen, crypto_pk_env_t *pkey, char *keyseed);

/* decrypts the first 128 bytes using RSA and prkey, decrypts the rest with DES OFB with key1. Writes the first layer into 'layer' */
int decrypt_onion(unsigned char *onion, uint32_t onionlen, crypto_pk_env_t *prkey, onion_layer_t *layer);

/* delete first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, int n);

void init_tracked_tree(void);

void onion_pack(char *dest, onion_layer_t *src);
void onion_unpack(onion_layer_t *dest, char *src);

/********************************* routers.c ***************************/

int learn_my_address(struct sockaddr_in *me);
void router_retry_connections(void);
routerinfo_t *router_pick_directory_server(void);
routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port);
unsigned int *router_new_route(int *routelen);
unsigned char *router_create_onion(unsigned int *route, int routelen, int *len, crypt_path_t **cpath);
int router_is_me(uint32_t addr, uint16_t port);
routerinfo_t *router_get_first_in_route(unsigned int *route, int routelen);
void router_forget_router(uint32_t addr, uint16_t port);
int router_get_list_from_file(char *routerfile);
int router_get_list_from_string(char *s);

int router_compare_to_exit_policy(connection_t *conn);

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
