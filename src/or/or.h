/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __OR_H
#define __OR_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../common/config.h"
#include "../common/key.h"
#include "../common/log.h"
#include "../common/ss.h"
#include "../common/version.h"

#define MAXCONNECTIONS 200 /* upper bound on max connections.
			      can be overridden by config file */

#define MAX_BUF_SIZE (640*1024)
#define DEFAULT_BANDWIDTH_OP 1024

#define ACI_TYPE_LOWER 0
#define ACI_TYPE_HIGHER 1
#define ACI_TYPE_BOTH 2

/* bitvector of the roles that we might want to play. You can or (|) them together */
#define ROLE_OR_LISTEN 1
#define ROLE_OR_CONNECT_ALL 2
#define ROLE_OP_LISTEN 4
#define ROLE_AP_LISTEN 8

#define CONN_TYPE_OP_LISTENER 1
#define CONN_TYPE_OP 2
#define CONN_TYPE_OR_LISTENER 3
#define CONN_TYPE_OR 4
#define CONN_TYPE_EXIT 5
#define CONN_TYPE_AP_LISTENER 6
#define CONN_TYPE_AP 7

#define LISTENER_STATE_READY 0

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

#define EXIT_CONN_STATE_CONNECTING_WAIT 0 /* waiting for standard structure or dest info */
#define EXIT_CONN_STATE_CONNECTING 1
#define EXIT_CONN_STATE_OPEN 2
#if 0
#define EXIT_CONN_STATE_CLOSE 3 /* flushing the buffer, then will close */
#define EXIT_CONN_STATE_CLOSE_WAIT 4 /* have sent a destroy, awaiting a confirmation */
#endif

#define AP_CONN_STATE_SS_WAIT 0
#define AP_CONN_STATE_OR_WAIT 1
#define AP_CONN_STATE_OPEN 2

#define CIRCUIT_STATE_OPEN_WAIT 0 /* receiving/processing the onion */
#define CIRCUIT_STATE_OR_WAIT 1 /* I'm at the beginning of the path, my firsthop is still connecting */
#define CIRCUIT_STATE_OPEN 2 /* onion processed, ready to send data along the connection */
#define CIRCUIT_STATE_CLOSE_WAIT1 3 /* sent two "destroy" signals, waiting for acks */
#define CIRCUIT_STATE_CLOSE_WAIT2 4 /* received one ack, waiting for one more 
				       (or if just one was sent, waiting for that one */
//#define CIRCUIT_STATE_CLOSE 4 /* both acks received, connection is dead */ /* NOT USED */

/* available cipher functions */
#define ONION_CIPHER_IDENTITY 0
#define ONION_CIPHER_DES 1
#define ONION_CIPHER_RC4 2

/* default cipher function */
#define ONION_DEFAULT_CIPHER ONION_CIPHER_DES

#define RECEIVE_WINDOW_START 100
#define RECEIVE_WINDOW_INCREMENT 10

/* cell commands */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_DATA 2
#define CELL_DESTROY 3
#define CELL_ACK 4
#define CELL_NACK 5
#define CELL_SENDME 6

#define CELL_PAYLOAD_SIZE 120

typedef uint16_t aci_t;

/* cell definition */
typedef struct
{ 
  aci_t aci; /* Anonymous Connection Identifier */
  unsigned char command;
  unsigned char length; /* of payload if data cell, else value of sendme */
  uint32_t seq; /* sequence number */
  unsigned char payload[120];
} cell_t;

typedef struct
{ 

/* Used by all types: */

  unsigned char type;
  int state;
  int s; /* our socket */
  int poll_index;
  int marked_for_close;

  char *inbuf;
  size_t inbuflen;
  size_t inbuf_datalen;
  int inbuf_reached_eof;

  char *outbuf;
  size_t outbuflen; /* how many bytes are allocated for the outbuf? */
  size_t outbuf_flushlen; /* how much data should we try to flush from the outbuf? */
  size_t outbuf_datalen; /* how much data is there total on the outbuf? */

//  uint16_t aci; /* anonymous connection identifier */

/* used by OR and OP: */

  uint32_t bandwidth; /* connection bandwidth */
  int receiver_bucket; /* when this hits 0, stop receiving. Every second we
		       	* add 'bandwidth' to this, capping it at 10*bandwidth.
		       	*/
  struct timeval send_timeval; /* for determining when to send the next cell */

  /* link encryption */
  unsigned char f_session_key[8];
  unsigned char b_session_key[8];
  unsigned char f_session_iv[8];
  unsigned char b_session_iv[8];
  EVP_CIPHER_CTX f_ctx;
  EVP_CIPHER_CTX b_ctx;

//  struct timeval lastsend; /* time of last transmission to the client */
//  struct timeval interval; /* transmission interval */

  uint32_t addr; /* these two uniquely identify a router */
  uint16_t port;

/* used by exit and ap: */

  ss_t ss; /* standard structure */
  int ss_received; /* size of ss, received so far */

  char *dest_addr, *dest_port;
  uint16_t dest_addr_len, dest_port_len;
  uint16_t dest_addr_received, dest_port_received;
  
/* used by OR, to keep state while connect()ing: Kludge. */

  RSA *prkey;
  struct sockaddr_in local;

#if 0 /* obsolete, we now use conn->bandwidth */
  /* link info */
  uint32_t min;
  uint32_t max;
#endif

  char *address; /* strdup into this, because free_connection frees it */
  RSA *pkey; /* public RSA key for the other side */

  char nonce[8];
 
} connection_t;

/* config stuff we know about the other ORs in the network */
typedef struct
{
  char *address;
 
  uint32_t addr;
  uint16_t or_port;
  uint16_t op_port;
  uint16_t ap_port;
 
  RSA *pkey; /* public RSA key */
 
  /* link info */
  uint32_t min;
  uint32_t max;
//  struct timeval  min_interval;
 
  /* time when last data was sent to that router */
//  struct timeval lastsend;
 
  /* socket */
//  int s;

  void *next;
} routerinfo_t;

typedef struct
{ 
  unsigned int forwf;
  unsigned int backf;
  char digest2[20]; /* second SHA output for onion_layer_t.keyseed */
  char digest3[20]; /* third SHA output for onion_layer_t.keyseed */

  /* IVs */
  char f_iv[16];
  char b_iv[16];

  /* cipher contexts */
  EVP_CIPHER_CTX f_ctx;
  EVP_CIPHER_CTX b_ctx;
  
} crypt_path_t;

/* per-anonymous-connection struct */
typedef struct
{
#if 0
  uint32_t p_addr; /* all in network order */
  uint16_t p_port;
#endif
  uint32_t n_addr;
  uint16_t n_port;
  connection_t *p_conn;
  connection_t *n_conn;
  int n_receive_window;
  int p_receive_window;

  aci_t p_aci; /* connection identifiers */
  aci_t n_aci;

  unsigned char p_f; /* crypto functions */
  unsigned char n_f;

  unsigned char p_key[16]; /* crypto keys */
  unsigned char n_key[16];

  unsigned char p_iv[16]; /* initialization vectors */
  unsigned char n_iv[16];

  EVP_CIPHER_CTX p_ctx; /* cipher context */
  EVP_CIPHER_CTX n_ctx;

  crypt_path_t **cpath;
  size_t cpathlen; 

  uint32_t expire; /* expiration time for the corresponding onion */

  int state;

  unsigned char *onion; /* stores the onion when state is CONN_STATE_OPEN_WAIT */
  uint32_t onionlen; /* total onion length */
  uint32_t recvlen; /* length of the onion so far */

  void *next;
} circuit_t;

typedef struct
{ 
  int zero:1;
  int version:7;
  int backf:4;
  int forwf:4;
  uint16_t port;
  uint32_t addr;
  time_t expire;
  unsigned char keyseed[16];
} onion_layer_t;

typedef struct
{ 
  time_t expire;
  char digest[20]; /* SHA digest of the onion */
  void *prev;
  void *next;
} tracked_onion_t;

typedef struct
{
   char *LogLevel;
   char *RouterFile;
   char *PrivateKeyFile;
   float CoinWeight;
   int ORPort;
   int OPPort;
   int APPort;
   int MaxConn;
   int TrafficShaping;
   int LinkPadding;
   int Role;
   int loglevel;
} or_options_t;


    /* all the function prototypes go here */


/********************************* buffers.c ***************************/

int buf_new(char **buf, size_t *buflen, size_t *buf_datalen);

void buf_free(char *buf);

int read_to_buf(int s, int at_most, char **buf, size_t *buflen, size_t *buf_datalen, int *reached_eof);
  /* grab from s, put onto buf, return how many bytes read */

int flush_buf(int s, char **buf, size_t *buflen, size_t *buf_flushlen, size_t *buf_datalen);
  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain on the buf */

int write_to_buf(char *string, size_t string_len,
                 char **buf, size_t *buflen, size_t *buf_datalen);
  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

int fetch_from_buf(char *string, size_t string_len,
		                 char **buf, size_t *buflen, size_t *buf_datalen);
	  /* if there is string_len bytes in buf, write them onto string,
	  *    * then memmove buf back (that is, remove them from buf) */

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
circuit_t *circuit_get_by_naddr_nport(uint32_t naddr, uint16_t nport);

int circuit_deliver_data_cell(cell_t *cell, circuit_t *circ, connection_t *conn, int crypt_type);
int circuit_crypt(circuit_t *circ, char *in, size_t inlen, char crypt_type);

int circuit_init(circuit_t *circ, int aci_type);
void circuit_free(circuit_t *circ);
void circuit_free_cpath(crypt_path_t **cpath, size_t cpathlen);

void circuit_close(circuit_t *circ);

void circuit_about_to_close_connection(connection_t *conn);
  /* flush and send destroys for all circuits using conn */

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, connection_t *conn);

void command_process_create_cell(cell_t *cell, connection_t *conn);
void command_process_sendme_cell(cell_t *cell, connection_t *conn);
void command_process_data_cell(cell_t *cell, connection_t *conn);
void command_process_destroy_cell(cell_t *cell, connection_t *conn);

/********************************* config.c ***************************/

/* loads the configuration file */
int getconfig(char *filename, config_opt_t *options);

/* create or_options_t from command-line args and config files(s) */
int getoptions(int argc, char **argv, or_options_t *options);

/********************************* connection.c ***************************/

int tv_cmp(struct timeval *a, struct timeval *b);

connection_t *connection_new(int type);

void connection_free(connection_t *conn);

int connection_create_listener(RSA *prkey, struct sockaddr_in *local, int type);

int connection_handle_listener_read(connection_t *conn, int new_type, int new_state);

/* start all connections that should be up but aren't */
int retry_all_connections(int role, routerinfo_t **router_array, int rarray_len,
		  RSA *prkey, uint16_t or_port, uint16_t op_port, uint16_t ap_port);
connection_t *connection_connect_to_router_as_op(routerinfo_t *router, RSA *prkey, uint16_t local_or_port);

int connection_read_to_buf(connection_t *conn);

int connection_fetch_from_buf(char *string, int len, connection_t *conn);

int connection_outbuf_too_full(connection_t *conn);
int connection_wants_to_flush(connection_t *conn);
int connection_flush_buf(connection_t *conn);

int connection_write_to_buf(char *string, int len, connection_t *conn);
void connection_send_cell(connection_t *conn);

int connection_receiver_bucket_should_increase(connection_t *conn);
void connection_increment_receiver_bucket (connection_t *conn);

void connection_increment_send_timeval(connection_t *conn);
void connection_init_timeval(connection_t *conn);

int connection_speaks_cells(connection_t *conn);
int connection_state_is_open(connection_t *conn);

int connection_send_destroy(aci_t aci, connection_t *conn);
int connection_encrypt_cell_header(cell_t *cellp, connection_t *conn);
int connection_write_cell_to_buf(cell_t *cellp, connection_t *conn);

int connection_process_inbuf(connection_t *conn);
int connection_package_raw_inbuf(connection_t *conn);
int connection_process_cell_from_inbuf(connection_t *conn);

int connection_consider_sending_sendme(connection_t *conn);
int connection_finished_flushing(connection_t *conn);

/********************************* connection_ap.c ****************************/

int connection_ap_process_inbuf(connection_t *conn);

int ap_handshake_process_ss(connection_t *conn);

int ap_handshake_create_onion(connection_t *conn);

int ap_handshake_establish_circuit(connection_t *conn, unsigned int *route, int routelen, char *onion,
		                                   int onionlen, crypt_path_t **cpath);

/* find the circ that's waiting on me, if any, and get it to send its onion */
int ap_handshake_n_conn_open(connection_t *or_conn);

int ap_handshake_send_onion(connection_t *ap_conn, connection_t *or_conn, circuit_t *circ);

int connection_ap_process_data_cell(cell_t *cell, connection_t *conn);

int connection_ap_finished_flushing(connection_t *conn);

int connection_ap_create_listener(RSA *prkey, struct sockaddr_in *local);

int connection_ap_handle_listener_read(connection_t *conn);

/********************************* connection_exit.c ***************************/

int connection_exit_process_inbuf(connection_t *conn);
int connection_exit_package_inbuf(connection_t *conn);
int connection_exit_process_data_cell(cell_t *cell, connection_t *conn);

int connection_exit_finished_flushing(connection_t *conn);


/********************************* connection_op.c ***************************/

int op_handshake_process_keys(connection_t *conn);

int connection_op_process_inbuf(connection_t *conn);

int connection_op_finished_flushing(connection_t *conn);

int connection_op_create_listener(RSA *prkey, struct sockaddr_in *local);

int connection_op_handle_listener_read(connection_t *conn);

/********************************* connection_or.c ***************************/

int connection_or_process_inbuf(connection_t *conn);
int connection_or_finished_flushing(connection_t *conn);

void conn_or_init_crypto(connection_t *conn);

int or_handshake_op_send_keys(connection_t *conn);
int or_handshake_op_finished_sending_keys(connection_t *conn);

int or_handshake_client_process_auth(connection_t *conn);
int or_handshake_client_send_auth(connection_t *conn);

int or_handshake_server_process_auth(connection_t *conn);
int or_handshake_server_process_nonce(connection_t *conn);

connection_t *connect_to_router_as_or(routerinfo_t *router, RSA *prkey, struct sockaddr_in *local);
connection_t *connection_or_connect_as_or(routerinfo_t *router, RSA *prkey, struct sockaddr_in *local);
connection_t *connection_or_connect_as_op(routerinfo_t *router, RSA *prkey, struct sockaddr_in *local);

int connection_or_create_listener(RSA *prkey, struct sockaddr_in *local);
int connection_or_handle_listener_read(connection_t *conn);

/********************************* main.c ***************************/

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_set_poll_socket(connection_t *conn);

int pkey_cmp(RSA *a, RSA *b);
connection_t *connection_twin_get_by_addr_port(uint32_t addr, uint16_t port);
connection_t *connection_exact_get_by_addr_port(uint32_t addr, uint16_t port);

connection_t *connection_get_by_type(int type);

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port);
unsigned int *router_new_route(size_t *rlen);
unsigned char *router_create_onion(unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp);
routerinfo_t *router_get_first_in_route(unsigned int *route, size_t routelen);
connection_t *connect_to_router_as_op(routerinfo_t *router);

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

int main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port);

int process_onion(circuit_t *circ, connection_t *conn);

/* uses a weighted coin with weight cw to choose a route length */
int chooselen(double cw);

/* returns an array of pointers to routent that define a new route through the OR network
 * int cw is the coin weight to use when choosing the route 
 * order of routers is from last to first
 */
unsigned int *new_route(double cw, routerinfo_t **rarray, size_t rarray_len, size_t *rlen);

/* creates a new onion from route, stores it and its length into bufp and lenp respectively */
unsigned char *create_onion(routerinfo_t **rarray, size_t rarray_len, unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp);

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
unsigned char *encrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *pkey);

/* decrypts the first 128 bytes using RSA and prkey, decrypts the rest with DES OFB with key1 */
unsigned char *decrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *prkey);

/* delete first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, size_t n);

/* create a new tracked_onion entry */
tracked_onion_t *new_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion);

/* delete a tracked onion entry */
void remove_tracked_onion(tracked_onion_t *to, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion);

/* find a tracked onion in the linked list of tracked onions */
tracked_onion_t *id_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t *tracked_onions);

/********************************* routers.c ***************************/

routerinfo_t **getrouters(char *routerfile, size_t *listlenp, uint16_t or_listenport);
void delete_routerlist(routerinfo_t *list);
/* create an NULL-terminated array of pointers pointing to elements of a router list */
routerinfo_t **make_rarray(routerinfo_t* list, size_t *listlenp);


#endif
