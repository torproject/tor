/* Copyright (c) 2002 Roger Dingledine.  See LICENSE for licensing information */
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
#include <sys/mman.h>
#include <sys/stat.h>
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

#include "../common/cell.h"
#include "../common/config.h"
#include "../common/key.h"
#include "../common/log.h"
#include "../common/onion.h"
#include "../common/ss.h"

#define MAXCONNECTIONS 200 /* upper bound on max connections.
			      can be overridden by config file */

#define MAX_BUF_SIZE (64*1024)

#define ACI_TYPE_LOWER 0
#define ACI_TYPE_HIGHER 1

#define CONN_TYPE_OP_LISTENER 1
#define CONN_TYPE_OP 2
#define CONN_TYPE_OR_LISTENER 3
#define CONN_TYPE_OR 4
#define CONN_TYPE_APP 5

#define LISTENER_STATE_READY 0

#define OP_CONN_STATE_AWAITING_KEYS 0
#define OP_CONN_STATE_OPEN 1
#if 0
#define OP_CONN_STATE_CLOSE 2 /* flushing the buffer, then will close */
#define OP_CONN_STATE_CLOSE_WAIT 3 /* have sent a destroy, awaiting a confirmation */
#endif

#define OR_CONN_STATE_CLIENT_CONNECTING 0
#define OR_CONN_STATE_CLIENT_SENDING_AUTH 1 /* sending address and info */
#define OR_CONN_STATE_CLIENT_AUTH_WAIT 2 /* have sent address and info, waiting */
#define OR_CONN_STATE_CLIENT_SENDING_NONCE 3 /* sending nonce, last piece of handshake */
#define OR_CONN_STATE_SERVER_AUTH_WAIT 4 /* waiting for address and info */
#define OR_CONN_STATE_SERVER_SENDING_AUTH 5 /* writing auth and nonce */
#define OR_CONN_STATE_SERVER_NONCE_WAIT 6 /* waiting for confirmation of nonce */
#define OR_CONN_STATE_OPEN 7 /* ready to send/receive cells. */

#define APP_CONN_STATE_CONNECTING_WAIT 0 /* waiting for standard structure or dest info */
#define APP_CONN_STATE_CONNECTING 1
#define APP_CONN_STATE_OPEN 2
#if 0
#define APP_CONN_STATE_CLOSE 3 /* flushing the buffer, then will close */
#define APP_CONN_STATE_CLOSE_WAIT 4 /* have sent a destroy, awaiting a confirmation */
#endif

#define CIRCUIT_STATE_OPEN_WAIT 0 /* receiving/processing the onion */
#define CIRCUIT_STATE_OPEN 1 /* onion processed, ready to send data along the connection */
#define CIRCUIT_STATE_CLOSE_WAIT1 2 /* sent two "destroy" signals, waiting for acks */
#define CIRCUIT_STATE_CLOSE_WAIT2 3 /* received one ack, waiting for one more 
				       (or if just one was sent, waiting for that one */
//#define CIRCUIT_STATE_CLOSE 4 /* both acks received, connection is dead */ /* NOT USED */

typedef uint16_t aci_t;

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
  size_t outbuflen;
  size_t outbuf_datalen;

/* used by OP and App: */

  uint16_t aci; /* anonymous connection identifier */

/* used by OR and OP: */

  uint32_t bandwidth; /* connection bandwidth */
  int window_sent; /* how many cells can i still send? */
  int window_received; /* how many cells do i still expect to receive? */

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

/* used by app: */

  ss_t ss; /* standard structure */
  int ss_received; /* size of ss, received so far */
  
/* used by OR, to keep state while connect()ing: Kludge. */

  RSA *prkey;
  struct sockaddr_in local;

   /* link info */
  uint32_t min;
  uint32_t max;

  char *address; /* strdup into this, gets free_connection frees it */
  RSA *pkey; /* public RSA key for the other side */

  char nonce[8];
 
} connection_t;

/* config stuff we know about the other ORs in the network */
typedef struct
{
  char *address;
 
  uint32_t addr;
  uint16_t port;
 
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

  aci_t p_aci; /* connection identifiers */
  aci_t n_aci;

  unsigned char p_f; /* crypto functions */
  unsigned char n_f;

  unsigned char p_key[128]; /* crypto keys */
  unsigned char n_key[128];

  unsigned char p_iv[16]; /* initialization vectors */
  unsigned char n_iv[16];

  EVP_CIPHER_CTX p_ctx; /* cipher context */
  EVP_CIPHER_CTX n_ctx;

  uint32_t expire; /* expiration time for the corresponding onion */

  int state;

  unsigned char *onion; /* stores the onion when state is CONN_STATE_OPEN_WAIT */
  uint32_t onionlen; /* total onion length */
  uint32_t recvlen; /* length of the onion so far */

  void *next;
} circuit_t;




    /* all the function prototypes go here */


/********************************* args.c ***************************/

/* print help*/
void print_usage();

/* get command-line arguments */
int getargs(int argc,char *argv[], char *args,char **conf_filename, int *loglevel);

/********************************* buffers.c ***************************/

int buf_new(char **pbuf, size_t *pbuflen, size_t *pbuf_datalen);

int buf_free(char *buf);

int read_to_buf(int s, char **pbuf, size_t *pbuflen, size_t *pbuf_datalen, int *preached_eof);
  /* grab from s, put onto buf, return how many bytes read */

int flush_buf(int s, char **pbuf, size_t *pbuflen, size_t *pbuf_datalen);
  /* push from buf onto s
   * then memmove to front of buf
   * return -1 or how many bytes remain on the buf */

int write_to_buf(char *string, size_t string_len,
                 char **pbuf, size_t *pbuflen, size_t *pbuf_datalen);
  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

int fetch_from_buf(char *string, size_t string_len,
		                 char **pbuf, size_t *pbuflen, size_t *pbuf_datalen);
	  /* if there is string_len bytes in buf, write them onto string,
	  *    * then memmove buf back (that is, remove them from buf) */

/********************************* cell.c ***************************/

int check_sane_cell(cell_t *cell);

/********************************* circuit.c ***************************/

void circuit_add(circuit_t *circ);
void circuit_remove(circuit_t *circ);

circuit_t *circuit_new(aci_t p_aci, connection_t *p_conn);

/* internal */
aci_t get_unique_aci_by_addr_port(uint32_t addr, uint16_t port, int aci_type);

circuit_t *circuit_get_by_aci_conn(aci_t aci, connection_t *conn);
circuit_t *circuit_get_by_conn(connection_t *conn);

int circuit_deliver_data_cell(cell_t *cell, circuit_t *circ, connection_t *conn, int crypt_type);
int circuit_crypt(circuit_t *circ, char *in, size_t inlen, char crypt_type);

int circuit_init(circuit_t *circ, int aci_type);
void circuit_free(circuit_t *circ);

void circuit_close(circuit_t *circ);

void circuit_about_to_close_connection(connection_t *conn);
  /* flush and send destroys for all circuits using conn */

/********************************* command.c ***************************/

void command_process_cell(cell_t *cell, connection_t *conn);

void command_process_create_cell(cell_t *cell, connection_t *conn);
void command_process_data_cell(cell_t *cell, connection_t *conn);
void command_process_destroy_cell(cell_t *cell, connection_t *conn);

/********************************* config.c ***************************/

/* loads the configuration file */
int getconfig(char *filename, config_opt_t *options);

/********************************* connection.c ***************************/

connection_t *connection_new(int type);

void connection_free(connection_t *conn);

int connection_create_listener(RSA *prkey, struct sockaddr_in *local, int type);

int connection_handle_listener_read(connection_t *conn, int new_type, int new_state);

/* start all connections that should be up but aren't */
int retry_all_connections(routerinfo_t **router_array, int rarray_len,
		  RSA *prkey, uint16_t or_port, uint16_t op_port);

int connection_read_to_buf(connection_t *conn);

int connection_fetch_from_buf(char *string, int len, connection_t *conn);

int connection_flush_buf(connection_t *conn);

int connection_write_to_buf(char *string, int len, connection_t *conn);
int connection_send_destroy(aci_t aci, connection_t *conn);
int connection_encrypt_cell_header(cell_t *cellp, connection_t *conn);
int connection_write_cell_to_buf(cell_t *cellp, connection_t *conn);

int connection_process_inbuf(connection_t *conn);
int connection_process_cell_from_inbuf(connection_t *conn);

int connection_finished_flushing(connection_t *conn);

/********************************* connection_or.c ***************************/

int connection_or_process_inbuf(connection_t *conn);
int connection_or_finished_flushing(connection_t *conn);

connection_t *connection_or_new(void);
connection_t *connection_or_listener_new(void);

void conn_or_init_crypto(connection_t *conn);

int or_handshake_client_process_auth(connection_t *conn);
int or_handshake_client_send_auth(connection_t *conn);

int or_handshake_server_process_auth(connection_t *conn);
int or_handshake_server_process_nonce(connection_t *conn);

int connect_to_router(routerinfo_t *router, RSA *prkey, struct sockaddr_in *local);

int connection_or_create_listener(RSA *prkey, struct sockaddr_in *local);
int connection_or_handle_listener_read(connection_t *conn);

/********************************* connection_op.c ***************************/

connection_t *connection_op_new(void);
connection_t *connection_op_listener_new(void);

int op_handshake_process_keys(connection_t *conn);

int connection_op_process_inbuf(connection_t *conn);

int connection_op_finished_flushing(connection_t *conn);

int connection_op_create_listener(RSA *prkey, struct sockaddr_in *local);

int connection_op_handle_listener_read(connection_t *conn);

/********************************* connection_app.c ***************************/

connection_t *connection_app_new(void);

int connection_app_process_inbuf(connection_t *conn);
int connection_app_package_inbuf(connection_t *conn);
int connection_app_process_data_cell(cell_t *cell, connection_t *conn);

int connection_app_finished_flushing(connection_t *conn);

/********************************* main.c ***************************/

int connection_add(connection_t *conn);
int connection_remove(connection_t *conn);
void connection_set_poll_socket(connection_t *conn);

connection_t *connection_get_by_addr_port(uint32_t addr, uint16_t port);

connection_t *connection_get_by_type(int type);

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port);

void connection_watch_events(connection_t *conn, short events);

void check_conn_read(int i);
void check_conn_marked(int i);
void check_conn_write(int i);

void check_conn_hup(int i);

int do_main_loop(void);

int main(int argc, char *argv[]);

/********************************* onion.c ***************************/

int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port);

int process_onion(circuit_t *circ, connection_t *conn);

/********************************* routers.c ***************************/

routerinfo_t **getrouters(char *routerfile, size_t *listlenp);
void delete_routerlist(routerinfo_t *list);
/* create an NULL-terminated array of pointers pointing to elements of a router list */
routerinfo_t **make_rarray(routerinfo_t* list, size_t *listlenp);


#endif
