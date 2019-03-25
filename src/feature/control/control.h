/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control.h
 * \brief Header file for control.c.
 **/

#ifndef TOR_CONTROL_H
#define TOR_CONTROL_H

control_connection_t *TO_CONTROL_CONN(connection_t *);

#define CONTROL_CONN_STATE_MIN_ 1
/** State for a control connection: Authenticated and accepting v1 commands. */
#define CONTROL_CONN_STATE_OPEN 1
/** State for a control connection: Waiting for authentication; speaking
 * protocol v1. */
#define CONTROL_CONN_STATE_NEEDAUTH 2
#define CONTROL_CONN_STATE_MAX_ 2

void control_ports_write_to_file(void);

/** Log information about the connection <b>conn</b>, protecting it as with
 * CONN_LOG_PROTECT. Example:
 *
 * LOG_FN_CONN(conn, (LOG_DEBUG, "Socket %d wants to write", conn->s));
 **/
#define LOG_FN_CONN(conn, args)                 \
  CONN_LOG_PROTECT(conn, log_fn args)

#define CC_LOCAL_FD_IS_OWNER (1u<<0)
#define CC_LOCAL_FD_IS_AUTHENTICATED (1u<<1)
int control_connection_add_local_fd(tor_socket_t sock, unsigned flags);

int connection_control_finished_flushing(control_connection_t *conn);
int connection_control_reached_eof(control_connection_t *conn);
void connection_control_closed(control_connection_t *conn);

int connection_control_process_inbuf(control_connection_t *conn);

int init_control_cookie_authentication(int enabled);
char *get_controller_cookie_file_name(void);
struct config_line_t;
smartlist_t *decode_hashed_passwords(struct config_line_t *passwords);
void disable_control_logging(void);
void enable_control_logging(void);

void monitor_owning_controller_process(const char *process_spec);

const char *rend_auth_type_to_string(rend_auth_type_t auth_type);
MOCK_DECL(const char *, node_describe_longname_by_id,(const char *id_digest));
void control_free_all(void);

#ifdef CONTROL_PRIVATE
#include "lib/crypt_ops/crypto_ed25519.h"

/* ADD_ONION secret key to create an ephemeral service. The command supports
 * multiple versions so this union stores the key and passes it to the HS
 * subsystem depending on the requested version. */
typedef union add_onion_secret_key_t {
  /* Hidden service v2 secret key. */
  crypto_pk_t *v2;
  /* Hidden service v3 secret key. */
  ed25519_secret_key_t *v3;
} add_onion_secret_key_t;

STATIC int add_onion_helper_keyarg(const char *arg, int discard_pk,
                                   const char **key_new_alg_out,
                                   char **key_new_blob_out,
                                   add_onion_secret_key_t *decoded_key,
                                   int *hs_version, char **err_msg_out);

STATIC rend_authorized_client_t *
add_onion_helper_clientauth(const char *arg, int *created, char **err_msg_out);

#endif /* defined(CONTROL_PRIVATE) */

#ifdef CONTROL_MODULE_PRIVATE
struct signal_name_t {
  int sig;
  const char *signal_name;
};
extern const struct signal_name_t signal_table[];

int get_cached_network_liveness(void);
void set_cached_network_liveness(int liveness);
smartlist_t * get_detached_onion_services(void);
#endif /* defined(CONTROL_MODULE_PRIVATE) */

#endif /* !defined(TOR_CONTROL_H) */
