/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_cmd.h
 * \brief Header file for control_cmd.c.
 **/

#ifndef TOR_CONTROL_CMD_H
#define TOR_CONTROL_CMD_H

int handle_control_command(control_connection_t *conn,
                           uint32_t cmd_data_len,
                           char *args);
void control_cmd_free_all(void);

#ifdef CONTROL_CMD_PRIVATE
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

STATIC rend_authorized_client_t *add_onion_helper_clientauth(const char *arg,
                                   int *created, char **err_msg_out);

#endif /* defined(CONTROL_CMD_PRIVATE) */

#ifdef CONTROL_MODULE_PRIVATE
smartlist_t * get_detached_onion_services(void);
#endif /* defined(CONTROL_MODULE_PRIVATE) */

#endif /* !defined(TOR_CONTROL_CMD_H) */
