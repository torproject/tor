/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file control_hs.c
 *
 * \brief Implement commands for Tor's control-socket interface that are
 *        related to onion services.
 **/

#include "core/or/or.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_hs.h"
#include "feature/control/control_proto.h"
#include "feature/hs/hs_client.h"
#include "lib/encoding/confline.h"

#include "feature/control/control_cmd_args_st.h"

/** Parse the 'KeyType ":" PrivateKey' from <b>client_privkey_str</b> and store
 *  it into <b>privkey</b>. Use <b>conn</b> to output any errors if needed.
 *
 *  Return 0 if all went well, -1 otherwise. */
static int
parse_private_key_from_control_port(const char *client_privkey_str,
                                    curve25519_secret_key_t *privkey,
                                    control_connection_t *conn)
{
  int retval = -1;
  smartlist_t *key_args = smartlist_new();

  tor_assert(privkey);

  smartlist_split_string(key_args, client_privkey_str, ":",
                         SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(key_args) != 2) {
    control_printf_endreply(conn, 512, "Invalid key type/blob");
    goto err;
  }

  const char *key_type = smartlist_get(key_args, 0);
  const char *key_blob = smartlist_get(key_args, 1);

  if (strcasecmp(key_type, "x25519")) {
    control_printf_endreply(conn, 552,
                            "Unrecognized key type \"%s\"", key_type);
    goto err;
  }

  if (base64_decode((char*)privkey->secret_key, sizeof(privkey->secret_key),
                    key_blob,
                   strlen(key_blob)) != sizeof(privkey->secret_key)) {
    control_printf_endreply(conn, 512, "Failed to decode ED25519-V3 key");
    goto err;
  }

  retval = 0;

 err:
  SMARTLIST_FOREACH(key_args, char *, c, tor_free(c));
  smartlist_free(key_args);
  return retval;
}

/** Syntax details for ONION_CLIENT_AUTH_ADD */
const control_cmd_syntax_t onion_client_auth_add_syntax = {
  .max_args = 2,
  .accept_keywords = true,
};

/** Called when we get an ONION_CLIENT_AUTH_ADD command; parse the body, and
 *  register the new client-side client auth credentials:
 *  "ONION_CLIENT_AUTH_ADD" SP HSAddress
 *                          SP KeyType ":" PrivateKeyBlob
 *                          [SP "ClientName=" Nickname]
 *                          [SP "Type=" TYPE] CRLF
 */
int
handle_control_onion_client_auth_add(control_connection_t *conn,
                                     const control_cmd_args_t *args)
{
  int retval = -1;
  smartlist_t *flags = smartlist_new();
  hs_client_service_authorization_t *creds = NULL;

  tor_assert(args);

  int argc = smartlist_len(args->args);
  /* We need at least 'HSAddress' and 'PrivateKeyBlob' */
  if (argc < 2) {
    control_printf_endreply(conn, 512,
                            "Incomplete ONION_CLIENT_AUTH_ADD command");
    goto err;
  }

  creds = tor_malloc_zero(sizeof(hs_client_service_authorization_t));

  const char *hsaddress = smartlist_get(args->args, 0);
  if (!hs_address_is_valid(hsaddress)) {
    control_printf_endreply(conn, 512, "Invalid v3 address \"%s\"",hsaddress);
    goto err;
  }
  strlcpy(creds->onion_address, hsaddress, sizeof(creds->onion_address));

  /* Parse the client private key */
  const char *client_privkey = smartlist_get(args->args, 1);
  if (parse_private_key_from_control_port(client_privkey,
                                          &creds->enc_seckey, conn) < 0) {
    goto err;
  }

  /* Now let's parse the remaining arguments (variable size) */
  for (const config_line_t *line = args->kwargs; line; line = line->next) {
    if (!strcasecmp(line->key, "ClientName")) {
      /* XXX apply length restriction? */
      creds->nickname = tor_strdup(line->value);

    } else if (!strcasecmpstart(line->key, "Flags")) {
      smartlist_split_string(flags, line->value, ",", SPLIT_IGNORE_BLANK, 0);
      if (smartlist_len(flags) < 1) {
        control_write_endreply(conn, 512, "Invalid 'Flags' argument");
        goto err;
      }
      SMARTLIST_FOREACH_BEGIN(flags, const char *, flag) {
        if (!strcasecmp(flag, "Permanent")) {
          creds->flags |= CLIENT_AUTH_FLAG_IS_PERMANENT;
        } else {
          control_printf_endreply(conn, 512, "Invalid 'Flags' argument: %s",
                                  escaped(flag));
          goto err;
        }
      } SMARTLIST_FOREACH_END(flag);
    }
  }

  hs_client_register_auth_status_t register_status;
  /* Register the credential (register func takes ownership of cred.) */
  register_status = hs_client_register_auth_credentials(creds);
  if (BUG(register_status == REGISTER_FAIL_BAD_ADDRESS)) {
    /* It's a bug because the service addr has already been validated above */
    control_printf_endreply(conn, 512, "Invalid v3 address \"%s\"", hsaddress);
  } else if (register_status == REGISTER_FAIL_ALREADY_EXISTS) {
    control_printf_endreply(conn, 551, "Client already exists");
  } else if (register_status == REGISTER_SUCCESS) {
    control_printf_endreply(conn, 250, "OK");
  } else {
    tor_assert_nonfatal_unreached();
  }

  retval = 0;
  goto done;

 err:
  client_service_authorization_free(creds);

 done:
  SMARTLIST_FOREACH(flags, char *, s, tor_free(s));
  smartlist_free(flags);
  return retval;
}
