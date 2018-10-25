/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_DISPATCH_MSG_IMPL_H
#define TOR_DISPATCH_MSG_IMPL_H

#include "lib/dispatch/msgtypes.h"

/* ============================================================
 * These functions are used by the macros in msg.h
 * ============================================================
 */

/**
 * Return an existing channel ID by name, allocating the channel ID if
 * if necessary.  Returns ERROR_ID if we have run out of
 * channels
 */
channel_id_t get_channel_id(const char *);
/**
 * Return the name corresponding to a given channel ID.
 **/
const char *get_channel_id_name(channel_id_t);

/* As above, but for messages. */
message_id_t get_message_id(const char *);
const char *get_message_id_name(message_id_t);

/* As above, but for subsystems */
subsys_id_t get_subsys_id(const char *);
const char *get_subsys_id_name(subsys_id_t);

/* As above, but for types. Note that types additionally must be
 * "defined", if any message is to use them. */
msg_type_id_t get_msg_type_id(const char *);
const char *get_msg_type_id_name(msg_type_id_t);

int dispatch_pub_(const pub_binding_t *pub, msg_aux_data_t auxdata);

int dispatch_add_pub_(dispatch_connector_t *con,
                      pub_binding_t *out,
                      channel_id_t channel,
                      message_id_t msg,
                      msg_type_id_t type,
                      unsigned flags,
                      const char *file,
                      unsigned line);

int dispatch_add_sub_(dispatch_connector_t *con,
                      recv_fn_t recv_fn,
                      channel_id_t channel,
                      message_id_t msg,
                      msg_type_id_t type,
                      unsigned flags,
                      const char *file,
                      unsigned line);

int dispatch_connector_define_type_(dispatch_connector_t *,
                                    msg_type_id_t,
                                    dispatch_typefns_t *,
                                    const char *file,
                                    unsigned line);

#endif
