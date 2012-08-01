/* * Copyright (c) 2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file channeltls.h
 * \brief Header file for channeltls.c
 **/

#ifndef _TOR_CHANNEL_TLS_H
#define _TOR_CHANNEL_TLS_H

#include "or.h"
#include "channel.h"

#define BASE_CHAN_TO_TLS(c) ((channel_tls_t *)(c))
#define TLS_CHAN_TO_BASE(c) ((channel_t *)(c))

#ifdef _TOR_CHANNEL_INTERNAL

struct channel_tls_s {
  /* Base channel_t struct */
  channel_t _base;
  /* or_connection_t pointer */
  or_connection_t *conn;
};

#endif /* _TOR_CHANNEL_INTERNAL */

channel_t * channel_tls_connect(const tor_addr_t *addr, uint16_t port,
                                const char *id_digest);
channel_t * channel_tls_get_listener(void);
channel_t * channel_tls_start_listener(void);
channel_t * channel_tls_handle_incoming(or_connection_t *orconn);

/* Things for connection_or.c to call back into */
ssize_t channel_tls_flush_some_cells(channel_tls_t *chan, ssize_t num_cells);
int channel_tls_more_to_flush(channel_tls_t *chan);
void channel_tls_handle_cell(cell_t *cell, or_connection_t *conn);
void channel_tls_handle_state_change_on_orconn(channel_tls_t *chan,
                                               or_connection_t *conn,
                                               uint8_t old_state,
                                               uint8_t state);
void channel_tls_handle_var_cell(var_cell_t *var_cell,
                                 or_connection_t *conn);

/* Cleanup at shutdown */
void channel_tls_free_all(void);

#endif

