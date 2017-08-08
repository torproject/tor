/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_BUFFERS_TLS_H
#define TOR_BUFFERS_TLS_H

struct buf_t;
struct tor_tls_t;

int read_to_buf_tls(struct tor_tls_t *tls, size_t at_most,
                    struct buf_t *buf);
int flush_buf_tls(struct tor_tls_t *tls, struct buf_t *buf, size_t sz,
                  size_t *buf_flushlen);

#endif

