/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_BUFFERS_TLS_H
#define TOR_BUFFERS_TLS_H

struct buf_t;
struct tor_tls_t;

int buf_read_from_tls(struct buf_t *buf,
                      struct tor_tls_t *tls, size_t at_most);
int buf_flush_to_tls(struct buf_t *buf, struct tor_tls_t *tls,
                     size_t sz, size_t *buf_flushlen);

#endif /* !defined(TOR_BUFFERS_TLS_H) */

