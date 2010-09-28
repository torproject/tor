/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file microdesc.h
 * \brief Header file for microdesc.c.
 **/

#ifndef _TOR_NODELIST_H
#define _TOR_NODELIST_H

node_t *node_get_by_id(const char *identity_digest);
node_t *nodelist_add_routerinfo(routerinfo_t *ri);
node_t *nodelist_add_microdesc(microdesc_t *md);
void nodelist_set_consensus(networkstatus_t *ns);

void nodelist_remove_microdesc(const char *identity_digest, microdesc_t *md);
void nodelist_remove_routerinfo(routerinfo_t *ri);
void nodelist_purge(void);

void nodelist_free_all(void);
void nodelist_assert_ok(void);

#endif

