/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2007 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dirvote_c_id[] =
  "$Id$";

#include "or.h"

/**
 * \file dirvote.c
 **/

/** DOCDOC */
void
networkstatus_vote_free(networkstatus_vote_t *ns)
{
  int i;
  if (!ns)
    return;

  tor_free(ns->client_versions);
  tor_free(ns->server_versions);
  if (ns->known_flags) {
    for (i=0; ns->known_flags[i]; ++i)
      tor_free(ns->known_flags[i]);
    tor_free(ns->known_flags);
  }
  tor_free(ns->nickname);
  tor_free(ns->address);
  tor_free(ns->contact);
  if (ns->cert)
    authority_cert_free(ns->cert);

  if (ns->routerstatus_list) {
    SMARTLIST_FOREACH(ns->routerstatus_list, vote_routerstatus_t *, rs,
    {
      tor_free(rs->version);
      tor_free(rs);
    });

    smartlist_free(ns->routerstatus_list);
  }

  memset(ns, 11, sizeof(*ns));
  tor_free(ns);
}

