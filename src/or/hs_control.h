/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_control.h
 * \brief Header file containing control port event related code.
 **/

#ifndef TOR_HS_CONTROL_H
#define TOR_HS_CONTROL_H

#include "hs_ident.h"

/* Event "HS_DESC REQUESTED [...]" */
void hs_control_desc_event_requested(const ed25519_public_key_t *onion_pk,
                                     const char *base64_blinded_pk,
                                     const routerstatus_t *hsdir_rs);

/* Event "HS_DESC FAILED [...]" */
void hs_control_desc_event_failed(const hs_ident_dir_conn_t *ident,
                                  const char *hsdir_id_digest,
                                  const char *reason);

#endif /* !defined(TOR_HS_CONTROL_H) */

