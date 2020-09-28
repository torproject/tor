/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file metrics.h
 * @brief Header for feature/metrics/metrics.c
 **/

#ifndef TOR_FEATURE_METRICS_METRICS_H
#define TOR_FEATURE_METRICS_METRICS_H

#include "lib/crypt_ops/crypto_ed25519.h"

#include "lib/container/smartlist.h"
#include "lib/metrics/metrics_key.h"

/* Initializer / Cleanup. */
void metrics_init(void);
void metrics_cleanup(void);

/* Accessors. */
char *metrics_get_output(void);

/**
 * Onion Service metrics.
 */

void metrics_hs_new(const ed25519_public_key_t *key,
                    const char *address, const smartlist_t *ports);
void metrics_hs_remove(const ed25519_public_key_t *key);
void metrics_hs_update(const ed25519_public_key_t *ident_key,
                       const unsigned int key, const uint16_t port,
                       const int64_t n);

/* Per address only metric helpers. */

/** New introducion request received. */
#define metrics_hs_new_introduction(ident_key) \
  metrics_hs_update(ident_key, METRICS_HS_NUM_INTRODUCTIONS, 0, 1)
/** Newly established rendezvous. This is called as soon as the circuit purpose
 * is REND_JOINED which is when the RENDEZVOUS2 cell is sent. */
#define metrics_hs_established_rdv_inc(ident_key) \
  metrics_hs_update(ident_key, METRICS_HS_NUM_ESTABLISHED_RDV, 0, 1)
/** Established rendezvous closed. This is called when the circuit in
 * REND_JOINED state is marked for close. */
#define metrics_hs_established_rdv_dec(ident_key) \
  metrics_hs_update(ident_key, METRICS_HS_NUM_ESTABLISHED_RDV, 0, -1)
/** New rendezvous circuit being launched. */
#define metrics_hs_new_rdv(ident_key) \
  metrics_hs_update(ident_key, METRICS_HS_NUM_RDV, 0, 1)

/* Per address + port metric helpers. */

/** Number of bytes written to the application from the service. */
#define metrics_hs_app_write_bytes(ident_key, p, n) \
  metrics_hs_update(ident_key, METRICS_HS_APP_WRITE_BYTES, p, n)
/** Number of bytes read from the application to the service. */
#define metrics_hs_app_read_bytes(ident_key, p, n) \
  metrics_hs_update(ident_key, METRICS_HS_APP_READ_BYTES, p, n)

#endif /* !defined(TOR_FEATURE_METRICS_METRICS_H) */
