/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file hs_metrics.h
 * @brief Header for feature/hs/hs_metrics.c
 **/

#ifndef TOR_FEATURE_HS_HS_METRICS_H
#define TOR_FEATURE_HS_HS_METRICS_H

#include "lib/container/smartlist.h"
#include "lib/crypt_ops/crypto_ed25519.h"

#define HS_METRICS_ENTRY_PRIVATE
#include "feature/hs/hs_metrics_entry.h"
#include "feature/hs/hs_service.h"

/* Init and Free. */
void hs_metrics_service_init(hs_service_t *service);
void hs_metrics_service_free(hs_service_t *service);

/* Accessors. */
const smartlist_t *hs_metrics_get_stores(void);

/* Metrics Update. */
void hs_metrics_update_by_ident(const hs_metrics_key_t key,
                                const ed25519_public_key_t *ident_pk,
                                const uint16_t port, int64_t n);
void hs_metrics_update_by_service(const hs_metrics_key_t key,
                                  hs_service_t *service, const uint16_t port,
                                  int64_t n);

/** New introducion request received. */
#define hs_metrics_new_introduction(s) \
  hs_metrics_update_by_service(HS_METRICS_NUM_INTRODUCTIONS, (s), 0, 1)

#endif /* !defined(TOR_FEATURE_HS_HS_METRICS_H) */
