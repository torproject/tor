/* Copyright (c) 2014, Daniel Martí
 * Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_CONSDIFF_H
#define TOR_CONSDIFF_H

#include "or.h"

smartlist_t *
consdiff_gen_diff(smartlist_t *cons1, smartlist_t *cons2,
                  common_digests_t *digests1, common_digests_t *digests2);
char *
consdiff_apply_diff(smartlist_t *cons1, smartlist_t *diff,
                    common_digests_t *digests1);
int
consdiff_get_digests(smartlist_t *diff,
                     char *digest1, char *digest1_hex,
                     char *digest2, char *digest2_hex);

#endif

