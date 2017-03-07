/* Copyright (c) 2014, Daniel Martí
 * Copyright (c) 2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_CONSDIFF_H
#define TOR_CONSDIFF_H

#include "or.h"

typedef struct consensus_digest_t {
  uint8_t sha3_256[DIGEST256_LEN];
} consensus_digest_t;

smartlist_t *consdiff_gen_diff(const smartlist_t *cons1,
                               const smartlist_t *cons2,
                               const consensus_digest_t *digests1,
                               const consensus_digest_t *digests2);
char *consdiff_apply_diff(const smartlist_t *cons1, const smartlist_t *diff,
                          const consensus_digest_t *digests1);
int consdiff_get_digests(const smartlist_t *diff,
                         char *digest1_out,
                         char *digest2_out);

#ifdef CONSDIFF_PRIVATE
/** Data structure to define a slice of a smarltist. */
typedef struct smartlist_slice_t {
  /**
   * Smartlist that this slice is made from.
   * References the whole original smartlist that the slice was made out of.
   * */
  const smartlist_t *list;
  /** Starting position of the slice in the smartlist. */
  int offset;
  /** Length of the slice, i.e. the number of elements it holds. */
  int len;
} smartlist_slice_t;
STATIC smartlist_t *gen_ed_diff(const smartlist_t *cons1,
                                const smartlist_t *cons2);
STATIC smartlist_t *apply_ed_diff(const smartlist_t *cons1,
                                  const smartlist_t *diff,
                                  int start_line);
STATIC void calc_changes(smartlist_slice_t *slice1, smartlist_slice_t *slice2,
                         bitarray_t *changed1, bitarray_t *changed2);
STATIC smartlist_slice_t *smartlist_slice(const smartlist_t *list,
                                          int start, int end);
STATIC int next_router(const smartlist_t *cons, int cur);
STATIC int *lcs_lengths(const smartlist_slice_t *slice1,
                        const smartlist_slice_t *slice2,
                        int direction);
STATIC void trim_slices(smartlist_slice_t *slice1, smartlist_slice_t *slice2);
STATIC int base64cmp(const char *hash1, const char *hash2);
STATIC const char *get_id_hash(const char *r_line);
STATIC int is_valid_router_entry(const char *line);
STATIC int smartlist_slice_string_pos(const smartlist_slice_t *slice,
                                      const char *string);
STATIC void set_changed(bitarray_t *changed1, bitarray_t *changed2,
                        const smartlist_slice_t *slice1,
                        const smartlist_slice_t *slice2);
STATIC int consensus_compute_digest(const char *cons,
                                    consensus_digest_t *digest_out);
#endif

#endif

