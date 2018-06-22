/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_SMARTLIST_H
#define TOR_SMARTLIST_H

#include <stddef.h>
#include <stdarg.h>

#include "lib/cc/compat_compiler.h"
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"

/** A resizeable list of pointers, with associated helpful functionality.
 *
 * The members of this struct are exposed only so that macros and inlines can
 * use them; all access to smartlist internals should go through the functions
 * and macros defined here.
 **/
typedef struct smartlist_t {
  /** @{ */
  /** <b>list</b> has enough capacity to store exactly <b>capacity</b> elements
   * before it needs to be resized.  Only the first <b>num_used</b> (\<=
   * capacity) elements point to valid data.
   */
  void **list;
  int num_used;
  int capacity;
  /** @} */
} smartlist_t;

MOCK_DECL(smartlist_t *, smartlist_new, (void));
MOCK_DECL(void, smartlist_free_, (smartlist_t *sl));
#define smartlist_free(sl) FREE_AND_NULL(smartlist_t, smartlist_free_, (sl))

void smartlist_clear(smartlist_t *sl);
void smartlist_add(smartlist_t *sl, void *element);
void smartlist_add_all(smartlist_t *sl, const smartlist_t *s2);
void smartlist_add_strdup(struct smartlist_t *sl, const char *string);
void smartlist_add_asprintf(struct smartlist_t *sl, const char *pattern, ...)
  CHECK_PRINTF(2, 3);
void smartlist_add_vasprintf(struct smartlist_t *sl, const char *pattern,
                             va_list args)
  CHECK_PRINTF(2, 0);
void smartlist_remove(smartlist_t *sl, const void *element);
void smartlist_remove_keeporder(smartlist_t *sl, const void *element);
void *smartlist_pop_last(smartlist_t *sl);
void smartlist_reverse(smartlist_t *sl);
void smartlist_string_remove(smartlist_t *sl, const char *element);
int smartlist_contains(const smartlist_t *sl, const void *element);
int smartlist_contains_string(const smartlist_t *sl, const char *element);
int smartlist_pos(const smartlist_t *sl, const void *element);
int smartlist_string_pos(const smartlist_t *, const char *elt);
int smartlist_contains_string_case(const smartlist_t *sl, const char *element);
int smartlist_contains_int_as_string(const smartlist_t *sl, int num);
int smartlist_strings_eq(const smartlist_t *sl1, const smartlist_t *sl2);
int smartlist_contains_digest(const smartlist_t *sl, const char *element);
int smartlist_ints_eq(const smartlist_t *sl1, const smartlist_t *sl2);
int smartlist_overlap(const smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_intersect(smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_subtract(smartlist_t *sl1, const smartlist_t *sl2);

/* smartlist_choose() is defined in crypto.[ch] */
#ifdef DEBUG_SMARTLIST
#include "lib/err/torerr.h"
/** Return the number of items in sl.
 */
static inline int smartlist_len(const smartlist_t *sl);
static inline int smartlist_len(const smartlist_t *sl) {
  raw_assert(sl);
  return (sl)->num_used;
}
/** Return the <b>idx</b>th element of sl.
 */
static inline void *smartlist_get(const smartlist_t *sl, int idx);
static inline void *smartlist_get(const smartlist_t *sl, int idx) {
  raw_assert(sl);
  raw_assert(idx>=0);
  raw_assert(sl->num_used > idx);
  return sl->list[idx];
}
static inline void smartlist_set(smartlist_t *sl, int idx, void *val) {
  raw_assert(sl);
  raw_assert(idx>=0);
  raw_assert(sl->num_used > idx);
  sl->list[idx] = val;
}
#else /* !(defined(DEBUG_SMARTLIST)) */
#define smartlist_len(sl) ((sl)->num_used)
#define smartlist_get(sl, idx) ((sl)->list[idx])
#define smartlist_set(sl, idx, val) ((sl)->list[idx] = (val))
#endif /* defined(DEBUG_SMARTLIST) */

/** Exchange the elements at indices <b>idx1</b> and <b>idx2</b> of the
 * smartlist <b>sl</b>. */
static inline void smartlist_swap(smartlist_t *sl, int idx1, int idx2)
{
  if (idx1 != idx2) {
    void *elt = smartlist_get(sl, idx1);
    smartlist_set(sl, idx1, smartlist_get(sl, idx2));
    smartlist_set(sl, idx2, elt);
  }
}

void smartlist_del(smartlist_t *sl, int idx);
void smartlist_del_keeporder(smartlist_t *sl, int idx);
void smartlist_insert(smartlist_t *sl, int idx, void *val);
void smartlist_sort(smartlist_t *sl,
                    int (*compare)(const void **a, const void **b));
void *smartlist_get_most_frequent_(const smartlist_t *sl,
                    int (*compare)(const void **a, const void **b),
                    int *count_out);
#define smartlist_get_most_frequent(sl, compare) \
  smartlist_get_most_frequent_((sl), (compare), NULL)
void smartlist_uniq(smartlist_t *sl,
                    int (*compare)(const void **a, const void **b),
                    void (*free_fn)(void *elt));

void smartlist_sort_strings(smartlist_t *sl);
void smartlist_sort_digests(smartlist_t *sl);
void smartlist_sort_digests256(smartlist_t *sl);
void smartlist_sort_pointers(smartlist_t *sl);

const char *smartlist_get_most_frequent_string(smartlist_t *sl);
const char *smartlist_get_most_frequent_string_(smartlist_t *sl,
                                                int *count_out);
const uint8_t *smartlist_get_most_frequent_digest256(smartlist_t *sl);

void smartlist_uniq_strings(smartlist_t *sl);
void smartlist_uniq_digests(smartlist_t *sl);
void smartlist_uniq_digests256(smartlist_t *sl);
void *smartlist_bsearch(smartlist_t *sl, const void *key,
                        int (*compare)(const void *key, const void **member));
int smartlist_bsearch_idx(const smartlist_t *sl, const void *key,
                          int (*compare)(const void *key, const void **member),
                          int *found_out);

void smartlist_pqueue_add(smartlist_t *sl,
                          int (*compare)(const void *a, const void *b),
                          int idx_field_offset,
                          void *item);
void *smartlist_pqueue_pop(smartlist_t *sl,
                           int (*compare)(const void *a, const void *b),
                           int idx_field_offset);
void smartlist_pqueue_remove(smartlist_t *sl,
                             int (*compare)(const void *a, const void *b),
                             int idx_field_offset,
                             void *item);
void smartlist_pqueue_assert_ok(smartlist_t *sl,
                                int (*compare)(const void *a, const void *b),
                                int idx_field_offset);

#define SPLIT_SKIP_SPACE   0x01
#define SPLIT_IGNORE_BLANK 0x02
#define SPLIT_STRIP_SPACE  0x04
int smartlist_split_string(smartlist_t *sl, const char *str, const char *sep,
                           int flags, int max);
char *smartlist_join_strings(smartlist_t *sl, const char *join, int terminate,
                             size_t *len_out) ATTR_MALLOC;
char *smartlist_join_strings2(smartlist_t *sl, const char *join,
                              size_t join_len, int terminate, size_t *len_out)
  ATTR_MALLOC;

/** Iterate over the items in a smartlist <b>sl</b>, in order.  For each item,
 * assign it to a new local variable of type <b>type</b> named <b>var</b>, and
 * execute the statements inside the loop body.  Inside the loop, the loop
 * index can be accessed as <b>var</b>_sl_idx and the length of the list can
 * be accessed as <b>var</b>_sl_len.
 *
 * NOTE: Do not change the length of the list while the loop is in progress,
 * unless you adjust the _sl_len variable correspondingly.  See second example
 * below.
 *
 * Example use:
 * <pre>
 *   smartlist_t *list = smartlist_split("A:B:C", ":", 0, 0);
 *   SMARTLIST_FOREACH_BEGIN(list, char *, cp) {
 *     printf("%d: %s\n", cp_sl_idx, cp);
 *     tor_free(cp);
 *   } SMARTLIST_FOREACH_END(cp);
 *   smartlist_free(list);
 * </pre>
 *
 * Example use (advanced):
 * <pre>
 *   SMARTLIST_FOREACH_BEGIN(list, char *, cp) {
 *     if (!strcmp(cp, "junk")) {
 *       tor_free(cp);
 *       SMARTLIST_DEL_CURRENT(list, cp);
 *     }
 *   } SMARTLIST_FOREACH_END(cp);
 * </pre>
 */
/* Note: these macros use token pasting, and reach into smartlist internals.
 * This can make them a little daunting. Here's the approximate unpacking of
 * the above examples, for entertainment value:
 *
 * <pre>
 * smartlist_t *list = smartlist_split("A:B:C", ":", 0, 0);
 * {
 *   int cp_sl_idx, cp_sl_len = smartlist_len(list);
 *   char *cp;
 *   for (cp_sl_idx = 0; cp_sl_idx < cp_sl_len; ++cp_sl_idx) {
 *     cp = smartlist_get(list, cp_sl_idx);
 *     printf("%d: %s\n", cp_sl_idx, cp);
 *     tor_free(cp);
 *   }
 * }
 * smartlist_free(list);
 * </pre>
 *
 * <pre>
 * {
 *   int cp_sl_idx, cp_sl_len = smartlist_len(list);
 *   char *cp;
 *   for (cp_sl_idx = 0; cp_sl_idx < cp_sl_len; ++cp_sl_idx) {
 *     cp = smartlist_get(list, cp_sl_idx);
 *     if (!strcmp(cp, "junk")) {
 *       tor_free(cp);
 *       smartlist_del(list, cp_sl_idx);
 *       --cp_sl_idx;
 *       --cp_sl_len;
 *     }
 *   }
 * }
 * </pre>
 */
#define SMARTLIST_FOREACH_BEGIN(sl, type, var)  \
  STMT_BEGIN                                                    \
    int var ## _sl_idx, var ## _sl_len=(sl)->num_used;          \
    type var;                                                   \
    for (var ## _sl_idx = 0; var ## _sl_idx < var ## _sl_len;   \
         ++var ## _sl_idx) {                                    \
      var = (sl)->list[var ## _sl_idx];

#define SMARTLIST_FOREACH_END(var)              \
    var = NULL;                                 \
    (void) var ## _sl_idx;                      \
  } STMT_END

/**
 * An alias for SMARTLIST_FOREACH_BEGIN and SMARTLIST_FOREACH_END, using
 * <b>cmd</b> as the loop body.  This wrapper is here for convenience with
 * very short loops.
 *
 * By convention, we do not use this for loops which nest, or for loops over
 * 10 lines or so.  Use SMARTLIST_FOREACH_{BEGIN,END} for those.
 */
#define SMARTLIST_FOREACH(sl, type, var, cmd)                   \
  SMARTLIST_FOREACH_BEGIN(sl,type,var) {                        \
    cmd;                                                        \
  } SMARTLIST_FOREACH_END(var)

/** Helper: While in a SMARTLIST_FOREACH loop over the list <b>sl</b> indexed
 * with the variable <b>var</b>, remove the current element in a way that
 * won't confuse the loop. */
#define SMARTLIST_DEL_CURRENT(sl, var)          \
  STMT_BEGIN                                    \
    smartlist_del(sl, var ## _sl_idx);          \
    --var ## _sl_idx;                           \
    --var ## _sl_len;                           \
  STMT_END

/** Helper: While in a SMARTLIST_FOREACH loop over the list <b>sl</b> indexed
 * with the variable <b>var</b>, remove the current element in a way that
 * won't confuse the loop. */
#define SMARTLIST_DEL_CURRENT_KEEPORDER(sl, var)          \
  STMT_BEGIN                                              \
     smartlist_del_keeporder(sl, var ## _sl_idx);         \
     --var ## _sl_idx;                                    \
     --var ## _sl_len;                                    \
  STMT_END

/** Helper: While in a SMARTLIST_FOREACH loop over the list <b>sl</b> indexed
 * with the variable <b>var</b>, replace the current element with <b>val</b>.
 * Does not deallocate the current value of <b>var</b>.
 */
#define SMARTLIST_REPLACE_CURRENT(sl, var, val) \
  STMT_BEGIN                                    \
    smartlist_set(sl, var ## _sl_idx, val);     \
  STMT_END

/* Helper: Given two lists of items, possibly of different types, such that
 * both lists are sorted on some common field (as determined by a comparison
 * expression <b>cmpexpr</b>), and such that one list (<b>sl1</b>) has no
 * duplicates on the common field, loop through the lists in lockstep, and
 * execute <b>unmatched_var2</b> on items in var2 that do not appear in
 * var1.
 *
 * WARNING: It isn't safe to add remove elements from either list while the
 * loop is in progress.
 *
 * Example use:
 *  SMARTLIST_FOREACH_JOIN(routerstatus_list, routerstatus_t *, rs,
 *                     routerinfo_list, routerinfo_t *, ri,
 *                    tor_memcmp(rs->identity_digest, ri->identity_digest, 20),
 *                     log_info(LD_GENERAL,"No match for %s", ri->nickname)) {
 *    log_info(LD_GENERAL, "%s matches routerstatus %p", ri->nickname, rs);
 * } SMARTLIST_FOREACH_JOIN_END(rs, ri);
 **/
/* The example above unpacks (approximately) to:
 *  int rs_sl_idx = 0, rs_sl_len = smartlist_len(routerstatus_list);
 *  int ri_sl_idx, ri_sl_len = smartlist_len(routerinfo_list);
 *  int rs_ri_cmp;
 *  routerstatus_t *rs;
 *  routerinfo_t *ri;
 *  for (; ri_sl_idx < ri_sl_len; ++ri_sl_idx) {
 *    ri = smartlist_get(routerinfo_list, ri_sl_idx);
 *    while (rs_sl_idx < rs_sl_len) {
 *      rs = smartlist_get(routerstatus_list, rs_sl_idx);
 *      rs_ri_cmp = tor_memcmp(rs->identity_digest, ri->identity_digest, 20);
 *      if (rs_ri_cmp > 0) {
 *        break;
 *      } else if (rs_ri_cmp == 0) {
 *        goto matched_ri;
 *      } else {
 *        ++rs_sl_idx;
 *      }
 *    }
 *    log_info(LD_GENERAL,"No match for %s", ri->nickname);
 *    continue;
 *   matched_ri: {
 *    log_info(LD_GENERAL,"%s matches with routerstatus %p",ri->nickname,rs);
 *    }
 *  }
 */
#define SMARTLIST_FOREACH_JOIN(sl1, type1, var1, sl2, type2, var2,      \
                                cmpexpr, unmatched_var2)                \
  STMT_BEGIN                                                            \
  int var1 ## _sl_idx = 0, var1 ## _sl_len=(sl1)->num_used;             \
  int var2 ## _sl_idx = 0, var2 ## _sl_len=(sl2)->num_used;             \
  int var1 ## _ ## var2 ## _cmp;                                        \
  type1 var1;                                                           \
  type2 var2;                                                           \
  for (; var2##_sl_idx < var2##_sl_len; ++var2##_sl_idx) {              \
    var2 = (sl2)->list[var2##_sl_idx];                                  \
    while (var1##_sl_idx < var1##_sl_len) {                             \
      var1 = (sl1)->list[var1##_sl_idx];                                \
      var1##_##var2##_cmp = (cmpexpr);                                  \
      if (var1##_##var2##_cmp > 0) {                                    \
        break;                                                          \
      } else if (var1##_##var2##_cmp == 0) {                            \
        goto matched_##var2;                                            \
      } else {                                                          \
        ++var1##_sl_idx;                                                \
      }                                                                 \
    }                                                                   \
    /* Ran out of v1, or no match for var2. */                          \
    unmatched_var2;                                                     \
    continue;                                                           \
    matched_##var2: ;                                                   \

#define SMARTLIST_FOREACH_JOIN_END(var1, var2)  \
  }                                             \
  STMT_END

#endif /* !defined(TOR_CONTAINER_H) */
