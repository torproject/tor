/* Copyright 2003-2004 Roger Dingledine
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __CONTAINER_H
#define __CONTAINER_H
#define CONTAINER_H_ID \
  "$Id$"

#include "compat.h"
#include "util.h"

/** A resizeable list of pointers, with associated helpful functionality. */
typedef struct smartlist_t {
  /** <b>list</b> has enough capacity to store exactly <b>capacity</b> elements
   * before it needs to be resized.  Only the first <b>num_used</b> (\<=
   * capacity) elements point to valid data.
   */
  void **list;
  int num_used;
  int capacity;
} smartlist_t;

smartlist_t *smartlist_create(void);
void smartlist_free(smartlist_t *sl);
void smartlist_set_capacity(smartlist_t *sl, int n);
void smartlist_clear(smartlist_t *sl);
void smartlist_add(smartlist_t *sl, void *element);
void smartlist_add_all(smartlist_t *sl, const smartlist_t *s2);
void smartlist_remove(smartlist_t *sl, const void *element);
void smartlist_string_remove(smartlist_t *sl, const char *element);
int smartlist_isin(const smartlist_t *sl, const void *element);
int smartlist_string_isin(const smartlist_t *sl, const char *element);
int smartlist_string_num_isin(const smartlist_t *sl, int num);
int smartlist_overlap(const smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_intersect(smartlist_t *sl1, const smartlist_t *sl2);
void smartlist_subtract(smartlist_t *sl1, const smartlist_t *sl2);
/* smartlist_choose() is defined in crypto.[ch] */
#ifdef DEBUG_SMARTLIST
/** Return the number of items in sl.
 */
extern INLINE int smartlist_len(const smartlist_t *sl) {
  tor_assert(sl);
  return (sl)->num_used;
}
/** Return the <b>idx</b>th element of sl.
 */
extern INLINE void *smartlist_get(const smartlist_t *sl, int idx) {
  tor_assert(sl);
  tor_assert(idx>=0);
  tor_assert(sl->num_used < idx);
  return sl->list[idx];
}
extern INLINE void smartlist_set(smartlist_t *sl, int idx, void *val) {
  tor_assert(sl);
  tor_assert(idx>=0);
  tor_assert(sl->num_used < idx);
  sl->list[idx] = val;
}
#else
#define smartlist_len(sl) ((sl)->num_used)
#define smartlist_get(sl, idx) ((sl)->list[idx])
#define smartlist_set(sl, idx, val) ((sl)->list[idx] = (val))
#endif

void smartlist_del(smartlist_t *sl, int idx);
void smartlist_del_keeporder(smartlist_t *sl, int idx);
void smartlist_insert(smartlist_t *sl, int idx, void *val);
void smartlist_sort(smartlist_t *sl,
                    int (*compare)(const void **a, const void **b));
void smartlist_sort_strings(smartlist_t *sl);
void *smartlist_bsearch(smartlist_t *sl, const void *key,
                        int (*compare)(const void *key, const void **member));

#define SPLIT_SKIP_SPACE   0x01
#define SPLIT_IGNORE_BLANK 0x02
int smartlist_split_string(smartlist_t *sl, const char *str, const char *sep,
                           int flags, int max);
char *smartlist_join_strings(smartlist_t *sl, const char *join, int terminate,
                             size_t *len_out);
char *smartlist_join_strings2(smartlist_t *sl, const char *join,
                              size_t join_len, int terminate, size_t *len_out);

/** Iterate over the items in a smartlist <b>sl</b>, in order.  For each item,
 * assign it to a new local variable of type <b>type</b> named <b>var</b>, and
 * execute the statement <b>cmd</b>.  Inside the loop, the loop index can
 * be accessed as <b>var</b>_sl_idx.
 *
 * Example use:
 * <pre>
 *   smartlist_t *list = smartlist_split("A:B:C", ":", 0, 0);
 *   SMARTLIST_FOREACH(list, char *, cp,
 *   {
 *     printf("%d: %s\n", cp_sl_idx, cp);
 *     tor_free(cp);
 *   });
 *   smarlitst_free(list);
 * </pre>
 */
#define SMARTLIST_FOREACH(sl, type, var, cmd)                   \
  do {                                                          \
    int var ## _sl_idx, var ## _sl_len=(sl)->num_used;          \
    type var;                                                   \
    for (var ## _sl_idx = 0; var ## _sl_idx < var ## _sl_len;   \
         ++var ## _sl_idx) {                                    \
      var = (sl)->list[var ## _sl_idx];                         \
      cmd;                                                      \
    } } while (0)

#define DECLARE_MAP_FNS(maptype, keytype, prefix)                       \
  typedef struct maptype maptype;                                       \
  typedef struct prefix##entry_t *prefix##iter_t;                       \
  maptype* prefix##new(void);                                           \
  void* prefix##set(maptype *map, keytype key, void *val);              \
  void* prefix##get(maptype *map, keytype key);                         \
  void* prefix##remove(maptype *map, keytype key);                      \
  void prefix##free(maptype *map, void (*free_val)(void*));             \
  int prefix##isempty(maptype *map);                                    \
  int prefix##size(maptype *map);                                       \
  prefix##iter_t *prefix##iter_init(maptype *map);                      \
  prefix##iter_t *prefix##iter_next(maptype *map, prefix##iter_t *iter); \
  prefix##iter_t *prefix##iter_next_rmv(maptype *map, prefix##iter_t *iter); \
  void prefix##iter_get(prefix##iter_t *iter, keytype *keyp, void **valp); \
  int prefix##iter_done(prefix##iter_t *iter);

/* Map from const char * to void *. Implemented with a hash table. */
DECLARE_MAP_FNS(strmap_t, const char *, strmap_);
DECLARE_MAP_FNS(digestmap_t, const char *, digestmap_);

void* strmap_set_lc(strmap_t *map, const char *key, void *val);
void* strmap_get_lc(strmap_t *map, const char *key);
void* strmap_remove_lc(strmap_t *map, const char *key);

#endif

