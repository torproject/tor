/* Copyright 2003-2004 Roger Dingledine
   Copyright 2004-2005 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */
const char container_c_id[] = "$Id$";

/**
 * \file container.c
 * \brief Implements a smartlist (a resizable array) along
 * with helper functions to use smartlists.  Also includes a
 * splay-tree implementation of the string-to-void* map.
 **/

#include "compat.h"
#include "util.h"
#include "log.h"
#include "../or/tree.h"
#include "container.h"
#include "crypto.h"

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* All newly allocated smartlists have this capacity.
 */
#define SMARTLIST_DEFAULT_CAPACITY 32

/** Allocate and return an empty smartlist.
 */
smartlist_t *
smartlist_create(void)
{
  smartlist_t *sl = tor_malloc(sizeof(smartlist_t));
  sl->num_used = 0;
  sl->capacity = SMARTLIST_DEFAULT_CAPACITY;
  sl->list = tor_malloc(sizeof(void *) * sl->capacity);
  return sl;
}

/** Deallocate a smartlist.  Does not release storage associated with the
 * list's elements.
 */
void
smartlist_free(smartlist_t *sl)
{
  tor_free(sl->list);
  tor_free(sl);
}

/** Change the capacity of the smartlist to <b>n</b>, so that we can grow
 * the list up to <b>n</b> elements with no further reallocation or wasted
 * space.  If <b>n</b> is less than or equal to the number of elements
 * currently in the list, reduce the list's capacity as much as
 * possible without losing elements.
 */
void
smartlist_set_capacity(smartlist_t *sl, int n)
{
  if (n < sl->num_used)
    n = sl->num_used;
  if (sl->capacity != n) {
    sl->capacity = n;
    sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
  }
}

/** Remove all elements from the list.
 */
void
smartlist_clear(smartlist_t *sl)
{
  sl->num_used = 0;
}

/** Set the list's new length to <b>len</b> (which must be \<= the list's
 * current size). Remove the last smartlist_len(sl)-len elements from the
 * list.
 */
void
smartlist_truncate(smartlist_t *sl, int len)
{
  tor_assert(len <= sl->num_used);
  sl->num_used = len;
}

/** Append element to the end of the list. */
void
smartlist_add(smartlist_t *sl, void *element)
{
  if (sl->num_used >= sl->capacity) {
    int higher = sl->capacity * 2;
    tor_assert(higher > sl->capacity); /* detect overflow */
    sl->capacity = higher;
    sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
  }
  sl->list[sl->num_used++] = element;
}

/** Append each element from S2 to the end of S1. */
void
smartlist_add_all(smartlist_t *sl, const smartlist_t *s2)
{
  int n2 = sl->num_used + s2->num_used;
  if (n2 > sl->capacity) {
    int higher = sl->capacity * 2;
    while (n2 > higher)
      higher *= 2;
    sl->capacity = higher;
    sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
  }
  memcpy(sl->list + sl->num_used, s2->list, s2->num_used*sizeof(void*));
  sl->num_used += s2->num_used;
}

/** Remove all elements E from sl such that E==element.  Preserve
 * the order of any elements before E, but elements after E can be
 * rearranged.
 */
void
smartlist_remove(smartlist_t *sl, void *element)
{
  int i;
  if (element == NULL)
    return;
  for (i=0; i < sl->num_used; i++)
    if (sl->list[i] == element) {
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/** If there are any strings in sl equal to element, remove and free them.
 * Does not preserve order. */
void
smartlist_string_remove(smartlist_t *sl, const char *element)
{
  int i;
  tor_assert(sl);
  tor_assert(element);
  for (i = 0; i < sl->num_used; ++i) {
    if (!strcmp(element, sl->list[i])) {
      tor_free(sl->list[i]);
      sl->list[i] = sl->list[--sl->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
  }
}

/** Return true iff some element E of sl has E==element.
 */
int
smartlist_isin(const smartlist_t *sl, void *element)
{
  int i;
  for (i=0; i < sl->num_used; i++)
    if (sl->list[i] == element)
      return 1;
  return 0;
}

/** Return true iff <b>sl</b> has some element E such that
 * !strcmp(E,<b>element</b>)
 */
int
smartlist_string_isin(const smartlist_t *sl, const char *element)
{
  int i;
  if (!sl) return 0;
  for (i=0; i < sl->num_used; i++)
    if (strcmp((const char*)sl->list[i],element)==0)
      return 1;
  return 0;
}

/** Return true iff <b>sl</b> has some element E such that E is equal
 * to the decimal encoding of <b>num</b>.
 */
int
smartlist_string_num_isin(const smartlist_t *sl, int num)
{
  char buf[16];
  tor_snprintf(buf,sizeof(buf),"%d", num);
  return smartlist_string_isin(sl, buf);
}

/** Return true iff some element E of sl2 has smartlist_isin(sl1,E).
 */
int
smartlist_overlap(const smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl2->num_used; i++)
    if (smartlist_isin(sl1, sl2->list[i]))
      return 1;
  return 0;
}

/** Remove every element E of sl1 such that !smartlist_isin(sl2,E).
 * Does not preserve the order of sl1.
 */
void
smartlist_intersect(smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl1->num_used; i++)
    if (!smartlist_isin(sl2, sl1->list[i])) {
      sl1->list[i] = sl1->list[--sl1->num_used]; /* swap with the end */
      i--; /* so we process the new i'th element */
    }
}

/** Remove every element E of sl1 such that smartlist_isin(sl2,E).
 * Does not preserve the order of sl1.
 */
void
smartlist_subtract(smartlist_t *sl1, const smartlist_t *sl2)
{
  int i;
  for (i=0; i < sl2->num_used; i++)
    smartlist_remove(sl1, sl2->list[i]);
}

/** Remove the <b>idx</b>th element of sl; if idx is not the last
 * element, swap the last element of sl into the <b>idx</b>th space.
 * Return the old value of the <b>idx</b>th element.
 */
void
smartlist_del(smartlist_t *sl, int idx)
{
  tor_assert(sl);
  tor_assert(idx>=0);
  tor_assert(idx < sl->num_used);
  sl->list[idx] = sl->list[--sl->num_used];
}
/** Remove the <b>idx</b>th element of sl; if idx is not the last element,
 * moving all subsequent elements back one space. Return the old value
 * of the <b>idx</b>th element.
 */
void
smartlist_del_keeporder(smartlist_t *sl, int idx)
{
  tor_assert(sl);
  tor_assert(idx>=0);
  tor_assert(idx < sl->num_used);
  --sl->num_used;
  if (idx < sl->num_used)
    memmove(sl->list+idx, sl->list+idx+1, sizeof(void*)*(sl->num_used-idx));
}
/** Insert the value <b>val</b> as the new <b>idx</b>th element of
 * <b>sl</b>, moving all items previously at <b>idx</b> or later
 * forward one space.
 */
void
smartlist_insert(smartlist_t *sl, int idx, void *val)
{
  tor_assert(sl);
  tor_assert(idx>=0);
  tor_assert(idx <= sl->num_used);
  if (idx == sl->num_used) {
    smartlist_add(sl, val);
  } else {
    /* Ensure sufficient capacity */
    if (sl->num_used >= sl->capacity) {
      sl->capacity *= 2;
      sl->list = tor_realloc(sl->list, sizeof(void*)*sl->capacity);
    }
    /* Move other elements away */
    if (idx < sl->num_used)
      memmove(sl->list + idx + 1, sl->list + idx,
              sizeof(void*)*(sl->num_used-idx));
    sl->num_used++;
    sl->list[idx] = val;
  }
}

/**
 * Split a string <b>str</b> along all occurrences of <b>sep</b>,
 * adding the split strings, in order, to <b>sl</b>.  If
 * <b>flags</b>&amp;SPLIT_SKIP_SPACE is true, remove initial and
 * trailing space from each entry.  If
 * <b>flags</b>&amp;SPLIT_IGNORE_BLANK is true, remove any entries of
 * length 0.  If max>0, divide the string into no more than <b>max</b>
 * pieces.  If <b>sep</b> is NULL, split on any sequence of horizontal space.
 */
int
smartlist_split_string(smartlist_t *sl, const char *str, const char *sep,
                       int flags, int max)
{
  const char *cp, *end, *next;
  int n = 0;

  tor_assert(sl);
  tor_assert(str);

  cp = str;
  while (1) {
    if (flags&SPLIT_SKIP_SPACE) {
      while (TOR_ISSPACE(*cp)) ++cp;
    }

    if (max>0 && n == max-1) {
      end = strchr(cp,'\0');
    } else if (sep) {
      end = strstr(cp,sep);
      if (!end)
        end = strchr(cp,'\0');
    } else {
      for (end = cp; *end && *end != '\t' && *end != ' '; ++end)
        ;
    }

    if (!*end) {
      next = NULL;
    } else if (sep) {
      next = end+strlen(sep);
    } else {
      next = end+1;
      while (*next == '\t' || *next == ' ')
        ++next;
    }

    if (flags&SPLIT_SKIP_SPACE) {
      while (end > cp && TOR_ISSPACE(*(end-1)))
        --end;
    }
    if (end != cp || !(flags&SPLIT_IGNORE_BLANK)) {
      smartlist_add(sl, tor_strndup(cp, end-cp));
      ++n;
    }
    if (!next)
      break;
    cp = next;
  }

  return n;
}

/** Allocate and return a new string containing the concatenation of
 * the elements of <b>sl</b>, in order, separated by <b>join</b>.  If
 * <b>terminate</b> is true, also terminate the string with <b>join</b>.
 * If <b>len_out</b> is not NULL, set <b>len_out</b> to the length of
 * the returned string. Requires that every element of <b>sl</b> is
 * NUL-terminated string.
 */
char *
smartlist_join_strings(smartlist_t *sl, const char *join,
                       int terminate, size_t *len_out)
{
  return smartlist_join_strings2(sl,join,strlen(join),terminate,len_out);
}

/** As smartlist_join_strings, but instead of separating/terminated with a
 * NUL-terminated string <b>join</b>, uses the <b>join_len</b>-byte sequence
 * at <b>join</b>.  (Useful for generating a sequence of NUL-terminated
 * strings.)
 */
char *
smartlist_join_strings2(smartlist_t *sl, const char *join,
                        size_t join_len, int terminate, size_t *len_out)
{
  int i;
  size_t n = 0;
  char *r = NULL, *dst, *src;

  tor_assert(sl);
  tor_assert(join);

  if (terminate)
    n = join_len;

  for (i = 0; i < sl->num_used; ++i) {
    n += strlen(sl->list[i]);
    if (i+1 < sl->num_used) /* avoid double-counting the last one */
      n += join_len;
  }
  dst = r = tor_malloc(n+1);
  for (i = 0; i < sl->num_used; ) {
    for (src = sl->list[i]; *src; )
      *dst++ = *src++;
    if (++i < sl->num_used) {
      memcpy(dst, join, join_len);
      dst += join_len;
    }
  }
  if (terminate) {
    memcpy(dst, join, join_len);
    dst += join_len;
  }
  *dst = '\0';

  if (len_out)
    *len_out = dst-r;
  return r;
}

/** Sort the members of <b>sl</b> into an order defined by
 * the ordering function <b>compare</b>, which returns less then 0 if a
 * precedes b, greater than 0 if b precedes a, and 0 if a 'equals' b.
 */
void
smartlist_sort(smartlist_t *sl, int (*compare)(const void **a, const void **b))
{
  if (!sl->num_used)
    return;
  qsort(sl->list, sl->num_used, sizeof(void*),
        (int (*)(const void *,const void*))compare);
}

/** Assuming the members of <b>sl</b> are in order, return a pointer to the
 * member which matches <b>key</b>.  Ordering and matching are defined by a
 * <b>compare</b> function, which returns 0 on a match; less than 0 if key is
 * less than member, and greater than 0 if key is greater then member.
 */
void *
smartlist_bsearch(smartlist_t *sl, const void *key,
                  int (*compare)(const void *key, const void **member))
{
  void ** r;
  if (!sl->num_used)
    return NULL;

  r = bsearch(key, sl->list, sl->num_used, sizeof(void*),
              (int (*)(const void *, const void *))compare);
  return r ? *r : NULL;
}

/** Helper: compare two const char **s. */
static int
_compare_string_ptrs(const void **_a, const void **_b)
{
  return strcmp((const char*)*_a, (const char*)*_b);
}

/** Sort a smartlist <b>sl</b> containing strings into lexically ascending
 * order. */
void
smartlist_sort_strings(smartlist_t *sl)
{
  smartlist_sort(sl, _compare_string_ptrs);
}

#define DEFINE_MAP_STRUCTS(maptype, keydecl, prefix)      \
  typedef struct prefix ## entry_t {                      \
    SPLAY_ENTRY(prefix ## entry_t) node;                  \
    keydecl;                                              \
    void *val;                                            \
  } prefix ## entry_t;                                    \
  struct maptype {                                        \
    SPLAY_HEAD(prefix ## tree, prefix ## entry_t) head;   \
  };

DEFINE_MAP_STRUCTS(strmap_t, char *key, strmap_);
DEFINE_MAP_STRUCTS(digestmap_t, char key[DIGEST_LEN], digestmap_);

/** Helper: compare strmap_t_entry objects by key value. */
static int
compare_strmap_entries(strmap_entry_t *a,
                       strmap_entry_t *b)
{
  return strcmp(a->key, b->key);
}

/** Helper: compare digestmap_entry_t objects by key value. */
static int
compare_digestmap_entries(digestmap_entry_t *a,
                          digestmap_entry_t *b)
{
  return memcmp(a->key, b->key, DIGEST_LEN);
}

SPLAY_PROTOTYPE(strmap_tree, strmap_entry_t, node, compare_strmap_entries);
SPLAY_GENERATE(strmap_tree, strmap_entry_t, node, compare_strmap_entries);

SPLAY_PROTOTYPE(digestmap_tree, digestmap_entry_t, node,
                compare_digestmap_entries);
SPLAY_GENERATE(digestmap_tree, digestmap_entry_t, node,
               compare_digestmap_entries);

/** Define function reate a new empty map from strings to void*'s.
 */
strmap_t *
strmap_new(void)
{
  strmap_t *result;
  result = tor_malloc(sizeof(strmap_t));
  SPLAY_INIT(&result->head);
  return result;
}

/** Define function reate a new empty map from digests to void*'s.
 */
digestmap_t *
digestmap_new(void)
{
  digestmap_t *result;
  result = tor_malloc(sizeof(digestmap_t));
  SPLAY_INIT(&result->head);
  return result;
}

/** Set the current value for <b>key</b> to <b>val</b>.  Returns the previous
 * value for <b>key</b> if one was set, or NULL if one was not.
 *
 * This function makes a copy of <b>key</b> if necessary, but not of
 * <b>val</b>.
 */
void *
strmap_set(strmap_t *map, const char *key, void *val)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  void *oldval;
  tor_assert(map);
  tor_assert(key);
  tor_assert(val);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    resolve->val = val;
    return oldval;
  } else {
    resolve = tor_malloc_zero(sizeof(strmap_entry_t));
    resolve->key = tor_strdup(key);
    resolve->val = val;
    SPLAY_INSERT(strmap_tree, &map->head, resolve);
    return NULL;
  }
}

void *
digestmap_set(digestmap_t *map, const char *key, void *val)
{
  digestmap_entry_t *resolve;
  digestmap_entry_t search;
  void *oldval;
  tor_assert(map);
  tor_assert(key);
  tor_assert(val);
  memcpy(&search.key, key, DIGEST_LEN);
  resolve = SPLAY_FIND(digestmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    resolve->val = val;
    return oldval;
  } else {
    resolve = tor_malloc_zero(sizeof(digestmap_entry_t));
    memcpy(resolve->key, key, DIGEST_LEN);
    resolve->val = val;
    SPLAY_INSERT(digestmap_tree, &map->head, resolve);
    return NULL;
  }
}

/** Return the current value associated with <b>key</b>, or NULL if no
 * value is set.
 */
void *
strmap_get(strmap_t *map, const char *key)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  tor_assert(map);
  tor_assert(key);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    return resolve->val;
  } else {
    return NULL;
  }
}

void *
digestmap_get(digestmap_t *map, const char *key)
{
  digestmap_entry_t *resolve;
  digestmap_entry_t search;
  tor_assert(map);
  tor_assert(key);
  memcpy(&search.key, key, DIGEST_LEN);
  resolve = SPLAY_FIND(digestmap_tree, &map->head, &search);
  if (resolve) {
    return resolve->val;
  } else {
    return NULL;
  }
}

/** Remove the value currently associated with <b>key</b> from the map.
 * Return the value if one was set, or NULL if there was no entry for
 * <b>key</b>.
 *
 * Note: you must free any storage associated with the returned value.
 */
void *
strmap_remove(strmap_t *map, const char *key)
{
  strmap_entry_t *resolve;
  strmap_entry_t search;
  void *oldval;
  tor_assert(map);
  tor_assert(key);
  search.key = (char*)key;
  resolve = SPLAY_FIND(strmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    SPLAY_REMOVE(strmap_tree, &map->head, resolve);
    tor_free(resolve->key);
    tor_free(resolve);
    return oldval;
  } else {
    return NULL;
  }
}

void *
digestmap_remove(digestmap_t *map, const char *key)
{
  digestmap_entry_t *resolve;
  digestmap_entry_t search;
  void *oldval;
  tor_assert(map);
  tor_assert(key);
  memcpy(&search.key, key, DIGEST_LEN);
  resolve = SPLAY_FIND(digestmap_tree, &map->head, &search);
  if (resolve) {
    oldval = resolve->val;
    SPLAY_REMOVE(digestmap_tree, &map->head, resolve);
    tor_free(resolve);
    return oldval;
  } else {
    return NULL;
  }
}

/** Same as strmap_set, but first converts <b>key</b> to lowercase. */
void *
strmap_set_lc(strmap_t *map, const char *key, void *val)
{
  /* We could be a little faster by using strcasecmp instead, and a separate
   * type, but I don't think it matters. */
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_set(map,lc_key,val);
  tor_free(lc_key);
  return v;
}
/** Same as strmap_get, but first converts <b>key</b> to lowercase. */
void *
strmap_get_lc(strmap_t *map, const char *key)
{
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_get(map,lc_key);
  tor_free(lc_key);
  return v;
}
/** Same as strmap_remove, but first converts <b>key</b> to lowercase */
void *
strmap_remove_lc(strmap_t *map, const char *key)
{
  void *v;
  char *lc_key = tor_strdup(key);
  tor_strlower(lc_key);
  v = strmap_remove(map,lc_key);
  tor_free(lc_key);
  return v;
}

/** Invoke fn() on every entry of the map, in order.  For every entry,
 * fn() is invoked with that entry's key, that entry's value, and the
 * value of <b>data</b> supplied to strmap_foreach.  fn() must return a new
 * (possibly unmodified) value for each entry: if fn() returns NULL, the
 * entry is removed.
 *
 * Example:
 * \code
 *   static void* upcase_and_remove_empty_vals(const char *key, void *val,
 *                                             void* data) {
 *     char *cp = (char*)val;
 *     if (!*cp) {  // val is an empty string.
 *       free(val);
 *       return NULL;
 *     } else {
 *       for (; *cp; cp++)
 *         *cp = toupper(*cp);
 *       }
 *       return val;
 *     }
 *   }
 *
 *   ...
 *
 *   strmap_foreach(map, upcase_and_remove_empty_vals, NULL);
 * \endcode
 */
void
strmap_foreach(strmap_t *map,
               void* (*fn)(const char *key, void *val, void *data),
               void *data)
{
  strmap_entry_t *ptr, *next;
  tor_assert(map);
  tor_assert(fn);
  for (ptr = SPLAY_MIN(strmap_tree, &map->head); ptr != NULL; ptr = next) {
    /* This remove-in-place usage is specifically blessed in tree(3). */
    next = SPLAY_NEXT(strmap_tree, &map->head, ptr);
    ptr->val = fn(ptr->key, ptr->val, data);
    if (!ptr->val) {
      SPLAY_REMOVE(strmap_tree, &map->head, ptr);
      tor_free(ptr->key);
      tor_free(ptr);
    }
  }
}

/** return an <b>iterator</b> pointer to the front of a map.
 *
 * Iterator example:
 *
 * \code
 * // uppercase values in "map", removing empty values.
 *
 * strmap_iter_t *iter;
 * const char *key;
 * void *val;
 * char *cp;
 *
 * for (iter = strmap_iter_init(map); !strmap_iter_done(iter); ) {
 *    strmap_iter_get(iter, &key, &val);
 *    cp = (char*)val;
 *    if (!*cp) {
 *       iter = strmap_iter_next_rmv(iter);
 *       free(val);
 *    } else {
 *       for (;*cp;cp++) *cp = toupper(*cp);
 *       iter = strmap_iter_next(iter);
 *    }
 * }
 * \endcode
 *
 */
strmap_iter_t *
strmap_iter_init(strmap_t *map)
{
  tor_assert(map);
  return SPLAY_MIN(strmap_tree, &map->head);
}

digestmap_iter_t *
digestmap_iter_init(digestmap_t *map)
{
  tor_assert(map);
  return SPLAY_MIN(digestmap_tree, &map->head);
}

/** Advance the iterator <b>iter</b> for map a single step to the next entry.
 */
strmap_iter_t *
strmap_iter_next(strmap_t *map, strmap_iter_t *iter)
{
  tor_assert(map);
  tor_assert(iter);
  return SPLAY_NEXT(strmap_tree, &map->head, iter);
}

digestmap_iter_t *
digestmap_iter_next(digestmap_t *map, digestmap_iter_t *iter)
{
  tor_assert(map);
  tor_assert(iter);
  return SPLAY_NEXT(digestmap_tree, &map->head, iter);
}

/** Advance the iterator <b>iter</b> a single step to the next entry, removing
 * the current entry.
 */
strmap_iter_t *
strmap_iter_next_rmv(strmap_t *map, strmap_iter_t *iter)
{
  strmap_iter_t *next;
  tor_assert(map);
  tor_assert(iter);
  next = SPLAY_NEXT(strmap_tree, &map->head, iter);
  SPLAY_REMOVE(strmap_tree, &map->head, iter);
  tor_free(iter->key);
  tor_free(iter);
  return next;
}

digestmap_iter_t *
digestmap_iter_next_rmv(digestmap_t *map, digestmap_iter_t *iter)
{
  digestmap_iter_t *next;
  tor_assert(map);
  tor_assert(iter);
  next = SPLAY_NEXT(digestmap_tree, &map->head, iter);
  SPLAY_REMOVE(digestmap_tree, &map->head, iter);
  tor_free(iter);
  return next;
}

/** Set *keyp and *valp to the current entry pointed to by iter.
 */
void
strmap_iter_get(strmap_iter_t *iter, const char **keyp, void **valp)
{
  tor_assert(iter);
  tor_assert(keyp);
  tor_assert(valp);
  *keyp = iter->key;
  *valp = iter->val;
}

void
digestmap_iter_get(digestmap_iter_t *iter, const char **keyp, void **valp)
{
  tor_assert(iter);
  tor_assert(keyp);
  tor_assert(valp);
  *keyp = iter->key;
  *valp = iter->val;
}

/** Return true iff iter has advanced past the last entry of map.
 */
int
strmap_iter_done(strmap_iter_t *iter)
{
  return iter == NULL;
}

int
digestmap_iter_done(digestmap_iter_t *iter)
{
  return iter == NULL;
}

/** Remove all entries from <b>map</b>, and deallocate storage for those entries.
 * If free_val is provided, it is invoked on every value in <b>map</b>.
 */
void
strmap_free(strmap_t *map, void (*free_val)(void*))
{
  strmap_entry_t *ent, *next;
  for (ent = SPLAY_MIN(strmap_tree, &map->head); ent != NULL; ent = next) {
    next = SPLAY_NEXT(strmap_tree, &map->head, ent);
    SPLAY_REMOVE(strmap_tree, &map->head, ent);
    tor_free(ent->key);
    if (free_val)
      free_val(ent->val);
    tor_free(ent);
  }
  tor_assert(SPLAY_EMPTY(&map->head));
  tor_free(map);
}

void
digestmap_free(digestmap_t *map, void (*free_val)(void*))
{
  digestmap_entry_t *ent, *next;
  for (ent = SPLAY_MIN(digestmap_tree, &map->head); ent != NULL; ent = next) {
    next = SPLAY_NEXT(digestmap_tree, &map->head, ent);
    SPLAY_REMOVE(digestmap_tree, &map->head, ent);
    if (free_val)
      free_val(ent->val);
    tor_free(ent);
  }
  tor_assert(SPLAY_EMPTY(&map->head));
  tor_free(map);
}

/* Return true iff <b>map</b> has no entries.
 */
int
strmap_isempty(strmap_t *map)
{
  return SPLAY_EMPTY(&map->head);
}

int
digestmap_isempty(digestmap_t *map)
{
  return SPLAY_EMPTY(&map->head);
}

