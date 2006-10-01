/* Copyright 2002 Christopher Clark */
/* Copyright 2005 Nick Mathewson */
/* See license at end. */
/* $Id$ */

/* Based on ideas by Christopher Clark and interfaces from Niels Provos. */

#ifndef __HT_H
#define __HT_H
#define HT_H_ID "$Id$"

#define HT_HEAD(name, type)                                             \
  struct name {                                                         \
    /* The hash table itself. */                                        \
    struct type **hth_table;                                            \
    /* How long is the hash table? */                                   \
    unsigned hth_table_length;                                          \
    /* How many elements does the table contain? */                     \
    unsigned hth_n_entries;                                             \
    /* How many elements will we allow in the table before resizing it? */ \
    unsigned hth_load_limit;                                            \
    /* Position of hth_table_length in the primes table. */             \
    int hth_prime_idx;                                                  \
  }

#define HT_INITIALIZER()                        \
  { NULL, 0, 0, 0, -1 }

#define HT_INIT(root) do {                      \
    (root)->hth_table_length = 0;               \
    (root)->hth_table = NULL;                   \
    (root)->hth_n_entries = 0;                  \
    (root)->hth_load_limit = 0;                 \
    (root)->hth_prime_idx = -1;                 \
  } while (0)

#define HT_ENTRY(type)                          \
  struct {                                      \
    struct type *hte_next;                      \
    unsigned hte_hash;                          \
  }

#define HT_EMPTY(head)                          \
  ((head)->hth_n_entries == 0)

/* Helper: alias for the bucket containing 'elm'. */
#define _HT_BUCKET(head, field, elm)                                    \
  ((head)->hth_table[elm->field.hte_hash % head->hth_table_length])

/* How many elements in 'head'? */
#define HT_SIZE(head)                           \
  ((head)->hth_n_entries)

#define HT_FIND(name, head, elm)     name##_HT_FIND((head), (elm))
#define HT_INSERT(name, head, elm)   name##_HT_INSERT((head), (elm))
#define HT_REPLACE(name, head, elm)  name##_HT_REPLACE((head), (elm))
#define HT_REMOVE(name, head, elm)   name##_HT_REMOVE((head), (elm))
#define HT_START(name, head)         name##_HT_START(head)
#define HT_NEXT(name, head, elm)     name##_HT_NEXT((head), (elm))
#define HT_NEXT_RMV(name, head, elm) name##_HT_NEXT_RMV((head), (elm))
#define HT_CLEAR(name, head)         name##_HT_CLEAR(head)

/* Helper: */
static INLINE unsigned
ht_improve_hash(unsigned h)
{
  /* Aim to protect against poor hash functions by adding logic here
   * - logic taken from java 1.4 hashtable source */
  h += ~(h << 9);
  h ^=  ((h >> 14) | (h << 18)); /* >>> */
  h +=  (h << 4);
  h ^=  ((h >> 10) | (h << 22)); /* >>> */
  return h;
}

/** Basic string hash function, from Java standard String.hashCode(). */
static INLINE unsigned
ht_string_hash(const char *s)
{
  unsigned h = 0;
  int m = 1;
  while (*s) {
    h += ((signed char)*s++)*m;
    m = (m<<5)-1; /* m *= 31 */
  }
  return h;
}

#define _HT_SET_HASH(elm, field, hashfn)        \
  do {                                          \
    elm->field.hte_hash = hashfn(elm);          \
  } while (0)

#define HT_FOREACH(x, name, head)                 \
  for ((x) = HT_START(name, head);                \
       (x) != NULL;                               \
       (x) = HT_NEXT(name, head, x))

#define HT_PROTOTYPE(name, type, field, hashfn, eqfn)                   \
  int name##_HT_GROW(struct name *ht, unsigned min_capacity);           \
  void name##_HT_CLEAR(struct name *ht);                                \
  int _##name##_HT_REP_OK(struct name *ht);                             \
  /* Helper: returns a pointer to the right location in the table       \
   * 'head' to find or insert the element 'elm'. */                     \
  static INLINE struct type **                                          \
  _##name##_HT_FIND_P(struct name *head, struct type *elm)              \
  {                                                                     \
    struct type **p;                                                    \
    if (!head->hth_table)                                               \
      return NULL;                                                      \
    p = &_HT_BUCKET(head, field, elm);                                  \
    while (*p) {                                                        \
      if (eqfn(*p, elm))                                                \
        return p;                                                       \
      p = &(*p)->field.hte_next;                                        \
    }                                                                   \
    return p;                                                           \
  }                                                                     \
  /* Return a pointer to the element in the table 'head' matching 'elm', \
   * or NULL if no such element exists */                               \
  static INLINE struct type *                                           \
  name##_HT_FIND(struct name *head, struct type *elm)                   \
  {                                                                     \
    struct type **p;                                                    \
    _HT_SET_HASH(elm, field, hashfn);                                   \
    p = _##name##_HT_FIND_P(head, elm);                                 \
    return p ? *p : NULL;                                               \
  }                                                                     \
  /* Insert the element 'elm' into the table 'head'.  Do not call this  \
   * function if the table might already contain a matching element. */ \
  static INLINE void                                                    \
  name##_HT_INSERT(struct name *head, struct type *elm)                 \
  {                                                                     \
    struct type **p;                                                    \
    if (!head->hth_table || head->hth_n_entries >= head->hth_load_limit) \
      name##_HT_GROW(head, head->hth_n_entries+1);                      \
    ++head->hth_n_entries;                                              \
    _HT_SET_HASH(elm, field, hashfn);                                   \
    p = &_HT_BUCKET(head, field, elm);                                  \
    elm->field.hte_next = *p;                                           \
    *p = elm;                                                           \
  }                                                                     \
  /* Insert the element 'elm' into the table 'head'. If there already   \
   * a matching element in the table, replace that element and return   \
   * it. */                                                             \
  static INLINE struct type *                                           \
  name##_HT_REPLACE(struct name *head, struct type *elm)                \
  {                                                                     \
    struct type **p, *r;                                                \
    if (!head->hth_table || head->hth_n_entries >= head->hth_load_limit) \
      name##_HT_GROW(head, head->hth_n_entries+1);                      \
    _HT_SET_HASH(elm, field, hashfn);                                   \
    p = _##name##_HT_FIND_P(head, elm);                                 \
    r = *p;                                                             \
    *p = elm;                                                           \
    if (r && (r!=elm)) {                                                \
      elm->field.hte_next = r->field.hte_next;                          \
      r->field.hte_next = NULL;                                         \
      return r;                                                         \
    } else {                                                            \
      ++head->hth_n_entries;                                            \
      return NULL;                                                      \
    }                                                                   \
  }                                                                     \
  /* Remove any element matching 'elm' from the table 'head'.  If such  \
   * an element is found, return it; otherwise return NULL. */          \
  static INLINE struct type *                                           \
  name##_HT_REMOVE(struct name *head, struct type *elm)                 \
  {                                                                     \
    struct type **p, *r;                                                \
    _HT_SET_HASH(elm, field, hashfn);                                   \
    p = _##name##_HT_FIND_P(head,elm);                                  \
    if (!p || !*p)                                                      \
      return NULL;                                                      \
    r = *p;                                                             \
    *p = r->field.hte_next;                                             \
    r->field.hte_next = NULL;                                           \
    --head->hth_n_entries;                                              \
    return r;                                                           \
  }                                                                     \
  /* Invoke the function 'fn' on every element of the table 'head',     \
   * using 'data' as its second argument.  If the function returns      \
   * nonzero, remove the most recently examined element before invoking \
   * the function again. */                                             \
  static INLINE void                                                    \
  name##_HT_FOREACH_FN(struct name *head,                               \
                       int (*fn)(struct type *, void *),                \
                       void *data)                                      \
  {                                                                     \
    /* XXXX use tricks to prevent concurrent mod? */                    \
    unsigned idx;                                                       \
    int remove;                                                         \
    struct type **p, **nextp, *next;                                    \
    if (!head->hth_table)                                               \
      return;                                                           \
    for (idx=0; idx < head->hth_table_length; ++idx) {                  \
      p = &head->hth_table[idx];                                        \
      while (*p) {                                                      \
        nextp = &(*p)->field.hte_next;                                  \
        next = *nextp;                                                  \
        remove = fn(*p, data);                                          \
        if (remove) {                                                   \
          --head->hth_n_entries;                                        \
          *p = next;                                                    \
        } else {                                                        \
          p = nextp;                                                    \
        }                                                               \
      }                                                                 \
    }                                                                   \
  }                                                                     \
  /* Return a pointer to the first element in the table 'head', under   \
   * an arbitrary order.  This order is stable under remove operations, \
   * but not under others. If the table is empty, return NULL. */       \
  static INLINE struct type **                                          \
  name##_HT_START(struct name *head)                                    \
  {                                                                     \
    unsigned b = 0;                                                     \
    while (b < head->hth_table_length) {                                \
      if (head->hth_table[b])                                           \
        return &head->hth_table[b];                                     \
      ++b;                                                              \
    }                                                                   \
    return NULL;                                                        \
  }                                                                     \
  /* Return the next element in 'head' after 'elm', under the arbitrary \
   * order used by HT_START.  If there are no more elements, return     \
   * NULL.  If 'elm' is to be removed from the table, you must call     \
   * this function for the next value before you remove it.             \
   */                                                                   \
  static INLINE struct type **                                          \
  name##_HT_NEXT(struct name *head, struct type **elm)                  \
  {                                                                     \
    if ((*elm)->field.hte_next) {                                       \
      return &(*elm)->field.hte_next;                                   \
    } else {                                                            \
      unsigned b = ((*elm)->field.hte_hash % head->hth_table_length)+1; \
      while (b < head->hth_table_length) {                              \
        if (head->hth_table[b])                                         \
          return &head->hth_table[b];                                   \
        ++b;                                                            \
      }                                                                 \
      return NULL;                                                      \
    }                                                                   \
  }                                                                     \
  static INLINE struct type **                                          \
  name##_HT_NEXT_RMV(struct name *head, struct type **elm)              \
  {                                                                     \
    unsigned h = (*elm)->field.hte_hash;                                \
    *elm = (*elm)->field.hte_next;                                      \
    --head->hth_n_entries;                                              \
    if (*elm) {                                                         \
      return elm;                                                       \
    } else {                                                            \
      unsigned b = (h % head->hth_table_length)+1;                      \
      while (b < head->hth_table_length) {                              \
        if (head->hth_table[b])                                         \
          return &head->hth_table[b];                                   \
        ++b;                                                            \
      }                                                                 \
      return NULL;                                                      \
    }                                                                   \
  }

#if 0
/* Helpers for an iterator type that saves some mod operations at the expense
 * of many branches. Not worth it, it seems. */

#define HT_ITER(type)                               \
  struct type##_ITER {                              \
    struct type **hti_nextp;                        \
    unsigned hti_bucket;                            \
  }

  static INLINE void                                                    \
  name##_HT_ITER_START(struct name *head, struct type##_ITER *iter)     \
  {                                                                     \
    /* XXXX Magic to stop modifications? */                             \
    iter->hti_bucket = 0;                                               \
    while (iter->hti_bucket < head->hth_table_length) {                 \
      iter->hti_nextp = &head->hth_table[iter->hti_bucket];             \
      if (*iter->hti_nextp)                                             \
        return;                                                         \
      ++iter->hti_bucket;                                               \
    }                                                                   \
    iter->hti_nextp = NULL;                                             \
  }                                                                     \
  static INLINE int                                                     \
  name##_HT_ITER_DONE(struct name *head, struct type##_ITER *iter)      \
  {                                                                     \
    return iter->hti_nextp == NULL;                                     \
  }                                                                     \
  static INLINE struct type *                                           \
  name##_HT_ITER_GET(struct name *head, struct type##_ITER *iter)       \
  {                                                                     \
    return *iter->hti_nextp;                                            \
  }                                                                     \
  static INLINE void                                                    \
  name##_HT_ITER_NEXT(struct name *head, struct type##_ITER *iter)      \
  {                                                                     \
    if (!iter->hti_nextp)                                               \
      return;                                                           \
    if ((*iter->hti_nextp)->field.hte_next) {                           \
      iter->hti_nextp = &(*iter->hti_nextp)->field.hte_next;            \
      return;                                                           \
    }                                                                   \
    while (++iter->hti_bucket < head->hth_table_length) {               \
      iter->hti_nextp = &head->hth_table[iter->hti_bucket];             \
      if (*iter->hti_nextp)                                             \
        return;                                                         \
      ++iter->hti_bucket;                                               \
    }                                                                   \
    iter->hti_nextp = NULL;                                             \
  }                                                                     \
  static INLINE void                                                    \
  name##_HT_ITER_NEXT_RMV(struct name *head, struct type##_ITER *iter)  \
  {                                                                     \
    if (!iter->hti_nextp)                                               \
      return;                                                           \
    --head->hth_n_entries;                                              \
    if ((*iter->hti_nextp)->field.hte_next) {                           \
      *iter->hti_nextp = (*iter->hti_nextp)->field.hte_next;            \
      if (*iter->hti_nextp)                                             \
        return;                                                         \
    }                                                                   \
    while (++iter->hti_bucket < head->hth_table_length) {               \
      iter->hti_nextp = &head->hth_table[iter->hti_bucket];             \
      if (*iter->hti_nextp)                                             \
        return;                                                         \
      ++iter->hti_bucket;                                               \
    }                                                                   \
    iter->hti_nextp = NULL;                                             \
  }
#endif

#define HT_GENERATE(name, type, field, hashfn, eqfn, load, mallocfn,    \
                    reallocfn, freefn)                                  \
  static unsigned name##_PRIMES[] = {                                   \
    53, 97, 193, 389,                                                   \
    769, 1543, 3079, 6151,                                              \
    12289, 24593, 49157, 98317,                                         \
    196613, 393241, 786433, 1572869,                                    \
    3145739, 6291469, 12582917, 25165843,                               \
    50331653, 100663319, 201326611, 402653189,                          \
    805306457, 1610612741                                               \
  };                                                                    \
  static unsigned name##_N_PRIMES =                                     \
    sizeof(name##_PRIMES)/sizeof(name##_PRIMES[0]);                     \
  /* Expand the internal table of 'head' until it is large enough to    \
   * hold 'size' elements.  Return 0 on success, -1 on allocation       \
   * failure. */                                                        \
  int                                                                   \
  name##_HT_GROW(struct name *head, unsigned size)                      \
  {                                                                     \
    unsigned new_len, new_load_limit;                                   \
    int prime_idx;                                                      \
    struct type **new_table;                                            \
    if (head->hth_prime_idx == (int)name##_N_PRIMES - 1)                \
      return 0;                                                         \
    if (head->hth_load_limit > size)                                    \
      return 0;                                                         \
    prime_idx = head->hth_prime_idx;                                    \
    do {                                                                \
      new_len = name##_PRIMES[++prime_idx];                             \
      new_load_limit = (unsigned)(load*new_len);                        \
    } while (new_load_limit <= size &&                                  \
             prime_idx < (int)name##_N_PRIMES);                         \
    if ((new_table = mallocfn(new_len*sizeof(struct type*)))) {         \
      unsigned b;                                                       \
      memset(new_table, 0, new_len*sizeof(struct type*));               \
      for (b = 0; b < head->hth_table_length; ++b) {                    \
        struct type *elm, *next;                                        \
        unsigned b2;                                                    \
        elm = head->hth_table[b];                                       \
        while (elm) {                                                   \
          next = elm->field.hte_next;                                   \
          b2 = elm->field.hte_hash % new_len;                           \
          elm->field.hte_next = new_table[b2];                          \
          new_table[b2] = elm;                                          \
          elm = next;                                                   \
        }                                                               \
      }                                                                 \
      if (head->hth_table)                                              \
        freefn(head->hth_table);                                        \
      head->hth_table = new_table;                                      \
    } else {                                                            \
      unsigned b, b2;                                                   \
      new_table = reallocfn(head->hth_table, new_len*sizeof(struct type*)); \
      if (!new_table) return -1;                                        \
      memset(new_table + head->hth_table_length, 0,                     \
             (new_len - head->hth_table_length)*sizeof(struct type*));  \
      for (b=0; b < head->hth_table_length; ++b) {                      \
        struct type *e, **pE;                                           \
        for (pE = &new_table[b], e = *pE; e != NULL; e = *pE) {         \
          b2 = e->field.hte_hash % new_len;                             \
          if (b2 == b) {                                                \
            pE = &e->field.hte_next;                                    \
          } else {                                                      \
            *pE = e->field.hte_next;                                    \
            e->field.hte_next = new_table[b2];                          \
            new_table[b2] = e;                                          \
          }                                                             \
        }                                                               \
      }                                                                 \
      head->hth_table = new_table;                                      \
    }                                                                   \
    head->hth_table_length = new_len;                                   \
    head->hth_prime_idx = prime_idx;                                    \
    head->hth_load_limit = new_load_limit;                              \
    return 0;                                                           \
  }                                                                     \
  /* Free all storage held by 'head'.  Does not free 'head' itself, or  \
   * individual elements. */                                            \
  void                                                                  \
  name##_HT_CLEAR(struct name *head)                                    \
  {                                                                     \
    if (head->hth_table)                                                \
      freefn(head->hth_table);                                          \
    head->hth_table_length = 0;                                         \
    HT_INIT(head);                                                      \
  }                                                                     \
  /* Debugging helper: return true iff the representation of 'head' is  \
   * internally consistent. */                                          \
  int                                                                   \
  _##name##_HT_REP_OK(struct name *head)                                \
  {                                                                     \
    unsigned n, i;                                                      \
    struct type *elm;                                                   \
    if (!head->hth_table_length) {                                      \
      return !head->hth_table && !head->hth_n_entries &&                \
        !head->hth_load_limit && head->hth_prime_idx == -1;             \
    }                                                                   \
    if (!head->hth_table || head->hth_prime_idx < 0 ||                  \
        !head->hth_load_limit)                                          \
      return 0;                                                         \
    if (head->hth_n_entries > head->hth_load_limit)                     \
      return 0;                                                         \
    if (head->hth_table_length != name##_PRIMES[head->hth_prime_idx])   \
      return 0;                                                         \
    if (head->hth_load_limit != (unsigned)(load*head->hth_table_length)) \
      return 0;                                                         \
    for (n = i = 0; i < head->hth_table_length; ++i) {                  \
      for (elm = head->hth_table[i]; elm; elm = elm->field.hte_next) {  \
        if (elm->field.hte_hash != hashfn(elm))                         \
          return 0;                                                     \
        if ((elm->field.hte_hash % head->hth_table_length) != i)        \
          return 0;                                                     \
        ++n;                                                            \
      }                                                                 \
    }                                                                   \
    if (n != head->hth_n_entries)                                       \
      return 0;                                                         \
    return 1;                                                           \
  }

/*
 * Copyright 2005, Nick Mathewson.  Implementation logic is adapted from code
 * by Cristopher Clark, retrofit to allow drop-in memory management, and to
 * use the same interface as Niels Provos's HT_H.  I'm not sure whether this
 * is a derived work any more, but whether it is or not, the license below
 * applies.
 *
 * Copyright (c) 2002, Christopher Clark
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#endif

