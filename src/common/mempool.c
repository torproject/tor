/* Copyright 2007 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id: /tor/trunk/src/common/util.c 12153 2007-03-12T03:11:12.797278Z nickm  $ */
#include <stdlib.h>
#include <string.h>

#define MEMPOOL_PRIVATE
#include "mempool.h"

/* OVERVIEW:
 *   DOCDOC
 */

/* DRAWBACKS:
 *   - Not even slightly threadsafe.
 *   - Likes to have lots of items per chunks.
 *   - One pointer overhead per allocated thing.  (The alternative is
 *     something like glib's use of an RB-tree to keep track of what
 *     chunk any given piece of memory is in.)
 *   - Only aligns allocated things to void* level: redefign ALIGNMENT_TYPE
 *     if you need doubles.
 *   - Could probably be optimized a bit; the representation contains
 *     a bit more info than it really needs to have.
 *   - probably, chunks should always be a power of 2.
 */

/* NOTES:
 *   - The algorithm is similar to the one used by Python, but assumes that
 *     we'll know in advance which objects we want to pool, and doesn't
 *     try to handle a zillion objects of weird different sizes.
 */

#if 1
/* Tor dependencies */
#include "orconfig.h"
#include "util.h"
#include "compat.h"
#include "log.h"
#define ALLOC(x) tor_malloc(x)
#define FREE(x) tor_free(x)
#define ASSERT(x) tor_assert(x)
/* End Tor dependencies */
#else
#include <assert.h>
#define PREDICT_UNLIKELY(x) (x)
#define PREDICT_LIKELY(x) (x)
#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#define STRUCT_OFFSET(tp, member)                       \
  ((off_t) (((char*)&((tp*)0)->member)-(char*)0))
#define ASSERT(x) assert(x)
#endif

/* Tuning parameters */
/** DOCDOC */
#define ALIGNMENT_TYPE void *
/** DOCDOC */
#define ALIGNMENT sizeof(void*)
/** DOCDOC */
#define MAX_CHUNK (8*(1L<<20))
/** DOCDOC */
#define MIN_CHUNK 4096

typedef struct mp_allocated_t mp_allocated_t;

/** DOCDOC */
struct mp_allocated_t {
  mp_chunk_t *in_chunk;
  union {
    mp_allocated_t *next_free;
    char mem[1];
    ALIGNMENT_TYPE _dummy;
  };
};

/** DOCDOC */
struct mp_chunk_t {
  unsigned long magic;
  mp_chunk_t *next;
  mp_chunk_t *prev;
  mp_pool_t *pool;
  mp_allocated_t *first_free;
  int n_allocated;
  int capacity;
  size_t mem_size;
  char *next_mem;
  char mem[1];
};

/** DOCDOC */
#define MP_CHUNK_MAGIC 0x09870123

/** DOCDOC */
#define CHUNK_OVERHEAD (sizeof(mp_chunk_t)-1)

/** DOCDOC */
#define A2M(a) (&(a)->mem[0])
/** DOCDOC */
#define M2A(p) ( ((char*)p) - STRUCT_OFFSET(mp_allocated_t, mem) )

/* INVARIANT: every chunk can hold 2 or more items. */

/** DOCDOC */
static mp_chunk_t *
mp_chunk_new(mp_pool_t *pool)
{
  size_t sz = pool->new_chunk_capacity * pool->item_alloc_size;
  mp_chunk_t *chunk = ALLOC(CHUNK_OVERHEAD + sz);
  memset(chunk, 0, sizeof(mp_chunk_t)); /* Doesn't clear the whole thing. */
  chunk->magic = MP_CHUNK_MAGIC;
  chunk->capacity = pool->new_chunk_capacity;
  chunk->mem_size = sz;
  chunk->next_mem = chunk->mem;
  chunk->pool = pool;
  return chunk;
}

/** DOCDOC */
void *
mp_pool_get(mp_pool_t *pool)
{
  mp_chunk_t *chunk;
  mp_allocated_t *allocated;
  if (PREDICT_LIKELY(pool->used_chunks != NULL)) {
    chunk = pool->used_chunks;
  } else if (pool->empty_chunks) {
    /* Put the most recently emptied chunk on the used list. */
    chunk = pool->empty_chunks;
    pool->empty_chunks = chunk->next;
    if (chunk->next)
      chunk->next->prev = NULL;
    chunk->next = pool->used_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;
    ASSERT(!chunk->prev);
    --pool->n_empty_chunks;
  } else {
    /* Allocate a new chunk and add it to the used list. */
    chunk = mp_chunk_new(pool);
    chunk->next = pool->used_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;
    ASSERT(!chunk->prev);
  }

  ASSERT(chunk->n_allocated < chunk->capacity);

  if (chunk->first_free) {
    allocated = chunk->first_free;
    chunk->first_free = allocated->next_free;
    allocated->next_free = NULL; /* debugging */
  } else {
    ASSERT(chunk->next_mem + pool->item_alloc_size <=
           chunk->mem + chunk->mem_size);
    allocated = (void*)chunk->next_mem;
    chunk->next_mem += pool->item_alloc_size;
    allocated->in_chunk = chunk;
  }

  ++chunk->n_allocated;
  if (PREDICT_UNLIKELY(chunk->n_allocated == chunk->capacity)) {
    /* This is now a full chunk. */
    ASSERT(chunk == pool->used_chunks);
    ASSERT(chunk->prev == NULL);
    pool->used_chunks = chunk->next;
    if (chunk->next)
      chunk->next->prev = NULL;

    chunk->next = pool->full_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->full_chunks = chunk;
  }

  return A2M(allocated);
}

/** DOCDOC */
void
mp_pool_release(void *_item)
{
  mp_allocated_t *allocated = (void*) M2A(_item);
  mp_chunk_t *chunk = allocated->in_chunk;

  ASSERT(chunk);
  ASSERT(chunk->magic == MP_CHUNK_MAGIC);
  ASSERT(chunk->n_allocated > 0);

  allocated->next_free = chunk->first_free;
  chunk->first_free = allocated;

  if (PREDICT_UNLIKELY(chunk->n_allocated == chunk->capacity)) {
    /* This chunk was full and is about to be used. */
    mp_pool_t *pool = chunk->pool;
    /* unlink from full */
    if (chunk->prev)
      chunk->prev->next = chunk->next;
    if (chunk->next)
      chunk->next->prev = chunk->prev;
    if (chunk == pool->full_chunks)
      pool->full_chunks = chunk->next;

    /* link to used */
    chunk->next = pool->used_chunks;
    chunk->prev = NULL;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;
  } else if (PREDICT_UNLIKELY(chunk->n_allocated == 1)) {
    /* This was used and is about to be empty. */
    mp_pool_t *pool = chunk->pool;
    /* unlink from used */
    if (chunk->prev)
      chunk->prev->next = chunk->next;
    if (chunk->next)
      chunk->next->prev = chunk->prev;
    if (chunk == pool->used_chunks)
      pool->used_chunks = chunk->next;

    /* link to empty */
    chunk->next = pool->empty_chunks;
    chunk->prev = NULL;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->empty_chunks = chunk;

    /* reset guts to defragment this chunk. */
    chunk->first_free = NULL;
    chunk->next_mem = chunk->mem;

    ++pool->n_empty_chunks;
  }
  --chunk->n_allocated;
}

/** DOCDOC */
mp_pool_t *
mp_pool_new(size_t item_size, size_t chunk_capacity)
{
  mp_pool_t *pool;
  size_t alloc_size;

  pool = ALLOC(sizeof(mp_pool_t));
  memset(pool, 0, sizeof(mp_pool_t));

  /* First, minimal size with overhead. */
  alloc_size = STRUCT_OFFSET(mp_allocated_t, mem) + item_size;
  if (alloc_size < sizeof(mp_allocated_t))
    alloc_size = sizeof(mp_allocated_t);

  /* Then, round up to alignment. */
  if (alloc_size % ALIGNMENT) {
    alloc_size = alloc_size + ALIGNMENT - (alloc_size % ALIGNMENT);
  }
  if (alloc_size < ALIGNMENT)
    alloc_size = ALIGNMENT;

  ASSERT((alloc_size % ALIGNMENT) == 0);

  if (chunk_capacity > MAX_CHUNK)
    chunk_capacity = MAX_CHUNK;

  if (chunk_capacity < alloc_size * 2 + CHUNK_OVERHEAD)
    chunk_capacity = alloc_size * 2 + CHUNK_OVERHEAD;

  if (chunk_capacity < MIN_CHUNK) /* Guess system page size. */
    chunk_capacity = MIN_CHUNK;

  pool->new_chunk_capacity = (chunk_capacity-CHUNK_OVERHEAD) / alloc_size;
  pool->item_alloc_size = alloc_size;

  return pool;
}

/** DOCDOC */
void
mp_pool_clean(mp_pool_t *pool)
{
  if (pool->empty_chunks) {
    mp_chunk_t *next, *chunk = pool->empty_chunks->next;
    while (chunk) {
      next = chunk->next;
      FREE(chunk);
      chunk = next;
    }
    pool->empty_chunks->next = NULL;
    pool->n_empty_chunks = 1;
  }
}

/** DOCDOC */
static void
destroy_chunks(mp_chunk_t *chunk)
{
  mp_chunk_t *next;
  while (chunk) {
    chunk->magic = 0xd3adb33f;
    next = chunk->next;
    FREE(chunk);
    chunk = next;
  }
}

/** DOCDOC */
void
mp_pool_destroy(mp_pool_t *pool)
{
  destroy_chunks(pool->empty_chunks);
  destroy_chunks(pool->used_chunks);
  destroy_chunks(pool->full_chunks);
  memset(pool, 0xe0, sizeof(mp_pool_t));
  FREE(pool);
}

static int
assert_chunks_ok(mp_pool_t *pool, mp_chunk_t *chunk, int empty, int full)
{
  mp_allocated_t *allocated;
  int n = 0;
  if (chunk)
    ASSERT(chunk->prev == NULL);

  while (chunk) {
    n++;
    ASSERT(chunk->magic == MP_CHUNK_MAGIC);
    ASSERT(chunk->pool == pool);
    for (allocated = chunk->first_free; allocated;
         allocated = allocated->next_free) {
      ASSERT(allocated->in_chunk == chunk);
    }
    if (empty)
      ASSERT(chunk->n_allocated == 0);
    else if (full)
      ASSERT(chunk->n_allocated == chunk->capacity);
    else
      ASSERT(chunk->n_allocated > 0 && chunk->n_allocated < chunk->capacity);

    ASSERT(chunk->capacity == pool->new_chunk_capacity);

    ASSERT(chunk->mem_size ==
           pool->new_chunk_capacity * pool->item_alloc_size);

    ASSERT(chunk->next_mem >= chunk->mem &&
           chunk->next_mem <= chunk->mem + chunk->mem_size);

    if (chunk->next)
      ASSERT(chunk->next->prev == chunk);

    chunk = chunk->next;
  }
  return n;
}

void
mp_pool_assert_ok(mp_pool_t *pool)
{
  int n_empty;

  n_empty = assert_chunks_ok(pool, pool->empty_chunks, 1, 0);
  assert_chunks_ok(pool, pool->full_chunks, 0, 1);
  assert_chunks_ok(pool, pool->used_chunks, 0, 0);

  ASSERT(pool->n_empty_chunks == n_empty);
}

