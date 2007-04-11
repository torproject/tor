/* Copyright 2007 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */
#include <stdlib.h>
#include <string.h>

#define MEMPOOL_PRIVATE
#include "mempool.h"

/* OVERVIEW:
 *
 *     This is an implementation of memory pools for Tor cells.  It may be
 *     useful for you too.
 *
 *     Generally, a memory pool is an allocation strategy optimized for large
 *     numbers of identically-sized objects.  Rather than the elaborate arena
 *     and coalescing strategeis you need to get good performance for a
 *     general-purpose malloc(), pools use a series of large memory "chunks",
 *     each of which is carved into a bunch of smaller "items" or
 *     "allocations".
 *
 *     To get decent performance, you need to:
 *        - Minimize the number of times you hit the underlying allocator.
 *        - Try to keep accesses as local in memory as possible.
 *        - Try to keep the common case fast.
 *
 *     Our implementation uses three lists of chunks per pool.  Each chunk can
 *     be either "full" (no more room for items); "empty" (no items); or
 *     "used" (not full, not empty).  There are independent doubly-linked
 *     lists for each state.
 *
 * CREDIT:
 *
 *     I wrote this after looking at 3 or 4 other pooling allocators, but
 *     without copying.  The strategy this most resembles (which is funny,
 *     since that's the one I looked at longest ago) the pool allocator
 *     underlying Python's obmalloc code.  Major differences from obmalloc's
 *     pools are:
 *       - We don't even try to be threadsafe.
 *       - We only handle objects of one size.
 *       - Our list of empty chunks is doubly-linked, not singly-linked.
 *         (This could change pretty easily; it's only doubly-linked for
 *         consistency.)
 *       - We keep a list of full chunks (so we can have a "nuke everything"
 *         function).  Obmalloc's pools leave full chunks to float unanchored.
 *
 *         [XXXX020 Another way to support 'nuke everything' would be to keep
 *         _all_ the chunks in a doubly-linked-list.  This would have more
 *         space overhead per chunk, but less pointer manipulation overhead
 *         than the current approach.]
 *
 * LIMITATIONS:
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

#if 1
/* Tor dependencies */
#include "orconfig.h"
#include "util.h"
#include "compat.h"
#include "log.h"
#define ALLOC(x) tor_malloc(x)
#define FREE(x) tor_free(x)
#define ASSERT(x) tor_assert(x)
#undef ALLOC_CAN_RETURN_NULL
/* End Tor dependencies */
#else
/* If you're not building this as part of Tor, you'll want to define the
 * following macros.  For now, these should do as defaults.
 */
#include <assert.h>
#define PREDICT_UNLIKELY(x) (x)
#define PREDICT_LIKELY(x) (x)
#define ALLOC(x) malloc(x)
#define FREE(x) free(x)
#define STRUCT_OFFSET(tp, member)                       \
  ((off_t) (((char*)&((tp*)0)->member)-(char*)0))
#define ASSERT(x) assert(x)
#define ALLOC_CAN_RETURN_NULL
#endif

/* Tuning parameters */
/** Largest type that we need to ensure returned memory items are aligned to.
 * Change this to "double" if we need to be safe for structs with doubles. */
#define ALIGNMENT_TYPE void *
/** Increment that we need to align allocated  */
#define ALIGNMENT sizeof(ALIGNMENT_TYPE)
/** Largest memory chunk that we should allocate. */
#define MAX_CHUNK (8*(1L<<20))
/** Smallest memory chunk size that we should allocate. */
#define MIN_CHUNK 4096

typedef struct mp_allocated_t mp_allocated_t;
typedef struct mp_chunk_t mp_chunk_t;

/** Holds a single allocated item, allocated as part of a chunk. */
struct mp_allocated_t {
  /** The chunk that this item is allocated in.  This adds overhead to each
   * allocated item, thus making this implementation inappropriate for
   * very small items. */
  mp_chunk_t *in_chunk;
  union {
    /** If this item is free, the next item on the free list. */
    mp_allocated_t *next_free;
    /** If this item is not free, the actual memory contents of this item.
     * (Not actual size.) */
    char mem[1];
    /** An extra element to the union to insure correct alignment. */
    ALIGNMENT_TYPE _dummy;
  };
};

/** 'Magic' value used to detect memory corruption. */
#define MP_CHUNK_MAGIC 0x09870123

/** A chunk of memory.  Chunks come from malloc; we use them  */
struct mp_chunk_t {
  unsigned long magic; /**< Must be MP_CHUNK_MAGIC if this chunk is valid. */
  mp_chunk_t *next; /**< The next free, used, or full chunk in sequence. */
  mp_chunk_t *prev; /**< The previous free, used, or full chunk in sequence. */
  mp_pool_t *pool; /**< The pool that this chunk is part of */
  /** First free item in the freelist for this chunk.  Note that this may be
   * NULL even if this chunk is not at capacity: if so, the free memory at
   * next_mem has not yet been carved into items.
   */
  mp_allocated_t *first_free;
  int n_allocated; /**< Number of currently allocated items in this chunk */
  int capacity; /**< Largest number of items that can be fit into this chunk */
  size_t mem_size; /**< Number of usable bytes in mem. */
  char *next_mem; /**< Pointer into part of <b>mem</b> not yet carved up. */
  char mem[1]; /**< Storage for this chunk. (Not actual size.) */
};


/** Number of extra bytes needed beyond mem_size to allocate a chunk. */
#define CHUNK_OVERHEAD (sizeof(mp_chunk_t)-1)

/** Given a pointer to a mp_allocated_t, return a pointer to the memory
 * item it holds. */
#define A2M(a) (&(a)->mem[0])
/** Given a pointer to a memory_item_t, return a pointer to its enclosing
 * mp_allocated_t. */
#define M2A(p) ( ((char*)p) - STRUCT_OFFSET(mp_allocated_t, mem) )

#ifdef ALLOC_CAN_RETURN_NULL
/** If our ALLOC() macro can return NULL, check whether <b>x</b> is NULL,
 * and if so, return NULL. */
#define CHECK_ALLOC(x)                           \
  if (PREDICT_UNLIKELY(!x)) { return NULL; }
#else
/** If our ALLOC() macro can't return NULL, do nothing. */
#define CHECK_ALLOC(x)
#endif

/** Helper: Allocate and return a new memory chunk for <b>pool</b>.  Does not
 * link the chunk into any list. */
static mp_chunk_t *
mp_chunk_new(mp_pool_t *pool)
{
  size_t sz = pool->new_chunk_capacity * pool->item_alloc_size;
  mp_chunk_t *chunk = ALLOC(CHUNK_OVERHEAD + sz);
  CHECK_ALLOC(chunk);
  memset(chunk, 0, sizeof(mp_chunk_t)); /* Doesn't clear the whole thing. */
  chunk->magic = MP_CHUNK_MAGIC;
  chunk->capacity = pool->new_chunk_capacity;
  chunk->mem_size = sz;
  chunk->next_mem = chunk->mem;
  chunk->pool = pool;
  return chunk;
}

/** Return an newly allocated item from <b>pool</b>. */
void *
mp_pool_get(mp_pool_t *pool)
{
  mp_chunk_t *chunk;
  mp_allocated_t *allocated;

  if (PREDICT_LIKELY(pool->used_chunks != NULL)) {
    /* Common case: there is some chunk that is neither full nor empty.  Use
     * that one. (We can't use the full ones, obviously, and we should fill
     * up the used ones before we start on any empty ones. */
    chunk = pool->used_chunks;

  } else if (pool->empty_chunks) {
    /* We have no used chunks, but we have an empty chunk that we haven't
     * freed yet: use that.  (We pull from the front of the list, which should
     * get us the most recently emptied chunk.) */
    chunk = pool->empty_chunks;

    /* Remove the chunk from the empty list. */
    pool->empty_chunks = chunk->next;
    if (chunk->next)
      chunk->next->prev = NULL;

    /* Put the chunk on the 'used' list*/
    chunk->next = pool->used_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;

    ASSERT(!chunk->prev);
    --pool->n_empty_chunks;
    if (pool->n_empty_chunks < pool->min_empty_chunks)
      pool->min_empty_chunks = pool->n_empty_chunks;
  } else {
    /* We have no used or empty chunks: allocate a new chunk. */
    chunk = mp_chunk_new(pool);
    CHECK_ALLOC(chunk);

    /* Add the new chunk to the used list. */
    chunk->next = pool->used_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;
    ASSERT(!chunk->prev);
  }

  ASSERT(chunk->n_allocated < chunk->capacity);

  if (chunk->first_free) {
    /* If there's anything on the chunk's freelist, unlink it and use it. */
    allocated = chunk->first_free;
    chunk->first_free = allocated->next_free;
    allocated->next_free = NULL; /* For debugging; not really needed. */
    ASSERT(allocated->in_chunk == chunk);
  } else {
    /* Otherwise, the chunk had better have some free space left on it. */
    ASSERT(chunk->next_mem + pool->item_alloc_size <=
           chunk->mem + chunk->mem_size);

    /* Good, it did.  Let's carve off a bit of that free space, and use
     * that. */
    allocated = (void*)chunk->next_mem;
    chunk->next_mem += pool->item_alloc_size;
    allocated->in_chunk = chunk;
    allocated->next_free = NULL; /* For debugging; not really needed. */
  }

  ++chunk->n_allocated;

  if (PREDICT_UNLIKELY(chunk->n_allocated == chunk->capacity)) {
    /* This chunk just became full. */
    ASSERT(chunk == pool->used_chunks);
    ASSERT(chunk->prev == NULL);

    /* Take it off the used list. */
    pool->used_chunks = chunk->next;
    if (chunk->next)
      chunk->next->prev = NULL;

    /* Put it on the full list. */
    chunk->next = pool->full_chunks;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->full_chunks = chunk;
  }

  /* And return the memory portion of the mp_allocated_t. */
  return A2M(allocated);
}

/** Return an allocated memory item to its memory pool. */
void
mp_pool_release(void *item)
{
  mp_allocated_t *allocated = (void*) M2A(item);
  mp_chunk_t *chunk = allocated->in_chunk;

  ASSERT(chunk);
  ASSERT(chunk->magic == MP_CHUNK_MAGIC);
  ASSERT(chunk->n_allocated > 0);

  allocated->next_free = chunk->first_free;
  chunk->first_free = allocated;

  if (PREDICT_UNLIKELY(chunk->n_allocated == chunk->capacity)) {
    /* This chunk was full and is about to be used. */
    mp_pool_t *pool = chunk->pool;
    /* unlink from the full list  */
    if (chunk->prev)
      chunk->prev->next = chunk->next;
    if (chunk->next)
      chunk->next->prev = chunk->prev;
    if (chunk == pool->full_chunks)
      pool->full_chunks = chunk->next;

    /* link to the used list. */
    chunk->next = pool->used_chunks;
    chunk->prev = NULL;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->used_chunks = chunk;
  } else if (PREDICT_UNLIKELY(chunk->n_allocated == 1)) {
    /* This was used and is about to be empty. */
    mp_pool_t *pool = chunk->pool;

    /* Unlink from the used list */
    if (chunk->prev)
      chunk->prev->next = chunk->next;
    if (chunk->next)
      chunk->next->prev = chunk->prev;
    if (chunk == pool->used_chunks)
      pool->used_chunks = chunk->next;

    /* Link to the empty list */
    chunk->next = pool->empty_chunks;
    chunk->prev = NULL;
    if (chunk->next)
      chunk->next->prev = chunk;
    pool->empty_chunks = chunk;

    /* Reset the guts of this chunk to defragment it, in case it gets
     * used again. */
    chunk->first_free = NULL;
    chunk->next_mem = chunk->mem;

    ++pool->n_empty_chunks;
  }

  --chunk->n_allocated;
}

/** Allocate a new memory pool to hold items of size <b>item_size</b>. We'll
 * try to fit about <b>chunk_capacity</b> bytes in each chunk. */
mp_pool_t *
mp_pool_new(size_t item_size, size_t chunk_capacity)
{
  mp_pool_t *pool;
  size_t alloc_size;

  pool = ALLOC(sizeof(mp_pool_t));
  CHECK_ALLOC(pool);
  memset(pool, 0, sizeof(mp_pool_t));

  /* First, we figure out how much space to allow per item.  We'll want to
   * use make sure we have enough for the overhead plus the item size. */
  alloc_size = STRUCT_OFFSET(mp_allocated_t, mem) + item_size;
  /* If the item_size is less than sizeof(next_free), we need to make
   * the allocation bigger. */
  if (alloc_size < sizeof(mp_allocated_t))
    alloc_size = sizeof(mp_allocated_t);

  /* If we're not an even multiple of ALIGNMENT, round up. */
  if (alloc_size % ALIGNMENT) {
    alloc_size = alloc_size + ALIGNMENT - (alloc_size % ALIGNMENT);
  }
  if (alloc_size < ALIGNMENT)
    alloc_size = ALIGNMENT;
  ASSERT((alloc_size % ALIGNMENT) == 0);

  /* Now we figure out how many items fit in each chunk.  We need to fit at
   * least 2 items per chunk. No chunk can be more than MAX_CHUNK bytes long,
   * or less than MIN_CHUNK. */
  /* XXXX020 Try a bit harder here: we want to be a bit less than a power of
     2, not a bit over. */
  if (chunk_capacity > MAX_CHUNK)
    chunk_capacity = MAX_CHUNK;
  if (chunk_capacity < alloc_size * 2 + CHUNK_OVERHEAD)
    chunk_capacity = alloc_size * 2 + CHUNK_OVERHEAD;
  if (chunk_capacity < MIN_CHUNK)
    chunk_capacity = MIN_CHUNK;

  pool->new_chunk_capacity = (chunk_capacity-CHUNK_OVERHEAD) / alloc_size;
  pool->item_alloc_size = alloc_size;

  return pool;
}

/** If there are more than <b>n</b> empty chunks in <b>pool</b>, free the
 * exces ones that have been empty for the longest.   (If <b>n</b> is less
 * than zero, free only empty chunks that were not used since the last
 * call to mp_pool_clean(), leaving only -<b>n</b>.) */
void
mp_pool_clean(mp_pool_t *pool, int n)
{
  mp_chunk_t *chunk, **first_to_free;
  if (n < 0) {
    n = pool->min_empty_chunks + (-n);
    if (n < pool->n_empty_chunks)
      pool->min_empty_chunks = n;
  }
  ASSERT(n>=0);

  first_to_free = &pool->empty_chunks;
  while (*first_to_free && n > 0) {
    first_to_free = &(*first_to_free)->next;
    --n;
  }
  if (!*first_to_free)
    return;

  chunk = *first_to_free;
  while (chunk) {
    mp_chunk_t *next = chunk->next;
    chunk->magic = 0xdeadbeef;
    FREE(chunk);
    --pool->n_empty_chunks;
    chunk = next;
  }

  *first_to_free = NULL;
}

/** Helper: Given a list of chunks, free all the chunks in the list. */
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

/** Free all space held in <b>pool</b>  This makes all pointers returned from
 * mp_pool_get(<b>pool</b>) invalid. */
void
mp_pool_destroy(mp_pool_t *pool)
{
  destroy_chunks(pool->empty_chunks);
  destroy_chunks(pool->used_chunks);
  destroy_chunks(pool->full_chunks);
  memset(pool, 0xe0, sizeof(mp_pool_t));
  FREE(pool);
}

/** Helper: make sure that a given chunk list is not corrupt. */
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

/** Fail with an assertion if <b>pool</b> is not internally consistent. */
void
mp_pool_assert_ok(mp_pool_t *pool)
{
  int n_empty;

  n_empty = assert_chunks_ok(pool, pool->empty_chunks, 1, 0);
  assert_chunks_ok(pool, pool->full_chunks, 0, 1);
  assert_chunks_ok(pool, pool->used_chunks, 0, 0);

  ASSERT(pool->n_empty_chunks == n_empty);
}

