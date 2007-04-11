/* Copyright 2007 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id: /tor/trunk/src/common/util.c 12153 2007-03-12T03:11:12.797278Z nickm  $ */

/**
 * \file util.h
 * \brief Headers for mempool.c
 **/

#ifndef MEMPOOL_H
#define MEMPOOL_H

typedef struct mp_pool_t mp_pool_t;

void *mp_pool_get(mp_pool_t *pool);
void mp_pool_release(void *item);
mp_pool_t *mp_pool_new(size_t item_size, unsigned int n_per_chunk);
void mp_pool_clean(mp_pool_t *pool);
void mp_pool_destroy(mp_pool_t *pool);

#ifdef MEMPOOL_PRIVATE
typedef struct mp_allocated_t mp_allocated_t;
typedef struct mp_chunk_t mp_chunk_t;

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
struct mp_pool_t {
  mp_chunk_t *empty_chunks;
  mp_chunk_t *used_chunks;
  mp_chunk_t *full_chunks;
  int n_empty_chunks;
  size_t new_chunk_capacity;
  size_t item_alloc_size;
};
#endif

#endif

