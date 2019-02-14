/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file map_anon.c
 * \brief Manage anonymous mappings.
 **/

#include "orconfig.h"
#include "lib/malloc/map_anon.h"
#include "lib/malloc/malloc.h"
#include "lib/err/torerr.h"

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_MACH_VM_INHERIT_H
#include <mach/vm_inherit.h>
#endif

#ifdef _WIN32
#include <windows.h>
#endif

/**
 * Macro to get the high bytes of a size_t, if there are high bytes.
 * Windows needs this; other operating systems define a size_t that does
 * what it should.
 */
#if SIZEOF_SIZE_T > 4
#define HIGH_SIZE_T_BYTES(sz) ((sz) >> 32)
#else
#define HIGH_SIZE_T_BYTES(sz) (0)
#endif

/* Here we define a MINHERIT macro that is minherit() or madvise(), depending
 * on what we actually want.
 *
 * If there's a flag that sets pages to zero after fork, we define FLAG_ZERO
 * to be that flag.  If there's a flag unmaps pages after fork, we define
 * FLAG_NOINHERIT to be that flag.
 */
#if defined(HAVE_MINHERIT)
#define MINHERIT minherit

#ifdef INHERIT_ZERO
#define FLAG_ZERO INHERIT_ZERO
#endif
#ifdef INHERIT_NONE
#define FLAG_NOINHERIT INHERIT_NONE
#elif defined(VM_INHERIT_NONE)
#define FLAG_NOINHERIT VM_INHERIT_NONE
#endif

#elif defined(HAVE_MADVISE)

#define MINHERIT madvise

#ifdef MADV_WIPEONFORK
#define FLAG_ZERO MADV_WIPEONFORK
#endif
#ifdef MADV_DONTFORK
#define FLAG_NOINHERIT MADV_DONTFORK
#endif

#endif

/**
 * Helper: try to prevent the <b>sz</b> bytes at <b>mem</b> from being swapped
 * to disk.  Return 0 on success or if the facility is not available on this
 * OS; return -1 on failure.
 */
static int
lock_mem(void *mem, size_t sz)
{
#ifdef _WIN32
  return VirtualLock(mem, sz) ? 0 : -1;
#elif defined(HAVE_MLOCK)
  return mlock(mem, sz);
#else
  (void) mem;
  (void) sz;

  return 0;
#endif
}

/**
 * Helper: try to prevent the <b>sz</b> bytes at <b>mem</b> from appearing in
 * a core dump.  Return 0 on success or if the facility is not available on
 * this OS; return -1 on failure.
 */
static int
nodump_mem(void *mem, size_t sz)
{
#if defined(MADV_DONTDUMP)
  return madvise(mem, sz, MADV_DONTDUMP);
#else
  (void) mem;
  (void) sz;
  return 0;
#endif
}

/**
 * Helper: try to prevent the <b>sz</b> bytes at <b>mem</b> from being
 * accessible in child processes -- ideally by having them set to 0 after a
 * fork, and if that doesn't work, by having them unmapped after a fork.
 * Return 0 on success or if the facility is not available on this OS; return
 * -1 on failure.
 */
static int
noinherit_mem(void *mem, size_t sz)
{
#ifdef FLAG_ZERO
  int r = MINHERIT(mem, sz, FLAG_ZERO);
  if (r == 0)
    return 0;
#endif
#ifdef FLAG_NOINHERIT
  return MINHERIT(mem, sz, FLAG_NOINHERIT);
#else
  (void)mem;
  (void)sz;
  return 0;
#endif
}

/**
 * Return a new anonymous memory mapping that holds <b>sz</b> bytes.
 *
 * Memory mappings are unlike the results from malloc() in that they are
 * handled separately by the operating system, and as such can have different
 * kernel-level flags set on them.
 *
 * The "flags" argument may be zero or more of ANONMAP_PRIVATE and
 * ANONMAP_NOINHERIT.
 *
 * Memory returned from this function must be released with
 * tor_munmap_anonymous().
 *
 * [Note: OS people use the word "anonymous" here to mean that the memory
 * isn't associated with any file. This has *nothing* to do with the kind of
 * anonymity that Tor is trying to provide.]
 */
void *
tor_mmap_anonymous(size_t sz, unsigned flags)
{
  void *ptr;
#if defined(_WIN32)
  HANDLE mapping = CreateFileMapping(INVALID_HANDLE_VALUE,
                                     NULL, /*attributes*/
                                     PAGE_READWRITE,
                                     HIGH_SIZE_T_BYTES(sz),
                                     sz & 0xffffffff,
                                     NULL /* name */);
  raw_assert(mapping != NULL);
  ptr = MapViewOfFile(mapping, FILE_MAP_WRITE,
                      0, 0, /* Offset */
                      0 /* Extend to end of mapping */);
  raw_assert(ptr);
  CloseHandle(mapping); /* mapped view holds a reference */
#elif defined(HAVE_SYS_MMAN_H)
  ptr = mmap(NULL, sz,
             PROT_READ|PROT_WRITE,
             MAP_ANON|MAP_PRIVATE,
             -1, 0);
  raw_assert(ptr != MAP_FAILED);
  raw_assert(ptr != NULL);
#else
  ptr = tor_malloc_zero(sz);
#endif

  if (flags & ANONMAP_PRIVATE) {
    int lock_result = lock_mem(ptr, sz);
    raw_assert(lock_result == 0);
    int nodump_result = nodump_mem(ptr, sz);
    raw_assert(nodump_result == 0);
  }

  if (flags & ANONMAP_NOINHERIT) {
    int noinherit_result = noinherit_mem(ptr, sz);
    raw_assert(noinherit_result == 0);
  }

  return ptr;
}

/**
 * Release <b>sz</b> bytes of memory that were previously mapped at
 * <b>mapping</b> by tor_mmap_anonymous().
 **/
void
tor_munmap_anonymous(void *mapping, size_t sz)
{
  if (!mapping)
    return;

#if defined(_WIN32)
  (void)sz;
  UnmapViewOfFile(mapping);
#elif defined(HAVE_SYS_MMAN_H)
  munmap(mapping, sz);
#else
  (void)sz;
  tor_free(mapping);
#endif
}
