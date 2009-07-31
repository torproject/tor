/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file buffers.c
 * \brief Implements a generic interface buffer.  Buffers are
 * fairly opaque string holders that can read to or flush from:
 * memory, file descriptors, or TLS connections.
 **/
#define BUFFERS_PRIVATE
#include "or.h"
#include "buffers.h"
#include "config.h"
#include "connection_edge.h"
#include "connection_or.h"
#include "control.h"
#include "reasons.h"
#include "../common/util.h"
#include "../common/torlog.h"
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

//#define PARANOIA

#ifdef PARANOIA
/** Helper: If PARANOIA is defined, assert that the buffer in local variable
 * <b>buf</b> is well-formed. */
#define check() STMT_BEGIN assert_buf_ok(buf); STMT_END
#else
#define check() STMT_NIL
#endif

/* Implementation notes:
 *
 * After flirting with memmove, and dallying with ring-buffers, we're finally
 * getting up to speed with the 1970s and implementing buffers as a linked
 * list of small chunks.  Each buffer has such a list; data is removed from
 * the head of the list, and added at the tail.  The list is singly linked,
 * and the buffer keeps a pointer to the head and the tail.
 *
 * Every chunk, except the tail, contains at least one byte of data.  Data in
 * each chunk is contiguous.
 *
 * When you need to treat the first N characters on a buffer as a contiguous
 * string, use the buf_pullup function to make them so.  Don't do this more
 * than necessary.
 *
 * The major free Unix kernels have handled buffers like this since, like,
 * forever.
 */

/* Chunk manipulation functions */

/** A single chunk on a buffer or in a freelist. */
typedef struct chunk_t {
  struct chunk_t *next; /**< The next chunk on the buffer or freelist. */
  size_t datalen; /**< The number of bytes stored in this chunk */
  size_t memlen; /**< The number of usable bytes of storage in <b>mem</b>. */
  char *data; /**< A pointer to the first byte of data stored in <b>mem</b>. */
  char mem[1]; /**< The actual memory used for storage in this chunk. May be
                * more than one byte long. */
} chunk_t;

#define CHUNK_HEADER_LEN STRUCT_OFFSET(chunk_t, mem[0])

/** Return the number of bytes needed to allocate a chunk to hold
 * <b>memlen</b> bytes. */
#define CHUNK_ALLOC_SIZE(memlen) (CHUNK_HEADER_LEN + (memlen))
/** Return the number of usable bytes in a chunk allocated with
 * malloc(<b>memlen</b>). */
#define CHUNK_SIZE_WITH_ALLOC(memlen) ((memlen) - CHUNK_HEADER_LEN)

/** Return the next character in <b>chunk</b> onto which data can be appended.
 * If the chunk is full, this might be off the end of chunk->mem. */
static INLINE char *
CHUNK_WRITE_PTR(chunk_t *chunk)
{
  return chunk->data + chunk->datalen;
}

/** Return the number of bytes that can be written onto <b>chunk</b> without
 * running out of space. */
static INLINE size_t
CHUNK_REMAINING_CAPACITY(const chunk_t *chunk)
{
  return (chunk->mem + chunk->memlen) - (chunk->data + chunk->datalen);
}

/** Move all bytes stored in <b>chunk</b> to the front of <b>chunk</b>->mem,
 * to free up space at the end. */
static INLINE void
chunk_repack(chunk_t *chunk)
{
  if (chunk->datalen && chunk->data != &chunk->mem[0]) {
    memmove(chunk->mem, chunk->data, chunk->datalen);
  }
  chunk->data = &chunk->mem[0];
}

#ifdef ENABLE_BUF_FREELISTS
/** A freelist of chunks. */
typedef struct chunk_freelist_t {
  size_t alloc_size; /**< What size chunks does this freelist hold? */
  int max_length; /**< Never allow more than this number of chunks in the
                   * freelist. */
  int slack; /**< When trimming the freelist, leave this number of extra
              * chunks beyond lowest_length.*/
  int cur_length; /**< How many chunks on the freelist now? */
  int lowest_length; /**< What's the smallest value of cur_length since the
                      * last time we cleaned this freelist? */
  uint64_t n_alloc;
  uint64_t n_free;
  uint64_t n_hit;
  chunk_t *head; /**< First chunk on the freelist. */
} chunk_freelist_t;

/** Macro to help define freelists. */
#define FL(a,m,s) { a, m, s, 0, 0, 0, 0, 0, NULL }

/** Static array of freelists, sorted by alloc_len, terminated by an entry
 * with alloc_size of 0. */
static chunk_freelist_t freelists[] = {
  FL(4096, 256, 8), FL(8192, 128, 4), FL(16384, 64, 4), FL(32768, 32, 2),
  FL(0, 0, 0)
};
#undef FL
/** How many times have we looked for a chunk of a size that no freelist
 * could help with? */
static uint64_t n_freelist_miss = 0;

static void assert_freelist_ok(chunk_freelist_t *fl);

/** Return the freelist to hold chunks of size <b>alloc</b>, or NULL if
 * no freelist exists for that size. */
static INLINE chunk_freelist_t *
get_freelist(size_t alloc)
{
  int i;
  for (i=0; freelists[i].alloc_size <= alloc; ++i) {
    if (freelists[i].alloc_size == alloc) {
      return &freelists[i];
    }
  }
  return NULL;
}

/** Deallocate a chunk or put it on a freelist */
static void
chunk_free_unchecked(chunk_t *chunk)
{
  size_t alloc;
  chunk_freelist_t *freelist;

  alloc = CHUNK_ALLOC_SIZE(chunk->memlen);
  freelist = get_freelist(alloc);
  if (freelist && freelist->cur_length < freelist->max_length) {
    chunk->next = freelist->head;
    freelist->head = chunk;
    ++freelist->cur_length;
  } else {
    if (freelist)
      ++freelist->n_free;
    tor_free(chunk);
  }
}

/** Allocate a new chunk with a given allocation size, or get one from the
 * freelist.  Note that a chunk with allocation size A can actually hold only
 * CHUNK_SIZE_WITH_ALLOC(A) bytes in its mem field. */
static INLINE chunk_t *
chunk_new_with_alloc_size(size_t alloc)
{
  chunk_t *ch;
  chunk_freelist_t *freelist;
  tor_assert(alloc >= sizeof(chunk_t));
  freelist = get_freelist(alloc);
  if (freelist && freelist->head) {
    ch = freelist->head;
    freelist->head = ch->next;
    if (--freelist->cur_length < freelist->lowest_length)
      freelist->lowest_length = freelist->cur_length;
    ++freelist->n_hit;
  } else {
    /* XXXX take advantage of tor_malloc_roundup, once we know how that
     * affects freelists. */
    if (freelist)
      ++freelist->n_alloc;
    else
      ++n_freelist_miss;
    ch = tor_malloc(alloc);
  }
  ch->next = NULL;
  ch->datalen = 0;
  ch->memlen = CHUNK_SIZE_WITH_ALLOC(alloc);
  ch->data = &ch->mem[0];
  return ch;
}
#else
static void
chunk_free_unchecked(chunk_t *chunk)
{
  tor_free(chunk);
}
static INLINE chunk_t *
chunk_new_with_alloc_size(size_t alloc)
{
  chunk_t *ch;
  ch = tor_malloc_roundup(&alloc);
  ch->next = NULL;
  ch->datalen = 0;
  ch->memlen = CHUNK_SIZE_WITH_ALLOC(alloc);
  ch->data = &ch->mem[0];
  return ch;
}
#endif

/** Expand <b>chunk</b> until it can hold <b>sz</b> bytes, and return a
 * new pointer to <b>chunk</b>.  Old pointers are no longer valid. */
static INLINE chunk_t *
chunk_grow(chunk_t *chunk, size_t sz)
{
  off_t offset;
  tor_assert(sz > chunk->memlen);
  offset = chunk->data - chunk->mem;
  chunk = tor_realloc(chunk, CHUNK_ALLOC_SIZE(sz));
  chunk->memlen = sz;
  chunk->data = chunk->mem + offset;
  return chunk;
}

/** If a read onto the end of a chunk would be smaller than this number, then
 * just start a new chunk. */
#define MIN_READ_LEN 8
/** Every chunk should take up at least this many bytes. */
#define MIN_CHUNK_ALLOC 256
/** No chunk should take up more than this many bytes. */
#define MAX_CHUNK_ALLOC 65536

/** Return the allocation size we'd like to use to hold <b>target</b>
 * bytes. */
static INLINE size_t
preferred_chunk_size(size_t target)
{
  size_t sz = MIN_CHUNK_ALLOC;
  while (CHUNK_SIZE_WITH_ALLOC(sz) < target) {
    sz <<= 1;
  }
  return sz;
}

/** Remove from the freelists most chunks that have not been used since the
 * last call to buf_shrink_freelists(). */
void
buf_shrink_freelists(int free_all)
{
#ifdef ENABLE_BUF_FREELISTS
  int i;
  for (i = 0; freelists[i].alloc_size; ++i) {
    int slack = freelists[i].slack;
    assert_freelist_ok(&freelists[i]);
    if (free_all || freelists[i].lowest_length > slack) {
      int n_to_free = free_all ? freelists[i].cur_length :
        (freelists[i].lowest_length - slack);
      int n_to_skip = freelists[i].cur_length - n_to_free;
      int orig_n_to_free = n_to_free, n_freed=0;
      int orig_n_to_skip = n_to_skip;
      int new_length = n_to_skip;
      chunk_t **chp = &freelists[i].head;
      chunk_t *chunk;
      log_info(LD_MM, "Cleaning freelist for %d-byte chunks: length %d, "
               "keeping %d, dropping %d.",
               (int)freelists[i].alloc_size, freelists[i].cur_length,
               n_to_skip, n_to_free);
      tor_assert(n_to_skip + n_to_free == freelists[i].cur_length);
      while (n_to_skip) {
        if (! (*chp)->next) {
          log_warn(LD_BUG, "I wanted to skip %d chunks in the freelist for "
                   "%d-byte chunks, but only found %d. (Length %d)",
                   orig_n_to_skip, (int)freelists[i].alloc_size,
                   orig_n_to_skip-n_to_skip, freelists[i].cur_length);
          assert_freelist_ok(&freelists[i]);
          return;
        }
        // tor_assert((*chp)->next);
        chp = &(*chp)->next;
        --n_to_skip;
      }
      chunk = *chp;
      *chp = NULL;
      while (chunk) {
        chunk_t *next = chunk->next;
        tor_free(chunk);
        chunk = next;
        --n_to_free;
        ++n_freed;
        ++freelists[i].n_free;
      }
      if (n_to_free) {
        log_warn(LD_BUG, "Freelist length for %d-byte chunks may have been "
                 "messed up somehow.", (int)freelists[i].alloc_size);
        log_warn(LD_BUG, "There were %d chunks at the start.  I decided to "
                 "keep %d. I wanted to free %d.  I freed %d.  I somehow think "
                 "I have %d left to free.",
                 freelists[i].cur_length, n_to_skip, orig_n_to_free,
                 n_freed, n_to_free);
      }
      // tor_assert(!n_to_free);
      freelists[i].cur_length = new_length;
    }
    freelists[i].lowest_length = freelists[i].cur_length;
    assert_freelist_ok(&freelists[i]);
  }
#else
  (void) free_all;
#endif
}

/** Describe the current status of the freelists at log level <b>severity</b>.
 */
void
buf_dump_freelist_sizes(int severity)
{
#ifdef ENABLE_BUF_FREELISTS
  int i;
  log(severity, LD_MM, "====== Buffer freelists:");
  for (i = 0; freelists[i].alloc_size; ++i) {
    uint64_t total = ((uint64_t)freelists[i].cur_length) *
      freelists[i].alloc_size;
    log(severity, LD_MM,
        U64_FORMAT" bytes in %d %d-byte chunks ["U64_FORMAT
        " misses; "U64_FORMAT" frees; "U64_FORMAT" hits]",
        U64_PRINTF_ARG(total),
        freelists[i].cur_length, (int)freelists[i].alloc_size,
        U64_PRINTF_ARG(freelists[i].n_alloc),
        U64_PRINTF_ARG(freelists[i].n_free),
        U64_PRINTF_ARG(freelists[i].n_hit));
  }
  log(severity, LD_MM, U64_FORMAT" allocations in non-freelist sizes",
      U64_PRINTF_ARG(n_freelist_miss));
#else
  (void)severity;
#endif
}

/** Magic value for buf_t.magic, to catch pointer errors. */
#define BUFFER_MAGIC 0xB0FFF312u
/** A resizeable buffer, optimized for reading and writing. */
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to
                   *   BUFFER_MAGIC. */
  size_t datalen; /**< How many bytes is this buffer holding right now? */
  size_t default_chunk_size; /**< Don't allocate any chunks smaller than
                              * this for this buffer. */
  chunk_t *head; /**< First chunk in the list, or NULL for none. */
  chunk_t *tail; /**< Last chunk in the list, or NULL for none. */
};

/** Collapse data from the first N chunks from <b>buf</b> into buf->head,
 * growing it as necessary, until buf->head has the first <b>bytes</b> bytes
 * of data from the buffer, or until buf->head has all the data in <b>buf</b>.
 *
 * If <b>nulterminate</b> is true, ensure that there is a 0 byte in
 * buf->head->mem right after all the data. */
static void
buf_pullup(buf_t *buf, size_t bytes, int nulterminate)
{
  chunk_t *dest, *src;
  size_t capacity;
  if (!buf->head)
    return;

  check();
  if (buf->datalen < bytes)
    bytes = buf->datalen;

  if (nulterminate) {
    capacity = bytes + 1;
    if (buf->head->datalen >= bytes && CHUNK_REMAINING_CAPACITY(buf->head)) {
      *CHUNK_WRITE_PTR(buf->head) = '\0';
      return;
    }
  } else {
    capacity = bytes;
    if (buf->head->datalen >= bytes)
      return;
  }

  if (buf->head->memlen >= capacity) {
    /* We don't need to grow the first chunk, but we might need to repack it.*/
    if (CHUNK_REMAINING_CAPACITY(buf->head) < capacity-buf->datalen)
      chunk_repack(buf->head);
    tor_assert(CHUNK_REMAINING_CAPACITY(buf->head) >= capacity-buf->datalen);
  } else {
    chunk_t *newhead;
    size_t newsize;
    /* We need to grow the chunk. */
    chunk_repack(buf->head);
    newsize = CHUNK_SIZE_WITH_ALLOC(preferred_chunk_size(capacity));
    newhead = chunk_grow(buf->head, newsize);
    tor_assert(newhead->memlen >= capacity);
    if (newhead != buf->head) {
      if (buf->tail == buf->head)
        buf->tail = newhead;
      buf->head = newhead;
    }
  }

  dest = buf->head;
  while (dest->datalen < bytes) {
    size_t n = bytes - dest->datalen;
    src = dest->next;
    tor_assert(src);
    if (n > src->datalen) {
      memcpy(CHUNK_WRITE_PTR(dest), src->data, src->datalen);
      dest->datalen += src->datalen;
      dest->next = src->next;
      if (buf->tail == src)
        buf->tail = dest;
      chunk_free_unchecked(src);
    } else {
      memcpy(CHUNK_WRITE_PTR(dest), src->data, n);
      dest->datalen += n;
      src->data += n;
      src->datalen -= n;
      tor_assert(dest->datalen == bytes);
    }
  }

  if (nulterminate) {
    tor_assert(CHUNK_REMAINING_CAPACITY(buf->head));
    *CHUNK_WRITE_PTR(buf->head) = '\0';
  }

  check();
}

/** Resize buf so it won't hold extra memory that we haven't been
 * using lately.
 */
void
buf_shrink(buf_t *buf)
{
  (void)buf;
}

/** Remove the first <b>n</b> bytes from buf. */
static INLINE void
buf_remove_from_front(buf_t *buf, size_t n)
{
  tor_assert(buf->datalen >= n);
  while (n) {
    tor_assert(buf->head);
    if (buf->head->datalen > n) {
      buf->head->datalen -= n;
      buf->head->data += n;
      buf->datalen -= n;
      return;
    } else {
      chunk_t *victim = buf->head;
      n -= victim->datalen;
      buf->datalen -= victim->datalen;
      buf->head = victim->next;
      if (buf->tail == victim)
        buf->tail = NULL;
      chunk_free_unchecked(victim);
    }
  }
  check();
}

/** Create and return a new buf with default chunk capacity <b>size</b>.
 */
buf_t *
buf_new_with_capacity(size_t size)
{
  buf_t *b = buf_new();
  b->default_chunk_size = preferred_chunk_size(size);
  return b;
}

/** Allocate and return a new buffer with default capacity. */
buf_t *
buf_new(void)
{
  buf_t *buf = tor_malloc_zero(sizeof(buf_t));
  buf->magic = BUFFER_MAGIC;
  buf->default_chunk_size = 4096;
  return buf;
}

/** Remove all data from <b>buf</b>. */
void
buf_clear(buf_t *buf)
{
  chunk_t *chunk, *next;
  buf->datalen = 0;
  for (chunk = buf->head; chunk; chunk = next) {
    next = chunk->next;
    chunk_free_unchecked(chunk);
  }
  buf->head = buf->tail = NULL;
}

/** Return the number of bytes stored in <b>buf</b> */
size_t
buf_datalen(const buf_t *buf)
{
  return buf->datalen;
}

/** Return the total length of all chunks used in <b>buf</b>. */
size_t
buf_allocation(const buf_t *buf)
{
  size_t total = 0;
  const chunk_t *chunk;
  for (chunk = buf->head; chunk; chunk = chunk->next) {
    total += chunk->memlen;
  }
  return total;
}

/** Return the number of bytes that can be added to <b>buf</b> without
 * performing any additional allocation. */
size_t
buf_slack(const buf_t *buf)
{
  if (!buf->tail)
    return 0;
  else
    return CHUNK_REMAINING_CAPACITY(buf->tail);
}

/** Release storage held by <b>buf</b>. */
void
buf_free(buf_t *buf)
{
  if (!buf)
    return;

  buf_clear(buf);
  buf->magic = 0xdeadbeef;
  tor_free(buf);
}

/** Append a new chunk with enough capacity to hold <b>capacity</b> bytes to
 * the tail of <b>buf</b>.  If <b>capped</b>, don't allocate a chunk bigger
 * than MAX_CHUNK_ALLOC. */
static chunk_t *
buf_add_chunk_with_capacity(buf_t *buf, size_t capacity, int capped)
{
  chunk_t *chunk;
  if (CHUNK_ALLOC_SIZE(capacity) < buf->default_chunk_size) {
    chunk = chunk_new_with_alloc_size(buf->default_chunk_size);
  } else if (capped && CHUNK_ALLOC_SIZE(capacity) > MAX_CHUNK_ALLOC) {
    chunk = chunk_new_with_alloc_size(MAX_CHUNK_ALLOC);
  } else {
    chunk = chunk_new_with_alloc_size(preferred_chunk_size(capacity));
  }
  if (buf->tail) {
    tor_assert(buf->head);
    buf->tail->next = chunk;
    buf->tail = chunk;
  } else {
    tor_assert(!buf->head);
    buf->head = buf->tail = chunk;
  }
  check();
  return chunk;
}

/** Read up to <b>at_most</b> bytes from the socket <b>fd</b> into
 * <b>chunk</b> (which must be on <b>buf</b>). If we get an EOF, set
 * *<b>reached_eof</b> to 1.  Return -1 on error, 0 on eof or blocking,
 * and the number of bytes read otherwise. */
static INLINE int
read_to_chunk(buf_t *buf, chunk_t *chunk, int fd, size_t at_most,
              int *reached_eof, int *socket_error)
{
  ssize_t read_result;
  if (at_most > CHUNK_REMAINING_CAPACITY(chunk))
    at_most = CHUNK_REMAINING_CAPACITY(chunk);
  read_result = tor_socket_recv(fd, CHUNK_WRITE_PTR(chunk), at_most, 0);

  if (read_result < 0) {
    int e = tor_socket_errno(fd);
    if (!ERRNO_IS_EAGAIN(e)) { /* it's a real error */
#ifdef MS_WINDOWS
      if (e == WSAENOBUFS)
        log_warn(LD_NET,"recv() failed: WSAENOBUFS. Not enough ram?");
#endif
      *socket_error = e;
      return -1;
    }
    return 0; /* would block. */
  } else if (read_result == 0) {
    log_debug(LD_NET,"Encountered eof on fd %d", (int)fd);
    *reached_eof = 1;
    return 0;
  } else { /* actually got bytes. */
    buf->datalen += read_result;
    chunk->datalen += read_result;
    log_debug(LD_NET,"Read %ld bytes. %d on inbuf.", (long)read_result,
              (int)buf->datalen);
    tor_assert(read_result < INT_MAX);
    return (int)read_result;
  }
}

/** As read_to_chunk(), but return (negative) error code on error, blocking,
 * or TLS, and the number of bytes read otherwise. */
static INLINE int
read_to_chunk_tls(buf_t *buf, chunk_t *chunk, tor_tls_t *tls,
                  size_t at_most)
{
  int read_result;

  tor_assert(CHUNK_REMAINING_CAPACITY(chunk) >= at_most);
  read_result = tor_tls_read(tls, CHUNK_WRITE_PTR(chunk), at_most);
  if (read_result < 0)
    return read_result;
  buf->datalen += read_result;
  chunk->datalen += read_result;
  return read_result;
}

/** Read from socket <b>s</b>, writing onto end of <b>buf</b>.  Read at most
 * <b>at_most</b> bytes, growing the buffer as necessary.  If recv() returns 0
 * (because of EOF), set *<b>reached_eof</b> to 1 and return 0. Return -1 on
 * error; else return the number of bytes read.
 */
/* XXXX021 indicate "read blocked" somehow? */
int
read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof,
            int *socket_error)
{
  /* XXXX021 It's stupid to overload the return values for these functions:
   * "error status" and "number of bytes read" are not mutually exclusive.
   */
  int r = 0;
  size_t total_read = 0;

  check();
  tor_assert(reached_eof);
  tor_assert(s >= 0);

  while (at_most > total_read) {
    size_t readlen = at_most - total_read;
    chunk_t *chunk;
    if (!buf->tail || CHUNK_REMAINING_CAPACITY(buf->tail) < MIN_READ_LEN) {
      chunk = buf_add_chunk_with_capacity(buf, at_most, 1);
      if (readlen > chunk->memlen)
        readlen = chunk->memlen;
    } else {
      size_t cap = CHUNK_REMAINING_CAPACITY(buf->tail);
      chunk = buf->tail;
      if (cap < readlen)
        readlen = cap;
    }

    r = read_to_chunk(buf, chunk, s, readlen, reached_eof, socket_error);
    check();
    if (r < 0)
      return r; /* Error */
    tor_assert(total_read+r < INT_MAX);
    total_read += r;
    if ((size_t)r < readlen) { /* eof, block, or no more to read. */
      break;
    }
  }
  return (int)total_read;
}

/** As read_to_buf, but reads from a TLS connection, and returns a TLS
 * status value rather than the number of bytes read.
 *
 * Using TLS on OR connections complicates matters in two ways.
 *
 * First, a TLS stream has its own read buffer independent of the
 * connection's read buffer.  (TLS needs to read an entire frame from
 * the network before it can decrypt any data.  Thus, trying to read 1
 * byte from TLS can require that several KB be read from the network
 * and decrypted.  The extra data is stored in TLS's decrypt buffer.)
 * Because the data hasn't been read by Tor (it's still inside the TLS),
 * this means that sometimes a connection "has stuff to read" even when
 * poll() didn't return POLLIN. The tor_tls_get_pending_bytes function is
 * used in connection.c to detect TLS objects with non-empty internal
 * buffers and read from them again.
 *
 * Second, the TLS stream's events do not correspond directly to network
 * events: sometimes, before a TLS stream can read, the network must be
 * ready to write -- or vice versa.
 */
int
read_to_buf_tls(tor_tls_t *tls, size_t at_most, buf_t *buf)
{
  int r = 0;
  size_t total_read = 0;
  check();

  while (at_most > total_read) {
    size_t readlen = at_most - total_read;
    chunk_t *chunk;
    if (!buf->tail || CHUNK_REMAINING_CAPACITY(buf->tail) < MIN_READ_LEN) {
      chunk = buf_add_chunk_with_capacity(buf, at_most, 1);
      if (readlen > chunk->memlen)
        readlen = chunk->memlen;
    } else {
      size_t cap = CHUNK_REMAINING_CAPACITY(buf->tail);
      chunk = buf->tail;
      if (cap < readlen)
        readlen = cap;
    }

    r = read_to_chunk_tls(buf, chunk, tls, readlen);
    check();
    if (r < 0)
      return r; /* Error */
    tor_assert(total_read+r < INT_MAX);
     total_read += r;
    if ((size_t)r < readlen) /* eof, block, or no more to read. */
      break;
  }
  return (int)total_read;
}

/** Helper for flush_buf(): try to write <b>sz</b> bytes from chunk
 * <b>chunk</b> of buffer <b>buf</b> onto socket <b>s</b>.  On success, deduct
 * the bytes written from *<b>buf_flushlen</b>.  Return the number of bytes
 * written on success, 0 on blocking, -1 on failure.
 */
static INLINE int
flush_chunk(int s, buf_t *buf, chunk_t *chunk, size_t sz,
            size_t *buf_flushlen)
{
  ssize_t write_result;

  if (sz > chunk->datalen)
    sz = chunk->datalen;
  write_result = tor_socket_send(s, chunk->data, sz, 0);

  if (write_result < 0) {
    int e = tor_socket_errno(s);
    if (!ERRNO_IS_EAGAIN(e)) { /* it's a real error */
#ifdef MS_WINDOWS
      if (e == WSAENOBUFS)
        log_warn(LD_NET,"write() failed: WSAENOBUFS. Not enough ram?");
#endif
      return -1;
    }
    log_debug(LD_NET,"write() would block, returning.");
    return 0;
  } else {
    *buf_flushlen -= write_result;
    buf_remove_from_front(buf, write_result);
    tor_assert(write_result < INT_MAX);
    return (int)write_result;
  }
}

/** Helper for flush_buf_tls(): try to write <b>sz</b> bytes from chunk
 * <b>chunk</b> of buffer <b>buf</b> onto socket <b>s</b>.  (Tries to write
 * more if there is a forced pending write size.)  On success, deduct the
 * bytes written from *<b>buf_flushlen</b>.  Return the number of bytes
 * written on success, and a TOR_TLS error code on failure or blocking.
 */
static INLINE int
flush_chunk_tls(tor_tls_t *tls, buf_t *buf, chunk_t *chunk,
                size_t sz, size_t *buf_flushlen)
{
  int r;
  size_t forced;
  char *data;

  forced = tor_tls_get_forced_write_size(tls);
  if (forced > sz)
    sz = forced;
  if (chunk) {
    data = chunk->data;
    tor_assert(sz <= chunk->datalen);
  } else {
    data = NULL;
    tor_assert(sz == 0);
  }
  r = tor_tls_write(tls, data, sz);
  if (r < 0)
    return r;
  if (*buf_flushlen > (size_t)r)
    *buf_flushlen -= r;
  else
    *buf_flushlen = 0;
  buf_remove_from_front(buf, r);
  log_debug(LD_NET,"flushed %d bytes, %d ready to flush, %d remain.",
            r,(int)*buf_flushlen,(int)buf->datalen);
  return r;
}

/** Write data from <b>buf</b> to the socket <b>s</b>.  Write at most
 * <b>sz</b> bytes, decrement *<b>buf_flushlen</b> by
 * the number of bytes actually written, and remove the written bytes
 * from the buffer.  Return the number of bytes written on success,
 * -1 on failure.  Return 0 if write() would block.
 */
int
flush_buf(int s, buf_t *buf, size_t sz, size_t *buf_flushlen)
{
  /* XXXX021 It's stupid to overload the return values for these functions:
   * "error status" and "number of bytes flushed" are not mutually exclusive.
   */
  int r;
  size_t flushed = 0;
  tor_assert(buf_flushlen);
  tor_assert(s >= 0);
  tor_assert(*buf_flushlen <= buf->datalen);
  tor_assert(sz <= *buf_flushlen);

  check();
  while (sz) {
    size_t flushlen0;
    tor_assert(buf->head);
    if (buf->head->datalen >= sz)
      flushlen0 = sz;
    else
      flushlen0 = buf->head->datalen;

    r = flush_chunk(s, buf, buf->head, flushlen0, buf_flushlen);
    check();
    if (r < 0)
      return r;
    flushed += r;
    sz -= r;
    if (r == 0 || (size_t)r < flushlen0) /* can't flush any more now. */
      break;
  }
  tor_assert(flushed < INT_MAX);
  return (int)flushed;
}

/** As flush_buf(), but writes data to a TLS connection.  Can write more than
 * <b>flushlen</b> bytes.
 */
int
flush_buf_tls(tor_tls_t *tls, buf_t *buf, size_t flushlen,
              size_t *buf_flushlen)
{
  int r;
  size_t flushed = 0;
  ssize_t sz;
  tor_assert(buf_flushlen);
  tor_assert(*buf_flushlen <= buf->datalen);
  tor_assert(flushlen <= *buf_flushlen);
  sz = (ssize_t) flushlen;

  /* we want to let tls write even if flushlen is zero, because it might
   * have a partial record pending */
  check_no_tls_errors();

  check();
  do {
    size_t flushlen0;
    if (buf->head) {
      if ((ssize_t)buf->head->datalen >= sz)
        flushlen0 = sz;
      else
        flushlen0 = buf->head->datalen;
    } else {
      flushlen0 = 0;
    }

    r = flush_chunk_tls(tls, buf, buf->head, flushlen0, buf_flushlen);
    check();
    if (r < 0)
      return r;
    flushed += r;
    sz -= r;
    if (r == 0) /* Can't flush any more now. */
      break;
  } while (sz > 0);
  tor_assert(flushed < INT_MAX);
  return (int)flushed;
}

/** Append <b>string_len</b> bytes from <b>string</b> to the end of
 * <b>buf</b>.
 *
 * Return the new length of the buffer on success, -1 on failure.
 */
int
write_to_buf(const char *string, size_t string_len, buf_t *buf)
{
  if (!string_len)
    return (int)buf->datalen;
  check();

  while (string_len) {
    size_t copy;
    if (!buf->tail || !CHUNK_REMAINING_CAPACITY(buf->tail))
      buf_add_chunk_with_capacity(buf, string_len, 1);

    copy = CHUNK_REMAINING_CAPACITY(buf->tail);
    if (copy > string_len)
      copy = string_len;
    memcpy(CHUNK_WRITE_PTR(buf->tail), string, copy);
    string_len -= copy;
    string += copy;
    buf->datalen += copy;
    buf->tail->datalen += copy;
  }

  check();
  tor_assert(buf->datalen < INT_MAX);
  return (int)buf->datalen;
}

/** Helper: copy the first <b>string_len</b> bytes from <b>buf</b>
 * onto <b>string</b>.
 */
static INLINE void
peek_from_buf(char *string, size_t string_len, const buf_t *buf)
{
  chunk_t *chunk;

  tor_assert(string);
  /* make sure we don't ask for too much */
  tor_assert(string_len <= buf->datalen);
  /* assert_buf_ok(buf); */

  chunk = buf->head;
  while (string_len) {
    size_t copy = string_len;
    tor_assert(chunk);
    if (chunk->datalen < copy)
      copy = chunk->datalen;
    memcpy(string, chunk->data, copy);
    string_len -= copy;
    string += copy;
    chunk = chunk->next;
  }
}

/** Remove <b>string_len</b> bytes from the front of <b>buf</b>, and store
 * them into <b>string</b>.  Return the new buffer size.  <b>string_len</b>
 * must be \<= the number of bytes on the buffer.
 */
int
fetch_from_buf(char *string, size_t string_len, buf_t *buf)
{
  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  check();
  peek_from_buf(string, string_len, buf);
  buf_remove_from_front(buf, string_len);
  check();
  tor_assert(buf->datalen < INT_MAX);
  return (int)buf->datalen;
}

/** Check <b>buf</b> for a variable-length cell according to the rules of link
 * protocol version <b>linkproto</b>.  If one is found, pull it off the buffer
 * and assign a newly allocated var_cell_t to *<b>out</b>, and return 1.
 * Return 0 if whatever is on the start of buf_t is not a variable-length
 * cell.  Return 1 and set *<b>out</b> to NULL if there seems to be the start
 * of a variable-length cell on <b>buf</b>, but the whole thing isn't there
 * yet. */
int
fetch_var_cell_from_buf(buf_t *buf, var_cell_t **out, int linkproto)
{
  char hdr[VAR_CELL_HEADER_SIZE];
  var_cell_t *result;
  uint8_t command;
  uint16_t length;
  /* If linkproto is unknown (0) or v2 (2), variable-length cells work as
   * implemented here. If it's 1, there are no variable-length cells.  Tor
   * does not support other versions right now, and so can't negotiate them.
   */
  if (linkproto == 1)
    return 0;
  check();
  *out = NULL;
  if (buf->datalen < VAR_CELL_HEADER_SIZE)
    return 0;
  peek_from_buf(hdr, sizeof(hdr), buf);

  command = get_uint8(hdr+2);
  if (!(CELL_COMMAND_IS_VAR_LENGTH(command)))
    return 0;

  length = ntohs(get_uint16(hdr+3));
  if (buf->datalen < (size_t)(VAR_CELL_HEADER_SIZE+length))
    return 1;
  result = var_cell_new(length);
  result->command = command;
  result->circ_id = ntohs(get_uint16(hdr));

  buf_remove_from_front(buf, VAR_CELL_HEADER_SIZE);
  peek_from_buf(result->payload, length, buf);
  buf_remove_from_front(buf, length);
  check();

  *out = result;
  return 1;
}

/** Move up to *<b>buf_flushlen</b> bytes from <b>buf_in</b> to
 * <b>buf_out</b>, and modify *<b>buf_flushlen</b> appropriately.
 * Return the number of bytes actually copied.
 */
int
move_buf_to_buf(buf_t *buf_out, buf_t *buf_in, size_t *buf_flushlen)
{
  /* XXXX we can do way better here, but this doesn't turn up in any
   * profiles. */
  char b[4096];
  size_t cp, len;
  len = *buf_flushlen;
  if (len > buf_in->datalen)
    len = buf_in->datalen;

  cp = len; /* Remember the number of bytes we intend to copy. */
  tor_assert(cp < INT_MAX);
  while (len) {
    /* This isn't the most efficient implementation one could imagine, since
     * it does two copies instead of 1, but I kinda doubt that this will be
     * critical path. */
    size_t n = len > sizeof(b) ? sizeof(b) : len;
    fetch_from_buf(b, n, buf_in);
    write_to_buf(b, n, buf_out);
    len -= n;
  }
  *buf_flushlen -= cp;
  return (int)cp;
}

/** Internal structure: represents a position in a buffer. */
typedef struct buf_pos_t {
  const chunk_t *chunk; /**< Which chunk are we pointing to? */
  int pos;/**< Which character inside the chunk's data are we pointing to? */
  size_t chunk_pos; /**< Total length of all previous chunks. */
} buf_pos_t;

/** Initialize <b>out</b> to point to the first character of <b>buf</b>.*/
static void
buf_pos_init(const buf_t *buf, buf_pos_t *out)
{
  out->chunk = buf->head;
  out->pos = 0;
  out->chunk_pos = 0;
}

/** Advance <b>out</b> to the first appearance of <b>ch</b> at the current
 * position of <b>out</b>, or later.  Return -1 if no instances are found;
 * otherwise returns the absolute position of the character. */
static off_t
buf_find_pos_of_char(char ch, buf_pos_t *out)
{
  const chunk_t *chunk;
  int pos;
  tor_assert(out);
  if (out->chunk) {
    if (out->chunk->datalen) {
      tor_assert(out->pos < (off_t)out->chunk->datalen);
    } else {
      tor_assert(out->pos == 0);
    }
  }
  pos = out->pos;
  for (chunk = out->chunk; chunk; chunk = chunk->next) {
    char *cp = memchr(chunk->data+pos, ch, chunk->datalen - pos);
    if (cp) {
      out->chunk = chunk;
      tor_assert(cp - chunk->data < INT_MAX);
      out->pos = (int)(cp - chunk->data);
      return out->chunk_pos + out->pos;
    } else {
      out->chunk_pos += chunk->datalen;
      pos = 0;
    }
  }
  return -1;
}

/** Advance <b>pos</b> by a single character, if there are any more characters
 * in the buffer.  Returns 0 on success, -1 on failure. */
static INLINE int
buf_pos_inc(buf_pos_t *pos)
{
  ++pos->pos;
  if (pos->pos == (off_t)pos->chunk->datalen) {
    if (!pos->chunk->next)
      return -1;
    pos->chunk_pos += pos->chunk->datalen;
    pos->chunk = pos->chunk->next;
    pos->pos = 0;
  }
  return 0;
}

/** Return true iff the <b>n</b>-character string in <b>s</b> appears
 * (verbatim) at <b>pos</b>. */
static int
buf_matches_at_pos(const buf_pos_t *pos, const char *s, size_t n)
{
  buf_pos_t p;
  if (!n)
    return 1;

  memcpy(&p, pos, sizeof(p));

  while (1) {
    char ch = p.chunk->data[p.pos];
    if (ch != *s)
      return 0;
    ++s;
    /* If we're out of characters that don't match, we match.  Check this
     * _before_ we test incrementing pos, in case we're at the end of the
     * string. */
    if (--n == 0)
      return 1;
    if (buf_pos_inc(&p)<0)
      return 0;
  }
}

/** Return the first position in <b>buf</b> at which the <b>n</b>-character
 * string <b>s</b> occurs, or -1 if it does not occur. */
/*private*/ int
buf_find_string_offset(const buf_t *buf, const char *s, size_t n)
{
  buf_pos_t pos;
  buf_pos_init(buf, &pos);
  while (buf_find_pos_of_char(*s, &pos) >= 0) {
    if (buf_matches_at_pos(&pos, s, n)) {
      tor_assert(pos.chunk_pos + pos.pos < INT_MAX);
      return (int)(pos.chunk_pos + pos.pos);
    } else {
      if (buf_pos_inc(&pos)<0)
        return -1;
    }
  }
  return -1;
}

/** There is a (possibly incomplete) http statement on <b>buf</b>, of the
 * form "\%s\\r\\n\\r\\n\%s", headers, body. (body may contain NULs.)
 * If a) the headers include a Content-Length field and all bytes in
 * the body are present, or b) there's no Content-Length field and
 * all headers are present, then:
 *
 *  - strdup headers into <b>*headers_out</b>, and NUL-terminate it.
 *  - memdup body into <b>*body_out</b>, and NUL-terminate it.
 *  - Then remove them from <b>buf</b>, and return 1.
 *
 *  - If headers or body is NULL, discard that part of the buf.
 *  - If a headers or body doesn't fit in the arg, return -1.
 *  (We ensure that the headers or body don't exceed max len,
 *   _even if_ we're planning to discard them.)
 *  - If force_complete is true, then succeed even if not all of the
 *    content has arrived.
 *
 * Else, change nothing and return 0.
 */
int
fetch_from_buf_http(buf_t *buf,
                    char **headers_out, size_t max_headerlen,
                    char **body_out, size_t *body_used, size_t max_bodylen,
                    int force_complete)
{
  char *headers, *p;
  size_t headerlen, bodylen, contentlen;
  int crlf_offset;

  check();
  if (!buf->head)
    return 0;

  crlf_offset = buf_find_string_offset(buf, "\r\n\r\n", 4);
  if (crlf_offset > (int)max_headerlen ||
      (crlf_offset < 0 && buf->datalen > max_headerlen)) {
    log_debug(LD_HTTP,"headers too long.");
    return -1;
  } else if (crlf_offset < 0) {
    log_debug(LD_HTTP,"headers not all here yet.");
    return 0;
  }
  /* Okay, we have a full header.  Make sure it all appears in the first
   * chunk. */
  if ((int)buf->head->datalen < crlf_offset + 4)
    buf_pullup(buf, crlf_offset+4, 0);
  headerlen = crlf_offset + 4;

  headers = buf->head->data;
  bodylen = buf->datalen - headerlen;
  log_debug(LD_HTTP,"headerlen %d, bodylen %d.", (int)headerlen, (int)bodylen);

  if (max_headerlen <= headerlen) {
    log_warn(LD_HTTP,"headerlen %d larger than %d. Failing.",
             (int)headerlen, (int)max_headerlen-1);
    return -1;
  }
  if (max_bodylen <= bodylen) {
    log_warn(LD_HTTP,"bodylen %d larger than %d. Failing.",
             (int)bodylen, (int)max_bodylen-1);
    return -1;
  }

#define CONTENT_LENGTH "\r\nContent-Length: "
  p = (char*) tor_memstr(headers, headerlen, CONTENT_LENGTH);
  if (p) {
    int i;
    i = atoi(p+strlen(CONTENT_LENGTH));
    if (i < 0) {
      log_warn(LD_PROTOCOL, "Content-Length is less than zero; it looks like "
               "someone is trying to crash us.");
      return -1;
    }
    contentlen = i;
    /* if content-length is malformed, then our body length is 0. fine. */
    log_debug(LD_HTTP,"Got a contentlen of %d.",(int)contentlen);
    if (bodylen < contentlen) {
      if (!force_complete) {
        log_debug(LD_HTTP,"body not all here yet.");
        return 0; /* not all there yet */
      }
    }
    if (bodylen > contentlen) {
      bodylen = contentlen;
      log_debug(LD_HTTP,"bodylen reduced to %d.",(int)bodylen);
    }
  }
  /* all happy. copy into the appropriate places, and return 1 */
  if (headers_out) {
    *headers_out = tor_malloc(headerlen+1);
    fetch_from_buf(*headers_out, headerlen, buf);
    (*headers_out)[headerlen] = 0; /* NUL terminate it */
  }
  if (body_out) {
    tor_assert(body_used);
    *body_used = bodylen;
    *body_out = tor_malloc(bodylen+1);
    fetch_from_buf(*body_out, bodylen, buf);
    (*body_out)[bodylen] = 0; /* NUL terminate it */
  }
  check();
  return 1;
}

/** There is a (possibly incomplete) socks handshake on <b>buf</b>, of one
 * of the forms
 *  - socks4: "socksheader username\\0"
 *  - socks4a: "socksheader username\\0 destaddr\\0"
 *  - socks5 phase one: "version #methods methods"
 *  - socks5 phase two: "version command 0 addresstype..."
 * If it's a complete and valid handshake, and destaddr fits in
 *   MAX_SOCKS_ADDR_LEN bytes, then pull the handshake off the buf,
 *   assign to <b>req</b>, and return 1.
 *
 * If it's invalid or too big, return -1.
 *
 * Else it's not all there yet, leave buf alone and return 0.
 *
 * If you want to specify the socks reply, write it into <b>req->reply</b>
 *   and set <b>req->replylen</b>, else leave <b>req->replylen</b> alone.
 *
 * If <b>log_sockstype</b> is non-zero, then do a notice-level log of whether
 * the connection is possibly leaking DNS requests locally or not.
 *
 * If <b>safe_socks</b> is true, then reject unsafe socks protocols.
 *
 * If returning 0 or -1, <b>req->address</b> and <b>req->port</b> are
 * undefined.
 */
int
fetch_from_buf_socks(buf_t *buf, socks_request_t *req,
                     int log_sockstype, int safe_socks)
{
  unsigned int len;
  char tmpbuf[TOR_ADDR_BUF_LEN+1];
  tor_addr_t destaddr;
  uint32_t destip;
  uint8_t socksver;
  enum {socks4, socks4a} socks4_prot = socks4a;
  char *next, *startaddr;
  struct in_addr in;

  /* If the user connects with socks4 or the wrong variant of socks5,
   * then log a warning to let him know that it might be unwise. */
  static int have_warned_about_unsafe_socks = 0;

  if (buf->datalen < 2) /* version and another byte */
    return 0;

  buf_pullup(buf, 128, 0);
  tor_assert(buf->head && buf->head->datalen >= 2);

  socksver = *buf->head->data;

  switch (socksver) { /* which version of socks? */

    case 5: /* socks5 */

      if (req->socks_version != 5) { /* we need to negotiate a method */
        unsigned char nummethods = (unsigned char)*(buf->head->data+1);
        tor_assert(!req->socks_version);
        if (buf->datalen < 2u+nummethods)
          return 0;
        buf_pullup(buf, 2u+nummethods, 0);
        if (!nummethods || !memchr(buf->head->data+2, 0, nummethods)) {
          log_warn(LD_APP,
                   "socks5: offered methods don't include 'no auth'. "
                   "Rejecting.");
          req->replylen = 2; /* 2 bytes of response */
          req->reply[0] = 5;
          req->reply[1] = '\xFF'; /* reject all methods */
          return -1;
        }
        /* remove packet from buf. also remove any other extraneous
         * bytes, to support broken socks clients. */
        buf_clear(buf);

        req->replylen = 2; /* 2 bytes of response */
        req->reply[0] = 5; /* socks5 reply */
        req->reply[1] = 0; /* tell client to use "none" auth method */
        req->socks_version = 5; /* remember we've already negotiated auth */
        log_debug(LD_APP,"socks5: accepted method 0");
        return 0;
      }
      /* we know the method; read in the request */
      log_debug(LD_APP,"socks5: checking request");
      if (buf->datalen < 8) /* basic info plus >=2 for addr plus 2 for port */
        return 0; /* not yet */
      tor_assert(buf->head->datalen >= 8);
      req->command = (unsigned char) *(buf->head->data+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE &&
          req->command != SOCKS_COMMAND_RESOLVE_PTR) {
        /* not a connect or resolve or a resolve_ptr? we don't support it. */
        log_warn(LD_APP,"socks5: command %d not recognized. Rejecting.",
                 req->command);
        return -1;
      }
      switch (*(buf->head->data+3)) { /* address type */
        case 1: /* IPv4 address */
        case 4: /* IPv6 address */ {
          const int is_v6 = *(buf->head->data+3) == 4;
          const unsigned addrlen = is_v6 ? 16 : 4;
          log_debug(LD_APP,"socks5: ipv4 address type");
          if (buf->datalen < 6+addrlen) /* ip/port there? */
            return 0; /* not yet */

          if (is_v6)
            tor_addr_from_ipv6_bytes(&destaddr, buf->head->data+4);
          else
            tor_addr_from_ipv4n(&destaddr, get_uint32(buf->head->data+4));

          tor_addr_to_str(tmpbuf, &destaddr, sizeof(tmpbuf), 1);

          if (strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
            log_warn(LD_APP,
                     "socks5 IP takes %d bytes, which doesn't fit in %d. "
                     "Rejecting.",
                     (int)strlen(tmpbuf)+1,(int)MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          strlcpy(req->address,tmpbuf,sizeof(req->address));
          req->port = ntohs(get_uint16(buf->head->data+4+addrlen));
          buf_remove_from_front(buf, 6+addrlen);
          if (req->command != SOCKS_COMMAND_RESOLVE_PTR &&
              !addressmap_have_mapping(req->address,0) &&
              !have_warned_about_unsafe_socks) {
            if (get_options()->WarnUnsafeSocks) {
              log_warn(LD_APP,
                  "Your application (using socks5 to port %d) is giving "
                  "Tor only an IP address. Applications that do DNS resolves "
                  "themselves may leak information. Consider using Socks4A "
                  "(e.g. via privoxy or socat) instead. For more information, "
                  "please see https://wiki.torproject.org/TheOnionRouter/"
                  "TorFAQ#SOCKSAndDNS.%s", req->port,
                  safe_socks ? " Rejecting." : "");
              /*have_warned_about_unsafe_socks = 1;*/
                                      /*(for now, warn every time)*/
            control_event_client_status(LOG_WARN,
                          "DANGEROUS_SOCKS PROTOCOL=SOCKS5 ADDRESS=%s:%d",
                          req->address, req->port);
            }
            if (safe_socks)
              return -1;
          }
          return 1;
        }
        case 3: /* fqdn */
          log_debug(LD_APP,"socks5: fqdn address type");
          if (req->command == SOCKS_COMMAND_RESOLVE_PTR) {
            log_warn(LD_APP, "socks5 received RESOLVE_PTR command with "
                     "hostname type. Rejecting.");
            return -1;
          }
          len = (unsigned char)*(buf->head->data+4);
          if (buf->datalen < 7+len) /* addr/port there? */
            return 0; /* not yet */
          buf_pullup(buf, 7+len, 0);
          tor_assert(buf->head->datalen >= 7+len);
          if (len+1 > MAX_SOCKS_ADDR_LEN) {
            log_warn(LD_APP,
                     "socks5 hostname is %d bytes, which doesn't fit in "
                     "%d. Rejecting.", len+1,MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          memcpy(req->address,buf->head->data+5,len);
          req->address[len] = 0;
          req->port = ntohs(get_uint16(buf->head->data+5+len));
          buf_remove_from_front(buf, 5+len+2);
          if (!tor_strisprint(req->address) || strchr(req->address,'\"')) {
            log_warn(LD_PROTOCOL,
                     "Your application (using socks5 to port %d) gave Tor "
                     "a malformed hostname: %s. Rejecting the connection.",
                     req->port, escaped(req->address));
            return -1;
          }
          if (log_sockstype)
            log_notice(LD_APP,
                  "Your application (using socks5 to port %d) gave "
                  "Tor a hostname, which means Tor will do the DNS resolve "
                  "for you. This is good.", req->port);
          return 1;
        default: /* unsupported */
          log_warn(LD_APP,"socks5: unsupported address type %d. Rejecting.",
                   (int) *(buf->head->data+3));
          return -1;
      }
      tor_assert(0);
    case 4: /* socks4 */
      /* http://archive.socks.permeo.com/protocol/socks4.protocol */
      /* http://archive.socks.permeo.com/protocol/socks4a.protocol */

      req->socks_version = 4;
      if (buf->datalen < SOCKS4_NETWORK_LEN) /* basic info available? */
        return 0; /* not yet */
      buf_pullup(buf, 1280, 0);
      req->command = (unsigned char) *(buf->head->data+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. (No resolve_ptr with
         * socks4.) */
        log_warn(LD_APP,"socks4: command %d not recognized. Rejecting.",
                 req->command);
        return -1;
      }

      req->port = ntohs(get_uint16(buf->head->data+2));
      destip = ntohl(get_uint32(buf->head->data+4));
      if ((!req->port && req->command!=SOCKS_COMMAND_RESOLVE) || !destip) {
        log_warn(LD_APP,"socks4: Port or DestIP is zero. Rejecting.");
        return -1;
      }
      if (destip >> 8) {
        log_debug(LD_APP,"socks4: destip not in form 0.0.0.x.");
        in.s_addr = htonl(destip);
        tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
        if (strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
          log_debug(LD_APP,"socks4 addr (%d bytes) too long. Rejecting.",
                    (int)strlen(tmpbuf));
          return -1;
        }
        log_debug(LD_APP,
                  "socks4: successfully read destip (%s)",
                  safe_str_client(tmpbuf));
        socks4_prot = socks4;
      }

      next = memchr(buf->head->data+SOCKS4_NETWORK_LEN, 0,
                    buf->head->datalen-SOCKS4_NETWORK_LEN);
      if (!next) {
        if (buf->head->datalen >= 1024) {
          log_debug(LD_APP, "Socks4 user name too long; rejecting.");
          return -1;
        }
        log_debug(LD_APP,"socks4: Username not here yet.");
        return 0;
      }
      tor_assert(next < CHUNK_WRITE_PTR(buf->head));

      startaddr = NULL;
      if (socks4_prot != socks4a &&
          !addressmap_have_mapping(tmpbuf,0) &&
          !have_warned_about_unsafe_socks) {
        if (get_options()->WarnUnsafeSocks) {
          log_warn(LD_APP,
                 "Your application (using socks4 to port %d) is giving Tor "
                 "only an IP address. Applications that do DNS resolves "
                 "themselves may leak information. Consider using Socks4A "
                 "(e.g. via privoxy or socat) instead. For more information, "
                 "please see https://wiki.torproject.org/TheOnionRouter/"
                 "TorFAQ#SOCKSAndDNS.%s", req->port,
                 safe_socks ? " Rejecting." : "");
          /*have_warned_about_unsafe_socks = 1;*/
          /*(for now, warn every time)*/
          control_event_client_status(LOG_WARN,
                        "DANGEROUS_SOCKS PROTOCOL=SOCKS4 ADDRESS=%s:%d",
                        tmpbuf, req->port);
        }
        if (safe_socks)
          return -1;
      }
      if (socks4_prot == socks4a) {
        if (next+1 == CHUNK_WRITE_PTR(buf->head)) {
          log_debug(LD_APP,"socks4: No part of destaddr here yet.");
          return 0;
        }
        startaddr = next+1;
        next = memchr(startaddr, 0, CHUNK_WRITE_PTR(buf->head)-startaddr);
        if (!next) {
          if (buf->head->datalen >= 1024) {
            log_debug(LD_APP,"socks4: Destaddr too long.");
            return -1;
          }
          log_debug(LD_APP,"socks4: Destaddr not all here yet.");
          return 0;
        }
        if (MAX_SOCKS_ADDR_LEN <= next-startaddr) {
          log_warn(LD_APP,"socks4: Destaddr too long. Rejecting.");
          return -1;
        }
        // tor_assert(next < buf->cur+buf->datalen);

        if (log_sockstype)
          log_notice(LD_APP,
                     "Your application (using socks4a to port %d) gave "
                     "Tor a hostname, which means Tor will do the DNS resolve "
                     "for you. This is good.", req->port);
      }
      log_debug(LD_APP,"socks4: Everything is here. Success.");
      strlcpy(req->address, startaddr ? startaddr : tmpbuf,
              sizeof(req->address));
      if (!tor_strisprint(req->address) || strchr(req->address,'\"')) {
        log_warn(LD_PROTOCOL,
                 "Your application (using socks4 to port %d) gave Tor "
                 "a malformed hostname: %s. Rejecting the connection.",
                 req->port, escaped(req->address));
        return -1;
      }
      /* next points to the final \0 on inbuf */
      buf_remove_from_front(buf, next - buf->head->data + 1);
      return 1;

    case 'G': /* get */
    case 'H': /* head */
    case 'P': /* put/post */
    case 'C': /* connect */
      strlcpy(req->reply,
"HTTP/1.0 501 Tor is not an HTTP Proxy\r\n"
"Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
"<html>\n"
"<head>\n"
"<title>Tor is not an HTTP Proxy</title>\n"
"</head>\n"
"<body>\n"
"<h1>Tor is not an HTTP Proxy</h1>\n"
"<p>\n"
"It appears you have configured your web browser to use Tor as an HTTP proxy."
"\n"
"This is not correct: Tor is a SOCKS proxy, not an HTTP proxy.\n"
"Please configure your client accordingly.\n"
"</p>\n"
"<p>\n"
"See <a href=\"https://www.torproject.org/documentation.html\">"
           "https://www.torproject.org/documentation.html</a> for more "
           "information.\n"
"<!-- Plus this comment, to make the body response more than 512 bytes, so "
"     IE will be willing to display it. Comment comment comment comment "
"     comment comment comment comment comment comment comment comment.-->\n"
"</p>\n"
"</body>\n"
"</html>\n"
             , MAX_SOCKS_REPLY_LEN);
      req->replylen = strlen(req->reply)+1;
      /* fall through */
    default: /* version is not socks4 or socks5 */
      log_warn(LD_APP,
               "Socks version %d not recognized. (Tor is not an http proxy.)",
               *(buf->head->data));
      {
        char *tmp = tor_strndup(buf->head->data, 8); /*XXXX what if longer?*/
        control_event_client_status(LOG_WARN,
                                    "SOCKS_UNKNOWN_PROTOCOL DATA=\"%s\"",
                                    escaped(tmp));
        tor_free(tmp);
      }
      return -1;
  }
}

/** Inspect a reply from SOCKS server stored in <b>buf</b> according
 * to <b>state</b>, removing the protocol data upon success. Return 0 on
 * incomplete response, 1 on success and -1 on error, in which case
 * <b>reason</b> is set to a descriptive message (free() when finished
 * with it).
 *
 * As a special case, 2 is returned when user/pass is required
 * during SOCKS5 handshake and user/pass is configured.
 */
int
fetch_from_buf_socks_client(buf_t *buf, int state, char **reason)
{
  unsigned char *data;
  size_t addrlen;

  if (buf->datalen < 2)
    return 0;

  buf_pullup(buf, 128, 0);
  tor_assert(buf->head && buf->head->datalen >= 2);

  data = (unsigned char *) buf->head->data;

  switch (state) {
    case PROXY_SOCKS4_WANT_CONNECT_OK:
      /* Wait for the complete response */
      if (buf->head->datalen < 8)
        return 0;

      if (data[1] != 0x5a) {
        *reason = tor_strdup(socks4_response_code_to_string(data[1]));
        return -1;
      }

      /* Success */
      buf_remove_from_front(buf, 8);
      return 1;

    case PROXY_SOCKS5_WANT_AUTH_METHOD_NONE:
      /* we don't have any credentials */
      if (data[1] != 0x00) {
        *reason = tor_strdup("server doesn't support any of our "
                             "available authentication methods");
        return -1;
      }

      log_info(LD_NET, "SOCKS 5 client: continuing without authentication");
      buf_clear(buf);
      return 1;

    case PROXY_SOCKS5_WANT_AUTH_METHOD_RFC1929:
      /* we have a username and password. return 1 if we can proceed without
       * providing authentication, or 2 otherwise. */
      switch (data[1]) {
        case 0x00:
          log_info(LD_NET, "SOCKS 5 client: we have auth details but server "
                            "doesn't require authentication.");
          buf_clear(buf);
          return 1;
        case 0x02:
          log_info(LD_NET, "SOCKS 5 client: need authentication.");
          buf_clear(buf);
          return 2;
        /* fall through */
      }

      *reason = tor_strdup("server doesn't support any of our available "
                           "authentication methods");
      return -1;

    case PROXY_SOCKS5_WANT_AUTH_RFC1929_OK:
      /* handle server reply to rfc1929 authentication */
      if (data[1] != 0x00) {
        *reason = tor_strdup("authentication failed");
        return -1;
      }

      log_info(LD_NET, "SOCKS 5 client: authentication successful.");
      buf_clear(buf);
      return 1;

    case PROXY_SOCKS5_WANT_CONNECT_OK:
      /* response is variable length. BND.ADDR, etc, isn't needed
       * (don't bother with buf_pullup()), but make sure to eat all
       * the data used */

      /* wait for address type field to arrive */
      if (buf->datalen < 4)
        return 0;

      switch (data[3]) {
        case 0x01: /* ip4 */
          addrlen = 4;
          break;
        case 0x04: /* ip6 */
          addrlen = 16;
          break;
        case 0x03: /* fqdn (can this happen here?) */
          if (buf->datalen < 5)
            return 0;
          addrlen = 1 + data[4];
          break;
        default:
          *reason = tor_strdup("invalid response to connect request");
          return -1;
      }

      /* wait for address and port */
      if (buf->datalen < 6 + addrlen)
        return 0;

      if (data[1] != 0x00) {
        *reason = tor_strdup(socks5_response_code_to_string(data[1]));
        return -1;
      }

      buf_remove_from_front(buf, 6 + addrlen);
      return 1;
  }

  /* shouldn't get here... */
  tor_assert(0);

  return -1;
}

/** Return 1 iff buf looks more like it has an (obsolete) v0 controller
 * command on it than any valid v1 controller command. */
int
peek_buf_has_control0_command(buf_t *buf)
{
  if (buf->datalen >= 4) {
    char header[4];
    uint16_t cmd;
    peek_from_buf(header, sizeof(header), buf);
    cmd = ntohs(get_uint16(header+2));
    if (cmd <= 0x14)
      return 1; /* This is definitely not a v1 control command. */
  }
  return 0;
}

/** Return the index within <b>buf</b> at which <b>ch</b> first appears,
 * or -1 if <b>ch</b> does not appear on buf. */
static off_t
buf_find_offset_of_char(buf_t *buf, char ch)
{
  chunk_t *chunk;
  off_t offset = 0;
  for (chunk = buf->head; chunk; chunk = chunk->next) {
    char *cp = memchr(chunk->data, ch, chunk->datalen);
    if (cp)
      return offset + (cp - chunk->data);
    else
      offset += chunk->datalen;
  }
  return -1;
}

/** Try to read a single LF-terminated line from <b>buf</b>, and write it,
 * NUL-terminated, into the *<b>data_len</b> byte buffer at <b>data_out</b>.
 * Set *<b>data_len</b> to the number of bytes in the line, not counting the
 * terminating NUL.  Return 1 if we read a whole line, return 0 if we don't
 * have a whole line yet, and return -1 if the line length exceeds
 * *<b>data_len</b>.
 */
int
fetch_from_buf_line(buf_t *buf, char *data_out, size_t *data_len)
{
  size_t sz;
  off_t offset;

  if (!buf->head)
    return 0;

  offset = buf_find_offset_of_char(buf, '\n');
  if (offset < 0)
    return 0;
  sz = (size_t) offset;
  if (sz+2 > *data_len) {
    *data_len = sz + 2;
    return -1;
  }
  fetch_from_buf(data_out, sz+1, buf);
  data_out[sz+1] = '\0';
  *data_len = sz+1;
  return 1;
}

/** Compress on uncompress the <b>data_len</b> bytes in <b>data</b> using the
 * zlib state <b>state</b>, appending the result to <b>buf</b>.  If
 * <b>done</b> is true, flush the data in the state and finish the
 * compression/uncompression.  Return -1 on failure, 0 on success. */
int
write_to_buf_zlib(buf_t *buf, tor_zlib_state_t *state,
                  const char *data, size_t data_len,
                  int done)
{
  char *next;
  size_t old_avail, avail;
  int over = 0;
  do {
    int need_new_chunk = 0;
    if (!buf->tail || ! CHUNK_REMAINING_CAPACITY(buf->tail)) {
      size_t cap = data_len / 4;
      buf_add_chunk_with_capacity(buf, cap, 1);
    }
    next = CHUNK_WRITE_PTR(buf->tail);
    avail = old_avail = CHUNK_REMAINING_CAPACITY(buf->tail);
    switch (tor_zlib_process(state, &next, &avail, &data, &data_len, done)) {
      case TOR_ZLIB_DONE:
        over = 1;
        break;
      case TOR_ZLIB_ERR:
        return -1;
      case TOR_ZLIB_OK:
        if (data_len == 0)
          over = 1;
        break;
      case TOR_ZLIB_BUF_FULL:
        if (avail) {
          /* Zlib says we need more room (ZLIB_BUF_FULL).  Start a new chunk
           * automatically, whether were going to or not. */
          need_new_chunk = 1;
        }
        break;
    }
    buf->datalen += old_avail - avail;
    buf->tail->datalen += old_avail - avail;
    if (need_new_chunk) {
      buf_add_chunk_with_capacity(buf, data_len/4, 1);
    }

  } while (!over);
  check();
  return 0;
}

/** Log an error and exit if <b>buf</b> is corrupted.
 */
void
assert_buf_ok(buf_t *buf)
{
  tor_assert(buf);
  tor_assert(buf->magic == BUFFER_MAGIC);

  if (! buf->head) {
    tor_assert(!buf->tail);
    tor_assert(buf->datalen == 0);
  } else {
    chunk_t *ch;
    size_t total = 0;
    tor_assert(buf->tail);
    for (ch = buf->head; ch; ch = ch->next) {
      total += ch->datalen;
      tor_assert(ch->datalen <= ch->memlen);
      tor_assert(ch->data >= &ch->mem[0]);
      tor_assert(ch->data < &ch->mem[0]+ch->memlen);
      tor_assert(ch->data+ch->datalen <= &ch->mem[0] + ch->memlen);
      if (!ch->next)
        tor_assert(ch == buf->tail);
    }
    tor_assert(buf->datalen == total);
  }
}

#ifdef ENABLE_BUF_FREELISTS
/** Log an error and exit if <b>fl</b> is corrupted.
 */
static void
assert_freelist_ok(chunk_freelist_t *fl)
{
  chunk_t *ch;
  int n;
  tor_assert(fl->alloc_size > 0);
  n = 0;
  for (ch = fl->head; ch; ch = ch->next) {
    tor_assert(CHUNK_ALLOC_SIZE(ch->memlen) == fl->alloc_size);
    ++n;
  }
  tor_assert(n == fl->cur_length);
  tor_assert(n >= fl->lowest_length);
  tor_assert(n <= fl->max_length);
}
#endif

