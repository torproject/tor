/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char buffers_c_id[] = "$Id$";

/**
 * \file buffers.c
 * \brief Abstractions for buffered IO.
 **/

#include "or.h"

#define SENTINELS
#undef CHECK_AFTER_RESIZE
#undef PARANOIA
#undef NOINLINE

#ifdef SENTINELS
/* If SENTINELS is defined, check for attempts to write beyond the
 * end/before the start of the buffer.
 */
#define START_MAGIC 0x70370370u
#define END_MAGIC 0xA0B0C0D0u
#define RAW_MEM(m) ((void*)(((char*)m)-4))
#define GUARDED_MEM(m) ((void*)(((char*)m)+4))
#define ALLOC_LEN(ln) ((ln)+8)
#define SET_GUARDS(m, ln) \
  do { set_uint32((m)-4,START_MAGIC); set_uint32((m)+ln,END_MAGIC); } while (0)
#else
#define RAW_MEM(m) (m)
#define GUARDED_MEM(m) (m)
#define ALLOC_LEN(ln) (ln)
#define SET_GUARDS(m,ln) do {} while (0)
#endif

#ifdef PARANOIA
#define check() do { assert_buf_ok(buf); } while (0)
#else
#define check() do { } while (0)
#endif

#ifdef NOINLINE
#undef INLINE
#define INLINE
#endif

#define BUFFER_MAGIC 0xB0FFF312u
struct buf_t {
  uint32_t magic; /**< Magic cookie for debugging: Must be set to BUFFER_MAGIC */
  char *mem;      /**< Storage for data in the buffer */
  char *cur;      /**< The first byte used for storing data in the buffer. */
  size_t highwater; /**< Largest observed datalen since last buf_shrink */
  size_t len;     /**< Maximum amount of data that <b>mem</b> can hold. */
  size_t datalen; /**< Number of bytes currently in <b>mem</b>. */
};

/** Size, in bytes, for newly allocated buffers.  Should be a power of 2. */
#define INITIAL_BUF_SIZE (4*1024)
/** Size, in bytes, for minimum 'shrink' size for buffers.  Buffers may start
 * out smaller than this, but they will never autoshrink to less
 * than this size. */
#define MIN_GREEDY_SHRINK_SIZE (16*1024)
#define MIN_LAZY_SHRINK_SIZE (4*1024)

static INLINE void peek_from_buf(char *string, size_t string_len, buf_t *buf);

static void buf_normalize(buf_t *buf)
{
  check();
  if (buf->cur + buf->datalen <= buf->mem+buf->len) {
    return;
  } else {
    char *newmem;
    size_t sz = (buf->mem+buf->len)-buf->cur;
    log_fn(LOG_WARN, "Unexpected non-normalized buffer.");
    newmem = GUARDED_MEM(tor_malloc(ALLOC_LEN(buf->len)));
    SET_GUARDS(newmem, buf->len);
    memcpy(newmem, buf->cur, sz);
    memcpy(newmem+sz, buf->mem, buf->datalen-sz);
    free(RAW_MEM(buf->mem));
    buf->mem = buf->cur = newmem;
    check();
  }
}

/** Return the point in the buffer where the next byte will get stored. */
static INLINE char *_buf_end(buf_t *buf)
{
  char *next = buf->cur + buf->datalen;
  char *end = buf->mem + buf->len;
  return (next < end) ? next : (next - buf->len);
}

/** If the pointer <b>cp</b> has passed beyond the end of the buffer, wrap it
 * around. */
static INLINE char *_wrap_ptr(buf_t *buf, char *cp) {
  return (cp >= buf->mem + buf->len) ? (cp - buf->len) : cp;
}

/** If the range of *<b>len</b> bytes starting at <b>at</b> wraps around the
 * end of the buffer, then set *<b>len</b> to the number of bytes starting
 * at <b>at</b>, and set *<b>more_len</b> to the number of bytes starting
 * at <b>buf-&gt;mem</b>.  Otherwise, set *<b>more_len</b> to 0.
 */
static INLINE void _split_range(buf_t *buf, char *at, size_t *len,
                                size_t *more_len)
{
  char *eos = at + *len;
  check();
  if (eos >= (buf->mem + buf->len)) {
    *more_len = eos - (buf->mem + buf->len);
    *len -= *more_len;
  } else {
    *more_len = 0;
  }
}

/** Change a buffer's capacity. <b>new_capacity</b> must be \>= buf->datalen. */
static void buf_resize(buf_t *buf, size_t new_capacity)
{
  off_t offset;
#ifdef CHECK_AFTER_RESIZE
  char *tmp, *tmp2;
#endif
  tor_assert(buf->datalen <= new_capacity);
  tor_assert(new_capacity);

#ifdef CHECK_AFTER_RESIZE
  assert_buf_ok(buf);
  tmp = tor_malloc(buf->datalen);
  tmp2 = tor_malloc(buf->datalen);
  peek_from_buf(tmp, buf->datalen, buf);
#endif

  if (buf->len == new_capacity)
    return;

  offset = buf->cur - buf->mem;
  if (offset + buf->datalen > new_capacity) {
    /* We need to move stuff before we shrink. */
    if (offset + buf->datalen > buf->len) {
      /* We have:
       *
       * mem[0] ... mem[datalen-(len-offset)] (end of data)
       * mem[offset] ... mem[len-1]           (the start of the data)
       *
       * We're shrinking the buffer by (len-new_capacity) bytes, so we need
       * to move the start portion back by that many bytes.
       */
      memmove(buf->cur-(buf->len-new_capacity), buf->cur,
              buf->len-offset);
      offset -= (buf->len-new_capacity);
    } else {
      /* The data doen't wrap around, but it does extend beyond the new
       * buffer length:
       *   mem[offset] ... mem[offset+datalen-1] (the data)
       */
      memmove(buf->mem, buf->cur, buf->datalen);
      offset = 0;
    }
  }
  buf->mem = GUARDED_MEM(tor_realloc(RAW_MEM(buf->mem),
                                     ALLOC_LEN(new_capacity)));
  SET_GUARDS(buf->mem, new_capacity);
  buf->cur = buf->mem+offset;
  if (offset + buf->datalen > buf->len) {
    /* We need to move data now that we are done growing.  The buffer
     * now contains:
     *
     * mem[0] ... mem[datalen-(len-offset)] (end of data)
     * mem[offset] ... mem[len-1]           (the start of the data)
     * mem[len]...mem[new_capacity]         (empty space)
     *
     * We're growing by (new_capacity-len) bytes, so we need to move the
     * end portion forward by that many bytes.
     */
    memmove(buf->cur+(new_capacity-buf->len), buf->cur,
            buf->len-offset);
    buf->cur += new_capacity-buf->len;
  }
  buf->len = new_capacity;

#ifdef CHECK_AFTER_RESIZE
  assert_buf_ok(buf);
  peek_from_buf(tmp2, buf->datalen, buf);
  if (memcmp(tmp, tmp2, buf->datalen)) {
    tor_assert(0);
  }
  tor_free(tmp);
  tor_free(tmp2);
#endif
}

/** If the buffer is not large enough to hold <b>capacity</b> bytes, resize
 * it so that it can.  (The new size will be a power of 2 times the old
 * size.)
 */
static INLINE int buf_ensure_capacity(buf_t *buf, size_t capacity)
{
  size_t new_len;
  if (buf->len >= capacity)  /* Don't grow if we're already big enough. */
    return 0;
  if (capacity > MAX_BUF_SIZE) /* Don't grow past the maximum. */
    return -1;
  /* Find the smallest new_len equal to (2**X)*len for some X; such that
   * new_len is at least capacity.
   */
  new_len = buf->len*2;
  while (new_len < capacity)
    new_len *= 2;
  /* Resize the buffer. */
  log_fn(LOG_DEBUG,"Growing buffer from %d to %d bytes.",
         (int)buf->len, (int)new_len);
  buf_resize(buf,new_len);
  return 0;
}

#if 0
/** If the buffer is at least 2*MIN_GREEDY_SHRINK_SIZE bytes in capacity,
 * and if the buffer is less than 1/8 full, shrink the buffer until
 * one of the above no longer holds.  (We shrink the buffer by
 * dividing by powers of 2.)
 */
static INLINE void buf_shrink_if_underfull(buf_t *buf) {
  size_t new_len;
  /* If the buffer is at least 1/8 full, or if shrinking the buffer would
   * put it under MIN_GREEDY_SHRINK_SIZE, don't do it. */
  if (buf->datalen >= (buf->len>>3) || buf->len < MIN_GREEDY_SHRINK_SIZE*2)
    return;
  /* Shrink new_len by powers of 2 until: datalen is at least 1/4 of
   * new_len, OR shrinking new_len more would put it under
   * MIN_GREEDY_SHRINK_SIZE.
   */
  new_len = (buf->len>>1);
  while (buf->datalen < (new_len>>3) && new_len > MIN_GREEDY_SHRINK_SIZE*2)
    new_len >>= 1;
  log_fn(LOG_DEBUG,"Shrinking buffer from %d to %d bytes.",
         (int)buf->len, (int)new_len);
  buf_resize(buf, new_len);
}
#else
#define buf_shrink_if_underfull(buf) do {} while (0)
#endif

/** Resize buf so it won't hold extra memory that we haven't been
 * using lately (that is, since the last time we called buf_shrink).
 * Try to shrink the buf until it is the largest factor of two that
 * can contain <b>buf</b>-&gt;highwater, but never smaller than
 * MIN_LAZY_SHRINK_SIZE.
 */
void
buf_shrink(buf_t *buf)
{
  size_t new_len;

  new_len = buf->len;
  while (buf->highwater < (new_len>>2) && new_len > MIN_LAZY_SHRINK_SIZE*2)
    new_len >>= 1;

  buf->highwater = buf->datalen;
  if (new_len == buf->len)
    return;

  log_fn(LOG_DEBUG,"Shrinking buffer from %d to %d bytes.",
         (int)buf->len, (int)new_len);
  buf_resize(buf, new_len);
}

/** Remove the first <b>n</b> bytes from buf.
 */
static INLINE void buf_remove_from_front(buf_t *buf, size_t n) {
  tor_assert(buf->datalen >= n);
  buf->datalen -= n;
  if (buf->datalen) {
    buf->cur = _wrap_ptr(buf, buf->cur+n);
  } else {
    buf->cur = buf->mem;
  }
  buf_shrink_if_underfull(buf);
  check();
}

/** Make sure that the memory in buf ends with a zero byte. */
static INLINE int buf_nul_terminate(buf_t *buf)
{
  if (buf_ensure_capacity(buf,buf->datalen+1)<0)
    return -1;
  *_buf_end(buf) = '\0';
  return 0;
}

/** Create and return a new buf with capacity <b>size</b>.
 */
buf_t *buf_new_with_capacity(size_t size) {
  buf_t *buf;
  buf = tor_malloc_zero(sizeof(buf_t));
  buf->magic = BUFFER_MAGIC;
  buf->cur = buf->mem = GUARDED_MEM(tor_malloc(ALLOC_LEN(size)));
  SET_GUARDS(buf->mem, size);
  buf->len = size;

  assert_buf_ok(buf);
  return buf;
}

/** Allocate and return a new buffer with default capacity. */
buf_t *buf_new()
{
  return buf_new_with_capacity(INITIAL_BUF_SIZE);
}

/** Remove all data from <b>buf</b> */
void buf_clear(buf_t *buf)
{
  buf->datalen = 0;
  buf->cur = buf->mem;
}

/** Return the number of bytes stored in <b>buf</b> */
size_t buf_datalen(const buf_t *buf)
{
  return buf->datalen;
}

/** Return the maximum bytes that can be stored in <b>buf</b> before buf
 * needs to resize. */
size_t buf_capacity(const buf_t *buf)
{
  return buf->len;
}

/** For testing only: Return a pointer to the raw memory stored in <b>buf</b>.
 */
const char *_buf_peek_raw_buffer(const buf_t *buf)
{
  return buf->cur;
}

/** Release storage held by <b>buf</b>.
 */
void buf_free(buf_t *buf) {
  assert_buf_ok(buf);
  buf->magic = 0xDEADBEEF;
  free(RAW_MEM(buf->mem));
  tor_free(buf);
}

static INLINE int read_to_buf_impl(int s, size_t at_most, buf_t *buf,
                            char *pos, int *reached_eof)
{
  int read_result;

//  log_fn(LOG_DEBUG,"reading at most %d bytes.",at_most);
  read_result = recv(s, pos, at_most, 0);
  if (read_result < 0) {
    int e = tor_socket_errno(s);
    if (!ERRNO_IS_EAGAIN(e)) { /* it's a real error */
      return -1;
    }
    return 0; /* would block. */
  } else if (read_result == 0) {
    log_fn(LOG_DEBUG,"Encountered eof");
    *reached_eof = 1;
    return 0;
  } else { /* we read some bytes */
    buf->datalen += read_result;
    if (buf->datalen > buf->highwater)
      buf->highwater = buf->datalen;
    log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf.",read_result,
           (int)buf->datalen);
    return read_result;
  }
}

/** Read from socket <b>s</b>, writing onto end of <b>buf</b>.  Read at most
 * <b>at_most</b> bytes, resizing the buffer as necessary.  If recv()
 * returns 0, set <b>*reached_eof</b> to 1 and return 0. Return -1 on error;
 * else return the number of bytes read.  Return 0 if recv() would
 * block.
 */
int read_to_buf(int s, size_t at_most, buf_t *buf, int *reached_eof)
{
  int r;
  char *next;
  size_t at_start;

  assert_buf_ok(buf);
  tor_assert(reached_eof);
  tor_assert(s>=0);

  if (buf_ensure_capacity(buf,buf->datalen+at_most))
    return -1;

  if (at_most + buf->datalen > buf->len)
    at_most = buf->len - buf->datalen; /* take the min of the two */

  if (at_most == 0)
    return 0; /* we shouldn't read anything */

  next = _buf_end(buf);
  _split_range(buf, next, &at_most, &at_start);

  r = read_to_buf_impl(s, at_most, buf, next, reached_eof);
  check();
  if (r < 0 || (size_t)r < at_most) {
    return r; /* Either error, eof, block, or no more to read. */
  }

  if (at_start) {
    int r2;
    tor_assert(_buf_end(buf) == buf->mem);
    r2 = read_to_buf_impl(s, at_start, buf, buf->mem, reached_eof);
    check();
    if (r2 < 0) {
      return r2;
    } else {
      r += r2;
    }
  }
  return r;
}

static INLINE int
read_to_buf_tls_impl(tor_tls *tls, size_t at_most, buf_t *buf, char *next)
{
  int r;

  log_fn(LOG_DEBUG,"before: %d on buf, %d pending, at_most %d.",
         (int)buf_datalen(buf), (int)tor_tls_get_pending_bytes(tls),
         (int)at_most);
  r = tor_tls_read(tls, next, at_most);
  if (r<0)
    return r;
  buf->datalen += r;
  if (buf->datalen > buf->highwater)
    buf->highwater = buf->datalen;
  log_fn(LOG_DEBUG,"Read %d bytes. %d on inbuf; %d pending",r,
         (int)buf->datalen,(int)tor_tls_get_pending_bytes(tls));
  return r;
}

/** As read_to_buf, but reads from a TLS connection.
 */
int read_to_buf_tls(tor_tls *tls, size_t at_most, buf_t *buf) {
  int r;
  char *next;
  size_t at_start;

  tor_assert(tls);
  assert_buf_ok(buf);

  log_fn(LOG_DEBUG,"start: %d on buf, %d pending, at_most %d.",
         (int)buf_datalen(buf), (int)tor_tls_get_pending_bytes(tls),
         (int)at_most);

  if (buf_ensure_capacity(buf, at_most+buf->datalen))
    return TOR_TLS_ERROR;

  if (at_most + buf->datalen > buf->len)
    at_most = buf->len - buf->datalen;

  if (at_most == 0)
    return 0;

  next = _buf_end(buf);
  _split_range(buf, next, &at_most, &at_start);

  r = read_to_buf_tls_impl(tls, at_most, buf, next);
  check();
  if (r < 0 || (size_t)r < at_most)
    return r; /* Either error, eof, block, or no more to read. */

  if (at_start) {
    int r2;
    tor_assert(_buf_end(buf) == buf->mem);
    r2 = read_to_buf_tls_impl(tls, at_start, buf, buf->mem);
    check();
    if (r2 < 0)
      return r2;
    else
      r += r2;
  }
  return r;
}

static INLINE int
flush_buf_impl(int s, buf_t *buf, size_t sz, size_t *buf_flushlen)
{
  int write_result;

  write_result = send(s, buf->cur, sz, 0);
  if (write_result < 0) {
    int e = tor_socket_errno(s);
    if (!ERRNO_IS_EAGAIN(e)) { /* it's a real error */
      return -1;
    }
    log_fn(LOG_DEBUG,"write() would block, returning.");
    return 0;
  } else {
    *buf_flushlen -= write_result;

    buf_remove_from_front(buf, write_result);

    return write_result;
  }
}

/** Write data from <b>buf</b> to the socket <b>s</b>.  Write at most
 * <b>*buf_flushlen</b> bytes, decrement <b>*buf_flushlen</b> by
 * the number of bytes actually written, and remove the written bytes
 * from the buffer.  Return the number of bytes written on success,
 * -1 on failure.  Return 0 if write() would block.
 */
int flush_buf(int s, buf_t *buf, size_t *buf_flushlen)
{
  int r;
  size_t flushed = 0;
  size_t flushlen0, flushlen1;

  assert_buf_ok(buf);
  tor_assert(buf_flushlen);
  tor_assert(s>=0);
  tor_assert(*buf_flushlen <= buf->datalen);

  if (*buf_flushlen == 0) /* nothing to flush */
    return 0;

  flushlen0 = *buf_flushlen;
  _split_range(buf, buf->cur, &flushlen0, &flushlen1);

  r = flush_buf_impl(s, buf, flushlen0, buf_flushlen);
  check();

  log_fn(LOG_DEBUG,"%d: flushed %d bytes, %d ready to flush, %d remain.",
           s,r,(int)*buf_flushlen,(int)buf->datalen);
  if (r < 0 || (size_t)r < flushlen0)
    return r; /* Error, or can't flush any more now. */
  flushed = r;

  if (flushlen1) {
    tor_assert(buf->cur == buf->mem);
    r = flush_buf_impl(s, buf, flushlen1, buf_flushlen);
    check();
    log_fn(LOG_DEBUG,"%d: flushed %d bytes, %d ready to flush, %d remain.",
           s,r,(int)*buf_flushlen,(int)buf->datalen);
    if (r<0)
      return r;
    flushed += r;
  }
  return flushed;
}

static INLINE int
flush_buf_tls_impl(tor_tls *tls, buf_t *buf, size_t sz, size_t *buf_flushlen)
{
  int r;

  r = tor_tls_write(tls, buf->cur, sz);
  if (r < 0) {
    return r;
  }
  *buf_flushlen -= r;
  buf_remove_from_front(buf, r);
  log_fn(LOG_DEBUG,"flushed %d bytes, %d ready to flush, %d remain.",
         r,(int)*buf_flushlen,(int)buf->datalen);
  return r;
}

/** As flush_buf, but writes data to a TLS connection.
 */
int flush_buf_tls(tor_tls *tls, buf_t *buf, size_t *buf_flushlen)
{
  int r;
  size_t flushed=0;
  size_t flushlen0, flushlen1;
  assert_buf_ok(buf);
  tor_assert(tls);
  tor_assert(buf_flushlen);

  /* we want to let tls write even if flushlen is zero, because it might
   * have a partial record pending */
  check_no_tls_errors();

  flushlen0 = *buf_flushlen;
  _split_range(buf, buf->cur, &flushlen0, &flushlen1);

  r = flush_buf_tls_impl(tls, buf, flushlen0, buf_flushlen);
  check();
  if (r < 0 || (size_t)r < flushlen0)
    return r; /* Error, or can't flush any more now. */
  flushed = r;

  if (flushlen1) {
    tor_assert(buf->cur == buf->mem);
    r = flush_buf_tls_impl(tls, buf, flushlen1, buf_flushlen);
    check();
    if (r<0)
      return r;
    flushed += r;
  }
  return flushed;
}

/** Append <b>string_len</b> bytes from <b>string</b> to the end of
 * <b>buf</b>.
 *
 * Return the new length of the buffer on success, -1 on failure.
 */
int
write_to_buf(const char *string, size_t string_len, buf_t *buf)
{
  char *next;
  size_t len2;

  /* append string to buf (growing as needed, return -1 if "too big")
   * return total number of bytes on the buf
   */

  tor_assert(string);
  assert_buf_ok(buf);

  if (buf_ensure_capacity(buf, buf->datalen+string_len)) {
    log_fn(LOG_WARN, "buflen too small, can't hold %d bytes.", (int)(buf->datalen+string_len));
    return -1;
  }

  next = _buf_end(buf);
  _split_range(buf, next, &string_len, &len2);

  memcpy(next, string, string_len);
  buf->datalen += string_len;

  if (len2) {
    tor_assert(_buf_end(buf) == buf->mem);
    memcpy(buf->mem, string+string_len, len2);
    buf->datalen += len2;
  }
  if (buf->datalen > buf->highwater)
    buf->highwater = buf->datalen;
  log_fn(LOG_DEBUG,"added %d bytes to buf (now %d total).",(int)string_len, (int)buf->datalen);
  check();
  return buf->datalen;
}

static INLINE void peek_from_buf(char *string, size_t string_len, buf_t *buf)
{
  size_t len2;

  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  tor_assert(string);
  tor_assert(string_len <= buf->datalen); /* make sure we don't ask for too much */
  assert_buf_ok(buf);

  _split_range(buf, buf->cur, &string_len, &len2);

  memcpy(string, buf->cur, string_len);
  if (len2) {
    memcpy(string+string_len,buf->mem,len2);
  }
}

/** Remove <b>string_len</b> bytes from the front of <b>buf</b>, and store them
 * into <b>string</b>.  Return the new buffer size.  <b>string_len</b> must be \<=
 * the number of bytes on the buffer.
 */
int fetch_from_buf(char *string, size_t string_len, buf_t *buf)
{
  /* There must be string_len bytes in buf; write them onto string,
   * then memmove buf back (that is, remove them from buf).
   *
   * Return the number of bytes still on the buffer. */

  check();
  peek_from_buf(string, string_len, buf);
  buf_remove_from_front(buf, string_len);
  check();
  return buf->datalen;
}

/** There is a (possibly incomplete) http statement on <b>buf</b>, of the
 * form "\%s\\r\\n\\r\\n\%s", headers, body. (body may contain nuls.)
 * If a) the headers include a Content-Length field and all bytes in
 * the body are present, or b) there's no Content-Length field and
 * all headers are present, then:
 *
 *  - strdup headers into <b>*headers_out</b>, and nul-terminate it.
 *  - memdup body into <b>*body_out</b>, and nul-terminate it.
 *  - Then remove them from <b>buf</b>, and return 1.
 *
 *  - If headers or body is NULL, discard that part of the buf.
 *  - If a headers or body doesn't fit in the arg, return -1.
 *  (We ensure that the headers or body don't exceed max len,
 *   _even if_ we're planning to discard them.)
 *
 * Else, change nothing and return 0.
 */
int fetch_from_buf_http(buf_t *buf,
                        char **headers_out, size_t max_headerlen,
                        char **body_out, size_t *body_used, size_t max_bodylen) {
  char *headers, *body, *p;
  size_t headerlen, bodylen, contentlen;

  assert_buf_ok(buf);
  buf_normalize(buf);

  if (buf_nul_terminate(buf)<0) {
    log_fn(LOG_WARN,"Couldn't nul-terminate buffer");
    return -1;
  }
  headers = buf->cur;
  body = strstr(headers,"\r\n\r\n");
  if (!body) {
    log_fn(LOG_DEBUG,"headers not all here yet.");
    return 0;
  }
  body += 4; /* Skip the the CRLFCRLF */
  headerlen = body-headers; /* includes the CRLFCRLF */
  bodylen = buf->datalen - headerlen;
  log_fn(LOG_DEBUG,"headerlen %d, bodylen %d.", (int)headerlen, (int)bodylen);

  if (max_headerlen <= headerlen) {
    log_fn(LOG_WARN,"headerlen %d larger than %d. Failing.", (int)headerlen,
           (int)max_headerlen-1);
    return -1;
  }
  if (max_bodylen <= bodylen) {
    log_fn(LOG_WARN,"bodylen %d larger than %d. Failing.", (int)bodylen, (int)max_bodylen-1);
    return -1;
  }

#define CONTENT_LENGTH "\r\nContent-Length: "
  p = strstr(headers, CONTENT_LENGTH);
  if (p) {
    int i;
    i = atoi(p+strlen(CONTENT_LENGTH));
    if (i < 0) {
      log_fn(LOG_WARN, "Content-Length is less than zero; it looks like someone is trying to crash us.");
      return -1;
    }
    contentlen = i;
    /* if content-length is malformed, then our body length is 0. fine. */
    log_fn(LOG_DEBUG,"Got a contentlen of %d.",(int)contentlen);
    if (bodylen < contentlen) {
      log_fn(LOG_DEBUG,"body not all here yet.");
      return 0; /* not all there yet */
    }
    if (bodylen > contentlen) {
      bodylen = contentlen;
      log_fn(LOG_DEBUG,"bodylen reduced to %d.",(int)bodylen);
    }
  }
  /* all happy. copy into the appropriate places, and return 1 */
  if (headers_out) {
    *headers_out = tor_malloc(headerlen+1);
    memcpy(*headers_out,buf->cur,headerlen);
    (*headers_out)[headerlen] = 0; /* null terminate it */
  }
  if (body_out) {
    tor_assert(body_used);
    *body_used = bodylen;
    *body_out = tor_malloc(bodylen+1);
    memcpy(*body_out,buf->cur+headerlen,bodylen);
    (*body_out)[bodylen] = 0; /* null terminate it */
  }
  buf_remove_from_front(buf, headerlen+bodylen);
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
 * If returning 0 or -1, <b>req->address</b> and <b>req->port</b> are undefined.
 */
int fetch_from_buf_socks(buf_t *buf, socks_request_t *req) {
  unsigned char len;
  char tmpbuf[INET_NTOA_BUF_LEN];
  uint32_t destip;
  enum {socks4, socks4a} socks4_prot = socks4a;
  char *next, *startaddr;
  struct in_addr in;

  /* If the user connects with socks4 or the wrong variant of socks5,
   * then log a warning to let him know that it might be unwise. */
  static int have_warned_about_unsafe_socks = 0;

  if (buf->datalen < 2) /* version and another byte */
    return 0;
  buf_normalize(buf);

  switch (*(buf->cur)) { /* which version of socks? */

    case 5: /* socks5 */

      if (req->socks_version != 5) { /* we need to negotiate a method */
        unsigned char nummethods = (unsigned char)*(buf->cur+1);
        tor_assert(!req->socks_version);
        if (buf->datalen < 2u+nummethods)
          return 0;
        if (!nummethods || !memchr(buf->cur+2, 0, nummethods)) {
          log_fn(LOG_WARN,"socks5: offered methods don't include 'no auth'. Rejecting.");
          req->replylen = 2; /* 2 bytes of response */
          req->reply[0] = 5;
          req->reply[1] = '\xFF'; /* reject all methods */
          return -1;
        }
        buf_remove_from_front(buf,2+nummethods);/* remove packet from buf */

        req->replylen = 2; /* 2 bytes of response */
        req->reply[0] = 5; /* socks5 reply */
        req->reply[1] = SOCKS5_SUCCEEDED;
        req->socks_version = 5; /* remember that we've already negotiated auth */
        log_fn(LOG_DEBUG,"socks5: accepted method 0");
        return 0;
      }
      /* we know the method; read in the request */
      log_fn(LOG_DEBUG,"socks5: checking request");
      if (buf->datalen < 8) /* basic info plus >=2 for addr plus 2 for port */
        return 0; /* not yet */
      req->command = (unsigned char) *(buf->cur+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. */
        log_fn(LOG_WARN,"socks5: command %d not recognized. Rejecting.",
               req->command);
        return -1;
      }
      switch (*(buf->cur+3)) { /* address type */
        case 1: /* IPv4 address */
          log_fn(LOG_DEBUG,"socks5: ipv4 address type");
          if (buf->datalen < 10) /* ip/port there? */
            return 0; /* not yet */

          destip = ntohl(*(uint32_t*)(buf->cur+4));
          in.s_addr = htonl(destip);
          tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
          if (strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
            log_fn(LOG_WARN,"socks5 IP takes %d bytes, which doesn't fit in %d. Rejecting.",
                   (int)strlen(tmpbuf)+1,(int)MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          strlcpy(req->address,tmpbuf,sizeof(req->address));
          req->port = ntohs(*(uint16_t*)(buf->cur+8));
          buf_remove_from_front(buf, 10);
          if (!have_warned_about_unsafe_socks) {
            log_fn(LOG_WARN,"Your application (using socks5 on port %d) is giving Tor only an IP address. Applications that do DNS resolves themselves may leak information. Consider using Socks4A (e.g. via privoxy or socat) instead.", req->port);
//            have_warned_about_unsafe_socks = 1; // (for now, warn every time)
          }
          return 1;
        case 3: /* fqdn */
          log_fn(LOG_DEBUG,"socks5: fqdn address type");
          len = (unsigned char)*(buf->cur+4);
          if (buf->datalen < 7u+len) /* addr/port there? */
            return 0; /* not yet */
          if (len+1 > MAX_SOCKS_ADDR_LEN) {
            log_fn(LOG_WARN,"socks5 hostname is %d bytes, which doesn't fit in %d. Rejecting.",
                   len+1,MAX_SOCKS_ADDR_LEN);
            return -1;
          }
          memcpy(req->address,buf->cur+5,len);
          req->address[len] = 0;
          req->port = ntohs(get_uint16(buf->cur+5+len));
          buf_remove_from_front(buf, 5+len+2);
          return 1;
        default: /* unsupported */
          log_fn(LOG_WARN,"socks5: unsupported address type %d. Rejecting.",*(buf->cur+3));
          return -1;
      }
      tor_assert(0);
    case 4: /* socks4 */
      /* http://archive.socks.permeo.com/protocol/socks4.protocol */
      /* http://archive.socks.permeo.com/protocol/socks4a.protocol */

      req->socks_version = 4;
      if (buf->datalen < SOCKS4_NETWORK_LEN) /* basic info available? */
        return 0; /* not yet */

      req->command = (unsigned char) *(buf->cur+1);
      if (req->command != SOCKS_COMMAND_CONNECT &&
          req->command != SOCKS_COMMAND_RESOLVE) {
        /* not a connect or resolve? we don't support it. */
        log_fn(LOG_WARN,"socks4: command %d not recognized. Rejecting.",
               req->command);
        return -1;
      }

      req->port = ntohs(*(uint16_t*)(buf->cur+2));
      destip = ntohl(*(uint32_t*)(buf->mem+4));
      if ((!req->port && req->command!=SOCKS_COMMAND_RESOLVE) || !destip) {
        log_fn(LOG_WARN,"socks4: Port or DestIP is zero. Rejecting.");
        return -1;
      }
      if (destip >> 8) {
        log_fn(LOG_DEBUG,"socks4: destip not in form 0.0.0.x.");
        in.s_addr = htonl(destip);
        tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
        if (strlen(tmpbuf)+1 > MAX_SOCKS_ADDR_LEN) {
          log_fn(LOG_WARN,"socks4 addr (%d bytes) too long. Rejecting.",
                 (int)strlen(tmpbuf));
          return -1;
        }
        log_fn(LOG_DEBUG,"socks4: successfully read destip (%s)", safe_str(tmpbuf));
        socks4_prot = socks4;
      }

      next = memchr(buf->cur+SOCKS4_NETWORK_LEN, 0,
                    buf->datalen-SOCKS4_NETWORK_LEN);
      if (!next) {
        log_fn(LOG_DEBUG,"socks4: Username not here yet.");
        return 0;
      }
      tor_assert(next < buf->cur+buf->datalen);

      startaddr = NULL;
      if (socks4_prot != socks4a && !have_warned_about_unsafe_socks) {
        log_fn(LOG_WARN,"Your application (using socks4 on port %d) is giving Tor only an IP address. Applications that do DNS resolves themselves may leak information. Consider using Socks4A (e.g. via privoxy or socat) instead.", req->port);
//      have_warned_about_unsafe_socks = 1; // (for now, warn every time)
      }
      if (socks4_prot == socks4a) {
        if (next+1 == buf->cur+buf->datalen) {
          log_fn(LOG_DEBUG,"socks4: No part of destaddr here yet.");
          return 0;
        }
        startaddr = next+1;
        next = memchr(startaddr, 0, buf->cur+buf->datalen-startaddr);
        if (!next) {
          log_fn(LOG_DEBUG,"socks4: Destaddr not all here yet.");
          return 0;
        }
        if (MAX_SOCKS_ADDR_LEN <= next-startaddr) {
          log_fn(LOG_WARN,"socks4: Destaddr too long. Rejecting.");
          return -1;
        }
        tor_assert(next < buf->cur+buf->datalen);
      }
      log_fn(LOG_DEBUG,"socks4: Everything is here. Success.");
      strlcpy(req->address, startaddr ? startaddr : tmpbuf,
              sizeof(req->address));
      buf_remove_from_front(buf, next-buf->cur+1); /* next points to the final \0 on inbuf */
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
"It appears you have configured your web browser to use Tor as an HTTP Proxy.\n"
"This is not correct: Tor provides a SOCKS proxy. Please configure your\n"
"client accordingly.\n"
"</p>\n"
"<p>\n"
"See <a href=\"http://tor.eff.org/documentation.html\">http://tor.eff.org/documentation.html</a> for more information.\n"
"<!-- Plus this comment, to make the body response more than 512 bytes, so IE will be willing to display it. Comment comment comment comment comment comment comment comment comment comment comment comment.-->\n"
"</p>\n"
"</body>\n"
"</html>\n"
             , MAX_SOCKS_REPLY_LEN);
      req->replylen = strlen(req->reply)+1;
      /* fall through */
    default: /* version is not socks4 or socks5 */
      log_fn(LOG_WARN,"Socks version %d not recognized. (Tor is not an http proxy.)",
             *(buf->cur));
      return -1;
  }
}

#define CONTROL_CMD_FRAGMENTHEADER 0x0010
#define CONTROL_CMD_FRAGMENT       0x0011
/** If there is a complete control message waiting on buf, then store
 * its contents into *<b>type_out</b>, store its body's length into
 * *<b>len_out</b>, allocate and store a string for its body into
 * *<b>body_out</b>, and return 1.  (body_out will always be NUL-terminated,
 * even if the control message body doesn't end with NUL.)
 *
 * If there is not a complete control message waiting, return 0.
 *
 * Return -1 on error.
 */
int fetch_from_buf_control(buf_t *buf, uint32_t *len_out, uint16_t *type_out,
                           char **body_out)
{
  uint32_t msglen;
  uint16_t type;
  char tmp[4];

  tor_assert(buf);
  tor_assert(len_out);
  tor_assert(type_out);
  tor_assert(body_out);

  if (buf->datalen < 4)
    return 0;

  peek_from_buf(tmp, 4, buf);

  msglen = ntohs(get_uint16(tmp));
  if (buf->datalen < 4 + (unsigned)msglen)
    return 0;

  type = ntohs(get_uint16(tmp+2));
  *len_out = msglen;
  *type_out = type;
  buf_remove_from_front(buf, 4);
  if (msglen) {
    *body_out = tor_malloc(msglen+1);
    fetch_from_buf(*body_out, msglen, buf);
    (*body_out)[msglen] = '\0';
  } else {
    *body_out = NULL;
  }
  return 1;
}

/** Log an error and exit if <b>buf</b> is corrupted.
 */
void assert_buf_ok(buf_t *buf)
{
  tor_assert(buf);
  tor_assert(buf->magic == BUFFER_MAGIC);
  tor_assert(buf->mem);
  tor_assert(buf->highwater <= buf->len);
  tor_assert(buf->datalen <= buf->highwater);
#ifdef SENTINELS
  {
    uint32_t u32 = get_uint32(buf->mem - 4);
    tor_assert(u32 == START_MAGIC);
    u32 = get_uint32(buf->mem + buf->len);
    tor_assert(u32 == END_MAGIC);
  }
#endif
}
