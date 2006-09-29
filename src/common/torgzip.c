/* Copyright 2004 Roger Dingledine */
/* Copyright 2004-2006 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */
const char torgzip_c_id[] =
  "$Id$";

/**
 * \file torgzip.c
 * \brief A simple in-memory gzip implementation.
 **/

#include "orconfig.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#ifdef _MSC_VER
#include "..\..\contrib\zlib\zlib.h"
#else
#include <zlib.h>
#endif
#include <string.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "util.h"
#include "log.h"
#include "torgzip.h"

/** Set to 1 if zlib is a version that supports gzip; set to 0 if it doesn't;
 * set to -1 if we haven't checked yet. */
static int gzip_is_supported = -1;

/** Return true iff we support gzip-based compression.  Otherwise, we need to
 * use zlib. */
int
is_gzip_supported(void)
{
  if (gzip_is_supported >= 0)
    return gzip_is_supported;

  if (!strcmpstart(ZLIB_VERSION, "0.") ||
      !strcmpstart(ZLIB_VERSION, "1.0") ||
      !strcmpstart(ZLIB_VERSION, "1.1"))
    gzip_is_supported = 0;
  else
    gzip_is_supported = 1;

  return gzip_is_supported;
}

/** Return the 'bits' value to tell zlib to use <b>method</b>.*/
static INLINE int
method_bits(compress_method_t method)
{
  /* Bits+16 means "use gzip" in zlib >= 1.2 */
  return method == GZIP_METHOD ? 15+16 : 15;
}

/** Given <b>in_len</b> bytes at <b>in</b>, compress them into a newly
 * allocated buffer, using the method described in <b>method</b>.  Store the
 * compressed string in *<b>out</b>, and its length in *<b>out_len</b>.
 * Return 0 on success, -1 on failure.
 */
int
tor_gzip_compress(char **out, size_t *out_len,
                  const char *in, size_t in_len,
                  compress_method_t method)
{
  struct z_stream_s *stream = NULL;
  size_t out_size;
  off_t offset;

  tor_assert(out);
  tor_assert(out_len);
  tor_assert(in);

  if (method == GZIP_METHOD && !is_gzip_supported()) {
    /* Old zlib version don't support gzip in deflateInit2 */
    log_warn(LD_BUG, "Gzip not supported with zlib %s", ZLIB_VERSION);
    return -1;
  }

  *out = NULL;

  stream = tor_malloc_zero(sizeof(struct z_stream_s));
  stream->zalloc = Z_NULL;
  stream->zfree = Z_NULL;
  stream->opaque = NULL;
  stream->next_in = (unsigned char*) in;
  stream->avail_in = in_len;

  if (deflateInit2(stream, Z_BEST_COMPRESSION, Z_DEFLATED,
                   method_bits(method),
                   8, Z_DEFAULT_STRATEGY) != Z_OK) {
    log_warn(LD_GENERAL, "Error from deflateInit2: %s",
             stream->msg?stream->msg:"<no message>");
    goto err;
  }

  /* Guess 50% compression. */
  out_size = in_len / 2;
  if (out_size < 1024) out_size = 1024;
  *out = tor_malloc(out_size);
  stream->next_out = (unsigned char*)*out;
  stream->avail_out = out_size;

  while (1) {
    switch (deflate(stream, Z_FINISH))
      {
      case Z_STREAM_END:
        goto done;
      case Z_OK:
        /* In case zlib doesn't work as I think .... */
        if (stream->avail_out >= stream->avail_in+16)
          break;
      case Z_BUF_ERROR:
        offset = stream->next_out - ((unsigned char*)*out);
        out_size *= 2;
        *out = tor_realloc(*out, out_size);
        stream->next_out = (unsigned char*)(*out + offset);
        stream->avail_out = out_size - offset;
        break;
      default:
        log_warn(LD_GENERAL, "Gzip compression didn't finish: %s",
                 stream->msg ? stream->msg : "<no message>");
        goto err;
      }
  }
 done:
  *out_len = stream->total_out;
  if (deflateEnd(stream)!=Z_OK) {
    log_warn(LD_BUG, "Error freeing gzip structures");
    goto err;
  }
  tor_free(stream);

  return 0;
 err:
  if (stream) {
    deflateEnd(stream);
    tor_free(stream);
  }
  if (*out) {
    tor_free(*out);
  }
  return -1;
}

/** Given zero or more zlib-compressed or gzip-compressed strings of
 * total length
 * <b>in_len</b> bytes at <b>in</b>, uncompress them into a newly allocated
 * buffer, using the method described in <b>method</b>.  Store the uncompressed
 * string in *<b>out</b>, and its length in *<b>out_len</b>.  Return 0 on
 * success, -1 on failure.
 *
 * If <b>complete_only</b> is true, we consider a truncated input as a
 * failure; otherwise we decompress as much as we can.  Warn about truncated
 * or corrupt inputs at <b>protocol_warn_level</b>.
 */
int
tor_gzip_uncompress(char **out, size_t *out_len,
                    const char *in, size_t in_len,
                    compress_method_t method,
                    int complete_only,
                    int protocol_warn_level)
{
  struct z_stream_s *stream = NULL;
  size_t out_size;
  off_t offset;
  int r;

  tor_assert(out);
  tor_assert(out_len);
  tor_assert(in);

  if (method == GZIP_METHOD && !is_gzip_supported()) {
    /* Old zlib version don't support gzip in inflateInit2 */
    log_warn(LD_BUG, "Gzip not supported with zlib %s", ZLIB_VERSION);
    return -1;
  }

  *out = NULL;

  stream = tor_malloc_zero(sizeof(struct z_stream_s));
  stream->zalloc = Z_NULL;
  stream->zfree = Z_NULL;
  stream->opaque = NULL;
  stream->next_in = (unsigned char*) in;
  stream->avail_in = in_len;

  if (inflateInit2(stream,
                   method_bits(method)) != Z_OK) {
    log_warn(LD_GENERAL, "Error from inflateInit2: %s",
             stream->msg?stream->msg:"<no message>");
    goto err;
  }

  out_size = in_len * 2;  /* guess 50% compression. */
  if (out_size < 1024) out_size = 1024;

  *out = tor_malloc(out_size);
  stream->next_out = (unsigned char*)*out;
  stream->avail_out = out_size;

  while (1) {
    switch (inflate(stream, complete_only ? Z_FINISH : Z_SYNC_FLUSH))
      {
      case Z_STREAM_END:
        if (stream->avail_in == 0)
          goto done;
        /* There may be more compressed data here. */
        if ((r = inflateEnd(stream)) != Z_OK) {
          log_warn(LD_BUG, "Error freeing gzip structures");
          goto err;
        }
        if (inflateInit2(stream, method_bits(method)) != Z_OK) {
          log_warn(LD_GENERAL, "Error from inflateInit2: %s",
                   stream->msg?stream->msg:"<no message>");
          goto err;
        }
        break;
      case Z_OK:
        if (!complete_only && stream->avail_in == 0)
          goto done;
        /* In case zlib doesn't work as I think.... */
        if (stream->avail_out >= stream->avail_in+16)
          break;
      case Z_BUF_ERROR:
        if (stream->avail_out > 0) {
          log_fn(protocol_warn_level, LD_PROTOCOL,
                 "possible truncated or corrupt zlib data");
          goto err;
        }
        offset = stream->next_out - (unsigned char*)*out;
        out_size *= 2;
        *out = tor_realloc(*out, out_size);
        stream->next_out = (unsigned char*)(*out + offset);
        stream->avail_out = out_size - offset;
        break;
      default:
        log_warn(LD_GENERAL, "Gzip decompression returned an error: %s",
                 stream->msg ? stream->msg : "<no message>");
        goto err;
      }
  }
 done:
  *out_len = stream->next_out - (unsigned char*)*out;
  r = inflateEnd(stream);
  tor_free(stream);
  if (r != Z_OK) {
    log_warn(LD_BUG, "Error freeing gzip structures");
    goto err;
  }

  /* NUL-terminate output. */
  if (out_size == *out_len)
    *out = tor_realloc(*out, out_size + 1);
  (*out)[*out_len] = '\0';

  return 0;
 err:
  if (stream) {
    inflateEnd(stream);
    tor_free(stream);
  }
  if (*out) {
    tor_free(*out);
  }
  return -1;
}

/** Try to tell whether the <b>in_len</b>-byte string in <b>in</b> is likely
 * to be compressed or not.  If it is, return the likeliest compression method.
 * Otherwise, return 0.
 */
int
detect_compression_method(const char *in, size_t in_len)
{
  if (in_len > 2 && !memcmp(in, "\x1f\x8b", 2)) {
    return GZIP_METHOD;
  } else if (in_len > 2 && (in[0] & 0x0f) == 8 &&
             (ntohs(get_uint16(in)) % 31) == 0) {
    return ZLIB_METHOD;
  } else {
    return 0;
  }
}

struct tor_zlib_state_t {
  struct z_stream_s stream;
  int compress;
};

/** Construct and return a tor_zlib_state_t object using <b>method</b>.  If
 * <b>compress</b>, it's for compression; otherwise it's for
 * decompression.  */
tor_zlib_state_t *
tor_zlib_new(int compress, compress_method_t method)
{
  tor_zlib_state_t *out;

  if (method == GZIP_METHOD && !is_gzip_supported()) {
    /* Old zlib version don't support gzip in inflateInit2 */
    log_warn(LD_BUG, "Gzip not supported with zlib %s", ZLIB_VERSION);
    return NULL;
 }

 out = tor_malloc_zero(sizeof(tor_zlib_state_t));
 out->stream.zalloc = Z_NULL;
 out->stream.zfree = Z_NULL;
 out->stream.opaque = NULL;
 out->compress = compress;
 if (compress) {
   if (deflateInit2(&out->stream, Z_BEST_COMPRESSION, Z_DEFLATED,
                    method_bits(method), 8, Z_DEFAULT_STRATEGY) != Z_OK)
     goto err;
 } else {
   if (inflateInit2(&out->stream, method_bits(method)) != Z_OK)
     goto err;
 }
 return out;

 err:
 tor_free(out);
 return NULL;
}

/** Compress/decommpress some bytes using <b>state</b>.  Read up to
 * *<b>in_len</b> bytes from *<b>in</b>, and write up to *<b>out_len</b> bytes
 * to *<b>out</b>, adjusting the values as we go.  If <b>finish</b> is true,
 * we've reached the end of the input.
 *
 * Return TOR_ZLIB_DONE if we've finished the entire compression/decompression.
 * Return TOR_ZLIB_OK if we're processed everything from the input.
 * Return TOR_ZLIB_BUF_FULL if we're out of space on <b>out</b>.
 * Return TOR_ZLIB_ERR if the stream is corrupt.
 */
tor_zlib_output_t
tor_zlib_process(tor_zlib_state_t *state,
                 char **out, size_t *out_len,
                 const char **in, size_t *in_len,
                 int finish)
{
  int err;
  state->stream.next_in = (unsigned char*) *in;
  state->stream.avail_in = *in_len;
  state->stream.next_out = (unsigned char*) *out;
  state->stream.avail_out = *out_len;

  if (state->compress) {
    err = deflate(&state->stream, finish ? Z_FINISH : Z_SYNC_FLUSH);
  } else {
    err = inflate(&state->stream, finish ? Z_FINISH : Z_SYNC_FLUSH);
  }

  *out = (char*) state->stream.next_out;
  *out_len = state->stream.avail_out;
  *in = (const char *) state->stream.next_in;
  *in_len = state->stream.avail_in;

  switch (err)
    {
    case Z_STREAM_END:
      return TOR_ZLIB_DONE;
    case Z_BUF_ERROR:
      if (state->stream.avail_in == 0)
        return TOR_ZLIB_OK;
      return TOR_ZLIB_BUF_FULL;
    case Z_OK:
      if (state->stream.avail_out == 0 || finish)
        return TOR_ZLIB_BUF_FULL;
      return TOR_ZLIB_OK;
    default:
      log_warn(LD_GENERAL, "Gzip returned an error: %s",
               state->stream.msg ? state->stream.msg : "<no message>");
      return TOR_ZLIB_ERR;
    }
}

/** Deallocate <b>state</b>. */
void
tor_zlib_free(tor_zlib_state_t *state)
{
  tor_assert(state);

  if (state->compress)
    deflateEnd(&state->stream);
  else
    inflateEnd(&state->stream);

  tor_free(state);
}

