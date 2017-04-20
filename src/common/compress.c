/* Copyright (c) 2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compress.c
 * \brief Common compression API.
 **/

#include "orconfig.h"

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "torint.h"

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "util.h"
#include "torlog.h"
#include "compress.h"
#include "compress_lzma.h"
#include "compress_zlib.h"
#include "compress_zstd.h"

/** @{ */
/* These macros define the maximum allowable compression factor.  Anything of
 * size greater than CHECK_FOR_COMPRESSION_BOMB_AFTER is not allowed to
 * have an uncompression factor (uncompressed size:compressed size ratio) of
 * any greater than MAX_UNCOMPRESSION_FACTOR.
 *
 * Picking a value for MAX_UNCOMPRESSION_FACTOR is a trade-off: we want it to
 * be small to limit the attack multiplier, but we also want it to be large
 * enough so that no legitimate document --even ones we might invent in the
 * future -- ever compresses by a factor of greater than
 * MAX_UNCOMPRESSION_FACTOR. Within those parameters, there's a reasonably
 * large range of possible values. IMO, anything over 8 is probably safe; IMO
 * anything under 50 is probably sufficient.
 */
#define MAX_UNCOMPRESSION_FACTOR 25
#define CHECK_FOR_COMPRESSION_BOMB_AFTER (1024*64)
/** @} */

/** Return true if uncompressing an input of size <b>in_size</b> to an input of
 * size at least <b>size_out</b> looks like a compression bomb. */
int
tor_compress_is_compression_bomb(size_t size_in, size_t size_out)
{
  if (size_in == 0 || size_out < CHECK_FOR_COMPRESSION_BOMB_AFTER)
    return 0;

  return (size_out / size_in > MAX_UNCOMPRESSION_FACTOR);
}

/** Given <b>level</b> return the memory level.  The memory level is needed for
 * the various compression backends used in Tor.
 */
int
tor_compress_memory_level(compression_level_t level)
{
  switch (level) {
    default:
    case HIGH_COMPRESSION: return 8;
    case MEDIUM_COMPRESSION: return 7;
    case LOW_COMPRESSION: return 6;
  }
}

/** Given <b>in_len</b> bytes at <b>in</b>, compress them into a newly
 * allocated buffer, using the method described in <b>method</b>.  Store the
 * compressed string in *<b>out</b>, and its length in *<b>out_len</b>.
 * Return 0 on success, -1 on failure.
 */
int
tor_compress(char **out, size_t *out_len,
             const char *in, size_t in_len,
             compress_method_t method)
{
  if (method == GZIP_METHOD || method == ZLIB_METHOD)
    return tor_zlib_compress(out, out_len, in, in_len, method);

  if (method == LZMA_METHOD)
    return tor_lzma_compress(out, out_len, in, in_len, method);

  if (method == ZSTD_METHOD)
    return tor_zstd_compress(out, out_len, in, in_len, method);

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
tor_uncompress(char **out, size_t *out_len,
               const char *in, size_t in_len,
               compress_method_t method,
               int complete_only,
               int protocol_warn_level)
{
  if (method == GZIP_METHOD || method == ZLIB_METHOD)
    return tor_zlib_uncompress(out, out_len, in, in_len,
                               method,
                               complete_only,
                               protocol_warn_level);

  if (method == LZMA_METHOD)
    return tor_lzma_uncompress(out, out_len, in, in_len,
                               method,
                               complete_only,
                               protocol_warn_level);

  if (method == ZSTD_METHOD)
    return tor_zstd_uncompress(out, out_len, in, in_len,
                               method,
                               complete_only,
                               protocol_warn_level);

  return -1;
}

/** Try to tell whether the <b>in_len</b>-byte string in <b>in</b> is likely
 * to be compressed or not.  If it is, return the likeliest compression method.
 * Otherwise, return UNKNOWN_METHOD.
 */
compress_method_t
detect_compression_method(const char *in, size_t in_len)
{
  if (in_len > 2 && fast_memeq(in, "\x1f\x8b", 2)) {
    return GZIP_METHOD;
  } else if (in_len > 2 && (in[0] & 0x0f) == 8 &&
             (ntohs(get_uint16(in)) % 31) == 0) {
    return ZLIB_METHOD;
  } else if (in_len > 3 &&
             fast_memeq(in, "\x5d\x00\x00\x00", 4)) {
    return LZMA_METHOD;
  } else if (in_len > 3 &&
             fast_memeq(in, "\x28\xb5\x2f\xfd", 4)) {
    return ZSTD_METHOD;
  } else {
    return UNKNOWN_METHOD;
  }
}

/** Return the approximate number of bytes allocated for all
 * supported compression schemas. */
size_t
tor_compress_get_total_allocation(void)
{
  return tor_zlib_get_total_allocation() +
         tor_lzma_get_total_allocation() +
         tor_zstd_get_total_allocation();
}

/** Internal state for an incremental compression/decompression.  The body of
 * this struct is not exposed. */
struct tor_compress_state_t {
  compress_method_t method; /**< The compression method. */

  union {
    tor_zlib_compress_state_t *zlib_state;
    tor_lzma_compress_state_t *lzma_state;
    tor_zstd_compress_state_t *zstd_state;
  } u; /**< Compression backend state. */
};

/** Construct and return a tor_compress_state_t object using <b>method</b>.  If
 * <b>compress</b>, it's for compression; otherwise it's for decompression. */
tor_compress_state_t *
tor_compress_new(int compress, compress_method_t method,
                 compression_level_t compression_level)
{
  tor_compress_state_t *state;

  state = tor_malloc_zero(sizeof(tor_compress_state_t));
  state->method = method;

  switch (method) {
    case GZIP_METHOD:
    case ZLIB_METHOD: {
      tor_zlib_compress_state_t *zlib_state =
        tor_zlib_compress_new(compress, method, compression_level);

      if (zlib_state == NULL)
        goto err;

      state->u.zlib_state = zlib_state;
      break;
    }
    case LZMA_METHOD: {
      tor_lzma_compress_state_t *lzma_state =
        tor_lzma_compress_new(compress, method, compression_level);

      if (lzma_state == NULL)
        goto err;

      state->u.lzma_state = lzma_state;
      break;
    }
    case ZSTD_METHOD: {
      tor_zstd_compress_state_t *zstd_state =
        tor_zstd_compress_new(compress, method, compression_level);

      if (zstd_state == NULL)
        goto err;

      state->u.zstd_state = zstd_state;
      break;
    }
    case NO_METHOD:
    case UNKNOWN_METHOD:
      goto err;
  }

  return state;

 err:
  tor_free(state);
  return NULL;
}

/** Compress/decompress some bytes using <b>state</b>.  Read up to
 * *<b>in_len</b> bytes from *<b>in</b>, and write up to *<b>out_len</b> bytes
 * to *<b>out</b>, adjusting the values as we go.  If <b>finish</b> is true,
 * we've reached the end of the input.
 *
 * Return TOR_COMPRESS_DONE if we've finished the entire
 * compression/decompression.
 * Return TOR_COMPRESS_OK if we're processed everything from the input.
 * Return TOR_COMPRESS_BUFFER_FULL if we're out of space on <b>out</b>.
 * Return TOR_COMPRESS_ERROR if the stream is corrupt.
 */
tor_compress_output_t
tor_compress_process(tor_compress_state_t *state,
                     char **out, size_t *out_len,
                     const char **in, size_t *in_len,
                     int finish)
{
  tor_assert(state != NULL);

  switch (state->method) {
    case GZIP_METHOD:
    case ZLIB_METHOD:
      return tor_zlib_compress_process(state->u.zlib_state,
                                       out, out_len, in, in_len,
                                       finish);
    case LZMA_METHOD:
      return tor_lzma_compress_process(state->u.lzma_state,
                                       out, out_len, in, in_len,
                                       finish);
    case ZSTD_METHOD:
      return tor_zstd_compress_process(state->u.zstd_state,
                                       out, out_len, in, in_len,
                                       finish);
    case NO_METHOD:
    case UNKNOWN_METHOD:
      goto err;
  }

 err:
  return TOR_COMPRESS_ERROR;
}

/** Deallocate <b>state</b>. */
void
tor_compress_free(tor_compress_state_t *state)
{
  if (state == NULL)
    return;

  switch (state->method) {
    case GZIP_METHOD:
    case ZLIB_METHOD:
      tor_zlib_compress_free(state->u.zlib_state);
      break;
    case LZMA_METHOD:
      tor_lzma_compress_free(state->u.lzma_state);
      break;
    case ZSTD_METHOD:
      tor_zstd_compress_free(state->u.zstd_state);
      break;
    case NO_METHOD:
    case UNKNOWN_METHOD:
      break;
  }

  tor_free(state);
}

/** Return the approximate number of bytes allocated for <b>state</b>. */
size_t
tor_compress_state_size(const tor_compress_state_t *state)
{
  tor_assert(state != NULL);

  switch (state->method) {
    case GZIP_METHOD:
    case ZLIB_METHOD:
      return tor_zlib_compress_state_size(state->u.zlib_state);
    case LZMA_METHOD:
      return tor_lzma_compress_state_size(state->u.lzma_state);
    case ZSTD_METHOD:
      return tor_zstd_compress_state_size(state->u.zstd_state);
    case NO_METHOD:
    case UNKNOWN_METHOD:
      goto err;
  }

 err:
  return 0;
}

