/* Copyright (c) 2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compress_zstd.c
 * \brief Compression backend for Zstandard.
 *
 * This module should never be invoked directly. Use the compress module
 * instead.
 **/

#include "orconfig.h"

#include "util.h"
#include "torlog.h"
#include "compress.h"
#include "compress_zstd.h"

#ifdef HAVE_ZSTD
#include <zstd.h>
#include <zstd_errors.h>
#endif

/** Total number of bytes allocated for Zstandard state. */
static size_t total_zstd_allocation = 0;

#ifdef HAVE_ZSTD
/** Given <b>level</b> return the memory level. */
static int
memory_level(compression_level_t level)
{
  switch (level) {
    default:
    case BEST_COMPRESSION:
    case HIGH_COMPRESSION: return 9;
    case MEDIUM_COMPRESSION: return 8;
    case LOW_COMPRESSION: return 7;
  }
}
#endif // HAVE_ZSTD.

/** Return 1 if Zstandard compression is supported; otherwise 0. */
int
tor_zstd_method_supported(void)
{
#ifdef HAVE_ZSTD
  return 1;
#else
  return 0;
#endif
}

/** Return a string representation of the version of the currently running
 * version of libzstd. Returns NULL if Zstandard is unsupported. */
const char *
tor_zstd_get_version_str(void)
{
#ifdef HAVE_ZSTD
  static char version_str[16];
  size_t version_number;

  version_number = ZSTD_versionNumber();
  tor_snprintf(version_str, sizeof(version_str),
               "%lu.%lu.%lu",
               version_number / 10000 % 100,
               version_number / 100 % 100,
               version_number % 100);

  return version_str;
#else
  return NULL;
#endif
}

/** Return a string representation of the version of the version of libzstd
 * used at compilation time. Returns NULL if Zstandard is unsupported. */
const char *
tor_zstd_get_header_version_str(void)
{
#ifdef HAVE_ZSTD
  return ZSTD_VERSION_STRING;
#else
  return NULL;
#endif
}

/** Internal Zstandard state for incremental compression/decompression.
 * The body of this struct is not exposed. */
struct tor_zstd_compress_state_t {
#ifdef HAVE_ZSTD
  union {
    /** Compression stream. Used when <b>compress</b> is true. */
    ZSTD_CStream *compress_stream;
    /** Decompression stream. Used when <b>compress</b> is false. */
    ZSTD_DStream *decompress_stream;
  } u; /**< Zstandard stream objects. */
#endif // HAVE_ZSTD.

  int compress; /**< True if we are compressing; false if we are inflating */

  /** Number of bytes read so far.  Used to detect compression bombs. */
  size_t input_so_far;
  /** Number of bytes written so far.  Used to detect compression bombs. */
  size_t output_so_far;

  /** Approximate number of bytes allocated for this object. */
  size_t allocation;
};

/** Construct and return a tor_zstd_compress_state_t object using
 * <b>method</b>. If <b>compress</b>, it's for compression; otherwise it's for
 * decompression. */
tor_zstd_compress_state_t *
tor_zstd_compress_new(int compress,
                      compress_method_t method,
                      compression_level_t compression_level)
{
  tor_assert(method == ZSTD_METHOD);

#ifdef HAVE_ZSTD
  tor_zstd_compress_state_t *result;
  size_t retval;

  result = tor_malloc_zero(sizeof(tor_zstd_compress_state_t));
  result->compress = compress;

  // FIXME(ahf): We should either try to do the pre-calculation that is done
  // with the zlib backend or use a custom allocator here where we pass our
  // tor_zstd_compress_state_t as the opaque value.
  result->allocation = 0;

  if (compress) {
    result->u.compress_stream = ZSTD_createCStream();

    if (result->u.compress_stream == NULL) {
      log_warn(LD_GENERAL, "Error while creating Zstandard stream");
      goto err;
    }

    retval = ZSTD_initCStream(result->u.compress_stream,
                              memory_level(compression_level));

    if (ZSTD_isError(retval)) {
      log_warn(LD_GENERAL, "Zstandard stream initialization error: %s",
               ZSTD_getErrorName(retval));
      goto err;
    }
  } else {
    result->u.decompress_stream = ZSTD_createDStream();

    if (result->u.decompress_stream == NULL) {
      log_warn(LD_GENERAL, "Error while creating Zstandard stream");
      goto err;
    }

    retval = ZSTD_initDStream(result->u.decompress_stream);

    if (ZSTD_isError(retval)) {
      log_warn(LD_GENERAL, "Zstandard stream initialization error: %s",
               ZSTD_getErrorName(retval));
      goto err;
    }
  }

  return result;

 err:
  if (compress) {
    ZSTD_freeCStream(result->u.compress_stream);
  } else {
    ZSTD_freeDStream(result->u.decompress_stream);
  }

  tor_free(result);
  return NULL;
#else // HAVE_ZSTD.
  (void)compress;
  (void)method;
  (void)compression_level;

  return NULL;
#endif // HAVE_ZSTD.
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
tor_zstd_compress_process(tor_zstd_compress_state_t *state,
                          char **out, size_t *out_len,
                          const char **in, size_t *in_len,
                          int finish)
{
#ifdef HAVE_ZSTD
  size_t retval;

  tor_assert(state != NULL);
  tor_assert(*in_len <= UINT_MAX);
  tor_assert(*out_len <= UINT_MAX);

  ZSTD_inBuffer input = { *in, *in_len, 0 };
  ZSTD_outBuffer output = { *out, *out_len, 0 };

  if (state->compress) {
    retval = ZSTD_compressStream(state->u.compress_stream,
                                 &output, &input);
  } else {
    retval = ZSTD_decompressStream(state->u.decompress_stream,
                                   &output, &input);
  }

  state->input_so_far += input.pos;
  state->output_so_far += output.pos;

  *out = (char *)output.dst + output.pos;
  *out_len = output.size - output.pos;
  *in = (char *)input.src + input.pos;
  *in_len = input.size - input.pos;

  if (! state->compress &&
      tor_compress_is_compression_bomb(state->input_so_far,
                                       state->output_so_far)) {
    log_warn(LD_DIR, "Possible compression bomb; abandoning stream.");
    return TOR_COMPRESS_ERROR;
  }

  if (ZSTD_isError(retval)) {
    log_warn(LD_GENERAL, "Zstandard %s didn't finish: %s.",
             state->compress ? "compression" : "decompression",
             ZSTD_getErrorName(retval));
    return TOR_COMPRESS_ERROR;
  }

  if (state->compress && !finish) {
    retval = ZSTD_flushStream(state->u.compress_stream, &output);

    *out = (char *)output.dst + output.pos;
    *out_len = output.size - output.pos;

    if (ZSTD_isError(retval)) {
      log_warn(LD_GENERAL, "Zstandard compression unable to flush: %s.",
               ZSTD_getErrorName(retval));
      return TOR_COMPRESS_ERROR;
    }

    if (retval > 0)
      return TOR_COMPRESS_BUFFER_FULL;
  }

  if (state->compress && finish) {
    retval = ZSTD_endStream(state->u.compress_stream, &output);

    *out = (char *)output.dst + output.pos;
    *out_len = output.size - output.pos;

    if (ZSTD_isError(retval)) {
      log_warn(LD_GENERAL, "Zstandard compression unable to write "
               "epilogue: %s.",
               ZSTD_getErrorName(retval));
      return TOR_COMPRESS_ERROR;
    }

    // endStream returns the number of bytes that is needed to write the
    // epilogue.
    if (retval > 0)
      return TOR_COMPRESS_BUFFER_FULL;
  }

  return finish ? TOR_COMPRESS_DONE : TOR_COMPRESS_OK;
#else // HAVE_ZSTD.
  (void)state;
  (void)out;
  (void)out_len;
  (void)in;
  (void)in_len;
  (void)finish;

  return TOR_COMPRESS_ERROR;
#endif // HAVE_ZSTD.
}

/** Deallocate <b>state</b>. */
void
tor_zstd_compress_free(tor_zstd_compress_state_t *state)
{
  if (state == NULL)
    return;

  total_zstd_allocation -= state->allocation;

#ifdef HAVE_ZSTD
  if (state->compress) {
    ZSTD_freeCStream(state->u.compress_stream);
  } else {
    ZSTD_freeDStream(state->u.decompress_stream);
  }
#endif // HAVE_ZSTD.

  tor_free(state);
}

/** Return the approximate number of bytes allocated for <b>state</b>. */
size_t
tor_zstd_compress_state_size(const tor_zstd_compress_state_t *state)
{
  tor_assert(state != NULL);
  return state->allocation;
}

/** Return the approximate number of bytes allocated for all Zstandard
 * states. */
size_t
tor_zstd_get_total_allocation(void)
{
  return total_zstd_allocation;
}

