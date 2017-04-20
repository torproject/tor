/* Copyright (c) 2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compress_lzma.c
 * \brief Compression backend for LZMA.
 *
 * This module should never be invoked directly. Use the compress module
 * instead.
 **/

#include "orconfig.h"

#include "util.h"
#include "torlog.h"
#include "compress.h"
#include "compress_lzma.h"

#ifdef HAVE_LZMA
#include <lzma.h>
#endif

/** Total number of bytes allocated for LZMA state. */
static size_t total_lzma_allocation = 0;

#ifdef HAVE_LZMA
/** Convert a given <b>error</b> to a human readable error string. */
static const char *
lzma_error_str(lzma_ret error)
{
  switch (error) {
    case LZMA_OK:
      return "Operation completed successfully";
    case LZMA_STREAM_END:
      return "End of stream";
    case LZMA_NO_CHECK:
      return "Input stream lacks integrity check";
    case LZMA_UNSUPPORTED_CHECK:
      return "Unable to calculate integrity check";
    case LZMA_GET_CHECK:
      return "Integrity check available";
    case LZMA_MEM_ERROR:
      return "Unable to allocate memory";
    case LZMA_MEMLIMIT_ERROR:
      return "Memory limit reached";
    case LZMA_FORMAT_ERROR:
      return "Unknown file format";
    case LZMA_OPTIONS_ERROR:
      return "Unsupported options";
    case LZMA_DATA_ERROR:
      return "Corrupt input data";
    case LZMA_BUF_ERROR:
      return "Unable to progress";
    case LZMA_PROG_ERROR:
      return "Programming error";
    default:
      return "Unknown LZMA error";
  }
}
#endif // HAVE_LZMA.

/** Return 1 if LZMA compression is supported; otherwise 0. */
int
tor_lzma_method_supported(void)
{
#ifdef HAVE_LZMA
  return 1;
#else
  return 0;
#endif
}

/** Return a string representation of the version of the currently running
 * version of liblzma. */
const char *
tor_lzma_get_version_str(void)
{
#ifdef HAVE_LZMA
  return lzma_version_string();
#else
  return "N/A";
#endif
}

/** Return a string representation of the version of the version of liblzma
 * used at compilation. */
const char *
tor_lzma_get_header_version_str(void)
{
#ifdef HAVE_LZMA
  return LZMA_VERSION_STRING;
#else
  return "N/A";
#endif
}

/** Given <b>in_len</b> bytes at <b>in</b>, compress them into a newly
 * allocated buffer, using the LZMA method.  Store the compressed string in
 * *<b>out</b>, and its length in *<b>out_len</b>.  Return 0 on success, -1 on
 * failure.
 */
int
tor_lzma_compress(char **out, size_t *out_len,
                  const char *in, size_t in_len,
                  compress_method_t method)
{
#ifdef HAVE_LZMA
  lzma_stream stream = LZMA_STREAM_INIT;
  lzma_options_lzma stream_options;
  lzma_ret retval;
  lzma_action action;
  size_t out_size, old_size;
  off_t offset;

  tor_assert(out);
  tor_assert(out_len);
  tor_assert(in);
  tor_assert(in_len < UINT_MAX);
  tor_assert(method == LZMA_METHOD);

  stream.next_in = (unsigned char *)in;
  stream.avail_in = in_len;

  lzma_lzma_preset(&stream_options,
                   tor_compress_memory_level(HIGH_COMPRESSION));

  retval = lzma_alone_encoder(&stream, &stream_options);

  if (retval != LZMA_OK) {
    log_warn(LD_GENERAL, "Error from LZMA encoder: %s (%u).",
             lzma_error_str(retval), retval);
    goto err;
  }

  out_size = in_len / 2;
  if (out_size < 1024)
    out_size = 1024;

  *out = tor_malloc(out_size);

  stream.next_out = (unsigned char *)*out;
  stream.avail_out = out_size;

  action = LZMA_RUN;

  while (1) {
    retval = lzma_code(&stream, action);
    switch (retval) {
      case LZMA_OK:
        action = LZMA_FINISH;
        break;
      case LZMA_STREAM_END:
        goto done;
      case LZMA_BUF_ERROR:
        offset = stream.next_out - ((unsigned char *)*out);
        old_size = out_size;
        out_size *= 2;

        if (out_size < old_size) {
          log_warn(LD_GENERAL, "Size overflow in LZMA compression.");
          goto err;
        }

        *out = tor_realloc(*out, out_size);
        stream.next_out = (unsigned char *)(*out + offset);
        if (out_size - offset > UINT_MAX) {
          log_warn(LD_BUG, "Ran over unsigned int limit of LZMA while "
                           "compressing.");
          goto err;
        }
        stream.avail_out = (unsigned int)(out_size - offset);
        break;

      // We list all the possible values of `lzma_ret` here to silence the
      // `switch-enum` warning and to detect if a new member was added.
      case LZMA_NO_CHECK:
      case LZMA_UNSUPPORTED_CHECK:
      case LZMA_GET_CHECK:
      case LZMA_MEM_ERROR:
      case LZMA_MEMLIMIT_ERROR:
      case LZMA_FORMAT_ERROR:
      case LZMA_OPTIONS_ERROR:
      case LZMA_DATA_ERROR:
      case LZMA_PROG_ERROR:
      default:
        log_warn(LD_GENERAL, "LZMA compression didn't finish: %s.",
                 lzma_error_str(retval));
        goto err;
    }
  }

 done:
  *out_len = stream.total_out;
  lzma_end(&stream);

  if (tor_compress_is_compression_bomb(*out_len, in_len)) {
    log_warn(LD_BUG, "We compressed something and got an insanely high "
                     "compression factor; other Tor instances would think "
                     "this is a compression bomb.");
    goto err;
  }

  return 0;

 err:
  lzma_end(&stream);
  tor_free(*out);
  return -1;
#else // HAVE_LZMA.
  (void)out;
  (void)out_len;
  (void)in;
  (void)in_len;
  (void)method;

  return -1;
#endif // HAVE_LZMA.
}

/** Given an LZMA compressed string of total length <b>in_len</b> bytes at
 * <b>in</b>, uncompress them into a newly allocated buffer.  Store the
 * uncompressed string in *<b>out</b>, and its length in *<b>out_len</b>.
 * Return 0 on success, -1 on failure.
 *
 * If <b>complete_only</b> is true, we consider a truncated input as a failure;
 * otherwise we decompress as much as we can.  Warn about truncated or corrupt
 * inputs at <b>protocol_warn_level</b>.
 */
int
tor_lzma_uncompress(char **out, size_t *out_len,
                    const char *in, size_t in_len,
                    compress_method_t method,
                    int complete_only,
                    int protocol_warn_level)
{
#ifdef HAVE_LZMA
  lzma_stream stream = LZMA_STREAM_INIT;
  lzma_ret retval;
  lzma_action action;
  size_t out_size, old_size;
  off_t offset;

  tor_assert(out);
  tor_assert(out_len);
  tor_assert(in);
  tor_assert(in_len < UINT_MAX);
  tor_assert(method == LZMA_METHOD);

  stream.next_in = (unsigned char *)in;
  stream.avail_in = in_len;

  // FIXME(ahf): This should be something more sensible than
  // UINT64_MAX: See #21665.
  retval = lzma_alone_decoder(&stream, UINT64_MAX);

  if (retval != LZMA_OK) {
    log_warn(LD_GENERAL, "Error from LZMA decoder: %s (%u).",
             lzma_error_str(retval), retval);
    goto err;
  }

  out_size = in_len * 2;
  if (out_size < 1024)
    out_size = 1024;

  if (out_size >= SIZE_T_CEILING || out_size > UINT_MAX)
    goto err;

  *out = tor_malloc(out_size);
  stream.next_out = (unsigned char *)*out;
  stream.avail_out = out_size;

  // FIXME(ahf): We should figure out how to use LZMA_FULL_FLUSH to
  // make the partial string read tests.
  //   action = complete_only ? LZMA_FINISH : LZMA_SYNC_FLUSH.  // To do this,
  // it seems like we have to use LZMA using their "xz" encoder instead of just
  // regular LZMA.
  (void)complete_only;
  action = LZMA_FINISH;

  while (1) {
    retval = lzma_code(&stream, action);
    switch (retval) {
      case LZMA_STREAM_END:
        if (stream.avail_in == 0)
          goto done;

        // We might have more data here. Reset our stream.
        lzma_end(&stream);

        retval = lzma_alone_decoder(&stream, UINT64_MAX);

        if (retval != LZMA_OK) {
          log_warn(LD_GENERAL, "Error from LZMA decoder: %s (%u).",
                   lzma_error_str(retval), retval);
          goto err;
        }
        break;
      case LZMA_OK:
        break;
      case LZMA_BUF_ERROR:
        if (stream.avail_out > 0) {
          log_fn(protocol_warn_level, LD_PROTOCOL,
                 "possible truncated or corrupt LZMA data.");
          goto err;
        }

        offset = stream.next_out - (unsigned char *)*out;
        old_size = out_size;
        out_size *= 2;

        if (out_size < old_size) {
          log_warn(LD_GENERAL, "Size overflow in LZMA uncompression.");
          goto err;
        }

        if (tor_compress_is_compression_bomb(in_len, out_size)) {
          log_warn(LD_GENERAL, "Input looks like a possible LZMA compression "
                               "bomb. Not proceeding.");
          goto err;
        }

        if (out_size >= SIZE_T_CEILING) {
          log_warn(LD_BUG, "Hit SIZE_T_CEILING limit while uncompressing "
                           "LZMA data.");
          goto err;
        }

        *out = tor_realloc(*out, out_size);
        stream.next_out = (unsigned char *)(*out + offset);

        if (out_size - offset > UINT_MAX) {
          log_warn(LD_BUG, "Ran over unsigned int limit of LZMA while "
                           "uncompressing.");
          goto err;
        }

        stream.avail_out = (unsigned int)(out_size - offset);
        break;

      // We list all the possible values of `lzma_ret` here to silence the
      // `switch-enum` warning and to detect if a new member was added.
      case LZMA_NO_CHECK:
      case LZMA_UNSUPPORTED_CHECK:
      case LZMA_GET_CHECK:
      case LZMA_MEM_ERROR:
      case LZMA_MEMLIMIT_ERROR:
      case LZMA_FORMAT_ERROR:
      case LZMA_OPTIONS_ERROR:
      case LZMA_DATA_ERROR:
      case LZMA_PROG_ERROR:
      default:
        log_warn(LD_GENERAL, "LZMA decompression didn't finish: %s.",
                 lzma_error_str(retval));
        goto err;
    }
  }

 done:
  *out_len = stream.next_out - (unsigned char*)*out;
  lzma_end(&stream);

  // NUL-terminate our output.
  if (out_size == *out_len)
    *out = tor_realloc(*out, out_size + 1);
  (*out)[*out_len] = '\0';

  return 0;

 err:
  lzma_end(&stream);
  tor_free(*out);
  return -1;
#else // HAVE_LZMA.
  (void)out;
  (void)out_len;
  (void)in;
  (void)in_len;
  (void)method;
  (void)complete_only;
  (void)protocol_warn_level;

  return -1;
#endif // HAVE_LZMA.
}

/** Internal LZMA state for incremental compression/decompression.
 * The body of this struct is not exposed. */
struct tor_lzma_compress_state_t {
#ifdef HAVE_LZMA
  lzma_stream stream; /**< The LZMA stream. */
#endif

  int compress; /**< True if we are compressing; false if we are inflating */

  /** Number of bytes read so far.  Used to detect compression bombs. */
  size_t input_so_far;
  /** Number of bytes written so far.  Used to detect compression bombs. */
  size_t output_so_far;

  /** Approximate number of bytes allocated for this object. */
  size_t allocation;
};

/** Construct and return a tor_lzma_compress_state_t object using
 * <b>method</b>. If <b>compress</b>, it's for compression; otherwise it's for
 * decompression. */
tor_lzma_compress_state_t *
tor_lzma_compress_new(int compress,
                      compress_method_t method,
                      compression_level_t compression_level)
{
  tor_assert(method == LZMA_METHOD);

#ifdef HAVE_LZMA
  tor_lzma_compress_state_t *result;
  lzma_ret retval;
  lzma_options_lzma stream_options;

  // Note that we do not explicitly initialize the lzma_stream object here,
  // since the LZMA_STREAM_INIT "just" initializes all members to 0, which is
  // also what `tor_malloc_zero()` does.
  result = tor_malloc_zero(sizeof(tor_lzma_compress_state_t));
  result->compress = compress;

  // FIXME(ahf): We should either try to do the pre-calculation that is done
  // with the zlib backend or use a custom allocator here where we pass our
  // tor_lzma_compress_state_t as the opaque value.
  result->allocation = 0;

  if (compress) {
    lzma_lzma_preset(&stream_options,
                     tor_compress_memory_level(compression_level));

    retval = lzma_alone_encoder(&result->stream, &stream_options);

    if (retval != LZMA_OK) {
      log_warn(LD_GENERAL, "Error from LZMA encoder: %s (%u).",
               lzma_error_str(retval), retval);
      goto err;
    }
  } else {
    // FIXME(ahf): This should be something more sensible than
    // UINT64_MAX: See #21665.
    retval = lzma_alone_decoder(&result->stream, UINT64_MAX);

    if (retval != LZMA_OK) {
      log_warn(LD_GENERAL, "Error from LZMA decoder: %s (%u).",
               lzma_error_str(retval), retval);
      goto err;
    }
  }

  return result;

 err:
  tor_free(result);
  return NULL;
#else // HAVE_LZMA.
  (void)compress;
  (void)method;
  (void)compression_level;

  return NULL;
#endif // HAVE_LZMA.
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
tor_lzma_compress_process(tor_lzma_compress_state_t *state,
                          char **out, size_t *out_len,
                          const char **in, size_t *in_len,
                          int finish)
{
#ifdef HAVE_LZMA
  lzma_ret retval;
  lzma_action action;

  tor_assert(state != NULL);
  tor_assert(*in_len <= UINT_MAX);
  tor_assert(*out_len <= UINT_MAX);

  state->stream.next_in = (unsigned char *)*in;
  state->stream.avail_in = *in_len;
  state->stream.next_out = (unsigned char *)*out;
  state->stream.avail_out = *out_len;

  action = finish ? LZMA_FINISH : LZMA_RUN;

  retval = lzma_code(&state->stream, action);

  state->input_so_far += state->stream.next_in - ((unsigned char *)*in);
  state->output_so_far += state->stream.next_out - ((unsigned char *)*out);

  *out = (char *)state->stream.next_out;
  *out_len = state->stream.avail_out;
  *in = (const char *)state->stream.next_in;
  *in_len = state->stream.avail_in;

  if (! state->compress &&
      tor_compress_is_compression_bomb(state->input_so_far,
                                       state->output_so_far)) {
    log_warn(LD_DIR, "Possible compression bomb; abandoning stream.");
    return TOR_COMPRESS_ERROR;
  }

  switch (retval) {
    case LZMA_OK:
      if (state->stream.avail_out == 0 || finish)
        return TOR_COMPRESS_BUFFER_FULL;

      return TOR_COMPRESS_OK;

    case LZMA_BUF_ERROR:
      if (state->stream.avail_in == 0 && !finish)
        return TOR_COMPRESS_OK;

      return TOR_COMPRESS_BUFFER_FULL;

    case LZMA_STREAM_END:
      return TOR_COMPRESS_DONE;

    // We list all the possible values of `lzma_ret` here to silence the
    // `switch-enum` warning and to detect if a new member was added.
    case LZMA_NO_CHECK:
    case LZMA_UNSUPPORTED_CHECK:
    case LZMA_GET_CHECK:
    case LZMA_MEM_ERROR:
    case LZMA_MEMLIMIT_ERROR:
    case LZMA_FORMAT_ERROR:
    case LZMA_OPTIONS_ERROR:
    case LZMA_DATA_ERROR:
    case LZMA_PROG_ERROR:
    default:
      log_warn(LD_GENERAL, "LZMA %s didn't finish: %s.",
               state->compress ? "compression" : "decompression",
               lzma_error_str(retval));
      return TOR_COMPRESS_ERROR;
  }
#else // HAVE_LZMA.
  (void)state;
  (void)out;
  (void)out_len;
  (void)in;
  (void)in_len;
  (void)finish;
  return TOR_COMPRESS_ERROR;
#endif // HAVE_LZMA.
}

/** Deallocate <b>state</b>. */
void
tor_lzma_compress_free(tor_lzma_compress_state_t *state)
{
  if (state == NULL)
    return;

  total_lzma_allocation -= state->allocation;

#ifdef HAVE_LZMA
  lzma_end(&state->stream);
#endif

  tor_free(state);
}

/** Return the approximate number of bytes allocated for <b>state</b>. */
size_t
tor_lzma_compress_state_size(const tor_lzma_compress_state_t *state)
{
  tor_assert(state != NULL);
  return state->allocation;
}

/** Return the approximate number of bytes allocated for all LZMA states. */
size_t
tor_lzma_get_total_allocation(void)
{
  return total_lzma_allocation;
}

