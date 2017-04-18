/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file torgzip.h
 * \brief Headers for torgzip.h
 **/

#ifndef TOR_TORGZIP_H
#define TOR_TORGZIP_H

/** Enumeration of what kind of compression to use.  Only ZLIB_METHOD and
 * GZIP_METHOD is guaranteed to be supported by the compress/uncompress
 * functions here. */
typedef enum {
  NO_METHOD=0, GZIP_METHOD=1, ZLIB_METHOD=2, UNKNOWN_METHOD=3
} compress_method_t;

/**
 * Enumeration to define tradeoffs between memory usage and compression level.
 * HIGH_COMPRESSION saves the most bandwidth; LOW_COMPRESSION saves the most
 * memory.
 **/
typedef enum {
  HIGH_COMPRESSION, MEDIUM_COMPRESSION, LOW_COMPRESSION
} compression_level_t;

int
tor_compress(char **out, size_t *out_len,
             const char *in, size_t in_len,
             compress_method_t method);
int
tor_uncompress(char **out, size_t *out_len,
               const char *in, size_t in_len,
               compress_method_t method,
               int complete_only,
               int protocol_warn_level);

const char *
tor_zlib_get_version_str(void);

const char *
tor_zlib_get_header_version_str(void);

compress_method_t detect_compression_method(const char *in, size_t in_len);

int
tor_compress_memory_level(compression_level_t level);

/** Return values from tor_compress_process; see that function's documentation
 * for details. */
typedef enum {
  TOR_COMPRESS_OK,
  TOR_COMPRESS_DONE,
  TOR_COMPRESS_BUFFER_FULL,
  TOR_COMPRESS_ERROR
} tor_compress_output_t;
/** Internal state for an incremental zlib compression/decompression. */
typedef struct tor_compress_state_t tor_compress_state_t;
tor_compress_state_t *tor_compress_new(int compress,
                                       compress_method_t method,
                                       compression_level_t level);

tor_compress_output_t tor_compress_process(tor_compress_state_t *state,
                                           char **out, size_t *out_len,
                                           const char **in, size_t *in_len,
                                           int finish);
void tor_compress_free(tor_compress_state_t *state);

size_t tor_compress_state_size(const tor_compress_state_t *state);
size_t tor_zlib_get_total_allocation(void);

#endif

