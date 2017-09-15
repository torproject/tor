/* Copyright (c) 2003, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file compress_zstd.h
 * \brief Header for compress_zstd.c
 **/

#ifndef TOR_COMPRESS_ZSTD_H
#define TOR_COMPRESS_ZSTD_H

int tor_zstd_method_supported(void);

const char *tor_zstd_get_version_str(void);

const char *tor_zstd_get_header_version_str(void);

/** Internal state for an incremental Zstandard compression/decompression. */
typedef struct tor_zstd_compress_state_t tor_zstd_compress_state_t;

tor_zstd_compress_state_t *
tor_zstd_compress_new(int compress,
                      compress_method_t method,
                      compression_level_t compression_level);

tor_compress_output_t
tor_zstd_compress_process(tor_zstd_compress_state_t *state,
                          char **out, size_t *out_len,
                          const char **in, size_t *in_len,
                          int finish);

void tor_zstd_compress_free(tor_zstd_compress_state_t *state);

size_t tor_zstd_compress_state_size(const tor_zstd_compress_state_t *state);

size_t tor_zstd_get_total_allocation(void);

void tor_zstd_init(void);

#endif /* !defined(TOR_COMPRESS_ZSTD_H) */

