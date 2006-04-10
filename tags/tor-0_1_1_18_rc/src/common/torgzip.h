/* Copyright 2003 Roger Dingledine
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file torgzip.h
 * \brief Headers for torgzip.h
 **/

#ifndef __TORGZIP_H
#define __TORGZIP_H
#define TORGZIP_H_ID "$Id$"

typedef enum {
  GZIP_METHOD=1, ZLIB_METHOD=2, UNKNOWN_METHOD=3
} compress_method_t;

int
tor_gzip_compress(char **out, size_t *out_len,
                  const char *in, size_t in_len,
                  compress_method_t method);
int
tor_gzip_uncompress(char **out, size_t *out_len,
                    const char *in, size_t in_len,
                    compress_method_t method,
                    int complete_only,
                    int protocol_warn_level);

int is_gzip_supported(void);

int detect_compression_method(const char *in, size_t in_len);

#endif

