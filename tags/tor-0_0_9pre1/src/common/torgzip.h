/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file torgzip.h
 * \brief Headers for torgzip.h
 **/

#ifndef __TORGZIP_H
#define __TORGZIP_H

typedef enum { GZIP_METHOD=1, ZLIB_METHOD=2 } compress_method_t;

int
tor_gzip_compress(char **out, size_t *out_len,
		  const char *in, size_t in_len,
		  compress_method_t method);
int
tor_gzip_uncompress(char **out, size_t *out_len,
		    const char *in, size_t in_len,
		    compress_method_t method);

int is_gzip_supported(void);

#endif
