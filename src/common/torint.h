/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __TORINT_H
#define __TORINT_H

#ifdef HAVE_STDINT_H
#include <stdint.h>
#else

#if (SIZEOF_CHAR == 1)
typedef unsigned char uint8_t;
typedef signed char int8_t;
#else
#error "sizeof(char) != 1"
#endif

#if (SIZEOF_SHORT == 2)
typedef unsigned short uint16_t;
typedef signed short int16_t;
#elif (SIZEOF_INT == 2)
typedef unsigned int uint16_t;
typedef signed int int16_t;
#else
#error "sizeof(short) != 2 && sizeof(int) != 2"
#endif

#if (SIZEOF_INT == 4)
typedef unsigned int uint32_t;
typedef signed int int32_t;
#elif (SIZEOF_LONG == 4)
typedef unsigned long uint32_t;
typedef signed long int32_t;
#else
#error "sizeof(int) != 4 && sizeof(long) != 4"
#endif

#if (SIZEOF_LONG == 8)
typedef unsigned long uint64_t;
typedef signed long int64_t;
#elif (SIZEOF_LONG_LONG == 8)
typedef unsigned long long uint64_t;
typedef signed long long int64_t;
#elif (SIZEOF___INT64 == 8)
typedef unsigned __int64 uint64_t;
typedef signed __int64 int64_t;
#else
#error "sizeof(long) != 8 && sizeof(long long) != 8 && sizeof(__int64) != 8"
#endif

#endif /* HAVE_STDINT_H */


#endif /* __TORINT_H */
