/* Copyright 2003 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

/*****
 * torint.h: Header file to define uint32_t and friends.
 *****/

#ifndef __TORINT_H
#define __TORINT_H

#include "orconfig.h"


#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif


#if (SIZEOF_INT8_T != 0)
#define HAVE_INT8_T
#endif
#if (SIZEOF_INT16_T != 0)
#define HAVE_INT16_T
#endif
#if (SIZEOF_INT32_T != 0)
#define HAVE_INT32_T
#endif
#if (SIZEOF_INT64_T != 0)
#define HAVE_INT64_T
#endif
#if (SIZEOF_UINT8_T != 0)
#define HAVE_UINT8_T
#endif
#if (SIZEOF_UINT16_T != 0)
#define HAVE_UINT16_T
#endif
#if (SIZEOF_UINT32_T != 0)
#define HAVE_UINT32_T
#endif
#if (SIZEOF_UINT64_T != 0)
#define HAVE_UINT64_T
#endif
#if (SIZEOF_INTPTR_T != 0)
#define HAVE_INTPTR_T
#endif
#if (SIZEOF_UINTPTR_T != 0)
#define HAVE_UINTPTR_T
#endif

#if (SIZEOF_CHAR == 1)
#ifndef HAVE_INT8_T
typedef signed char int8_t;
#define HAVE_INT8_T
#endif
#ifndef HAVE_UINT8_T
typedef unsigned char uint8_t;
#define HAVE_UINT8_T
#endif
#endif

#if (SIZEOF_SHORT == 2)
#ifndef HAVE_INT16_T
typedef signed short int16_t;
#define HAVE_INT16_T
#endif
#ifndef HAVE_UINT16_T
typedef unsigned short uint16_t;
#define HAVE_UINT16_T
#endif
#endif


#if (SIZEOF_INT == 2)
#ifndef HAVE_INT16_T
typedef signed int int16_t;
#define HAVE_INT16_T
#endif
#ifndef HAVE_UINT16_T
typedef unsigned int uint16_t;
#define HAVE_UINT16_T
#endif
#elif (SIZEOF_INT == 4)
#ifndef HAVE_INT32_T
typedef signed int int32_t;
#define HAVE_INT32_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned int uint32_t;
#define HAVE_UINT32_T
#endif
#endif


#if (SIZEOF_LONG == 4)
#ifndef HAVE_INT32_T
typedef signed long int32_t;
#define HAVE_INT32_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned long uint32_t;
#define HAVE_UINT32_T
#endif
#elif (SIZEOF_LONG == 8)
#ifndef HAVE_INT64_T
typedef signed long int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT32_T
typedef unsigned long uint64_t;
#define HAVE_UINT32_T
#endif
#endif

#if (SIZEOF_LONG_LONG == 8)
#ifndef HAVE_INT64_T
typedef signed long long int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT64_T
typedef unsigned long long uint64_t;
#define HAVE_UINT64_T
#endif
#endif

#if (SIZEOF___INT64 == 8)
#ifndef HAVE_INT64_T
typedef signed __int64 int64_t;
#define HAVE_INT64_T
#endif
#ifndef HAVE_UINT64_T
typedef unsigned __int64 uint64_t;
#define HAVE_UINT64_T
#endif
#endif

#if (SIZEOF_VOID_P > 4 && SIZEOF_VOID_P <= 8)
#ifndef HAVE_INTPTR_T
typedef int64_t intptr_t;
#endif
#ifndef HAVE_UINTPTR_T
typedef uint64_t uintptr_t;
#endif
#elif (SIZEOF_VOID_P > 2 && SIZEOF_VOID_P <= 4)
#ifndef HAVE_INTPTR_T
typedef int32_t intptr_t;
#endif
#ifndef HAVE_UINTPTR_T
typedef uint32_t uintptr_t;
#endif
#else
#error "void * is either >8 bytes or <= 2.  In either case, I am confused."
#endif

#ifndef HAVE_INT8_T
#error "Missing type int8_t"
#endif
#ifndef HAVE_UINT8_T
#error "Missing type uint8_t"
#endif
#ifndef HAVE_INT16_T
#error "Missing type int16_t"
#endif
#ifndef HAVE_UINT16_T
#error "Missing type uint16_t"
#endif
#ifndef HAVE_INT32_T
#error "Missing type int32_t"
#endif
#ifndef HAVE_UINT32_T
#error "Missing type uint32_t"
#endif
#ifndef HAVE_INT64_T
#error "Missing type int64_t"
#endif
#ifndef HAVE_UINT64_T
#error "Missing type uint64_t"
#endif

#endif /* __TORINT_H */

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
