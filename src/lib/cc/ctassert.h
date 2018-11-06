/*-
 * Copyright (c) 2018 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file ctassert.h
 *
 * \brief Compile-time assertions: CTASSERT(expression).
 */

#ifndef TOR_CTASSERT_H
#define TOR_CTASSERT_H

#include "lib/cc/compat_compiler.h"

/**
 * CTASSERT(expression)
 *
 *       Trigger a compiler error if expression is false.
 */
#if __STDC_VERSION__ >= 201112L

/* If C11 is available, just use _Static_assert.  */
#define CTASSERT(x) _Static_assert((x), #x)

#else

/*
 * If C11 is not available, expand __COUNTER__, or __INCLUDE_LEVEL__
 * and __LINE__, or just __LINE__, with an intermediate preprocessor
 * macro CTASSERT_EXPN, and then use CTASSERT_DECL to paste the
 * expansions together into a unique name.
 *
 * We use this name as a typedef of an array type with a positive
 * length if the assertion is true, and a negative length of the
 * assertion is false, which is invalid and hence triggers a compiler
 * error.
 */
#if defined(__COUNTER__)
#define CTASSERT(x) CTASSERT_EXPN((x), c, __COUNTER__)
#elif defined(__INCLUDE_LEVEL__)
#define CTASSERT(x) CTASSERT_EXPN((x), __INCLUDE_LEVEL__, __LINE__)
#else
/* hope it's unique enough */
#define CTASSERT(x) CTASSERT_EXPN((x), l, __LINE__)
#endif

#define CTASSERT_EXPN(x, a, b) CTASSERT_DECL(x, a, b)
#define CTASSERT_DECL(x, a, b) \
  typedef char tor_ctassert_##a##_##b[(x) ? 1 : -1] ATTR_UNUSED

#endif

#endif /* !defined(TOR_CTASSERT_H) */
