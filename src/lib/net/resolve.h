/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_RESOLVE_H
#define TOR_RESOLVE_H

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"
#ifdef _WIN32
#include <winsock2.h>
#endif

#if defined(HAVE_SECCOMP_H) && defined(__linux__)
#define USE_SANDBOX_GETADDRINFO
#endif

MOCK_DECL(int,tor_lookup_hostname,(const char *name, uint32_t *addr));

struct addrinfo;
#ifdef USE_SANDBOX_GETADDRINFO
/** Pre-calls getaddrinfo in order to pre-record result. */
int sandbox_add_addrinfo(const char *addr);

// XXXX rename these.  They are named as though they were sandbox-only,
// XXXX but in fact they're the only allowed entry point to getaddrinfo.
// XXXX They don't invoke the sandbox code; they only have an internal cache.
struct addrinfo;
/** Replacement for getaddrinfo(), using pre-recorded results. */
int sandbox_getaddrinfo(const char *name, const char *servname,
                        const struct addrinfo *hints,
                        struct addrinfo **res);
void sandbox_freeaddrinfo(struct addrinfo *addrinfo);
void sandbox_free_getaddrinfo_cache(void);
void sandbox_make_getaddrinfo_cache_active(void);
#else /* !(defined(USE_SANDBOX_GETADDRINFO)) */
#define sandbox_getaddrinfo(name, servname, hints, res)  \
  getaddrinfo((name),(servname), (hints),(res))
#define sandbox_add_addrinfo(name) \
  ((void)(name))
#define sandbox_freeaddrinfo(addrinfo) \
  freeaddrinfo((addrinfo))
#define sandbox_free_getaddrinfo_cache()
#endif /* defined(USE_SANDBOX_GETADDRINFO) */

void sandbox_disable_getaddrinfo_cache(void);

#endif
