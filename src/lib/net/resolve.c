/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file resolve.c
 * \brief Use the libc DNS resolver to convert hostnames into addresses.
 **/

#include "lib/net/resolve.h"
#include "lib/net/address.h"
#include "lib/malloc/util_malloc.h"

#include "siphash.h"
#include "ht.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <string.h>

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address, in host byte order.  Returns 0
 * on success, -1 on failure; 1 on transient failure.
 *
 * (This function exists because standard windows gethostbyname
 * doesn't treat raw IP addresses properly.)
 */

MOCK_IMPL(int,
tor_lookup_hostname,(const char *name, uint32_t *addr))
{
  tor_addr_t myaddr;
  int ret;

  if ((ret = tor_addr_lookup(name, AF_INET, &myaddr)))
    return ret;

  if (tor_addr_family(&myaddr) == AF_INET) {
    *addr = tor_addr_to_ipv4h(&myaddr);
    return ret;
  }

  return -1;
}

#ifdef USE_SANDBOX_GETADDRINFO
/** True if we should only return cached values */
static int sandbox_getaddrinfo_is_active = 0;

/** Cache entry for getaddrinfo results; used when sandboxing is implemented
 * so that we can consult the cache when the sandbox prevents us from doing
 * getaddrinfo.
 *
 * We support only a limited range of getaddrinfo calls, where servname is null
 * and hints contains only socktype=SOCK_STREAM, family in INET,INET6,UNSPEC.
 */
typedef struct cached_getaddrinfo_item_t {
  HT_ENTRY(cached_getaddrinfo_item_t) node;
  char *name;
  int family;
  /** set if no error; otherwise NULL */
  struct addrinfo *res;
  /** 0 for no error; otherwise an EAI_* value */
  int err;
} cached_getaddrinfo_item_t;

static unsigned
cached_getaddrinfo_item_hash(const cached_getaddrinfo_item_t *item)
{
  return (unsigned)siphash24g(item->name, strlen(item->name)) + item->family;
}

static unsigned
cached_getaddrinfo_items_eq(const cached_getaddrinfo_item_t *a,
                            const cached_getaddrinfo_item_t *b)
{
  return (a->family == b->family) && 0 == strcmp(a->name, b->name);
}

#define cached_getaddrinfo_item_free(item)              \
  FREE_AND_NULL(cached_getaddrinfo_item_t,              \
                cached_getaddrinfo_item_free_, (item))

static void
cached_getaddrinfo_item_free_(cached_getaddrinfo_item_t *item)
{
  if (item == NULL)
    return;

  tor_free(item->name);
  if (item->res)
    freeaddrinfo(item->res);
  tor_free(item);
}

static HT_HEAD(getaddrinfo_cache, cached_getaddrinfo_item_t)
     getaddrinfo_cache = HT_INITIALIZER();

HT_PROTOTYPE(getaddrinfo_cache, cached_getaddrinfo_item_t, node,
             cached_getaddrinfo_item_hash,
             cached_getaddrinfo_items_eq)
HT_GENERATE2(getaddrinfo_cache, cached_getaddrinfo_item_t, node,
             cached_getaddrinfo_item_hash,
             cached_getaddrinfo_items_eq,
             0.6, tor_reallocarray_, tor_free_)

/** If true, don't try to cache getaddrinfo results. */
static int sandbox_getaddrinfo_cache_disabled = 0;

/** Tell the sandbox layer not to try to cache getaddrinfo results. Used as in
 * tor-resolve, when we have no intention of initializing crypto or of
 * installing the sandbox.*/
void
sandbox_disable_getaddrinfo_cache(void)
{
  sandbox_getaddrinfo_cache_disabled = 1;
}

void
tor_freeaddrinfo(struct addrinfo *ai)
{
  if (sandbox_getaddrinfo_cache_disabled)
    freeaddrinfo(ai);
}

int
tor_getaddrinfo(const char *name, const char *servname,
                const struct addrinfo *hints,
                struct addrinfo **res)
{
  int err;
  struct cached_getaddrinfo_item_t search, *item;

  if (sandbox_getaddrinfo_cache_disabled) {
    return getaddrinfo(name, NULL, hints, res);
  }

  if (servname != NULL) {
    log_warn(LD_BUG, "called with non-NULL servname");
    return EAI_NONAME;
  }
  if (name == NULL) {
    log_warn(LD_BUG, "called with NULL name");
    return EAI_NONAME;
  }

  *res = NULL;

  memset(&search, 0, sizeof(search));
  search.name = (char *) name;
  search.family = hints ? hints->ai_family : AF_UNSPEC;
  item = HT_FIND(getaddrinfo_cache, &getaddrinfo_cache, &search);

  if (! sandbox_getaddrinfo_is_active) {
    /* If the sandbox is not turned on yet, then getaddrinfo and store the
       result. */

    err = getaddrinfo(name, NULL, hints, res);
    log_info(LD_NET,"(Sandbox) getaddrinfo %s.", err ? "failed" : "succeeded");

    if (! item) {
      item = tor_malloc_zero(sizeof(*item));
      item->name = tor_strdup(name);
      item->family = hints ? hints->ai_family : AF_UNSPEC;
      HT_INSERT(getaddrinfo_cache, &getaddrinfo_cache, item);
    }

    if (item->res) {
      freeaddrinfo(item->res);
      item->res = NULL;
    }
    item->res = *res;
    item->err = err;
    return err;
  }

  /* Otherwise, the sandbox is on.  If we have an item, yield its cached
     result. */
  if (item) {
    *res = item->res;
    return item->err;
  }

  /* getting here means something went wrong */
  log_err(LD_BUG,"(Sandbox) failed to get address %s!", name);
  return EAI_NONAME;
}

int
tor_add_addrinfo(const char *name)
{
  struct addrinfo *res;
  struct addrinfo hints;
  int i;
  static const int families[] = { AF_INET, AF_INET6, AF_UNSPEC };

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_STREAM;
  for (i = 0; i < 3; ++i) {
    hints.ai_family = families[i];

    res = NULL;
    (void) tor_getaddrinfo(name, NULL, &hints, &res);
    if (res)
      tor_freeaddrinfo(res);
  }

  return 0;
}

void
tor_free_getaddrinfo_cache(void)
{
  cached_getaddrinfo_item_t **next, **item, *this;

  for (item = HT_START(getaddrinfo_cache, &getaddrinfo_cache);
       item;
       item = next) {
    this = *item;
    next = HT_NEXT_RMV(getaddrinfo_cache, &getaddrinfo_cache, item);
    cached_getaddrinfo_item_free(this);
  }

  HT_CLEAR(getaddrinfo_cache, &getaddrinfo_cache);
}

void
tor_make_getaddrinfo_cache_active(void)
{
  sandbox_getaddrinfo_is_active = 1;
}
#endif
