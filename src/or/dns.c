/* Copyright 2003-2004 Roger Dingledine.
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dns_c_id[] =
  "$Id$";

/**
 * \file dns.c
 * \brief Implements a local cache for DNS results for Tor servers.
 * We provide two asynchrounous backend implementations:
 *   1) A farm of 'DNS worker' threads or processes to perform DNS lookups for
 *      onion routers and cache the results.
 *   2) A wrapper around Adam Langley's eventdns.c code, to send requests
 *      to the nameservers asynchronously.
 * (We can't just use gethostbyname() and friends because we really need to
 * be nonblocking.)
 **/

#include "or.h"
#include "../common/ht.h"
#ifdef USE_EVENTDNS
#include "eventdns.h"
#endif

/** Longest hostname we're willing to resolve. */
#define MAX_ADDRESSLEN 256

/** Maximum DNS processes to spawn. */
#define MAX_DNSWORKERS 100
/** Minimum DNS processes to spawn. */
#define MIN_DNSWORKERS 3

/** If more than this many processes are idle, shut down the extras. */
#define MAX_IDLE_DNSWORKERS 10

/** How long will we wait for an answer from the resolver before we decide
 * that the resolver is wedged? */
#define RESOLVE_MAX_TIMEOUT 300

/** Possible outcomes from hostname lookup: permanent failure,
 * transient (retryable) failure, and success. */
#define DNS_RESOLVE_FAILED_TRANSIENT 1
#define DNS_RESOLVE_FAILED_PERMANENT 2
#define DNS_RESOLVE_SUCCEEDED 3

#ifndef USE_EVENTDNS
/** How many dnsworkers we have running right now. */
static int num_dnsworkers=0;
/** How many of the running dnsworkers have an assigned task right now. */
static int num_dnsworkers_busy=0;
/** When did we last rotate the dnsworkers? */
static time_t last_rotation_time=0;
#endif

/** Linked list of connections waiting for a DNS answer. */
typedef struct pending_connection_t {
  edge_connection_t *conn;
  struct pending_connection_t *next;
} pending_connection_t;

#define CACHED_RESOLVE_MAGIC 0x1234F00D

/* Possible states for a cached resolve_t */
/** We are waiting for the resolver system to tell us an answer here.
 * When we get one, or when we time out, the state of this cached_resolve_t
 * will become "DONE" and we'll possibly add a CACHED_VALID or a CACHED_FAILED
 * entry. This cached_resolve_t will be in the hash table so that we will
 * know not to launch more requests for this addr, but rather to add more
 * connections to the pending list for the addr. */
#define CACHE_STATE_PENDING 0
/** This used to be a pending cached_resolve_t, and we got an answer for it.
 * Now we're waiting for this cached_resolve_t to expire.  This should
 * have no pending connections, and should not appear in the hash table. */
#define CACHE_STATE_DONE 1
/** We are caching an answer for this address. This should have no pending
 * connections, and should appear in the hash table. */
#define CACHE_STATE_CACHED_VALID 2
/** We are caching a failure for this address. This should have no pending
 * connections, and should appear in the hash table */
#define CACHE_STATE_CACHED_FAILED 3

/** A DNS request: possibly completed, possibly pending; cached_resolve
 * structs are stored at the OR side in a hash table, and as a linked
 * list from oldest to newest.
 */
typedef struct cached_resolve_t {
  HT_ENTRY(cached_resolve_t) node;
  uint32_t magic;
  char address[MAX_ADDRESSLEN]; /**< The hostname to be resolved. */
  uint32_t addr; /**< IPv4 addr for <b>address</b>. */
  uint8_t state; /**< Is this cached entry pending/done/valid/failed? */
  time_t expire; /**< Remove items from cache after this time. */
  uint32_t ttl; /**< What TTL did the nameserver tell us? */
  pending_connection_t *pending_connections;
} cached_resolve_t;

static void purge_expired_resolves(uint32_t now);
static void dns_found_answer(const char *address, uint32_t addr, char outcome,
                             uint32_t ttl);
static void send_resolved_cell(edge_connection_t *conn, uint8_t answer_type);
static int launch_resolve(edge_connection_t *exitconn);
#ifndef USE_EVENTDNS
static int dnsworker_main(void *data);
static int spawn_dnsworker(void);
static int spawn_enough_dnsworkers(void);
#else
static void configure_nameservers(void);
#endif
static void assert_cache_ok(void);
static void assert_resolve_ok(cached_resolve_t *resolve);

/** Hash table of cached_resolve objects. */
static HT_HEAD(cache_map, cached_resolve_t) cache_root;

/** Function to compare hashed resolves on their addresses; used to
 * implement hash tables. */
static INLINE int
cached_resolves_eq(cached_resolve_t *a, cached_resolve_t *b)
{
  /* make this smarter one day? */
  assert_resolve_ok(a); // Not b; b may be just a search.
  return !strncmp(a->address, b->address, MAX_ADDRESSLEN);
}

static INLINE unsigned int
cached_resolve_hash(cached_resolve_t *a)
{
  return ht_string_hash(a->address);
}

HT_PROTOTYPE(cache_map, cached_resolve_t, node, cached_resolve_hash,
             cached_resolves_eq);
HT_GENERATE(cache_map, cached_resolve_t, node, cached_resolve_hash,
            cached_resolves_eq, 0.6, malloc, realloc, free);

/** Initialize the DNS cache. */
static void
init_cache_map(void)
{
  HT_INIT(&cache_root);
}

#ifdef USE_EVENTDNS
static void
eventdns_log_cb(const char *msg)
{
  if (!strcmpstart(msg, "Resolve requested for") &&
      get_options()->SafeLogging) {
    log(LOG_INFO, LD_EXIT, "eventdns: Resolve requested.");
    return;
  }
  log(LOG_INFO, LD_EXIT, "eventdns: %s", msg);
}
#endif

/** Initialize the DNS subsystem; called by the OR process. */
void
dns_init(void)
{
  init_cache_map();
  dnsworkers_rotate();
  if (server_mode(get_options()))
    configure_nameservers();
}

uint32_t
dns_clip_ttl(uint32_t ttl)
{
  if (ttl < MIN_DNS_TTL)
    return MIN_DNS_TTL;
  else if (ttl > MAX_DNS_TTL)
    return MAX_DNS_TTL;
  else
    return ttl;
}

static uint32_t
dns_get_expiry_ttl(uint32_t ttl)
{
  if (ttl < MIN_DNS_TTL)
    return MIN_DNS_TTL;
  else if (ttl > MAX_DNS_ENTRY_AGE)
    return MAX_DNS_ENTRY_AGE;
  else
    return ttl;
}

/** Helper: free storage held by an entry in the DNS cache. */
static void
_free_cached_resolve(cached_resolve_t *r)
{
  while (r->pending_connections) {
    pending_connection_t *victim = r->pending_connections;
    r->pending_connections = victim->next;
    tor_free(victim);
  }
  r->magic = 0xFF00FF00;
  tor_free(r);
}

/** Compare two cached_resolve_t pointers by expiry time, and return
 * less-than-zero, zero, or greater-than-zero as appropriate. Used for
 * the priority queue implementation. */
static int
_compare_cached_resolves_by_expiry(const void *_a, const void *_b)
{
  const cached_resolve_t *a = _a, *b = _b;
  if (a->expire < b->expire)
    return -1;
  else if (a->expire == b->expire)
    return 0;
  else
    return 1;
}

/** Priority queue of cached_resolve_t objects to let us know when they
 * will expire. */
static smartlist_t *cached_resolve_pqueue = NULL;

/** Set an expiry time for a cached_resolve_t, and add it to the expiry
 * priority queue */
static void
set_expiry(cached_resolve_t *resolve, time_t expires)
{
  tor_assert(resolve && resolve->expire == 0);
  if (!cached_resolve_pqueue)
    cached_resolve_pqueue = smartlist_create();
  resolve->expire = expires;
  smartlist_pqueue_add(cached_resolve_pqueue,
                       _compare_cached_resolves_by_expiry,
                       resolve);
}

/** Free all storage held in the DNS cache */
void
dns_free_all(void)
{
  cached_resolve_t **ptr, **next, *item;
  for (ptr = HT_START(cache_map, &cache_root); ptr != NULL; ptr = next) {
    item = *ptr;
    next = HT_NEXT_RMV(cache_map, &cache_root, ptr);
    _free_cached_resolve(item);
  }
  HT_CLEAR(cache_map, &cache_root);
  if (cached_resolve_pqueue)
    smartlist_free(cached_resolve_pqueue);
  cached_resolve_pqueue = NULL;
}

/** Remove every cached_resolve whose <b>expire</b> time is before <b>now</b>
 * from the cache. */
static void
purge_expired_resolves(uint32_t now)
{
  cached_resolve_t *resolve, *removed;
  pending_connection_t *pend;
  edge_connection_t *pendconn;

  assert_cache_ok();
  if (!cached_resolve_pqueue)
    return;

  while (smartlist_len(cached_resolve_pqueue)) {
    resolve = smartlist_get(cached_resolve_pqueue, 0);
    if (resolve->expire > now)
      break;
    smartlist_pqueue_pop(cached_resolve_pqueue,
                         _compare_cached_resolves_by_expiry);

    if (resolve->state == CACHE_STATE_PENDING) {
      log_debug(LD_EXIT,
                "Expiring a dns resolve %s that's still pending. Forgot to cull"
                " it? DNS resolve didn't tell us about the timeout?",
                escaped_safe_str(resolve->address));
    } else if (resolve->state == CACHE_STATE_CACHED_VALID ||
               resolve->state == CACHE_STATE_CACHED_FAILED) {
      log_debug(LD_EXIT,
                "Forgetting old cached resolve (address %s, expires %lu)",
                escaped_safe_str(resolve->address),
                (unsigned long)resolve->expire);
      tor_assert(!resolve->pending_connections);
    } else {
      tor_assert(resolve->state == CACHE_STATE_DONE);
      tor_assert(!resolve->pending_connections);
    }

    if (resolve->pending_connections) {
      log_debug(LD_EXIT,
                "Closing pending connections on timed-out DNS resolve!");
      tor_fragile_assert();
      while (resolve->pending_connections) {
        pend = resolve->pending_connections;
        resolve->pending_connections = pend->next;
        /* Connections should only be pending if they have no socket. */
        tor_assert(pend->conn->_base.s == -1);
        pendconn = pend->conn;
        connection_edge_end(pendconn, END_STREAM_REASON_TIMEOUT,
                            pendconn->cpath_layer);
        circuit_detach_stream(circuit_get_by_edge_conn(pendconn), pendconn);
        connection_free(TO_CONN(pendconn));
        tor_free(pend);
      }
    }

    if (resolve->state == CACHE_STATE_CACHED_VALID ||
        resolve->state == CACHE_STATE_CACHED_FAILED ||
        resolve->state == CACHE_STATE_PENDING) {
      removed = HT_REMOVE(cache_map, &cache_root, resolve);
      if (removed != resolve) {
        log_err(LD_BUG, "The expired resolve we purged didn't match any in"
                " the cache. Tried to purge %s (%p); instead got %s (%p).",
                resolve->address, resolve,
                removed ? removed->address : "NULL", remove);
      }
      tor_assert(removed == resolve);
      resolve->magic = 0xF0BBF0BB;
      tor_free(resolve);
    } else {
      /* This should be in state DONE. Make sure it's not in the cache. */
      cached_resolve_t *tmp = HT_FIND(cache_map, &cache_root, resolve);
      tor_assert(tmp != resolve);
    }
  }

  assert_cache_ok();
}

/** Send a response to the RESOLVE request of a connection. answer_type must
 *  be one of RESOLVED_TYPE_(IPV4|ERROR|ERROR_TRANSIENT) */
static void
send_resolved_cell(edge_connection_t *conn, uint8_t answer_type)
{
  char buf[RELAY_PAYLOAD_SIZE];
  size_t buflen;
  uint32_t ttl;

  buf[0] = answer_type;
  ttl = dns_clip_ttl(conn->address_ttl);

  switch (answer_type)
    {
    case RESOLVED_TYPE_IPV4:
      buf[1] = 4;
      set_uint32(buf+2, htonl(conn->_base.addr));
      set_uint32(buf+6, htonl(ttl));
      buflen = 10;
      break;
    case RESOLVED_TYPE_ERROR_TRANSIENT:
    case RESOLVED_TYPE_ERROR:
      {
        const char *errmsg = "Error resolving hostname";
        int msglen = strlen(errmsg);

        buf[1] = msglen;
        strlcpy(buf+2, errmsg, sizeof(buf)-2);
        set_uint32(buf+2+msglen, htonl(ttl));
        buflen = 6+msglen;
        break;
      }
    default:
      tor_assert(0);
    }
  connection_edge_send_command(conn, circuit_get_by_edge_conn(conn),
                               RELAY_COMMAND_RESOLVED, buf, buflen,
                               conn->cpath_layer);
}

/** See if we have a cache entry for <b>exitconn</b>-\>address. if so,
 * if resolve valid, put it into <b>exitconn</b>-\>addr and return 1.
 * If resolve failed, unlink exitconn if needed, free it, and return -1.
 *
 * Else, if seen before and pending, add conn to the pending list,
 * and return 0.
 *
 * Else, if not seen before, add conn to pending list, hand to
 * dns farm, and return 0.
 */
int
dns_resolve(edge_connection_t *exitconn)
{
  cached_resolve_t *resolve;
  cached_resolve_t search;
  pending_connection_t *pending_connection;
  struct in_addr in;
  circuit_t *circ;
  uint32_t now = time(NULL);
  assert_connection_ok(TO_CONN(exitconn), 0);
  tor_assert(exitconn->_base.s == -1);

  assert_cache_ok();

  /* first check if exitconn->_base.address is an IP. If so, we already
   * know the answer. */
  if (tor_inet_aton(exitconn->_base.address, &in) != 0) {
    exitconn->_base.addr = ntohl(in.s_addr);
    exitconn->address_ttl = DEFAULT_DNS_TTL;
    if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE)
      send_resolved_cell(exitconn, RESOLVED_TYPE_IPV4);
    return 1;
  }

  /* then take this opportunity to see if there are any expired
   * resolves in the hash table. */
  purge_expired_resolves(now);

  /* lower-case exitconn->_base.address, so it's in canonical form */
  tor_strlower(exitconn->_base.address);

  /* now check the hash table to see if 'address' is already there. */
  strlcpy(search.address, exitconn->_base.address, sizeof(search.address));
  resolve = HT_FIND(cache_map, &cache_root, &search);
  if (resolve && resolve->expire > now) { /* already there */
    switch (resolve->state) {
      case CACHE_STATE_PENDING:
        /* add us to the pending list */
        pending_connection = tor_malloc_zero(
                                      sizeof(pending_connection_t));
        pending_connection->conn = exitconn;
        pending_connection->next = resolve->pending_connections;
        resolve->pending_connections = pending_connection;
        log_debug(LD_EXIT,"Connection (fd %d) waiting for pending DNS "
                  "resolve of %s", exitconn->_base.s,
                  escaped_safe_str(exitconn->_base.address));
        exitconn->_base.state = EXIT_CONN_STATE_RESOLVING;
        return 0;
      case CACHE_STATE_CACHED_VALID:
        exitconn->_base.addr = resolve->addr;
        exitconn->address_ttl = resolve->ttl;
        log_debug(LD_EXIT,"Connection (fd %d) found cached answer for %s",
                  exitconn->_base.s,
                  escaped_safe_str(exitconn->_base.address));
        if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE)
          send_resolved_cell(exitconn, RESOLVED_TYPE_IPV4);
        return 1;
      case CACHE_STATE_CACHED_FAILED:
        log_debug(LD_EXIT,"Connection (fd %d) found cached error for %s",
                  exitconn->_base.s,
                  escaped_safe_str(exitconn->_base.address));
        if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE)
          send_resolved_cell(exitconn, RESOLVED_TYPE_ERROR);
        circ = circuit_get_by_edge_conn(exitconn);
        if (circ)
          circuit_detach_stream(circ, exitconn);
        if (!exitconn->_base.marked_for_close)
          connection_free(TO_CONN(exitconn));
        return -1;
      case CACHE_STATE_DONE:
        log_err(LD_BUG, "Found a 'DONE' dns resolve still in the cache.");
        tor_fragile_assert();
    }
    tor_assert(0);
  }
  /* not there, need to add it */
  resolve = tor_malloc_zero(sizeof(cached_resolve_t));
  resolve->magic = CACHED_RESOLVE_MAGIC;
  resolve->state = CACHE_STATE_PENDING;
  strlcpy(resolve->address, exitconn->_base.address, sizeof(resolve->address));

  /* add this connection to the pending list */
  pending_connection = tor_malloc_zero(sizeof(pending_connection_t));
  pending_connection->conn = exitconn;
  resolve->pending_connections = pending_connection;
  exitconn->_base.state = EXIT_CONN_STATE_RESOLVING;

  /* Add this resolve to the cache and priority queue. */
  HT_INSERT(cache_map, &cache_root, resolve);
  set_expiry(resolve, now + RESOLVE_MAX_TIMEOUT);

  log_debug(LD_EXIT,"Launching %s.",
            escaped_safe_str(exitconn->_base.address));
  assert_cache_ok();
  return launch_resolve(exitconn);
}

/** Log an error and abort if conn is waiting for a DNS resolve.
 */
void
assert_connection_edge_not_dns_pending(edge_connection_t *conn)
{
  pending_connection_t *pend;
  cached_resolve_t **resolve;

  HT_FOREACH(resolve, cache_map, &cache_root) {
    for (pend = (*resolve)->pending_connections;
         pend;
         pend = pend->next) {
      tor_assert(pend->conn != conn);
    }
  }
}

/** Log an error and abort if any connection waiting for a DNS resolve is
 * corrupted. */
void
assert_all_pending_dns_resolves_ok(void)
{
  pending_connection_t *pend;
  cached_resolve_t **resolve;

  HT_FOREACH(resolve, cache_map, &cache_root) {
    for (pend = (*resolve)->pending_connections;
         pend;
         pend = pend->next) {
      assert_connection_ok(TO_CONN(pend->conn), 0);
      tor_assert(pend->conn->_base.s == -1);
      tor_assert(!connection_in_array(TO_CONN(pend->conn)));
    }
  }
}

/** Remove <b>conn</b> from the list of connections waiting for conn-\>address.
 */
void
connection_dns_remove(edge_connection_t *conn)
{
  pending_connection_t *pend, *victim;
  cached_resolve_t search;
  cached_resolve_t *resolve;

  tor_assert(conn->_base.type == CONN_TYPE_EXIT);
  tor_assert(conn->_base.state == EXIT_CONN_STATE_RESOLVING);

  strlcpy(search.address, conn->_base.address, sizeof(search.address));

  resolve = HT_FIND(cache_map, &cache_root, &search);
  if (!resolve) {
    log_notice(LD_BUG, "Address %s is not pending. Dropping.",
               escaped_safe_str(conn->_base.address));
    return;
  }

  tor_assert(resolve->pending_connections);
  assert_connection_ok(TO_CONN(conn),0);

  pend = resolve->pending_connections;

  if (pend->conn == conn) {
    resolve->pending_connections = pend->next;
    tor_free(pend);
    log_debug(LD_EXIT, "First connection (fd %d) no longer waiting "
              "for resolve of %s",
              conn->_base.s, escaped_safe_str(conn->_base.address));
    return;
  } else {
    for ( ; pend->next; pend = pend->next) {
      if (pend->next->conn == conn) {
        victim = pend->next;
        pend->next = victim->next;
        tor_free(victim);
        log_debug(LD_EXIT,
                  "Connection (fd %d) no longer waiting for resolve of %s",
                  conn->_base.s, escaped_safe_str(conn->_base.address));
        return; /* more are pending */
      }
    }
    tor_assert(0); /* not reachable unless onlyconn not in pending list */
  }
}

/** Mark all connections waiting for <b>address</b> for close.  Then cancel
 * the resolve for <b>address</b> itself, and remove any cached results for
 * <b>address</b> from the cache.
 */
void
dns_cancel_pending_resolve(char *address)
{
  pending_connection_t *pend;
  cached_resolve_t search;
  cached_resolve_t *resolve, *tmp;
  edge_connection_t *pendconn;
  circuit_t *circ;

  strlcpy(search.address, address, sizeof(search.address));

  resolve = HT_FIND(cache_map, &cache_root, &search);
  if (!resolve || resolve->state != CACHE_STATE_PENDING) {
    log_notice(LD_BUG,"Address %s is not pending. Dropping.",
               escaped_safe_str(address));
    return;
  }

  if (!resolve->pending_connections) {
    /* XXX this should never trigger, but sometimes it does */
    log_warn(LD_BUG,
             "Bug: Address %s is pending but has no pending connections!",
             escaped_safe_str(address));
    tor_fragile_assert();
    return;
  }
  tor_assert(resolve->pending_connections);
  tor_assert(! resolve->expire);

  /* mark all pending connections to fail */
  log_debug(LD_EXIT,
             "Failing all connections waiting on DNS resolve of %s",
             escaped_safe_str(address));
  while (resolve->pending_connections) {
    pend = resolve->pending_connections;
    pend->conn->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
    pendconn = pend->conn;
    assert_connection_ok(TO_CONN(pendconn), 0);
    tor_assert(pendconn->_base.s == -1);
    if (!pendconn->_base.marked_for_close) {
      connection_edge_end(pendconn, END_STREAM_REASON_RESOURCELIMIT,
                          pendconn->cpath_layer);
    }
    circ = circuit_get_by_edge_conn(pendconn);
    if (circ)
      circuit_detach_stream(circ, pendconn);
    connection_free(TO_CONN(pendconn));
    resolve->pending_connections = pend->next;
    tor_free(pend);
  }

  tmp = HT_REMOVE(cache_map, &cache_root, resolve);
  if (tmp != resolve) {
    log_err(LD_BUG, "The cancelled resolve we purged didn't match any in"
            " the cache. Tried to purge %s (%p); instead got %s (%p).",
            resolve->address, resolve,
            tmp ? tmp->address : "NULL", tmp);
  }
  tor_assert(tmp == resolve);
  resolve->magic = 0xABABABAB;
  tor_free(resolve);
}

static void
add_answer_to_cache(const char *address, uint32_t addr, char outcome,
                    uint32_t ttl)
{
  cached_resolve_t *resolve;
  if (outcome == DNS_RESOLVE_FAILED_TRANSIENT)
    return;

  resolve = tor_malloc_zero(sizeof(cached_resolve_t));
  resolve->magic = CACHED_RESOLVE_MAGIC;
  resolve->state = (outcome == DNS_RESOLVE_SUCCEEDED) ?
    CACHE_STATE_CACHED_VALID : CACHE_STATE_CACHED_FAILED;
  strlcpy(resolve->address, address, sizeof(resolve->address));
  resolve->addr = addr;
  resolve->ttl = ttl;
  assert_resolve_ok(resolve);
  HT_INSERT(cache_map, &cache_root, resolve);
  set_expiry(resolve, time(NULL) + dns_get_expiry_ttl(ttl));
}

/** Called on the OR side when a DNS worker tells us the outcome of a DNS
 * resolve: tell all pending connections about the result of the lookup, and
 * cache the value.  (<b>address</b> is a NUL-terminated string containing the
 * address to look up; <b>addr</b> is an IPv4 address in host order;
 * <b>outcome</b> is one of
 * DNS_RESOLVE_{FAILED_TRANSIENT|FAILED_PERMANENT|SUCCEEDED}.
 */
static void
dns_found_answer(const char *address, uint32_t addr, char outcome,
                 uint32_t ttl)
{
  pending_connection_t *pend;
  cached_resolve_t search;
  cached_resolve_t *resolve, *removed;
  edge_connection_t *pendconn;
  circuit_t *circ;

  assert_cache_ok();

  strlcpy(search.address, address, sizeof(search.address));

  resolve = HT_FIND(cache_map, &cache_root, &search);
  if (!resolve) {
    log_info(LD_EXIT,"Resolved unasked address %s; caching anyway.",
             escaped_safe_str(address));
    add_answer_to_cache(address, addr, outcome, ttl);
    return;
  }
  assert_resolve_ok(resolve);

  if (resolve->state != CACHE_STATE_PENDING) {
    /* XXXX Maybe update addr? or check addr for consistency? Or let
     * VALID replace FAILED? */
    log_notice(LD_EXIT, "Resolved %s which was already resolved; ignoring",
               escaped_safe_str(address));
    tor_assert(resolve->pending_connections == NULL);
    return;
  }
  /* Removed this assertion: in fact, we'll sometimes get a double answer
   * to the same question.  This can happen when we ask one worker to resolve
   * X.Y.Z., then we cancel the request, and then we ask another worker to
   * resolve X.Y.Z. */
  /* tor_assert(resolve->state == CACHE_STATE_PENDING); */

  while (resolve->pending_connections) {
    pend = resolve->pending_connections;
    pendconn = pend->conn; /* don't pass complex things to the
                              connection_mark_for_close macro */
    assert_connection_ok(TO_CONN(pendconn),time(NULL));
    pendconn->_base.addr = addr;
    pendconn->address_ttl = ttl;

    if (outcome != DNS_RESOLVE_SUCCEEDED) {
      /* prevent double-remove. */
      pendconn->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
      if (pendconn->_base.purpose == EXIT_PURPOSE_CONNECT) {
        connection_edge_end(pendconn, END_STREAM_REASON_RESOLVEFAILED,
                            pendconn->cpath_layer);
        /* This detach must happen after we send the end cell. */
        circuit_detach_stream(circuit_get_by_edge_conn(pendconn), pendconn);
      } else {
        send_resolved_cell(pendconn, RESOLVED_TYPE_ERROR);
        /* This detach must happen after we send the resolved cell. */
        circuit_detach_stream(circuit_get_by_edge_conn(pendconn), pendconn);
      }
      connection_free(TO_CONN(pendconn));
    } else {
      if (pendconn->_base.purpose == EXIT_PURPOSE_CONNECT) {
        /* prevent double-remove. */
        pend->conn->_base.state = EXIT_CONN_STATE_CONNECTING;

        circ = circuit_get_by_edge_conn(pend->conn);
        tor_assert(circ);
        tor_assert(!CIRCUIT_IS_ORIGIN(circ));
        /* unlink pend->conn from resolving_streams, */
        circuit_detach_stream(circ, pend->conn);
        /* and link it to n_streams */
        pend->conn->next_stream = TO_OR_CIRCUIT(circ)->n_streams;
        pend->conn->on_circuit = circ;
        TO_OR_CIRCUIT(circ)->n_streams = pend->conn;

        connection_exit_connect(pend->conn);
      } else {
        /* prevent double-remove.  This isn't really an accurate state,
         * but it does the right thing. */
        pendconn->_base.state = EXIT_CONN_STATE_RESOLVEFAILED;
        send_resolved_cell(pendconn, RESOLVED_TYPE_IPV4);
        circ = circuit_get_by_edge_conn(pendconn);
        tor_assert(circ);
        circuit_detach_stream(circ, pendconn);
        connection_free(TO_CONN(pendconn));
      }
    }
    resolve->pending_connections = pend->next;
    tor_free(pend);
  }

  resolve->state = CACHE_STATE_DONE;
  removed = HT_REMOVE(cache_map, &cache_root, &search);
  if (removed != resolve) {
    log_err(LD_BUG, "The pending resolve we found wasn't removable from"
            " the cache. Tried to purge %s (%p); instead got %s (%p).",
            resolve->address, resolve,
            removed ? removed->address : "NULL", removed);
  }
  assert_resolve_ok(resolve);
  assert_cache_ok();

  add_answer_to_cache(address, addr, outcome, ttl);
  assert_cache_ok();
}

#ifndef USE_EVENTDNS
/** Find or spawn a dns worker process to handle resolving
 * <b>exitconn</b>-\>address; tell that dns worker to begin resolving.
 */
static int
launch_resolve(edge_connection_t *exitconn)
{
  connection_t *dnsconn;
  unsigned char len;

  tor_assert(exitconn->_base.state == EXIT_CONN_STATE_RESOLVING);
  assert_connection_ok(TO_CONN(exitconn), 0);
  tor_assert(exitconn->_base.s == -1);

  /* respawn here, to be sure there are enough */
  if (spawn_enough_dnsworkers() < 0) {
    goto err;
  }

  dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER,
                                         DNSWORKER_STATE_IDLE);

  if (!dnsconn) {
    log_warn(LD_EXIT,"no idle dns workers. Failing.");
    if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE)
      send_resolved_cell(exitconn, RESOLVED_TYPE_ERROR_TRANSIENT);
    goto err;
  }

  log_debug(LD_EXIT,
            "Connection (fd %d) needs to resolve %s; assigning "
            "to DNSWorker (fd %d)", exitconn->_base.s,
            escaped_safe_str(exitconn->_base.address), dnsconn->s);

  tor_free(dnsconn->address);
  dnsconn->address = tor_strdup(exitconn->_base.address);
  dnsconn->state = DNSWORKER_STATE_BUSY;
  /* touch the lastwritten timestamp, since that's how we check to
   * see how long it's been since we asked the question, and sometimes
   * we check before the first call to connection_handle_write(). */
  dnsconn->timestamp_lastwritten = time(NULL);
  num_dnsworkers_busy++;

  len = strlen(dnsconn->address);
  connection_write_to_buf((char*)&len, 1, dnsconn);
  connection_write_to_buf(dnsconn->address, len, dnsconn);

  return 0;
err:
  /* also sends end and frees */
  dns_cancel_pending_resolve(exitconn->_base.address);
  return -1;
}

/******************************************************************/

/*
 * Connection between OR and dnsworker
 */

/** Write handler: called when we've pushed a request to a dnsworker. */
int
connection_dns_finished_flushing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DNSWORKER);
  connection_stop_writing(conn);
  return 0;
}

int
connection_dns_reached_eof(connection_t *conn)
{
  log_warn(LD_EXIT,"Read eof. Worker died unexpectedly.");
  if (conn->state == DNSWORKER_STATE_BUSY) {
    /* don't cancel the resolve here -- it would be cancelled in
     * connection_about_to_close_connection(), since conn is still
     * in state BUSY
     */
    num_dnsworkers_busy--;
  }
  num_dnsworkers--;
  connection_mark_for_close(conn);
  return 0;
}

/** Read handler: called when we get data from a dnsworker. See
 * if we have a complete answer.  If so, call dns_found_answer on the
 * result.  If not, wait.  Returns 0. */
int
connection_dns_process_inbuf(connection_t *conn)
{
  char success;
  uint32_t addr;
  int ttl;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DNSWORKER);

  if (conn->state != DNSWORKER_STATE_BUSY && buf_datalen(conn->inbuf)) {
    log_warn(LD_BUG,
             "Bug: read data (%d bytes) from an idle dns worker (fd %d, "
             "address %s). Please report.", (int)buf_datalen(conn->inbuf),
             conn->s, escaped_safe_str(conn->address));
    tor_fragile_assert();

    /* Pull it off the buffer anyway, or it will just stay there.
     * Keep pulling things off because sometimes we get several
     * answers at once (!). */
    while (buf_datalen(conn->inbuf)) {
      connection_fetch_from_buf(&success,1,conn);
      connection_fetch_from_buf((char *)&addr,sizeof(uint32_t),conn);
      log_warn(LD_EXIT,"Discarding idle dns answer (success %d, addr %d.)",
               success, addr);
    }
    return 0;
  }
  if (buf_datalen(conn->inbuf) < 5) /* entire answer available? */
    return 0; /* not yet */
  tor_assert(conn->state == DNSWORKER_STATE_BUSY);
  tor_assert(buf_datalen(conn->inbuf) == 5);

  connection_fetch_from_buf(&success,1,conn);
  connection_fetch_from_buf((char *)&addr,sizeof(uint32_t),conn);

  log_debug(LD_EXIT, "DNSWorker (fd %d) returned answer for %s",
            conn->s, escaped_safe_str(conn->address));

  tor_assert(success >= DNS_RESOLVE_FAILED_TRANSIENT);
  tor_assert(success <= DNS_RESOLVE_SUCCEEDED);

  ttl = (success == DNS_RESOLVE_FAILED_TRANSIENT) ? 0 : MAX_DNS_ENTRY_AGE;
  dns_found_answer(conn->address, ntohl(addr), success, ttl);

  tor_free(conn->address);
  conn->address = tor_strdup("<idle>");
  conn->state = DNSWORKER_STATE_IDLE;
  num_dnsworkers_busy--;
  if (conn->timestamp_created < last_rotation_time) {
    connection_mark_for_close(conn);
    num_dnsworkers--;
    spawn_enough_dnsworkers();
  }
  return 0;
}

/** Close and re-open all idle dnsworkers; schedule busy ones to be closed
 * and re-opened once they're no longer busy.
 **/
void
dnsworkers_rotate(void)
{
  connection_t *dnsconn;
  while ((dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER,
                                                 DNSWORKER_STATE_IDLE))) {
    connection_mark_for_close(dnsconn);
    num_dnsworkers--;
  }
  last_rotation_time = time(NULL);
  if (server_mode(get_options()))
    spawn_enough_dnsworkers();
}

/** Implementation for DNS workers; this code runs in a separate
 * execution context.  It takes as its argument an fdarray as returned
 * by socketpair(), and communicates via fdarray[1].  The protocol is
 * as follows:
 *    - The OR says:
 *         - ADDRESSLEN [1 byte]
 *         - ADDRESS    [ADDRESSLEN bytes]
 *    - The DNS worker does the lookup, and replies:
 *         - OUTCOME    [1 byte]
 *         - IP         [4 bytes]
 *
 * OUTCOME is one of DNS_RESOLVE_{FAILED_TRANSIENT|FAILED_PERMANENT|SUCCEEDED}.
 * IP is in host order.
 *
 * The dnsworker runs indefinitely, until its connection is closed or an error
 * occurs.
 */
static int
dnsworker_main(void *data)
{
  char address[MAX_ADDRESSLEN];
  unsigned char address_len;
  char *log_address;
  char answer[5];
  uint32_t ip;
  int *fdarray = data;
  int fd;
  int result;

  /* log_fn(LOG_NOTICE,"After spawn: fdarray @%d has %d:%d", (int)fdarray,
   * fdarray[0],fdarray[1]); */

  fd = fdarray[1]; /* this side is ours */
#ifndef TOR_IS_MULTITHREADED
  tor_close_socket(fdarray[0]); /* this is the side of the socketpair the
                                 * parent uses */
  tor_free_all(1); /* so the child doesn't hold the parent's fd's open */
  handle_signals(0); /* ignore interrupts from the keyboard, etc */
#endif
  tor_free(data);

  for (;;) {
    int r;

    if ((r = recv(fd, &address_len, 1, 0)) != 1) {
      if (r == 0) {
        log_info(LD_EXIT,"DNS worker exiting because Tor process closed "
                 "connection (either pruned idle dnsworker or died).");
      } else {
        log_info(LD_EXIT,"DNS worker exiting because of error on connection "
                 "to Tor process.");
        log_info(LD_EXIT,"(Error on %d was %s)", fd,
                 tor_socket_strerror(tor_socket_errno(fd)));
      }
      tor_close_socket(fd);
      crypto_thread_cleanup();
      spawn_exit();
    }

    if (address_len && read_all(fd, address, address_len, 1) != address_len) {
      log_err(LD_BUG,"read hostname failed. Child exiting.");
      tor_close_socket(fd);
      crypto_thread_cleanup();
      spawn_exit();
    }
    address[address_len] = 0; /* nul terminate it */

    log_address = esc_for_log(safe_str(address));
    result = tor_lookup_hostname(address, &ip);
    /* Make 0.0.0.0 an error, so that we can use "0" to mean "no addr") */
    if (!ip)
      result = -1;
    switch (result) {
      case 1:
        /* XXX result can never be 1, because we set it to -1 above on error */
        log_info(LD_NET,"Could not resolve dest addr %s (transient).",
                 log_address);
        answer[0] = DNS_RESOLVE_FAILED_TRANSIENT;
        break;
      case -1:
        log_info(LD_NET,"Could not resolve dest addr %s (permanent).",
                 log_address);
        answer[0] = DNS_RESOLVE_FAILED_PERMANENT;
        break;
      case 0:
        log_info(LD_NET,"Resolved address %s.", log_address);
        answer[0] = DNS_RESOLVE_SUCCEEDED;
        break;
    }
    tor_free(log_address);
    set_uint32(answer+1, ip);
    if (write_all(fd, answer, 5, 1) != 5) {
      log_err(LD_NET,"writing answer failed. Child exiting.");
      tor_close_socket(fd);
      crypto_thread_cleanup();
      spawn_exit();
    }
  }
  return 0; /* windows wants this function to return an int */
}

/** Launch a new DNS worker; return 0 on success, -1 on failure.
 */
static int
spawn_dnsworker(void)
{
  int *fdarray;
  int fd;
  connection_t *conn;
  int err;

  fdarray = tor_malloc(sizeof(int)*2);
  if ((err = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fdarray)) < 0) {
    log_warn(LD_NET, "Couldn't construct socketpair: %s",
             tor_socket_strerror(-err));
    tor_free(fdarray);
    return -1;
  }

  tor_assert(fdarray[0] >= 0);
  tor_assert(fdarray[1] >= 0);

  /* log_fn(LOG_NOTICE,"Before spawn: fdarray @%d has %d:%d",
            (int)fdarray, fdarray[0],fdarray[1]); */

  fd = fdarray[0]; /* We copy this out here, since dnsworker_main may free
                    * fdarray */
  spawn_func(dnsworker_main, (void*)fdarray);
  log_debug(LD_EXIT,"just spawned a dns worker.");
#ifndef TOR_IS_MULTITHREADED
  tor_close_socket(fdarray[1]); /* don't need the worker's side of the pipe */
  tor_free(fdarray);
#endif

  conn = connection_new(CONN_TYPE_DNSWORKER);

  set_socket_nonblocking(fd);

  /* set up conn so it's got all the data we need to remember */
  conn->s = fd;
  conn->address = tor_strdup("<unused>");

  if (connection_add(conn) < 0) { /* no space, forget it */
    log_warn(LD_NET,"connection_add failed. Giving up.");
    connection_free(conn); /* this closes fd */
    return -1;
  }

  conn->state = DNSWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

/** If we have too many or too few DNS workers, spawn or kill some.
 * Return 0 if we are happy, return -1 if we tried to spawn more but
 * we couldn't.
 */
static int
spawn_enough_dnsworkers(void)
{
  int num_dnsworkers_needed; /* aim to have 1 more than needed,
                           * but no less than min and no more than max */
  connection_t *dnsconn;

  /* XXX This may not be the best strategy. Maybe we should queue pending
   *     requests until the old ones finish or time out: otherwise, if the
   *     connection requests come fast enough, we never get any DNS done. -NM
   *
   * XXX But if we queue them, then the adversary can pile even more
   *     queries onto us, blocking legitimate requests for even longer.  Maybe
   *     we should compromise and only kill if it's been at it for more than,
   *     e.g., 2 seconds. -RD
   */
  if (num_dnsworkers_busy == MAX_DNSWORKERS) {
    /* We always want at least one worker idle.
     * So find the oldest busy worker and kill it.
     */
    dnsconn = connection_get_by_type_state_lastwritten(CONN_TYPE_DNSWORKER,
                                                       DNSWORKER_STATE_BUSY);
    tor_assert(dnsconn);

    log_warn(LD_EXIT, "%d DNS workers are spawned; all are busy. Killing one.",
             MAX_DNSWORKERS);

    connection_mark_for_close(dnsconn);
    num_dnsworkers_busy--;
    num_dnsworkers--;
  }

  if (num_dnsworkers_busy >= MIN_DNSWORKERS)
    num_dnsworkers_needed = num_dnsworkers_busy+1;
  else
    num_dnsworkers_needed = MIN_DNSWORKERS;

  while (num_dnsworkers < num_dnsworkers_needed) {
    if (spawn_dnsworker() < 0) {
      log_warn(LD_EXIT,"Spawn failed. Will try again later.");
      return -1;
    }
    num_dnsworkers++;
  }

  while (num_dnsworkers > num_dnsworkers_busy+MAX_IDLE_DNSWORKERS) {
    /* too many idle? */
    /* cull excess workers */
    log_info(LD_EXIT,"%d of %d dnsworkers are idle. Killing one.",
             num_dnsworkers-num_dnsworkers_busy, num_dnsworkers);
    dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER,
                                           DNSWORKER_STATE_IDLE);
    tor_assert(dnsconn);
    connection_mark_for_close(dnsconn);
    num_dnsworkers--;
  }

  return 0;
}
#else /* !USE_EVENTDNS */
static int
eventdns_err_is_transient(int err)
{
  switch (err)
  {
    case DNS_ERR_SERVERFAILED:
    case DNS_ERR_TRUNCATED:
    case DNS_ERR_TIMEOUT:
      return 1;
    default:
      return 0;
  }
}
void
dnsworkers_rotate(void)
{
}
int
connection_dns_finished_flushing(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}
int
connection_dns_process_inbuf(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}
int
connection_dns_reached_eof(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}
static int nameservers_configured = 0;
static void
configure_nameservers(void)
{
  or_options_t *options;
  if (nameservers_configured)
    return;
  options = get_options();
  eventdns_set_log_fn(eventdns_log_cb);
  if (options->Nameservers && smartlist_len(options->Nameservers)) {
    log_info(LD_EXIT, "Configuring nameservers from Tor configuration");
    SMARTLIST_FOREACH(options->Nameservers, const char *, ip,
      {
        struct in_addr in;
        if (tor_inet_aton(ip, &in)) {
          log_info(LD_EXIT, "Adding nameserver '%s'", ip);
          eventdns_nameserver_add(in.s_addr);
        }
      });
  } else {
#ifdef MS_WINDOWS
    eventdns_config_windows_nameservers();
#else
    log_info(LD_EXIT, "Parsing /etc/resolv.conf");
    eventdns_resolv_conf_parse(DNS_OPTION_NAMESERVERS|DNS_OPTION_MISC,
                               "/etc/resolv.conf");
#endif
  }
  nameservers_configured = 1;
}
static void
eventdns_callback(int result, char type, int count, int ttl, void *addresses,
                  void *arg)
{
  char *string_address = arg;
  int status = DNS_RESOLVE_FAILED_PERMANENT;
  uint32_t addr = 0;
  if (result == DNS_ERR_NONE) {
    if (type == DNS_IPv4_A && count) {
      char answer_buf[INET_NTOA_BUF_LEN+1];
      struct in_addr in;
      uint32_t *addrs = addresses;
      in.s_addr = addrs[0];
      addr = ntohl(addrs[0]);
      status = DNS_RESOLVE_SUCCEEDED;
      tor_inet_ntoa(&in, answer_buf, sizeof(answer_buf));
      log_debug(LD_EXIT, "eventdns said that %s resolves to %s",
                escaped_safe_str(string_address),
                escaped_safe_str(answer_buf));
    } else if (count) {
      log_warn(LD_EXIT, "eventdns returned only non-IPv4 answers for %s.",
               escaped_safe_str(string_address));
    } else {
      log_warn(LD_BUG, "eventdns returned no addresses or error for %s!",
               escaped_safe_str(string_address));
    }
  } else {
    if (eventdns_err_is_transient(result))
      status = DNS_RESOLVE_FAILED_TRANSIENT;
  }
  dns_found_answer(string_address, addr, status, ttl);
  tor_free(string_address);
}

static int
launch_resolve(edge_connection_t *exitconn)
{
  char *addr = tor_strdup(exitconn->_base.address);
  int r;
  if (!nameservers_configured)
    configure_nameservers();
  log_info(LD_EXIT, "Launching eventdns request for %s",
           escaped_safe_str(exitconn->_base.address));
  r = eventdns_resolve(exitconn->_base.address, DNS_QUERY_NO_SEARCH,
                       eventdns_callback, addr);
  if (r) {
    log_warn(LD_EXIT, "eventdns rejected address %s: error %d.",
             escaped_safe_str(addr), r);
    if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE) {
      if (eventdns_err_is_transient(r))
        send_resolved_cell(exitconn, RESOLVED_TYPE_ERROR_TRANSIENT);
      else {
        exitconn->address_ttl = DEFAULT_DNS_TTL;
        send_resolved_cell(exitconn, RESOLVED_TYPE_ERROR);
      }
    }
    dns_cancel_pending_resolve(addr);/* also sends end and frees */
    tor_free(addr);
  }
  return r ? -1 : 0;
}
#endif /* USE_EVENTDNS */

static void
assert_resolve_ok(cached_resolve_t *resolve)
{
  tor_assert(resolve);
  tor_assert(resolve->magic == CACHED_RESOLVE_MAGIC);
  tor_assert(strlen(resolve->address) < MAX_ADDRESSLEN);
  tor_assert(tor_strisnonupper(resolve->address));
  if (resolve->state != CACHE_STATE_PENDING) {
    tor_assert(!resolve->pending_connections);
  }
  if (resolve->state == CACHE_STATE_PENDING ||
      resolve->state == CACHE_STATE_DONE) {
    tor_assert(!resolve->ttl);
    tor_assert(!resolve->addr);
  }
}

static void
assert_cache_ok(void)
{
  cached_resolve_t **resolve;
  int bad_rep = _cache_map_HT_REP_IS_BAD(&cache_root);
  if (bad_rep) {
    log_err(LD_BUG, "Bad rep type %d on dns cache hash table", bad_rep);
    tor_assert(!bad_rep);
  }

  HT_FOREACH(resolve, cache_map, &cache_root) {
    assert_resolve_ok(*resolve);
    tor_assert((*resolve)->state != CACHE_STATE_DONE);
  }
  if (!cached_resolve_pqueue)
    return;

  smartlist_pqueue_assert_ok(cached_resolve_pqueue,
                             _compare_cached_resolves_by_expiry);
}

