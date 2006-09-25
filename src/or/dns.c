/* Copyright 2003-2004 Roger Dingledine.
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dns_c_id[] =
  "$Id$";

/**
 * \file dns.c
 * \brief Implements a local cache for DNS results for Tor servers.
 * We provide two asynchronous backend implementations:
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
#else
/** Have we currently configured nameservers with eventdns? */
static int nameservers_configured = 0;
/** What was the resolv_conf fname we last used when configuring the
 * nameservers? Used to check whether we need to reconfigure. */
static char *resolv_conf_fname = NULL;
/** What was the mtime on the resolv.conf file we last used when configuring
 * the nameservers?  Used to check whether we need to reconfigure. */
static time_t resolv_conf_mtime = 0;
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
  union {
    uint32_t addr;  /**< IPv4 addr for <b>address</b>. */
    char *hostname; /**< Hostname for <b>address</b> (if a reverse lookup) */
  } result;
  uint8_t state; /**< Is this cached entry pending/done/valid/failed? */
  uint8_t is_reverse; /**< Is this a reverse (addr-to-hostname) lookup? */
  time_t expire; /**< Remove items from cache after this time. */
  uint32_t ttl; /**< What TTL did the nameserver tell us? */
  /** Connections that want to know when we get an answer for this resolve. */
  pending_connection_t *pending_connections;
} cached_resolve_t;

static void purge_expired_resolves(time_t now);
static void dns_found_answer(const char *address, int is_reverse,
                             uint32_t addr, const char *hostname, char outcome,
                             uint32_t ttl);
static void send_resolved_cell(edge_connection_t *conn, or_circuit_t *circ,
                               uint8_t answer_type);
static int launch_resolve(edge_connection_t *exitconn, or_circuit_t *circ);
#ifndef USE_EVENTDNS
static void dnsworkers_rotate(void);
static void dnsworker_main(void *data);
static int spawn_dnsworker(void);
static int spawn_enough_dnsworkers(void);
#else
static int configure_nameservers(int force);
static int answer_is_wildcarded(const char *ip);
#endif
#ifdef DEBUG_DNS_CACHE
static void _assert_cache_ok(void);
#define assert_cache_ok() _assert_cache_ok()
#else
#define assert_cache_ok() do {} while (0)
#endif
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

/** Hash function for cached_resolve objects */
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
/** Helper: called by eventdns when eventdns wants to log something. */
static void
evdns_log_cb(int warn, const char *msg)
{
  if (!strcmpstart(msg, "Resolve requested for") &&
      get_options()->SafeLogging) {
    log(LOG_INFO, LD_EXIT, "eventdns: Resolve requested.");
    return;
  } else if (!strcmpstart(msg, "Search: ")) {
    return;
  }
  log(warn?LOG_WARN:LOG_INFO, LD_EXIT, "eventdns: %s", msg);
}
#endif

/** Initialize the DNS subsystem; called by the OR process. */
int
dns_init(void)
{
  init_cache_map();
#ifdef USE_EVENTDNS
  if (server_mode(get_options()))
    return configure_nameservers(1);
#else
  dnsworkers_rotate();
#endif
  return 0;
}

/** Called when DNS-related options change (or may have changed) */
void
dns_reset(void)
{
#ifdef USE_EVENTDNS
  or_options_t *options = get_options();
  if (! server_mode(options)) {
    evdns_clear_nameservers_and_suspend();
    evdns_search_clear();
    nameservers_configured = 0;
    tor_free(resolv_conf_fname);
    resolv_conf_mtime = 0;
  } else {
    if (configure_nameservers(0) < 0)
      /* XXXX */
      return;
  }
#else
  dnsworkers_rotate();
#endif
}

/** Helper: Given a TTL from a DNS response, determine what TTL to give the
 * OP that asked us to resolve it. */
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

/** Helper: Given a TTL from a DNS response, determine how long to hold it in
 * our cache. */
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
  if (r->is_reverse)
    tor_free(r->result.hostname);
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
  return a->expire - b->expire;
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

/** Free all storage held in the DNS cache and related structures. */
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
#ifdef USE_EVENTDNS
  tor_free(resolv_conf_fname);
#endif
}

/** Remove every cached_resolve whose <b>expire</b> time is before <b>now</b>
 * from the cache. */
static void
purge_expired_resolves(time_t now)
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
                "Expiring a dns resolve %s that's still pending. Forgot to "
                "cull it? DNS resolve didn't tell us about the timeout?",
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
                resolve->address, (void*)resolve,
                removed ? removed->address : "NULL", (void*)remove);
      }
      tor_assert(removed == resolve);
      if (resolve->is_reverse)
        tor_free(resolve->result.hostname);
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
 * be one of RESOLVED_TYPE_(IPV4|ERROR|ERROR_TRANSIENT)
 *
 * If <b>circ</b> is provided, and we have a cached answer, send the
 * answer back along circ; otherwise, send the answer back along *
 * <b>exitconn</b>'s attached circuit.
 */
static void
send_resolved_cell(edge_connection_t *conn, or_circuit_t *circ,
                   uint8_t answer_type)
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
      return;
    }
  // log_notice(LD_EXIT, "Sending a regular RESOLVED reply: ");

  if (!circ) {
    circuit_t *tmp = circuit_get_by_edge_conn(conn);
    if (! CIRCUIT_IS_ORIGIN(tmp))
      circ = TO_OR_CIRCUIT(tmp);
  }

  connection_edge_send_command(conn, TO_CIRCUIT(circ),
                               RELAY_COMMAND_RESOLVED, buf, buflen,
                               conn->cpath_layer);
}

/** Send a response to the RESOLVE request of a connection for an in-addr.arpa
 * address on connection <b>conn</b> which yielded the result <b>hostname</b>.
 * The answer type will be RESOLVED_HOSTNAME.
 *
 * If <b>circ</b> is provided, and we have a cached answer, send the
 * answer back along circ; otherwise, send the answer back along
 * <b>exitconn</b>'s attached circuit.
 */
static void
send_resolved_hostname_cell(edge_connection_t *conn, or_circuit_t *circ,
                            const char *hostname)
{
  char buf[RELAY_PAYLOAD_SIZE];
  size_t buflen;
  uint32_t ttl;
  size_t namelen = strlen(hostname);

  tor_assert(namelen < 256);
  ttl = dns_clip_ttl(conn->address_ttl);

  buf[0] = RESOLVED_TYPE_HOSTNAME;
  buf[1] = (uint8_t)namelen;
  memcpy(buf+2, hostname, namelen);
  set_uint32(buf+2+namelen, htonl(ttl));
  buflen = 2+namelen+4;

  if (!circ) {
    circuit_t *tmp = circuit_get_by_edge_conn(conn);
    if (! CIRCUIT_IS_ORIGIN(tmp))
      circ = TO_OR_CIRCUIT(tmp);
  }

  // log_notice(LD_EXIT, "Sending a reply RESOLVED reply: %s", hostname);
  connection_edge_send_command(conn, TO_CIRCUIT(circ),
                               RELAY_COMMAND_RESOLVED, buf, buflen,
                               conn->cpath_layer);
  // log_notice(LD_EXIT, "Sent");
}

/** Given a lower-case <b>address</b>, check to see whether it's a
 * 1.2.3.4.in-addr.arpa address used for reverse lookups.  If so,
 * parse it and place the address in <b>in</b> if present. Return 1 on success;
 * 0 if the address is not in in-addr.arpa format, and -1 if the address is
 * malformed. */
static int
parse_inaddr_arpa_address(const char *address, struct in_addr *in)
{
  char buf[INET_NTOA_BUF_LEN];
  char *cp;
  size_t len;
  struct in_addr inaddr;

  cp = strstr(address, ".in-addr.arpa");
  if (!cp || *(cp+strlen(".in-addr.arpa")))
    return 0; /* not an .in-addr.arpa address  */

  len = cp - address;

  if (len >= INET_NTOA_BUF_LEN)
    return -1; /* Too long. */

  memcpy(buf, address, len);
  buf[len] = '\0';
  if (tor_inet_aton(buf, &inaddr) == 0)
    return -1; /* malformed. */

  if (in) {
    uint32_t a;
    /* reverse the bytes */
    a = (  ((inaddr.s_addr & 0x000000fful) << 24)
          |((inaddr.s_addr & 0x0000ff00ul) << 8)
          |((inaddr.s_addr & 0x00ff0000ul) >> 8)
          |((inaddr.s_addr & 0xff000000ul) >> 24));
    inaddr.s_addr = a;

    memcpy(in, &inaddr, sizeof(inaddr));
  }

  return 1;
}

/** See if we have a cache entry for <b>exitconn</b>-\>address. if so,
 * if resolve valid, put it into <b>exitconn</b>-\>addr and return 1.
 * If resolve failed, unlink exitconn if needed, free it, and return -1.
 *
 * If <b>oncirc</b> is provided, and this is a resolve request, we have
 * a cached answer, send the answer back along oncirc; otherwise, send
 * the answer back along <b>exitconn</b>'s attached circuit.
 *
 * Else, if seen before and pending, add conn to the pending list,
 * and return 0.
 *
 * Else, if not seen before, add conn to pending list, hand to
 * dns farm, and return 0.
 */
int
dns_resolve(edge_connection_t *exitconn, or_circuit_t *oncirc)
{
  cached_resolve_t *resolve;
  cached_resolve_t search;
  pending_connection_t *pending_connection;
  circuit_t *circ;
  struct in_addr in;
  time_t now = time(NULL);
  int is_reverse = 0, is_resolve, r;
  assert_connection_ok(TO_CONN(exitconn), 0);
  tor_assert(exitconn->_base.s == -1);

  assert_cache_ok();

  is_resolve = exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE;

  /* first check if exitconn->_base.address is an IP. If so, we already
   * know the answer. */
  if (tor_inet_aton(exitconn->_base.address, &in) != 0) {
    exitconn->_base.addr = ntohl(in.s_addr);
    exitconn->address_ttl = DEFAULT_DNS_TTL;
    if (is_resolve)
      send_resolved_cell(exitconn, oncirc, RESOLVED_TYPE_IPV4);
    return 1;
  }

  /* then take this opportunity to see if there are any expired
   * resolves in the hash table. */
  purge_expired_resolves(now);

  /* lower-case exitconn->_base.address, so it's in canonical form */
  tor_strlower(exitconn->_base.address);

  /* Check whether this is a reverse lookup.  If it's malformed, or it's a
   * .in-addr.arpa address but this isn't a resolve request, kill the
   * connection.
   */
  if ((r = parse_inaddr_arpa_address(exitconn->_base.address, NULL)) != 0) {
    if (r == 1)
      is_reverse = 1;

#ifdef USE_EVENTDNS
    if (!is_reverse || !is_resolve) {
      if (!is_reverse)
        log_info(LD_EXIT, "Bad .in-addr.arpa address \"%s\"; sending error.",
                 escaped_safe_str(exitconn->_base.address));
      else if (!is_resolve)
        log_info(LD_EXIT,
                 "Attempt to connect to a .in-addr.arpa address \"%s\"; "
                 "sending error.",
                 escaped_safe_str(exitconn->_base.address));
#else
    if (1) {
      log_info(LD_PROTOCOL, "Dnsworker code does not support in-addr.arpa "
               "domain, but received a request for \"%s\"; sending error.",
               escaped_safe_str(exitconn->_base.address));
#endif

      if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE)
        send_resolved_cell(exitconn, oncirc, RESOLVED_TYPE_ERROR);
      circ = circuit_get_by_edge_conn(exitconn);
      if (circ)
        circuit_detach_stream(circ, exitconn);
      if (!exitconn->_base.marked_for_close)
        connection_free(TO_CONN(exitconn));
      return -1;
    }
    //log_notice(LD_EXIT, "Looks like an address %s",
    //exitconn->_base.address);
  }

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
        log_debug(LD_EXIT,"Connection (fd %d) found cached answer for %s",
                  exitconn->_base.s,
                  escaped_safe_str(resolve->address));
        exitconn->address_ttl = resolve->ttl;
        if (resolve->is_reverse) {
          tor_assert(is_resolve);
          send_resolved_hostname_cell(exitconn, oncirc,
                                      resolve->result.hostname);
        } else {
          exitconn->_base.addr = resolve->result.addr;
          if (is_resolve)
            send_resolved_cell(exitconn, oncirc, RESOLVED_TYPE_IPV4);
        }
        return 1;
      case CACHE_STATE_CACHED_FAILED:
        log_debug(LD_EXIT,"Connection (fd %d) found cached error for %s",
                  exitconn->_base.s,
                  escaped_safe_str(exitconn->_base.address));
        /*  XXXX send back indication of failure for connect case? -NM*/
        if (is_resolve)
          send_resolved_cell(exitconn, oncirc, RESOLVED_TYPE_ERROR);
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
  resolve->is_reverse = is_reverse;
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
  return launch_resolve(exitconn, oncirc);
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
dns_cancel_pending_resolve(const char *address)
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
            resolve->address, (void*)resolve,
            tmp ? tmp->address : "NULL", (void*)tmp);
  }
  tor_assert(tmp == resolve);

  resolve->state = CACHE_STATE_DONE;
}

/** Helper: adds an entry to the DNS cache mapping <b>address</b> to the ipv4
 * address <b>addr</b> (if is_reverse is 0) or the hostname <b>hostname</b> (if
 * is_reverse is 1).  <b>ttl</b> is a cache ttl; <b>outcome</b> is one of
 * DNS_RESOLVE_{FAILED_TRANSIENT|FAILED_PERMANENT|SUCCEEDED}.
 **/
static void
add_answer_to_cache(const char *address, int is_reverse, uint32_t addr,
                    const char *hostname, char outcome, uint32_t ttl)
{
  cached_resolve_t *resolve;
  if (outcome == DNS_RESOLVE_FAILED_TRANSIENT)
    return;

  /* XXX This is dumb, but it seems to workaround a bug I can't find.  We
   * should nail this so we can cache reverse DNS answers. -NM */
  if (is_reverse)
    return;

  //log_notice(LD_EXIT, "Adding to cache: %s -> %s (%lx, %s), %d",
  //           address, is_reverse?"(reverse)":"", (unsigned long)addr,
  //           hostname?hostname:"NULL",(int)outcome);

  resolve = tor_malloc_zero(sizeof(cached_resolve_t));
  resolve->magic = CACHED_RESOLVE_MAGIC;
  resolve->state = (outcome == DNS_RESOLVE_SUCCEEDED) ?
    CACHE_STATE_CACHED_VALID : CACHE_STATE_CACHED_FAILED;
  strlcpy(resolve->address, address, sizeof(resolve->address));
  resolve->is_reverse = is_reverse;
  if (is_reverse) {
    tor_assert(hostname);
    resolve->result.hostname = tor_strdup(hostname);
  } else {
    tor_assert(!hostname);
    resolve->result.addr = addr;
  }
  resolve->ttl = ttl;
  assert_resolve_ok(resolve);
  HT_INSERT(cache_map, &cache_root, resolve);
  set_expiry(resolve, time(NULL) + dns_get_expiry_ttl(ttl));
}

/** Called on the OR side when a DNS worker or the eventdns library tells us
 * the outcome of a DNS resolve: tell all pending connections about the result
 * of the lookup, and cache the value.  (<b>address</b> is a NUL-terminated
 * string containing the address to look up; <b>addr</b> is an IPv4 address in
 * host order; <b>outcome</b> is one of
 * DNS_RESOLVE_{FAILED_TRANSIENT|FAILED_PERMANENT|SUCCEEDED}.
 */
static void
dns_found_answer(const char *address, int is_reverse, uint32_t addr,
                 const char *hostname, char outcome, uint32_t ttl)
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
    add_answer_to_cache(address, is_reverse, addr, hostname, outcome, ttl);
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
        send_resolved_cell(pendconn, NULL, RESOLVED_TYPE_ERROR);
        /* This detach must happen after we send the resolved cell. */
        circuit_detach_stream(circuit_get_by_edge_conn(pendconn), pendconn);
      }
      connection_free(TO_CONN(pendconn));
    } else {
      if (pendconn->_base.purpose == EXIT_PURPOSE_CONNECT) {
        tor_assert(!is_reverse);
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
        if (is_reverse)
          send_resolved_hostname_cell(pendconn, NULL, hostname);
        else
          send_resolved_cell(pendconn, NULL, RESOLVED_TYPE_IPV4);
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
            resolve->address, (void*)resolve,
            removed ? removed->address : "NULL", (void*)removed);
  }
  assert_resolve_ok(resolve);
  assert_cache_ok();

  add_answer_to_cache(address, is_reverse, addr, hostname, outcome, ttl);
  assert_cache_ok();
}

#ifndef USE_EVENTDNS
/** Find or spawn a dns worker process to handle resolving
 * <b>exitconn</b>-\>address; tell that dns worker to begin resolving.
 */
static int
launch_resolve(edge_connection_t *exitconn, or_circuit_t *circ)
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
      send_resolved_cell(exitconn, circ, RESOLVED_TYPE_ERROR_TRANSIENT);
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

/** Called when a connection to a dnsworker hits an EOF; this only happens
 * when a dnsworker dies unexpectedly. */
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
  dns_found_answer(conn->address, 0, ntohl(addr), NULL, success, ttl);

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
static void
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
static void
dnsworker_main(void *data)
{
  char address[MAX_ADDRESSLEN+1]; /* Plus a byte for a final '.' */
  unsigned char address_len;
  char *log_address;
  char answer[5];
  uint32_t ip;
  int *fdarray = data;
  int fd;
  int result;
  int search = get_options()->ServerDNSSearchDomains;

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
    /* Add a period to prevent local domain search, and NUL-terminate. */
    if (address[address_len-1] != '.' && !search) {
      address[address_len] = '.';
      address[address_len+1] = '\0';
    } else {
      address[address_len] = '\0';
    }

    log_address = esc_for_log(safe_str(address));
    result = tor_lookup_hostname(address, &ip);
    /* Make 0.0.0.0 an error, so that we can use "0" to mean "no addr") */
    if (!ip)
      result = -1;
    switch (result) {
      case 1:
        /* XXX result can never be 1, because we set it to -1 above on error */
        log_info(LD_NET,"Could not resolve dest addr %s (transient)",
                 log_address);
        answer[0] = DNS_RESOLVE_FAILED_TRANSIENT;
        break;
      case -1:
        log_info(LD_NET,"Could not resolve dest addr %s (permanent)",
                 log_address);
        answer[0] = DNS_RESOLVE_FAILED_PERMANENT;
        break;
      case 0:
        log_info(LD_NET,"Resolved address %s", log_address);
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
  spawn_func((void*) dnsworker_main, (void*)fdarray);
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

void
dns_launch_wildcard_checks(void)
{
}
#else /* !USE_EVENTDNS */

/** Eventdns helper: return true iff the eventdns result <b>err</b> is
 * a transient failure. */
static int
evdns_err_is_transient(int err)
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
/* Dummy function; never called with eventdns enabled. */
int
connection_dns_finished_flushing(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}
/* Dummy function; never called with eventdns enabled. */
int
connection_dns_process_inbuf(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}
/* Dummy function; never called with eventdns enabled. */
int
connection_dns_reached_eof(connection_t *conn)
{
  (void)conn;
  tor_assert(0);
  return 0;
}

/** Configure eventdns nameservers if force is true, or if the configuration
 * has changed since the last time we called this function.  On Unix, this
 * reads from options->ServerDNSResolvConfFile or /etc/resolv.conf; on
 * Windows, this reads from options->ServerDNSResolvConfFile or the registry.
 * Return 0 on success or -1 on failure. */
static int
configure_nameservers(int force)
{
  or_options_t *options;
  const char *conf_fname;
  struct stat st;
  options = get_options();
  conf_fname = options->ServerDNSResolvConfFile;
#ifndef MS_WINDOWS
  if (!conf_fname)
    conf_fname = "/etc/resolv.conf";
#endif

  evdns_set_log_fn(evdns_log_cb);
  if (conf_fname) {
    if (stat(conf_fname, &st)) {
      log_warn(LD_EXIT, "Unable to stat resolver configuration in '%s'",
               conf_fname);
      return -1;
    }
    if (!force && resolv_conf_fname && !strcmp(conf_fname,resolv_conf_fname)
        && st.st_mtime == resolv_conf_mtime) {
      log_info(LD_EXIT, "No change to '%s'", conf_fname);
      return 0;
    }
    if (nameservers_configured) {
      evdns_search_clear();
      evdns_clear_nameservers_and_suspend();
    }
    log_info(LD_EXIT, "Parsing resolver configuration in '%s'", conf_fname);
    if (evdns_resolv_conf_parse(DNS_OPTIONS_ALL, conf_fname))
      return -1;
    if (evdns_count_nameservers() == 0) {
      log_warn(LD_EXIT, "Unable to find any nameservers in '%s'.", conf_fname);
      return -1;
    }
    tor_free(resolv_conf_fname);
    resolv_conf_fname = tor_strdup(conf_fname);
    resolv_conf_mtime = st.st_mtime;
    if (nameservers_configured)
      evdns_resume();
  }
#ifdef MS_WINDOWS
  else {
    if (nameservers_configured) {
      evdns_search_clear();
      evdns_clear_nameservers_and_suspend();
    }
    if (evdns_config_windows_nameservers())  {
      log_warn(LD_EXIT,"Could not config nameservers.");
      return -1;
    }
    if (evdns_count_nameservers() == 0) {
      log_warn(LD_EXIT, "Unable to find any platform nameservers in "
               "your Windows configuration.  Perhaps you should list a "
               "ServerDNSResolvConfFile file in your torrc?");
      return -1;
    }
    if (nameservers_configured)
      evdns_resume();
    tor_free(resolv_conf_fname);
    resolv_conf_mtime = 0;
  }
#endif

  nameservers_configured = 1;
  return 0;
}

/** For eventdns: Called when we get an answer for a request we launched.
 * See eventdns.h for arguments; 'arg' holds the address we tried to resolve.
 */
static void
evdns_callback(int result, char type, int count, int ttl, void *addresses,
                  void *arg)
{
  char *string_address = arg;
  int is_reverse = 0;
  int status = DNS_RESOLVE_FAILED_PERMANENT;
  uint32_t addr = 0;
  const char *hostname = NULL;

  if (result == DNS_ERR_NONE) {
    if (type == DNS_IPv4_A && count) {
      char answer_buf[INET_NTOA_BUF_LEN+1];
      struct in_addr in;
      char *escaped_address;
      uint32_t *addrs = addresses;
      in.s_addr = addrs[0];
      addr = ntohl(addrs[0]);
      status = DNS_RESOLVE_SUCCEEDED;
      tor_inet_ntoa(&in, answer_buf, sizeof(answer_buf));
      escaped_address = esc_for_log(string_address);

      if (answer_is_wildcarded(answer_buf)) {
        log_debug(LD_EXIT, "eventdns said that %s resolves to ISP-hijacked "
                  "address %s; treating as a failure.",
                  safe_str(escaped_address),
                  escaped_safe_str(answer_buf));
        addr = 0;
        status = DNS_RESOLVE_FAILED_PERMANENT;
      } else {
        log_debug(LD_EXIT, "eventdns said that %s resolves to %s",
                  safe_str(escaped_address),
                  escaped_safe_str(answer_buf));
      }
      tor_free(escaped_address);
    } else if (type == DNS_PTR && count) {
      char *escaped_address;
      is_reverse = 1;
      hostname = ((char**)addresses)[0];
      status = DNS_RESOLVE_SUCCEEDED;
      escaped_address = esc_for_log(string_address);
      log_debug(LD_EXIT, "eventdns said that %s resolves to %s",
                safe_str(escaped_address),
                escaped_safe_str(hostname));
      tor_free(escaped_address);
    } else if (count) {
      log_warn(LD_EXIT, "eventdns returned only non-IPv4 answers for %s.",
               escaped_safe_str(string_address));
    } else {
      log_warn(LD_BUG, "eventdns returned no addresses or error for %s!",
               escaped_safe_str(string_address));
    }
  } else {
    if (evdns_err_is_transient(result))
      status = DNS_RESOLVE_FAILED_TRANSIENT;
  }
  dns_found_answer(string_address, is_reverse, addr, hostname, status, ttl);
  tor_free(string_address);
}

/** For eventdns: start resolving as necessary to find the target for
 * <b>exitconn</b> */
static int
launch_resolve(edge_connection_t *exitconn, or_circuit_t *circ)
{
  char *addr = tor_strdup(exitconn->_base.address);
  struct in_addr in;
  int r;
  int options = get_options()->ServerDNSSearchDomains ? 0
    : DNS_QUERY_NO_SEARCH;
  /* What? Nameservers not configured?  Sounds like a bug. */
  if (!nameservers_configured) {
    log_warn(LD_EXIT, "Harmless bug: nameservers not configured, but resolve "
             "launched.  Configuring.");
    if (configure_nameservers(1) < 0)
      return -1;
  }

  r = parse_inaddr_arpa_address(exitconn->_base.address, &in);
  if (r == 0) {
    log_info(LD_EXIT, "Launching eventdns request for %s",
             escaped_safe_str(exitconn->_base.address));
    r = evdns_resolve_ipv4(exitconn->_base.address, options,
                              evdns_callback, addr);
  } else if (r == 1) {
    log_info(LD_EXIT, "Launching eventdns reverse request for %s",
             escaped_safe_str(exitconn->_base.address));
    r = evdns_resolve_reverse(&in, DNS_QUERY_NO_SEARCH,
                                 evdns_callback, addr);
  } else if (r == -1) {
    log_warn(LD_BUG, "Somehow a malformed in-addr.arpa address reached here.");
  }

  if (r) {
    log_warn(LD_EXIT, "eventdns rejected address %s: error %d.",
             escaped_safe_str(addr), r);
    if (exitconn->_base.purpose == EXIT_PURPOSE_RESOLVE) {
      if (evdns_err_is_transient(r))
        send_resolved_cell(exitconn, circ, RESOLVED_TYPE_ERROR_TRANSIENT);
      else {
        exitconn->address_ttl = DEFAULT_DNS_TTL;
        send_resolved_cell(exitconn, circ, RESOLVED_TYPE_ERROR);
      }
    }
    dns_cancel_pending_resolve(addr); /* also sends end and frees */
    tor_free(addr);
  }
  return r ? -1 : 0;
}

/** How many requests for bogus addresses have we launched so far? */
static int n_wildcard_requests = 0;

/** Map from dotted-quad IP address in response to an int holding how many
 * times we've seen it for a randomly generated (hopefully bogus) address.  It
 * would be easier to use definitely-invalid addresses (as specified by
 * RFC2606), but see comment in dns_launch_wildcard_checks(). */
static strmap_t *dns_wildcard_response_count = NULL;

/** If present, a list of dotted-quad IP addresses that we are pretty sure our
 * nameserver wants to return in response to requests for nonexistent domains.
 */
static smartlist_t *dns_wildcard_list = NULL;

/** Called when we see <b>id</b> (a dotted quad) in response to a request for
 * a hopefully bogus address. */
static void
wildcard_increment_answer(const char *id)
{
  int *ip;
  static int notice_given = 0;
  if (!dns_wildcard_response_count)
    dns_wildcard_response_count = strmap_new();

  ip = strmap_get(dns_wildcard_response_count, id); // may be null (0)
  if (!ip) {
    ip = tor_malloc_zero(sizeof(int));
    strmap_set(dns_wildcard_response_count, id, ip);
  }
  ++*ip;

  if (*ip > 5 && n_wildcard_requests > 10) {
    if (!dns_wildcard_list) dns_wildcard_list = smartlist_create();
    if (!smartlist_string_isin(dns_wildcard_list, id)) {
    log(notice_given ? LOG_INFO : LOG_NOTICE, LD_EXIT,
        "Your DNS provider has given \"%s\" as an answer for %d different "
        "invalid addresses. Apparently they are hijacking DNS failures. "
        "I'll trying to correct for this by treating future occurrences of "
        "\"%s\" as 'not found'.", id, *ip, id);
      smartlist_add(dns_wildcard_list, tor_strdup(id));
    }
  }
}

/** Callback function when we get an answer (possibly failing) for a request
 * for a (hopefully) nonexistent domain. */
static void
evdns_wildcard_check_callback(int result, char type, int count, int ttl,
                                 void *addresses, void *arg)
{
  static int notice_given = 0;
  (void)ttl;
  ++n_wildcard_requests;
  if (result == DNS_ERR_NONE && type == DNS_IPv4_A && count) {
    uint32_t *addrs = addresses;
    int i;
    char *string_address = arg;
    for (i = 0; i < count; ++i) {
      char answer_buf[INET_NTOA_BUF_LEN+1];
      struct in_addr in;
      in.s_addr = addrs[i];
      tor_inet_ntoa(&in, answer_buf, sizeof(answer_buf));
      wildcard_increment_answer(answer_buf);
    }
    log(notice_given ? LOG_INFO : LOG_NOTICE, LD_EXIT,
        "Your DNS provider gave an answer for \"%s\", which "
        "is not supposed to exist.  Apparently they are hijacking "
        "DNS failures. Trying to correct for this.  We've noticed %d possibly "
        "bad addresses so far.",
        string_address, strmap_size(dns_wildcard_response_count));
    notice_given = 1;
  }
  tor_free(arg);
}

/** Launch a single request for a nonexistent hostname consisting of between
 * <b>min_len</b> and <b>max_len</b> random (plausible) characters followed by
 * <b>suffix</b> */
static void
launch_wildcard_check(int min_len, int max_len, const char *suffix)
{
  char random_bytes[20], name[64], *addr;
  size_t len;
  int r;

  len = min_len + crypto_rand_int(max_len-min_len+1);
  if (crypto_rand(random_bytes, sizeof(random_bytes)) < 0)
    return;
  base32_encode(name, sizeof(name), random_bytes, sizeof(random_bytes));
  name[len] = '\0';
  strlcat(name, suffix, sizeof(name));

  addr = tor_strdup(name);
  r = evdns_resolve_ipv4(name, DNS_QUERY_NO_SEARCH,
                            evdns_wildcard_check_callback, addr);
  if (r)
    tor_free(addr);
}

#define N_WILDCARD_CHECKS 2

/** Launch DNS requests for a few nonexistent hostnames, and see if we can
 * catch our nameserver trying to hijack them and map them to a stupid "I
 * couldn't find ggoogle.com but maybe you'd like to buy these lovely
 * encyclopedias" page. */
void
dns_launch_wildcard_checks(void)
{
  int i;
  if (!get_options()->ServerDNSDetectHijacking)
    return;
  log_info(LD_EXIT, "Launching checks to see whether our nameservers like "
           "to hijack DNS failures.");
  for (i = 0; i < N_WILDCARD_CHECKS; ++i) {
    /* RFC2606 reserves these.  Sadly, some DNS hijackers, in a silly attempt
     * to 'comply' with rfc2606, refrain from giving A records for these.
     * This is the standards-compliance equivalent of making sure that your
     * crackhouse's elevator inspection certificate is up to date.
     */
    launch_wildcard_check(2, 16, "%s.invalid");
    launch_wildcard_check(2, 16, "%s.test");

    /* These will break specs if there are ever any number of
     * 8+-character top-level domains. */
    launch_wildcard_check(8, 16, "");

    /* Try some random .com/org/net domains. This will work fine so long as
     * not too many resolve to the same place. */
    launch_wildcard_check(8, 16, "%s.com");
    launch_wildcard_check(8, 16, "%s.org");
    launch_wildcard_check(8, 16, "%s.net");
  }
}

/** Return true iff we have noticed that the dotted-quad <b>ip</b> has been
 * returned in response to requests for nonexistent hostnames. */
static int
answer_is_wildcarded(const char *ip)
{
  return dns_wildcard_list && smartlist_string_isin(dns_wildcard_list, ip);
}
#endif /* USE_EVENTDNS */

/** Exit with an assertion if <b>resolve</b> is corrupt. */
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
    if (resolve->is_reverse)
      tor_assert(!resolve->result.hostname);
    else
      tor_assert(!resolve->result.addr);
  }
}

#ifdef DEBUG_DNS_CACHE
/** Exit with an assertion if the DNS cache is corrupt. */
static void
_assert_cache_ok(void)
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
#endif

