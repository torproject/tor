/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file dns.c
 * \brief Resolve hostnames in separate processes.
 **/

/* See http://elvin.dstc.com/ListArchive/elvin-dev/archive/2001/09/msg00027.html
 * for some approaches to asynchronous dns. We will want to switch once one of
 * them becomes more commonly available.
 */

#include "or.h"
#include "tree.h"

extern or_options_t options; /* command-line and config-file options */

/** Longest hostname we're willing to resolve. */
#define MAX_ADDRESSLEN 256

/** Maximum DNS processes to spawn. */
#define MAX_DNSWORKERS 50
/** Minimum DNS processes to spawn. */
#define MIN_DNSWORKERS 3

/** If more than this many processes are idle, shut down the extras. */
#define MAX_IDLE_DNSWORKERS 10

/** Possible outcomes from hostname lookup: permanent failure,
 * transient (retryable) failure, and success */
#define DNS_RESOLVE_FAILED_TRANSIENT 1
#define DNS_RESOLVE_FAILED_PERMANENT 2
#define DNS_RESOLVE_SUCCEEDED 3

/** How many dnsworkers we have running right now */
int num_dnsworkers=0;
/** How many of the running dnsworkers have an assigned task right now */
int num_dnsworkers_busy=0;

/** Linked list of connections waiting for a DNS answer. */
struct pending_connection_t {
  struct connection_t *conn;
  struct pending_connection_t *next;
};

/** A DNS request: possibly completed, possibly pending; cached_resolve
 * structs are stored at the OR side in a splay tree, and as a linked
 * list from oldest to newest.
 */
struct cached_resolve {
  SPLAY_ENTRY(cached_resolve) node;
  char address[MAX_ADDRESSLEN]; /**< the hostname to be resolved */
  uint32_t addr; /**< IPv4 addr for <b>address</b>. */
  char state; /**< 0 is pending; 1 means answer is valid; 2 means resolve failed */
#define CACHE_STATE_PENDING 0
#define CACHE_STATE_VALID 1
#define CACHE_STATE_FAILED 2
  uint32_t expire; /**< Remove items from cache after this time */
  struct pending_connection_t *pending_connections;
  struct cached_resolve *next;
};

static void purge_expired_resolves(uint32_t now);
static int assign_to_dnsworker(connection_t *exitconn);
static void dns_purge_resolve(struct cached_resolve *resolve);
static void dns_found_answer(char *address, uint32_t addr, char outcome);
int dnsworker_main(void *data);
static int spawn_dnsworker(void);
static void spawn_enough_dnsworkers(void);

/** Splay tree of cached_resolve objects */
static SPLAY_HEAD(cache_tree, cached_resolve) cache_root;

/** Function to compare hashed resolves on their addresses; used to
 * implement splay trees. */
static int compare_cached_resolves(struct cached_resolve *a,
                                   struct cached_resolve *b) {
  /* make this smarter one day? */
  return strncasecmp(a->address, b->address, MAX_ADDRESSLEN);
}

SPLAY_PROTOTYPE(cache_tree, cached_resolve, node, compare_cached_resolves);
SPLAY_GENERATE(cache_tree, cached_resolve, node, compare_cached_resolves);

/** Initialize the DNS cache */
static void init_cache_tree(void) {
  SPLAY_INIT(&cache_root);
}

/** Initialize the DNS subsystem; called by the OR process. */
void dns_init(void) {
  init_cache_tree();
  spawn_enough_dnsworkers();
}

/** linked list of resolved addresses, oldest to newest */
static struct cached_resolve *oldest_cached_resolve = NULL;
static struct cached_resolve *newest_cached_resolve = NULL;

/** Remove every cached_resolve whose <b>expire</b> time is before <b>now</b>
 * from the cache. */
static void purge_expired_resolves(uint32_t now) {
  struct cached_resolve *resolve;

  /* this is fast because the linked list
   * oldest_cached_resolve is ordered by when they came in.
   */
  while(oldest_cached_resolve && (oldest_cached_resolve->expire < now)) {
    resolve = oldest_cached_resolve;
    log(LOG_DEBUG,"Forgetting old cached resolve (expires %lu)", (unsigned long)resolve->expire);
    if(resolve->state == CACHE_STATE_PENDING) {
      log_fn(LOG_WARN,"Expiring a dns resolve that's still pending. Forgot to cull it?");
      /* XXX if resolve->pending_connections is used, then we're probably
       * introducing bugs by closing resolve without notifying those streams.
       */
    }
    oldest_cached_resolve = resolve->next;
    if(!oldest_cached_resolve) /* if there are no more, */
      newest_cached_resolve = NULL; /* then make sure the list's tail knows that too */
    SPLAY_REMOVE(cache_tree, &cache_root, resolve);
    tor_free(resolve);
  }
}

/** See if we have a cache entry for <b>exitconn</b>-\>address. if so,
 * if resolve valid, put it into <b>exitconn</b>-\>addr and return 1.
 * If resolve failed, return -1.
 *
 * Else, if seen before and pending, add conn to the pending list,
 * and return 0.
 *
 * Else, if not seen before, add conn to pending list, hand to
 * dns farm, and return 0.
 */
int dns_resolve(connection_t *exitconn) {
  struct cached_resolve *resolve;
  struct cached_resolve search;
  struct pending_connection_t *pending_connection;
  struct in_addr in;
  uint32_t now = time(NULL);
  assert_connection_ok(exitconn, 0);

  /* first check if exitconn->address is an IP. If so, we already
   * know the answer. */
  if (tor_inet_aton(exitconn->address, &in) != 0) {
    exitconn->addr = ntohl(in.s_addr);
    return 1;
  }

  /* then take this opportunity to see if there are any expired
   * resolves in the tree. */
  purge_expired_resolves(now);

  /* now check the tree to see if 'address' is already there. */
  strncpy(search.address, exitconn->address, MAX_ADDRESSLEN);
  search.address[MAX_ADDRESSLEN-1] = 0;
  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(resolve) { /* already there */
    switch(resolve->state) {
      case CACHE_STATE_PENDING:
        /* add us to the pending list */
        pending_connection = tor_malloc(sizeof(struct pending_connection_t));
        pending_connection->conn = exitconn;
        pending_connection->next = resolve->pending_connections;
        resolve->pending_connections = pending_connection;
        log_fn(LOG_DEBUG,"Connection (fd %d) waiting for pending DNS resolve of '%s'",
               exitconn->s, exitconn->address);
        exitconn->state = EXIT_CONN_STATE_RESOLVING;
        return 0;
      case CACHE_STATE_VALID:
        exitconn->addr = resolve->addr;
        log_fn(LOG_DEBUG,"Connection (fd %d) found cached answer for '%s'",
               exitconn->s, exitconn->address);
        return 1;
      case CACHE_STATE_FAILED:
        return -1;
    }
    tor_assert(0);
  }
  /* not there, need to add it */
  resolve = tor_malloc_zero(sizeof(struct cached_resolve));
  resolve->state = CACHE_STATE_PENDING;
  resolve->expire = now + MAX_DNS_ENTRY_AGE;
  strncpy(resolve->address, exitconn->address, MAX_ADDRESSLEN);
  resolve->address[MAX_ADDRESSLEN-1] = 0;

  /* add us to the pending list */
  pending_connection = tor_malloc(sizeof(struct pending_connection_t));
  pending_connection->conn = exitconn;
  pending_connection->next = NULL;
  resolve->pending_connections = pending_connection;
  exitconn->state = EXIT_CONN_STATE_RESOLVING;

  /* add us to the linked list of resolves */
  if (!oldest_cached_resolve) {
    oldest_cached_resolve = resolve;
  } else {
    newest_cached_resolve->next = resolve;
  }
  newest_cached_resolve = resolve;

  SPLAY_INSERT(cache_tree, &cache_root, resolve);
  return assign_to_dnsworker(exitconn);
}

/** Find or spawn a dns worker process to handle resolving
 * <b>exitconn</b>-\>address; tell that dns worker to begin resolving.
 */
static int assign_to_dnsworker(connection_t *exitconn) {
  connection_t *dnsconn;
  unsigned char len;

  tor_assert(exitconn->state == EXIT_CONN_STATE_RESOLVING);

  spawn_enough_dnsworkers(); /* respawn here, to be sure there are enough */

  dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_IDLE);

  if(!dnsconn) {
    log_fn(LOG_WARN,"no idle dns workers. Failing.");
    dns_cancel_pending_resolve(exitconn->address);
    return -1;
  }

  log_fn(LOG_DEBUG, "Connection (fd %d) needs to resolve '%s'; assigning to DNSWorker (fd %d)",
         exitconn->s, exitconn->address, dnsconn->s);

  tor_free(dnsconn->address);
  dnsconn->address = tor_strdup(exitconn->address);
  dnsconn->state = DNSWORKER_STATE_BUSY;
  num_dnsworkers_busy++;

  len = strlen(dnsconn->address);
  connection_write_to_buf(&len, 1, dnsconn);
  connection_write_to_buf(dnsconn->address, len, dnsconn);

//  log_fn(LOG_DEBUG,"submitted '%s'", exitconn->address);
  return 0;
}

/** Remove <b>conn</b> from the list of connections waiting for conn-\>address.
 */
void connection_dns_remove(connection_t *conn)
{
  struct pending_connection_t *pend, *victim;
  struct cached_resolve search;
  struct cached_resolve *resolve;

  strncpy(search.address, conn->address, MAX_ADDRESSLEN);
  search.address[MAX_ADDRESSLEN-1] = 0;

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_WARN,"Address '%s' is not pending. Dropping.", conn->address);
    return;
  }

  tor_assert(resolve->pending_connections);
  assert_connection_ok(conn,0);

  pend = resolve->pending_connections;

  if(pend->conn == conn) {
    resolve->pending_connections = pend->next;
    tor_free(pend);
    log_fn(LOG_DEBUG, "First connection (fd %d) no longer waiting for resolve of '%s'",
           conn->s, conn->address);
    return;
  } else {
    for( ; pend->next; pend = pend->next) {
      if(pend->next->conn == conn) {
        victim = pend->next;
        pend->next = victim->next;
        tor_free(victim);
        log_fn(LOG_DEBUG, "Connection (fd %d) no longer waiting for resolve of '%s'",
               conn->s, conn->address);
        return; /* more are pending */
      }
    }
    tor_assert(0); /* not reachable unless onlyconn not in pending list */
  }
}

/** Log an error and abort if conn is waiting for a DNS resolve.
 */
void assert_connection_edge_not_dns_pending(connection_t *conn) {
  struct pending_connection_t *pend;
  struct cached_resolve *resolve;

  SPLAY_FOREACH(resolve, cache_tree, &cache_root) {
    for(pend = resolve->pending_connections;
        pend;
        pend = pend->next) {
      tor_assert(pend->conn != conn);
    }
  }
}

/** Log an error and abort if any connection waiting for a DNS resolve is
 * corrupted. */
void assert_all_pending_dns_resolves_ok(void) {
  struct pending_connection_t *pend;
  struct cached_resolve *resolve;

  SPLAY_FOREACH(resolve, cache_tree, &cache_root) {
    for(pend = resolve->pending_connections;
        pend;
        pend = pend->next) {
      assert_connection_ok(pend->conn, 0);
    }
  }
}

/** Mark all connections waiting for <b>address</b> for close.  Then cancel
 * the resolve for <b>address</b> itself, and remove any cached results for
 * <b>address</b> from the cache.
 */
void dns_cancel_pending_resolve(char *address) {
  struct pending_connection_t *pend;
  struct cached_resolve search;
  struct cached_resolve *resolve;
  connection_t *pendconn;

  strncpy(search.address, address, MAX_ADDRESSLEN);
  search.address[MAX_ADDRESSLEN-1] = 0;

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_WARN,"Address '%s' is not pending. Dropping.", address);
    return;
  }

  tor_assert(resolve->pending_connections);

  /* mark all pending connections to fail */
  log_fn(LOG_DEBUG, "Failing all connections waiting on DNS resolve of '%s'",
         address);
  while(resolve->pending_connections) {
    pend = resolve->pending_connections;
    /* So that mark_for_close doesn't double-remove the connection. */
    pend->conn->state = EXIT_CONN_STATE_RESOLVEFAILED;
    pendconn = pend->conn; /* don't pass complex things to the
                              connection_mark_for_close macro */
    connection_mark_for_close(pendconn, END_STREAM_REASON_MISC);
    resolve->pending_connections = pend->next;
    tor_free(pend);
  }

  dns_purge_resolve(resolve);
}

/** Remove <b>resolve</b> from the cache.
 */
static void dns_purge_resolve(struct cached_resolve *resolve) {
  struct cached_resolve *tmp;

  /* remove resolve from the linked list */
  if(resolve == oldest_cached_resolve) {
    oldest_cached_resolve = resolve->next;
    if(oldest_cached_resolve == NULL)
      newest_cached_resolve = NULL;
  } else {
    /* FFFF make it a doubly linked list if this becomes too slow */
    for(tmp=oldest_cached_resolve; tmp && tmp->next != resolve; tmp=tmp->next) ;
    tor_assert(tmp); /* it's got to be in the list, or we screwed up somewhere else */
    tmp->next = resolve->next; /* unlink it */

    if(newest_cached_resolve == resolve)
      newest_cached_resolve = tmp;
  }

  /* remove resolve from the tree */
  SPLAY_REMOVE(cache_tree, &cache_root, resolve);

  tor_free(resolve);
}

/** Called on the OR side when a DNS worker tells us the outcome of a DNS
 * resolve: tell all pending connections about the result of the lookup, and
 * cache the value.  (<b>address</b> is a NUL-terminated string containing the
 * address to look up; <b>addr</b> is an IPv4 address in host order;
 * <b>outcome</b> is one of
 * DNS_RESOLVE_{FAILED_TRANSIENT|FAILED_PERMANENT|SUCCEEDED}.
 */
static void dns_found_answer(char *address, uint32_t addr, char outcome) {
  struct pending_connection_t *pend;
  struct cached_resolve search;
  struct cached_resolve *resolve;
  connection_t *pendconn;
  circuit_t *circ;

  strncpy(search.address, address, MAX_ADDRESSLEN);
  search.address[MAX_ADDRESSLEN-1] = 0;

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_INFO,"Resolved unasked address '%s'? Dropping.", address);
    /* XXX Why drop?  Just because we don't care now doesn't mean we shouldn't
     * XXX cache the result for later. */
    return;
  }

  if (resolve->state != CACHE_STATE_PENDING) {
    /* XXXX Maybe update addr? or check addr for consistency? Or let
     * VALID replace FAILED? */
    log_fn(LOG_WARN, "Resolved '%s' which was already resolved; ignoring",
           address);
    tor_assert(resolve->pending_connections == NULL);
    return;
  }
  /* Removed this assertion: in fact, we'll sometimes get a double answer
   * to the same question.  This can happen when we ask one worker to resolve
   * X.Y.Z., then we cancel the request, and then we ask another worker to
   * resolve X.Y.Z. */
  /* tor_assert(resolve->state == CACHE_STATE_PENDING); */

  resolve->addr = ntohl(addr);
  if(outcome == DNS_RESOLVE_SUCCEEDED)
    resolve->state = CACHE_STATE_VALID;
  else
    resolve->state = CACHE_STATE_FAILED;

  while(resolve->pending_connections) {
    pend = resolve->pending_connections;
    assert_connection_ok(pend->conn,time(NULL));
    pend->conn->addr = resolve->addr;


    if(resolve->state == CACHE_STATE_FAILED) {
      pendconn = pend->conn; /* don't pass complex things to the
                                connection_mark_for_close macro */
      /* prevent double-remove. */
      pendconn->state = EXIT_CONN_STATE_RESOLVEFAILED;
      connection_mark_for_close(pendconn, END_STREAM_REASON_RESOLVEFAILED);
      connection_free(pendconn);
    } else {
      /* prevent double-remove. */
      pend->conn->state = EXIT_CONN_STATE_CONNECTING;

      circ = circuit_get_by_conn(pend->conn);
      assert(circ);
      /* unlink pend->conn from resolving_streams, */
      circuit_detach_stream(circ, pend->conn);
      /* and link it to n_streams */
      pend->conn->next_stream = circ->n_streams;
      circ->n_streams = pend->conn;

      connection_exit_connect(pend->conn);
    }
    resolve->pending_connections = pend->next;
    tor_free(pend);
  }

  if(outcome == DNS_RESOLVE_FAILED_TRANSIENT) { /* remove from cache */
    dns_purge_resolve(resolve);
  }
}

/******************************************************************/

/*
 * Connection between OR and dnsworker
 */

/** Write handler: called when we've pushed a request to a dnsworker. */
int connection_dns_finished_flushing(connection_t *conn) {
  tor_assert(conn && conn->type == CONN_TYPE_DNSWORKER);
  connection_stop_writing(conn);
  return 0;
}

/** Read handler: called when we get data from a dnsworker.  If the
 * connection is closed, mark the dnsworker as dead.  Otherwise, see
 * if we have a complete answer.  If so, call dns_found_answer on the
 * result.  If not, wait.  Returns 0. */
int connection_dns_process_inbuf(connection_t *conn) {
  char success;
  uint32_t addr;

  tor_assert(conn && conn->type == CONN_TYPE_DNSWORKER);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_WARN,"Read eof. Worker died unexpectedly.");
    if(conn->state == DNSWORKER_STATE_BUSY) {
      dns_cancel_pending_resolve(conn->address);
      num_dnsworkers_busy--;
    }
    num_dnsworkers--;
    connection_mark_for_close(conn,0);
    return 0;
  }

  tor_assert(conn->state == DNSWORKER_STATE_BUSY);
  if(buf_datalen(conn->inbuf) < 5) /* entire answer available? */
    return 0; /* not yet */
  tor_assert(buf_datalen(conn->inbuf) == 5);

  connection_fetch_from_buf(&success,1,conn);
  connection_fetch_from_buf((char *)&addr,sizeof(uint32_t),conn);

  log_fn(LOG_DEBUG, "DNSWorker (fd %d) returned answer for '%s'",
         conn->s, conn->address);

  tor_assert(success >= DNS_RESOLVE_FAILED_TRANSIENT);
  tor_assert(success <= DNS_RESOLVE_SUCCEEDED);
  dns_found_answer(conn->address, addr, success);

  tor_free(conn->address);
  conn->address = tor_strdup("<idle>");
  conn->state = DNSWORKER_STATE_IDLE;
  num_dnsworkers_busy--;

  return 0;
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
int dnsworker_main(void *data) {
  char address[MAX_ADDRESSLEN];
  unsigned char address_len;
  char answer[5];
  uint32_t ip;
  int *fdarray = data;
  int fd;

  tor_close_socket(fdarray[0]); /* this is the side of the socketpair the parent uses */
  fd = fdarray[1]; /* this side is ours */
#ifndef MS_WINDOWS
  connection_free_all(); /* so the child doesn't hold the parent's fd's open */
#endif

  for(;;) {

    if(recv(fd, &address_len, 1, 0) != 1) {
      log_fn(LOG_INFO,"dnsworker exiting because tor process died.");
      spawn_exit();
    }
    tor_assert(address_len > 0);

    if(read_all(fd, address, address_len, 1) != address_len) {
      log_fn(LOG_ERR,"read hostname failed. Child exiting.");
      spawn_exit();
    }
    address[address_len] = 0; /* null terminate it */

    switch (tor_lookup_hostname(address, &ip)) {
      case 1:
        log_fn(LOG_INFO,"Could not resolve dest addr %s (transient).",address);
        answer[0] = DNS_RESOLVE_FAILED_TRANSIENT;
        break;
      case -1:
        log_fn(LOG_INFO,"Could not resolve dest addr %s (permanent).",address);
        answer[0] = DNS_RESOLVE_FAILED_PERMANENT;
        break;
      case 0:
        log_fn(LOG_INFO,"Resolved address '%s'.",address);
        answer[0] = DNS_RESOLVE_SUCCEEDED;
        break;
    }
    set_uint32(answer+1, ip);
    if(write_all(fd, answer, 5, 1) != 5) {
      log_fn(LOG_ERR,"writing answer failed. Child exiting.");
      spawn_exit();
    }
  }
  return 0; /* windows wants this function to return an int */
}

/** Launch a new DNS worker; return 0 on success, -1 on failure.
 */
static int spawn_dnsworker(void) {
  int fd[2];
  connection_t *conn;

  if(tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    log(LOG_ERR, "Couldn't construct socketpair: %s",
        tor_socket_strerror(tor_socket_errno(-1)));
    exit(1);
  }

  spawn_func(dnsworker_main, (void*)fd);
  log_fn(LOG_DEBUG,"just spawned a worker.");
  tor_close_socket(fd[1]); /* we don't need the worker's side of the pipe */

  conn = connection_new(CONN_TYPE_DNSWORKER);

  set_socket_nonblocking(fd[0]);

  /* set up conn so it's got all the data we need to remember */
  conn->s = fd[0];
  conn->address = tor_strdup("<unused>");

  if(connection_add(conn) < 0) { /* no space, forget it */
    log_fn(LOG_WARN,"connection_add failed. Giving up.");
    connection_free(conn); /* this closes fd[0] */
    return -1;
  }

  conn->state = DNSWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

/** If we have too many or too few DNS workers, spawn or kill some.
 */
static void spawn_enough_dnsworkers(void) {
  int num_dnsworkers_needed; /* aim to have 1 more than needed,
                           * but no less than min and no more than max */
  connection_t *dnsconn;

  /* XXX This may not be the best strategy. Maybe we should queue pending
   *     requests until the old ones finish or time out: otherwise, if
   *     the connection requests come fast enough, we never get any DNS done. -NM
   * XXX But if we queue them, then the adversary can pile even more
   *     queries onto us, blocking legitimate requests for even longer.
   *     Maybe we should compromise and only kill if it's been at it for
   *     more than, e.g., 2 seconds. -RD
   */
  if(num_dnsworkers_busy == MAX_DNSWORKERS) {
    /* We always want at least one worker idle.
     * So find the oldest busy worker and kill it.
     */
    dnsconn = connection_get_by_type_state_lastwritten(CONN_TYPE_DNSWORKER,
                                                       DNSWORKER_STATE_BUSY);
    tor_assert(dnsconn);

    log_fn(LOG_WARN, "%d DNS workers are spawned; all are busy. Killing one.",
           MAX_DNSWORKERS);

    connection_mark_for_close(dnsconn,0);
    num_dnsworkers_busy--;
    num_dnsworkers--;
  }

  if(num_dnsworkers_busy >= MIN_DNSWORKERS)
    num_dnsworkers_needed = num_dnsworkers_busy+1;
  else
    num_dnsworkers_needed = MIN_DNSWORKERS;

  while(num_dnsworkers < num_dnsworkers_needed) {
    if(spawn_dnsworker() < 0) {
      log(LOG_WARN,"spawn_enough_dnsworkers(): spawn failed!");
      return;
    }
    num_dnsworkers++;
  }

  while(num_dnsworkers > num_dnsworkers_busy+MAX_IDLE_DNSWORKERS) { /* too many idle? */
    /* cull excess workers */
    log_fn(LOG_WARN,"%d of %d dnsworkers are idle. Killing one.",
           num_dnsworkers-num_dnsworkers_needed, num_dnsworkers);
    dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_IDLE);
    tor_assert(dnsconn);
    connection_mark_for_close(dnsconn,0);
    num_dnsworkers--;
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
