/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/* See http://elvin.dstc.com/ListArchive/elvin-dev/archive/2001/09/msg00027.html
 * for some approaches to asynchronous dns. We will want to switch once one of
 * them becomes more commonly available.
 */

#include "or.h"
#include "tree.h"

#define MAX_ADDRESSLEN 256

#define MAX_DNSWORKERS 50
#define MIN_DNSWORKERS 3
#define MAX_IDLE_DNSWORKERS 10

int num_dnsworkers=0;
int num_dnsworkers_busy=0;

static void purge_expired_resolves(uint32_t now);
static int assign_to_dnsworker(connection_t *exitconn);
static void dns_found_answer(char *address, uint32_t addr);
int dnsworker_main(void *data);
static int spawn_dnsworker(void);
static void spawn_enough_dnsworkers(void);

struct pending_connection_t {
  struct connection_t *conn;
  struct pending_connection_t *next;
};

struct cached_resolve {
  SPLAY_ENTRY(cached_resolve) node;
  char address[MAX_ADDRESSLEN]; /* the hostname to be resolved */
  uint32_t addr; /* in host order. I know I'm horrible for assuming ipv4 */
  char state; /* 0 is pending; 1 means answer is valid; 2 means resolve failed */
#define CACHE_STATE_PENDING 0
#define CACHE_STATE_VALID 1
#define CACHE_STATE_FAILED 2
  uint32_t expire; /* remove untouched items from cache after some time? */
  struct pending_connection_t *pending_connections;
  struct cached_resolve *next;
};

static SPLAY_HEAD(cache_tree, cached_resolve) cache_root;

static int compare_cached_resolves(struct cached_resolve *a,
                                   struct cached_resolve *b) {
  /* make this smarter one day? */
  return strncasecmp(a->address, b->address, MAX_ADDRESSLEN);
}

SPLAY_PROTOTYPE(cache_tree, cached_resolve, node, compare_cached_resolves);
SPLAY_GENERATE(cache_tree, cached_resolve, node, compare_cached_resolves);

static void init_cache_tree(void) {
  SPLAY_INIT(&cache_root);
}

void dns_init(void) {
  init_cache_tree();
  spawn_enough_dnsworkers();
}

static struct cached_resolve *oldest_cached_resolve = NULL; /* linked list, */
static struct cached_resolve *newest_cached_resolve = NULL; /* oldest to newest */

static void purge_expired_resolves(uint32_t now) {
  struct cached_resolve *resolve;

  /* this is fast because the linked list
   * oldest_cached_resolve is ordered by when they came in.
   */
  while(oldest_cached_resolve && (oldest_cached_resolve->expire < now)) {
    resolve = oldest_cached_resolve;
    log(LOG_DEBUG,"Forgetting old cached resolve (expires %lu)", (unsigned long)resolve->expire);
    oldest_cached_resolve = resolve->next;
    if(!oldest_cached_resolve) /* if there are no more, */
      newest_cached_resolve = NULL; /* then make sure the list's tail knows that too */
    SPLAY_REMOVE(cache_tree, &cache_root, resolve);
    free(resolve);
  }
}

/* See if we have a cache entry for 'exitconn->address'. if so,
 * if resolve valid, put it into exitconn->addr and return 1.
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
  uint32_t now = time(NULL);
  assert_connection_ok(exitconn, 0);

  /* first take this opportunity to see if there are any expired
     resolves in the tree.*/
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
        return 0;
      case CACHE_STATE_VALID:
        exitconn->addr = resolve->addr;
        log_fn(LOG_DEBUG,"Connection (fd %d) found cached answer for '%s'",
               exitconn->s, exitconn->address);
        return 1;
      case CACHE_STATE_FAILED:
        return -1;
    }
    assert(0);
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
  pending_connection->next = resolve->pending_connections;
  resolve->pending_connections = pending_connection;

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

static int assign_to_dnsworker(connection_t *exitconn) {
  connection_t *dnsconn;
  unsigned char len;

  spawn_enough_dnsworkers(); /* respawn here, to be sure there are enough */

  dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_IDLE);

  if(!dnsconn) {
    log_fn(LOG_WARN,"no idle dns workers. Failing.");
    dns_cancel_pending_resolve(exitconn->address, NULL);
    return -1;
  }

  log_fn(LOG_DEBUG, "Connection (fd %d) needs to resolve '%s'; assigning to DNSWorker (fd %d)",
         exitconn->s, exitconn->address, dnsconn->s);

  free(dnsconn->address);
  dnsconn->address = tor_strdup(exitconn->address);
  dnsconn->state = DNSWORKER_STATE_BUSY;
  num_dnsworkers_busy++;

  len = strlen(dnsconn->address);
  connection_write_to_buf(&len, 1, dnsconn);
  connection_write_to_buf(dnsconn->address, len, dnsconn);

//  log_fn(LOG_DEBUG,"submitted '%s'", exitconn->address);
  return 0;
}

/* if onlyconn is NULL, cancel the whole thing. if onlyconn is defined,
 * then remove onlyconn from the pending list, and if the pending list
 * is now empty, cancel the whole thing.
 */
void dns_cancel_pending_resolve(char *address, connection_t *onlyconn) {
  struct pending_connection_t *pend, *victim;
  struct cached_resolve search;
  struct cached_resolve *resolve, *tmp;

  strncpy(search.address, address, MAX_ADDRESSLEN);
  search.address[MAX_ADDRESSLEN-1] = 0;

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_WARN,"Address '%s' is not pending. Dropping.", address);
    return;
  }

  assert(resolve->state == CACHE_STATE_PENDING);
  assert(resolve->pending_connections);

  if(onlyconn) {
    assert_connection_ok(onlyconn,0);
    pend = resolve->pending_connections;
    if(pend->conn == onlyconn) {
      resolve->pending_connections = pend->next;
      free(pend);
      if(resolve->pending_connections) {/* more pending, don't cancel it */
        log_fn(LOG_DEBUG, "Connection (fd %d) no longer waiting for resolve of '%s'",
               onlyconn->s, address);
        return;
      }
    } else {
      for( ; pend->next; pend = pend->next) {
        if(pend->next->conn == onlyconn) {
          victim = pend->next;
          pend->next = victim->next;
          free(victim);
          log_fn(LOG_DEBUG, "Connection (fd %d) no longer waiting for resolve of '%s'",
                 onlyconn->s, address);
          return; /* more are pending */
        }
      }
      assert(0); /* not reachable unless onlyconn not in pending list */
    }
  } else {
    /* mark all pending connections to fail */
    log_fn(LOG_DEBUG, "Failing all connections waiting on DNS resolve of '%s'",
           address);
    while(resolve->pending_connections) {
      pend = resolve->pending_connections;
      connection_mark_for_close(pend->conn, END_STREAM_REASON_MISC);
      resolve->pending_connections = pend->next;
      free(pend);
    }
  }

  /* remove resolve from the linked list */
  if(resolve == oldest_cached_resolve) {
    oldest_cached_resolve = resolve->next;
    if(oldest_cached_resolve == NULL)
      newest_cached_resolve = NULL;
  } else {
    /* FFFF make it a doubly linked list if this becomes too slow */
    for(tmp=oldest_cached_resolve; tmp && tmp->next != resolve; tmp=tmp->next) ;
    assert(tmp); /* it's got to be in the list, or we screwed up somewhere else */
    tmp->next = resolve->next; /* unlink it */

    if(newest_cached_resolve == resolve)
      newest_cached_resolve = tmp;
  }

  /* remove resolve from the tree */
  SPLAY_REMOVE(cache_tree, &cache_root, resolve);

  free(resolve);
}

static void dns_found_answer(char *address, uint32_t addr) {
  struct pending_connection_t *pend;
  struct cached_resolve search;
  struct cached_resolve *resolve;

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
    log_fn(LOG_WARN, "Resolved '%s' which was already resolved; ignoring",
           address);
    return;
  }
  /* Removed this assertion: in fact, we'll sometimes get a double answer
   * to the same question.  This can happen when we ask one worker to resolve
   * X.Y.Z., then we cancel the request, and then we ask another worker to
   * resolve X.Y.Z. */
  /* assert(resolve->state == CACHE_STATE_PENDING); */

  resolve->addr = ntohl(addr);
  if(resolve->addr)
    resolve->state = CACHE_STATE_VALID;
  else
    resolve->state = CACHE_STATE_FAILED;

  while(resolve->pending_connections) {
    pend = resolve->pending_connections;
    assert_connection_ok(pend->conn,0);
    pend->conn->addr = resolve->addr;
    if(resolve->state == CACHE_STATE_FAILED) {
      connection_mark_for_close(pend->conn, END_STREAM_REASON_RESOLVEFAILED);
    } else {
      assert_connection_ok(pend->conn, time(NULL));
      connection_exit_connect(pend->conn);
    }
    resolve->pending_connections = pend->next;
    free(pend);
  }
}

/******************************************************************/

int connection_dns_finished_flushing(connection_t *conn) {
  assert(conn && conn->type == CONN_TYPE_DNSWORKER);
  connection_stop_writing(conn);
  return 0;
}

int connection_dns_process_inbuf(connection_t *conn) {
  uint32_t addr;

  assert(conn && conn->type == CONN_TYPE_DNSWORKER);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_WARN,"Read eof. Worker dying.");
    if(conn->state == DNSWORKER_STATE_BUSY) {
      dns_cancel_pending_resolve(conn->address, NULL);
      num_dnsworkers_busy--;
    }
    num_dnsworkers--;
    return -1;
  }

  assert(conn->state == DNSWORKER_STATE_BUSY);
  if(buf_datalen(conn->inbuf) < 4) /* entire answer available? */
    return 0; /* not yet */
  assert(buf_datalen(conn->inbuf) == 4);

  connection_fetch_from_buf((char*)&addr,sizeof(addr),conn);

  log_fn(LOG_DEBUG, "DNSWorker (fd %d) returned answer for '%s'",
         conn->s, conn->address);

  dns_found_answer(conn->address, addr);

  free(conn->address);
  conn->address = tor_strdup("<idle>");
  conn->state = DNSWORKER_STATE_IDLE;
  num_dnsworkers_busy--;

  return 0;
}

int dnsworker_main(void *data) {
  char address[MAX_ADDRESSLEN];
  unsigned char address_len;
  struct hostent *rent;
  int *fdarray = data;
  int fd;

  close(fdarray[0]); /* this is the side of the socketpair the parent uses */
  fd = fdarray[1]; /* this side is ours */
  connection_free_all(); /* so the child doesn't hold the parent's fd's open */
/* XXX probably don't close all the fd's on MS_WINDOWS? */

  for(;;) {

    if(read(fd, &address_len, 1) != 1) {
      log_fn(LOG_INFO,"read length failed. Child exiting.");
      spawn_exit();
    }
    assert(address_len > 0);

    if(read_all(fd, address, address_len) != address_len) {
      log_fn(LOG_ERR,"read hostname failed. Child exiting.");
      spawn_exit();
    }
    address[address_len] = 0; /* null terminate it */

    rent = gethostbyname(address);
    if (!rent) {
      log_fn(LOG_INFO,"Could not resolve dest addr %s. Returning nulls.",address);
      if(write_all(fd, "\0\0\0\0", 4) != 4) {
        log_fn(LOG_ERR,"writing nulls failed. Child exiting.");
        spawn_exit();
      }
    } else {
      assert(rent->h_length == 4); /* break to remind us if we move away from ipv4 */
      if(write_all(fd, rent->h_addr, 4) != 4) {
        log_fn(LOG_INFO,"writing answer failed. Child exiting.");
        spawn_exit();
      }
      log_fn(LOG_INFO,"Resolved address '%s'.",address);
    }
  }
  return 0; /* windows wants this function to return an int */
}

static int spawn_dnsworker(void) {
  int fd[2];
  connection_t *conn;

  if(tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    log(LOG_ERR, "Couldn't construct socketpair: %s", strerror(errno));
    exit(1);
  }

  spawn_func(dnsworker_main, (void*)fd);
  log_fn(LOG_DEBUG,"just spawned a worker.");
  close(fd[1]); /* we don't need the worker's side of the pipe */

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
    assert(dnsconn);

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
    assert(dnsconn);
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
