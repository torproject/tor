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

int num_workers=0;
int num_workers_busy=0;

static int dns_assign_to_worker(connection_t *exitconn);
static void dns_cancel_pending_resolve(char *question);
static void dns_found_answer(char *question, uint32_t answer);
static void dnsworker_main(int fd);
static int dns_spawn_worker(void);
static void spawn_enough_workers(void);

struct pending_connection_t {
  struct connection_t *conn;
  struct pending_connection_t *next;
};

struct cached_resolve {
  SPLAY_ENTRY(cached_resolve) node;
  char question[MAX_ADDRESSLEN]; /* the hostname to be resolved */
  uint32_t answer; /* in host order. I know I'm horrible for assuming ipv4 */
  char state; /* 0 is pending; 1 means answer is valid; 2 means resolve failed */
#define CACHE_STATE_PENDING 0
#define CACHE_STATE_VALID 1
#define CACHE_STATE_FAILED 2
  uint32_t expire; /* remove untouched items from cache after some time? */
  struct pending_connection_t *pending_connections;
  struct cached_resolve *next;
};

SPLAY_HEAD(cache_tree, cached_resolve) cache_root;

static int compare_cached_resolves(struct cached_resolve *a, struct cached_resolve *b) {
  /* make this smarter one day? */
  return strncasecmp(a->question, b->question, MAX_ADDRESSLEN);
}

SPLAY_PROTOTYPE(cache_tree, cached_resolve, node, compare_cached_resolves);
SPLAY_GENERATE(cache_tree, cached_resolve, node, compare_cached_resolves);

static void init_cache_tree(void) {
  SPLAY_INIT(&cache_root);
}

void dns_init(void) {
  init_cache_tree();
  spawn_enough_workers();
}

static struct cached_resolve *oldest_cached_resolve = NULL; /* linked list, */
static struct cached_resolve *newest_cached_resolve = NULL; /* oldest to newest */

/* See if the question 'exitconn->address' has been answered. if so,
 * if resolve valid, put it into exitconn->addr and exec to
 * connection_exit_connect. If resolve failed, return -1.
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

  /* first take this opportunity to see if there are any expired
   * resolves in the tree. this is fast because the linked list
   * oldest_cached_resolve is ordered by when they came in.
   */
  while(oldest_cached_resolve && (oldest_cached_resolve->expire < now)) {
    resolve = oldest_cached_resolve;
    log(LOG_DEBUG,"Forgetting old cached resolve (expires %d)", resolve->expire);
    oldest_cached_resolve = resolve->next;
    if(!oldest_cached_resolve) /* if there are no more, */
      newest_cached_resolve = NULL; /* then make sure the list's tail knows that too */
    SPLAY_REMOVE(cache_tree, &cache_root, resolve);
    free(resolve);
  }

  /* now check the tree to see if 'question' is already there. */
  strncpy(search.question, exitconn->address, MAX_ADDRESSLEN);
  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(resolve) { /* already there */
    switch(resolve->state) {
      case CACHE_STATE_PENDING:
        /* add us to the pending list */
        pending_connection = tor_malloc(sizeof(struct pending_connection_t));
        pending_connection->conn = exitconn;
        pending_connection->next = resolve->pending_connections;
        resolve->pending_connections = pending_connection;
        return 0;
      case CACHE_STATE_VALID:
        exitconn->addr = resolve->answer;
        return connection_exit_connect(exitconn);
      case CACHE_STATE_FAILED:
        return -1;
    }
  } else { /* need to add it */
    resolve = tor_malloc(sizeof(struct cached_resolve));
    memset(resolve, 0, sizeof(struct cached_resolve));
    resolve->state = CACHE_STATE_PENDING;
    resolve->expire = now + 100; /* XXX for testing. when we're confident, switch it back */
//    resolve->expire = now + 86400; /* now + 1 day */
    strncpy(resolve->question, exitconn->address, MAX_ADDRESSLEN);

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
    return dns_assign_to_worker(exitconn);
  }

  assert(0);
  return 0; /* not reached; keep gcc happy */
}

static int dns_assign_to_worker(connection_t *exitconn) {
  connection_t *dnsconn;
  unsigned char len;

  spawn_enough_workers(); /* respawn here, to be sure there are enough */

  dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_IDLE);

  if(!dnsconn) {
    log(LOG_INFO,"dns_assign_to_worker(): no idle dns workers. Failing.");
    dns_cancel_pending_resolve(exitconn->address);
    return -1;
  }

  dnsconn->address = strdup(exitconn->address);
  dnsconn->state = DNSWORKER_STATE_BUSY;
  num_workers_busy++;

  len = strlen(dnsconn->address);
  /* FFFF we should have it retry if the first worker bombs out */
  if(connection_write_to_buf(&len, 1, dnsconn) < 0 ||
     connection_write_to_buf(dnsconn->address, len, dnsconn) < 0) {
    log(LOG_NOTICE,"dns_assign_to_worker(): Write failed. Closing worker and failing resolve.");
    dnsconn->marked_for_close = 1;
    dns_cancel_pending_resolve(exitconn->address);
    return -1;
  }

//  log(LOG_DEBUG,"dns_assign_to_worker(): submitted '%s'", exitconn->address);
  return 0;
}

static void dns_cancel_pending_resolve(char *question) {
  struct pending_connection_t *pend;
  struct cached_resolve search;
  struct cached_resolve *resolve, *tmp;

  strncpy(search.question, question, MAX_ADDRESSLEN);

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_ERR,"Answer to unasked question '%s'? Dropping.", question);
    return;
  }

  assert(resolve->state == CACHE_STATE_PENDING);

  /* mark all pending connections to fail */
  while(resolve->pending_connections) {
    pend = resolve->pending_connections;
    pend->conn->marked_for_close = 1;
    resolve->pending_connections = pend->next;
    free(pend);
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

static void dns_found_answer(char *question, uint32_t answer) {
  struct pending_connection_t *pend;
  struct cached_resolve search;
  struct cached_resolve *resolve;

  strncpy(search.question, question, MAX_ADDRESSLEN);

  resolve = SPLAY_FIND(cache_tree, &cache_root, &search);
  if(!resolve) {
    log_fn(LOG_ERR,"Answer to unasked question '%s'? Dropping.", question);
    return;
  }

  assert(resolve->state == CACHE_STATE_PENDING);
  /* XXX this is a bug which hasn't been found yet. Probably something
   * about slaves answering questions when they're not supposed to, and
   * reusing the old question.
   */
  if(resolve->state != CACHE_STATE_PENDING) {
    log(LOG_ERR,"dns_found_answer(): BUG: resolve '%s' in state %d (not pending). Dropping.",question, resolve->state);
    return;
  }

  resolve->answer = ntohl(answer);
  if(resolve->answer)
    resolve->state = CACHE_STATE_VALID;
  else
    resolve->state = CACHE_STATE_FAILED;

  while(resolve->pending_connections) {
    pend = resolve->pending_connections;
    pend->conn->addr = resolve->answer;
    if(resolve->state == CACHE_STATE_FAILED || connection_exit_connect(pend->conn) < 0) {
      pend->conn->marked_for_close = 1;
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
  uint32_t answer;

  assert(conn && conn->type == CONN_TYPE_DNSWORKER);

  if(conn->inbuf_reached_eof) {
    log(LOG_ERR,"connection_dnsworker_process_inbuf(): Read eof. Worker dying.");
    if(conn->state == DNSWORKER_STATE_BUSY)
      dns_cancel_pending_resolve(conn->address);
    return -1;
  }

  assert(conn->state == DNSWORKER_STATE_BUSY);
  if(conn->inbuf_datalen < 4) /* entire answer available? */
    return 0; /* not yet */
  assert(conn->inbuf_datalen == 4);

  connection_fetch_from_buf((char*)&answer,sizeof(answer),conn);

  dns_found_answer(conn->address, answer);

  free(conn->address);
  conn->address = NULL;
  conn->state = DNSWORKER_STATE_IDLE;
  num_workers_busy--;

  return 0;
}

static void dnsworker_main(int fd) {
  char question[MAX_ADDRESSLEN];
  unsigned char question_len;
  struct hostent *rent;

  for(;;) {

    if(read(fd, &question_len, 1) != 1) {
      log(LOG_INFO,"dnsworker_main(): read length failed. Exiting.");
      exit(0);
    }
    assert(question_len > 0);

    if(read(fd, question, question_len) != question_len) {
      log(LOG_INFO,"dnsworker_main(): read hostname failed. Exiting.");
      exit(0);
    }
    question[question_len] = 0; /* null terminate it */

    rent = gethostbyname(question);
    if (!rent) {
      log(LOG_INFO,"dnsworker_main(): Could not resolve dest addr %s. Returning nulls.",question);
      /* XXX it's conceivable write could return 1 through 3. but that's never gonna happen, right? */
      if(write(fd, "\0\0\0\0", 4) != 4) {
        log(LOG_INFO,"dnsworker_main(): writing nulls failed. Exiting.");
        exit(0);
      }
    } else {
      assert(rent->h_length == 4); /* break to remind us if we move away from ipv4 */
      if(write(fd, rent->h_addr, 4) != 4) {
        log(LOG_INFO,"dnsworker_main(): writing answer failed. Exiting.");
        exit(0);
      }
      log(LOG_INFO,"dnsworker_main(): Answered question '%s'.",question);
    }
  }
}

static int dns_spawn_worker(void) {
  pid_t pid;
  int fd[2];
  connection_t *conn;

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    perror("socketpair");
    exit(1);
  }

  pid = fork();
  if(pid < 0) {
    perror("fork");
    exit(1);
  }
  if(pid == 0) { /* i'm the child */
    close(fd[0]);
    dnsworker_main(fd[1]);
    assert(0); /* never gets here */
  }

  /* i'm the parent */
  log(LOG_DEBUG,"dns_spawn_worker(): just spawned a worker.");
  close(fd[1]);

  conn = connection_new(CONN_TYPE_DNSWORKER);
  if(!conn) {
    close(fd[0]);
    return -1;
  }

  fcntl(fd[0], F_SETFL, O_NONBLOCK); /* set it to non-blocking */

  /* set up conn so it's got all the data we need to remember */
  conn->receiver_bucket = -1; /* non-cell connections don't do receiver buckets */
  conn->bandwidth = -1;
  conn->s = fd[0];

  if(connection_add(conn) < 0) { /* no space, forget it */
    log(LOG_INFO,"dns_spawn_worker(): connection_add failed. Giving up.");
    connection_free(conn); /* this closes fd[0] */
    return -1;
  }

  conn->state = DNSWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

static void spawn_enough_workers(void) {
  int num_workers_needed; /* aim to have 1 more than needed,
                           * but no less than min and no more than max */
  connection_t *dnsconn;

  if(num_workers_busy == MAX_DNSWORKERS) {
    /* We always want at least one worker idle.
     * So find the oldest busy worker and kill it.
     */
    dnsconn = connection_get_by_type_state_lastwritten(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_BUSY);
    assert(dnsconn);

    /* tell the exit connection that it's failed */
    dns_cancel_pending_resolve(dnsconn->address);

    dnsconn->marked_for_close = 1;
    num_workers_busy--;
  }

  if(num_workers_busy >= MIN_DNSWORKERS)
    num_workers_needed = num_workers_busy+1;
  else
    num_workers_needed = MIN_DNSWORKERS;

  while(num_workers < num_workers_needed) {
    if(dns_spawn_worker() < 0) {
      log(LOG_ERR,"spawn_enough_workers(): spawn failed!");
      return;
    }
    num_workers++;
  }

  while(num_workers > num_workers_needed+MAX_IDLE_DNSWORKERS) { /* too many idle? */
    /* cull excess workers */
    dnsconn = connection_get_by_type_state(CONN_TYPE_DNSWORKER, DNSWORKER_STATE_IDLE);
    assert(dnsconn);
    dnsconn->marked_for_close = 1;
    num_workers--;
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
