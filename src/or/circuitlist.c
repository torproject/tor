/* Copyright 2001 Matej Pfajfar, 2001-2004 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file circuitlist.c
 * \brief Manage the global circuit list.
 **/

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

/********* START VARIABLES **********/

/** A global list of all circuits at this hop. */
circuit_t *global_circuitlist=NULL;

/** Array of strings to make circ-\>state human-readable */
char *circuit_state_to_string[] = {
  "doing handshakes",        /* 0 */
  "processing the onion",    /* 1 */
  "connecting to firsthop",  /* 2 */
  "open"                     /* 3 */
};

/********* END VARIABLES ************/

static void circuit_free(circuit_t *circ);
static void circuit_free_cpath(crypt_path_t *cpath);

/** Add <b>circ</b> to the global list of circuits. This is called only from
 * within circuit_new.
 */
static void circuit_add(circuit_t *circ) {
  if(!global_circuitlist) { /* first one */
    global_circuitlist = circ;
    circ->next = NULL;
  } else {
    circ->next = global_circuitlist;
    global_circuitlist = circ;
  }
}

/** Detach from the global circuit list, and deallocate, all
 * circuits that have been marked for close.
 */
void circuit_close_all_marked(void)
{
  circuit_t *tmp,*m;

  while (global_circuitlist && global_circuitlist->marked_for_close) {
    tmp = global_circuitlist->next;
    circuit_free(global_circuitlist);
    global_circuitlist = tmp;
  }

  tmp = global_circuitlist;
  while (tmp && tmp->next) {
    if (tmp->next->marked_for_close) {
      m = tmp->next->next;
      circuit_free(tmp->next);
      tmp->next = m;
      /* Need to check new tmp->next; don't advance tmp. */
    } else {
      /* Advance tmp. */
      tmp = tmp->next;
    }
  }
}

/** Allocate space for a new circuit, initializing with <b>p_circ_id</b>
 * and <b>p_conn</b>. Add it to the global circuit list.
 */
circuit_t *circuit_new(uint16_t p_circ_id, connection_t *p_conn) {
  circuit_t *circ;

  circ = tor_malloc_zero(sizeof(circuit_t));
  circ->magic = CIRCUIT_MAGIC;

  circ->timestamp_created = time(NULL);

  circ->p_circ_id = p_circ_id;
  circ->p_conn = p_conn;

  circ->state = CIRCUIT_STATE_ONIONSKIN_PENDING;

  /* CircIDs */
  circ->p_circ_id = p_circ_id;
  /* circ->n_circ_id remains 0 because we haven't identified the next hop yet */

  circ->package_window = CIRCWINDOW_START;
  circ->deliver_window = CIRCWINDOW_START;

  circ->next_stream_id = crypto_pseudo_rand_int(1<<16);

  circuit_add(circ);

  return circ;
}

/** Deallocate space associated with circ.
 */
static void circuit_free(circuit_t *circ) {
  tor_assert(circ);
  tor_assert(circ->magic == CIRCUIT_MAGIC);
  if (circ->n_crypto)
    crypto_free_cipher_env(circ->n_crypto);
  if (circ->p_crypto)
    crypto_free_cipher_env(circ->p_crypto);
  if (circ->n_digest)
    crypto_free_digest_env(circ->n_digest);
  if (circ->p_digest)
    crypto_free_digest_env(circ->p_digest);
  if(circ->build_state) {
    tor_free(circ->build_state->chosen_exit);
    if (circ->build_state->pending_final_cpath)
      circuit_free_cpath_node(circ->build_state->pending_final_cpath);
  }
  tor_free(circ->build_state);
  circuit_free_cpath(circ->cpath);
  if (circ->rend_splice) {
    circ->rend_splice->rend_splice = NULL;
  }

  memset(circ, 0xAA, sizeof(circuit_t)); /* poison memory */
  free(circ);
}

/** Deallocate space associated with the linked list <b>cpath</b>. */
static void circuit_free_cpath(crypt_path_t *cpath) {
  crypt_path_t *victim, *head=cpath;

  if(!cpath)
    return;

  /* it's a doubly linked list, so we have to notice when we've
   * gone through it once. */
  while(cpath->next && cpath->next != head) {
    victim = cpath;
    cpath = victim->next;
    circuit_free_cpath_node(victim);
  }

  circuit_free_cpath_node(cpath);
}

/** Deallocate space associated with the cpath node <b>victim</b>. */
/* XXX rewrite so the call from circuitbuild isn't necessary */
void circuit_free_cpath_node(crypt_path_t *victim) {
  if(victim->f_crypto)
    crypto_free_cipher_env(victim->f_crypto);
  if(victim->b_crypto)
    crypto_free_cipher_env(victim->b_crypto);
  if(victim->f_digest)
    crypto_free_digest_env(victim->f_digest);
  if(victim->b_digest)
    crypto_free_digest_env(victim->b_digest);
  if(victim->handshake_state)
    crypto_dh_free(victim->handshake_state);
  free(victim);
}

/** Return a circ such that:
 *  - circ-\>n_circ_id or circ-\>p_circ_id is equal to <b>circ_id</b>, and
 *  - circ is attached to <b>conn</b>, either as p_conn, n-conn, or
 *    in p_streams or n_streams.
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_circ_id_conn(uint16_t circ_id, connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;

    if(circ->p_circ_id == circ_id) {
      if(circ->p_conn == conn)
        return circ;
      for(tmpconn = circ->p_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
    if(circ->n_circ_id == circ_id) {
      if(circ->n_conn == conn)
        return circ;
      for(tmpconn = circ->n_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
      for(tmpconn = circ->resolving_streams; tmpconn; tmpconn = tmpconn->next_stream) {
        if(tmpconn == conn)
          return circ;
      }
    }
  }
  return NULL;
}

/** Return a circ such that circ is attached to <b>conn</b>, either as
 * p_conn, n-conn, or in p_streams or n_streams.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_conn(connection_t *conn) {
  circuit_t *circ;
  connection_t *tmpconn;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if (circ->marked_for_close)
      continue;

    if(circ->p_conn == conn)
      return circ;
    if(circ->n_conn == conn)
      return circ;
    for(tmpconn = circ->p_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->n_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
    for(tmpconn = circ->resolving_streams; tmpconn; tmpconn=tmpconn->next_stream)
      if(tmpconn == conn)
        return circ;
  }
  return NULL;
}

/** Return a circ such that:
 *  - circ-\>rend_query is equal to <b>rend_query</b>, and
 *  - circ-\>purpose is equal to <b>purpose</b>.
 *
 * Return NULL if no such circuit exists.
 */
circuit_t *circuit_get_by_rend_query_and_purpose(const char *rend_query, uint8_t purpose) {
  circuit_t *circ;

  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (!circ->marked_for_close &&
        circ->purpose == purpose &&
        !rend_cmp_service_ids(rend_query, circ->rend_query))
      return circ;
  }
  return NULL;
}

/** Return the first circuit in global_circuitlist after <b>start</b> whose
 * rend_pk_digest field is <b>digest</b> and whose purpose is <b>purpose</b>. Returns
 * NULL if no circuit is found.  If <b>start</b> is NULL, begin at the start of
 * the list.
 */
circuit_t *
circuit_get_next_by_pk_and_purpose(circuit_t *start,
                                   const char *digest, uint8_t purpose)
{
  circuit_t *circ;
  if (start == NULL)
    circ = global_circuitlist;
  else
    circ = start->next;

  for( ; circ; circ = circ->next) {
    if (circ->marked_for_close)
      continue;
    if (circ->purpose != purpose)
      continue;
    if (!memcmp(circ->rend_pk_digest, digest, DIGEST_LEN))
      return circ;
  }
  return NULL;
}

/** Return the circuit waiting for a rendezvous with the provided cookie.
 * Return NULL if no such circuit is found.
 */
circuit_t *circuit_get_rendezvous(const char *cookie)
{
  circuit_t *circ;
  for (circ = global_circuitlist; circ; circ = circ->next) {
    if (! circ->marked_for_close &&
        circ->purpose == CIRCUIT_PURPOSE_REND_POINT_WAITING &&
        ! memcmp(circ->rend_cookie, cookie, REND_COOKIE_LEN) )
      return circ;
  }
  return NULL;
}

/** Count the number of circs originating here that aren't open, and
 * that have the specified <b>purpose</b>. */
int circuit_count_building(uint8_t purpose) {
  circuit_t *circ;
  int num=0;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(CIRCUIT_IS_ORIGIN(circ) &&
       circ->state != CIRCUIT_STATE_OPEN &&
       circ->purpose == purpose &&
       !circ->marked_for_close)
      num++;
  }
  return num;
}

/** Return the circuit that is open, has specified <b>purpose</b>,
 * has a timestamp_dirty value of 0, and was created most recently,
 * or NULL if no circuit fits this description.
 */
circuit_t *
circuit_get_youngest_clean_open(uint8_t purpose) {
  circuit_t *circ;
  circuit_t *youngest=NULL;

  for(circ=global_circuitlist;circ;circ = circ->next) {
    if(CIRCUIT_IS_ORIGIN(circ) && circ->state == CIRCUIT_STATE_OPEN &&
       !circ->marked_for_close && circ->purpose == purpose &&
       !circ->timestamp_dirty &&
       (!youngest || youngest->timestamp_created < circ->timestamp_created))
      youngest = circ;
  }
  return youngest;
}

/** Mark <b>circ</b> to be closed next time we call
 * circuit_close_all_marked(). Do any cleanup needed:
 *   - If state is onionskin_pending, remove circ from the onion_pending
 *     list.
 *   - If circ isn't open yet, call circuit_build_failed() if we're
 *     the origin, and in case call circuit_rep_hist_note_result()
 *     to note stats.
 *   - If purpose is C_INTRODUCE_ACK_WAIT, remove the intro point we
 *     just tried from our list of intro points for that service
 *     descriptor.
 *   - Send appropriate destroys and edge_destroys for conns and
 *     streams attached to circ.
 *   - If circ->rend_splice is set (we are the midpoint of a joined
 *     rendezvous stream), then mark the other circuit to close as well.
 */
int _circuit_mark_for_close(circuit_t *circ) {
  connection_t *conn;

  assert_circuit_ok(circ);
  if (circ->marked_for_close)
    return -1;

  if(circ->state == CIRCUIT_STATE_ONIONSKIN_PENDING) {
    onion_pending_remove(circ);
  }
  /* If the circuit ever became OPEN, we sent it to the reputation history
   * module then.  If it isn't OPEN, we send it there now to remember which
   * links worked and which didn't.
   */
  if (circ->state != CIRCUIT_STATE_OPEN) {
    if(CIRCUIT_IS_ORIGIN(circ))
      circuit_build_failed(circ); /* take actions if necessary */
    circuit_rep_hist_note_result(circ);
  }
  if (circ->purpose == CIRCUIT_PURPOSE_C_INTRODUCE_ACK_WAIT) {
    tor_assert(circ->state == CIRCUIT_STATE_OPEN);
    /* treat this like getting a nack from it */
    log_fn(LOG_INFO,"Failed intro circ %s to %s (awaiting ack). Removing from descriptor.",
           circ->rend_query, circ->build_state->chosen_exit);
    rend_client_remove_intro_point(circ->build_state->chosen_exit, circ->rend_query);
  }

  if(circ->n_conn)
    connection_send_destroy(circ->n_circ_id, circ->n_conn);
  for(conn=circ->n_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->n_circ_id, conn);
  while(circ->resolving_streams) {
    conn = circ->resolving_streams;
    circ->resolving_streams = conn->next_stream;
    log_fn(LOG_INFO,"Freeing resolving-conn.");
    connection_free(conn);
  }
  if(circ->p_conn)
    connection_send_destroy(circ->p_circ_id, circ->p_conn);
  for(conn=circ->p_streams; conn; conn=conn->next_stream)
    connection_edge_destroy(circ->p_circ_id, conn);

  circ->marked_for_close = 1;

  if (circ->rend_splice && !circ->rend_splice->marked_for_close) {
    /* do this after marking this circuit, to avoid infinite recursion. */
    circuit_mark_for_close(circ->rend_splice);
    circ->rend_splice = NULL;
  }
  return 0;
}

/** Verify that cpath layer <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_cpath_layer_ok(const crypt_path_t *cp)
{
//  tor_assert(cp->addr); /* these are zero for rendezvous extra-hops */
//  tor_assert(cp->port);
  switch(cp->state)
    {
    case CPATH_STATE_OPEN:
      tor_assert(cp->f_crypto);
      tor_assert(cp->b_crypto);
      /* fall through */
    case CPATH_STATE_CLOSED:
      tor_assert(!cp->handshake_state);
      break;
    case CPATH_STATE_AWAITING_KEYS:
      tor_assert(cp->handshake_state);
      break;
    default:
      tor_assert(0);
    }
  tor_assert(cp->package_window >= 0);
  tor_assert(cp->deliver_window >= 0);
}

/** Verify that cpath <b>cp</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
static void
assert_cpath_ok(const crypt_path_t *cp)
{
  const crypt_path_t *start = cp;

  do {
    assert_cpath_layer_ok(cp);
    /* layers must be in sequence of: "open* awaiting? closed*" */
    if (cp != start) {
      if (cp->state == CPATH_STATE_AWAITING_KEYS) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      } else if (cp->state == CPATH_STATE_OPEN) {
        tor_assert(cp->prev->state == CPATH_STATE_OPEN);
      }
    }
    cp = cp->next;
    tor_assert(cp);
  } while (cp != start);
}

/** Verify that circuit <b>c</b> has all of its invariants
 * correct. Trigger an assert if anything is invalid.
 */
void assert_circuit_ok(const circuit_t *c)
{
  connection_t *conn;

  tor_assert(c);
  tor_assert(c->magic == CIRCUIT_MAGIC);
  tor_assert(c->purpose >= _CIRCUIT_PURPOSE_MIN &&
             c->purpose <= _CIRCUIT_PURPOSE_MAX);

  if (c->n_conn)
    tor_assert(c->n_conn->type == CONN_TYPE_OR);
  if (c->p_conn)
    tor_assert(c->p_conn->type == CONN_TYPE_OR);
  for (conn = c->p_streams; conn; conn = conn->next_stream)
    tor_assert(conn->type == CONN_TYPE_AP);
  for (conn = c->n_streams; conn; conn = conn->next_stream)
    tor_assert(conn->type == CONN_TYPE_EXIT);

  tor_assert(c->deliver_window >= 0);
  tor_assert(c->package_window >= 0);
  if (c->state == CIRCUIT_STATE_OPEN) {
    if (c->cpath) {
      tor_assert(CIRCUIT_IS_ORIGIN(c));
      tor_assert(!c->n_crypto);
      tor_assert(!c->p_crypto);
      tor_assert(!c->n_digest);
      tor_assert(!c->p_digest);
    } else {
      tor_assert(!CIRCUIT_IS_ORIGIN(c));
      tor_assert(c->n_crypto);
      tor_assert(c->p_crypto);
      tor_assert(c->n_digest);
      tor_assert(c->p_digest);
    }
  }
  if (c->cpath) {
    assert_cpath_ok(c->cpath);
  }
  if (c->purpose == CIRCUIT_PURPOSE_REND_ESTABLISHED) {
    if (!c->marked_for_close) {
      tor_assert(c->rend_splice);
      tor_assert(c->rend_splice->rend_splice == c);
    }
    tor_assert(c->rend_splice != c);
  } else {
    tor_assert(!c->rend_splice);
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
