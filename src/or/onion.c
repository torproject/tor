/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* prototypes for smartlist operations from routerlist.h
 * they're here to prevent precedence issues with the .h files
 */
void router_add_running_routers_to_smartlist(smartlist_t *sl);
void add_nickname_list_to_smartlist(smartlist_t *sl, char *list);

extern or_options_t options; /* command-line and config-file options */

static int count_acceptable_routers(smartlist_t *routers);

int decide_circ_id_type(char *local_nick, char *remote_nick) {
  int result;

  assert(remote_nick);
  if(!local_nick)
    return CIRC_ID_TYPE_LOWER;
  result = strcmp(local_nick, remote_nick);
  assert(result);
  if(result < 0)
    return CIRC_ID_TYPE_LOWER;
  return CIRC_ID_TYPE_HIGHER;
}

struct onion_queue_t {
  circuit_t *circ;
  struct onion_queue_t *next;
};

/* global (within this file) variables used by the next few functions */
static struct onion_queue_t *ol_list=NULL;
static struct onion_queue_t *ol_tail=NULL;
static int ol_length=0;

int onion_pending_add(circuit_t *circ) {
  struct onion_queue_t *tmp;

  tmp = tor_malloc(sizeof(struct onion_queue_t));
  tmp->circ = circ;
  tmp->next = NULL;

  if(!ol_tail) {
    assert(!ol_list);
    assert(!ol_length);
    ol_list = tmp;
    ol_tail = tmp;
    ol_length++;
    return 0;
  }

  assert(ol_list);
  assert(!ol_tail->next);

  if(ol_length >= options.MaxOnionsPending) {
    log_fn(LOG_WARN,"Already have %d onions queued. Closing.", ol_length);
    free(tmp);
    return -1;
  }

  ol_length++;
  ol_tail->next = tmp;
  ol_tail = tmp;
  return 0;

}

circuit_t *onion_next_task(void) {
  circuit_t *circ;

  if(!ol_list)
    return NULL; /* no onions pending, we're done */

  assert(ol_list->circ);
  assert(ol_list->circ->p_conn); /* make sure it's still valid */
  assert(ol_length > 0);
  circ = ol_list->circ;
  onion_pending_remove(ol_list->circ);
  return circ;
}

/* go through ol_list, find the onion_queue_t element which points to
 * circ, remove and free that element. leave circ itself alone.
 */
void onion_pending_remove(circuit_t *circ) {
  struct onion_queue_t *tmpo, *victim;

  if(!ol_list)
    return; /* nothing here. */

  /* first check to see if it's the first entry */
  tmpo = ol_list;
  if(tmpo->circ == circ) {
    /* it's the first one. remove it from the list. */
    ol_list = tmpo->next;
    if(!ol_list)
      ol_tail = NULL;
    ol_length--;
    victim = tmpo;
  } else { /* we need to hunt through the rest of the list */
    for( ;tmpo->next && tmpo->next->circ != circ; tmpo=tmpo->next) ;
    if(!tmpo->next) {
      log_fn(LOG_DEBUG,"circ (p_circ_id %d) not in list, probably at cpuworker.",circ->p_circ_id);
      return;
    }
    /* now we know tmpo->next->circ == circ */
    victim = tmpo->next;
    tmpo->next = victim->next;
    if(ol_tail == victim)
      ol_tail = tmpo;
    ol_length--;
  }

  /* now victim points to the element that needs to be removed */

  free(victim);
}

/* given a response payload and keys, initialize, then send a created cell back */
int onionskin_answer(circuit_t *circ, unsigned char *payload, unsigned char *keys) {
  cell_t cell;
  crypt_path_t *tmp_cpath;

  tmp_cpath = tor_malloc_zero(sizeof(crypt_path_t));

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_CREATED;
  cell.circ_id = circ->p_circ_id;

  circ->state = CIRCUIT_STATE_OPEN;

  log_fn(LOG_DEBUG,"Entering.");

  memcpy(cell.payload, payload, ONIONSKIN_REPLY_LEN);

  log_fn(LOG_INFO,"init digest forward 0x%.8x, backward 0x%.8x.",
         (unsigned int)*(uint32_t*)(keys), (unsigned int)*(uint32_t*)(keys+20));
  if (circuit_init_cpath_crypto(tmp_cpath, keys, 0)<0) {
    log_fn(LOG_WARN,"Circuit initialization failed");
    tor_free(tmp_cpath);
    return -1;
  }
  circ->n_digest = tmp_cpath->f_digest;
  circ->n_crypto = tmp_cpath->f_crypto;
  circ->p_digest = tmp_cpath->b_digest;
  circ->p_crypto = tmp_cpath->b_crypto;
  tor_free(tmp_cpath);

  memcpy(circ->handshake_digest, cell.payload+DH_KEY_LEN, DIGEST_LEN);

  connection_or_write_cell_to_buf(&cell, circ->p_conn);
  log_fn(LOG_DEBUG,"Finished sending 'created' cell.");

  return 0;
}

extern int has_fetched_directory;

static int new_route_len(double cw, smartlist_t *routers) {
  int num_acceptable_routers;
  int routelen;

  assert((cw >= 0) && (cw < 1) && routers); /* valid parameters */

#ifdef TOR_PERF
  routelen = 2;
#else
  routelen = 3;
#endif
#if 0
  for(routelen = 3; ; routelen++) { /* 3, increment until coinflip says we're done */
    if (crypto_pseudo_rand_int(255) >= cw*255) /* don't extend */
      break;
  }
#endif
  log_fn(LOG_DEBUG,"Chosen route length %d (%d routers available).",routelen,
         smartlist_len(routers));

  num_acceptable_routers = count_acceptable_routers(routers);

  if(num_acceptable_routers < 2) {
    log_fn(LOG_INFO,"Not enough acceptable routers (%d). Discarding this circuit.",
           num_acceptable_routers);
    return -1;
  }

  if(num_acceptable_routers < routelen) {
    log_fn(LOG_INFO,"Not enough routers: cutting routelen from %d to %d.",
           routelen, num_acceptable_routers);
    routelen = num_acceptable_routers;
  }

  return routelen;
}

static routerinfo_t *choose_good_exit_server_general(routerlist_t *dir)
{
  int *n_supported;
  int i, j;
  int n_pending_connections = 0;
  connection_t **carray;
  int n_connections;
  int best_support = -1;
  int n_best_support=0;
  smartlist_t *sl, *preferredexits, *excludedexits;
  routerinfo_t *router;

  get_connection_array(&carray, &n_connections);

  /* Count how many connections are waiting for a circuit to be built.
   * We use this for log messages now, but in the future we may depend on it.
   */
  for (i = 0; i < n_connections; ++i) {
    if (carray[i]->type == CONN_TYPE_AP &&
        carray[i]->state == AP_CONN_STATE_CIRCUIT_WAIT &&
        !carray[i]->marked_for_close &&
        !circuit_stream_is_being_handled(carray[i]))
      ++n_pending_connections;
  }
  log_fn(LOG_DEBUG, "Choosing exit node; %d connections are pending",
         n_pending_connections);
  /* Now we count, for each of the routers in the directory, how many
   * of the pending connections could possibly exit from that
   * router (n_supported[i]). (We can't be sure about cases where we
   * don't know the IP address of the pending connection.)
   */
  n_supported = tor_malloc(sizeof(int)*smartlist_len(dir->routers));
  for (i = 0; i < smartlist_len(dir->routers); ++i) { /* iterate over routers */
    router = smartlist_get(dir->routers, i);
    if(router_is_me(router)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s -- it's me.", router->nickname);
      /* XXX there's probably a reverse predecessor attack here, but
       * it's slow. should we take this out? -RD
       */
      continue;
    }
    if(!router->is_running) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- directory says it's not running.",
             router->nickname, i);
      continue; /* skip routers that are known to be down */
    }
    if(router_exit_policy_rejects_all(router)) {
      n_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
             router->nickname, i);
      continue; /* skip routers that reject all */
    }
    n_supported[i] = 0;
    for (j = 0; j < n_connections; ++j) { /* iterate over connections */
      if (carray[j]->type != CONN_TYPE_AP ||
          carray[j]->state != AP_CONN_STATE_CIRCUIT_WAIT ||
          carray[j]->marked_for_close ||
          circuit_stream_is_being_handled(carray[j]))
        continue; /* Skip everything but APs in CIRCUIT_WAIT */
      switch (connection_ap_can_use_exit(carray[j], router))
        {
        case ADDR_POLICY_REJECTED:
          log_fn(LOG_DEBUG,"%s (index %d) would reject this stream.",
                 router->nickname, i);
          break; /* would be rejected; try next connection */
        case ADDR_POLICY_ACCEPTED:
        case ADDR_POLICY_UNKNOWN:
          ++n_supported[i];
          log_fn(LOG_DEBUG,"%s is supported. n_supported[%d] now %d.",
                 router->nickname, i, n_supported[i]);
        }
    } /* End looping over connections. */
    if (n_supported[i] > best_support) {
      /* If this router is better than previous ones, remember its index
       * and goodness, and start counting how many routers are this good. */
      best_support = n_supported[i]; n_best_support=1;
      log_fn(LOG_DEBUG,"%s is new best supported option so far.",
             router->nickname);
    } else if (n_supported[i] == best_support) {
      /* If this router is _as good_ as the best one, just increment the
       * count of equally good routers.*/
      ++n_best_support;
    }
  }
  log_fn(LOG_INFO, "Found %d servers that might support %d/%d pending connections.",
         n_best_support, best_support, n_pending_connections);

  preferredexits = smartlist_create();
  add_nickname_list_to_smartlist(preferredexits,options.ExitNodes);

  excludedexits = smartlist_create();
  add_nickname_list_to_smartlist(excludedexits,options.ExcludeNodes);

  sl = smartlist_create();

  /* If any routers definitely support any pending connections, choose one
   * at random. */
  if (best_support > 0) {
    for (i = 0; i < smartlist_len(dir->routers); i++)
      if (n_supported[i] == best_support)
        smartlist_add(sl, smartlist_get(dir->routers, i));

    smartlist_subtract(sl,excludedexits);
    if (smartlist_overlap(sl,preferredexits))
      smartlist_intersect(sl,preferredexits);
    router = smartlist_choose(sl);
  } else {
    /* Either there are no pending connections, or no routers even seem to
     * possibly support any of them.  Choose a router at random. */
    if (best_support == -1) {
      log(LOG_WARN, "All routers are down or middleman -- choosing a doomed exit at random.");
    }
    for(i = 0; i < smartlist_len(dir->routers); i++)
      if(n_supported[i] != -1)
        smartlist_add(sl, smartlist_get(dir->routers, i));

    smartlist_subtract(sl,excludedexits);
    if (smartlist_overlap(sl,preferredexits))
      smartlist_intersect(sl,preferredexits);
    router = smartlist_choose(sl);
  }

  smartlist_free(preferredexits);
  smartlist_free(excludedexits);
  smartlist_free(sl);
  tor_free(n_supported);
  if(router) {
    log_fn(LOG_INFO, "Chose exit server '%s'", router->nickname);
    return router;
  }
  log_fn(LOG_WARN, "No exit routers seem to be running; can't choose an exit.");
  return NULL;
}

static routerinfo_t *choose_good_exit_server(uint8_t purpose, routerlist_t *dir)
{
  if(purpose == CIRCUIT_PURPOSE_C_GENERAL)
    return choose_good_exit_server_general(dir);
  else if (purpose == CIRCUIT_PURPOSE_C_ESTABLISH_REND ||
           purpose == CIRCUIT_PURPOSE_C_REND_JOINED) {
    smartlist_t *obsolete_routers;
    routerinfo_t *r;
    obsolete_routers = smartlist_create();
    router_add_nonrendezvous_to_list(obsolete_routers);
    r = router_choose_random_node(dir, options.RendNodes, options.RendExcludeNodes, NULL);
    smartlist_free(obsolete_routers);
    return r;
  } else
    return router_choose_random_node(dir, options.RendNodes, options.RendExcludeNodes, NULL);
}

cpath_build_state_t *onion_new_cpath_build_state(uint8_t purpose,
                                                 const char *exit_nickname) {
  routerlist_t *rl;
  int r;
  cpath_build_state_t *info;
  routerinfo_t *exit;

  router_get_routerlist(&rl);
  r = new_route_len(options.PathlenCoinWeight, rl->routers);
  if (r < 0)
    return NULL;
  info = tor_malloc_zero(sizeof(cpath_build_state_t));
  info->desired_path_len = r;
  if(exit_nickname) { /* the circuit-builder pre-requested one */
    log_fn(LOG_INFO,"Using requested exit node '%s'", exit_nickname);
    info->chosen_exit = tor_strdup(exit_nickname);
  } else { /* we have to decide one */
    exit = choose_good_exit_server(purpose, rl);
    if(!exit) {
      log_fn(LOG_WARN,"failed to choose an exit server");
      tor_free(info);
      return NULL;
    }
    info->chosen_exit = tor_strdup(exit->nickname);
  }
  return info;
}

static int count_acceptable_routers(smartlist_t *routers) {
  int i, j, n;
  int num=0;
  connection_t *conn;
  routerinfo_t *r, *r2;

  n = smartlist_len(routers);
  for(i=0;i<n;i++) {
    log_fn(LOG_DEBUG,"Contemplating whether router %d is a new option...",i);
    r = smartlist_get(routers, i);
    if(r->is_running == 0) {
      log_fn(LOG_DEBUG,"Nope, the directory says %d is not running.",i);
      goto next_i_loop;
    }
    if(options.ORPort) {
      conn = connection_exact_get_by_addr_port(r->addr, r->or_port);
      if(!conn || conn->type != CONN_TYPE_OR || conn->state != OR_CONN_STATE_OPEN) {
        log_fn(LOG_DEBUG,"Nope, %d is not connected.",i);
        goto next_i_loop;
      }
    }
    for(j=0;j<i;j++) {
      r2 = smartlist_get(routers, j);
      if(!crypto_pk_cmp_keys(r->onion_pkey, r2->onion_pkey)) {
        /* these guys are twins. so we've already counted him. */
        log_fn(LOG_DEBUG,"Nope, %d is a twin of %d.",i,j);
        goto next_i_loop;
      }
    }
    num++;
    log_fn(LOG_DEBUG,"I like %d. num_acceptable_routers now %d.",i, num);
    next_i_loop:
      ; /* our compiler may need an explicit statement after the label */
  }

  return num;
}

static void remove_twins_from_smartlist(smartlist_t *sl, routerinfo_t *twin) {
  int i;
  routerinfo_t *r;

  if(twin == NULL)
    return;

  for(i=0; i < smartlist_len(sl); i++) {
    r = smartlist_get(sl,i);
    if (!crypto_pk_cmp_keys(r->onion_pkey, twin->onion_pkey)) {
      smartlist_del(sl,i--);
    }
  }
}

void onion_append_to_cpath(crypt_path_t **head_ptr, crypt_path_t *new_hop)
{
  if (*head_ptr) {
    new_hop->next = (*head_ptr);
    new_hop->prev = (*head_ptr)->prev;
    (*head_ptr)->prev->next = new_hop;
    (*head_ptr)->prev = new_hop;
  } else {
    *head_ptr = new_hop;
    new_hop->prev = new_hop->next = new_hop;
  }
}

int onion_extend_cpath(crypt_path_t **head_ptr, cpath_build_state_t *state, routerinfo_t **router_out)
{
  int cur_len;
  crypt_path_t *cpath, *hop;
  routerinfo_t *r;
  routerinfo_t *choice;
  int i;
  smartlist_t *sl, *excludednodes;

  assert(head_ptr);
  assert(router_out);

  if (!*head_ptr) {
    cur_len = 0;
  } else {
    cur_len = 1;
    for (cpath = *head_ptr; cpath->next != *head_ptr; cpath = cpath->next) {
      ++cur_len;
    }
  }
  if (cur_len >= state->desired_path_len) {
    log_fn(LOG_DEBUG, "Path is complete: %d steps long",
           state->desired_path_len);
    return 1;
  }
  log_fn(LOG_DEBUG, "Path is %d long; we want %d", cur_len,
         state->desired_path_len);

  excludednodes = smartlist_create();
  add_nickname_list_to_smartlist(excludednodes,options.ExcludeNodes);

  if(cur_len == state->desired_path_len - 1) { /* Picking last node */
    log_fn(LOG_DEBUG, "Contemplating last hop: choice already made: %s",
           state->chosen_exit);
    choice = router_get_by_nickname(state->chosen_exit);
    smartlist_free(excludednodes);
    if(!choice) {
      log_fn(LOG_WARN,"Our chosen exit %s is no longer in the directory? Discarding this circuit.",
             state->chosen_exit);
      return -1;
    }
  } else if(cur_len == 0) { /* picking first node */
    /* try the nodes in EntryNodes first */
    sl = smartlist_create();
    add_nickname_list_to_smartlist(sl,options.EntryNodes);
    /* XXX one day, consider picking chosen_exit knowing what's in EntryNodes */
    remove_twins_from_smartlist(sl,router_get_by_nickname(state->chosen_exit));
    remove_twins_from_smartlist(sl,router_get_my_routerinfo());
    smartlist_subtract(sl,excludednodes);
    choice = smartlist_choose(sl);
    smartlist_free(sl);
    if(!choice) {
      sl = smartlist_create();
      router_add_running_routers_to_smartlist(sl);
      remove_twins_from_smartlist(sl,router_get_by_nickname(state->chosen_exit));
      remove_twins_from_smartlist(sl,router_get_my_routerinfo());
      smartlist_subtract(sl,excludednodes);
      choice = smartlist_choose(sl);
      smartlist_free(sl);
    }
    smartlist_free(excludednodes);
    if(!choice) {
      log_fn(LOG_WARN,"No acceptable routers while picking entry node. Discarding this circuit.");
      return -1;
    }
  } else {
    log_fn(LOG_DEBUG, "Contemplating intermediate hop: random choice.");
    sl = smartlist_create();
    router_add_running_routers_to_smartlist(sl);
    remove_twins_from_smartlist(sl,router_get_by_nickname(state->chosen_exit));
    remove_twins_from_smartlist(sl,router_get_my_routerinfo());
    for (i = 0, cpath = *head_ptr; i < cur_len; ++i, cpath=cpath->next) {
      r = router_get_by_addr_port(cpath->addr, cpath->port);
      assert(r);
      remove_twins_from_smartlist(sl,r);
    }
    smartlist_subtract(sl,excludednodes);
    choice = smartlist_choose(sl);
    smartlist_free(sl);
    smartlist_free(excludednodes);
    if(!choice) {
      log_fn(LOG_WARN,"No acceptable routers while picking intermediate node. Discarding this circuit.");
      return -1;
    }
  }

  log_fn(LOG_DEBUG,"Chose router %s for hop %d (exit is %s)",
         choice->nickname, cur_len, state->chosen_exit);

  hop = tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  onion_append_to_cpath(head_ptr, hop);

  hop->state = CPATH_STATE_CLOSED;

  hop->port = choice->or_port;
  hop->addr = choice->addr;

  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  log_fn(LOG_DEBUG, "Extended circuit path with %s for hop %d",
         choice->nickname, cur_len);

  *router_out = choice;
  return 0;
}

/*----------------------------------------------------------------------*/

/* Given a router's 128 byte public key,
   stores the following in onion_skin_out:
[16 bytes] Symmetric key for encrypting blob past RSA
[112 bytes] g^x part 1 (inside the RSA)
[16 bytes] g^x part 2 (symmetrically encrypted)
[ 6 bytes] Meeting point (IP/port)
[ 8 bytes] Meeting cookie
[16 bytes] End-to-end authentication [optional]

 * Stores the DH private key into handshake_state_out for later completion
 * of the handshake.
 *
 * The meeting point/cookies and auth are zeroed out for now.
 */
int
onion_skin_create(crypto_pk_env_t *dest_router_key,
                  crypto_dh_env_t **handshake_state_out,
                  char *onion_skin_out) /* Must be ONIONSKIN_CHALLENGE_LEN bytes */
{
  char *challenge = NULL;
  crypto_dh_env_t *dh = NULL;
  int dhbytes, pkbytes;

  *handshake_state_out = NULL;
  memset(onion_skin_out, 0, ONIONSKIN_CHALLENGE_LEN);

  if (!(dh = crypto_dh_new()))
    goto err;

  dhbytes = crypto_dh_get_bytes(dh);
  pkbytes = crypto_pk_keysize(dest_router_key);
  assert(dhbytes == 128);
  assert(pkbytes == 128);
  challenge = tor_malloc_zero(ONIONSKIN_CHALLENGE_LEN-CIPHER_KEY_LEN);

  if (crypto_dh_get_public(dh, challenge, dhbytes))
    goto err;

#ifdef DEBUG_ONION_SKINS
#define PA(a,n) \
  { int _i; for (_i = 0; _i<n; ++_i) printf("%02x ",((int)(a)[_i])&0xFF); }

  printf("Client: client g^x:");
  PA(challenge+16,3);
  printf("...");
  PA(challenge+141,3);
  puts("");

  printf("Client: client symkey:");
  PA(challenge+0,16);
  puts("");
#endif

  /* set meeting point, meeting cookie, etc here. Leave zero for now. */
  if (crypto_pk_public_hybrid_encrypt(dest_router_key, challenge,
                                      ONIONSKIN_CHALLENGE_LEN-CIPHER_KEY_LEN,
                                      onion_skin_out, PK_NO_PADDING, 1)<0)
    goto err;

  tor_free(challenge);
  *handshake_state_out = dh;

  return 0;
 err:
  tor_free(challenge);
  if (dh) crypto_dh_free(dh);
  return -1;
}

/* Given an encrypted DH public key as generated by onion_skin_create,
 * and the private key for this onion router, generate the reply (128-byte
 * DH plus the first 20 bytes of shared key material), and store the
 * next key_out_len bytes of key material in key_out.
 */
int
onion_skin_server_handshake(char *onion_skin, /* ONIONSKIN_CHALLENGE_LEN bytes */
                            crypto_pk_env_t *private_key,
                            char *handshake_reply_out, /* ONIONSKIN_REPLY_LEN bytes */
                            char *key_out,
                            int key_out_len)
{
  char challenge[ONIONSKIN_CHALLENGE_LEN];
  crypto_dh_env_t *dh = NULL;
  int len;
  char *key_material=NULL;

  if (crypto_pk_private_hybrid_decrypt(private_key,
                                       onion_skin, ONIONSKIN_CHALLENGE_LEN,
                                       challenge, PK_NO_PADDING)<0)
    goto err;

  dh = crypto_dh_new();
  if (crypto_dh_get_public(dh, handshake_reply_out, DH_KEY_LEN))
    goto err;

#ifdef DEBUG_ONION_SKINS
  printf("Server: server g^y:");
  PA(handshake_reply_out+0,3);
  printf("...");
  PA(handshake_reply_out+125,3);
  puts("");
#endif

  key_material = tor_malloc(DIGEST_LEN+key_out_len);
  len = crypto_dh_compute_secret(dh, challenge, DH_KEY_LEN,
                                 key_material, DIGEST_LEN+key_out_len);
  if (len < 0)
    goto err;

  /* send back H(K|0) as proof that we learned K. */
  memcpy(handshake_reply_out+DH_KEY_LEN, key_material, DIGEST_LEN);

  /* use the rest of the key material for our shared keys, digests, etc */
  memcpy(key_out, key_material+DIGEST_LEN, key_out_len);

#ifdef DEBUG_ONION_SKINS
  printf("Server: key material:");
  PA(buf, DH_KEY_LEN);
  puts("");
  printf("Server: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  tor_free(key_material);
  crypto_dh_free(dh);
  return 0;
 err:
  tor_free(key_material);
  if (dh) crypto_dh_free(dh);

  return -1;
}

/* Finish the client side of the DH handshake.
 * Given the 128 byte DH reply + 20 byte hash as generated by
 * onion_skin_server_handshake and the handshake state generated by
 * onion_skin_create, verify H(K) with the first 20 bytes of shared
 * key material, then generate key_out_len more bytes of shared key
 * material and store them in key_out.
 *
 * After the invocation, call crypto_dh_free on handshake_state.
 */
int
onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
                            char *handshake_reply, /* Must be ONIONSKIN_REPLY_LEN bytes */
                            char *key_out,
                            int key_out_len)
{
  int len;
  char *key_material=NULL;
  assert(crypto_dh_get_bytes(handshake_state) == DH_KEY_LEN);

#ifdef DEBUG_ONION_SKINS
  printf("Client: server g^y:");
  PA(handshake_reply+0,3);
  printf("...");
  PA(handshake_reply+125,3);
  puts("");
#endif

  key_material = tor_malloc(20+key_out_len);
  len = crypto_dh_compute_secret(handshake_state, handshake_reply, DH_KEY_LEN,
                                 key_material, 20+key_out_len);
  if (len < 0)
    return -1;

  if(memcmp(key_material, handshake_reply+DH_KEY_LEN, 20)) {
    /* H(K) does *not* match. Something fishy. */
    tor_free(key_material);
    log_fn(LOG_WARN,"Digest DOES NOT MATCH on onion handshake. Bug or attack.");
    return -1;
  }

  /* use the rest of the key material for our shared keys, digests, etc */
  memcpy(key_out, key_material+20, key_out_len);

#ifdef DEBUG_ONION_SKINS
  printf("Client: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  tor_free(key_material);
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
