/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern or_options_t options; /* command-line and config-file options */

static int count_acceptable_routers(routerinfo_t **rarray, int rarray_len);

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

  tmp = tor_malloc_zero(sizeof(struct onion_queue_t));
  tmp->circ = circ;

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
#if 0
  if(!ol_list->circ->p_conn) {
    log_fn(LOG_INFO,"ol_list->circ->p_conn null, must have died?");
    onion_pending_remove(ol_list->circ);
    return onion_next_task(); /* recurse: how about the next one? */
  }
#endif

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
  unsigned char iv[16];
  cell_t cell;

  memset(iv, 0, 16);

  memset(&cell, 0, sizeof(cell_t));
  cell.command = CELL_CREATED;
  cell.circ_id = circ->p_circ_id;
  cell.length = DH_KEY_LEN;

  circ->state = CIRCUIT_STATE_OPEN;

  log_fn(LOG_DEBUG,"Entering.");

  memcpy(cell.payload, payload, DH_KEY_LEN);

  log_fn(LOG_DEBUG,"init cipher forward %d, backward %d.", *(int*)keys, *(int*)(keys+16));

  if (!(circ->n_crypto =
        crypto_create_init_cipher(CIRCUIT_CIPHER,keys,iv,0))) {
    log_fn(LOG_WARN,"Cipher initialization failed (n).");
    return -1;
  }

  if (!(circ->p_crypto =
        crypto_create_init_cipher(CIRCUIT_CIPHER,keys+16,iv,1))) {
    log_fn(LOG_WARN,"Cipher initialization failed (p).");
    return -1;
  }

  connection_or_write_cell_to_buf(&cell, circ->p_conn);
  log_fn(LOG_DEBUG,"Finished sending 'created' cell.");

  return 0;
}

char **parse_nickname_list(char *list, int *num) {
  char **out;
  char *start,*end;
  int i;
   
  while(isspace(*list)) list++;

  i=0, start = list;
  while(*start) {
    while(*start && !isspace(*start)) start++;
    i++;
    while(isspace(*start)) start++;
  }

  out = tor_malloc(i * sizeof(char *));

  i=0, start=list;
  while(*start) {
    end=start; while(*end && !isspace(*end)) end++;
    out[i] = tor_malloc(MAX_NICKNAME_LEN);
    strncpy(out[i],start,end-start);
    out[i][end-start] = 0; /* null terminate it */
    i++;
    while(isspace(*end)) end++;
    start = end;
  }
  *num = i;
  return out;  
}

static int new_route_len(double cw, routerinfo_t **rarray, int rarray_len) {
  int num_acceptable_routers;
  int routelen;

  assert((cw >= 0) && (cw < 1) && rarray); /* valid parameters */

  for(routelen=3; ; routelen++) { /* 3, increment until coinflip says we're done */
    if (crypto_pseudo_rand_int(255) >= cw*255) /* don't extend */
      break;
  }
  log_fn(LOG_DEBUG,"Chosen route length %d (%d routers available).",routelen, rarray_len);

  num_acceptable_routers = count_acceptable_routers(rarray, rarray_len);

  if(num_acceptable_routers < 2) {
    log_fn(LOG_INFO,"Not enough acceptable routers. Failing.");
    return -1;
  }

  if(num_acceptable_routers < routelen) {
    log_fn(LOG_INFO,"Not enough routers: cutting routelen from %d to %d.",routelen, num_acceptable_routers);
    routelen = num_acceptable_routers;
  }

  if (routelen < 1) {
    log_fn(LOG_WARN,"Didn't find any acceptable routers. Failing.");
    return -1;
  }

  return routelen;
}

static routerinfo_t *choose_good_exit_server(directory_t *dir)
{
  int *n_supported;
  int *n_maybe_supported;
  int i, j;
  int n_pending_connections = 0;
  connection_t **carray;
  int n_connections;
  int best_support = -1;
  int best_maybe_support = -1;
  int best_support_idx = -1;
  int best_maybe_support_idx = -1;
  int n_best_support=0, n_best_maybe_support=0;
  int n_running_routers=0;
  
  get_connection_array(&carray, &n_connections);

  /* Count how many connections are waiting for a circuit to be built.
   * We use this for log messages now, but in the future we may depend on it.
   */
  for (i = 0; i < n_connections; ++i) {
    if (carray[i]->type == CONN_TYPE_AP &&
        carray[i]->state == AP_CONN_STATE_CIRCUIT_WAIT &&
        !carray[i]->marked_for_close)
      ++n_pending_connections;
  }
  log_fn(LOG_DEBUG, "Choosing exit node; %d connections are pending",
         n_pending_connections);
  /* Now we count, for each of the routers in the directory: how many
   * of the pending connections could _definitely_ exit from that
   * router (n_supported[i]) and how many could _possibly_ exit from
   * that router (n_maybe_supported[i]).  (We can't be sure about
   * cases where we don't know the IP address of the pending
   * connection.)
   */
  n_supported = tor_malloc(sizeof(int)*dir->n_routers);
  n_maybe_supported = tor_malloc(sizeof(int)*dir->n_routers);
  for (i = 0; i < dir->n_routers; ++i) { /* iterate over routers */
    if(!dir->routers[i]->is_running) {
      n_supported[i] = n_maybe_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- directory says it's not running.",
             dir->routers[i]->nickname, i);
      continue; /* skip routers that are known to be down */
    }
    if(router_exit_policy_rejects_all(dir->routers[i])) {
      n_supported[i] = n_maybe_supported[i] = -1;
      log_fn(LOG_DEBUG,"Skipping node %s (index %d) -- it rejects all.",
             dir->routers[i]->nickname, i);
      continue; /* skip routers that reject all */
    }
    n_supported[i] = n_maybe_supported[i] = 0;
    ++n_running_routers;
    for (j = 0; j < n_connections; ++j) { /* iterate over connections */
      if (carray[j]->type != CONN_TYPE_AP ||
          carray[j]->state != AP_CONN_STATE_CIRCUIT_WAIT ||
          carray[j]->marked_for_close)
        continue; /* Skip everything but APs in CIRCUIT_WAIT */
      switch (connection_ap_can_use_exit(carray[j], dir->routers[i])) 
        {
        case -1:
          log_fn(LOG_DEBUG,"%s (index %d) would reject this stream.",
                 dir->routers[i]->nickname, i);
          break; /* would be rejected; try next connection */
        case 0:
          ++n_supported[i];
          log_fn(LOG_DEBUG,"%s is supported. n_supported[%d] now %d.",
                 dir->routers[i]->nickname, i, n_supported[i]);
          ; /* Fall through: If it is supported, it is also maybe supported. */
        case 1:
          ++n_maybe_supported[i];
          log_fn(LOG_DEBUG,"%s is maybe supported. n_maybe_supported[%d] now %d.",
                 dir->routers[i]->nickname, i, n_maybe_supported[i]);
        }
    } /* End looping over connections. */
    if (n_supported[i] > best_support) { 
      /* If this router is better than previous ones, remember its index
       * and goodness, and start counting how many routers are this good. */
      best_support = n_supported[i]; best_support_idx = i; n_best_support=1;
      log_fn(LOG_DEBUG,"%s is new best supported option so far.",
             dir->routers[i]->nickname);
    } else if (n_supported[i] == best_support) {
      /* If this router is _as good_ as the best one, just increment the
       * count of equally good routers.*/
      ++n_best_support;
    }
    /* As above, but for 'maybe-supported' connections */
    if (n_maybe_supported[i] > best_maybe_support) {
      best_maybe_support = n_maybe_supported[i]; best_maybe_support_idx = i;
      n_best_maybe_support = 1;
      log_fn(LOG_DEBUG,"%s is new best maybe-supported option so far.",
             dir->routers[i]->nickname);
    } else if (n_maybe_supported[i] == best_maybe_support) {
      ++n_best_maybe_support;
    }
  }
  log_fn(LOG_INFO, "Found %d servers that will definitely support %d/%d pending connections, and %d that might support %d/%d.",
         n_best_support, best_support, n_pending_connections,
         n_best_maybe_support, best_maybe_support, n_pending_connections);
  /* If any routers definitely support any pending connections, choose one
   * at random. */
  if (best_support > 0) {
    i = crypto_pseudo_rand_int(n_best_support);
    /* Iterate over the routers, until we find the i-th one such that
     * n_supported[j] == best_support
     */
    for (j = best_support_idx; j < dir->n_routers; ++j) {
      if (n_supported[j] == best_support) {
        if (i)
          --i;
        else {
          tor_free(n_supported); tor_free(n_maybe_supported);
          log_fn(LOG_DEBUG, "Chose exit server '%s'", dir->routers[j]->nickname);
          return dir->routers[j];
        }
      }
    }
    /* This point should never be reached. */
    assert(0);
  }
  /* If any routers _maybe_ support pending connections, choose one at
   * random, as above.  */
  if (best_maybe_support > 0) {
    i = crypto_pseudo_rand_int(n_best_maybe_support);
    for (j = best_maybe_support_idx; j < dir->n_routers; ++j) {
      if (n_maybe_supported[j] == best_maybe_support) {
        if (i)
          --i;
        else {
          tor_free(n_supported); tor_free(n_maybe_supported);
          log_fn(LOG_DEBUG, "Chose exit server '%s'", dir->routers[j]->nickname);
          return dir->routers[j];
        }
      }
    }
    /* This point should never be reached. */
    assert(0);
  }
  /* Either there are no pending connections, or no routers even seem to
   * possibly support any of them.  Choose a router at random. */
  if (!n_running_routers) {
    log_fn(LOG_WARN, "No exit routers seem to be running; can't choose an exit.");
    return NULL;
  }
  /* Iterate over the routers, till we find the i'th one that has ->is_running
   * and allows exits. */
  i = crypto_pseudo_rand_int(n_running_routers);
  for (j = 0; j < dir->n_routers; ++j) {
    if (n_supported[j] != -1) {
      if (i)
        --i;
      else {
        tor_free(n_supported); tor_free(n_maybe_supported);
        log_fn(LOG_DEBUG, "Chose exit server '%s'", dir->routers[j]->nickname);
        return dir->routers[j];
      }
    }
  }
  assert(0);
  return NULL;
}

cpath_build_state_t *onion_new_cpath_build_state(void) {
  directory_t *dir;
  int r;
  cpath_build_state_t *info;
  
  router_get_directory(&dir);
  r = new_route_len(options.PathlenCoinWeight, dir->routers, dir->n_routers);
  if (r < 0) 
    return NULL;
  info = tor_malloc(sizeof(cpath_build_state_t));
  info->desired_path_len = r;
  info->chosen_exit = tor_strdup(choose_good_exit_server(dir)->nickname);
  return info;
}

static int count_acceptable_routers(routerinfo_t **rarray, int rarray_len) {
  int i, j;
  int num=0;
  connection_t *conn;

  for(i=0;i<rarray_len;i++) {
    log_fn(LOG_DEBUG,"Contemplating whether router %d is a new option...",i);
    if(rarray[i]->is_running == 0) {
      log_fn(LOG_DEBUG,"Nope, the directory says %d is not running.",i);
      goto next_i_loop;
    }
    if(options.ORPort) {
      conn = connection_exact_get_by_addr_port(rarray[i]->addr, rarray[i]->or_port);
      if(!conn || conn->type != CONN_TYPE_OR || conn->state != OR_CONN_STATE_OPEN) {
        log_fn(LOG_DEBUG,"Nope, %d is not connected.",i);
        goto next_i_loop;
      }
    }
    for(j=0;j<i;j++) {
      if(!crypto_pk_cmp_keys(rarray[i]->onion_pkey, rarray[j]->onion_pkey)) {
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

int onion_extend_cpath(crypt_path_t **head_ptr, cpath_build_state_t *state, routerinfo_t **router_out)
{
  int cur_len;
  crypt_path_t *cpath, *hop;
  routerinfo_t **rarray, *r;
  routerinfo_t *choice;
  int rarray_len;
  int i;
  directory_t *dir;
  int n_failures;

  assert(head_ptr);
  assert(router_out);

  router_get_directory(&dir);
  rarray = dir->routers;
  rarray_len = dir->n_routers;
  
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

  n_failures = 0;
  goto start;
 again:
  log_fn(LOG_DEBUG, "Picked an already-selected router for hop %d; retrying.",
         cur_len);
  ++n_failures;
  if (n_failures == 25) {
    /* This actually happens with P=1/30,000,000 when we _could_ build a
     * circuit.  For now, let's leave it in.
     */
    log_fn(LOG_INFO, "Unable to continue generating circuit path");
    return -1;
  }
 start:
  /* XXX through each of these, don't pick nodes that are down */
  if(cur_len == 0) { /* picking entry node */
    log_fn(LOG_DEBUG, "Contemplating first hop: random choice.");
    choice = rarray[crypto_pseudo_rand_int(rarray_len)];
  } else if (cur_len == state->desired_path_len - 1) { /* Picking last node */
    log_fn(LOG_DEBUG, "Contemplating last hop: choice already made.");
    choice = router_get_by_nickname(state->chosen_exit);
    /* XXX check if null */
  } else {
    log_fn(LOG_DEBUG, "Contemplating intermediate hop: random choice.");
    choice = rarray[crypto_pseudo_rand_int(rarray_len)];
  }
  log_fn(LOG_DEBUG,"Contemplating router %s for hop %d (exit is %s)",
         choice->nickname, cur_len, state->chosen_exit);
  if (cur_len != state->desired_path_len-1 && 
      !strcasecmp(choice->nickname, state->chosen_exit)) {
    goto again;
  }

  for (i = 0, cpath = *head_ptr; i < cur_len; ++i, cpath=cpath->next) {
    r = router_get_by_addr_port(cpath->addr, cpath->port);
    if ((r && !crypto_pk_cmp_keys(r->onion_pkey, choice->onion_pkey))
        || (cur_len != state->desired_path_len-1 &&
            !strcasecmp(choice->nickname, state->chosen_exit))
        || (cpath->addr == choice->addr && 
            cpath->port == choice->or_port)
        || (options.ORPort &&
            !(connection_twin_get_by_addr_port(choice->addr,
                                               choice->or_port)))) {
      goto again;
    }
  }
 
  /* Okay, so we haven't used 'choice' before. */
  hop = (crypt_path_t *)tor_malloc_zero(sizeof(crypt_path_t));

  /* link hop into the cpath, at the end. */
  if (*head_ptr) {
    hop->next = (*head_ptr);
    hop->prev = (*head_ptr)->prev;
    (*head_ptr)->prev->next = hop;
    (*head_ptr)->prev = hop;
  } else {
    *head_ptr = hop;
    hop->prev = hop->next = hop;
  }

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

/* Given a router's public key, generates a 144-byte encrypted DH pubkey,
 * and stores it into onion_skin out.  Stores the DH private key into 
 * handshake_state_out for later completion of the handshake.
 *
 * The encrypted pubkey is formed as follows:
 *    16 bytes of symmetric key
 *   128 bytes of g^x for DH.
 * The first 128 bytes are RSA-encrypted with the server's public key,
 * and the last 16 are encrypted with the symmetric key.
 */
int
onion_skin_create(crypto_pk_env_t *dest_router_key,
                  crypto_dh_env_t **handshake_state_out,
                  char *onion_skin_out) /* Must be DH_ONIONSKIN_LEN bytes long */
{
  char iv[16];
  char *pubkey = NULL;
  crypto_dh_env_t *dh = NULL;
  crypto_cipher_env_t *cipher = NULL;
  int dhbytes, pkbytes;

  *handshake_state_out = NULL;
  memset(onion_skin_out, 0, DH_ONIONSKIN_LEN);
  memset(iv, 0, 16);

  if (!(dh = crypto_dh_new()))
    goto err;
  
  dhbytes = crypto_dh_get_bytes(dh);
  pkbytes = crypto_pk_keysize(dest_router_key);
  assert(dhbytes+16 == DH_ONIONSKIN_LEN);
  pubkey = (char *)tor_malloc(dhbytes+16);

  if (crypto_rand(16, pubkey))
    goto err;
  
  /* XXXX You can't just run around RSA-encrypting any bitstream: if it's
   *      greater than the RSA key, then OpenSSL will happily encrypt,
   *      and later decrypt to the wrong value.  So we set the first bit
   *      of 'pubkey' to 0.  This means that our symmetric key is really only
   *      127 bits long, but since it shouldn't be necessary to encrypt
   *      DH public keys values in the first place, we should be fine.
   */
  pubkey[0] &= 0x7f; 

  if (crypto_dh_get_public(dh, pubkey+16, dhbytes))
    goto err;

#ifdef DEBUG_ONION_SKINS
#define PA(a,n) \
  { int _i; for (_i = 0; _i<n; ++_i) printf("%02x ",((int)(a)[_i])&0xFF); }

  printf("Client: client g^x:");
  PA(pubkey+16,3);
  printf("...");
  PA(pubkey+141,3);
  puts("");

  printf("Client: client symkey:");
  PA(pubkey+0,16);
  puts("");
#endif

  cipher = crypto_create_init_cipher(ONION_CIPHER, pubkey, iv, 1);

  if (!cipher)
    goto err;

  if (crypto_pk_public_encrypt(dest_router_key, pubkey, pkbytes,
                               onion_skin_out, RSA_NO_PADDING)==-1)
    goto err;

  if (crypto_cipher_encrypt(cipher, pubkey+pkbytes, dhbytes+16-pkbytes,
                            onion_skin_out+pkbytes))
    goto err;
  
  free(pubkey);
  crypto_free_cipher_env(cipher);
  *handshake_state_out = dh;

  return 0;
 err:
  tor_free(pubkey);
  if (dh) crypto_dh_free(dh);
  if (cipher) crypto_free_cipher_env(cipher);
  return -1;
}

/* Given an encrypted DH public key as generated by onion_skin_create,
 * and the private key for this onion router, generate the 128-byte DH
 * reply, and key_out_len bytes of key material, stored in key_out.
 */
int
onion_skin_server_handshake(char *onion_skin, /* DH_ONIONSKIN_LEN bytes long */
                            crypto_pk_env_t *private_key,
                            char *handshake_reply_out, /* DH_KEY_LEN bytes long */
                            char *key_out,
                            int key_out_len)
{
  char buf[DH_ONIONSKIN_LEN];
  char iv[16];
  crypto_dh_env_t *dh = NULL;
  crypto_cipher_env_t *cipher = NULL;
  int pkbytes;
  int len;
  
  memset(iv, 0, 16);
  pkbytes = crypto_pk_keysize(private_key);

  if (crypto_pk_private_decrypt(private_key,
                                onion_skin, pkbytes,
                                buf, RSA_NO_PADDING) == -1)
    goto err;
  
#ifdef DEBUG_ONION_SKINS
  printf("Server: client symkey:");
  PA(buf+0,16);
  puts("");
#endif

  cipher = crypto_create_init_cipher(ONION_CIPHER, buf, iv, 0);

  if (crypto_cipher_decrypt(cipher, onion_skin+pkbytes, DH_ONIONSKIN_LEN-pkbytes,
                            buf+pkbytes))
    goto err;

#ifdef DEBUG_ONION_SKINS
  printf("Server: client g^x:");
  PA(buf+16,3);
  printf("...");
  PA(buf+141,3);
  puts("");
#endif
  
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

  len = crypto_dh_compute_secret(dh, buf+16, DH_KEY_LEN, key_out, key_out_len);
  if (len < 0)
    goto err;

#ifdef DEBUG_ONION_SKINS
  printf("Server: key material:");
  PA(buf, DH_KEY_LEN);
  puts("");
  printf("Server: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  crypto_free_cipher_env(cipher);
  crypto_dh_free(dh);
  return 0;
 err:
  if (cipher) crypto_free_cipher_env(cipher);
  if (dh) crypto_dh_free(dh);

  return -1;
}

/* Finish the client side of the DH handshake.
 * Given the 128 byte DH reply as generated by onion_skin_server_handshake
 * and the handshake state generated by onion_skin_create, generate
 * key_out_len bytes of shared key material and store them in key_out.
 *
 * After the invocation, call crypto_dh_free on handshake_state.
 */
int
onion_skin_client_handshake(crypto_dh_env_t *handshake_state,
                            char *handshake_reply,/* Must be DH_KEY_LEN bytes long*/
                            char *key_out,
                            int key_out_len) 
{
  int len;
  assert(crypto_dh_get_bytes(handshake_state) == DH_KEY_LEN);
  
#ifdef DEBUG_ONION_SKINS
  printf("Client: server g^y:");
  PA(handshake_reply+0,3);
  printf("...");
  PA(handshake_reply+125,3);
  puts("");
#endif

  len = crypto_dh_compute_secret(handshake_state, handshake_reply, DH_KEY_LEN,
                                 key_out, key_out_len);
  if (len < 0)
    return -1;
  
#ifdef DEBUG_ONION_SKINS
  printf("Client: keys out:");
  PA(key_out, key_out_len);
  puts("");
#endif

  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
