/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

/* This module implements the hidden-service side of rendezvous functionality.
 */

#include "or.h"

/* Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struct rend_service_port_config_t {
  uint16_t virtual_port;
  uint16_t real_port;
  uint32_t real_address;
} rend_service_port_config_t;

/* Try to maintain this many intro points per service if possible.
 */
#define NUM_INTRO_POINTS 3

/* Represents a single hidden service running at this OP.
 */
typedef struct rend_service_t {
  /* Fields specified in config file */
  char *directory; /* where in the filesystem it stores it */
  smartlist_t *ports;
  char *intro_prefer_nodes;
  char *intro_exclude_nodes;
  /* Other fields */
  crypto_pk_env_t *private_key;
  char service_id[REND_SERVICE_ID_LEN+1];
  char pk_digest[DIGEST_LEN];
  smartlist_t *intro_nodes; /* list of nicknames */
  rend_service_descriptor_t *desc;
} rend_service_t;

/* A list of rend_service_t's for services run on this OP.
 */
static smartlist_t *rend_service_list = NULL;

/* Release the storage held by 'service'.
 */
static void rend_service_free(rend_service_t *service)
{
  if (!service) return;
  tor_free(service->directory);
  SMARTLIST_FOREACH(service->ports, void*, p, tor_free(p));
  smartlist_free(service->ports);
  if (service->private_key)
    crypto_free_pk_env(service->private_key);
  tor_free(service->intro_prefer_nodes);
  tor_free(service->intro_exclude_nodes);
  SMARTLIST_FOREACH(service->intro_nodes, void*, p, tor_free(p));
  smartlist_free(service->intro_nodes);
  if (service->desc)
    rend_service_descriptor_free(service->desc);
  tor_free(service);
}

/* Release all the storage held in rend_service_list, and allocate a new,
 * empty rend_service_list.
 */
static void rend_service_free_all(void)
{
  if (!rend_service_list) {
    rend_service_list = smartlist_create();
    return;
  }
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, ptr,
                    rend_service_free(ptr));
  smartlist_free(rend_service_list);
  rend_service_list = smartlist_create();
}

/* Validate 'service' and add it to rend_service_list if possible.
 */
static void add_service(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;
  struct in_addr addr;

  if (!service->intro_prefer_nodes)
    service->intro_prefer_nodes = tor_strdup("");
  if (!service->intro_exclude_nodes)
    service->intro_exclude_nodes = tor_strdup("");

  if (!smartlist_len(service->ports)) {
    log_fn(LOG_WARN, "Hidden service with no ports configured; ignoring.");
    rend_service_free(service);
  } else {
    smartlist_set_capacity(service->ports, -1);
    smartlist_add(rend_service_list, service);
    log_fn(LOG_INFO,"Configuring service with directory %s",service->directory);
    for (i = 0; i < smartlist_len(service->ports); ++i) {
      p = smartlist_get(service->ports, i);
      addr.s_addr = htonl(p->real_address);
      log_fn(LOG_INFO,"Service maps port %d to %s:%d",
             p->virtual_port, inet_ntoa(addr), p->real_port);
    }
  }
}

/* Parses a real-port to virtual-port mapping and returns a new
 * rend_service_port_config_t.
 *
 * The format is: VirtualPort (IP|RealPort|IP:RealPort)?
 *    IP defaults to 127.0.0.1; RealPort defaults to VirtualPort.
 */
static rend_service_port_config_t *parse_port_config(const char *string)
{
  int virtport, realport, r;
  struct in_addr addr;
  char *endptr, *colon, *addrstring;
  rend_service_port_config_t *result;

  virtport = (int) strtol(string, &endptr, 10);
  if (endptr == string) {
    log_fn(LOG_WARN, "Missing port in hidden service port configuration");
    return NULL;
  }
  if (virtport < 1 || virtport > 65535) {
    log_fn(LOG_WARN, "Port out of range in hidden service port configuration");
    return NULL;
  }
  string = endptr + strspn(endptr, " \t");
  if (!*string) {
    /* No addr:port part; use default. */
    realport = virtport;
    addr.s_addr = htonl(0x7F000001u); /* 127.0.0.1 */
  } else {
    colon = strchr(string, ':');
    if (colon) {
      /* Try to parse addr:port. */
      addrstring = tor_strndup(string, colon-string);
      r = tor_inet_aton(addrstring, &addr);
      tor_free(addrstring);
      if (!r) {
        log_fn(LOG_WARN,"Unparseable address in hidden service port configuration");
        return NULL;
      }
      realport = strtol(colon+1, &endptr, 10);
      if (*endptr) {
        log_fn(LOG_WARN,"Unparseable or missing port in hidden service port configuration.");
        return NULL;
      }
    } else if (strchr(string, '.') && tor_inet_aton(string, &addr)) {
      /* We have addr; use deafult port. */
      realport = virtport;
    } else {
      /* No addr:port, no addr -- must be port. */
      realport = strtol(string, &endptr, 10);
      if (*endptr) {
        log_fn(LOG_WARN, "Unparseable of missing port in hidden service port configuration.");
        return NULL;
      }
      addr.s_addr = htonl(0x7F000001u); /* Default to 127.0.0.1 */
    }
  }
  if (realport < 1 || realport > 65535) {
    log_fn(LOG_WARN, "Port out of range in hidden service port configuration.");
    return NULL;
  }

  result = tor_malloc(sizeof(rend_service_port_config_t));
  result->virtual_port = virtport;
  result->real_port = realport;
  result->real_address = (uint32_t) ntohl(addr.s_addr);
  return result;
}

/* Set up rend_service_list, based on the values of HiddenServiceDir and
 * HiddenServicePort in 'options'.  Return 0 on success and -1 on
 * failure.
 */
int rend_config_services(or_options_t *options)
{
  struct config_line_t *line;
  rend_service_t *service = NULL;
  rend_service_port_config_t *portcfg;
  rend_service_free_all();

  for (line = options->RendConfigLines; line; line = line->next) {
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      if (service)
        add_service(service);
      service = tor_malloc_zero(sizeof(rend_service_t));
      service->directory = tor_strdup(line->value);
      service->ports = smartlist_create();
      service->intro_nodes = smartlist_create();
      continue;
    }
    if (!service) {
      log_fn(LOG_WARN, "HiddenServicePort with no preceeding HiddenServiceDir directive");
      rend_service_free(service);
      return -1;
    }
    if (!strcasecmp(line->key, "HiddenServicePort")) {
      portcfg = parse_port_config(line->value);
      if (!portcfg) {
        rend_service_free(service);
        return -1;
      }
      smartlist_add(service->ports, portcfg);
    } else if (!strcasecmp(line->key, "HiddenServiceNodes")) {
      if (service->intro_prefer_nodes) {
        log_fn(LOG_WARN, "Got multiple HiddenServiceNodes lines for a single service");
        return -1;
      }
      service->intro_prefer_nodes = tor_strdup(line->value);
    } else {
      assert(!strcasecmp(line->key, "HiddenServiceExcludeNodes"));
      if (service->intro_exclude_nodes) {
        log_fn(LOG_WARN, "Got multiple HiddenServiceExcludedNodes lines for a single service");
        return -1;
      }
      service->intro_exclude_nodes = tor_strdup(line->value);
    }
  }
  if (service)
    add_service(service);

  return 0;
}

/* Replace the old value of service->desc with one that reflects
 * the other fields in service.
 */
static void rend_service_update_descriptor(rend_service_t *service)
{
  rend_service_descriptor_t *d;
  int i,n;

  if (service->desc) {
    rend_service_descriptor_free(service->desc);
    service->desc = NULL;
  }
  d = service->desc = tor_malloc(sizeof(rend_service_descriptor_t));
  d->pk = crypto_pk_dup_key(service->private_key);
  d->timestamp = time(NULL);
  n = d->n_intro_points = smartlist_len(service->intro_nodes);
  d->intro_points = tor_malloc(sizeof(char*)*n);
  for (i=0; i < n; ++i) {
    d->intro_points[i] = tor_strdup(smartlist_get(service->intro_nodes, i));
  }
}

/* Load and/or generate private keys for all hidden services.  Return 0 on
 * success, -1 on failure.
 */
int rend_service_init_keys(void)
{
  int i;
  rend_service_t *s;
  char fname[512];
  char buf[128];

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    s = smartlist_get(rend_service_list,i);
    if (s->private_key)
      continue;
    log_fn(LOG_INFO, "Loading hidden-service keys from '%s'", s->directory);

    /* Check/create directory */
    if (check_private_dir(s->directory, 1) < 0)
      return -1;

    /* Load key */
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,"/private_key",sizeof(fname)) >= sizeof(fname)) {
      log_fn(LOG_WARN, "Directory name too long: '%s'", s->directory);
      return -1;
    }
    s->private_key = init_key_from_file(fname);
    if (!s->private_key)
      return -1;

    /* Create service file */
    if (rend_get_service_id(s->private_key, s->service_id)<0) {
      log_fn(LOG_WARN, "Couldn't encode service ID");
      return -1;
    }
    if (crypto_pk_get_digest(s->private_key, s->pk_digest)<0) {
      log_fn(LOG_WARN, "Couldn't compute hash of public key");
      return -1;
    }
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,"/hostname",sizeof(fname)) >= sizeof(fname)) {
      log_fn(LOG_WARN, "Directory name too long: '%s'", s->directory);
      return -1;
    }
    sprintf(buf, "%s.onion\n", s->service_id);
    if (write_str_to_file(fname,buf)<0)
      return -1;
  }
  return 0;
}

/* Return the service whose public key has a digest of 'digest'. Return
 * NULL if no such service exists.
 */
static rend_service_t *
rend_service_get_by_pk_digest(const char* digest)
{
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, s,
                    if (!memcmp(s->pk_digest,digest,DIGEST_LEN)) return s);
  return NULL;
}

/******
 * Handle cells
 ******/

/* Respond to an INTRODUCE2 cell by launching a circuit to the chosen
 * rendezvous points.
 */
int
rend_service_introduce(circuit_t *circuit, const char *request, int request_len)
{
  char *ptr, *rp_nickname, *r_cookie;
  char buf[RELAY_PAYLOAD_SIZE];
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN]; /* Holds KH, Df, Db, Kf, Kb */
  rend_service_t *service;
  int len, keylen;
  crypto_dh_env_t *dh = NULL;
  circuit_t *launched = NULL;
  crypt_path_t *cpath = NULL;
  char hexid[9];
  char hexcookie[9];

  hex_encode(circuit->rend_pk_digest, 4, hexid);

  log_fn(LOG_INFO, "Received INTRODUCE2 cell for service %s on circ %d",
         hexid, circuit->n_circ_id);

  if (circuit->purpose != CIRCUIT_PURPOSE_S_INTRO) {
    log_fn(LOG_WARN, "Got an INTRODUCE2 over a non-introduction circuit %d",
           circuit->n_circ_id);
    return -1;
  }

  /* min key length plus digest length plus nickname length */
  if (request_len < DIGEST_LEN+REND_COOKIE_LEN+(MAX_NICKNAME_LEN+1)+
      DH_KEY_LEN+42){
    log_fn(LOG_WARN, "Got a truncated INTRODUCE2 cell on circ %d",
           circuit->n_circ_id);
    return -1;
  }

  /* first DIGEST_LEN bytes of request is service pk digest */
  service = rend_service_get_by_pk_digest(request);
  if (!service) {
    log_fn(LOG_WARN, "Got an INTRODUCE2 cell for an unrecognized service %s",
           hexid);
    return -1;
  }
  if (memcmp(circuit->rend_pk_digest, request, DIGEST_LEN)) {
    hex_encode(request, 4, hexid);
    log_fn(LOG_WARN, "Got an INTRODUCE2 cell for the wrong service (%s)",
           hexid);
    return -1;
  }

  keylen = crypto_pk_keysize(service->private_key);
  if (request_len < keylen+DIGEST_LEN) {
    log_fn(LOG_WARN, "PK-encrypted portion of INTRODUCE2 cell was truncated");
    return -1;
  }
  /* Next N bytes is encrypted with service key */
  len = crypto_pk_private_hybrid_decrypt(
       service->private_key,request+DIGEST_LEN,request_len-DIGEST_LEN,buf,
       PK_PKCS1_OAEP_PADDING);
  if (len<0) {
    log_fn(LOG_WARN, "Couldn't decrypt INTRODUCE2 cell");
    return -1;
  }
  ptr=memchr(buf,0,MAX_NICKNAME_LEN+1);
  if (!ptr || ptr == buf) {
    log_fn(LOG_WARN, "Couldn't find a null-padded nickname in INTRODUCE2 cell");
    return -1;
  }
  if (strspn(buf,LEGAL_NICKNAME_CHARACTERS) != ptr-buf) {
    log_fn(LOG_WARN, "Nickname in INTRODUCE2 cell contains illegal character.");
    return -1;
  }
  /* Okay, now we know that the nickname is at the start of the buffer. */
  rp_nickname = buf;
  ptr = buf+(MAX_NICKNAME_LEN+1);
  len -= (MAX_NICKNAME_LEN+1);
  if (len != REND_COOKIE_LEN+DH_KEY_LEN) {
    log_fn(LOG_WARN, "Bad length for INTRODUCE2 cell.");
    return -1;
  }
  r_cookie = ptr;
  hex_encode(r_cookie,4,hexcookie);

  /* Try DH handshake... */
  dh = crypto_dh_new();
  if (!dh || crypto_dh_generate_public(dh)<0) {
    log_fn(LOG_WARN, "Couldn't build DH state or generate public key");
    goto err;
  }
  if (crypto_dh_compute_secret(dh, ptr+REND_COOKIE_LEN, DH_KEY_LEN, keys,
                               DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_fn(LOG_WARN, "Couldn't complete DH handshake");
    goto err;
  }

  /* Launch a circuit to alice's chosen rendezvous point.
   */
  launched = circuit_launch_new(CIRCUIT_PURPOSE_S_CONNECT_REND, rp_nickname);
  log_fn(LOG_INFO,
        "Accepted intro; launching circuit to '%s' (cookie %s) for service %s",
         rp_nickname, hexcookie, hexid);
  if (!launched) {
    log_fn(LOG_WARN,
           "Can't launch circuit to rendezvous point '%s' for service %s",
           rp_nickname, hexid);
    return -1;
  }
  assert(launched->build_state);
  /* Fill in the circuit's state. */
  memcpy(launched->rend_pk_digest, circuit->rend_pk_digest,
         DIGEST_LEN);
  memcpy(launched->rend_cookie, r_cookie, REND_COOKIE_LEN);
  launched->build_state->pending_final_cpath = cpath =
    tor_malloc_zero(sizeof(crypt_path_t));

  cpath->handshake_state = dh;
  dh = NULL;
  if (circuit_init_cpath_crypto(cpath,keys+DIGEST_LEN,1)<0)
    goto err;
  memcpy(cpath->handshake_digest, keys, DIGEST_LEN);

  return 0;
 err:
  if (dh) crypto_dh_free(dh);
  if (launched) circuit_mark_for_close(launched);
  return -1;
}

/* Launch a circuit to serve as an introduction point.
 */
static int
rend_service_launch_establish_intro(rend_service_t *service, char *nickname)
{
  circuit_t *launched;
  char hexid[9];

  assert(service && nickname);

  hex_encode(service->pk_digest, 4, hexid);
  log_fn(LOG_INFO, "Launching circuit to introduction point %s for service %s",
         nickname, hexid);

  launched = circuit_launch_new(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, nickname);
  if (!launched) {
    log_fn(LOG_WARN, "Can't launch circuit to establish introduction at '%s'",
           nickname);
    return -1;
  }
  memcpy(launched->rend_pk_digest, service->pk_digest, DIGEST_LEN);

  return 0;
}

/* Called when we're done building a circuit to an introduction point:
 *  sends a RELAY_ESTABLISH_INTRO cell.
 */
void
rend_service_intro_is_ready(circuit_t *circuit)
{
  rend_service_t *service;
  int len, r;
  char buf[RELAY_PAYLOAD_SIZE];
  char auth[DIGEST_LEN + 9];
  char hexid[9];

  assert(circuit->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);
  assert(circuit->cpath);

  hex_encode(circuit->rend_pk_digest, 4, hexid);
  service = rend_service_get_by_pk_digest(circuit->rend_pk_digest);
  if (!service) {
    log_fn(LOG_WARN, "Unrecognized service ID %s on introduction circuit %d",
           hexid, circuit->n_circ_id);
    goto err;
  }

  log_fn(LOG_INFO,
         "Established circuit %d as introduction point for service %s",
         circuit->n_circ_id, hexid);

  /* Build the payload for a RELAY_ESTABLISH_INTRO cell. */
  len = crypto_pk_asn1_encode(service->private_key, buf+2,
                              RELAY_PAYLOAD_SIZE-2);
  set_uint16(buf, len);
  len += 2;
  memcpy(auth, circuit->cpath->prev->handshake_digest, DIGEST_LEN);
  memcpy(auth+DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_digest(auth, DIGEST_LEN+9, buf+len))
    goto err;
  len += 20;
  r = crypto_pk_private_sign_digest(service->private_key, buf, len, buf+len);
  if (r<0) {
    log_fn(LOG_WARN, "Couldn't sign introduction request");
    goto err;
  }
  len += r;

  if (connection_edge_send_command(NULL, circuit,RELAY_COMMAND_ESTABLISH_INTRO,
                                   buf, len, circuit->cpath->prev)<0) {
    log_fn(LOG_WARN,
           "Couldn't send introduction request for service %s on circuit %d",
           hexid, circuit->n_circ_id);
    goto err;
  }

  return;
 err:
  circuit_mark_for_close(circuit);
}

/* Handle an intro_established cell. */
int
rend_service_intro_established(circuit_t *circuit, const char *request, int request_len)
{
  if (circuit->purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_fn(LOG_WARN, "received INTRO_ESTABLISHED cell on non-intro circuit");
    goto err;
  }
  circuit->purpose = CIRCUIT_PURPOSE_S_INTRO;

  return 0;
 err:
  circuit_mark_for_close(circuit);
  return -1;
}

/* Called once a circuit to a rendezvous point is ready: sends a
 *  RELAY_COMMAND_RENDEZVOUS1 cell.
 */
void
rend_service_rendezvous_is_ready(circuit_t *circuit)
{
  rend_service_t *service;
  char buf[RELAY_PAYLOAD_SIZE];
  crypt_path_t *hop;
  char hexid[9];
  char hexcookie[9];

  assert(circuit->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);
  assert(circuit->cpath);
  assert(circuit->build_state);
  hop = circuit->build_state->pending_final_cpath;
  assert(hop);

  hex_encode(circuit->rend_pk_digest, 4, hexid);
  hex_encode(circuit->rend_cookie, 4, hexcookie);

  log_fn(LOG_INFO,
       "Done building circuit %d to rendezvous with cookie %s for service %s",
         circuit->n_circ_id, hexcookie, hexid);

  service = rend_service_get_by_pk_digest(circuit->rend_pk_digest);
  if (!service) {
    log_fn(LOG_WARN, "Internal error: unrecognized service ID on introduction circuit");
    goto err;
  }

  /* All we need to do is send a RELAY_RENDEZVOUS1 cell... */
  memcpy(buf, circuit->rend_cookie, REND_COOKIE_LEN);
  if (crypto_dh_get_public(hop->handshake_state,
                           buf+REND_COOKIE_LEN, DH_KEY_LEN)<0) {
    log_fn(LOG_WARN,"Couldn't get DH public key");
    goto err;
  }
  memcpy(buf+REND_COOKIE_LEN+DH_KEY_LEN, hop->handshake_digest,
         DIGEST_LEN);

  /* Send the cell */
  if (connection_edge_send_command(NULL, circuit, RELAY_COMMAND_RENDEZVOUS1,
                                   buf, REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN,
                                   circuit->cpath->prev)<0) {
    log_fn(LOG_WARN, "Couldn't send RENDEZVOUS1 cell");
    goto err;
  }

  crypto_dh_free(hop->handshake_state);
  hop->handshake_state = NULL;

  /* Append the cpath entry. */
  hop->state = CPATH_STATE_OPEN;
  /* set the windows to default. these are the windows
   * that bob thinks alice has.
   */
  hop->package_window = CIRCWINDOW_START;
  hop->deliver_window = CIRCWINDOW_START;

  onion_append_to_cpath(&circuit->cpath, hop);
  circuit->build_state->pending_final_cpath = NULL; /* prevent double-free */

  /* Change the circuit purpose. */
  circuit->purpose = CIRCUIT_PURPOSE_S_REND_JOINED;

  return;
 err:
  circuit_mark_for_close(circuit);
}

/******
 * Manage introduction points
 ******/

/* Return the introduction circuit ending at 'router' for the service
 * whose public key is 'pk_digest'.  Return NULL if no such service is
 * found.
 */
static circuit_t *
find_intro_circuit(routerinfo_t *router, const char *pk_digest)
{
  circuit_t *circ = NULL;

  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                                  CIRCUIT_PURPOSE_S_INTRO))) {
    assert(circ->cpath);
    if (circ->cpath->prev->addr == router->addr &&
        circ->cpath->prev->port == router->or_port) {
      return circ;
    }
  }

  circ = NULL;
  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                        CIRCUIT_PURPOSE_S_ESTABLISH_INTRO))) {
    assert(circ->cpath);
    if (circ->cpath->prev->addr == router->addr &&
        circ->cpath->prev->port == router->or_port) {
      return circ;
    }
  }
  return NULL;
}

/* XXXX Make this longer once directories remember service descriptors across
 * restarts.*/
#define MAX_SERVICE_PUBLICATION_INTERVAL (15*60)

/* For every service, check how many intro points it currently has, and:
 *  - Pick new intro points as necessary.
 *  - Launch circuits to any new intro points.
 *  - Upload a fresh service descriptor if anything has changed.
 */
int rend_services_init(void) {
  int i,j,r;
  routerinfo_t *router;
  routerlist_t *rl;
  rend_service_t *service;
  char *desc, *intro;
  int changed, prev_intro_nodes, desc_len;
  smartlist_t *intro_routers, *exclude_routers;
  int n_old_routers;
  time_t now;

  router_get_routerlist(&rl);
  intro_routers = smartlist_create();
  exclude_routers = smartlist_create();
  router_add_nonrendezvous_to_list(exclude_routers);
  n_old_routers = smartlist_len(exclude_routers);

  for (i=0; i< smartlist_len(rend_service_list); ++i) {
    smartlist_clear(intro_routers);
    service = smartlist_get(rend_service_list, i);

    assert(service);
    changed = 0;

    /* Find out which introduction points we really have for this service. */
    for (j=0;j< smartlist_len(service->intro_nodes); ++j) {
      router = router_get_by_nickname(smartlist_get(service->intro_nodes,j));
      if (!router || !find_intro_circuit(router,service->pk_digest)) {
        smartlist_del(service->intro_nodes,j--);
        changed = 1;
      }
      smartlist_add(intro_routers, router);
    }

    /* We have enough intro points, and the intro points we thought we had were
     * all connected.
     */
    if (!changed && smartlist_len(service->intro_nodes) >= NUM_INTRO_POINTS)
      continue;

    /* Remember how many introduction circuits we started with. */
    prev_intro_nodes = smartlist_len(service->intro_nodes);

    smartlist_add_all(exclude_routers, intro_routers);
    /* The directory is now here. Pick three ORs as intro points. */
    for (j=prev_intro_nodes; j < NUM_INTRO_POINTS; ++j) {
      router = router_choose_random_node(rl,
                                         service->intro_prefer_nodes,
                                         service->intro_exclude_nodes,
                                         exclude_routers);
      if (!router) {
        log_fn(LOG_WARN, "Could only establish %d introduction points",
               smartlist_len(service->intro_nodes));
        break;
      }
      changed = 1;
      smartlist_add(intro_routers, router);
      smartlist_add(exclude_routers, router);
      smartlist_add(service->intro_nodes, tor_strdup(router->nickname));
    }

    /* Reset exclude_routers to include obsolete routers only for the next
     * time around the loop. */
    smartlist_truncate(exclude_routers, n_old_routers);

    /* If there's no need to republish, stop here. */
    now = time(NULL);
    if (!changed &&
        service->desc->timestamp+MAX_SERVICE_PUBLICATION_INTERVAL >= now)
      continue;

    /* Update the descriptor. */
    rend_service_update_descriptor(service);
    if (rend_encode_service_descriptor(service->desc,
                                       service->private_key,
                                       &desc, &desc_len)<0) {
      log_fn(LOG_WARN, "Couldn't encode service descriptor; not uploading");
      continue;
    }

    /* Post it to the dirservers */
    router_post_to_dirservers(DIR_PURPOSE_UPLOAD_RENDDESC, desc, desc_len);
    tor_free(desc);

    /* Establish new introduction points. */
    for (j=prev_intro_nodes; j < smartlist_len(service->intro_nodes); ++j) {
      intro = smartlist_get(service->intro_nodes, j);
      r = rend_service_launch_establish_intro(service, intro);
      if (r<0) {
        log_fn(LOG_WARN, "Error launching circuit to node %s", intro);
      }
    }
  }
  smartlist_free(intro_routers);
  smartlist_free(exclude_routers);

  return 0;
}

/* This is a beginning rendezvous stream. Look up conn->port,
 * and assign the actual conn->addr and conn->port. Return -1
 * if failure, or 0 for success.
 */
int
rend_service_set_connection_addr_port(connection_t *conn, circuit_t *circ)
{
  rend_service_t *service;
  int i;
  rend_service_port_config_t *p;
  char hexid[9];

  assert(circ->purpose == CIRCUIT_PURPOSE_S_REND_JOINED);
  hex_encode(circ->rend_pk_digest, 4, hexid);
  service = rend_service_get_by_pk_digest(circ->rend_pk_digest);
  if (!service) {
    log_fn(LOG_WARN, "Couldn't find any service associated with pk %s on rendezvous circuit %d; closing",
           hexid, circ->n_circ_id);
    circuit_mark_for_close(circ);
    connection_mark_for_close(conn, 0/*XXX*/);
  }
  for (i = 0; i < smartlist_len(service->ports); ++i) {
    p = smartlist_get(service->ports, i);
    if (conn->port == p->virtual_port) {
      conn->addr = p->real_address;
      conn->port = p->real_port;
      return 0;
    }
  }
  log_fn(LOG_WARN, "No virtual port mapping exists for port %d on service %s",
         conn->port, hexid);
  connection_mark_for_close(conn, 0/*XXX*/);
  return -1;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
