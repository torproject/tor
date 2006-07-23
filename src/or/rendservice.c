/* Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rendservice_c_id[] =
  "$Id$";

/**
 * \file rendservice.c
 * \brief The hidden-service side of rendezvous functionality.
 **/

#include "or.h"

static origin_circuit_t *find_intro_circuit(routerinfo_t *router,
                                            const char *pk_digest);

/** Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struct rend_service_port_config_t {
  uint16_t virtual_port;
  uint16_t real_port;
  uint32_t real_addr;
} rend_service_port_config_t;

/** Try to maintain this many intro points per service if possible. */
#define NUM_INTRO_POINTS 3

/** If we can't build our intro circuits, don't retry for this long. */
#define INTRO_CIRC_RETRY_PERIOD (60*5)
/** Don't try to build more than this many circuits before giving up
 * for a while.*/
#define MAX_INTRO_CIRCS_PER_PERIOD 10
/** How many times will a hidden service operator attempt to connect to
 * a requested rendezvous point before giving up? */
#define MAX_REND_FAILURES 30
/** How many seconds should we spend trying to connect to a requested
 * rendezvous point before giving up? */
#define MAX_REND_TIMEOUT 30

/** Represents a single hidden service running at this OP. */
typedef struct rend_service_t {
  /** Fields specified in config file */
  char *directory; /**< where in the filesystem it stores it */
  smartlist_t *ports; /**< List of rend_service_port_config_t */
  char *intro_prefer_nodes; /**< comma-separated list of nicknames */
  char *intro_exclude_nodes; /**< comma-separated list of nicknames */
  /* Other fields */
  crypto_pk_env_t *private_key;
  char service_id[REND_SERVICE_ID_LEN+1];
  char pk_digest[DIGEST_LEN];
  smartlist_t *intro_nodes; /**< list of hexdigests for intro points we have,
                             * or are trying to establish. */
  time_t intro_period_started;
  int n_intro_circuits_launched; /**< count of intro circuits we have
                                  * established in this period. */
  rend_service_descriptor_t *desc;
  time_t desc_is_dirty;
  time_t next_upload_time;
} rend_service_t;

/** A list of rend_service_t's for services run on this OP.
 */
static smartlist_t *rend_service_list = NULL;

/** Return the number of rendezvous services we have configured. */
int
num_rend_services(void)
{
  if (!rend_service_list)
    return 0;
  return smartlist_len(rend_service_list);
}

/** Release the storage held by <b>service</b>.
 */
static void
rend_service_free(rend_service_t *service)
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

/** Release all the storage held in rend_service_list.
 */
void
rend_service_free_all(void)
{
  if (!rend_service_list) {
    return;
  }
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, ptr,
                    rend_service_free(ptr));
  smartlist_free(rend_service_list);
  rend_service_list = NULL;
}

/** Validate <b>service</b> and add it to rend_service_list if possible.
 */
static void
add_service(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;
  struct in_addr addr;

  if (!service->intro_prefer_nodes)
    service->intro_prefer_nodes = tor_strdup("");
  if (!service->intro_exclude_nodes)
    service->intro_exclude_nodes = tor_strdup("");

  if (!smartlist_len(service->ports)) {
    log_warn(LD_CONFIG, "Hidden service with no ports configured; ignoring.");
    rend_service_free(service);
  } else {
    smartlist_set_capacity(service->ports, -1);
    smartlist_add(rend_service_list, service);
    log_debug(LD_REND,"Configuring service with directory \"%s\"",
              service->directory);
    for (i = 0; i < smartlist_len(service->ports); ++i) {
      char addrbuf[INET_NTOA_BUF_LEN];
      p = smartlist_get(service->ports, i);
      addr.s_addr = htonl(p->real_addr);
      tor_inet_ntoa(&addr, addrbuf, sizeof(addrbuf));
      log_debug(LD_REND,"Service maps port %d to %s:%d",
                p->virtual_port, addrbuf, p->real_port);
    }
  }
}

/** Parses a real-port to virtual-port mapping and returns a new
 * rend_service_port_config_t.
 *
 * The format is: VirtualPort (IP|RealPort|IP:RealPort)?
 *
 * IP defaults to 127.0.0.1; RealPort defaults to VirtualPort.
 */
static rend_service_port_config_t *
parse_port_config(const char *string)
{
  smartlist_t *sl;
  int virtport;
  int realport;
  uint16_t p;
  uint32_t addr;
  const char *addrport;
  rend_service_port_config_t *result = NULL;

  sl = smartlist_create();
  smartlist_split_string(sl, string, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(sl) < 1 || smartlist_len(sl) > 2) {
    log_warn(LD_CONFIG, "Bad syntax in hidden service port configuration.");
    goto err;
  }

  virtport = atoi(smartlist_get(sl,0));
  if (virtport < 1 || virtport > 65535) {
    log_warn(LD_CONFIG, "Missing or invalid port in hidden service port "
             "configuration.");
    goto err;
  }

  if (smartlist_len(sl) == 1) {
    /* No addr:port part; use default. */
    realport = virtport;
    addr = 0x7F000001u; /* 127.0.0.1 */
  } else {
    addrport = smartlist_get(sl,1);
    if (strchr(addrport, ':') || strchr(addrport, '.')) {
      if (parse_addr_port(LOG_WARN, addrport, NULL, &addr, &p)<0) {
        log_warn(LD_CONFIG,"Unparseable address in hidden service port "
                 "configuration.");
        goto err;
      }
      realport = p?p:virtport;
    } else {
      /* No addr:port, no addr -- must be port. */
      realport = atoi(addrport);
      if (realport < 1 || realport > 65535)
        goto err;
      addr = 0x7F000001u; /* Default to 127.0.0.1 */
    }
  }

  result = tor_malloc(sizeof(rend_service_port_config_t));
  result->virtual_port = virtport;
  result->real_port = realport;
  result->real_addr = addr;
 err:
  SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
  smartlist_free(sl);
  return result;
}

/** Set up rend_service_list, based on the values of HiddenServiceDir and
 * HiddenServicePort in <b>options</b>.  Return 0 on success and -1 on
 * failure.  (If <b>validate_only</b> is set, parse, warn and return as
 * normal, but don't actually change the configured services.)
 */
int
rend_config_services(or_options_t *options, int validate_only)
{
  config_line_t *line;
  rend_service_t *service = NULL;
  rend_service_port_config_t *portcfg;

  if (!validate_only) {
    rend_service_free_all();
    rend_service_list = smartlist_create();
  }

  for (line = options->RendConfigLines; line; line = line->next) {
    if (!strcasecmp(line->key, "HiddenServiceDir")) {
      if (service) {
        if (validate_only)
          rend_service_free(service);
        else
          add_service(service);
      }
      service = tor_malloc_zero(sizeof(rend_service_t));
      service->directory = tor_strdup(line->value);
      service->ports = smartlist_create();
      service->intro_nodes = smartlist_create();
      service->intro_period_started = time(NULL);
      continue;
    }
    if (!service) {
      log_warn(LD_CONFIG, "%s with no preceding HiddenServiceDir directive",
               line->key);
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
        log_warn(LD_CONFIG,
                 "Got multiple HiddenServiceNodes lines for a single "
                 "service.");
        return -1;
      }
      service->intro_prefer_nodes = tor_strdup(line->value);
    } else {
      tor_assert(!strcasecmp(line->key, "HiddenServiceExcludeNodes"));
      if (service->intro_exclude_nodes) {
        log_warn(LD_CONFIG,
                 "Got multiple HiddenServiceExcludedNodes lines for "
                 "a single service.");
        return -1;
      }
      service->intro_exclude_nodes = tor_strdup(line->value);
    }
  }
  if (service) {
    if (validate_only)
      rend_service_free(service);
    else
      add_service(service);
  }

  return 0;
}

/** Replace the old value of <b>service</b>-\>desc with one that reflects
 * the other fields in service.
 */
static void
rend_service_update_descriptor(rend_service_t *service)
{
  rend_service_descriptor_t *d;
  origin_circuit_t *circ;
  int i,n;
  routerinfo_t *router;

  if (service->desc) {
    rend_service_descriptor_free(service->desc);
    service->desc = NULL;
  }
  d = service->desc = tor_malloc(sizeof(rend_service_descriptor_t));
  d->pk = crypto_pk_dup_key(service->private_key);
  d->timestamp = time(NULL);
  d->version = 1;
  n = smartlist_len(service->intro_nodes);
  d->n_intro_points = 0;
  d->intro_points = tor_malloc_zero(sizeof(char*)*n);
  d->intro_point_extend_info = tor_malloc_zero(sizeof(extend_info_t*)*n);
  d->protocols = (1<<2) | (1<<0); /* We support protocol 2 and protocol 0. */
  for (i=0; i < n; ++i) {
    router = router_get_by_nickname(smartlist_get(service->intro_nodes, i),1);
    if (!router) {
      log_info(LD_REND,"Router '%s' not found. Skipping.",
               (char*)smartlist_get(service->intro_nodes, i));
      continue;
    }
    circ = find_intro_circuit(router, service->pk_digest);
    if (circ && circ->_base.purpose == CIRCUIT_PURPOSE_S_INTRO) {
      /* We have an entirely established intro circuit. */
      d->intro_points[d->n_intro_points] = tor_strdup(router->nickname);
      d->intro_point_extend_info[d->n_intro_points] =
        extend_info_from_router(router);
      d->n_intro_points++;
    }
  }
}

/** Load and/or generate private keys for all hidden services.  Return 0 on
 * success, -1 on failure.
 */
int
rend_service_load_keys(void)
{
  int i;
  rend_service_t *s;
  char fname[512];
  char buf[128];

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    s = smartlist_get(rend_service_list,i);
    if (s->private_key)
      continue;
    log_info(LD_REND, "Loading hidden-service keys from \"%s\"",
             s->directory);

    /* Check/create directory */
    if (check_private_dir(s->directory, CPD_CREATE) < 0)
      return -1;

    /* Load key */
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,"/private_key",sizeof(fname)) >= sizeof(fname)) {
      log_warn(LD_CONFIG, "Directory name too long: \"%s\".", s->directory);
      return -1;
    }
    s->private_key = init_key_from_file(fname);
    if (!s->private_key)
      return -1;

    /* Create service file */
    if (rend_get_service_id(s->private_key, s->service_id)<0) {
      log_warn(LD_BUG, "Internal error: couldn't encode service ID.");
      return -1;
    }
    if (crypto_pk_get_digest(s->private_key, s->pk_digest)<0) {
      log_warn(LD_BUG, "Bug: Couldn't compute hash of public key.");
      return -1;
    }
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,"/hostname",sizeof(fname)) >= sizeof(fname)) {
      log_warn(LD_CONFIG, "Directory name too long: \"%s\".", s->directory);
      return -1;
    }
    tor_snprintf(buf, sizeof(buf),"%s.onion\n", s->service_id);
    if (write_str_to_file(fname,buf,0)<0)
      return -1;
  }
  return 0;
}

/** Return the service whose public key has a digest of <b>digest</b>. Return
 * NULL if no such service exists.
 */
static rend_service_t *
rend_service_get_by_pk_digest(const char* digest)
{
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, s,
                    if (!memcmp(s->pk_digest,digest,DIGEST_LEN)) return s);
  return NULL;
}

/** Return 1 if any virtual port in <b>service</b> wants a circuit
 * to have good uptime. Else return 0.
 */
static int
rend_service_requires_uptime(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;

  for (i=0; i < smartlist_len(service->ports); ++i) {
    p = smartlist_get(service->ports, i);
    if (smartlist_string_num_isin(get_options()->LongLivedPorts,
                                  p->virtual_port))
      return 1;
  }
  return 0;
}

/******
 * Handle cells
 ******/

/** Respond to an INTRODUCE2 cell by launching a circuit to the chosen
 * rendezvous point.
 */
int
rend_service_introduce(origin_circuit_t *circuit, const char *request,
                       size_t request_len)
{
  char *ptr, *r_cookie;
  extend_info_t *extend_info = NULL;
  char buf[RELAY_PAYLOAD_SIZE];
  char keys[DIGEST_LEN+CPATH_KEY_MATERIAL_LEN]; /* Holds KH, Df, Db, Kf, Kb */
  rend_service_t *service;
  int r, i;
  size_t len, keylen;
  crypto_dh_env_t *dh = NULL;
  origin_circuit_t *launched = NULL;
  crypt_path_t *cpath = NULL;
  char serviceid[REND_SERVICE_ID_LEN+1];
  char hexcookie[9];
  int circ_needs_uptime;

  base32_encode(serviceid, REND_SERVICE_ID_LEN+1,
                circuit->_base.rend_pk_digest,10);
  log_info(LD_REND, "Received INTRODUCE2 cell for service %s on circ %d.",
           escaped(serviceid), circuit->_base.n_circ_id);

  if (circuit->_base.purpose != CIRCUIT_PURPOSE_S_INTRO) {
    log_warn(LD_PROTOCOL,
             "Got an INTRODUCE2 over a non-introduction circuit %d.",
             circuit->_base.n_circ_id);
    return -1;
  }

  /* min key length plus digest length plus nickname length */
  if (request_len < DIGEST_LEN+REND_COOKIE_LEN+(MAX_NICKNAME_LEN+1)+
      DH_KEY_LEN+42) {
    log_warn(LD_PROTOCOL, "Got a truncated INTRODUCE2 cell on circ %d.",
             circuit->_base.n_circ_id);
    return -1;
  }

  /* first DIGEST_LEN bytes of request is service pk digest */
  service = rend_service_get_by_pk_digest(request);
  if (!service) {
    log_warn(LD_REND, "Got an INTRODUCE2 cell for an unrecognized service %s.",
             escaped(serviceid));
    return -1;
  }
  if (memcmp(circuit->_base.rend_pk_digest, request, DIGEST_LEN)) {
    base32_encode(serviceid, REND_SERVICE_ID_LEN+1, request, 10);
    log_warn(LD_REND, "Got an INTRODUCE2 cell for the wrong service (%s).",
             escaped(serviceid));
    return -1;
  }

  keylen = crypto_pk_keysize(service->private_key);
  if (request_len < keylen+DIGEST_LEN) {
    log_warn(LD_PROTOCOL,
             "PK-encrypted portion of INTRODUCE2 cell was truncated.");
    return -1;
  }
  /* Next N bytes is encrypted with service key */
  r = crypto_pk_private_hybrid_decrypt(
       service->private_key,buf,request+DIGEST_LEN,request_len-DIGEST_LEN,
       PK_PKCS1_OAEP_PADDING,1);
  if (r<0) {
    log_warn(LD_PROTOCOL, "Couldn't decrypt INTRODUCE2 cell.");
    return -1;
  }
  len = r;
  if (*buf == 2) {
    /* Version 2 INTRODUCE2 cell. */
    int klen;
    extend_info = tor_malloc_zero(sizeof(extend_info_t));
    extend_info->addr = ntohl(get_uint32(buf+1));
    extend_info->port = ntohs(get_uint16(buf+5));
    memcpy(extend_info->identity_digest, buf+7, DIGEST_LEN);
    extend_info->nickname[0] = '$';
    base16_encode(extend_info->nickname+1, sizeof(extend_info->nickname)-1,
                  extend_info->identity_digest, DIGEST_LEN);

    klen = ntohs(get_uint16(buf+7+DIGEST_LEN));
    if ((int)len != 7+DIGEST_LEN+2+klen+20+128) {
      log_warn(LD_PROTOCOL, "Bad length %u for version 2 INTRODUCE2 cell.",
               (int)len);
      goto err;
    }
    extend_info->onion_key = crypto_pk_asn1_decode(buf+7+DIGEST_LEN+2, klen);
    if (!extend_info->onion_key) {
      log_warn(LD_PROTOCOL,
               "Error decoding onion key in version 2 INTRODUCE2 cell.");
      goto err;
    }
    ptr = buf+7+DIGEST_LEN+2+klen;
    len -= 7+DIGEST_LEN+2+klen;
  } else {
    char *rp_nickname;
    size_t nickname_field_len;
    routerinfo_t *router;
    int version;
    if (*buf == 1) {
      rp_nickname = buf+1;
      nickname_field_len = MAX_HEX_NICKNAME_LEN+1;
      version = 1;
    } else {
      nickname_field_len = MAX_NICKNAME_LEN+1;
      rp_nickname = buf;
      version = 0;
    }
    ptr=memchr(rp_nickname,0,nickname_field_len);
    if (!ptr || ptr == rp_nickname) {
      log_warn(LD_PROTOCOL,
               "Couldn't find a nul-padded nickname in INTRODUCE2 cell.");
      return -1;
    }
    if ((version == 0 && !is_legal_nickname(rp_nickname)) ||
        (version == 1 && !is_legal_nickname_or_hexdigest(rp_nickname))) {
      log_warn(LD_PROTOCOL, "Bad nickname in INTRODUCE2 cell.");
      return -1;
    }
    /* Okay, now we know that a nickname is at the start of the buffer. */
    ptr = rp_nickname+nickname_field_len;
    len -= nickname_field_len;
    len -= rp_nickname - buf; /* also remove header space used by version, if
                               * any */
    router = router_get_by_nickname(rp_nickname, 0);
    if (!router) {
      log_info(LD_REND, "Couldn't find router %s named in rendezvous cell.",
               escaped(rp_nickname));
      goto err;
    }

    extend_info = extend_info_from_router(router);
  }

  if (len != REND_COOKIE_LEN+DH_KEY_LEN) {
    log_warn(LD_PROTOCOL, "Bad length %u for INTRODUCE2 cell.", (int)len);
    return -1;
  }

  r_cookie = ptr;
  base16_encode(hexcookie,9,r_cookie,4);

  /* Try DH handshake... */
  dh = crypto_dh_new();
  if (!dh || crypto_dh_generate_public(dh)<0) {
    log_warn(LD_BUG,"Internal error: couldn't build DH state "
             "or generate public key.");
    goto err;
  }
  if (crypto_dh_compute_secret(dh, ptr+REND_COOKIE_LEN, DH_KEY_LEN, keys,
                               DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_warn(LD_BUG, "Internal error: couldn't complete DH handshake");
    goto err;
  }

  circ_needs_uptime = rend_service_requires_uptime(service);

  /* help predict this next time */
  rep_hist_note_used_internal(time(NULL), circ_needs_uptime, 1);

  /* Launch a circuit to alice's chosen rendezvous point.
   */
  for (i=0;i<MAX_REND_FAILURES;i++) {
    launched = circuit_launch_by_extend_info(
          CIRCUIT_PURPOSE_S_CONNECT_REND, extend_info,
          circ_needs_uptime, 1, 1);

    if (launched)
      break;
  }
  if (!launched) { /* give up */
    log_warn(LD_REND, "Giving up launching first hop of circuit to rendezvous "
             "point '%s' for service %s.",
             extend_info->nickname, serviceid);
    goto err;
  }
  log_info(LD_REND,
           "Accepted intro; launching circuit to '%s' "
           "(cookie %s) for service %s.",
           extend_info->nickname, hexcookie, serviceid);
  tor_assert(launched->build_state);
  /* Fill in the circuit's state. */
  memcpy(launched->_base.rend_pk_digest, circuit->_base.rend_pk_digest,
         DIGEST_LEN);
  memcpy(launched->_base.rend_cookie, r_cookie, REND_COOKIE_LEN);
  strlcpy(launched->_base.rend_query, service->service_id,
          sizeof(launched->_base.rend_query));
  launched->build_state->pending_final_cpath = cpath =
    tor_malloc_zero(sizeof(crypt_path_t));
  cpath->magic = CRYPT_PATH_MAGIC;
  launched->build_state->expiry_time = time(NULL) + MAX_REND_TIMEOUT;

  cpath->dh_handshake_state = dh;
  dh = NULL;
  if (circuit_init_cpath_crypto(cpath,keys+DIGEST_LEN,1)<0)
    goto err;
  memcpy(cpath->handshake_digest, keys, DIGEST_LEN);
  if (extend_info) extend_info_free(extend_info);

  return 0;
 err:
  if (dh) crypto_dh_free(dh);
  if (launched)
    circuit_mark_for_close(TO_CIRCUIT(launched), END_CIRC_AT_ORIGIN);
  if (extend_info) extend_info_free(extend_info);
  return -1;
}

/** Called when we fail building a rendezvous circuit at some point other
 * than the last hop: launches a new circuit to the same rendezvous point.
 */
void
rend_service_relaunch_rendezvous(origin_circuit_t *oldcirc)
{
  origin_circuit_t *newcirc;
  cpath_build_state_t *newstate, *oldstate;

  tor_assert(oldcirc->_base.purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);

  if (!oldcirc->build_state ||
      oldcirc->build_state->failure_count > MAX_REND_FAILURES ||
      oldcirc->build_state->expiry_time < time(NULL)) {
    log_info(LD_REND,
             "Attempt to build circuit to %s for rendezvous has failed "
             "too many times or expired; giving up.",
             oldcirc->build_state ?
               oldcirc->build_state->chosen_exit->nickname : "*unknown*");
    return;
  }

  oldstate = oldcirc->build_state;
  tor_assert(oldstate);

  if (oldstate->pending_final_cpath == NULL) {
    log_info(LD_REND,"Skipping relaunch of circ that failed on its first hop. "
             "Initiator will retry.");
    return;
  }

  log_info(LD_REND,"Reattempting rendezvous circuit to '%s'",
           oldstate->chosen_exit->nickname);

  newcirc = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_CONNECT_REND,
                               oldstate->chosen_exit, 0, 1, 1);
  if (!newcirc) {
    log_warn(LD_REND,"Couldn't relaunch rendezvous circuit to '%s'.",
             oldstate->chosen_exit->nickname);
    return;
  }
  newstate = newcirc->build_state;
  tor_assert(newstate);
  newstate->failure_count = oldstate->failure_count+1;
  newstate->expiry_time = oldstate->expiry_time;
  newstate->pending_final_cpath = oldstate->pending_final_cpath;
  oldstate->pending_final_cpath = NULL;

  memcpy(newcirc->_base.rend_query, oldcirc->_base.rend_query,
         REND_SERVICE_ID_LEN+1);
  memcpy(newcirc->_base.rend_pk_digest, oldcirc->_base.rend_pk_digest,
         DIGEST_LEN);
  memcpy(newcirc->_base.rend_cookie, oldcirc->_base.rend_cookie,
         REND_COOKIE_LEN);
}

/** Launch a circuit to serve as an introduction point for the service
 * <b>service</b> at the introduction point <b>nickname</b>
 */
static int
rend_service_launch_establish_intro(rend_service_t *service,
                                    const char *nickname)
{
  origin_circuit_t *launched;

  log_info(LD_REND,
           "Launching circuit to introduction point %s for service %s",
           nickname, service->service_id);

  rep_hist_note_used_internal(time(NULL), 1, 0);

  ++service->n_intro_circuits_launched;
  launched = circuit_launch_by_nickname(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                                        nickname, 1, 0, 1);
  if (!launched) {
    log_info(LD_REND,
             "Can't launch circuit to establish introduction at '%s'.",
             nickname);
    return -1;
  }
  strlcpy(launched->_base.rend_query, service->service_id,
          sizeof(launched->_base.rend_query));
  memcpy(launched->_base.rend_pk_digest, service->pk_digest, DIGEST_LEN);

  if (launched->_base.state == CIRCUIT_STATE_OPEN)
    rend_service_intro_has_opened(launched);
  return 0;
}

/** Called when we're done building a circuit to an introduction point:
 *  sends a RELAY_ESTABLISH_INTRO cell.
 */
void
rend_service_intro_has_opened(origin_circuit_t *circuit)
{
  rend_service_t *service;
  size_t len;
  int r;
  char buf[RELAY_PAYLOAD_SIZE];
  char auth[DIGEST_LEN + 9];
  char serviceid[REND_SERVICE_ID_LEN+1];

  tor_assert(circuit->_base.purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);
  tor_assert(circuit->cpath);

  base32_encode(serviceid, REND_SERVICE_ID_LEN+1,
                circuit->_base.rend_pk_digest,10);

  service = rend_service_get_by_pk_digest(circuit->_base.rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Unrecognized service ID %s on introduction circuit %d.",
             serviceid, circuit->_base.n_circ_id);
    goto err;
  }

  log_info(LD_REND,
           "Established circuit %d as introduction point for service %s",
           circuit->_base.n_circ_id, serviceid);

  /* Build the payload for a RELAY_ESTABLISH_INTRO cell. */
  len = crypto_pk_asn1_encode(service->private_key, buf+2,
                              RELAY_PAYLOAD_SIZE-2);
  set_uint16(buf, htons((uint16_t)len));
  len += 2;
  memcpy(auth, circuit->cpath->prev->handshake_digest, DIGEST_LEN);
  memcpy(auth+DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_digest(buf+len, auth, DIGEST_LEN+9))
    goto err;
  len += 20;
  r = crypto_pk_private_sign_digest(service->private_key, buf+len, buf, len);
  if (r<0) {
    log_warn(LD_BUG, "Internal error: couldn't sign introduction request.");
    goto err;
  }
  len += r;

  if (connection_edge_send_command(NULL, TO_CIRCUIT(circuit),
                                   RELAY_COMMAND_ESTABLISH_INTRO,
                                   buf, len, circuit->cpath->prev)<0) {
    log_info(LD_GENERAL,
             "Couldn't send introduction request for service %s on circuit %d",
             serviceid, circuit->_base.n_circ_id);
    goto err;
  }

  return;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_AT_ORIGIN);
}

/** Called when we get an INTRO_ESTABLISHED cell; mark the circuit as a
 * live introduction point, and note that the service descriptor is
 * now out-of-date.*/
int
rend_service_intro_established(origin_circuit_t *circuit, const char *request,
                               size_t request_len)
{
  rend_service_t *service;
  (void) request;
  (void) request_len;

  if (circuit->_base.purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_warn(LD_PROTOCOL,
             "received INTRO_ESTABLISHED cell on non-intro circuit.");
    goto err;
  }
  service = rend_service_get_by_pk_digest(circuit->_base.rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Unknown service on introduction circuit %d.",
             circuit->_base.n_circ_id);
    goto err;
  }
  service->desc_is_dirty = time(NULL);
  circuit->_base.purpose = CIRCUIT_PURPOSE_S_INTRO;

  return 0;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_AT_ORIGIN);
  return -1;
}

/** Called once a circuit to a rendezvous point is established: sends a
 *  RELAY_COMMAND_RENDEZVOUS1 cell.
 */
void
rend_service_rendezvous_has_opened(origin_circuit_t *circuit)
{
  rend_service_t *service;
  char buf[RELAY_PAYLOAD_SIZE];
  crypt_path_t *hop;
  char serviceid[REND_SERVICE_ID_LEN+1];
  char hexcookie[9];

  tor_assert(circuit->_base.purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);
  tor_assert(circuit->cpath);
  tor_assert(circuit->build_state);
  hop = circuit->build_state->pending_final_cpath;
  tor_assert(hop);

  base16_encode(hexcookie,9,circuit->_base.rend_cookie,4);
  base32_encode(serviceid, REND_SERVICE_ID_LEN+1,
                circuit->_base.rend_pk_digest,10);

  log_info(LD_REND,
           "Done building circuit %d to rendezvous with "
           "cookie %s for service %s",
           circuit->_base.n_circ_id, hexcookie, serviceid);

  service = rend_service_get_by_pk_digest(circuit->_base.rend_pk_digest);
  if (!service) {
    log_warn(LD_GENERAL, "Internal error: unrecognized service ID on "
             "introduction circuit.");
    goto err;
  }

  /* All we need to do is send a RELAY_RENDEZVOUS1 cell... */
  memcpy(buf, circuit->_base.rend_cookie, REND_COOKIE_LEN);
  if (crypto_dh_get_public(hop->dh_handshake_state,
                           buf+REND_COOKIE_LEN, DH_KEY_LEN)<0) {
    log_warn(LD_GENERAL,"Couldn't get DH public key.");
    goto err;
  }
  memcpy(buf+REND_COOKIE_LEN+DH_KEY_LEN, hop->handshake_digest,
         DIGEST_LEN);

  /* Send the cell */
  if (connection_edge_send_command(NULL, TO_CIRCUIT(circuit),
                                   RELAY_COMMAND_RENDEZVOUS1,
                                   buf, REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN,
                                   circuit->cpath->prev)<0) {
    log_warn(LD_GENERAL, "Couldn't send RENDEZVOUS1 cell.");
    goto err;
  }

  crypto_dh_free(hop->dh_handshake_state);
  hop->dh_handshake_state = NULL;

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
  circuit->_base.purpose = CIRCUIT_PURPOSE_S_REND_JOINED;

  return;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_AT_ORIGIN);
}

/*
 * Manage introduction points
 */

/** Return the (possibly non-open) introduction circuit ending at
 * <b>router</b> for the service whose public key is <b>pk_digest</b>.  Return
 * NULL if no such service is found.
 */
static origin_circuit_t *
find_intro_circuit(routerinfo_t *router, const char *pk_digest)
{
  circuit_t *circ = NULL;
  cpath_build_state_t *build_state = NULL;

  tor_assert(router);
  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                                  CIRCUIT_PURPOSE_S_INTRO))) {
    tor_assert(CIRCUIT_IS_ORIGIN(circ));
    build_state = TO_ORIGIN_CIRCUIT(circ)->build_state;
    if (!strcasecmp(build_state->chosen_exit->nickname,
                    router->nickname)) {
      return TO_ORIGIN_CIRCUIT(circ);
    }
  }

  circ = NULL;
  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                        CIRCUIT_PURPOSE_S_ESTABLISH_INTRO))) {
    tor_assert(CIRCUIT_IS_ORIGIN(circ));
    build_state = TO_ORIGIN_CIRCUIT(circ)->build_state;
    if (!strcasecmp(build_state->chosen_exit->nickname,
                    router->nickname)) {
      return TO_ORIGIN_CIRCUIT(circ);
    }
  }
  return NULL;
}

/** Encode and sign an up-to-date service descriptor for <b>service</b>,
 * and upload it to all the dirservers.
 */
static void
upload_service_descriptor(rend_service_t *service, int version)
{
  char *desc;
  size_t desc_len;

  /* Update the descriptor. */
  rend_service_update_descriptor(service);
  if (rend_encode_service_descriptor(service->desc,
                                     version,
                                     service->private_key,
                                     &desc, &desc_len)<0) {
    log_warn(LD_BUG, "Internal error: couldn't encode service descriptor; "
             "not uploading.");
    return;
  }

  /* Post it to the dirservers */
  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_RENDDESC, desc, desc_len);
  tor_free(desc);

  service->desc_is_dirty = 0;
}

/** For every service, check how many intro points it currently has, and:
 *  - Pick new intro points as necessary.
 *  - Launch circuits to any new intro points.
 */
void
rend_services_introduce(void)
{
  int i,j,r;
  routerinfo_t *router;
  rend_service_t *service;
  char *intro;
  int changed, prev_intro_nodes;
  smartlist_t *intro_routers, *exclude_routers;
  time_t now;

  intro_routers = smartlist_create();
  exclude_routers = smartlist_create();
  now = time(NULL);

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    smartlist_clear(intro_routers);
    service = smartlist_get(rend_service_list, i);

    tor_assert(service);
    changed = 0;
    if (now > service->intro_period_started+INTRO_CIRC_RETRY_PERIOD) {
      /* One period has elapsed; we can try building circuits again. */
      service->intro_period_started = now;
      service->n_intro_circuits_launched = 0;
    } else if (service->n_intro_circuits_launched >=
               MAX_INTRO_CIRCS_PER_PERIOD) {
      /* We have failed too many times in this period; wait for the next
       * one before we try again. */
      continue;
    }

    /* Find out which introduction points we have in progress for this
       service. */
    for (j=0; j < smartlist_len(service->intro_nodes); ++j) {
      intro = smartlist_get(service->intro_nodes, j);
      router = router_get_by_nickname(intro, 0);
      if (!router || !find_intro_circuit(router,service->pk_digest)) {
        log_info(LD_REND,"Giving up on %s as intro point for %s.",
                 intro, service->service_id);
        tor_free(intro);
        smartlist_del(service->intro_nodes,j--);
        changed = 1;
        service->desc_is_dirty = now;
      }
      smartlist_add(intro_routers, router);
    }

    /* We have enough intro points, and the intro points we thought we had were
     * all connected.
     */
    if (!changed && smartlist_len(service->intro_nodes) >= NUM_INTRO_POINTS) {
      /* We have all our intro points! Start a fresh period and reset the
       * circuit count. */
      service->intro_period_started = now;
      service->n_intro_circuits_launched = 0;
      continue;
    }

    /* Remember how many introduction circuits we started with. */
    prev_intro_nodes = smartlist_len(service->intro_nodes);

    smartlist_add_all(exclude_routers, intro_routers);
    /* The directory is now here. Pick three ORs as intro points. */
    for (j=prev_intro_nodes; j < NUM_INTRO_POINTS; ++j) {
      char *hex_digest;
      router = router_choose_random_node(service->intro_prefer_nodes,
               service->intro_exclude_nodes, exclude_routers, 1, 0, 0,
               get_options()->_AllowInvalid & ALLOW_INVALID_INTRODUCTION,
               0);
      if (!router) {
        log_warn(LD_REND,
                 "Could only establish %d introduction points for %s.",
                 smartlist_len(service->intro_nodes), service->service_id);
        break;
      }
      changed = 1;
      hex_digest = tor_malloc_zero(HEX_DIGEST_LEN+2);
      hex_digest[0] = '$';
      base16_encode(hex_digest+1, HEX_DIGEST_LEN+1,
                    router->cache_info.identity_digest,
                    DIGEST_LEN);
      smartlist_add(intro_routers, router);
      smartlist_add(exclude_routers, router);
      smartlist_add(service->intro_nodes, hex_digest);
      log_info(LD_REND, "Picked router %s as an intro point for %s.",
               router->nickname, service->service_id);
    }

    /* Reset exclude_routers, for the next time around the loop. */
    smartlist_clear(exclude_routers);

    /* If there's no need to launch new circuits, stop here. */
    if (!changed)
      continue;

    /* Establish new introduction points. */
    for (j=prev_intro_nodes; j < smartlist_len(service->intro_nodes); ++j) {
      intro = smartlist_get(service->intro_nodes, j);
      r = rend_service_launch_establish_intro(service, intro);
      if (r<0) {
        log_warn(LD_REND, "Error launching circuit to node %s for service %s.",
                 intro, service->service_id);
      }
    }
  }
  smartlist_free(intro_routers);
  smartlist_free(exclude_routers);
}

/** Regenerate and upload rendezvous service descriptors for all
 * services, if necessary. If the descriptor has been dirty enough
 * for long enough, definitely upload; else only upload when the
 * periodic timeout has expired.
 *
 * For the first upload, pick a random time between now and two periods
 * from now, and pick it independently for each service.
 */
void
rend_consider_services_upload(time_t now)
{
  int i;
  rend_service_t *service;
  int rendpostperiod = get_options()->RendPostPeriod;

  if (!get_options()->PublishHidServDescriptors)
    return;

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    service = smartlist_get(rend_service_list, i);
    if (!service->next_upload_time) { /* never been uploaded yet */
      service->next_upload_time =
        now + crypto_rand_int(2*rendpostperiod);
    }
    if (service->next_upload_time < now ||
        (service->desc_is_dirty &&
         service->desc_is_dirty < now-5)) {
      /* if it's time, or if the directory servers have a wrong service
       * descriptor and ours has been stable for 5 seconds, upload a
       * new one of each format. */
      upload_service_descriptor(service, 0);
      service->next_upload_time = now + rendpostperiod;
    }
  }
}

/** Log the status of introduction points for all rendezvous services
 * at log severity <b>severity</b>.
 */
void
rend_service_dump_stats(int severity)
{
  int i,j;
  routerinfo_t *router;
  rend_service_t *service;
  char *nickname;
  origin_circuit_t *circ;

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    service = smartlist_get(rend_service_list, i);
    log(severity, LD_GENERAL, "Service configured in \"%s\":",
        service->directory);
    for (j=0; j < smartlist_len(service->intro_nodes); ++j) {
      nickname = smartlist_get(service->intro_nodes, j);
      router = router_get_by_nickname(smartlist_get(service->intro_nodes,j),1);
      if (!router) {
        log(severity, LD_GENERAL, "  Intro point at %s: unrecognized router",
            nickname);
        continue;
      }
      circ = find_intro_circuit(router, service->pk_digest);
      if (!circ) {
        log(severity, LD_GENERAL, "  Intro point at %s: no circuit",nickname);
        continue;
      }
      log(severity, LD_GENERAL, "  Intro point at %s: circuit is %s",nickname,
          circuit_state_to_string(circ->_base.state));
    }
  }
}

/** Given <b>conn</b>, a rendezvous exit stream, look up the hidden service for
 * 'circ', and look up the port and address based on conn-\>port.
 * Assign the actual conn-\>addr and conn-\>port. Return -1 if failure,
 * or 0 for success.
 */
int
rend_service_set_connection_addr_port(connection_t *conn,
                                      origin_circuit_t *circ)
{
  rend_service_t *service;
  int i;
  rend_service_port_config_t *p;
  char serviceid[REND_SERVICE_ID_LEN+1];

  tor_assert(circ->_base.purpose == CIRCUIT_PURPOSE_S_REND_JOINED);
  log_debug(LD_REND,"beginning to hunt for addr/port");
  base32_encode(serviceid, REND_SERVICE_ID_LEN+1,
                circ->_base.rend_pk_digest,10);
  service = rend_service_get_by_pk_digest(circ->_base.rend_pk_digest);
  if (!service) {
    log_warn(LD_REND, "Couldn't find any service associated with pk %s on "
             "rendezvous circuit %d; closing.",
             serviceid, circ->_base.n_circ_id);
    return -1;
  }
  for (i = 0; i < smartlist_len(service->ports); ++i) {
    p = smartlist_get(service->ports, i);
    if (conn->port == p->virtual_port) {
      conn->addr = p->real_addr;
      conn->port = p->real_port;
      return 0;
    }
  }
  log_info(LD_REND, "No virtual port mapping exists for port %d on service %s",
           conn->port,serviceid);
  return -1;
}

