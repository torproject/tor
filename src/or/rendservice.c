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

/* Represents a single hidden service running at this OP.
 */
typedef struct rend_service_t {
  /* Fields specified in config file */
  char *directory; /* where in the filesystem it stores it */
  smartlist_t *ports;
  char *intro_nodes;
  char *intro_exclude_nodes;
  /* Other fields */
  crypto_pk_env_t *private_key;
  char service_id[REND_SERVICE_ID_LEN+1];
  char pk_digest[20];
} rend_service_t;

/* A list of rend_service_t.
 */
static smartlist_t *rend_service_list = NULL;

static void rend_service_free(rend_service_t *config)
{
  int i;
  if (!config) return;
  tor_free(config->directory);
  for (i=0; i<config->ports->num_used; ++i) {
    tor_free(config->ports->list[i]);
  }
  smartlist_free(config->ports);
  if (config->private_key)
    crypto_free_pk_env(config->private_key);
}

static void rend_service_free_all(void)
{
  int i;
  if (!rend_service_list) {
    rend_service_list = smartlist_create();
    return;
  }
  for (i=0; i < rend_service_list->num_used; ++i) {
    rend_service_free(rend_service_list->list[i]);
  }
  smartlist_free(rend_service_list);
  rend_service_list = smartlist_create();
}

static void add_service(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;
  struct in_addr addr;

  if (!service->ports->num_used) {
    log_fn(LOG_WARN, "Hidden service with no ports configured; ignoring.");
    rend_service_free(service);
  } else {
    smartlist_set_capacity(service->ports, service->ports->num_used);
    smartlist_add(rend_service_list, service);
    log_fn(LOG_INFO,"Configuring service with directory %s",service->directory);
    for (i = 0; i < service->ports->num_used; ++i) {
      p = (rend_service_port_config_t *) service->ports->list[i];
      addr.s_addr = htonl(p->real_address);
      log_fn(LOG_INFO,"Service maps port %d to %s:%d",
	     p->virtual_port, inet_ntoa(addr), p->real_port);
    }
  }
}

/* Format: VirtualPort (IP|RealPort|IP:RealPort)?
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
    addr.s_addr = htonl(0x7F000001u);
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
      if (service->intro_nodes) {
        log_fn(LOG_WARN, "Got multiple HiddenServiceNodes lines for a single service");
        return -1;
      }
      service->intro_nodes = tor_strdup(line->value);
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

/* Load and/or generate private keys for all hidden services.  Return 0 on
 * success, -1 on failure.
 */
int rend_service_init_keys(void)
{
  int i;
  rend_service_t *s;
  char fname[512];
  char buf[128];

  for (i=0; i < rend_service_list->num_used; ++i) {
    s = (rend_service_t*) rend_service_list->list[i];
    if (s->private_key)
      continue;
    /* Check/create directory */
    if (check_private_dir(s->directory, 1) < 0)
      return -1;

    /* Load key */
    if (strlcpy(fname,s->directory,512) >= 512 ||
	strlcat(fname,"/private_key",512) >= 512) {
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
    if (strlcpy(fname,s->directory,512) >= 512 ||
	strlcat(fname,"/hostname",512) >= 512) {
      log_fn(LOG_WARN, "Directory name too long: '%s'", s->directory);
      return -1;
    }
    sprintf(buf, "%s.onion\n", s->service_id);
    if (write_str_to_file(fname,buf)<0)
      return -1;
  }
  return 0;
}

static rend_service_t *
rend_service_get_by_pk_digest(const char* digest)
{
  int i;
  rend_service_t *s;
  for (i = 0; i < rend_service_list->num_used; ++i) {
    s = (rend_service_t*)rend_service_list->list[i];
    if (!memcmp(s->pk_digest, digest, 20))
      return s;
  }
  return NULL;
}

/******
 * Handle cells
 ******/

/* Respond to an INTRODUCE2 cell by launching a circuit to the chosen
 * rendezvous points.
 */
int
rend_service_introduce(circuit_t *circuit, char *request, int request_len)
{
  char *ptr, *rp_nickname, *r_cookie;
  char buf[RELAY_PAYLOAD_SIZE];
  char keys[20+CPATH_KEY_MATERIAL_LEN]; /* Holds KH, Df, Db, Kf, Kb */
  rend_service_t *service;
  int len, keylen;
  crypto_dh_env_t *dh = NULL;
  circuit_t *launched = NULL;
  crypt_path_t *cpath = NULL;

  if (circuit->purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_fn(LOG_WARN, "Got an INTRODUCE2 over a non-introduction circuit.");
    return -1;
  }

  /* min key length plus digest length */
  if (request_len < 148) {
    log_fn(LOG_WARN, "Got a truncated INTRODUCE2 cell.");
    return -1;
  }

  /* first 20 bytes of request is service pk digest */
  service = rend_service_get_by_pk_digest(request);
  if (!service) {
    log_fn(LOG_WARN, "Got an INTRODUCE2 cell for an unrecognized service");
    return -1;
  }
  if (!memcmp(circuit->rend_service, request, 20)) {
    log_fn(LOG_WARN, "Got an INTRODUCE2 cell for the wrong service");
    return -1;
  }

  keylen = crypto_pk_keysize(service->private_key);
  if (request_len < keylen+20) {
    log_fn(LOG_WARN, "PK-encrypted portion of INTRODUCE2 cell was truncated");
    return -1;
  }
  /* Next N bytes is encrypted with service key */
  len = crypto_pk_private_hybrid_decrypt(
       service->private_key,request,request_len-20,buf, RSA_PKCS1_PADDING);
  if (len<0) {
    log_fn(LOG_WARN, "Couldn't decrypt INTRODUCE2 cell");
    return -1;
  }
  ptr=memchr(buf,0,len);
  if (!ptr || ptr == buf) {
    log_fn(LOG_WARN, "Couldn't find a null-terminated nickname in INTRODUCE2 cell");
    return -1;
  }
  if (strspn(buf,LEGAL_NICKNAME_CHARACTERS) != ptr-buf) {
    log_fn(LOG_WARN, "Nickname in INTRODUCE2 cell contains illegal character.");
    return -1;
  }
  /* Okay, now we know that the nickname is at the start of the buffer. */
  rp_nickname = buf;
  ++ptr;
  len -= (ptr-buf);
  if (len != 20+128) {
    log_fn(LOG_WARN, "Bad length for INTRODUCE2 cell.");
    return -1;
  }
  r_cookie = ptr;

  /* Try DH handshake... */
  dh = crypto_dh_new();
  if (!dh || crypto_dh_generate_public(dh)<0) {
    log_fn(LOG_WARN, "Couldn't build DH state or generate public key");
    goto err;
  }
  if (crypto_dh_compute_secret(dh, ptr+20, DH_KEY_LEN, keys,
                               20+CPATH_KEY_MATERIAL_LEN)<0) {
    log_fn(LOG_WARN, "Couldn't complete DH handshake");
    goto err;
  }

  /* Launch a circuit to alice's chosen rendezvous point.
   */
  launched = circuit_launch_new(CIRCUIT_PURPOSE_S_CONNECT_REND, rp_nickname);
  if (!launched) {
    log_fn(LOG_WARN, "Can't launch circuit to rendezvous point '%s'",
           rp_nickname);
    return -1;
  }
  assert(launched->build_state);
  /* Fill in the circuit's state. */
  memcpy(launched->rend_service, circuit->rend_service,CRYPTO_SHA1_DIGEST_LEN);
  memcpy(launched->rend_cookie, r_cookie, REND_COOKIE_LEN);
  launched->build_state->pending_final_cpath = cpath =
    tor_malloc_zero(sizeof(crypt_path_t));

  cpath->handshake_state = dh;
  dh = NULL;
  if (circuit_init_cpath_crypto(cpath,keys+20)<0)
    goto err;
  memcpy(cpath->handshake_digest, keys, 20);

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

  assert(service && nickname);

  launched = circuit_launch_new(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO, nickname);
  if (!launched) {
    log_fn(LOG_WARN, "Can't launch circuit to establish introduction at '%s'",
           nickname);
    return -1;
  }
  memcpy(launched->rend_service, service->pk_digest, CRYPTO_SHA1_DIGEST_LEN);

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
  char auth[CRYPTO_SHA1_DIGEST_LEN + 10];

  assert(circuit->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);
  assert(circuit->cpath);
  service = rend_service_get_by_pk_digest(circuit->rend_service);
  if (!service) {
    log_fn(LOG_WARN, "Internal error: unrecognized service ID on introduction circuit");
    goto err;
  }

  /* Build the payload for a RELAY_ESTABLISH_INTRO cell. */
  len = crypto_pk_asn1_encode(service->private_key, buf+2,
                              RELAY_PAYLOAD_SIZE-2);
  set_uint16(buf, len);
  len += 2;
  memcpy(auth, circuit->cpath->prev->handshake_digest, CRYPTO_SHA1_DIGEST_LEN);
  memcpy(auth+CRYPTO_SHA1_DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_SHA_digest(auth, CRYPTO_SHA1_DIGEST_LEN+9, buf+len))
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
    log_fn(LOG_WARN, "Couldn't send introduction request");
    goto err;
  }

  return;
 err:
  circuit_mark_for_close(circuit);
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

  assert(circuit->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);
  assert(circuit->cpath);
  assert(circuit->build_state);
  hop = circuit->build_state->pending_final_cpath;
  assert(hop);

  service = rend_service_get_by_pk_digest(circuit->rend_service);
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
         CRYPTO_SHA1_DIGEST_LEN);

  /* Send the cell */
  if (connection_edge_send_command(NULL, circuit, RELAY_COMMAND_RENDEZVOUS1,
                                   buf, REND_COOKIE_LEN+DH_KEY_LEN+1,
                                   circuit->cpath->prev)<0) {
    log_fn(LOG_WARN, "Couldn't send RENDEZVOUS1 cell");
    goto err;
  }

  /* Append the cpath entry. */
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

#define NUM_INTRO_POINTS 3
int rend_services_init(void) {
  int i,j,r;
  routerinfo_t *router;
  routerlist_t *rl;
  rend_service_t *service;

  router_get_routerlist(&rl);

  for (i=0;i<rend_service_list->num_used;++i) {
    service = rend_service_list->list[i];

    /* The directory is now here. Pick three ORs as intro points. */
    for (j=0;j<rl->n_routers;j++) {
      router = rl->routers[j];
      //...
      // maybe built a smartlist of all of them, then pick at random
      // until you have three? or something smarter.
    }

    /* build a service descriptor out of them, and tuck it away
     * somewhere so we don't lose it */

    /* post it to the dirservers */
    //call router_post_to_dirservers(DIR_PURPOSE_UPLOAD_HIDSERV, desc, desc_len);

    // for each intro point,
    {
      //r = rend_service_launch_establish_intro(service, intro->nickname);
      //if (r<0) freak out
    }

    // anything else?
  }
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
