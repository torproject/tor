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
  char *directory;
  smartlist_t *ports;
  /* Other fields */
  crypto_pk_env_t *private_key;
  char service_id[REND_SERVICE_ID_LEN+1];
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
    } else {
      assert(!strcasecmp(line->key, "HiddenServicePort"));
      if (!service) {
	log_fn(LOG_WARN, "HiddenServicePort with no preceeding HiddenServiceDir directive");
	rend_service_free(service);
	return -1;
      }
      portcfg = parse_port_config(line->value);
      if (!portcfg) {
	rend_service_free(service);
	return -1;
      }
      smartlist_add(service->ports, portcfg);
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
