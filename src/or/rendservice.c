/* Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id$ */
const char rendservice_c_id[] =
  "$Id$";

/**
 * \file rendservice.c
 * \brief The hidden-service side of rendezvous functionality.
 **/

#include "or.h"

static origin_circuit_t *find_intro_circuit(rend_intro_point_t *intro,
                                            const char *pk_digest,
                                            int desc_version);

/** Represents the mapping from a virtual port of a rendezvous service to
 * a real port on some IP.
 */
typedef struct rend_service_port_config_t {
  uint16_t virtual_port;
  uint16_t real_port;
  tor_addr_t real_addr;
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

/** DOCDOC */
typedef enum rend_auth_type_t {
  REND_NO_AUTH      = 0,
  REND_BASIC_AUTH   = 1,
  REND_STEALTH_AUTH = 2,
} rend_auth_type_t;

/** Represents a single hidden service running at this OP. */
typedef struct rend_service_t {
  /* Fields specified in config file */
  char *directory; /**< where in the filesystem it stores it */
  smartlist_t *ports; /**< List of rend_service_port_config_t */
  int descriptor_version; /**< Rendezvous descriptor version that will be
                           * published. */
  rend_auth_type_t auth_type; /**< Client authorization type or 0 if no client
                               * authorization is performed. */
  smartlist_t *clients; /**< List of rend_authorized_client_t's of
                         * clients that may access our service. */
  /* Other fields */
  crypto_pk_env_t *private_key; /**< Permanent hidden-service key. */
  char service_id[REND_SERVICE_ID_LEN_BASE32+1]; /**< Onion address without
                                                  * '.onion' */
  char pk_digest[DIGEST_LEN]; /**< Hash of permanent hidden-service key. */
  smartlist_t *intro_nodes; /**< List of rend_intro_point_t's we have,
                             * or are trying to establish. */
  time_t intro_period_started; /**< Start of the current period to build
                                * introduction points. */
  int n_intro_circuits_launched; /**< count of intro circuits we have
                                  * established in this period. */
  rend_service_descriptor_t *desc; /**< Current hidden service descriptor. */
  time_t desc_is_dirty; /**< Time at which changes to the hidden service
                         * descriptor content occurred, or 0 if it's
                         * up-to-date. */
  time_t next_upload_time; /**< Scheduled next hidden service descriptor
                            * upload time. */
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

/** Helper: free storage held by a single service authorized client entry. */
static void
rend_authorized_client_free(rend_authorized_client_t *client)
{
  if (!client) return;
  if (client->client_key)
    crypto_free_pk_env(client->client_key);
  tor_free(client->client_name);
  tor_free(client);
}

/** Helper for strmap_free. */
static void
rend_authorized_client_strmap_item_free(void *authorized_client)
{
  rend_authorized_client_free(authorized_client);
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
  if (service->intro_nodes) {
    SMARTLIST_FOREACH(service->intro_nodes, rend_intro_point_t *, intro,
      rend_intro_point_free(intro););
    smartlist_free(service->intro_nodes);
  }
  if (service->desc)
    rend_service_descriptor_free(service->desc);
  if (service->clients) {
    SMARTLIST_FOREACH(service->clients, rend_authorized_client_t *, c,
      rend_authorized_client_free(c););
    smartlist_free(service->clients);
  }
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
rend_add_service(rend_service_t *service)
{
  int i;
  rend_service_port_config_t *p;

  service->intro_nodes = smartlist_create();

  /* If the service is configured to publish unversioned (v0) and versioned
   * descriptors (v2 or higher), split it up into two separate services
   * (unless it is configured to perform client authorization). */
  if (service->descriptor_version == -1) {
    if (service->auth_type == REND_NO_AUTH) {
      rend_service_t *v0_service = tor_malloc_zero(sizeof(rend_service_t));
      v0_service->directory = tor_strdup(service->directory);
      v0_service->ports = smartlist_create();
      SMARTLIST_FOREACH(service->ports, rend_service_port_config_t *, p, {
        rend_service_port_config_t *copy =
          tor_malloc_zero(sizeof(rend_service_port_config_t));
        memcpy(copy, p, sizeof(rend_service_port_config_t));
        smartlist_add(v0_service->ports, copy);
      });
      v0_service->intro_period_started = service->intro_period_started;
      v0_service->descriptor_version = 0; /* Unversioned descriptor. */
      v0_service->auth_type = REND_NO_AUTH;
      rend_add_service(v0_service);
    }

    service->descriptor_version = 2; /* Versioned descriptor. */
  }

  if (service->auth_type && !service->descriptor_version) {
    log_warn(LD_CONFIG, "Hidden service with client authorization and "
                        "version 0 descriptors configured; ignoring.");
    rend_service_free(service);
    return;
  }

  if (service->auth_type && smartlist_len(service->clients) == 0) {
    log_warn(LD_CONFIG, "Hidden service with client authorization but no "
                        "clients; ignoring.");
    rend_service_free(service);
    return;
  }

  if (!smartlist_len(service->ports)) {
    log_warn(LD_CONFIG, "Hidden service with no ports configured; ignoring.");
    rend_service_free(service);
  } else {
    smartlist_add(rend_service_list, service);
    log_debug(LD_REND,"Configuring service with directory \"%s\"",
              service->directory);
    for (i = 0; i < smartlist_len(service->ports); ++i) {
      p = smartlist_get(service->ports, i);
      log_debug(LD_REND,"Service maps port %d to %s:%d",
                p->virtual_port, fmt_addr(&p->real_addr), p->real_port);
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
  tor_addr_t addr;
  const char *addrport;
  rend_service_port_config_t *result = NULL;

  sl = smartlist_create();
  smartlist_split_string(sl, string, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(sl) < 1 || smartlist_len(sl) > 2) {
    log_warn(LD_CONFIG, "Bad syntax in hidden service port configuration.");
    goto err;
  }

  virtport = (int)tor_parse_long(smartlist_get(sl,0), 10, 1, 65535, NULL,NULL);
  if (!virtport) {
    log_warn(LD_CONFIG, "Missing or invalid port %s in hidden service port "
             "configuration", escaped(smartlist_get(sl,0)));
    goto err;
  }

  if (smartlist_len(sl) == 1) {
    /* No addr:port part; use default. */
    realport = virtport;
    tor_addr_from_ipv4h(&addr, 0x7F000001u); /* 127.0.0.1 */
  } else {
    addrport = smartlist_get(sl,1);
    if (strchr(addrport, ':') || strchr(addrport, '.')) {
      if (tor_addr_port_parse(addrport, &addr, &p)<0) {
        log_warn(LD_CONFIG,"Unparseable address in hidden service port "
                 "configuration.");
        goto err;
      }
      realport = p?p:virtport;
    } else {
      /* No addr:port, no addr -- must be port. */
      realport = (int)tor_parse_long(addrport, 10, 1, 65535, NULL, NULL);
      if (!realport) {
        log_warn(LD_CONFIG,"Unparseable or out-of-range port %s in hidden "
                 "service port configuration.", escaped(addrport));
        goto err;
      }
      tor_addr_from_ipv4h(&addr, 0x7F000001u); /* Default to 127.0.0.1 */
    }
  }

  result = tor_malloc(sizeof(rend_service_port_config_t));
  result->virtual_port = virtport;
  result->real_port = realport;
  tor_addr_copy(&result->real_addr, &addr);
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
          rend_add_service(service);
      }
      service = tor_malloc_zero(sizeof(rend_service_t));
      service->directory = tor_strdup(line->value);
      service->ports = smartlist_create();
      service->intro_period_started = time(NULL);
      service->descriptor_version = -1; /**< All descriptor versions. */
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
    } else if (!strcasecmp(line->key, "HiddenServiceAuthorizeClient")) {
      /* Parse auth type and comma-separated list of client names and add a
       * rend_authorized_client_t for each client to the service's list
       * of authorized clients. */
      smartlist_t *type_names_split, *clients;
      const char *authname;
      if (service->auth_type) {
        log_warn(LD_CONFIG, "Got multiple HiddenServiceAuthorizeClient "
                 "lines for a single service.");
        rend_service_free(service);
        return -1;
      }
      type_names_split = smartlist_create();
      smartlist_split_string(type_names_split, line->value, " ", 0, 0);
      if (smartlist_len(type_names_split) < 1) {
        log_warn(LD_BUG, "HiddenServiceAuthorizeClient has no value. This "
                         "should have been prevented when parsing the "
                         "configuration.");
        smartlist_free(type_names_split);
        rend_service_free(service);
        return -1;
      }
      authname = smartlist_get(type_names_split, 0);
      if (!strcasecmp(authname, "basic") || !strcmp(authname, "1")) {
        service->auth_type = REND_BASIC_AUTH;
      } else if (!strcasecmp(authname, "stealth") || !strcmp(authname, "2")) {
        service->auth_type = REND_STEALTH_AUTH;
      } else {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains "
                 "unrecognized auth-type '%s'. Only 1 or 2 are recognized.",
                 (char *) smartlist_get(type_names_split, 0));
        SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
        smartlist_free(type_names_split);
        rend_service_free(service);
        return -1;
      }
      service->clients = smartlist_create();
      if (smartlist_len(type_names_split) < 2) {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains "
                            "authorization type %d, but no client names.",
                 service->auth_type);
        SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
        smartlist_free(type_names_split);
        continue;
      }
      if (smartlist_len(type_names_split) > 2) {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains "
                            "illegal value '%s'. Must be formatted "
                            "as 'HiddenServiceAuthorizeClient auth-type "
                            "client-name,client-name,...' (without "
                            "additional spaces in comma-separated client "
                            "list).",
                 line->value);
        SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
        smartlist_free(type_names_split);
        rend_service_free(service);
        return -1;
      }
      clients = smartlist_create();
      smartlist_split_string(clients, smartlist_get(type_names_split, 1),
                             ",", 0, 0);
      SMARTLIST_FOREACH(type_names_split, char *, cp, tor_free(cp));
      smartlist_free(type_names_split);
      SMARTLIST_FOREACH_BEGIN(clients, const char *, client_name)
      {
        rend_authorized_client_t *client;
        size_t len = strlen(client_name);
        int found_duplicate = 0;
        /* XXXX proposal 121 Why 19?  Also, this should be a constant. */
        if (len < 1 || len > 19) {
          log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains an "
                              "illegal client name: '%s'. Length must be "
                              "between 1 and 19 characters.",
                   client_name);
          SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
          smartlist_free(clients);
          rend_service_free(service);
          return -1;
        }
        if (strspn(client_name, REND_LEGAL_CLIENTNAME_CHARACTERS) != len) {
          log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains an "
                              "illegal client name: '%s'. Valid "
                              "characters are [A-Za-z0-9+-_].",
                   client_name);
          SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
          smartlist_free(clients);
          rend_service_free(service);
          return -1;
        }
        /* Check if client name is duplicate. */
        /*XXXX proposal 121 This is O(N^2).  That's not so good. */
        SMARTLIST_FOREACH(service->clients, rend_authorized_client_t *, c, {
          if (!strcmp(c->client_name, client_name)) {
            log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains a "
                     "duplicate client name: '%s'; ignoring.", client_name);
            found_duplicate = 1;
            break;
          }
        });
        if (found_duplicate)
          continue;
        client = tor_malloc_zero(sizeof(rend_authorized_client_t));
        client->client_name = tor_strdup(client_name);
        smartlist_add(service->clients, client);
        log_debug(LD_REND, "Adding client name '%s'", client_name);
      }
      SMARTLIST_FOREACH_END(client_name);
      SMARTLIST_FOREACH(clients, char *, cp, tor_free(cp));
      smartlist_free(clients);
      /* Ensure maximum number of clients. */
      if ((service->auth_type == REND_BASIC_AUTH &&
            smartlist_len(service->clients) > 512) ||
          (service->auth_type == REND_STEALTH_AUTH &&
            smartlist_len(service->clients) > 16)) {
        log_warn(LD_CONFIG, "HiddenServiceAuthorizeClient contains %d "
                            "client authorization entries, but only a "
                            "maximum of %d entries is allowed for "
                            "authorization type %d.",
                 smartlist_len(service->clients),
                 service->auth_type == REND_BASIC_AUTH ? 512 : 16,
                 (int)service->auth_type);
        rend_service_free(service);
        return -1;
      }
    } else {
      smartlist_t *versions;
      char *version_str;
      int i, version, ver_ok=1, versions_bitmask = 0;
      tor_assert(!strcasecmp(line->key, "HiddenServiceVersion"));
      versions = smartlist_create();
      smartlist_split_string(versions, line->value, ",",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      for (i = 0; i < smartlist_len(versions); i++) {
        version_str = smartlist_get(versions, i);
        if (strlen(version_str) != 1 || strspn(version_str, "02") != 1) {
          log_warn(LD_CONFIG,
                   "HiddenServiceVersion can only be 0 and/or 2.");
          SMARTLIST_FOREACH(versions, char *, cp, tor_free(cp));
          smartlist_free(versions);
          rend_service_free(service);
          return -1;
        }
        version = (int)tor_parse_long(version_str, 10, 0, INT_MAX, &ver_ok,
                                      NULL);
        if (!ver_ok)
          continue;
        versions_bitmask |= 1 << version;
      }
      /* If exactly one version is set, change descriptor_version to that
       * value; otherwise leave it at -1. */
      if (versions_bitmask == 1 << 0) service->descriptor_version = 0;
      if (versions_bitmask == 1 << 2) service->descriptor_version = 2;
      SMARTLIST_FOREACH(versions, char *, cp, tor_free(cp));
      smartlist_free(versions);
    }
  }
  if (service) {
    if (validate_only)
      rend_service_free(service);
    else
      rend_add_service(service);
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
  int i;
  if (service->desc) {
    rend_service_descriptor_free(service->desc);
    service->desc = NULL;
  }
  d = service->desc = tor_malloc_zero(sizeof(rend_service_descriptor_t));
  d->pk = crypto_pk_dup_key(service->private_key);
  d->timestamp = time(NULL);
  d->version = service->descriptor_version;
  d->intro_nodes = smartlist_create();
  /* Whoever understands descriptor version 2 also understands intro
   * protocol 2. So we only support 2. */
  d->protocols = 1 << 2;

  for (i = 0; i < smartlist_len(service->intro_nodes); ++i) {
    rend_intro_point_t *intro_svc = smartlist_get(service->intro_nodes, i);
    rend_intro_point_t *intro_desc;
    circ = find_intro_circuit(intro_svc, service->pk_digest, d->version);
    if (!circ || circ->_base.purpose != CIRCUIT_PURPOSE_S_INTRO)
      continue;

    /* We have an entirely established intro circuit. */
    intro_desc = tor_malloc_zero(sizeof(rend_intro_point_t));
    intro_desc->extend_info = extend_info_dup(intro_svc->extend_info);
    if (intro_svc->intro_key)
      intro_desc->intro_key = crypto_pk_dup_key(intro_svc->intro_key);
    smartlist_add(d->intro_nodes, intro_desc);
  }
}

/** Load and/or generate private keys for all hidden services, possibly
 * including keys for client authorization.  Return 0 on success, -1 on
 * failure.
 */
int
rend_service_load_keys(void)
{
  int r = 0;
  char fname[512];
  char buf[1500];

  SMARTLIST_FOREACH_BEGIN(rend_service_list, rend_service_t *, s) {
    if (s->private_key)
      continue;
    log_info(LD_REND, "Loading hidden-service keys from \"%s\"",
             s->directory);

    /* Check/create directory */
    if (check_private_dir(s->directory, CPD_CREATE) < 0)
      return -1;

    /* Load key */
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,PATH_SEPARATOR"private_key",sizeof(fname))
                                                  >= sizeof(fname)) {
      log_warn(LD_CONFIG, "Directory name too long to store key file: \"%s\".",
               s->directory);
      return -1;
    }
    s->private_key = init_key_from_file(fname, 1, LOG_ERR);
    if (!s->private_key)
      return -1;

    /* Create service file */
    if (rend_get_service_id(s->private_key, s->service_id)<0) {
      log_warn(LD_BUG, "Internal error: couldn't encode service ID.");
      return -1;
    }
    if (crypto_pk_get_digest(s->private_key, s->pk_digest)<0) {
      log_warn(LD_BUG, "Couldn't compute hash of public key.");
      return -1;
    }
    if (strlcpy(fname,s->directory,sizeof(fname)) >= sizeof(fname) ||
        strlcat(fname,PATH_SEPARATOR"hostname",sizeof(fname))
                                                  >= sizeof(fname)) {
      log_warn(LD_CONFIG, "Directory name too long to store hostname file:"
               " \"%s\".", s->directory);
      return -1;
    }
    tor_snprintf(buf, sizeof(buf),"%s.onion\n", s->service_id);
    if (write_str_to_file(fname,buf,0)<0) {
      log_warn(LD_CONFIG, "Could not write onion address to hostname file.");
      return -1;
    }

    /* If client authorization is configured, load or generate keys. */
    if (s->auth_type) {
      char *client_keys_str = NULL;
      strmap_t *parsed_clients = strmap_new();
      char cfname[512];
      FILE *cfile, *hfile;
      open_file_t *open_cfile = NULL, *open_hfile = NULL;

      /* Load client keys and descriptor cookies, if available. */
      if (tor_snprintf(cfname, sizeof(cfname), "%s"PATH_SEPARATOR"client_keys",
                       s->directory)<0) {
        log_warn(LD_CONFIG, "Directory name too long to store client keys "
                 "file: \"%s\".", s->directory);
        goto err;
      }
      client_keys_str = read_file_to_str(cfname, RFTS_IGNORE_MISSING, NULL);
      if (client_keys_str) {
        if (rend_parse_client_keys(parsed_clients, client_keys_str) < 0) {
          log_warn(LD_CONFIG, "Previously stored client_keys file could not "
                              "be parsed.");
          goto err;
        } else {
          log_info(LD_CONFIG, "Parsed %d previously stored client entries.",
                   strmap_size(parsed_clients));
          tor_free(client_keys_str);
        }
      }

      /* Prepare client_keys and hostname files. */
      if (!(cfile = start_writing_to_stdio_file(cfname, OPEN_FLAGS_REPLACE,
                                                0600, &open_cfile))) {
        log_warn(LD_CONFIG, "Could not open client_keys file %s",
                 escaped(cfname));
        goto err;
      }
      if (!(hfile = start_writing_to_stdio_file(fname, OPEN_FLAGS_REPLACE,
                                                0600, &open_hfile))) {
        log_warn(LD_CONFIG, "Could not open hostname file %s", escaped(fname));
        goto err;
      }

      /* Either use loaded keys for configured clients or generate new
       * ones if a client is new. */
      SMARTLIST_FOREACH_BEGIN(s->clients, rend_authorized_client_t *, client)
      {
        char desc_cook_out[3*REND_DESC_COOKIE_LEN_BASE64+1];
        char service_id[16+1];
        rend_authorized_client_t *parsed =
            strmap_get(parsed_clients, client->client_name);
        int written;
        size_t len;
        /* Copy descriptor cookie from parsed entry or create new one. */
        if (parsed) {
          memcpy(client->descriptor_cookie, parsed->descriptor_cookie,
                 REND_DESC_COOKIE_LEN);
        } else {
          crypto_rand(client->descriptor_cookie, REND_DESC_COOKIE_LEN);
        }
        if (base64_encode(desc_cook_out, 3*REND_DESC_COOKIE_LEN_BASE64+1,
                          client->descriptor_cookie,
                          REND_DESC_COOKIE_LEN) < 0) {
          log_warn(LD_BUG, "Could not base64-encode descriptor cookie.");
          strmap_free(parsed_clients, rend_authorized_client_strmap_item_free);
          return -1;
        }
        /* Copy client key from parsed entry or create new one if required. */
        if (parsed && parsed->client_key) {
          client->client_key = crypto_pk_dup_key(parsed->client_key);
        } else if (s->auth_type == REND_STEALTH_AUTH) {
          /* Create private key for client. */
          crypto_pk_env_t *prkey = NULL;
          if (!(prkey = crypto_new_pk_env())) {
            log_warn(LD_BUG,"Error constructing client key");
            goto err;
          }
          if (crypto_pk_generate_key(prkey)) {
            log_warn(LD_BUG,"Error generating client key");
            goto err;
          }
          if (crypto_pk_check_key(prkey) <= 0) {
            log_warn(LD_BUG,"Generated client key seems invalid");
            crypto_free_pk_env(prkey);
            goto err;
          }
          client->client_key = prkey;
        }
        /* Add entry to client_keys file. */
        desc_cook_out[strlen(desc_cook_out)-1] = '\0'; /* Remove newline. */
        written = tor_snprintf(buf, sizeof(buf),
                               "client-name %s\ndescriptor-cookie %s\n",
                               client->client_name, desc_cook_out);
        if (written < 0) {
          log_warn(LD_BUG, "Could not write client entry.");
          goto err;

        }
        if (client->client_key) {
          char *client_key_out;
          crypto_pk_write_private_key_to_string(client->client_key,
                                                &client_key_out, &len);
          if (rend_get_service_id(client->client_key, service_id)<0) {
            log_warn(LD_BUG, "Internal error: couldn't encode service ID.");
            goto err;
          }
          written = tor_snprintf(buf + written, sizeof(buf) - written,
                                 "client-key\n%s", client_key_out);
          if (written < 0) {
            log_warn(LD_BUG, "Could not write client entry.");
            goto err;
          }
        }

        if (fputs(buf, cfile) < 0) {
          log_warn(LD_FS, "Could not append client entry to file: %s",
                   strerror(errno));
          goto err;
        }

        /* Add line to hostname file. */
        if (s->auth_type == REND_BASIC_AUTH) {
          /* Remove == signs (newline has been removed above). */
          desc_cook_out[strlen(desc_cook_out)-2] = '\0';
          tor_snprintf(buf, sizeof(buf),"%s.onion %s # client: %s\n",
                       s->service_id, desc_cook_out, client->client_name);
        } else {
          char extended_desc_cookie[REND_DESC_COOKIE_LEN+1];
          memcpy(extended_desc_cookie, client->descriptor_cookie,
                 REND_DESC_COOKIE_LEN);
          extended_desc_cookie[REND_DESC_COOKIE_LEN] = (s->auth_type - 1) << 4;
          if (base64_encode(desc_cook_out, 3*REND_DESC_COOKIE_LEN_BASE64+1,
                            extended_desc_cookie,
                            REND_DESC_COOKIE_LEN+1) < 0) {
            log_warn(LD_BUG, "Could not base64-encode descriptor cookie.");
            goto err;
          }
          desc_cook_out[strlen(desc_cook_out)-3] = '\0'; /* Remove A= and
                                                            newline. */
          tor_snprintf(buf, sizeof(buf),"%s.onion %s # client: %s\n",
                       service_id, desc_cook_out, client->client_name);
        }

        if (fputs(buf, hfile)<0) {
          log_warn(LD_FS, "Could not append host entry to file: %s",
                   strerror(errno));
          goto err;
        }
      }
      SMARTLIST_FOREACH_END(client);

      goto done;
    err:
      r = -1;
    done:
      tor_free(client_keys_str);
      strmap_free(parsed_clients, rend_authorized_client_strmap_item_free);
      if (r<0) {
        abort_writing_to_file(open_cfile);
        abort_writing_to_file(open_hfile);
        return r;
      } else {
        finish_writing_to_file(open_cfile);
        finish_writing_to_file(open_hfile);
      }
    }
  } SMARTLIST_FOREACH_END(s);
  return r;
}

/** Return the service whose public key has a digest of <b>digest</b> and
 * which publishes the given descriptor <b>version</b>.  Return NULL if no
 * such service exists.
 */
static rend_service_t *
rend_service_get_by_pk_digest_and_version(const char* digest,
                                          uint8_t version)
{
  SMARTLIST_FOREACH(rend_service_list, rend_service_t*, s,
                    if (!memcmp(s->pk_digest,digest,DIGEST_LEN) &&
                        s->descriptor_version == version) return s);
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
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  char hexcookie[9];
  int circ_needs_uptime;
  int reason = END_CIRC_REASON_TORPROTOCOL;
  crypto_pk_env_t *intro_key;
  char intro_key_digest[DIGEST_LEN];

  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,
                circuit->rend_pk_digest, REND_SERVICE_ID_LEN);
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

  /* look up service depending on circuit. */
  service = rend_service_get_by_pk_digest_and_version(
              circuit->rend_pk_digest, circuit->rend_desc_version);
  if (!service) {
    log_warn(LD_REND, "Got an INTRODUCE2 cell for an unrecognized service %s.",
             escaped(serviceid));
    return -1;
  }

  /* if descriptor version is 2, use intro key instead of service key. */
  if (circuit->rend_desc_version == 0) {
    intro_key = service->private_key;
  } else {
    intro_key = circuit->intro_key;
  }

  /* first DIGEST_LEN bytes of request is intro or service pk digest */
  crypto_pk_get_digest(intro_key, intro_key_digest);
  if (memcmp(intro_key_digest, request, DIGEST_LEN)) {
    base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,
                  request, REND_SERVICE_ID_LEN);
    log_warn(LD_REND, "Got an INTRODUCE2 cell for the wrong service (%s).",
             escaped(serviceid));
    return -1;
  }

  keylen = crypto_pk_keysize(intro_key);
  if (request_len < keylen+DIGEST_LEN) {
    log_warn(LD_PROTOCOL,
             "PK-encrypted portion of INTRODUCE2 cell was truncated.");
    return -1;
  }
  /* Next N bytes is encrypted with service key */
  note_crypto_pk_op(REND_SERVER);
  r = crypto_pk_private_hybrid_decrypt(
       intro_key,buf,request+DIGEST_LEN,request_len-DIGEST_LEN,
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
    tor_addr_from_ipv4n(&extend_info->addr, get_uint32(buf+1));
    extend_info->port = ntohs(get_uint16(buf+5));
    memcpy(extend_info->identity_digest, buf+7, DIGEST_LEN);
    extend_info->nickname[0] = '$';
    base16_encode(extend_info->nickname+1, sizeof(extend_info->nickname)-1,
                  extend_info->identity_digest, DIGEST_LEN);

    klen = ntohs(get_uint16(buf+7+DIGEST_LEN));
    if ((int)len != 7+DIGEST_LEN+2+klen+20+128) {
      log_warn(LD_PROTOCOL, "Bad length %u for version 2 INTRODUCE2 cell.",
               (int)len);
      reason = END_CIRC_REASON_TORPROTOCOL;
      goto err;
    }
    extend_info->onion_key = crypto_pk_asn1_decode(buf+7+DIGEST_LEN+2, klen);
    if (!extend_info->onion_key) {
      log_warn(LD_PROTOCOL,
               "Error decoding onion key in version 2 INTRODUCE2 cell.");
      reason = END_CIRC_REASON_TORPROTOCOL;
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
      log_info(LD_REND, "Couldn't find router %s named in introduce2 cell.",
               escaped_safe_str(rp_nickname));
      /* XXXX Add a no-such-router reason? */
      reason = END_CIRC_REASON_TORPROTOCOL;
      goto err;
    }

    extend_info = extend_info_from_router(router);
  }

  if (len != REND_COOKIE_LEN+DH_KEY_LEN) {
    log_warn(LD_PROTOCOL, "Bad length %u for INTRODUCE2 cell.", (int)len);
    reason = END_CIRC_REASON_TORPROTOCOL;
    goto err;
  }

  r_cookie = ptr;
  base16_encode(hexcookie,9,r_cookie,4);

  /* Try DH handshake... */
  dh = crypto_dh_new();
  if (!dh || crypto_dh_generate_public(dh)<0) {
    log_warn(LD_BUG,"Internal error: couldn't build DH state "
             "or generate public key.");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }
  if (crypto_dh_compute_secret(dh, ptr+REND_COOKIE_LEN, DH_KEY_LEN, keys,
                               DIGEST_LEN+CPATH_KEY_MATERIAL_LEN)<0) {
    log_warn(LD_BUG, "Internal error: couldn't complete DH handshake");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }

  circ_needs_uptime = rend_service_requires_uptime(service);

  /* help predict this next time */
  rep_hist_note_used_internal(time(NULL), circ_needs_uptime, 1);

  /* Launch a circuit to alice's chosen rendezvous point.
   */
  for (i=0;i<MAX_REND_FAILURES;i++) {
    int flags = CIRCLAUNCH_NEED_CAPACITY | CIRCLAUNCH_IS_INTERNAL;
    if (circ_needs_uptime) flags |= CIRCLAUNCH_NEED_UPTIME;
    launched = circuit_launch_by_extend_info(
                        CIRCUIT_PURPOSE_S_CONNECT_REND, extend_info, flags);

    if (launched)
      break;
  }
  if (!launched) { /* give up */
    log_warn(LD_REND, "Giving up launching first hop of circuit to rendezvous "
             "point %s for service %s.",
             escaped_safe_str(extend_info->nickname), serviceid);
    reason = END_CIRC_REASON_CONNECTFAILED;
    goto err;
  }
  log_info(LD_REND,
           "Accepted intro; launching circuit to %s "
           "(cookie %s) for service %s.",
           escaped_safe_str(extend_info->nickname), hexcookie, serviceid);
  tor_assert(launched->build_state);
  /* Fill in the circuit's state. */
  memcpy(launched->rend_pk_digest, circuit->rend_pk_digest,
         DIGEST_LEN);
  memcpy(launched->rend_cookie, r_cookie, REND_COOKIE_LEN);
  strlcpy(launched->rend_query, service->service_id,
          sizeof(launched->rend_query));
  launched->rend_desc_version = service->descriptor_version;
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
    circuit_mark_for_close(TO_CIRCUIT(launched), reason);
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
                            oldstate->chosen_exit,
                            CIRCLAUNCH_NEED_CAPACITY|CIRCLAUNCH_IS_INTERNAL);

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

  memcpy(newcirc->rend_query, oldcirc->rend_query,
         REND_SERVICE_ID_LEN_BASE32+1);
  memcpy(newcirc->rend_pk_digest, oldcirc->rend_pk_digest,
         DIGEST_LEN);
  memcpy(newcirc->rend_cookie, oldcirc->rend_cookie,
         REND_COOKIE_LEN);
  newcirc->rend_desc_version = oldcirc->rend_desc_version;
}

/** Launch a circuit to serve as an introduction point for the service
 * <b>service</b> at the introduction point <b>nickname</b>
 */
static int
rend_service_launch_establish_intro(rend_service_t *service,
                                    rend_intro_point_t *intro)
{
  origin_circuit_t *launched;

  log_info(LD_REND,
           "Launching circuit to introduction point %s for service %s",
           escaped_safe_str(intro->extend_info->nickname),
           service->service_id);

  rep_hist_note_used_internal(time(NULL), 1, 0);

  ++service->n_intro_circuits_launched;
  launched = circuit_launch_by_extend_info(CIRCUIT_PURPOSE_S_ESTABLISH_INTRO,
                             intro->extend_info,
                             CIRCLAUNCH_NEED_UPTIME|CIRCLAUNCH_IS_INTERNAL);

  if (!launched) {
    log_info(LD_REND,
             "Can't launch circuit to establish introduction at %s.",
             escaped_safe_str(intro->extend_info->nickname));
    return -1;
  }

  if (memcmp(intro->extend_info->identity_digest,
      launched->build_state->chosen_exit->identity_digest, DIGEST_LEN)) {
    char cann[HEX_DIGEST_LEN+1], orig[HEX_DIGEST_LEN+1];
    base16_encode(cann, sizeof(cann),
                  launched->build_state->chosen_exit->identity_digest,
                  DIGEST_LEN);
    base16_encode(orig, sizeof(orig),
                  intro->extend_info->identity_digest, DIGEST_LEN);
    log_info(LD_REND, "The intro circuit we just cannibalized ends at $%s, "
                      "but we requested an intro circuit to $%s. Updating "
                      "our service.", cann, orig);
    extend_info_free(intro->extend_info);
    intro->extend_info = extend_info_dup(launched->build_state->chosen_exit);
  }

  strlcpy(launched->rend_query, service->service_id,
          sizeof(launched->rend_query));
  memcpy(launched->rend_pk_digest, service->pk_digest, DIGEST_LEN);
  launched->rend_desc_version = service->descriptor_version;
  if (service->descriptor_version == 2)
    launched->intro_key = crypto_pk_dup_key(intro->intro_key);
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
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  int reason = END_CIRC_REASON_TORPROTOCOL;
  crypto_pk_env_t *intro_key;

  tor_assert(circuit->_base.purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);
  tor_assert(circuit->cpath);

  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,
                circuit->rend_pk_digest, REND_SERVICE_ID_LEN);

  service = rend_service_get_by_pk_digest_and_version(
              circuit->rend_pk_digest, circuit->rend_desc_version);
  if (!service) {
    log_warn(LD_REND, "Unrecognized service ID %s on introduction circuit %d.",
             serviceid, circuit->_base.n_circ_id);
    reason = END_CIRC_REASON_NOSUCHSERVICE;
    goto err;
  }

  log_info(LD_REND,
           "Established circuit %d as introduction point for service %s",
           circuit->_base.n_circ_id, serviceid);

  /* If the introduction point will not be used in an unversioned
   * descriptor, use the intro key instead of the service key in
   * ESTABLISH_INTRO. */
  if (service->descriptor_version == 0)
    intro_key = service->private_key;
  else
    intro_key = circuit->intro_key;
  /* Build the payload for a RELAY_ESTABLISH_INTRO cell. */
  r = crypto_pk_asn1_encode(intro_key, buf+2,
                            RELAY_PAYLOAD_SIZE-2);
  if (r < 0) {
    log_warn(LD_BUG, "Internal error; failed to establish intro point.");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }
  len = r;
  set_uint16(buf, htons((uint16_t)len));
  len += 2;
  memcpy(auth, circuit->cpath->prev->handshake_digest, DIGEST_LEN);
  memcpy(auth+DIGEST_LEN, "INTRODUCE", 9);
  if (crypto_digest(buf+len, auth, DIGEST_LEN+9))
    goto err;
  len += 20;
  note_crypto_pk_op(REND_SERVER);
  r = crypto_pk_private_sign_digest(intro_key, buf+len, buf, len);
  if (r<0) {
    log_warn(LD_BUG, "Internal error: couldn't sign introduction request.");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }
  len += r;

  if (relay_send_command_from_edge(0, TO_CIRCUIT(circuit),
                                   RELAY_COMMAND_ESTABLISH_INTRO,
                                   buf, len, circuit->cpath->prev)<0) {
    log_info(LD_GENERAL,
             "Couldn't send introduction request for service %s on circuit %d",
             serviceid, circuit->_base.n_circ_id);
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }

  return;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circuit), reason);
}

/** Called when we get an INTRO_ESTABLISHED cell; mark the circuit as a
 * live introduction point, and note that the service descriptor is
 * now out-of-date.*/
int
rend_service_intro_established(origin_circuit_t *circuit, const char *request,
                               size_t request_len)
{
  rend_service_t *service;
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  (void) request;
  (void) request_len;

  if (circuit->_base.purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_warn(LD_PROTOCOL,
             "received INTRO_ESTABLISHED cell on non-intro circuit.");
    goto err;
  }
  service = rend_service_get_by_pk_digest_and_version(
              circuit->rend_pk_digest, circuit->rend_desc_version);
  if (!service) {
    log_warn(LD_REND, "Unknown service on introduction circuit %d.",
             circuit->_base.n_circ_id);
    goto err;
  }
  service->desc_is_dirty = time(NULL);
  circuit->_base.purpose = CIRCUIT_PURPOSE_S_INTRO;

  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32 + 1,
                circuit->rend_pk_digest, REND_SERVICE_ID_LEN);
  log_info(LD_REND,
           "Received INTRO_ESTABLISHED cell on circuit %d for service %s",
           circuit->_base.n_circ_id, serviceid);

  return 0;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circuit), END_CIRC_REASON_TORPROTOCOL);
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
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  char hexcookie[9];
  int reason;

  tor_assert(circuit->_base.purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);
  tor_assert(circuit->cpath);
  tor_assert(circuit->build_state);
  hop = circuit->build_state->pending_final_cpath;
  tor_assert(hop);

  base16_encode(hexcookie,9,circuit->rend_cookie,4);
  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,
                circuit->rend_pk_digest, REND_SERVICE_ID_LEN);

  log_info(LD_REND,
           "Done building circuit %d to rendezvous with "
           "cookie %s for service %s",
           circuit->_base.n_circ_id, hexcookie, serviceid);

  service = rend_service_get_by_pk_digest_and_version(
              circuit->rend_pk_digest, circuit->rend_desc_version);
  if (!service) {
    log_warn(LD_GENERAL, "Internal error: unrecognized service ID on "
             "introduction circuit.");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }

  /* All we need to do is send a RELAY_RENDEZVOUS1 cell... */
  memcpy(buf, circuit->rend_cookie, REND_COOKIE_LEN);
  if (crypto_dh_get_public(hop->dh_handshake_state,
                           buf+REND_COOKIE_LEN, DH_KEY_LEN)<0) {
    log_warn(LD_GENERAL,"Couldn't get DH public key.");
    reason = END_CIRC_REASON_INTERNAL;
    goto err;
  }
  memcpy(buf+REND_COOKIE_LEN+DH_KEY_LEN, hop->handshake_digest,
         DIGEST_LEN);

  /* Send the cell */
  if (relay_send_command_from_edge(0, TO_CIRCUIT(circuit),
                                   RELAY_COMMAND_RENDEZVOUS1,
                                   buf, REND_COOKIE_LEN+DH_KEY_LEN+DIGEST_LEN,
                                   circuit->cpath->prev)<0) {
    log_warn(LD_GENERAL, "Couldn't send RENDEZVOUS1 cell.");
    reason = END_CIRC_REASON_INTERNAL;
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
  circuit_mark_for_close(TO_CIRCUIT(circuit), reason);
}

/*
 * Manage introduction points
 */

/** Return the (possibly non-open) introduction circuit ending at
 * <b>intro</b> for the service whose public key is <b>pk_digest</b> and
 * which publishes descriptor of version <b>desc_version</b>.  Return
 * NULL if no such service is found.
 */
static origin_circuit_t *
find_intro_circuit(rend_intro_point_t *intro, const char *pk_digest,
                   int desc_version)
{
  origin_circuit_t *circ = NULL;

  tor_assert(intro);
  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                                  CIRCUIT_PURPOSE_S_INTRO))) {
    if (!memcmp(circ->build_state->chosen_exit->identity_digest,
                intro->extend_info->identity_digest, DIGEST_LEN) &&
        circ->rend_desc_version == desc_version) {
      return circ;
    }
  }

  circ = NULL;
  while ((circ = circuit_get_next_by_pk_and_purpose(circ,pk_digest,
                                        CIRCUIT_PURPOSE_S_ESTABLISH_INTRO))) {
    if (!memcmp(circ->build_state->chosen_exit->identity_digest,
                intro->extend_info->identity_digest, DIGEST_LEN) &&
        circ->rend_desc_version == desc_version) {
      return circ;
    }
  }
  return NULL;
}

/** Determine the responsible hidden service directories for the
 * rend_encoded_v2_service_descriptor_t's in <b>descs</b> and upload them;
 * <b>service_id</b> and <b>seconds_valid</b> are only passed for logging
 * purposes. */
static void
directory_post_to_hs_dir(smartlist_t *descs, const char *service_id,
                         int seconds_valid)
{
  int i, j;
  smartlist_t *responsible_dirs = smartlist_create();
  routerstatus_t *hs_dir;
  for (i = 0; i < smartlist_len(descs); i++) {
    rend_encoded_v2_service_descriptor_t *desc = smartlist_get(descs, i);
    /* Determine responsible dirs. */
    if (hid_serv_get_responsible_directories(responsible_dirs,
                                             desc->desc_id) < 0) {
      log_warn(LD_REND, "Could not determine the responsible hidden service "
                        "directories to post descriptors to.");
      smartlist_free(responsible_dirs);
      return;
    }
    for (j = 0; j < smartlist_len(responsible_dirs); j++) {
      char desc_id_base32[REND_DESC_ID_V2_LEN_BASE32 + 1];
      hs_dir = smartlist_get(responsible_dirs, j);
      /* Send publish request. */
      directory_initiate_command_routerstatus(hs_dir,
                                              DIR_PURPOSE_UPLOAD_RENDDESC_V2,
                                              ROUTER_PURPOSE_GENERAL,
                                              1, NULL, desc->desc_str,
                                              strlen(desc->desc_str), 0);
      base32_encode(desc_id_base32, sizeof(desc_id_base32),
                    desc->desc_id, DIGEST_LEN);
      log_info(LD_REND, "Sending publish request for v2 descriptor for "
                        "service '%s' with descriptor ID '%s' with validity "
                        "of %d seconds to hidden service directory '%s' on "
                        "port %d.",
               safe_str(service_id),
               safe_str(desc_id_base32),
               seconds_valid,
               hs_dir->nickname,
               hs_dir->dir_port);
    }
    smartlist_clear(responsible_dirs);
  }
  smartlist_free(responsible_dirs);
}

/** Encode and sign up-to-date v0 and/or v2 service descriptors for
 * <b>service</b>, and upload it/them to all the dirservers/to the
 * responsible hidden service directories.
 */
static void
upload_service_descriptor(rend_service_t *service)
{
  time_t now = time(NULL);
  int rendpostperiod;
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  int uploaded = 0;

  /* Update the descriptor. */
  rend_service_update_descriptor(service);

  rendpostperiod = get_options()->RendPostPeriod;

  /* Upload unversioned (v0) descriptor? */
  if (service->descriptor_version == 0 &&
      get_options()->PublishHidServDescriptors) {
    char *desc;
    size_t desc_len;
    /* Encode the descriptor. */
    if (rend_encode_service_descriptor(service->desc,
                                       service->private_key,
                                       &desc, &desc_len)<0) {
      log_warn(LD_BUG, "Internal error: couldn't encode service descriptor; "
               "not uploading.");
      return;
    }

    /* Post it to the dirservers */
    rend_get_service_id(service->desc->pk, serviceid);
    log_info(LD_REND, "Sending publish request for hidden service %s",
             serviceid);
    directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_RENDDESC,
                                 ROUTER_PURPOSE_GENERAL,
                                 HIDSERV_AUTHORITY, desc, desc_len, 0);
    tor_free(desc);
    service->next_upload_time = now + rendpostperiod;
    uploaded = 1;
  }

  /* Upload v2 descriptor? */
  if (service->descriptor_version == 2 &&
      get_options()->PublishHidServDescriptors) {
    networkstatus_t *c = networkstatus_get_latest_consensus();
    if (c && smartlist_len(c->routerstatus_list) > 0) {
      int seconds_valid;
      smartlist_t *descs = smartlist_create();
      int i;
      /* Encode the current descriptor. */
      seconds_valid = rend_encode_v2_descriptors(descs, service->desc, now,
                                                 NULL, 0);
      if (seconds_valid < 0) {
        log_warn(LD_BUG, "Internal error: couldn't encode service descriptor; "
                 "not uploading.");
        smartlist_free(descs);
        return;
      }
      /* Post the current descriptors to the hidden service directories. */
      rend_get_service_id(service->desc->pk, serviceid);
      log_info(LD_REND, "Sending publish request for hidden service %s",
                   serviceid);
      directory_post_to_hs_dir(descs, serviceid, seconds_valid);
      /* Free memory for descriptors. */
      for (i = 0; i < smartlist_len(descs); i++)
        rend_encoded_v2_service_descriptor_free(smartlist_get(descs, i));
      smartlist_clear(descs);
      /* Update next upload time. */
      if (seconds_valid - REND_TIME_PERIOD_OVERLAPPING_V2_DESCS
          > rendpostperiod)
        service->next_upload_time = now + rendpostperiod;
      else if (seconds_valid < REND_TIME_PERIOD_OVERLAPPING_V2_DESCS)
        service->next_upload_time = now + seconds_valid + 1;
      else
        service->next_upload_time = now + seconds_valid -
            REND_TIME_PERIOD_OVERLAPPING_V2_DESCS + 1;
      /* Post also the next descriptors, if necessary. */
      if (seconds_valid < REND_TIME_PERIOD_OVERLAPPING_V2_DESCS) {
        seconds_valid = rend_encode_v2_descriptors(descs, service->desc,
                                                   now, NULL, 1);
        if (seconds_valid < 0) {
          log_warn(LD_BUG, "Internal error: couldn't encode service "
                   "descriptor; not uploading.");
          smartlist_free(descs);
          return;
        }
        directory_post_to_hs_dir(descs, serviceid, seconds_valid);
        /* Free memory for descriptors. */
        for (i = 0; i < smartlist_len(descs); i++)
          rend_encoded_v2_service_descriptor_free(smartlist_get(descs, i));
      }
      smartlist_free(descs);
      uploaded = 1;
      log_info(LD_REND, "Successfully uploaded v2 rend descriptors!");
    }
  }

  /* If not uploaded, try again in one minute. */
  if (!uploaded)
    service->next_upload_time = now + 60;

  /* Unmark dirty flag of this service. */
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
  rend_intro_point_t *intro;
  int changed, prev_intro_nodes;
  smartlist_t *intro_routers;
  time_t now;
  or_options_t *options = get_options();

  intro_routers = smartlist_create();
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
      router = router_get_by_digest(intro->extend_info->identity_digest);
      if (!router || !find_intro_circuit(intro, service->pk_digest,
                                         service->descriptor_version)) {
        log_info(LD_REND,"Giving up on %s as intro point for %s.",
                 intro->extend_info->nickname, service->service_id);
        if (service->desc) {
          SMARTLIST_FOREACH(service->desc->intro_nodes, rend_intro_point_t *,
                            dintro, {
            if (!memcmp(dintro->extend_info->identity_digest,
                intro->extend_info->identity_digest, DIGEST_LEN)) {
              log_info(LD_REND, "The intro point we are giving up on was "
                                "included in the last published descriptor. "
                                "Marking current descriptor as dirty.");
              service->desc_is_dirty = now;
            }
          });
        }
        rend_intro_point_free(intro);
        smartlist_del(service->intro_nodes,j--);
        changed = 1;
      }
      if (router)
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

    /* The directory is now here. Pick three ORs as intro points. */
    for (j=prev_intro_nodes; j < NUM_INTRO_POINTS; ++j) {
      router_crn_flags_t flags = CRN_NEED_UPTIME;
      if (get_options()->_AllowInvalid & ALLOW_INVALID_INTRODUCTION)
        flags |= CRN_ALLOW_INVALID;
      router = router_choose_random_node(NULL, intro_routers,
                                         options->ExcludeNodes, flags);
      if (!router) {
        log_warn(LD_REND,
                 "Could only establish %d introduction points for %s.",
                 smartlist_len(service->intro_nodes), service->service_id);
        break;
      }
      changed = 1;
      smartlist_add(intro_routers, router);
      intro = tor_malloc_zero(sizeof(rend_intro_point_t));
      intro->extend_info = extend_info_from_router(router);
      if (service->descriptor_version == 2) {
        intro->intro_key = crypto_new_pk_env();
        tor_assert(!crypto_pk_generate_key(intro->intro_key));
      }
      smartlist_add(service->intro_nodes, intro);
      log_info(LD_REND, "Picked router %s as an intro point for %s.",
               router->nickname, service->service_id);
    }

    /* If there's no need to launch new circuits, stop here. */
    if (!changed)
      continue;

    /* Establish new introduction points. */
    for (j=prev_intro_nodes; j < smartlist_len(service->intro_nodes); ++j) {
      intro = smartlist_get(service->intro_nodes, j);
      r = rend_service_launch_establish_intro(service, intro);
      if (r<0) {
        log_warn(LD_REND, "Error launching circuit to node %s for service %s.",
                 intro->extend_info->nickname, service->service_id);
      }
    }
  }
  smartlist_free(intro_routers);
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
      /* The fixed lower bound of 30 seconds ensures that the descriptor
       * is stable before being published. See comment below. */
      service->next_upload_time =
        now + 30 + crypto_rand_int(2*rendpostperiod);
    }
    if (service->next_upload_time < now ||
        (service->desc_is_dirty &&
         service->desc_is_dirty < now-30)) {
      /* if it's time, or if the directory servers have a wrong service
       * descriptor and ours has been stable for 30 seconds, upload a
       * new one of each format. */
      upload_service_descriptor(service);
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
  rend_service_t *service;
  rend_intro_point_t *intro;
  const char *safe_name;
  origin_circuit_t *circ;

  for (i=0; i < smartlist_len(rend_service_list); ++i) {
    service = smartlist_get(rend_service_list, i);
    log(severity, LD_GENERAL, "Service configured in \"%s\":",
        service->directory);
    for (j=0; j < smartlist_len(service->intro_nodes); ++j) {
      intro = smartlist_get(service->intro_nodes, j);
      safe_name = safe_str(intro->extend_info->nickname);

      circ = find_intro_circuit(intro, service->pk_digest,
                                service->descriptor_version);
      if (!circ) {
        log(severity, LD_GENERAL, "  Intro point %d at %s: no circuit",
            j, safe_name);
        continue;
      }
      log(severity, LD_GENERAL, "  Intro point %d at %s: circuit is %s",
          j, safe_name, circuit_state_to_string(circ->_base.state));
    }
  }
}

/** Given <b>conn</b>, a rendezvous exit stream, look up the hidden service for
 * 'circ', and look up the port and address based on conn-\>port.
 * Assign the actual conn-\>addr and conn-\>port. Return -1 if failure,
 * or 0 for success.
 */
int
rend_service_set_connection_addr_port(edge_connection_t *conn,
                                      origin_circuit_t *circ)
{
  rend_service_t *service;
  char serviceid[REND_SERVICE_ID_LEN_BASE32+1];
  smartlist_t *matching_ports;
  rend_service_port_config_t *chosen_port;

  tor_assert(circ->_base.purpose == CIRCUIT_PURPOSE_S_REND_JOINED);
  log_debug(LD_REND,"beginning to hunt for addr/port");
  base32_encode(serviceid, REND_SERVICE_ID_LEN_BASE32+1,
                circ->rend_pk_digest, REND_SERVICE_ID_LEN);
  service = rend_service_get_by_pk_digest_and_version(circ->rend_pk_digest,
                                                      circ->rend_desc_version);
  if (!service) {
    log_warn(LD_REND, "Couldn't find any service associated with pk %s on "
             "rendezvous circuit %d; closing.",
             serviceid, circ->_base.n_circ_id);
    return -1;
  }
  matching_ports = smartlist_create();
  SMARTLIST_FOREACH(service->ports, rend_service_port_config_t *, p,
  {
    if (conn->_base.port == p->virtual_port) {
      smartlist_add(matching_ports, p);
    }
  });
  chosen_port = smartlist_choose(matching_ports);
  smartlist_free(matching_ports);
  if (chosen_port) {
    tor_addr_copy(&conn->_base.addr, &chosen_port->real_addr);
    conn->_base.port = chosen_port->real_port;
    return 0;
  }
  log_info(LD_REND, "No virtual port mapping exists for port %d on service %s",
           conn->_base.port,serviceid);
  return -1;
}

