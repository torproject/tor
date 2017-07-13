/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service functionality
 **/

#define HS_SERVICE_PRIVATE

#include "or.h"
#include "circuitlist.h"
#include "config.h"
#include "relay.h"
#include "rendservice.h"
#include "router.h"
#include "routerkeys.h"

#include "hs_common.h"
#include "hs_config.h"
#include "hs_intropoint.h"
#include "hs_service.h"

#include "hs/cell_establish_intro.h"
#include "hs/cell_common.h"

/* Onion service directory file names. */
static const char *fname_keyfile_prefix = "hs_ed25519";
static const char *fname_hostname = "hostname";
static const char *address_tld = "onion";

/* Staging list of service object. When configuring service, we add them to
 * this list considered a staging area and they will get added to our global
 * map once the keys have been loaded. These two steps are seperated because
 * loading keys requires that we are an actual running tor process. */
static smartlist_t *hs_service_staging_list;

/* Helper: Function to compare two objects in the service map. Return 1 if the
 * two service have the same master public identity key. */
static inline int
hs_service_ht_eq(const hs_service_t *first, const hs_service_t *second)
{
  tor_assert(first);
  tor_assert(second);
  /* Simple key compare. */
  return ed25519_pubkey_eq(&first->keys.identity_pk,
                           &second->keys.identity_pk);
}

/* Helper: Function for the service hash table code below. The key used is the
 * master public identity key which is ultimately the onion address. */
static inline unsigned int
hs_service_ht_hash(const hs_service_t *service)
{
  tor_assert(service);
  return (unsigned int) siphash24g(service->keys.identity_pk.pubkey,
                                   sizeof(service->keys.identity_pk.pubkey));
}

/* This is _the_ global hash map of hidden services which indexed the service
 * contained in it by master public identity key which is roughly the onion
 * address of the service. */
static struct hs_service_ht *hs_service_map;

/* Register the service hash table. */
HT_PROTOTYPE(hs_service_ht,      /* Name of hashtable. */
             hs_service_t,       /* Object contained in the map. */
             hs_service_node,    /* The name of the HT_ENTRY member. */
             hs_service_ht_hash, /* Hashing function. */
             hs_service_ht_eq)   /* Compare function for objects. */

HT_GENERATE2(hs_service_ht, hs_service_t, hs_service_node,
             hs_service_ht_hash, hs_service_ht_eq,
             0.6, tor_reallocarray, tor_free_)

/* Query the given service map with a public key and return a service object
 * if found else NULL. It is also possible to set a directory path in the
 * search query. If pk is NULL, then it will be set to zero indicating the
 * hash table to compare the directory path instead. */
STATIC hs_service_t *
find_service(hs_service_ht *map, const ed25519_public_key_t *pk)
{
  hs_service_t dummy_service;
  tor_assert(map);
  tor_assert(pk);
  memset(&dummy_service, 0, sizeof(dummy_service));
  ed25519_pubkey_copy(&dummy_service.keys.identity_pk, pk);
  return HT_FIND(hs_service_ht, map, &dummy_service);
}

/* Register the given service in the given map. If the service already exists
 * in the map, -1 is returned. On success, 0 is returned and the service
 * ownership has been transfered to the global map. */
STATIC int
register_service(hs_service_ht *map, hs_service_t *service)
{
  tor_assert(map);
  tor_assert(service);
  tor_assert(!ed25519_public_key_is_zero(&service->keys.identity_pk));

  if (find_service(map, &service->keys.identity_pk)) {
    /* Existing service with the same key. Do not register it. */
    return -1;
  }
  /* Taking ownership of the object at this point. */
  HT_INSERT(hs_service_ht, map, service);
  return 0;
}

/* Remove a given service from the given map. If service is NULL or the
 * service key is unset, return gracefully. */
STATIC void
remove_service(hs_service_ht *map, hs_service_t *service)
{
  hs_service_t *elm;

  tor_assert(map);

  /* Ignore if no service or key is zero. */
  if (BUG(service == NULL) ||
      BUG(ed25519_public_key_is_zero(&service->keys.identity_pk))) {
    return;
  }

  elm = HT_REMOVE(hs_service_ht, map, service);
  if (elm) {
    tor_assert(elm == service);
  } else {
    log_warn(LD_BUG, "Could not find service in the global map "
                     "while removing service %s",
             escaped(service->config.directory_path));
  }
}

/* Set the default values for a service configuration object <b>c</b>. */
static void
set_service_default_config(hs_service_config_t *c,
                           const or_options_t *options)
{
  tor_assert(c);
  c->ports = smartlist_new();
  c->directory_path = NULL;
  c->descriptor_post_period = options->RendPostPeriod;
  c->max_streams_per_rdv_circuit = 0;
  c->max_streams_close_circuit = 0;
  c->num_intro_points = NUM_INTRO_POINTS_DEFAULT;
  c->allow_unknown_ports = 0;
  c->is_single_onion = 0;
  c->dir_group_readable = 0;
  c->is_ephemeral = 0;
}

/* From a service configuration object config, clear everything from it
 * meaning free allocated pointers and reset the values. */
static void
service_clear_config(hs_service_config_t *config)
{
  if (config == NULL) {
    return;
  }
  tor_free(config->directory_path);
  if (config->ports) {
    SMARTLIST_FOREACH(config->ports, rend_service_port_config_t *, p,
                      rend_service_port_config_free(p););
    smartlist_free(config->ports);
  }
  memset(config, 0, sizeof(*config));
}

/* Helper: Function that needs to return 1 for the HT for each loop which
 * frees every service in an hash map. */
static int
ht_free_service_(struct hs_service_t *service, void *data)
{
  (void) data;
  hs_service_free(service);
  /* This function MUST return 1 so the given object is then removed from the
   * service map leading to this free of the object being safe. */
  return 1;
}

/* Free every service that can be found in the global map. Once done, clear
 * and free the global map. */
static void
service_free_all(void)
{
  if (hs_service_map) {
    /* The free helper function returns 1 so this is safe. */
    hs_service_ht_HT_FOREACH_FN(hs_service_map, ht_free_service_, NULL);
    HT_CLEAR(hs_service_ht, hs_service_map);
    tor_free(hs_service_map);
    hs_service_map = NULL;
  }

  if (hs_service_staging_list) {
    /* Cleanup staging list. */
    SMARTLIST_FOREACH(hs_service_staging_list, hs_service_t *, s,
                      hs_service_free(s));
    smartlist_free(hs_service_staging_list);
    hs_service_staging_list = NULL;
  }
}

/* Close all rendezvous circuits for the given service. */
static void
close_service_rp_circuits(hs_service_t *service)
{
  tor_assert(service);
  /* XXX: To implement. */
  return;
}

/* Close the circuit(s) for the given map of introduction points. */
static void
close_intro_circuits(hs_service_intropoints_t *intro_points)
{
  tor_assert(intro_points);

  DIGEST256MAP_FOREACH(intro_points->map, key,
                       const hs_service_intro_point_t *, ip) {
    origin_circuit_t *ocirc =
      hs_circuitmap_get_intro_circ_v3_service_side(
                                      &ip->auth_key_kp.pubkey);
    if (ocirc) {
      hs_circuitmap_remove_circuit(TO_CIRCUIT(ocirc));
      /* Reason is FINISHED because service has been removed and thus the
       * circuit is considered old/uneeded. */
      circuit_mark_for_close(TO_CIRCUIT(ocirc), END_CIRC_REASON_FINISHED);
    }
  } DIGEST256MAP_FOREACH_END;
}

/* Close all introduction circuits for the given service. */
static void
close_service_intro_circuits(hs_service_t *service)
{
  tor_assert(service);

  if (service->desc_current) {
    close_intro_circuits(&service->desc_current->intro_points);
  }
  if (service->desc_next) {
    close_intro_circuits(&service->desc_next->intro_points);
  }
}

/* Close any circuits related to the given service. */
static void
close_service_circuits(hs_service_t *service)
{
  tor_assert(service);

  /* Only support for version >= 3. */
  if (BUG(service->config.version < HS_VERSION_THREE)) {
    return;
  }
  /* Close intro points. */
  close_service_intro_circuits(service);
  /* Close rendezvous points. */
  close_service_rp_circuits(service);
}

/* Move introduction points from the src descriptor to the dst descriptor. The
 * destination service intropoints are wiped out if any before moving. */
static void
move_descriptor_intro_points(hs_service_descriptor_t *src,
                             hs_service_descriptor_t *dst)
{
  tor_assert(src);
  tor_assert(dst);

  /* XXX: Free dst introduction points. */
  dst->intro_points.map = src->intro_points.map;
  /* Nullify the source. */
  src->intro_points.map = NULL;
}

/* Move introduction points from the src service to the dst service. The
 * destination service intropoints are wiped out if any before moving. */
static void
move_intro_points(hs_service_t *src, hs_service_t *dst)
{
  tor_assert(src);
  tor_assert(dst);

  /* Cleanup destination. */
  if (src->desc_current && dst->desc_current) {
    move_descriptor_intro_points(src->desc_current, dst->desc_current);
  }
  if (src->desc_next && dst->desc_next) {
    move_descriptor_intro_points(src->desc_next, dst->desc_next);
  }
}

/* Move every ephemeral services from the src service map to the dst service
 * map. It is possible that a service can't be register to the dst map which
 * won't stop the process of moving them all but will trigger a log warn. */
static void
move_ephemeral_services(hs_service_ht *src, hs_service_ht *dst)
{
  hs_service_t **iter, **next;

  tor_assert(src);
  tor_assert(dst);

  /* Iterate over the map to find ephemeral service and move them to the other
   * map. We loop using this method to have a safe removal process. */
  for (iter = HT_START(hs_service_ht, src); iter != NULL; iter = next) {
    hs_service_t *s = *iter;
    if (!s->config.is_ephemeral) {
      /* Yeah, we are in a very manual loop :). */
      next = HT_NEXT(hs_service_ht, src, iter);
      continue;
    }
    /* Remove service from map and then register to it to the other map.
     * Reminder that "*iter" and "s" are the same thing. */
    next = HT_NEXT_RMV(hs_service_ht, src, iter);
    if (register_service(dst, s) < 0) {
      log_warn(LD_BUG, "Ephemeral service key is already being used. "
                       "Skipping.");
    }
  }
}

/* Return a const string of the directory path escaped. If this is an
 * ephemeral service, it returns "[EPHEMERAL]". This can only be called from
 * the main thread because escaped() uses a static variable. */
static const char *
service_escaped_dir(const hs_service_t *s)
{
  return (s->config.is_ephemeral) ? "[EPHEMERAL]" :
                                    escaped(s->config.directory_path);
}

/* Register services that are in the staging list. Once this function returns,
 * the global service map will be set with the right content and all non
 * surviving services will be cleaned up. */
static void
register_all_services(void)
{
  struct hs_service_ht *new_service_map;
  hs_service_t *s, **iter;

  tor_assert(hs_service_staging_list);

  /* We'll save us some allocation and computing time. */
  if (smartlist_len(hs_service_staging_list) == 0) {
    return;
  }

  /* Allocate a new map that will replace the current one. */
  new_service_map = tor_malloc_zero(sizeof(*new_service_map));
  HT_INIT(hs_service_ht, new_service_map);

  /* First step is to transfer all ephemeral services from the current global
   * map to the new one we are constructing. We do not prune ephemeral
   * services as the only way to kill them is by deleting it from the control
   * port or stopping the tor daemon. */
  move_ephemeral_services(hs_service_map, new_service_map);

  SMARTLIST_FOREACH_BEGIN(hs_service_staging_list, hs_service_t *, snew) {
    /* Check if that service is already in our global map and if so, we'll
     * transfer the intro points to it. */
    s = find_service(hs_service_map, &snew->keys.identity_pk);
    if (s) {
      /* Pass ownership of intro points from s (the current service) to snew
       * (the newly configured one). */
      move_intro_points(s, snew);
      /* Remove the service from the global map because after this, we need to
       * go over the remaining service in that map that aren't surviving the
       * reload to close their circuits. */
      remove_service(hs_service_map, s);
    }
    /* Great, this service is now ready to be added to our new map. */
    if (BUG(register_service(new_service_map, snew) < 0)) {
      /* This should never happen because prior to registration, we validate
       * every service against the entire set. Not being able to register a
       * service means we failed to validate correctly. In that case, don't
       * break tor and ignore the service but tell user. */
      log_warn(LD_BUG, "Unable to register service with directory %s",
               service_escaped_dir(snew));
      SMARTLIST_DEL_CURRENT(hs_service_staging_list, snew);
      hs_service_free(snew);
    }
  } SMARTLIST_FOREACH_END(snew);

  /* Close any circuits associated with the non surviving services. Every
   * service in the current global map are roaming. */
  HT_FOREACH(iter, hs_service_ht, hs_service_map) {
    close_service_circuits(*iter);
  }

  /* Time to make the switch. We'll clear the staging list because its content
   * has now changed ownership to the map. */
  smartlist_clear(hs_service_staging_list);
  service_free_all();
  hs_service_map = new_service_map;
}

/* Write the onion address of a given service to the given filename fname_ in
 * the service directory. Return 0 on success else -1 on error. */
static int
write_address_to_file(const hs_service_t *service, const char *fname_)
{
  int ret = -1;
  char *fname = NULL;
  /* Length of an address plus the sizeof the address tld (onion) which counts
   * the NUL terminated byte so we keep it for the "." and the newline. */
  char buf[HS_SERVICE_ADDR_LEN_BASE32 + sizeof(address_tld) + 1];

  tor_assert(service);
  tor_assert(fname_);

  /* Construct the full address with the onion tld and write the hostname file
   * to disk. */
  tor_snprintf(buf, sizeof(buf), "%s.%s\n", service->onion_address,
               address_tld);
  /* Notice here that we use the given "fname_". */
  fname = hs_path_from_filename(service->config.directory_path, fname_);
  if (write_str_to_file(fname, buf, 0) < 0) {
    log_warn(LD_REND, "Could not write onion address to hostname file %s",
             escaped(fname));
    goto end;
  }

#ifndef _WIN32
  if (service->config.dir_group_readable) {
    /* Mode to 0640. */
    if (chmod(fname, S_IRUSR | S_IWUSR | S_IRGRP) < 0) {
      log_warn(LD_FS, "Unable to make onion service hostname file %s "
                      "group-readable.", escaped(fname));
    }
  }
#endif /* _WIN32 */

  /* Success. */
  ret = 0;
 end:
  tor_free(fname);
  return ret;
}

/* Load and/or generate private keys for the given service. On success, the
 * hostname file will be written to disk along with the master private key iff
 * the service is not configured for offline keys. Return 0 on success else -1
 * on failure. */
static int
load_service_keys(hs_service_t *service)
{
  int ret = -1;
  char *fname = NULL;
  ed25519_keypair_t *kp;
  const hs_service_config_t *config;

  tor_assert(service);

  config = &service->config;

  /* Create and fix permission on service directory. We are about to write
   * files to that directory so make sure it exists and has the right
   * permissions. We do this here because at this stage we know that Tor is
   * actually running and the service we have has been validated. */
  if (BUG(hs_check_service_private_dir(get_options()->User,
                                       config->directory_path,
                                       config->dir_group_readable, 1) < 0)) {
    goto end;
  }

  /* Try to load the keys from file or generate it if not found. */
  fname = hs_path_from_filename(config->directory_path, fname_keyfile_prefix);
  /* Don't ask for key creation, we want to know if we were able to load it or
   * we had to generate it. Better logging! */
  kp = ed_key_init_from_file(fname, 0, LOG_INFO, NULL, 0, 0, 0, NULL);
  if (!kp) {
    log_info(LD_REND, "Unable to load keys from %s. Generating it...", fname);
    /* We'll now try to generate the keys and for it we want the strongest
     * randomness for it. The keypair will be written in different files. */
    uint32_t key_flags = INIT_ED_KEY_CREATE | INIT_ED_KEY_EXTRA_STRONG |
                         INIT_ED_KEY_SPLIT;
    kp = ed_key_init_from_file(fname, key_flags, LOG_WARN, NULL, 0, 0, 0,
                               NULL);
    if (!kp) {
      log_warn(LD_REND, "Unable to generate keys and save in %s.", fname);
      goto end;
    }
  }

  /* Copy loaded or generated keys to service object. */
  ed25519_pubkey_copy(&service->keys.identity_pk, &kp->pubkey);
  memcpy(&service->keys.identity_sk, &kp->seckey,
         sizeof(service->keys.identity_sk));
  /* This does a proper memory wipe. */
  ed25519_keypair_free(kp);

  /* Build onion address from the newly loaded keys. */
  tor_assert(service->config.version <= UINT8_MAX);
  hs_build_address(&service->keys.identity_pk,
                   (uint8_t) service->config.version,
                   service->onion_address);

  /* Write onion address to hostname file. */
  if (write_address_to_file(service, fname_hostname) < 0) {
    goto end;
  }

  /* Succes. */
  ret = 0;
 end:
  tor_free(fname);
  return ret;
}

/* Load and/or generate keys for all onion services including the client
 * authorization if any. Return 0 on success, -1 on failure. */
int
hs_service_load_all_keys(void)
{
  /* Load v2 service keys if we have v2. */
  if (num_rend_services() != 0) {
    if (rend_service_load_all_keys(NULL) < 0) {
      goto err;
    }
  }

  /* Load or/and generate them for v3+. */
  SMARTLIST_FOREACH_BEGIN(hs_service_staging_list, hs_service_t *, service) {
    /* Ignore ephemeral service, they already have their keys set. */
    if (service->config.is_ephemeral) {
      continue;
    }
    log_info(LD_REND, "Loading v3 onion service keys from %s",
             service_escaped_dir(service));
    if (load_service_keys(service) < 0) {
      goto err;
    }
    /* XXX: Load/Generate client authorization keys. (#20700) */
  } SMARTLIST_FOREACH_END(service);

  /* Final step, the staging list contains service in a quiescent state that
   * is ready to be used. Register them to the global map. Once this is over,
   * the staging list will be cleaned up. */
  register_all_services();

  /* All keys have been loaded successfully. */
  return 0;
 err:
  return -1;
}

/* Put all service object in the given service list. After this, the caller
 * looses ownership of every elements in the list and responsible to free the
 * list pointer. */
void
hs_service_stage_services(const smartlist_t *service_list)
{
  tor_assert(service_list);
  /* This list is freed at registration time but this function can be called
   * multiple time. */
  if (hs_service_staging_list == NULL) {
    hs_service_staging_list = smartlist_new();
  }
  /* Add all service object to our staging list. Caller is responsible for
   * freeing the service_list. */
  smartlist_add_all(hs_service_staging_list, service_list);
}

/* Allocate and initilize a service object. The service configuration will
 * contain the default values. Return the newly allocated object pointer. This
 * function can't fail. */
hs_service_t *
hs_service_new(const or_options_t *options)
{
  hs_service_t *service = tor_malloc_zero(sizeof(hs_service_t));
  /* Set default configuration value. */
  set_service_default_config(&service->config, options);
  /* Set the default service version. */
  service->config.version = HS_SERVICE_DEFAULT_VERSION;
  return service;
}

/* Free the given <b>service</b> object and all its content. This function
 * also takes care of wiping service keys from memory. It is safe to pass a
 * NULL pointer. */
void
hs_service_free(hs_service_t *service)
{
  if (service == NULL) {
    return;
  }

  /* Free descriptors. */
  if (service->desc_current) {
    hs_descriptor_free(service->desc_current->desc);
    /* Wipe keys. */
    memwipe(&service->desc_current->signing_kp, 0,
            sizeof(service->desc_current->signing_kp));
    memwipe(&service->desc_current->blinded_kp, 0,
            sizeof(service->desc_current->blinded_kp));
    /* XXX: Free intro points. */
    tor_free(service->desc_current);
  }
  if (service->desc_next) {
    hs_descriptor_free(service->desc_next->desc);
    /* Wipe keys. */
    memwipe(&service->desc_next->signing_kp, 0,
            sizeof(service->desc_next->signing_kp));
    memwipe(&service->desc_next->blinded_kp, 0,
            sizeof(service->desc_next->blinded_kp));
    /* XXX: Free intro points. */
    tor_free(service->desc_next);
  }

  /* Free service configuration. */
  service_clear_config(&service->config);

  /* Wipe service keys. */
  memwipe(&service->keys.identity_sk, 0, sizeof(service->keys.identity_sk));

  tor_free(service);
}

/* Initialize the service HS subsystem. */
void
hs_service_init(void)
{
  /* Should never be called twice. */
  tor_assert(!hs_service_map);
  tor_assert(!hs_service_staging_list);

  /* v2 specific. */
  rend_service_init();

  hs_service_map = tor_malloc_zero(sizeof(struct hs_service_ht));
  HT_INIT(hs_service_ht, hs_service_map);

  hs_service_staging_list = smartlist_new();
}

/* Release all global storage of the hidden service subsystem. */
void
hs_service_free_all(void)
{
  rend_service_free_all();
  service_free_all();
}

/* XXX We don't currently use these functions, apart from generating unittest
   data. When we start implementing the service-side support for prop224 we
   should revisit these functions and use them. */

/** Given an ESTABLISH_INTRO <b>cell</b>, encode it and place its payload in
 *  <b>buf_out</b> which has size <b>buf_out_len</b>. Return the number of
 *  bytes written, or a negative integer if there was an error. */
ssize_t
get_establish_intro_payload(uint8_t *buf_out, size_t buf_out_len,
                            const trn_cell_establish_intro_t *cell)
{
  ssize_t bytes_used = 0;

  if (buf_out_len < RELAY_PAYLOAD_SIZE) {
    return -1;
  }

  bytes_used = trn_cell_establish_intro_encode(buf_out, buf_out_len,
                                              cell);
  return bytes_used;
}

/* Set the cell extensions of <b>cell</b>. */
static void
set_trn_cell_extensions(trn_cell_establish_intro_t *cell)
{
  trn_cell_extension_t *trn_cell_extensions = trn_cell_extension_new();

  /* For now, we don't use extensions at all. */
  trn_cell_extensions->num = 0; /* It's already zeroed, but be explicit. */
  trn_cell_establish_intro_set_extensions(cell, trn_cell_extensions);
}

/** Given the circuit handshake info in <b>circuit_key_material</b>, create and
 *  return an ESTABLISH_INTRO cell. Return NULL if something went wrong.  The
 *  returned cell is allocated on the heap and it's the responsibility of the
 *  caller to free it. */
trn_cell_establish_intro_t *
generate_establish_intro_cell(const uint8_t *circuit_key_material,
                              size_t circuit_key_material_len)
{
  trn_cell_establish_intro_t *cell = NULL;
  ssize_t encoded_len;

  log_warn(LD_GENERAL,
           "Generating ESTABLISH_INTRO cell (key_material_len: %u)",
           (unsigned) circuit_key_material_len);

  /* Generate short-term keypair for use in ESTABLISH_INTRO */
  ed25519_keypair_t key_struct;
  if (ed25519_keypair_generate(&key_struct, 0) < 0) {
    goto err;
  }

  cell = trn_cell_establish_intro_new();

  /* Set AUTH_KEY_TYPE: 2 means ed25519 */
  trn_cell_establish_intro_set_auth_key_type(cell,
                                             HS_INTRO_AUTH_KEY_TYPE_ED25519);

  /* Set AUTH_KEY_LEN field */
  /* Must also set byte-length of AUTH_KEY to match */
  int auth_key_len = ED25519_PUBKEY_LEN;
  trn_cell_establish_intro_set_auth_key_len(cell, auth_key_len);
  trn_cell_establish_intro_setlen_auth_key(cell, auth_key_len);

  /* Set AUTH_KEY field */
  uint8_t *auth_key_ptr = trn_cell_establish_intro_getarray_auth_key(cell);
  memcpy(auth_key_ptr, key_struct.pubkey.pubkey, auth_key_len);

  /* No cell extensions needed */
  set_trn_cell_extensions(cell);

  /* Set signature size.
     We need to do this up here, because _encode() needs it and we need to call
     _encode() to calculate the MAC and signature.
  */
  int sig_len = ED25519_SIG_LEN;
  trn_cell_establish_intro_set_sig_len(cell, sig_len);
  trn_cell_establish_intro_setlen_sig(cell, sig_len);

  /* XXX How to make this process easier and nicer? */

  /* Calculate the cell MAC (aka HANDSHAKE_AUTH). */
  {
    /* To calculate HANDSHAKE_AUTH, we dump the cell in bytes, and then derive
       the MAC from it. */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    uint8_t mac[TRUNNEL_SHA3_256_LEN];

    encoded_len = trn_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell.");
      goto err;
    }

    /* sanity check */
    tor_assert(encoded_len > ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN);

    /* Calculate MAC of all fields before HANDSHAKE_AUTH */
    crypto_mac_sha3_256(mac, sizeof(mac),
                        circuit_key_material, circuit_key_material_len,
                        cell_bytes_tmp,
                        encoded_len -
                          (ED25519_SIG_LEN + 2 + TRUNNEL_SHA3_256_LEN));
    /* Write the MAC to the cell */
    uint8_t *handshake_ptr =
      trn_cell_establish_intro_getarray_handshake_mac(cell);
    memcpy(handshake_ptr, mac, sizeof(mac));
  }

  /* Calculate the cell signature */
  {
    /* To calculate the sig we follow the same procedure as above. We first
       dump the cell up to the sig, and then calculate the sig */
    uint8_t cell_bytes_tmp[RELAY_PAYLOAD_SIZE] = {0};
    ed25519_signature_t sig;

    encoded_len = trn_cell_establish_intro_encode(cell_bytes_tmp,
                                                 sizeof(cell_bytes_tmp),
                                                 cell);
    if (encoded_len < 0) {
      log_warn(LD_OR, "Unable to pre-encode ESTABLISH_INTRO cell (2).");
      goto err;
    }

    tor_assert(encoded_len > ED25519_SIG_LEN);

    if (ed25519_sign_prefixed(&sig,
                              cell_bytes_tmp,
                              encoded_len -
                                (ED25519_SIG_LEN + sizeof(cell->sig_len)),
                              ESTABLISH_INTRO_SIG_PREFIX,
                              &key_struct)) {
      log_warn(LD_BUG, "Unable to gen signature for ESTABLISH_INTRO cell.");
      goto err;
    }

    /* And write the signature to the cell */
    uint8_t *sig_ptr = trn_cell_establish_intro_getarray_sig(cell);
    memcpy(sig_ptr, sig.sig, sig_len);
  }

  /* We are done! Return the cell! */
  return cell;

 err:
  trn_cell_establish_intro_free(cell);
  return NULL;
}

#ifdef TOR_UNIT_TESTS

/* Return the global service map size. Only used by unit test. */
STATIC unsigned int
get_hs_service_map_size(void)
{
  return HT_SIZE(hs_service_map);
}

/* Return the staging list size. Only used by unit test. */
STATIC int
get_hs_service_staging_list_size(void)
{
  return smartlist_len(hs_service_staging_list);
}

STATIC hs_service_ht *
get_hs_service_map(void)
{
  return hs_service_map;
}

STATIC hs_service_t *
get_first_service(void)
{
  hs_service_t **obj = HT_START(hs_service_ht, hs_service_map);
  if (obj == NULL) {
    return NULL;
  }
  return *obj;
}

#endif /* TOR_UNIT_TESTS */

