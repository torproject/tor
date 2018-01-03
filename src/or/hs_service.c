/* Copyright (c) 2016-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_service.c
 * \brief Implement next generation hidden service functionality
 **/

#define HS_SERVICE_PRIVATE

#include "or.h"
#include "circpathbias.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "circuituse.h"
#include "config.h"
#include "connection.h"
#include "directory.h"
#include "main.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "relay.h"
#include "rendservice.h"
#include "router.h"
#include "routerkeys.h"
#include "routerlist.h"
#include "shared_random_state.h"
#include "statefile.h"

#include "hs_circuit.h"
#include "hs_common.h"
#include "hs_config.h"
#include "hs_circuit.h"
#include "hs_descriptor.h"
#include "hs_ident.h"
#include "hs_intropoint.h"
#include "hs_service.h"

/* Trunnel */
#include "ed25519_cert.h"
#include "hs/cell_common.h"
#include "hs/cell_establish_intro.h"

/* Helper macro. Iterate over every service in the global map. The var is the
 * name of the service pointer. */
#define FOR_EACH_SERVICE_BEGIN(var)                          \
    STMT_BEGIN                                               \
    hs_service_t **var##_iter, *var;                         \
    HT_FOREACH(var##_iter, hs_service_ht, hs_service_map) {  \
      var = *var##_iter;
#define FOR_EACH_SERVICE_END } STMT_END ;

/* Helper macro. Iterate over both current and previous descriptor of a
 * service. The var is the name of the descriptor pointer. This macro skips
 * any descriptor object of the service that is NULL. */
#define FOR_EACH_DESCRIPTOR_BEGIN(service, var)                  \
  STMT_BEGIN                                                     \
    hs_service_descriptor_t *var;                                \
    for (int var ## _loop_idx = 0; var ## _loop_idx < 2;         \
         ++var ## _loop_idx) {                                   \
      (var ## _loop_idx == 0) ? (var = service->desc_current) :  \
                                (var = service->desc_next);      \
      if (var == NULL) continue;
#define FOR_EACH_DESCRIPTOR_END } STMT_END ;

/* Onion service directory file names. */
static const char fname_keyfile_prefix[] = "hs_ed25519";
static const char fname_hostname[] = "hostname";
static const char address_tld[] = "onion";

/* Staging list of service object. When configuring service, we add them to
 * this list considered a staging area and they will get added to our global
 * map once the keys have been loaded. These two steps are seperated because
 * loading keys requires that we are an actual running tor process. */
static smartlist_t *hs_service_staging_list;

/** True if the list of available router descriptors might have changed which
 *  might result in an altered hash ring. Check if the hash ring changed and
 *  reupload if needed */
static int consider_republishing_hs_descriptors = 0;

static void set_descriptor_revision_counter(hs_descriptor_t *hs_desc);
static void move_descriptors(hs_service_t *src, hs_service_t *dst);

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
  (void) options;
  tor_assert(c);
  c->ports = smartlist_new();
  c->directory_path = NULL;
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

/* Helper function to return a human readable description of the given intro
 * point object.
 *
 * This function is not thread-safe. Each call to this invalidates the
 * previous values returned by it. */
static const char *
describe_intro_point(const hs_service_intro_point_t *ip)
{
  /* Hex identity digest of the IP prefixed by the $ sign and ends with NUL
   * byte hence the plus two. */
  static char buf[HEX_DIGEST_LEN + 2];
  const char *legacy_id = NULL;

  SMARTLIST_FOREACH_BEGIN(ip->base.link_specifiers,
                          const hs_desc_link_specifier_t *, lspec) {
    if (lspec->type == LS_LEGACY_ID) {
      legacy_id = (const char *) lspec->u.legacy_id;
      break;
    }
  } SMARTLIST_FOREACH_END(lspec);

  /* For now, we only print the identity digest but we could improve this with
   * much more information such as the ed25519 identity has well. */
  buf[0] = '$';
  if (legacy_id) {
    base16_encode(buf + 1, HEX_DIGEST_LEN + 1, legacy_id, DIGEST_LEN);
  }

  return buf;
}

/* Return the lower bound of maximum INTRODUCE2 cells per circuit before we
 * rotate intro point (defined by a consensus parameter or the default
 * value). */
static int32_t
get_intro_point_min_introduce2(void)
{
  /* The [0, 2147483647] range is quite large to accomodate anything we decide
   * in the future. */
  return networkstatus_get_param(NULL, "hs_intro_min_introduce2",
                                 INTRO_POINT_MIN_LIFETIME_INTRODUCTIONS,
                                 0, INT32_MAX);
}

/* Return the upper bound of maximum INTRODUCE2 cells per circuit before we
 * rotate intro point (defined by a consensus parameter or the default
 * value). */
static int32_t
get_intro_point_max_introduce2(void)
{
  /* The [0, 2147483647] range is quite large to accomodate anything we decide
   * in the future. */
  return networkstatus_get_param(NULL, "hs_intro_max_introduce2",
                                 INTRO_POINT_MAX_LIFETIME_INTRODUCTIONS,
                                 0, INT32_MAX);
}

/* Return the minimum lifetime in seconds of an introduction point defined by a
 * consensus parameter or the default value. */
static int32_t
get_intro_point_min_lifetime(void)
{
#define MIN_INTRO_POINT_LIFETIME_TESTING 10
  if (get_options()->TestingTorNetwork) {
    return MIN_INTRO_POINT_LIFETIME_TESTING;
  }

  /* The [0, 2147483647] range is quite large to accomodate anything we decide
   * in the future. */
  return networkstatus_get_param(NULL, "hs_intro_min_lifetime",
                                 INTRO_POINT_LIFETIME_MIN_SECONDS,
                                 0, INT32_MAX);
}

/* Return the maximum lifetime in seconds of an introduction point defined by a
 * consensus parameter or the default value. */
static int32_t
get_intro_point_max_lifetime(void)
{
#define MAX_INTRO_POINT_LIFETIME_TESTING 30
  if (get_options()->TestingTorNetwork) {
    return MAX_INTRO_POINT_LIFETIME_TESTING;
  }

  /* The [0, 2147483647] range is quite large to accomodate anything we decide
   * in the future. */
  return networkstatus_get_param(NULL, "hs_intro_max_lifetime",
                                 INTRO_POINT_LIFETIME_MAX_SECONDS,
                                 0, INT32_MAX);
}

/* Return the number of extra introduction point defined by a consensus
 * parameter or the default value. */
static int32_t
get_intro_point_num_extra(void)
{
  /* The [0, 128] range bounds the number of extra introduction point allowed.
   * Above 128 intro points, it's getting a bit crazy. */
  return networkstatus_get_param(NULL, "hs_intro_num_extra",
                                 NUM_INTRO_POINTS_EXTRA, 0, 128);
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

/* Free a given service intro point object. */
STATIC void
service_intro_point_free(hs_service_intro_point_t *ip)
{
  if (!ip) {
    return;
  }
  memwipe(&ip->auth_key_kp, 0, sizeof(ip->auth_key_kp));
  memwipe(&ip->enc_key_kp, 0, sizeof(ip->enc_key_kp));
  crypto_pk_free(ip->legacy_key);
  replaycache_free(ip->replay_cache);
  hs_intropoint_clear(&ip->base);
  tor_free(ip);
}

/* Helper: free an hs_service_intro_point_t object. This function is used by
 * digest256map_free() which requires a void * pointer. */
static void
service_intro_point_free_(void *obj)
{
  service_intro_point_free(obj);
}

/* Return a newly allocated service intro point and fully initialized from the
 * given extend_info_t ei if non NULL. If is_legacy is true, we also generate
 * the legacy key. On error, NULL is returned.
 *
 * If ei is NULL, returns a hs_service_intro_point_t with an empty link
 * specifier list and no onion key. (This is used for testing.)
 *
 * ei must be an extend_info_t containing an IPv4 address. (We will add supoort
 * for IPv6 in a later release.) When calling extend_info_from_node(), pass
 * 0 in for_direct_connection to make sure ei always has an IPv4 address. */
STATIC hs_service_intro_point_t *
service_intro_point_new(const extend_info_t *ei, unsigned int is_legacy)
{
  hs_desc_link_specifier_t *ls;
  hs_service_intro_point_t *ip;

  ip = tor_malloc_zero(sizeof(*ip));
  /* We'll create the key material. No need for extra strong, those are short
   * term keys. */
  ed25519_keypair_generate(&ip->auth_key_kp, 0);

  { /* Set introduce2 max cells limit */
    int32_t min_introduce2_cells = get_intro_point_min_introduce2();
    int32_t max_introduce2_cells = get_intro_point_max_introduce2();
    if (BUG(max_introduce2_cells < min_introduce2_cells)) {
      goto err;
    }
    ip->introduce2_max = crypto_rand_int_range(min_introduce2_cells,
                                               max_introduce2_cells);
  }
  { /* Set intro point lifetime */
    int32_t intro_point_min_lifetime = get_intro_point_min_lifetime();
    int32_t intro_point_max_lifetime = get_intro_point_max_lifetime();
    if (BUG(intro_point_max_lifetime < intro_point_min_lifetime)) {
      goto err;
    }
    ip->time_to_expire = time(NULL) +
      crypto_rand_int_range(intro_point_min_lifetime,intro_point_max_lifetime);
  }

  ip->replay_cache = replaycache_new(0, 0);

  /* Initialize the base object. We don't need the certificate object. */
  ip->base.link_specifiers = smartlist_new();

  /* Generate the encryption key for this intro point. */
  curve25519_keypair_generate(&ip->enc_key_kp, 0);
  /* Figure out if this chosen node supports v3 or is legacy only. */
  if (is_legacy) {
    ip->base.is_only_legacy = 1;
    /* Legacy mode that is doesn't support v3+ with ed25519 auth key. */
    ip->legacy_key = crypto_pk_new();
    if (crypto_pk_generate_key(ip->legacy_key) < 0) {
      goto err;
    }
  }

  if (ei == NULL) {
    goto done;
  }

  /* We'll try to add all link specifiers. Legacy is mandatory.
   * IPv4 or IPv6 is required, and we always send IPv4. */
  ls = hs_desc_link_specifier_new(ei, LS_IPV4);
  /* It is impossible to have an extend info object without a v4. */
  if (BUG(!ls)) {
    goto err;
  }
  smartlist_add(ip->base.link_specifiers, ls);

  ls = hs_desc_link_specifier_new(ei, LS_LEGACY_ID);
  /* It is impossible to have an extend info object without an identity
   * digest. */
  if (BUG(!ls)) {
    goto err;
  }
  smartlist_add(ip->base.link_specifiers, ls);

  /* ed25519 identity key is optional for intro points */
  ls = hs_desc_link_specifier_new(ei, LS_ED25519_ID);
  if (ls) {
    smartlist_add(ip->base.link_specifiers, ls);
  }

  /* IPv6 is not supported in this release. */

  /* Finally, copy onion key from the extend_info_t object. */
  memcpy(&ip->onion_key, &ei->curve25519_onion_key, sizeof(ip->onion_key));

 done:
  return ip;
 err:
  service_intro_point_free(ip);
  return NULL;
}

/* Add the given intro point object to the given intro point map. The intro
 * point MUST have its RSA encryption key set if this is a legacy type or the
 * authentication key set otherwise. */
STATIC void
service_intro_point_add(digest256map_t *map, hs_service_intro_point_t *ip)
{
  hs_service_intro_point_t *old_ip_entry;

  tor_assert(map);
  tor_assert(ip);

  old_ip_entry = digest256map_set(map, ip->auth_key_kp.pubkey.pubkey, ip);
  /* Make sure we didn't just try to double-add an intro point */
  tor_assert_nonfatal(!old_ip_entry);
}

/* For a given service, remove the intro point from that service's descriptors
 * (check both current and next descriptor) */
STATIC void
service_intro_point_remove(const hs_service_t *service,
                           const hs_service_intro_point_t *ip)
{
  tor_assert(service);
  tor_assert(ip);

  /* Trying all descriptors. */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    /* We'll try to remove the descriptor on both descriptors which is not
     * very expensive to do instead of doing loopup + remove. */
    digest256map_remove(desc->intro_points.map,
                        ip->auth_key_kp.pubkey.pubkey);
  } FOR_EACH_DESCRIPTOR_END;
}

/* For a given service and authentication key, return the intro point or NULL
 * if not found. This will check both descriptors in the service. */
STATIC hs_service_intro_point_t *
service_intro_point_find(const hs_service_t *service,
                         const ed25519_public_key_t *auth_key)
{
  hs_service_intro_point_t *ip = NULL;

  tor_assert(service);
  tor_assert(auth_key);

  /* Trying all descriptors to find the right intro point.
   *
   * Even if we use the same node as intro point in both descriptors, the node
   * will have a different intro auth key for each descriptor since we generate
   * a new one everytime we pick an intro point.
   *
   * After #22893 gets implemented, intro points will be moved to be
   * per-service instead of per-descriptor so this function will need to
   * change.
   */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    if ((ip = digest256map_get(desc->intro_points.map,
                               auth_key->pubkey)) != NULL) {
      break;
    }
  } FOR_EACH_DESCRIPTOR_END;

  return ip;
}

/* For a given service and intro point, return the descriptor for which the
 * intro point is assigned to. NULL is returned if not found. */
STATIC hs_service_descriptor_t *
service_desc_find_by_intro(const hs_service_t *service,
                           const hs_service_intro_point_t *ip)
{
  hs_service_descriptor_t *descp = NULL;

  tor_assert(service);
  tor_assert(ip);

  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    if (digest256map_get(desc->intro_points.map,
                         ip->auth_key_kp.pubkey.pubkey)) {
      descp = desc;
      break;
    }
  } FOR_EACH_DESCRIPTOR_END;

  return descp;
}

/* From a circuit identifier, get all the possible objects associated with the
 * ident. If not NULL, service, ip or desc are set if the object can be found.
 * They are untouched if they can't be found.
 *
 * This is an helper function because we do those lookups often so it's more
 * convenient to simply call this functions to get all the things at once. */
STATIC void
get_objects_from_ident(const hs_ident_circuit_t *ident,
                       hs_service_t **service, hs_service_intro_point_t **ip,
                       hs_service_descriptor_t **desc)
{
  hs_service_t *s;

  tor_assert(ident);

  /* Get service object from the circuit identifier. */
  s = find_service(hs_service_map, &ident->identity_pk);
  if (s && service) {
    *service = s;
  }

  /* From the service object, get the intro point object of that circuit. The
   * following will query both descriptors intro points list. */
  if (s && ip) {
    *ip = service_intro_point_find(s, &ident->intro_auth_pk);
  }

  /* Get the descriptor for this introduction point and service. */
  if (s && ip && *ip && desc) {
    *desc = service_desc_find_by_intro(s, *ip);
  }
}

/* From a given intro point, return the first link specifier of type
 * encountered in the link specifier list. Return NULL if it can't be found.
 *
 * The caller does NOT have ownership of the object, the intro point does. */
static hs_desc_link_specifier_t *
get_link_spec_by_type(const hs_service_intro_point_t *ip, uint8_t type)
{
  hs_desc_link_specifier_t *lnk_spec = NULL;

  tor_assert(ip);

  SMARTLIST_FOREACH_BEGIN(ip->base.link_specifiers,
                          hs_desc_link_specifier_t *, ls) {
    if (ls->type == type) {
      lnk_spec = ls;
      goto end;
    }
  } SMARTLIST_FOREACH_END(ls);

 end:
  return lnk_spec;
}

/* Given a service intro point, return the node_t associated to it. This can
 * return NULL if the given intro point has no legacy ID or if the node can't
 * be found in the consensus. */
STATIC const node_t *
get_node_from_intro_point(const hs_service_intro_point_t *ip)
{
  const hs_desc_link_specifier_t *ls;

  tor_assert(ip);

  ls = get_link_spec_by_type(ip, LS_LEGACY_ID);
  if (BUG(!ls)) {
    return NULL;
  }
  /* XXX In the future, we want to only use the ed25519 ID (#22173). */
  return node_get_by_id((const char *) ls->u.legacy_id);
}

/* Given a service intro point, return the extend_info_t for it. This can
 * return NULL if the node can't be found for the intro point or the extend
 * info can't be created for the found node. If direct_conn is set, the extend
 * info is validated on if we can connect directly. */
static extend_info_t *
get_extend_info_from_intro_point(const hs_service_intro_point_t *ip,
                                 unsigned int direct_conn)
{
  extend_info_t *info = NULL;
  const node_t *node;

  tor_assert(ip);

  node = get_node_from_intro_point(ip);
  if (node == NULL) {
    /* This can happen if the relay serving as intro point has been removed
     * from the consensus. In that case, the intro point will be removed from
     * the descriptor during the scheduled events. */
    goto end;
  }

  /* In the case of a direct connection (single onion service), it is possible
   * our firewall policy won't allow it so this can return a NULL value. */
  info = extend_info_from_node(node, direct_conn);

 end:
  return info;
}

/* Return the number of introduction points that are established for the
 * given descriptor. */
static unsigned int
count_desc_circuit_established(const hs_service_descriptor_t *desc)
{
  unsigned int count = 0;

  tor_assert(desc);

  DIGEST256MAP_FOREACH(desc->intro_points.map, key,
                       const hs_service_intro_point_t *, ip) {
    count += ip->circuit_established;
  } DIGEST256MAP_FOREACH_END;

  return count;
}

/* For a given service and descriptor of that service, close all active
 * directory connections. */
static void
close_directory_connections(const hs_service_t *service,
                            const hs_service_descriptor_t *desc)
{
  unsigned int count = 0;
  smartlist_t *dir_conns;

  tor_assert(service);
  tor_assert(desc);

  /* Close pending HS desc upload connections for the blinded key of 'desc'. */
  dir_conns = connection_list_by_type_purpose(CONN_TYPE_DIR,
                                              DIR_PURPOSE_UPLOAD_HSDESC);
  SMARTLIST_FOREACH_BEGIN(dir_conns, connection_t *, conn) {
    dir_connection_t *dir_conn = TO_DIR_CONN(conn);
    if (ed25519_pubkey_eq(&dir_conn->hs_ident->identity_pk,
                          &service->keys.identity_pk) &&
        ed25519_pubkey_eq(&dir_conn->hs_ident->blinded_pk,
                          &desc->blinded_kp.pubkey)) {
      connection_mark_for_close(conn);
      count++;
      continue;
    }
  } SMARTLIST_FOREACH_END(conn);

  log_info(LD_REND, "Closed %u active service directory connections for "
                    "descriptor %s of service %s",
           count, safe_str_client(ed25519_fmt(&desc->blinded_kp.pubkey)),
           safe_str_client(service->onion_address));
  /* We don't have ownership of the objects in this list. */
  smartlist_free(dir_conns);
}

/* Close all rendezvous circuits for the given service. */
static void
close_service_rp_circuits(hs_service_t *service)
{
  origin_circuit_t *ocirc = NULL;

  tor_assert(service);

  /* The reason we go over all circuit instead of using the circuitmap API is
   * because most hidden service circuits are rendezvous circuits so there is
   * no real improvement at getting all rendezvous circuits from the
   * circuitmap and then going over them all to find the right ones.
   * Furthermore, another option would have been to keep a list of RP cookies
   * for a service but it creates an engineering complexity since we don't
   * have a "RP circuit closed" event to clean it up properly so we avoid a
   * memory DoS possibility. */

  while ((ocirc = circuit_get_next_service_rp_circ(ocirc))) {
    /* Only close circuits that are v3 and for this service. */
    if (ocirc->hs_ident != NULL &&
        ed25519_pubkey_eq(&ocirc->hs_ident->identity_pk,
                          &service->keys.identity_pk)) {
      /* Reason is FINISHED because service has been removed and thus the
       * circuit is considered old/uneeded. When freed, it is removed from the
       * hs circuitmap. */
      circuit_mark_for_close(TO_CIRCUIT(ocirc), END_CIRC_REASON_FINISHED);
    }
  }
}

/* Close the circuit(s) for the given map of introduction points. */
static void
close_intro_circuits(hs_service_intropoints_t *intro_points)
{
  tor_assert(intro_points);

  DIGEST256MAP_FOREACH(intro_points->map, key,
                       const hs_service_intro_point_t *, ip) {
    origin_circuit_t *ocirc = hs_circ_service_get_intro_circ(ip);
    if (ocirc) {
      /* Reason is FINISHED because service has been removed and thus the
       * circuit is considered old/uneeded. When freed, the circuit is removed
       * from the HS circuitmap. */
      circuit_mark_for_close(TO_CIRCUIT(ocirc), END_CIRC_REASON_FINISHED);
    }
  } DIGEST256MAP_FOREACH_END;
}

/* Close all introduction circuits for the given service. */
static void
close_service_intro_circuits(hs_service_t *service)
{
  tor_assert(service);

  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    close_intro_circuits(&desc->intro_points);
  } FOR_EACH_DESCRIPTOR_END;
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

/** Move the hidden service state from <b>src</b> to <b>dst</b>. We do this
 *  when we receive a SIGHUP: <b>dst</b> is the post-HUP service */
static void
move_hs_state(hs_service_t *src_service, hs_service_t *dst_service)
{
  tor_assert(src_service);
  tor_assert(dst_service);

  hs_service_state_t *src = &src_service->state;
  hs_service_state_t *dst = &dst_service->state;

  /* Let's do a shallow copy */
  dst->intro_circ_retry_started_time = src->intro_circ_retry_started_time;
  dst->num_intro_circ_launched = src->num_intro_circ_launched;
  dst->replay_cache_rend_cookie = src->replay_cache_rend_cookie;

  src->replay_cache_rend_cookie = NULL; /* steal pointer reference */
}

/* Register services that are in the staging list. Once this function returns,
 * the global service map will be set with the right content and all non
 * surviving services will be cleaned up. */
static void
register_all_services(void)
{
  struct hs_service_ht *new_service_map;

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
    hs_service_t *s;

    /* Check if that service is already in our global map and if so, we'll
     * transfer the intro points to it. */
    s = find_service(hs_service_map, &snew->keys.identity_pk);
    if (s) {
      /* Pass ownership of the descriptors from s (the current service) to
       * snew (the newly configured one). */
      move_descriptors(s, snew);
      move_hs_state(s, snew);
      /* Remove the service from the global map because after this, we need to
       * go over the remaining service in that map that aren't surviving the
       * reload to close their circuits. */
      remove_service(hs_service_map, s);
      hs_service_free(s);
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
  FOR_EACH_SERVICE_BEGIN(service) {
    close_service_circuits(service);
  } FOR_EACH_SERVICE_END;

  /* Time to make the switch. We'll clear the staging list because its content
   * has now changed ownership to the map. */
  smartlist_clear(hs_service_staging_list);
  service_free_all();
  hs_service_map = new_service_map;
}

/* Write the onion address of a given service to the given filename fname_ in
 * the service directory. Return 0 on success else -1 on error. */
STATIC int
write_address_to_file(const hs_service_t *service, const char *fname_)
{
  int ret = -1;
  char *fname = NULL;
  char *addr_buf = NULL;

  tor_assert(service);
  tor_assert(fname_);

  /* Construct the full address with the onion tld and write the hostname file
   * to disk. */
  tor_asprintf(&addr_buf, "%s.%s\n", service->onion_address, address_tld);
  /* Notice here that we use the given "fname_". */
  fname = hs_path_from_filename(service->config.directory_path, fname_);
  if (write_str_to_file(fname, addr_buf, 0) < 0) {
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
#endif /* !defined(_WIN32) */

  /* Success. */
  ret = 0;
 end:
  tor_free(fname);
  tor_free(addr_buf);
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
  kp = ed_key_init_from_file(fname, INIT_ED_KEY_SPLIT, LOG_INFO, NULL, 0, 0,
                             0, NULL);
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

/* Free a given service descriptor object and all key material is wiped. */
STATIC void
service_descriptor_free(hs_service_descriptor_t *desc)
{
  if (!desc) {
    return;
  }
  hs_descriptor_free(desc->desc);
  memwipe(&desc->signing_kp, 0, sizeof(desc->signing_kp));
  memwipe(&desc->blinded_kp, 0, sizeof(desc->blinded_kp));
  /* Cleanup all intro points. */
  digest256map_free(desc->intro_points.map, service_intro_point_free_);
  digestmap_free(desc->intro_points.failed_id, tor_free_);
  if (desc->previous_hsdirs) {
    SMARTLIST_FOREACH(desc->previous_hsdirs, char *, s, tor_free(s));
    smartlist_free(desc->previous_hsdirs);
  }
  tor_free(desc);
}

/* Return a newly allocated service descriptor object. */
STATIC hs_service_descriptor_t *
service_descriptor_new(void)
{
  hs_service_descriptor_t *sdesc = tor_malloc_zero(sizeof(*sdesc));
  sdesc->desc = tor_malloc_zero(sizeof(hs_descriptor_t));
  /* Initialize the intro points map. */
  sdesc->intro_points.map = digest256map_new();
  sdesc->intro_points.failed_id = digestmap_new();
  sdesc->previous_hsdirs = smartlist_new();
  return sdesc;
}

/* Move descriptor(s) from the src service to the dst service. We do this
 * during SIGHUP when we re-create our hidden services. */
static void
move_descriptors(hs_service_t *src, hs_service_t *dst)
{
  tor_assert(src);
  tor_assert(dst);

  if (src->desc_current) {
    /* Nothing should be there, but clean it up just in case */
    if (BUG(dst->desc_current)) {
      service_descriptor_free(dst->desc_current);
    }
    dst->desc_current = src->desc_current;
    src->desc_current = NULL;
  }

  if (src->desc_next) {
    /* Nothing should be there, but clean it up just in case */
    if (BUG(dst->desc_next)) {
      service_descriptor_free(dst->desc_next);
    }
    dst->desc_next = src->desc_next;
    src->desc_next = NULL;
  }
}

/* From the given service, remove all expired failing intro points for each
 * descriptor. */
static void
remove_expired_failing_intro(hs_service_t *service, time_t now)
{
  tor_assert(service);

  /* For both descriptors, cleanup the failing intro points list. */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    DIGESTMAP_FOREACH_MODIFY(desc->intro_points.failed_id, key, time_t *, t) {
      time_t failure_time = *t;
      if ((failure_time + INTRO_CIRC_RETRY_PERIOD) <= now) {
        MAP_DEL_CURRENT(key);
        tor_free(t);
      }
    } DIGESTMAP_FOREACH_END;
  } FOR_EACH_DESCRIPTOR_END;
}

/* For the given descriptor desc, put all node_t object found from its failing
 * intro point list and put them in the given node_list. */
static void
setup_intro_point_exclude_list(const hs_service_descriptor_t *desc,
                               smartlist_t *node_list)
{
  tor_assert(desc);
  tor_assert(node_list);

  DIGESTMAP_FOREACH(desc->intro_points.failed_id, key, time_t *, t) {
    (void) t; /* Make gcc happy. */
    const node_t *node = node_get_by_id(key);
    if (node) {
      smartlist_add(node_list, (void *) node);
    }
  } DIGESTMAP_FOREACH_END;
}

/* For the given failing intro point ip, we add its time of failure to the
 * failed map and index it by identity digest (legacy ID) in the descriptor
 * desc failed id map. */
static void
remember_failing_intro_point(const hs_service_intro_point_t *ip,
                             hs_service_descriptor_t *desc, time_t now)
{
  time_t *time_of_failure, *prev_ptr;
  const hs_desc_link_specifier_t *legacy_ls;

  tor_assert(ip);
  tor_assert(desc);

  time_of_failure = tor_malloc_zero(sizeof(time_t));
  *time_of_failure = now;
  legacy_ls = get_link_spec_by_type(ip, LS_LEGACY_ID);
  tor_assert(legacy_ls);
  prev_ptr = digestmap_set(desc->intro_points.failed_id,
                           (const char *) legacy_ls->u.legacy_id,
                           time_of_failure);
  tor_free(prev_ptr);
}

/* Copy the descriptor link specifier object from src to dst. */
static void
link_specifier_copy(hs_desc_link_specifier_t *dst,
                    const hs_desc_link_specifier_t *src)
{
  tor_assert(dst);
  tor_assert(src);
  memcpy(dst, src, sizeof(hs_desc_link_specifier_t));
}

/* Using a given descriptor signing keypair signing_kp, a service intro point
 * object ip and the time now, setup the content of an already allocated
 * descriptor intro desc_ip.
 *
 * Return 0 on success else a negative value. */
static int
setup_desc_intro_point(const ed25519_keypair_t *signing_kp,
                       const hs_service_intro_point_t *ip,
                       time_t now, hs_desc_intro_point_t *desc_ip)
{
  int ret = -1;
  time_t nearest_hour = now - (now % 3600);

  tor_assert(signing_kp);
  tor_assert(ip);
  tor_assert(desc_ip);

  /* Copy the onion key. */
  memcpy(&desc_ip->onion_key, &ip->onion_key, sizeof(desc_ip->onion_key));

  /* Key and certificate material. */
  desc_ip->auth_key_cert = tor_cert_create(signing_kp,
                                           CERT_TYPE_AUTH_HS_IP_KEY,
                                           &ip->auth_key_kp.pubkey,
                                           nearest_hour,
                                           HS_DESC_CERT_LIFETIME,
                                           CERT_FLAG_INCLUDE_SIGNING_KEY);
  if (desc_ip->auth_key_cert == NULL) {
    log_warn(LD_REND, "Unable to create intro point auth-key certificate");
    goto done;
  }

  /* Copy link specifier(s). */
  SMARTLIST_FOREACH_BEGIN(ip->base.link_specifiers,
                          const hs_desc_link_specifier_t *, ls) {
    hs_desc_link_specifier_t *copy = tor_malloc_zero(sizeof(*copy));
    link_specifier_copy(copy, ls);
    smartlist_add(desc_ip->link_specifiers, copy);
  } SMARTLIST_FOREACH_END(ls);

  /* For a legacy intro point, we'll use an RSA/ed cross certificate. */
  if (ip->base.is_only_legacy) {
    desc_ip->legacy.key = crypto_pk_dup_key(ip->legacy_key);
    /* Create cross certification cert. */
    ssize_t cert_len = tor_make_rsa_ed25519_crosscert(
                                    &signing_kp->pubkey,
                                    desc_ip->legacy.key,
                                    nearest_hour + HS_DESC_CERT_LIFETIME,
                                    &desc_ip->legacy.cert.encoded);
    if (cert_len < 0) {
      log_warn(LD_REND, "Unable to create enc key legacy cross cert.");
      goto done;
    }
    desc_ip->legacy.cert.len = cert_len;
  }

  /* Encryption key and its cross certificate. */
  {
    ed25519_public_key_t ed25519_pubkey;

    /* Use the public curve25519 key. */
    memcpy(&desc_ip->enc_key, &ip->enc_key_kp.pubkey,
           sizeof(desc_ip->enc_key));
    /* The following can't fail. */
    ed25519_public_key_from_curve25519_public_key(&ed25519_pubkey,
                                                  &ip->enc_key_kp.pubkey,
                                                  0);
    desc_ip->enc_key_cert = tor_cert_create(signing_kp,
                                            CERT_TYPE_CROSS_HS_IP_KEYS,
                                            &ed25519_pubkey, nearest_hour,
                                            HS_DESC_CERT_LIFETIME,
                                            CERT_FLAG_INCLUDE_SIGNING_KEY);
    if (desc_ip->enc_key_cert == NULL) {
      log_warn(LD_REND, "Unable to create enc key curve25519 cross cert.");
      goto done;
    }
  }
  /* Success. */
  ret = 0;

 done:
  return ret;
}

/* Using the given descriptor from the given service, build the descriptor
 * intro point list so we can then encode the descriptor for publication. This
 * function does not pick intro points, they have to be in the descriptor
 * current map. Cryptographic material (keys) must be initialized in the
 * descriptor for this function to make sense. */
static void
build_desc_intro_points(const hs_service_t *service,
                        hs_service_descriptor_t *desc, time_t now)
{
  hs_desc_encrypted_data_t *encrypted;

  tor_assert(service);
  tor_assert(desc);

  /* Ease our life. */
  encrypted = &desc->desc->encrypted_data;
  /* Cleanup intro points, we are about to set them from scratch. */
  hs_descriptor_clear_intro_points(desc->desc);

  DIGEST256MAP_FOREACH(desc->intro_points.map, key,
                       const hs_service_intro_point_t *, ip) {
    hs_desc_intro_point_t *desc_ip = hs_desc_intro_point_new();
    if (setup_desc_intro_point(&desc->signing_kp, ip, now, desc_ip) < 0) {
      hs_desc_intro_point_free(desc_ip);
      continue;
    }
    /* We have a valid descriptor intro point. Add it to the list. */
    smartlist_add(encrypted->intro_points, desc_ip);
  } DIGEST256MAP_FOREACH_END;
}

/* Populate the descriptor encrypted section fomr the given service object.
 * This will generate a valid list of introduction points that can be used
 * after for circuit creation. Return 0 on success else -1 on error. */
static int
build_service_desc_encrypted(const hs_service_t *service,
                             hs_service_descriptor_t *desc)
{
  hs_desc_encrypted_data_t *encrypted;

  tor_assert(service);
  tor_assert(desc);

  encrypted = &desc->desc->encrypted_data;

  encrypted->create2_ntor = 1;
  encrypted->single_onion_service = service->config.is_single_onion;

  /* Setup introduction points from what we have in the service. */
  if (encrypted->intro_points == NULL) {
    encrypted->intro_points = smartlist_new();
  }
  /* We do NOT build introduction point yet, we only do that once the circuit
   * have been opened. Until we have the right number of introduction points,
   * we do not encode anything in the descriptor. */

  /* XXX: Support client authorization (#20700). */
  encrypted->intro_auth_types = NULL;
  return 0;
}

/* Populare the descriptor plaintext section from the given service object.
 * The caller must make sure that the keys in the descriptors are valid that
 * is are non-zero. Return 0 on success else -1 on error. */
static int
build_service_desc_plaintext(const hs_service_t *service,
                             hs_service_descriptor_t *desc, time_t now)
{
  int ret = -1;
  hs_desc_plaintext_data_t *plaintext;

  tor_assert(service);
  tor_assert(desc);
  /* XXX: Use a "assert_desc_ok()" ? */
  tor_assert(!tor_mem_is_zero((char *) &desc->blinded_kp,
                              sizeof(desc->blinded_kp)));
  tor_assert(!tor_mem_is_zero((char *) &desc->signing_kp,
                              sizeof(desc->signing_kp)));

  /* Set the subcredential. */
  hs_get_subcredential(&service->keys.identity_pk, &desc->blinded_kp.pubkey,
                       desc->desc->subcredential);

  plaintext = &desc->desc->plaintext_data;

  plaintext->version = service->config.version;
  plaintext->lifetime_sec = HS_DESC_DEFAULT_LIFETIME;
  plaintext->signing_key_cert =
    tor_cert_create(&desc->blinded_kp, CERT_TYPE_SIGNING_HS_DESC,
                    &desc->signing_kp.pubkey, now, HS_DESC_CERT_LIFETIME,
                    CERT_FLAG_INCLUDE_SIGNING_KEY);
  if (plaintext->signing_key_cert == NULL) {
    log_warn(LD_REND, "Unable to create descriptor signing certificate for "
                      "service %s",
             safe_str_client(service->onion_address));
    goto end;
  }
  /* Copy public key material to go in the descriptor. */
  ed25519_pubkey_copy(&plaintext->signing_pubkey, &desc->signing_kp.pubkey);
  ed25519_pubkey_copy(&plaintext->blinded_pubkey, &desc->blinded_kp.pubkey);
  /* Success. */
  ret = 0;

 end:
  return ret;
}

/* For the given service and descriptor object, create the key material which
 * is the blinded keypair and the descriptor signing keypair. Return 0 on
 * success else -1 on error where the generated keys MUST be ignored. */
static int
build_service_desc_keys(const hs_service_t *service,
                        hs_service_descriptor_t *desc,
                        uint64_t time_period_num)
{
  int ret = 0;
  ed25519_keypair_t kp;

  tor_assert(desc);
  tor_assert(!tor_mem_is_zero((char *) &service->keys.identity_pk,
             ED25519_PUBKEY_LEN));

  /* XXX: Support offline key feature (#18098). */

  /* Copy the identity keys to the keypair so we can use it to create the
   * blinded key. */
  memcpy(&kp.pubkey, &service->keys.identity_pk, sizeof(kp.pubkey));
  memcpy(&kp.seckey, &service->keys.identity_sk, sizeof(kp.seckey));
  /* Build blinded keypair for this time period. */
  hs_build_blinded_keypair(&kp, NULL, 0, time_period_num, &desc->blinded_kp);
  /* Let's not keep too much traces of our keys in memory. */
  memwipe(&kp, 0, sizeof(kp));

  /* No need for extra strong, this is a temporary key only for this
   * descriptor. Nothing long term. */
  if (ed25519_keypair_generate(&desc->signing_kp, 0) < 0) {
    log_warn(LD_REND, "Can't generate descriptor signing keypair for "
                      "service %s",
             safe_str_client(service->onion_address));
    ret = -1;
  }

  return ret;
}

/* Given a service and the current time, build a descriptor for the service.
 * This function does not pick introduction point, this needs to be done by
 * the update function. On success, desc_out will point to the newly allocated
 * descriptor object.
 *
 * This can error if we are unable to create keys or certificate. */
static void
build_service_descriptor(hs_service_t *service, time_t now,
                         uint64_t time_period_num,
                         hs_service_descriptor_t **desc_out)
{
  char *encoded_desc;
  hs_service_descriptor_t *desc;

  tor_assert(service);
  tor_assert(desc_out);

  desc = service_descriptor_new();
  desc->time_period_num = time_period_num;

  /* Create the needed keys so we can setup the descriptor content. */
  if (build_service_desc_keys(service, desc, time_period_num) < 0) {
    goto err;
  }
  /* Setup plaintext descriptor content. */
  if (build_service_desc_plaintext(service, desc, now) < 0) {
    goto err;
  }
  /* Setup encrypted descriptor content. */
  if (build_service_desc_encrypted(service, desc) < 0) {
    goto err;
  }

  /* Set the revision counter for this descriptor */
  set_descriptor_revision_counter(desc->desc);

  /* Let's make sure that we've created a descriptor that can actually be
   * encoded properly. This function also checks if the encoded output is
   * decodable after. */
  if (BUG(hs_desc_encode_descriptor(desc->desc, &desc->signing_kp,
                                    &encoded_desc) < 0)) {
    goto err;
  }
  tor_free(encoded_desc);

  /* Assign newly built descriptor to the next slot. */
  *desc_out = desc;
  return;

 err:
  service_descriptor_free(desc);
}

/* Build both descriptors for the given service that has just booted up.
 * Because it's a special case, it deserves its special function ;). */
static void
build_descriptors_for_new_service(hs_service_t *service, time_t now)
{
  uint64_t current_desc_tp, next_desc_tp;

  tor_assert(service);
  /* These are the conditions for a new service. */
  tor_assert(!service->desc_current);
  tor_assert(!service->desc_next);

  /*
   * +------------------------------------------------------------------+
   * |                                                                  |
   * | 00:00      12:00       00:00       12:00       00:00       12:00 |
   * | SRV#1      TP#1        SRV#2       TP#2        SRV#3       TP#3  |
   * |                                                                  |
   * |  $==========|-----------$===========|-----------$===========|    |
   * |                             ^         ^                          |
   * |                             A         B                          |
   * +------------------------------------------------------------------+
   *
   * Case A: The service boots up before a new time period, the current time
   * period is thus TP#1 and the next is TP#2 which for both we have access to
   * their SRVs.
   *
   * Case B: The service boots up inside TP#2, we can't use the TP#3 for the
   * next descriptor because we don't have the SRV#3 so the current should be
   * TP#1 and next TP#2.
   */

  if (hs_in_period_between_tp_and_srv(NULL, now)) {
    /* Case B from the above, inside of the new time period. */
    current_desc_tp = hs_get_previous_time_period_num(0); /* TP#1 */
    next_desc_tp = hs_get_time_period_num(0);             /* TP#2 */
  } else {
    /* Case A from the above, outside of the new time period. */
    current_desc_tp = hs_get_time_period_num(0);    /* TP#1 */
    next_desc_tp = hs_get_next_time_period_num(0);  /* TP#2 */
  }

  /* Build descriptors. */
  build_service_descriptor(service, now, current_desc_tp,
                           &service->desc_current);
  build_service_descriptor(service, now, next_desc_tp,
                           &service->desc_next);
  log_info(LD_REND, "Hidden service %s has just started. Both descriptors "
                    "built. Now scheduled for upload.",
           safe_str_client(service->onion_address));
}

/* Build descriptors for each service if needed. There are conditions to build
 * a descriptor which are details in the function. */
STATIC void
build_all_descriptors(time_t now)
{
  FOR_EACH_SERVICE_BEGIN(service) {

    /* A service booting up will have both descriptors to NULL. No other cases
     * makes both descriptor non existent. */
    if (service->desc_current == NULL && service->desc_next == NULL) {
      build_descriptors_for_new_service(service, now);
      continue;
    }

    /* Reaching this point means we are pass bootup so at runtime. We should
     * *never* have an empty current descriptor. If the next descriptor is
     * empty, we'll try to build it for the next time period. This only
     * happens when we rotate meaning that we are guaranteed to have a new SRV
     * at that point for the next time period. */
    tor_assert(service->desc_current);

    if (service->desc_next == NULL) {
      build_service_descriptor(service, now, hs_get_next_time_period_num(0),
                               &service->desc_next);
      log_info(LD_REND, "Hidden service %s next descriptor successfully "
                        "built. Now scheduled for upload.",
               safe_str_client(service->onion_address));
    }
  } FOR_EACH_DESCRIPTOR_END;
}

/* Randomly pick a node to become an introduction point but not present in the
 * given exclude_nodes list. The chosen node is put in the exclude list
 * regardless of success or not because in case of failure, the node is simply
 * unsusable from that point on.
 *
 * If direct_conn is set, try to pick a node that our local firewall/policy
 * allows us to connect to directly. If we can't find any, return NULL.
 * This function supports selecting dual-stack nodes for direct single onion
 * service IPv6 connections. But it does not send IPv6 addresses in link
 * specifiers. (Current clients don't use IPv6 addresses to extend, and
 * direct client connections to intro points are not supported.)
 *
 * Return a newly allocated service intro point ready to be used for encoding.
 * Return NULL on error. */
static hs_service_intro_point_t *
pick_intro_point(unsigned int direct_conn, smartlist_t *exclude_nodes)
{
  const node_t *node;
  extend_info_t *info = NULL;
  hs_service_intro_point_t *ip = NULL;
  /* Normal 3-hop introduction point flags. */
  router_crn_flags_t flags = CRN_NEED_UPTIME | CRN_NEED_DESC;
  /* Single onion flags. */
  router_crn_flags_t direct_flags = flags | CRN_PREF_ADDR | CRN_DIRECT_CONN;

  node = router_choose_random_node(exclude_nodes, get_options()->ExcludeNodes,
                                   direct_conn ? direct_flags : flags);
  /* Unable to find a node. When looking for a node for a direct connection,
   * we could try a 3-hop path instead. We'll add support for this in a later
   * release. */
  if (!node) {
    goto err;
  }

  /* We have a suitable node, add it to the exclude list. We do this *before*
   * we can validate the extend information because even in case of failure,
   * we don't want to use that node anymore. */
  smartlist_add(exclude_nodes, (void *) node);

  /* We do this to ease our life but also this call makes appropriate checks
   * of the node object such as validating ntor support for instance.
   *
   * We must provide an extend_info for clients to connect over a 3-hop path,
   * so we don't pass direct_conn here. */
  info = extend_info_from_node(node, 0);
  if (BUG(info == NULL)) {
    goto err;
  }

  /* Let's do a basic sanity check here so that we don't end up advertising the
   * ed25519 identity key of relays that don't actually support the link
   * protocol */
  if (!node_supports_ed25519_link_authentication(node)) {
    tor_assert_nonfatal(ed25519_public_key_is_zero(&info->ed_identity));
  } else {
    /* Make sure we *do* have an ed key if we support the link authentication.
     * Sending an empty key would result in a failure to extend. */
    tor_assert_nonfatal(!ed25519_public_key_is_zero(&info->ed_identity));
  }

  /* Create our objects and populate them with the node information. */
  ip = service_intro_point_new(info, !node_supports_ed25519_hs_intro(node));
  if (ip == NULL) {
    goto err;
  }

  log_info(LD_REND, "Picked intro point: %s", extend_info_describe(info));
  extend_info_free(info);
  return ip;
 err:
  service_intro_point_free(ip);
  extend_info_free(info);
  return NULL;
}

/* For a given descriptor from the given service, pick any needed intro points
 * and update the current map with those newly picked intro points. Return the
 * number node that might have been added to the descriptor current map. */
static unsigned int
pick_needed_intro_points(hs_service_t *service,
                         hs_service_descriptor_t *desc)
{
  int i = 0, num_needed_ip;
  smartlist_t *exclude_nodes = smartlist_new();

  tor_assert(service);
  tor_assert(desc);

  /* Compute how many intro points we actually need to open. */
  num_needed_ip = service->config.num_intro_points -
                  digest256map_size(desc->intro_points.map);
  if (BUG(num_needed_ip < 0)) {
    /* Let's not make tor freak out here and just skip this. */
    goto done;
  }

  /* We want to end up with config.num_intro_points intro points, but if we
   * have no intro points at all (chances are they all cycled or we are
   * starting up), we launch get_intro_point_num_extra() extra circuits and
   * use the first config.num_intro_points that complete. See proposal #155,
   * section 4 for the rationale of this which is purely for performance.
   *
   * The ones after the first config.num_intro_points will be converted to
   * 'General' internal circuits and then we'll drop them from the list of
   * intro points. */
  if (digest256map_size(desc->intro_points.map) == 0) {
    num_needed_ip += get_intro_point_num_extra();
  }

  /* Build an exclude list of nodes of our intro point(s). The expiring intro
   * points are OK to pick again because this is afterall a concept of round
   * robin so they are considered valid nodes to pick again. */
  DIGEST256MAP_FOREACH(desc->intro_points.map, key,
                       hs_service_intro_point_t *, ip) {
    const node_t *intro_node = get_node_from_intro_point(ip);
    if (intro_node) {
      smartlist_add(exclude_nodes, (void*)intro_node);
    }
  } DIGEST256MAP_FOREACH_END;
  /* Also, add the failing intro points that our descriptor encounteered in
   * the exclude node list. */
  setup_intro_point_exclude_list(desc, exclude_nodes);

  for (i = 0; i < num_needed_ip; i++) {
    hs_service_intro_point_t *ip;

    /* This function will add the picked intro point node to the exclude nodes
     * list so we don't pick the same one at the next iteration. */
    ip = pick_intro_point(service->config.is_single_onion, exclude_nodes);
    if (ip == NULL) {
      /* If we end up unable to pick an introduction point it is because we
       * can't find suitable node and calling this again is highly unlikely to
       * give us a valid node all of the sudden. */
      log_info(LD_REND, "Unable to find a suitable node to be an "
                        "introduction point for service %s.",
               safe_str_client(service->onion_address));
      goto done;
    }
    /* Valid intro point object, add it to the descriptor current map. */
    service_intro_point_add(desc->intro_points.map, ip);
  }
  /* We've successfully picked all our needed intro points thus none are
   * missing which will tell our upload process to expect the number of
   * circuits to be the number of configured intro points circuits and not the
   * number of intro points object that we have. */
  desc->missing_intro_points = 0;

  /* Success. */
 done:
  /* We don't have ownership of the node_t object in this list. */
  smartlist_free(exclude_nodes);
  return i;
}

/** Clear previous cached HSDirs in <b>desc</b>. */
static void
service_desc_clear_previous_hsdirs(hs_service_descriptor_t *desc)
{
  if (BUG(!desc->previous_hsdirs)) {
    return;
  }

  SMARTLIST_FOREACH(desc->previous_hsdirs, char*, s, tor_free(s));
  smartlist_clear(desc->previous_hsdirs);
}

/** Note that we attempted to upload <b>desc</b> to <b>hsdir</b>. */
static void
service_desc_note_upload(hs_service_descriptor_t *desc, const node_t *hsdir)
{
  char b64_digest[BASE64_DIGEST_LEN+1] = {0};
  digest_to_base64(b64_digest, hsdir->identity);

  if (BUG(!desc->previous_hsdirs)) {
    return;
  }

  if (!smartlist_contains_string(desc->previous_hsdirs, b64_digest)) {
    smartlist_add_strdup(desc->previous_hsdirs, b64_digest);
  }
}

/** Schedule an upload of <b>desc</b>. If <b>descriptor_changed</b> is set, it
 *  means that this descriptor is dirty. */
STATIC void
service_desc_schedule_upload(hs_service_descriptor_t *desc,
                             time_t now,
                             int descriptor_changed)

{
  desc->next_upload_time = now;

  /* If the descriptor changed, clean up the old HSDirs list. We want to
   * re-upload no matter what. */
  if (descriptor_changed) {
    service_desc_clear_previous_hsdirs(desc);
  }
}

/* Update the given descriptor from the given service. The possible update
 * actions includes:
 *    - Picking missing intro points if needed.
 *    - Incrementing the revision counter if needed.
 */
static void
update_service_descriptor(hs_service_t *service,
                          hs_service_descriptor_t *desc, time_t now)
{
  unsigned int num_intro_points;

  tor_assert(service);
  tor_assert(desc);
  tor_assert(desc->desc);

  num_intro_points = digest256map_size(desc->intro_points.map);

  /* Pick any missing introduction point(s). */
  if (num_intro_points < service->config.num_intro_points) {
    unsigned int num_new_intro_points = pick_needed_intro_points(service,
                                                                 desc);
    if (num_new_intro_points != 0) {
      log_info(LD_REND, "Service %s just picked %u intro points and wanted "
                        "%u for %s descriptor. It currently has %d intro "
                        "points. Launching ESTABLISH_INTRO circuit shortly.",
               safe_str_client(service->onion_address),
               num_new_intro_points,
               service->config.num_intro_points - num_intro_points,
               (desc == service->desc_current) ? "current" : "next",
               num_intro_points);
      /* We'll build those introduction point into the descriptor once we have
       * confirmation that the circuits are opened and ready. However,
       * indicate that this descriptor should be uploaded from now on. */
      service_desc_schedule_upload(desc, now, 1);
    }
    /* Were we able to pick all the intro points we needed? If not, we'll
     * flag the descriptor that it's missing intro points because it
     * couldn't pick enough which will trigger a descriptor upload. */
    if ((num_new_intro_points + num_intro_points) <
        service->config.num_intro_points) {
      desc->missing_intro_points = 1;
    }
  }
}

/* Update descriptors for each service if needed. */
STATIC void
update_all_descriptors(time_t now)
{
  FOR_EACH_SERVICE_BEGIN(service) {
    /* We'll try to update each descriptor that is if certain conditions apply
     * in order for the descriptor to be updated. */
    FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
      update_service_descriptor(service, desc, now);
    } FOR_EACH_DESCRIPTOR_END;
  } FOR_EACH_SERVICE_END;
}

/* Return true iff the given intro point has expired that is it has been used
 * for too long or we've reached our max seen INTRODUCE2 cell. */
STATIC int
intro_point_should_expire(const hs_service_intro_point_t *ip,
                          time_t now)
{
  tor_assert(ip);

  if (ip->introduce2_count >= ip->introduce2_max) {
    goto expired;
  }

  if (ip->time_to_expire <= now) {
    goto expired;
  }

  /* Not expiring. */
  return 0;
 expired:
  return 1;
}

/* Go over the given set of intro points for each service and remove any
 * invalid ones. The conditions for removal are:
 *
 *    - The node doesn't exists anymore (not in consensus)
 *                          OR
 *    - The intro point maximum circuit retry count has been reached and no
 *      circuit can be found associated with it.
 *                          OR
 *    - The intro point has expired and we should pick a new one.
 *
 * If an intro point is removed, the circuit (if any) is immediately close.
 * If a circuit can't be found, the intro point is kept if it hasn't reached
 * its maximum circuit retry value and thus should be retried.  */
static void
cleanup_intro_points(hs_service_t *service, time_t now)
{
  /* List of intro points to close. We can't mark the intro circuits for close
   * in the modify loop because doing so calls
   * hs_service_intro_circ_has_closed() which does a digest256map_get() on the
   * intro points map (that we are iterating over). This can't be done in a
   * single iteration after a MAP_DEL_CURRENT, the object will still be
   * returned leading to a use-after-free. So, we close the circuits and free
   * the intro points after the loop if any. */
  smartlist_t *ips_to_free = smartlist_new();

  tor_assert(service);

  /* For both descriptors, cleanup the intro points. */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    /* Go over the current intro points we have, make sure they are still
     * valid and remove any of them that aren't. */
    DIGEST256MAP_FOREACH_MODIFY(desc->intro_points.map, key,
                                hs_service_intro_point_t *, ip) {
      const node_t *node = get_node_from_intro_point(ip);
      int has_expired = intro_point_should_expire(ip, now);

      /* We cleanup an intro point if it has expired or if we do not know the
       * node_t anymore (removed from our latest consensus) or if we've
       * reached the maximum number of retry with a non existing circuit. */
      if (has_expired || node == NULL ||
          ip->circuit_retries > MAX_INTRO_POINT_CIRCUIT_RETRIES) {
        log_info(LD_REND, "Intro point %s%s (retried: %u times). "
                          "Removing it.",
                 describe_intro_point(ip),
                 has_expired ? " has expired" :
                    (node == NULL) ?  " fell off the consensus" : "",
                 ip->circuit_retries);

        /* We've retried too many times, remember it as a failed intro point
         * so we don't pick it up again for INTRO_CIRC_RETRY_PERIOD sec. */
        if (ip->circuit_retries > MAX_INTRO_POINT_CIRCUIT_RETRIES) {
          remember_failing_intro_point(ip, desc, approx_time());
        }

        /* Remove intro point from descriptor map and add it to the list of
         * ips to free for which we'll also try to close the intro circuit. */
        MAP_DEL_CURRENT(key);
        smartlist_add(ips_to_free, ip);
      }
    } DIGEST256MAP_FOREACH_END;
  } FOR_EACH_DESCRIPTOR_END;

  /* Go over the intro points to free and close their circuit if any. */
  SMARTLIST_FOREACH_BEGIN(ips_to_free, hs_service_intro_point_t *, ip) {
    /* See if we need to close the intro point circuit as well */

    /* XXX: Legacy code does NOT close circuits like this: it keeps the circuit
     * open until a new descriptor is uploaded and then closed all expiring
     * intro point circuit. Here, we close immediately and because we just
     * discarded the intro point, a new one will be selected, a new descriptor
     * created and uploaded. There is no difference to an attacker between the
     * timing of a new consensus and intro point rotation (possibly?). */
    origin_circuit_t *ocirc = hs_circ_service_get_intro_circ(ip);
    if (ocirc && !TO_CIRCUIT(ocirc)->marked_for_close) {
      circuit_mark_for_close(TO_CIRCUIT(ocirc), END_CIRC_REASON_FINISHED);
    }

    /* Cleanup the intro point */
    service_intro_point_free(ip);
  } SMARTLIST_FOREACH_END(ip);

  smartlist_free(ips_to_free);
}

/* Set the next rotation time of the descriptors for the given service for the
 * time now. */
static void
set_rotation_time(hs_service_t *service, time_t now)
{
  time_t valid_after;
  const networkstatus_t *ns = networkstatus_get_live_consensus(now);
  if (ns) {
    valid_after = ns->valid_after;
  } else {
    valid_after = now;
  }

  tor_assert(service);
  service->state.next_rotation_time =
    sr_state_get_start_time_of_current_protocol_run(valid_after) +
    sr_state_get_protocol_run_duration();

  {
    char fmt_time[ISO_TIME_LEN + 1];
    format_local_iso_time(fmt_time, service->state.next_rotation_time);
    log_info(LD_REND, "Next descriptor rotation time set to %s for %s",
             fmt_time, safe_str_client(service->onion_address));
  }
}

/* Return true iff the service should rotate its descriptor. The time now is
 * only used to fetch the live consensus and if none can be found, this
 * returns false. */
static unsigned int
should_rotate_descriptors(hs_service_t *service, time_t now)
{
  const networkstatus_t *ns;

  tor_assert(service);

  ns = networkstatus_get_live_consensus(now);
  if (ns == NULL) {
    goto no_rotation;
  }

  if (ns->valid_after >= service->state.next_rotation_time) {
    goto rotation;
  }

 no_rotation:
  return 0;
 rotation:
  return 1;
}

/* Rotate the service descriptors of the given service. The current descriptor
 * will be freed, the next one put in as the current and finally the next
 * descriptor pointer is NULLified. */
static void
rotate_service_descriptors(hs_service_t *service, time_t now)
{
  if (service->desc_current) {
    /* Close all IP circuits for the descriptor. */
    close_intro_circuits(&service->desc_current->intro_points);
    /* We don't need this one anymore, we won't serve any clients coming with
     * this service descriptor. */
    service_descriptor_free(service->desc_current);
  }
  /* The next one become the current one and emptying the next will trigger
   * a descriptor creation for it. */
  service->desc_current = service->desc_next;
  service->desc_next = NULL;

  /* We've just rotated, set the next time for the rotation. */
  set_rotation_time(service, now);
}

/* Rotate descriptors for each service if needed. A non existing current
 * descriptor will trigger a descriptor build for the next time period. */
STATIC void
rotate_all_descriptors(time_t now)
{
  /* XXX We rotate all our service descriptors at once. In the future it might
   *     be wise, to rotate service descriptors independently to hide that all
   *     those descriptors are on the same tor instance */

  FOR_EACH_SERVICE_BEGIN(service) {

    /* Note for a service booting up: Both descriptors are NULL in that case
     * so this function might return true if we are in the timeframe for a
     * rotation leading to basically swapping two NULL pointers which is
     * harmless. However, the side effect is that triggering a rotation will
     * update the service state and avoid doing anymore rotations after the
     * two descriptors have been built. */
    if (!should_rotate_descriptors(service, now)) {
      continue;
    }

    tor_assert(service->desc_current);
    tor_assert(service->desc_next);

    log_info(LD_REND, "Time to rotate our descriptors (%p / %p) for %s",
             service->desc_current, service->desc_next,
             safe_str_client(service->onion_address));

    rotate_service_descriptors(service, now);
  } FOR_EACH_SERVICE_END;
}

/* Scheduled event run from the main loop. Make sure all our services are up
 * to date and ready for the other scheduled events. This includes looking at
 * the introduction points status and descriptor rotation time. */
STATIC void
run_housekeeping_event(time_t now)
{
  /* Note that nothing here opens circuit(s) nor uploads descriptor(s). We are
   * simply moving things around or removing unneeded elements. */

  FOR_EACH_SERVICE_BEGIN(service) {

    /* If the service is starting off, set the rotation time. We can't do that
     * at configure time because the get_options() needs to be set for setting
     * that time that uses the voting interval. */
    if (service->state.next_rotation_time == 0) {
      /* Set the next rotation time of the descriptors. If it's Oct 25th
       * 23:47:00, the next rotation time is when the next SRV is computed
       * which is at Oct 26th 00:00:00 that is in 13 minutes. */
      set_rotation_time(service, now);
    }

    /* Cleanup invalid intro points from the service descriptor. */
    cleanup_intro_points(service, now);

    /* Remove expired failing intro point from the descriptor failed list. We
     * reset them at each INTRO_CIRC_RETRY_PERIOD. */
    remove_expired_failing_intro(service, now);

    /* At this point, the service is now ready to go through the scheduled
     * events guaranteeing a valid state. Intro points might be missing from
     * the descriptors after the cleanup but the update/build process will
     * make sure we pick those missing ones. */
  } FOR_EACH_SERVICE_END;
}

/* Scheduled event run from the main loop. Make sure all descriptors are up to
 * date. Once this returns, each service descriptor needs to be considered for
 * new introduction circuits and then for upload. */
static void
run_build_descriptor_event(time_t now)
{
  /* For v2 services, this step happens in the upload event. */

  /* Run v3+ events. */
  /* We start by rotating the descriptors only if needed. */
  rotate_all_descriptors(now);

  /* Then, we'll try to build  new descriptors that we might need. The
   * condition is that the next descriptor is non existing because it has
   * been rotated or we just started up. */
  build_all_descriptors(now);

  /* Finally, we'll check if we should update the descriptors. Missing
   * introduction points will be picked in this function which is useful for
   * newly built descriptors. */
  update_all_descriptors(now);
}

/* For the given service, launch any intro point circuits that could be
 * needed. This considers every descriptor of the service. */
static void
launch_intro_point_circuits(hs_service_t *service)
{
  tor_assert(service);

  /* For both descriptors, try to launch any missing introduction point
   * circuits using the current map. */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    /* Keep a ref on if we need a direct connection. We use this often. */
    unsigned int direct_conn = service->config.is_single_onion;

    DIGEST256MAP_FOREACH_MODIFY(desc->intro_points.map, key,
                                hs_service_intro_point_t *, ip) {
      extend_info_t *ei;

      /* Skip the intro point that already has an existing circuit
       * (established or not). */
      if (hs_circ_service_get_intro_circ(ip)) {
        continue;
      }

      ei = get_extend_info_from_intro_point(ip, direct_conn);
      if (ei == NULL) {
        /* This is possible if we can get a node_t but not the extend info out
         * of it. In this case, we remove the intro point and a new one will
         * be picked at the next main loop callback. */
        MAP_DEL_CURRENT(key);
        service_intro_point_free(ip);
        continue;
      }

      /* Launch a circuit to the intro point. */
      ip->circuit_retries++;
      if (hs_circ_launch_intro_point(service, ip, ei) < 0) {
        log_info(LD_REND, "Unable to launch intro circuit to node %s "
                          "for service %s.",
                 safe_str_client(extend_info_describe(ei)),
                 safe_str_client(service->onion_address));
        /* Intro point will be retried if possible after this. */
      }
      extend_info_free(ei);
    } DIGEST256MAP_FOREACH_END;
  } FOR_EACH_DESCRIPTOR_END;
}

/* Don't try to build more than this many circuits before giving up for a
 * while. Dynamically calculated based on the configured number of intro
 * points for the given service and how many descriptor exists. The default
 * use case of 3 introduction points and two descriptors will allow 28
 * circuits for a retry period (((3 + 2) + (3 * 3)) * 2). */
static unsigned int
get_max_intro_circ_per_period(const hs_service_t *service)
{
  unsigned int count = 0;
  unsigned int multiplier = 0;
  unsigned int num_wanted_ip;

  tor_assert(service);
  tor_assert(service->config.num_intro_points <=
             HS_CONFIG_V3_MAX_INTRO_POINTS);

/* For a testing network, allow to do it for the maximum amount so circuit
 * creation and rotation and so on can actually be tested without limit. */
#define MAX_INTRO_POINT_CIRCUIT_RETRIES_TESTING -1
  if (get_options()->TestingTorNetwork) {
    return MAX_INTRO_POINT_CIRCUIT_RETRIES_TESTING;
  }

  num_wanted_ip = service->config.num_intro_points;

  /* The calculation is as follow. We have a number of intro points that we
   * want configured as a torrc option (num_intro_points). We then add an
   * extra value so we can launch multiple circuits at once and pick the
   * quickest ones. For instance, we want 3 intros, we add 2 extra so we'll
   * pick 5 intros and launch 5 circuits. */
  count += (num_wanted_ip + get_intro_point_num_extra());

  /* Then we add the number of retries that is possible to do for each intro
   * point. If we want 3 intros, we'll allow 3 times the number of possible
   * retry. */
  count += (num_wanted_ip * MAX_INTRO_POINT_CIRCUIT_RETRIES);

  /* Then, we multiply by a factor of 2 if we have both descriptor or 0 if we
   * have none.  */
  multiplier += (service->desc_current) ? 1 : 0;
  multiplier += (service->desc_next) ? 1 : 0;

  return (count * multiplier);
}

/* For the given service, return 1 if the service is allowed to launch more
 * introduction circuits else 0 if the maximum has been reached for the retry
 * period of INTRO_CIRC_RETRY_PERIOD. */
STATIC int
can_service_launch_intro_circuit(hs_service_t *service, time_t now)
{
  tor_assert(service);

  /* Consider the intro circuit retry period of the service. */
  if (now > (service->state.intro_circ_retry_started_time +
             INTRO_CIRC_RETRY_PERIOD)) {
    service->state.intro_circ_retry_started_time = now;
    service->state.num_intro_circ_launched = 0;
    goto allow;
  }
  /* Check if we can still launch more circuits in this period. */
  if (service->state.num_intro_circ_launched <=
      get_max_intro_circ_per_period(service)) {
    goto allow;
  }

  /* Rate limit log that we've reached our circuit creation limit. */
  {
    char *msg;
    time_t elapsed_time = now - service->state.intro_circ_retry_started_time;
    static ratelim_t rlimit = RATELIM_INIT(INTRO_CIRC_RETRY_PERIOD);
    if ((msg = rate_limit_log(&rlimit, now))) {
      log_info(LD_REND, "Hidden service %s exceeded its circuit launch limit "
                        "of %u per %d seconds. It launched %u circuits in "
                        "the last %ld seconds. Will retry in %ld seconds.",
               safe_str_client(service->onion_address),
               get_max_intro_circ_per_period(service),
               INTRO_CIRC_RETRY_PERIOD,
               service->state.num_intro_circ_launched,
               (long int) elapsed_time,
               (long int) (INTRO_CIRC_RETRY_PERIOD - elapsed_time));
      tor_free(msg);
    }
  }

  /* Not allow. */
  return 0;
 allow:
  return 1;
}

/* Scheduled event run from the main loop. Make sure we have all the circuits
 * we need for each service. */
static void
run_build_circuit_event(time_t now)
{
  /* Make sure we can actually have enough information or able to build
   * internal circuits as required by services. */
  if (router_have_consensus_path() == CONSENSUS_PATH_UNKNOWN ||
      !have_completed_a_circuit()) {
    return;
  }

  /* Run v2 check. */
  if (rend_num_services() > 0) {
    rend_consider_services_intro_points(now);
  }

  /* Run v3+ check. */
  FOR_EACH_SERVICE_BEGIN(service) {
    /* For introduction circuit, we need to make sure we don't stress too much
     * circuit creation so make sure this service is respecting that limit. */
    if (can_service_launch_intro_circuit(service, now)) {
      /* Launch intro point circuits if needed. */
      launch_intro_point_circuits(service);
      /* Once the circuits have opened, we'll make sure to update the
       * descriptor intro point list and cleanup any extraneous. */
    }
  } FOR_EACH_SERVICE_END;
}

/* Encode and sign the service descriptor desc and upload it to the given
 * hidden service directory.  This does nothing if PublishHidServDescriptors
 * is false. */
static void
upload_descriptor_to_hsdir(const hs_service_t *service,
                           hs_service_descriptor_t *desc, const node_t *hsdir)
{
  char version_str[4] = {0}, *encoded_desc = NULL;
  directory_request_t *dir_req;
  hs_ident_dir_conn_t ident;

  tor_assert(service);
  tor_assert(desc);
  tor_assert(hsdir);

  memset(&ident, 0, sizeof(ident));

  /* Let's avoid doing that if tor is configured to not publish. */
  if (!get_options()->PublishHidServDescriptors) {
    log_info(LD_REND, "Service %s not publishing descriptor. "
                      "PublishHidServDescriptors is set to 1.",
             safe_str_client(service->onion_address));
    goto end;
  }

  /* First of all, we'll encode the descriptor. This should NEVER fail but
   * just in case, let's make sure we have an actual usable descriptor. */
  if (BUG(hs_desc_encode_descriptor(desc->desc, &desc->signing_kp,
                                    &encoded_desc) < 0)) {
    goto end;
  }

  /* Setup the connection identifier. */
  hs_ident_dir_conn_init(&service->keys.identity_pk, &desc->blinded_kp.pubkey,
                         &ident);

  /* This is our resource when uploading which is used to construct the URL
   * with the version number: "/tor/hs/<version>/publish". */
  tor_snprintf(version_str, sizeof(version_str), "%u",
               service->config.version);

  /* Build the directory request for this HSDir. */
  dir_req = directory_request_new(DIR_PURPOSE_UPLOAD_HSDESC);
  directory_request_set_routerstatus(dir_req, hsdir->rs);
  directory_request_set_indirection(dir_req, DIRIND_ANONYMOUS);
  directory_request_set_resource(dir_req, version_str);
  directory_request_set_payload(dir_req, encoded_desc,
                                strlen(encoded_desc));
  /* The ident object is copied over the directory connection object once
   * the directory request is initiated. */
  directory_request_upload_set_hs_ident(dir_req, &ident);

  /* Initiate the directory request to the hsdir.*/
  directory_initiate_request(dir_req);
  directory_request_free(dir_req);

  /* Add this node to previous_hsdirs list */
  service_desc_note_upload(desc, hsdir);

  /* Logging so we know where it was sent. */
  {
    int is_next_desc = (service->desc_next == desc);
    const uint8_t *idx = (is_next_desc) ? hsdir->hsdir_index->store_second:
                                          hsdir->hsdir_index->store_first;
    log_info(LD_REND, "Service %s %s descriptor of revision %" PRIu64
                      " initiated upload request to %s with index %s",
             safe_str_client(service->onion_address),
             (is_next_desc) ? "next" : "current",
             desc->desc->plaintext_data.revision_counter,
             safe_str_client(node_describe(hsdir)),
             safe_str_client(hex_str((const char *) idx, 32)));
  }

  /* XXX: Inform control port of the upload event (#20699). */
 end:
  tor_free(encoded_desc);
  return;
}

/** Return a newly-allocated string for our state file which contains revision
 *  counter information for <b>desc</b>. The format is:
 *
 *     HidServRevCounter <blinded_pubkey> <rev_counter>
 */
STATIC char *
encode_desc_rev_counter_for_state(const hs_service_descriptor_t *desc)
{
  char *state_str = NULL;
  char blinded_pubkey_b64[ED25519_BASE64_LEN+1];
  uint64_t rev_counter = desc->desc->plaintext_data.revision_counter;
  const ed25519_public_key_t *blinded_pubkey = &desc->blinded_kp.pubkey;

  /* Turn the blinded key into b64 so that we save it on state */
  tor_assert(blinded_pubkey);
  if (ed25519_public_to_base64(blinded_pubkey_b64, blinded_pubkey) < 0) {
    goto done;
  }

  /* Format is: <blinded key> <rev counter> */
  tor_asprintf(&state_str, "%s %" PRIu64, blinded_pubkey_b64, rev_counter);

  log_info(LD_GENERAL, "[!] Adding rev counter %" PRIu64 " for %s!",
           rev_counter, blinded_pubkey_b64);

 done:
  return state_str;
}

/** Update HS descriptor revision counters in our state by removing the old
 *  ones and writing down the ones that are currently active. */
static void
update_revision_counters_in_state(void)
{
  config_line_t *lines = NULL;
  config_line_t **nextline = &lines;
  or_state_t *state = get_or_state();

  /* Prepare our state structure with the rev counters */
  FOR_EACH_SERVICE_BEGIN(service) {
    FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
      /* We don't want to save zero counters */
      if (desc->desc->plaintext_data.revision_counter == 0) {
        continue;
      }

      *nextline = tor_malloc_zero(sizeof(config_line_t));
      (*nextline)->key = tor_strdup("HidServRevCounter");
      (*nextline)->value = encode_desc_rev_counter_for_state(desc);
      nextline = &(*nextline)->next;
    } FOR_EACH_DESCRIPTOR_END;
  } FOR_EACH_SERVICE_END;

  /* Remove the old rev counters, and replace them with the new ones */
  config_free_lines(state->HidServRevCounter);
  state->HidServRevCounter = lines;

  /* Set the state as dirty since we just edited it */
  if (!get_options()->AvoidDiskWrites) {
    or_state_mark_dirty(state, 0);
  }
}

/** Scan the string <b>state_line</b> for the revision counter of the service
 *  with <b>blinded_pubkey</b>. Set <b>service_found_out</b> to True if the
 *  line is relevant to this service, and return the cached revision
 *  counter. Else set <b>service_found_out</b> to False. */
STATIC uint64_t
check_state_line_for_service_rev_counter(const char *state_line,
                                    const ed25519_public_key_t *blinded_pubkey,
                                    int *service_found_out)
{
  smartlist_t *items = NULL;
  int ok;
  ed25519_public_key_t pubkey_in_state;
  uint64_t rev_counter = 0;

  tor_assert(service_found_out);
  tor_assert(state_line);
  tor_assert(blinded_pubkey);

  /* Assume that the line is not for this service */
  *service_found_out = 0;

  /* Start parsing the state line */
  items = smartlist_new();
  smartlist_split_string(items, state_line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (smartlist_len(items) < 2) {
    log_warn(LD_GENERAL, "Incomplete rev counter line. Ignoring.");
    goto done;
  }

  char *b64_key_str = smartlist_get(items, 0);
  char *saved_rev_counter_str = smartlist_get(items, 1);

  /* Parse blinded key to check if it's for this hidden service */
  if (ed25519_public_from_base64(&pubkey_in_state, b64_key_str) < 0) {
    log_warn(LD_GENERAL, "Unable to base64 key in revcount line. Ignoring.");
    goto done;
  }
  /* State line not for this hidden service */
  if (!ed25519_pubkey_eq(&pubkey_in_state, blinded_pubkey)) {
    goto done;
  }

  rev_counter = tor_parse_uint64(saved_rev_counter_str,
                                 10, 0, UINT64_MAX, &ok, NULL);
  if (!ok) {
    log_warn(LD_GENERAL, "Unable to parse rev counter. Ignoring.");
    goto done;
  }

  /* Since we got this far, the line was for this service */
  *service_found_out = 1;

  log_info(LD_GENERAL, "Found rev counter for %s: %" PRIu64,
           b64_key_str, rev_counter);

 done:
  tor_assert(items);
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);

  return rev_counter;
}

/** Dig into our state file and find the current revision counter for the
 *  service with blinded key <b>blinded_pubkey</b>. If no revision counter is
 *  found, return 0. */
static uint64_t
get_rev_counter_for_service(const ed25519_public_key_t *blinded_pubkey)
{
  or_state_t *state = get_or_state();
  config_line_t *line;

  /* Set default value for rev counters (if not found) to 0 */
  uint64_t final_rev_counter = 0;

  for (line = state->HidServRevCounter ; line ; line = line->next) {
    int service_found = 0;
    uint64_t rev_counter = 0;

    tor_assert(!strcmp(line->key, "HidServRevCounter"));

    /* Scan all the HidServRevCounter lines till we find the line for this
       service: */
    rev_counter = check_state_line_for_service_rev_counter(line->value,
                                                           blinded_pubkey,
                                                           &service_found);
    if (service_found) {
      final_rev_counter = rev_counter;
      goto done;
    }
  }

 done:
  return final_rev_counter;
}

/** Update the value of the revision counter for <b>hs_desc</b> and save it on
    our state file. */
static void
increment_descriptor_revision_counter(hs_descriptor_t *hs_desc)
{
  /* Find stored rev counter if it exists */
  uint64_t rev_counter =
    get_rev_counter_for_service(&hs_desc->plaintext_data.blinded_pubkey);

  /* Increment the revision counter of <b>hs_desc</b> so the next update (which
   * will trigger an upload) will have the right value. We do this at this
   * stage to only do it once because a descriptor can have many updates before
   * being uploaded. By doing it at upload, we are sure to only increment by 1
   * and thus avoid leaking how many operations we made on the descriptor from
   * the previous one before uploading. */
  rev_counter++;
  hs_desc->plaintext_data.revision_counter = rev_counter;

  update_revision_counters_in_state();
}

/** Set the revision counter in <b>hs_desc</b>, using the state file to find
 *  the current counter value if it exists. */
static void
set_descriptor_revision_counter(hs_descriptor_t *hs_desc)
{
  /* Find stored rev counter if it exists */
  uint64_t rev_counter =
    get_rev_counter_for_service(&hs_desc->plaintext_data.blinded_pubkey);

  hs_desc->plaintext_data.revision_counter = rev_counter;
}

/* Encode and sign the service descriptor desc and upload it to the
 * responsible hidden service directories. If for_next_period is true, the set
 * of directories are selected using the next hsdir_index. This does nothing
 * if PublishHidServDescriptors is false. */
STATIC void
upload_descriptor_to_all(const hs_service_t *service,
                         hs_service_descriptor_t *desc)
{
  smartlist_t *responsible_dirs = NULL;

  tor_assert(service);
  tor_assert(desc);

  /* We'll first cancel any directory request that are ongoing for this
   * descriptor. It is possible that we can trigger multiple uploads in a
   * short time frame which can lead to a race where the second upload arrives
   * before the first one leading to a 400 malformed descriptor response from
   * the directory. Closing all pending requests avoids that. */
  close_directory_connections(service, desc);

  /* Get our list of responsible HSDir. */
  responsible_dirs = smartlist_new();
  /* The parameter 0 means that we aren't a client so tell the function to use
   * the spread store consensus paremeter. */
  hs_get_responsible_hsdirs(&desc->blinded_kp.pubkey, desc->time_period_num,
                            service->desc_next == desc, 0, responsible_dirs);

  /** Clear list of previous hsdirs since we are about to upload to a new
   *  list. Let's keep it up to date. */
  service_desc_clear_previous_hsdirs(desc);

  /* For each responsible HSDir we have, initiate an upload command. */
  SMARTLIST_FOREACH_BEGIN(responsible_dirs, const routerstatus_t *,
                          hsdir_rs) {
    const node_t *hsdir_node = node_get_by_id(hsdir_rs->identity_digest);
    /* Getting responsible hsdir implies that the node_t object exists for the
     * routerstatus_t found in the consensus else we have a problem. */
    tor_assert(hsdir_node);
    /* Upload this descriptor to the chosen directory. */
    upload_descriptor_to_hsdir(service, desc, hsdir_node);
  } SMARTLIST_FOREACH_END(hsdir_rs);

  /* Set the next upload time for this descriptor. Even if we are configured
   * to not upload, we still want to follow the right cycle of life for this
   * descriptor. */
  desc->next_upload_time =
    (time(NULL) + crypto_rand_int_range(HS_SERVICE_NEXT_UPLOAD_TIME_MIN,
                                        HS_SERVICE_NEXT_UPLOAD_TIME_MAX));
  {
    char fmt_next_time[ISO_TIME_LEN+1];
    format_local_iso_time(fmt_next_time, desc->next_upload_time);
    log_debug(LD_REND, "Service %s set to upload a descriptor at %s",
              safe_str_client(service->onion_address), fmt_next_time);
  }

  /* Update the revision counter of this descriptor */
  increment_descriptor_revision_counter(desc->desc);

  smartlist_free(responsible_dirs);
  return;
}

/** The set of HSDirs have changed: check if the change affects our descriptor
 *  HSDir placement, and if it does, reupload the desc. */
STATIC int
service_desc_hsdirs_changed(const hs_service_t *service,
                            const hs_service_descriptor_t *desc)
{
  int should_reupload = 0;
  smartlist_t *responsible_dirs = smartlist_new();

  /* No desc upload has happened yet: it will happen eventually */
  if (!desc->previous_hsdirs || !smartlist_len(desc->previous_hsdirs)) {
    goto done;
  }

  /* Get list of responsible hsdirs */
  hs_get_responsible_hsdirs(&desc->blinded_kp.pubkey, desc->time_period_num,
                            service->desc_next == desc, 0, responsible_dirs);

  /* Check if any new hsdirs have been added to the responsible hsdirs set:
   * Iterate over the list of new hsdirs, and reupload if any of them is not
   * present in the list of previous hsdirs.
   */
  SMARTLIST_FOREACH_BEGIN(responsible_dirs, const routerstatus_t *, hsdir_rs) {
    char b64_digest[BASE64_DIGEST_LEN+1] = {0};
    digest_to_base64(b64_digest, hsdir_rs->identity_digest);

    if (!smartlist_contains_string(desc->previous_hsdirs, b64_digest)) {
      should_reupload = 1;
      break;
    }
  } SMARTLIST_FOREACH_END(hsdir_rs);

 done:
  smartlist_free(responsible_dirs);

  return should_reupload;
}

/* Return 1 if the given descriptor from the given service can be uploaded
 * else return 0 if it can not. */
static int
should_service_upload_descriptor(const hs_service_t *service,
                              const hs_service_descriptor_t *desc, time_t now)
{
  unsigned int num_intro_points;

  tor_assert(service);
  tor_assert(desc);

  /* If this descriptors has missing intro points that is that it couldn't get
   * them all when it was time to pick them, it means that we should upload
   * instead of waiting an arbitrary amount of time breaking the service.
   * Else, if we have no missing intro points, we use the value taken from the
   * service configuration. */
  if (desc->missing_intro_points) {
    num_intro_points = digest256map_size(desc->intro_points.map);
  } else {
    num_intro_points = service->config.num_intro_points;
  }

  /* This means we tried to pick intro points but couldn't get any so do not
   * upload descriptor in this case. We need at least one for the service to
   * be reachable. */
  if (desc->missing_intro_points && num_intro_points == 0) {
    goto cannot;
  }

  /* Check if all our introduction circuit have been established for all the
   * intro points we have selected. */
  if (count_desc_circuit_established(desc) != num_intro_points) {
    goto cannot;
  }

  /* Is it the right time to upload? */
  if (desc->next_upload_time > now) {
    goto cannot;
  }

  /* Don't upload desc if we don't have a live consensus */
  if (!networkstatus_get_live_consensus(now)) {
    goto cannot;
  }

  /* Do we know enough router descriptors to have adequate vision of the HSDir
     hash ring? */
  if (!router_have_minimum_dir_info()) {
    goto cannot;
  }

  /* Can upload! */
  return 1;
 cannot:
  return 0;
}

/* Scheduled event run from the main loop. Try to upload the descriptor for
 * each service. */
STATIC void
run_upload_descriptor_event(time_t now)
{
  /* v2 services use the same function for descriptor creation and upload so
   * we do everything here because the intro circuits were checked before. */
  if (rend_num_services() > 0) {
    rend_consider_services_upload(now);
    rend_consider_descriptor_republication();
  }

  /* Run v3+ check. */
  FOR_EACH_SERVICE_BEGIN(service) {
    FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
      /* If we were asked to re-examine the hash ring, and it changed, then
         schedule an upload */
      if (consider_republishing_hs_descriptors &&
          service_desc_hsdirs_changed(service, desc)) {
        service_desc_schedule_upload(desc, now, 0);
      }

      /* Can this descriptor be uploaded? */
      if (!should_service_upload_descriptor(service, desc, now)) {
        continue;
      }

      log_info(LD_REND, "Initiating upload for hidden service %s descriptor "
                        "for service %s with %u/%u introduction points%s.",
               (desc == service->desc_current) ? "current" : "next",
               safe_str_client(service->onion_address),
               digest256map_size(desc->intro_points.map),
               service->config.num_intro_points,
               (desc->missing_intro_points) ? " (couldn't pick more)" : "");

      /* At this point, we have to upload the descriptor so start by building
       * the intro points descriptor section which we are now sure to be
       * accurate because all circuits have been established. */
      build_desc_intro_points(service, desc, now);

      upload_descriptor_to_all(service, desc);
    } FOR_EACH_DESCRIPTOR_END;
  } FOR_EACH_SERVICE_END;

  /* We are done considering whether to republish rend descriptors */
  consider_republishing_hs_descriptors = 0;
}

/* Called when the introduction point circuit is done building and ready to be
 * used. */
static void
service_intro_circ_has_opened(origin_circuit_t *circ)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;
  hs_service_descriptor_t *desc = NULL;

  tor_assert(circ);

  /* Let's do some basic sanity checking of the circ state */
  if (BUG(!circ->cpath)) {
    return;
  }
  if (BUG(TO_CIRCUIT(circ)->purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO)) {
    return;
  }
  if (BUG(!circ->hs_ident)) {
    return;
  }

  /* Get the corresponding service and intro point. */
  get_objects_from_ident(circ->hs_ident, &service, &ip, &desc);

  if (service == NULL) {
    log_warn(LD_REND, "Unknown service identity key %s on the introduction "
                      "circuit %u. Can't find onion service.",
             safe_str_client(ed25519_fmt(&circ->hs_ident->identity_pk)),
             TO_CIRCUIT(circ)->n_circ_id);
    goto err;
  }
  if (ip == NULL) {
    log_warn(LD_REND, "Unknown introduction point auth key on circuit %u "
                      "for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }
  /* We can't have an IP object without a descriptor. */
  tor_assert(desc);

  if (hs_circ_service_intro_has_opened(service, ip, desc, circ)) {
    /* Getting here means that the circuit has been re-purposed because we
     * have enough intro circuit opened. Remove the IP from the service. */
    service_intro_point_remove(service, ip);
    service_intro_point_free(ip);
  }

  goto done;

 err:
  /* Close circuit, we can't use it. */
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_NOSUCHSERVICE);
 done:
  return;
}

/* Called when a rendezvous circuit is done building and ready to be used. */
static void
service_rendezvous_circ_has_opened(origin_circuit_t *circ)
{
  hs_service_t *service = NULL;

  tor_assert(circ);
  tor_assert(circ->cpath);
  /* Getting here means this is a v3 rendezvous circuit. */
  tor_assert(circ->hs_ident);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_CONNECT_REND);

  /* Declare the circuit dirty to avoid reuse, and for path-bias. We set the
   * timestamp regardless of its content because that circuit could have been
   * cannibalized so in any cases, we are about to use that circuit more. */
  TO_CIRCUIT(circ)->timestamp_dirty = time(NULL);
  pathbias_count_use_attempt(circ);

  /* Get the corresponding service and intro point. */
  get_objects_from_ident(circ->hs_ident, &service, NULL, NULL);
  if (service == NULL) {
    log_warn(LD_REND, "Unknown service identity key %s on the rendezvous "
                      "circuit %u with cookie %s. Can't find onion service.",
             safe_str_client(ed25519_fmt(&circ->hs_ident->identity_pk)),
             TO_CIRCUIT(circ)->n_circ_id,
             hex_str((const char *) circ->hs_ident->rendezvous_cookie,
                     REND_COOKIE_LEN));
    goto err;
  }

  /* If the cell can't be sent, the circuit will be closed within this
   * function. */
  hs_circ_service_rp_has_opened(service, circ);
  goto done;

 err:
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_NOSUCHSERVICE);
 done:
  return;
}

/* We've been expecting an INTRO_ESTABLISHED cell on this circuit and it just
 * arrived. Handle the INTRO_ESTABLISHED cell arriving on the given
 * introduction circuit. Return 0 on success else a negative value. */
static int
service_handle_intro_established(origin_circuit_t *circ,
                                 const uint8_t *payload,
                                 size_t payload_len)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;

  tor_assert(circ);
  tor_assert(payload);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_ESTABLISH_INTRO);

  /* We need the service and intro point for this cell. */
  get_objects_from_ident(circ->hs_ident, &service, &ip, NULL);

  /* Get service object from the circuit identifier. */
  if (service == NULL) {
    log_warn(LD_REND, "Unknown service identity key %s on the introduction "
                      "circuit %u. Can't find onion service.",
             safe_str_client(ed25519_fmt(&circ->hs_ident->identity_pk)),
             TO_CIRCUIT(circ)->n_circ_id);
    goto err;
  }
  if (ip == NULL) {
    /* We don't recognize the key. */
    log_warn(LD_REND, "Introduction circuit established without an intro "
                      "point object on circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }

  /* Try to parse the payload into a cell making sure we do actually have a
   * valid cell. On success, the ip object and circuit purpose is updated to
   * reflect the fact that the introduction circuit is established. */
  if (hs_circ_handle_intro_established(service, ip, circ, payload,
                                       payload_len) < 0) {
    goto err;
  }

  /* Flag that we have an established circuit for this intro point. This value
   * is what indicates the upload scheduled event if we are ready to build the
   * intro point into the descriptor and upload. */
  ip->circuit_established = 1;

  log_info(LD_REND, "Successfully received an INTRO_ESTABLISHED cell "
                    "on circuit %u for service %s",
           TO_CIRCUIT(circ)->n_circ_id,
           safe_str_client(service->onion_address));
  return 0;

 err:
  return -1;
}

/* We just received an INTRODUCE2 cell on the established introduction circuit
 * circ. Handle the cell and return 0 on success else a negative value. */
static int
service_handle_introduce2(origin_circuit_t *circ, const uint8_t *payload,
                          size_t payload_len)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;
  hs_service_descriptor_t *desc = NULL;

  tor_assert(circ);
  tor_assert(payload);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_INTRO);

  /* We'll need every object associated with this circuit. */
  get_objects_from_ident(circ->hs_ident, &service, &ip, &desc);

  /* Get service object from the circuit identifier. */
  if (service == NULL) {
    log_warn(LD_BUG, "Unknown service identity key %s when handling "
                     "an INTRODUCE2 cell on circuit %u",
             safe_str_client(ed25519_fmt(&circ->hs_ident->identity_pk)),
             TO_CIRCUIT(circ)->n_circ_id);
    goto err;
  }
  if (ip == NULL) {
    /* We don't recognize the key. */
    log_warn(LD_BUG, "Unknown introduction auth key when handling "
                     "an INTRODUCE2 cell on circuit %u for service %s",
             TO_CIRCUIT(circ)->n_circ_id,
             safe_str_client(service->onion_address));
    goto err;
  }
  /* If we have an IP object, we MUST have a descriptor object. */
  tor_assert(desc);

  /* The following will parse, decode and launch the rendezvous point circuit.
   * Both current and legacy cells are handled. */
  if (hs_circ_handle_introduce2(service, circ, ip, desc->desc->subcredential,
                                payload, payload_len) < 0) {
    goto err;
  }

  return 0;
 err:
  return -1;
}

/* Add to list every filename used by service. This is used by the sandbox
 * subsystem. */
static void
service_add_fnames_to_list(const hs_service_t *service, smartlist_t *list)
{
  const char *s_dir;
  char fname[128] = {0};

  tor_assert(service);
  tor_assert(list);

  /* Ease our life. */
  s_dir = service->config.directory_path;
  /* The hostname file. */
  smartlist_add(list, hs_path_from_filename(s_dir, fname_hostname));
  /* The key files splitted in two. */
  tor_snprintf(fname, sizeof(fname), "%s_secret_key", fname_keyfile_prefix);
  smartlist_add(list, hs_path_from_filename(s_dir, fname));
  tor_snprintf(fname, sizeof(fname), "%s_public_key", fname_keyfile_prefix);
  smartlist_add(list, hs_path_from_filename(s_dir, fname));
}

/* ========== */
/* Public API */
/* ========== */

/* Return the number of service we have configured and usable. */
unsigned int
hs_service_get_num_services(void)
{
  if (hs_service_map == NULL) {
    return 0;
  }
  return HT_SIZE(hs_service_map);
}

/* Called once an introduction circuit is closed. If the circuit doesn't have
 * a v3 identifier, it is ignored. */
void
hs_service_intro_circ_has_closed(origin_circuit_t *circ)
{
  hs_service_t *service = NULL;
  hs_service_intro_point_t *ip = NULL;
  hs_service_descriptor_t *desc = NULL;

  tor_assert(circ);

  if (circ->hs_ident == NULL) {
    /* This is not a v3 circuit, ignore. */
    goto end;
  }

  get_objects_from_ident(circ->hs_ident, &service, &ip, &desc);
  if (service == NULL) {
    log_warn(LD_REND, "Unable to find any hidden service associated "
                      "identity key %s on intro circuit %u.",
             ed25519_fmt(&circ->hs_ident->identity_pk),
             TO_CIRCUIT(circ)->n_circ_id);
    goto end;
  }
  if (ip == NULL) {
    /* The introduction point object has already been removed probably by our
     * cleanup process so ignore. */
    goto end;
  }
  /* Can't have an intro point object without a descriptor. */
  tor_assert(desc);

  /* Circuit disappeared so make sure the intro point is updated. By
   * keeping the object in the descriptor, we'll be able to retry. */
  ip->circuit_established = 0;

 end:
  return;
}

/* Given conn, a rendezvous edge connection acting as an exit stream, look up
 * the hidden service for the circuit circ, and look up the port and address
 * based on the connection port. Assign the actual connection address.
 *
 * Return 0 on success. Return -1 on failure and the caller should NOT close
 * the circuit. Return -2 on failure and the caller MUST close the circuit for
 * security reasons. */
int
hs_service_set_conn_addr_port(const origin_circuit_t *circ,
                              edge_connection_t *conn)
{
  hs_service_t *service = NULL;

  tor_assert(circ);
  tor_assert(conn);
  tor_assert(TO_CIRCUIT(circ)->purpose == CIRCUIT_PURPOSE_S_REND_JOINED);
  tor_assert(circ->hs_ident);

  get_objects_from_ident(circ->hs_ident, &service, NULL, NULL);

  if (service == NULL) {
    log_warn(LD_REND, "Unable to find any hidden service associated "
                      "identity key %s on rendezvous circuit %u.",
             ed25519_fmt(&circ->hs_ident->identity_pk),
             TO_CIRCUIT(circ)->n_circ_id);
    /* We want the caller to close the circuit because it's not a valid
     * service so no danger. Attempting to bruteforce the entire key space by
     * opening circuits to learn which service is being hosted here is
     * impractical. */
    goto err_close;
  }

  /* Enforce the streams-per-circuit limit, and refuse to provide a mapping if
   * this circuit will exceed the limit. */
  if (service->config.max_streams_per_rdv_circuit > 0 &&
      (circ->hs_ident->num_rdv_streams >=
       service->config.max_streams_per_rdv_circuit)) {
#define MAX_STREAM_WARN_INTERVAL 600
    static struct ratelim_t stream_ratelim =
      RATELIM_INIT(MAX_STREAM_WARN_INTERVAL);
    log_fn_ratelim(&stream_ratelim, LOG_WARN, LD_REND,
                   "Maximum streams per circuit limit reached on "
                   "rendezvous circuit %u for service %s. Circuit has "
                   "%" PRIu64 " out of %" PRIu64 " streams. %s.",
                   TO_CIRCUIT(circ)->n_circ_id,
                   service->onion_address,
                   circ->hs_ident->num_rdv_streams,
                   service->config.max_streams_per_rdv_circuit,
                   service->config.max_streams_close_circuit ?
                    "Closing circuit" : "Ignoring open stream request");
    if (service->config.max_streams_close_circuit) {
      /* Service explicitly configured to close immediately. */
      goto err_close;
    }
    /* Exceeding the limit makes tor silently ignore the stream creation
     * request and keep the circuit open. */
    goto err_no_close;
  }

  /* Find a virtual port of that service mathcing the one in the connection if
   * succesful, set the address in the connection. */
  if (hs_set_conn_addr_port(service->config.ports, conn) < 0) {
    log_info(LD_REND, "No virtual port mapping exists for port %d for "
                      "hidden service %s.",
             TO_CONN(conn)->port, service->onion_address);
    if (service->config.allow_unknown_ports) {
      /* Service explicitly allow connection to unknown ports so close right
       * away because we do not care about port mapping. */
      goto err_close;
    }
    /* If the service didn't explicitly allow it, we do NOT close the circuit
     * here to raise the bar in terms of performance for port mapping. */
    goto err_no_close;
  }

  /* Success. */
  return 0;
 err_close:
  /* Indicate the caller that the circuit should be closed. */
  return -2;
 err_no_close:
  /* Indicate the caller to NOT close the circuit. */
  return -1;
}

/* Add to file_list every filename used by a configured hidden service, and to
 * dir_list every directory path used by a configured hidden service. This is
 * used by the sandbox subsystem to whitelist those. */
void
hs_service_lists_fnames_for_sandbox(smartlist_t *file_list,
                                    smartlist_t *dir_list)
{
  tor_assert(file_list);
  tor_assert(dir_list);

  /* Add files and dirs for legacy services. */
  rend_services_add_filenames_to_lists(file_list, dir_list);

  /* Add files and dirs for v3+. */
  FOR_EACH_SERVICE_BEGIN(service) {
    /* Skip ephemeral service, they don't touch the disk. */
    if (service->config.is_ephemeral) {
      continue;
    }
    service_add_fnames_to_list(service, file_list);
    smartlist_add_strdup(dir_list, service->config.directory_path);
  } FOR_EACH_DESCRIPTOR_END;
}

/* Called when our internal view of the directory has changed. We might have
 * received a new batch of descriptors which might affect the shape of the
 * HSDir hash ring. Signal that we should reexamine the hash ring and
 * re-upload our HS descriptors if needed. */
void
hs_service_dir_info_changed(void)
{
  if (hs_service_get_num_services() > 0) {
    /* New directory information usually goes every consensus so rate limit
     * every 30 minutes to not be too conservative. */
    static struct ratelim_t dir_info_changed_ratelim = RATELIM_INIT(30 * 60);
    log_fn_ratelim(&dir_info_changed_ratelim, LOG_INFO, LD_REND,
                   "New dirinfo arrived: consider reuploading descriptor");
    consider_republishing_hs_descriptors = 1;
  }
}

/* Called when we get an INTRODUCE2 cell on the circ. Respond to the cell and
 * launch a circuit to the rendezvous point. */
int
hs_service_receive_introduce2(origin_circuit_t *circ, const uint8_t *payload,
                              size_t payload_len)
{
  int ret = -1;

  tor_assert(circ);
  tor_assert(payload);

  /* Do some initial validation and logging before we parse the cell */
  if (TO_CIRCUIT(circ)->purpose != CIRCUIT_PURPOSE_S_INTRO) {
    log_warn(LD_PROTOCOL, "Received an INTRODUCE2 cell on a "
                          "non introduction circuit of purpose %d",
             TO_CIRCUIT(circ)->purpose);
    goto done;
  }

  if (circ->hs_ident) {
    ret = service_handle_introduce2(circ, payload, payload_len);
  } else {
    ret = rend_service_receive_introduction(circ, payload, payload_len);
  }

 done:
  return ret;
}

/* Called when we get an INTRO_ESTABLISHED cell. Mark the circuit as an
 * established introduction point. Return 0 on success else a negative value
 * and the circuit is closed. */
int
hs_service_receive_intro_established(origin_circuit_t *circ,
                                     const uint8_t *payload,
                                     size_t payload_len)
{
  int ret = -1;

  tor_assert(circ);
  tor_assert(payload);

  if (TO_CIRCUIT(circ)->purpose != CIRCUIT_PURPOSE_S_ESTABLISH_INTRO) {
    log_warn(LD_PROTOCOL, "Received an INTRO_ESTABLISHED cell on a "
                          "non introduction circuit of purpose %d",
             TO_CIRCUIT(circ)->purpose);
    goto err;
  }

  /* Handle both version. v2 uses rend_data and v3 uses the hs circuit
   * identifier hs_ident. Can't be both. */
  if (circ->hs_ident) {
    ret = service_handle_intro_established(circ, payload, payload_len);
  } else {
    ret = rend_service_intro_established(circ, payload, payload_len);
  }

  if (ret < 0) {
    goto err;
  }
  return 0;
 err:
  circuit_mark_for_close(TO_CIRCUIT(circ), END_CIRC_REASON_TORPROTOCOL);
  return -1;
}

/* Called when any kind of hidden service circuit is done building thus
 * opened. This is the entry point from the circuit subsystem. */
void
hs_service_circuit_has_opened(origin_circuit_t *circ)
{
  tor_assert(circ);

  /* Handle both version. v2 uses rend_data and v3 uses the hs circuit
   * identifier hs_ident. Can't be both. */
  switch (TO_CIRCUIT(circ)->purpose) {
  case CIRCUIT_PURPOSE_S_ESTABLISH_INTRO:
    if (circ->hs_ident) {
      service_intro_circ_has_opened(circ);
    } else {
      rend_service_intro_has_opened(circ);
    }
    break;
  case CIRCUIT_PURPOSE_S_CONNECT_REND:
    if (circ->hs_ident) {
      service_rendezvous_circ_has_opened(circ);
    } else {
      rend_service_rendezvous_has_opened(circ);
    }
    break;
  default:
    tor_assert(0);
  }
}

/* Load and/or generate keys for all onion services including the client
 * authorization if any. Return 0 on success, -1 on failure. */
int
hs_service_load_all_keys(void)
{
  /* Load v2 service keys if we have v2. */
  if (rend_num_services() != 0) {
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
  /* Allocate the CLIENT_PK replay cache in service state. */
  service->state.replay_cache_rend_cookie =
    replaycache_new(REND_REPLAY_TIME_INTERVAL, REND_REPLAY_TIME_INTERVAL);

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

  /* Free descriptors. Go over both descriptor with this loop. */
  FOR_EACH_DESCRIPTOR_BEGIN(service, desc) {
    service_descriptor_free(desc);
  } FOR_EACH_DESCRIPTOR_END;

  /* Free service configuration. */
  service_clear_config(&service->config);

  /* Free replay cache from state. */
  if (service->state.replay_cache_rend_cookie) {
    replaycache_free(service->state.replay_cache_rend_cookie);
  }

  /* Wipe service keys. */
  memwipe(&service->keys.identity_sk, 0, sizeof(service->keys.identity_sk));

  tor_free(service);
}

/* Periodic callback. Entry point from the main loop to the HS service
 * subsystem. This is call every second. This is skipped if tor can't build a
 * circuit or the network is disabled. */
void
hs_service_run_scheduled_events(time_t now)
{
  /* First thing we'll do here is to make sure our services are in a
   * quiescent state for the scheduled events. */
  run_housekeeping_event(now);

  /* Order matters here. We first make sure the descriptor object for each
   * service contains the latest data. Once done, we check if we need to open
   * new introduction circuit. Finally, we try to upload the descriptor for
   * each service. */

  /* Make sure descriptors are up to date. */
  run_build_descriptor_event(now);
  /* Make sure services have enough circuits. */
  run_build_circuit_event(now);
  /* Upload the descriptors if needed/possible. */
  run_upload_descriptor_event(now);
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

#endif /* defined(TOR_UNIT_TESTS) */

