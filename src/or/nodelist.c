/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "config.h"
#include "dirserv.h"
#include "microdesc.h"
#include "networkstatus.h"
#include "nodelist.h"
#include "policies.h"
#include "router.h"
#include "routerlist.h"

#include <string.h>

static void nodelist_drop_node(node_t *node, int remove_from_ht);
static void node_free(node_t *node);

/** A nodelist_t holds a node_t object for every router we're "willing to use
 * for something".  Specifically, it should hold a node_t for every node that
 * is currently in the routerlist, or currently in the consensus we're using.
 */
typedef struct nodelist_t {
  /* A list of all the nodes. */
  smartlist_t *nodes;
  /* Hash table to map from node ID digest to node. */
  HT_HEAD(nodelist_map, node_t) nodes_by_id;

} nodelist_t;

static INLINE unsigned int
node_id_hash(const node_t *node)
{
#if SIZEOF_INT == 4
  const uint32_t *p = (const uint32_t*)node->identity;
  return p[0] ^ p[1] ^ p[2] ^ p[3] ^ p[4];
#elif SIZEOF_INT == 8
  const uint64_t *p = (const uint32_t*)node->identity;
  const uint32_t *p32 = (const uint32_t*)node->identity;
  return p[0] ^ p[1] ^ p32[4];
#endif
}

static INLINE unsigned int
node_id_eq(const node_t *node1, const node_t *node2)
{
  return tor_memeq(node1->identity, node2->identity, DIGEST_LEN);
}

HT_PROTOTYPE(nodelist_map, node_t, ht_ent, node_id_hash, node_id_eq);
HT_GENERATE(nodelist_map, node_t, ht_ent, node_id_hash, node_id_eq,
            0.6, malloc, realloc, free);

/** The global nodelist. */
static nodelist_t *the_nodelist=NULL;

/** Create an empty nodelist if we haven't done so already. */
static void
init_nodelist(void)
{
  if (PREDICT_UNLIKELY(the_nodelist == NULL)) {
    the_nodelist = tor_malloc_zero(sizeof(nodelist_t));
    HT_INIT(nodelist_map, &the_nodelist->nodes_by_id);
    the_nodelist->nodes = smartlist_new();
  }
}

/** As node_get_by_id, but returns a non-const pointer */
node_t *
node_get_mutable_by_id(const char *identity_digest)
{
  node_t search, *node;
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return NULL;

  memcpy(&search.identity, identity_digest, DIGEST_LEN);
  node = HT_FIND(nodelist_map, &the_nodelist->nodes_by_id, &search);
  return node;
}

/** Return the node_t whose identity is <b>identity_digest</b>, or NULL
 * if no such node exists. */
const node_t *
node_get_by_id(const char *identity_digest)
{
  return node_get_mutable_by_id(identity_digest);
}

/** Internal: return the node_t whose identity_digest is
 * <b>identity_digest</b>.  If none exists, create a new one, add it to the
 * nodelist, and return it.
 *
 * Requires that the nodelist be initialized.
 */
static node_t *
node_get_or_create(const char *identity_digest)
{
  node_t *node;

  if ((node = node_get_mutable_by_id(identity_digest)))
    return node;

  node = tor_malloc_zero(sizeof(node_t));
  memcpy(node->identity, identity_digest, DIGEST_LEN);
  HT_INSERT(nodelist_map, &the_nodelist->nodes_by_id, node);

  smartlist_add(the_nodelist->nodes, node);
  node->nodelist_idx = smartlist_len(the_nodelist->nodes) - 1;

  node->country = -1;

  return node;
}

/** Add <b>ri</b> to the nodelist. */
node_t *
nodelist_add_routerinfo(routerinfo_t *ri)
{
  node_t *node;
  init_nodelist();
  node = node_get_or_create(ri->cache_info.identity_digest);
  node->ri = ri;

  if (node->country == -1)
    node_set_country(node);

  if (authdir_mode(get_options())) {
    const char *discard=NULL;
    uint32_t status = dirserv_router_get_status(ri, &discard);
    dirserv_set_node_flags_from_authoritative_status(node, status);
  }

  return node;
}

/** Set the appropriate node_t to use <b>md</b> as its microdescriptor.
 *
 * Called when a new microdesc has arrived and the usable consensus flavor
 * is "microdesc".
 **/
node_t *
nodelist_add_microdesc(microdesc_t *md)
{
  networkstatus_t *ns =
    networkstatus_get_latest_consensus_by_flavor(FLAV_MICRODESC);
  const routerstatus_t *rs;
  node_t *node;
  if (ns == NULL)
    return NULL;
  init_nodelist();

  /* Microdescriptors don't carry an identity digest, so we need to figure
   * it out by looking up the routerstatus. */
  rs = router_get_consensus_status_by_descriptor_digest(ns, md->digest);
  if (rs == NULL)
    return NULL;
  node = node_get_mutable_by_id(rs->identity_digest);
  if (node) {
    if (node->md)
      node->md->held_by_nodes--;
    node->md = md;
    md->held_by_nodes++;
  }
  return node;
}

/** Tell the nodelist that the current usable consensus to <b>ns</b>.
 * This makes the nodelist change all of the routerstatus entries for
 * the nodes, drop nodes that no longer have enough info to get used,
 * and grab microdescriptors into nodes as appropriate.
 */
void
nodelist_set_consensus(networkstatus_t *ns)
{
  const or_options_t *options = get_options();
  int authdir = authdir_mode_v2(options) || authdir_mode_v3(options);

  init_nodelist();
  if (ns->flavor == FLAV_MICRODESC)
    (void) get_microdesc_cache(); /* Make sure it exists first. */

  SMARTLIST_FOREACH(the_nodelist->nodes, node_t *, node,
                    node->rs = NULL);

  SMARTLIST_FOREACH_BEGIN(ns->routerstatus_list, routerstatus_t *, rs) {
    node_t *node = node_get_or_create(rs->identity_digest);
    node->rs = rs;
    if (ns->flavor == FLAV_MICRODESC) {
      if (node->md == NULL ||
          tor_memneq(node->md->digest,rs->descriptor_digest,DIGEST256_LEN)) {
        if (node->md)
          node->md->held_by_nodes--;
        node->md = microdesc_cache_lookup_by_digest256(NULL,
                                                       rs->descriptor_digest);
        if (node->md)
          node->md->held_by_nodes++;
      }
    }

    node_set_country(node);

    /* If we're not an authdir, believe others. */
    if (!authdir) {
      node->is_valid = rs->is_valid;
      node->is_running = rs->is_flagged_running;
      node->is_fast = rs->is_fast;
      node->is_stable = rs->is_stable;
      node->is_possible_guard = rs->is_possible_guard;
      node->is_exit = rs->is_exit;
      node->is_bad_directory = rs->is_bad_directory;
      node->is_bad_exit = rs->is_bad_exit;
      node->is_hs_dir = rs->is_hs_dir;
    }

  } SMARTLIST_FOREACH_END(rs);

  nodelist_purge();

  if (! authdir) {
    SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
      /* We have no routerstatus for this router. Clear flags so we can skip
       * it, maybe.*/
      if (!node->rs) {
        tor_assert(node->ri); /* if it had only an md, or nothing, purge
                               * would have removed it. */
        if (node->ri->purpose == ROUTER_PURPOSE_GENERAL) {
          /* Clear all flags. */
          node->is_valid = node->is_running = node->is_hs_dir =
            node->is_fast = node->is_stable =
            node->is_possible_guard = node->is_exit =
            node->is_bad_exit = node->is_bad_directory = 0;
        }
      }
    } SMARTLIST_FOREACH_END(node);
  }
}

/** Helper: return true iff a node has a usable amount of information*/
static INLINE int
node_is_usable(const node_t *node)
{
  return (node->rs) || (node->ri);
}

/** Tell the nodelist that <b>md</b> is no longer a microdescriptor for the
 * node with <b>identity_digest</b>. */
void
nodelist_remove_microdesc(const char *identity_digest, microdesc_t *md)
{
  node_t *node = node_get_mutable_by_id(identity_digest);
  if (node && node->md == md) {
    node->md = NULL;
    md->held_by_nodes--;
  }
}

/** Tell the nodelist that <b>ri</b> is no longer in the routerlist. */
void
nodelist_remove_routerinfo(routerinfo_t *ri)
{
  node_t *node = node_get_mutable_by_id(ri->cache_info.identity_digest);
  if (node && node->ri == ri) {
    node->ri = NULL;
    if (! node_is_usable(node)) {
      nodelist_drop_node(node, 1);
      node_free(node);
    }
  }
}

/** Remove <b>node</b> from the nodelist.  (Asserts that it was there to begin
 * with.) */
static void
nodelist_drop_node(node_t *node, int remove_from_ht)
{
  node_t *tmp;
  int idx;
  if (remove_from_ht) {
    tmp = HT_REMOVE(nodelist_map, &the_nodelist->nodes_by_id, node);
    tor_assert(tmp == node);
  }

  idx = node->nodelist_idx;
  tor_assert(idx >= 0);

  tor_assert(node == smartlist_get(the_nodelist->nodes, idx));
  smartlist_del(the_nodelist->nodes, idx);
  if (idx < smartlist_len(the_nodelist->nodes)) {
    tmp = smartlist_get(the_nodelist->nodes, idx);
    tmp->nodelist_idx = idx;
  }
  node->nodelist_idx = -1;
}

/** Release storage held by <b>node</b>  */
static void
node_free(node_t *node)
{
  if (!node)
    return;
  if (node->md)
    node->md->held_by_nodes--;
  tor_assert(node->nodelist_idx == -1);
  tor_free(node);
}

/** Remove all entries from the nodelist that don't have enough info to be
 * usable for anything. */
void
nodelist_purge(void)
{
  node_t **iter;
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return;

  /* Remove the non-usable nodes. */
  for (iter = HT_START(nodelist_map, &the_nodelist->nodes_by_id); iter; ) {
    node_t *node = *iter;

    if (node->md && !node->rs) {
      /* An md is only useful if there is an rs. */
      node->md->held_by_nodes--;
      node->md = NULL;
    }

    if (node_is_usable(node)) {
      iter = HT_NEXT(nodelist_map, &the_nodelist->nodes_by_id, iter);
    } else {
      iter = HT_NEXT_RMV(nodelist_map, &the_nodelist->nodes_by_id, iter);
      nodelist_drop_node(node, 0);
      node_free(node);
    }
  }
  nodelist_assert_ok();
}

/** Release all storage held by the nodelist. */
void
nodelist_free_all(void)
{
  if (PREDICT_UNLIKELY(the_nodelist == NULL))
    return;

  HT_CLEAR(nodelist_map, &the_nodelist->nodes_by_id);
  SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
    node->nodelist_idx = -1;
    node_free(node);
  } SMARTLIST_FOREACH_END(node);

  smartlist_free(the_nodelist->nodes);

  tor_free(the_nodelist);
}

/** Check that the nodelist is internally consistent, and consistent with
 * the directory info it's derived from.
 */
void
nodelist_assert_ok(void)
{
  routerlist_t *rl = router_get_routerlist();
  networkstatus_t *ns = networkstatus_get_latest_consensus();
  digestmap_t *dm;

  if (!the_nodelist)
    return;

  dm = digestmap_new();

  /* every routerinfo in rl->routers should be in the nodelist. */
  if (rl) {
    SMARTLIST_FOREACH_BEGIN(rl->routers, routerinfo_t *, ri) {
      const node_t *node = node_get_by_id(ri->cache_info.identity_digest);
      tor_assert(node && node->ri == ri);
      tor_assert(fast_memeq(ri->cache_info.identity_digest,
                             node->identity, DIGEST_LEN));
      tor_assert(! digestmap_get(dm, node->identity));
      digestmap_set(dm, node->identity, (void*)node);
    } SMARTLIST_FOREACH_END(ri);
  }

  /* every routerstatus in ns should be in the nodelist */
  if (ns) {
    SMARTLIST_FOREACH_BEGIN(ns->routerstatus_list, routerstatus_t *, rs) {
      const node_t *node = node_get_by_id(rs->identity_digest);
      tor_assert(node && node->rs == rs);
      tor_assert(fast_memeq(rs->identity_digest, node->identity, DIGEST_LEN));
      digestmap_set(dm, node->identity, (void*)node);
      if (ns->flavor == FLAV_MICRODESC) {
        /* If it's a microdesc consensus, every entry that has a
         * microdescriptor should be in the nodelist.
         */
        microdesc_t *md =
          microdesc_cache_lookup_by_digest256(NULL, rs->descriptor_digest);
        tor_assert(md == node->md);
        if (md)
          tor_assert(md->held_by_nodes >= 1);
      }
    } SMARTLIST_FOREACH_END(rs);
  }

  /* The nodelist should have no other entries, and its entries should be
   * well-formed. */
  SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
    tor_assert(digestmap_get(dm, node->identity) != NULL);
    tor_assert(node_sl_idx == node->nodelist_idx);
  } SMARTLIST_FOREACH_END(node);

  tor_assert((long)smartlist_len(the_nodelist->nodes) ==
             (long)HT_SIZE(&the_nodelist->nodes_by_id));

  digestmap_free(dm, NULL);
}

/** Return a list of a node_t * for every node we know about.  The caller
 * MUST NOT modify the list. (You can set and clear flags in the nodes if
 * you must, but you must not add or remove nodes.) */
smartlist_t *
nodelist_get_list(void)
{
  init_nodelist();
  return the_nodelist->nodes;
}

/** Given a hex-encoded nickname of the format DIGEST, $DIGEST, $DIGEST=name,
 * or $DIGEST~name, return the node with the matching identity digest and
 * nickname (if any).  Return NULL if no such node exists, or if <b>hex_id</b>
 * is not well-formed. */
const node_t *
node_get_by_hex_id(const char *hex_id)
{
  char digest_buf[DIGEST_LEN];
  char nn_buf[MAX_NICKNAME_LEN+1];
  char nn_char='\0';

  if (hex_digest_nickname_decode(hex_id, digest_buf, &nn_char, nn_buf)==0) {
    const node_t *node = node_get_by_id(digest_buf);
    if (!node)
      return NULL;
    if (nn_char) {
      const char *real_name = node_get_nickname(node);
      if (!real_name || strcasecmp(real_name, nn_buf))
        return NULL;
      if (nn_char == '=') {
        const char *named_id =
          networkstatus_get_router_digest_by_nickname(nn_buf);
        if (!named_id || tor_memneq(named_id, digest_buf, DIGEST_LEN))
          return NULL;
      }
    }
    return node;
  }

  return NULL;
}

/** Given a nickname (possibly verbose, possibly a hexadecimal digest), return
 * the corresponding node_t, or NULL if none exists.  Warn the user if
 * <b>warn_if_unnamed</b> is set, and they have specified a router by
 * nickname, but the Named flag isn't set for that router. */
const node_t *
node_get_by_nickname(const char *nickname, int warn_if_unnamed)
{
  const node_t *node;
  if (!the_nodelist)
    return NULL;

  /* Handle these cases: DIGEST, $DIGEST, $DIGEST=name, $DIGEST~name. */
  if ((node = node_get_by_hex_id(nickname)) != NULL)
      return node;

  if (!strcasecmp(nickname, UNNAMED_ROUTER_NICKNAME))
    return NULL;

  /* Okay, so if we get here, the nickname is just a nickname.  Is there
   * a binding for it in the consensus? */
  {
    const char *named_id =
      networkstatus_get_router_digest_by_nickname(nickname);
    if (named_id)
      return node_get_by_id(named_id);
  }

  /* Is it marked as owned-by-someone-else? */
  if (networkstatus_nickname_is_unnamed(nickname)) {
    log_info(LD_GENERAL, "The name %s is listed as Unnamed: there is some "
             "router that holds it, but not one listed in the current "
             "consensus.", escaped(nickname));
    return NULL;
  }

  /* Okay, so the name is not canonical for anybody. */
  {
    smartlist_t *matches = smartlist_new();
    const node_t *choice = NULL;

    SMARTLIST_FOREACH_BEGIN(the_nodelist->nodes, node_t *, node) {
      if (!strcasecmp(node_get_nickname(node), nickname))
        smartlist_add(matches, node);
    } SMARTLIST_FOREACH_END(node);

    if (smartlist_len(matches)>1 && warn_if_unnamed) {
      int any_unwarned = 0;
      SMARTLIST_FOREACH_BEGIN(matches, node_t *, node) {
        if (!node->name_lookup_warned) {
          node->name_lookup_warned = 1;
          any_unwarned = 1;
        }
      } SMARTLIST_FOREACH_END(node);

      if (any_unwarned) {
        log_warn(LD_CONFIG, "There are multiple matches for the name %s, "
                 "but none is listed as Named in the directory consensus. "
                 "Choosing one arbitrarily.", nickname);
      }
    } else if (smartlist_len(matches)>1 && warn_if_unnamed) {
      char fp[HEX_DIGEST_LEN+1];
      node_t *node = smartlist_get(matches, 0);
      if (node->name_lookup_warned) {
        base16_encode(fp, sizeof(fp), node->identity, DIGEST_LEN);
        log_warn(LD_CONFIG,
                 "You specified a server \"%s\" by name, but the directory "
                 "authorities do not have any key registered for this "
                 "nickname -- so it could be used by any server, not just "
                 "the one you meant. "
                 "To make sure you get the same server in the future, refer "
                 "to it by key, as \"$%s\".", nickname, fp);
        node->name_lookup_warned = 1;
      }
    }

    if (smartlist_len(matches))
      choice = smartlist_get(matches, 0);

    smartlist_free(matches);
    return choice;
  }
}

/** Return the nickname of <b>node</b>, or NULL if we can't find one. */
const char *
node_get_nickname(const node_t *node)
{
  tor_assert(node);
  if (node->rs)
    return node->rs->nickname;
  else if (node->ri)
    return node->ri->nickname;
  else
    return NULL;
}

/** Return true iff the nickname of <b>node</b> is canonical, based on the
 * latest consensus. */
int
node_is_named(const node_t *node)
{
  const char *named_id;
  const char *nickname = node_get_nickname(node);
  if (!nickname)
    return 0;
  named_id = networkstatus_get_router_digest_by_nickname(nickname);
  if (!named_id)
    return 0;
  return tor_memeq(named_id, node->identity, DIGEST_LEN);
}

/** Return true iff <b>node</b> appears to be a directory authority or
 * directory cache */
int
node_is_dir(const node_t *node)
{
  if (node->rs)
    return node->rs->dir_port != 0;
  else if (node->ri)
    return node->ri->dir_port != 0;
  else
    return 0;
}

/** Return true iff <b>node</b> has either kind of usable descriptor -- that
 * is, a routerdecriptor or a microdescriptor. */
int
node_has_descriptor(const node_t *node)
{
  return (node->ri ||
          (node->rs && node->md));
}

/** Return the router_purpose of <b>node</b>. */
int
node_get_purpose(const node_t *node)
{
  if (node->ri)
    return node->ri->purpose;
  else
    return ROUTER_PURPOSE_GENERAL;
}

/** Compute the verbose ("extended") nickname of <b>node</b> and store it
 * into the MAX_VERBOSE_NICKNAME_LEN+1 character buffer at
 * <b>verbose_nickname_out</b> */
void
node_get_verbose_nickname(const node_t *node,
                          char *verbose_name_out)
{
  const char *nickname = node_get_nickname(node);
  int is_named = node_is_named(node);
  verbose_name_out[0] = '$';
  base16_encode(verbose_name_out+1, HEX_DIGEST_LEN+1, node->identity,
                DIGEST_LEN);
  if (!nickname)
    return;
  verbose_name_out[1+HEX_DIGEST_LEN] = is_named ? '=' : '~';
  strlcpy(verbose_name_out+1+HEX_DIGEST_LEN+1, nickname, MAX_NICKNAME_LEN+1);
}

/** Return true iff it seems that <b>node</b> allows circuits to exit
 * through it directlry from the client. */
int
node_allows_single_hop_exits(const node_t *node)
{
  if (node && node->ri)
    return node->ri->allow_single_hop_exits;
  else
    return 0;
}

/** Return true iff it seems that <b>node</b> has an exit policy that doesn't
 * actually permit anything to exit, or we don't know its exit policy */
int
node_exit_policy_rejects_all(const node_t *node)
{
  if (node->rejects_all)
    return 1;

  if (node->ri)
    return node->ri->policy_is_reject_star;
  else if (node->md)
    return node->md->exit_policy == NULL ||
      short_policy_is_reject_star(node->md->exit_policy);
  else
    return 1;
}

/** Return list of tor_addr_port_t with all OR ports (in the sense IP
 * addr + TCP port) for <b>node</b>.  Caller must free all elements
 * using tor_free() and free the list using smartlist_free().
 *
 * XXX this is potentially a memory fragmentation hog -- if on
 * critical path consider the option of having the caller allocate the
 * memory
 */
smartlist_t *
node_get_all_orports(const node_t *node)
{
  smartlist_t *sl = smartlist_new();

  if (node->ri != NULL) {
    if (node->ri->addr != 0) {
      tor_addr_port_t *ap = tor_malloc(sizeof(tor_addr_port_t));
      tor_addr_from_ipv4h(&ap->addr, node->ri->addr);
      ap->port = node->ri->or_port;
      smartlist_add(sl, ap);
    }
    if (!tor_addr_is_null(&node->ri->ipv6_addr)) {
      tor_addr_port_t *ap = tor_malloc(sizeof(tor_addr_port_t));
      tor_addr_copy(&ap->addr, &node->ri->ipv6_addr);
      ap->port = node->ri->or_port;
      smartlist_add(sl, ap);
    }
  } else if (node->rs != NULL) {
      tor_addr_port_t *ap = tor_malloc(sizeof(tor_addr_port_t));
      tor_addr_from_ipv4h(&ap->addr, node->rs->addr);
      ap->port = node->rs->or_port;
      smartlist_add(sl, ap);
  }

  return sl;
}

/** Copy the primary (IPv4) OR port (IP address and TCP port) for
 * <b>node</b> into *<b>ap_out</b>.  */
void
node_get_prim_orport(const node_t *node, tor_addr_port_t *ap_out)
{
  if (node->ri) {
    router_get_prim_orport(node->ri, ap_out);
  } else if (node->rs) {
    tor_addr_from_ipv4h(&ap_out->addr, node->rs->addr);
    ap_out->port = node->rs->or_port;
  }
}

/** Wrapper around node_get_prim_orport for backward
    compatibility.  */
void
node_get_addr(const node_t *node, tor_addr_t *addr_out)
{
  tor_addr_port_t ap;
  node_get_prim_orport(node, &ap);
  tor_addr_copy(addr_out, &ap.addr);
}

/** Return the host-order IPv4 address for <b>node</b>, or 0 if it doesn't
 * seem to have one.  */
uint32_t
node_get_prim_addr_ipv4h(const node_t *node)
{
  if (node->ri) {
    return node->ri->addr;
  } else if (node->rs) {
    return node->rs->addr;
  }
  return 0;
}

/** Copy the preferred OR port (IP address and TCP port) for
 * <b>node</b> into <b>ap_out</b>.  */
void
node_get_pref_orport(const node_t *node, tor_addr_port_t *ap_out)
{
  if (node->ri) {
    router_get_pref_orport(node->ri, ap_out);
  } else if (node->rs) {
    /* No IPv6 in routerstatus_t yet.  XXXprop186 ok for private
       bridges but needs fixing */
    tor_addr_from_ipv4h(&ap_out->addr, node->rs->addr);
    ap_out->port = node->rs->or_port;
  }
}

/** Copy the preferred IPv6 OR port (address and TCP port) for
 * <b>node</b> into *<b>ap_out</b>. */
void
node_get_pref_ipv6_orport(const node_t *node, tor_addr_port_t *ap_out)
{
  if (node->ri) {
    router_get_pref_ipv6_orport(node->ri, ap_out);
  } else if (node->rs) {
    /* No IPv6 in routerstatus_t yet.  XXXprop186 ok for private
       bridges but needs fixing */
    tor_addr_make_unspec(&ap_out->addr);
    ap_out->port = 0;
  }
}

/** Copy a string representation of an IP address for <b>node</b> into
 * the <b>len</b>-byte buffer at <b>buf</b>.  */
void
node_get_address_string(const node_t *node, char *buf, size_t len)
{
  if (node->ri) {
    strlcpy(buf, node->ri->address, len);
  } else if (node->rs) {
    tor_addr_t addr;
    tor_addr_from_ipv4h(&addr, node->rs->addr);
    tor_addr_to_str(buf, &addr, len, 0);
  } else {
    buf[0] = '\0';
  }
}

/** Return <b>node</b>'s declared uptime, or -1 if it doesn't seem to have
 * one. */
long
node_get_declared_uptime(const node_t *node)
{
  if (node->ri)
    return node->ri->uptime;
  else
    return -1;
}

/** Return <b>node</b>'s platform string, or NULL if we don't know it. */
const char *
node_get_platform(const node_t *node)
{
  /* If we wanted, we could record the version in the routerstatus_t, since
   * the consensus lists it.  We don't, though, so this function just won't
   * work with microdescriptors. */
  if (node->ri)
    return node->ri->platform;
  else
    return NULL;
}

/** Return <b>node</b>'s time of publication, or 0 if we don't have one. */
time_t
node_get_published_on(const node_t *node)
{
  if (node->ri)
    return node->ri->cache_info.published_on;
  else
    return 0;
}

/** Return true iff <b>node</b> is one representing this router. */
int
node_is_me(const node_t *node)
{
  return router_digest_is_me(node->identity);
}

/** Return <b>node</b> declared family (as a list of names), or NULL if
 * the node didn't declare a family. */
const smartlist_t *
node_get_declared_family(const node_t *node)
{
  if (node->ri && node->ri->declared_family)
    return node->ri->declared_family;
  else if (node->md && node->md->family)
    return node->md->family;
  else
    return NULL;
}

