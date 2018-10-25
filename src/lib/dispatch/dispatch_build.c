/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define DISPATCH_PRIVATE

#include "lib/dispatch/dispatch_core.h"
#include "lib/dispatch/dispatch_st.h"
#include "lib/dispatch/dispatch_core.h"
#include "lib/dispatch/msg.h"
#include "lib/dispatch/msgtypes.h"
#include "lib/dispatch/namemap.h"

#include "lib/container/bitarray.h"
#include "lib/log/util_bug.h"
#include "lib/malloc/malloc.h"
#include "lib/string/compat_string.h"

#include <string.h>

static void dispatch_adjacency_map_add(dispatch_adjacency_map_t *map,
                                       const pubsub_cfg_t *item);

/** Global namemap for message IDs. */
static namemap_t message_id_map;
/** Global namemap for subsystem IDs. */
static namemap_t subsys_id_map;
/** Global namemap for channel IDs. */
static namemap_t channel_id_map;
/** Global namemap for message type IDs. */
static namemap_t msg_type_id_map;

static bool namemaps_initialized = false;

static void
init_namemaps(void)
{
  namemap_init(&message_id_map);
  namemap_init(&subsys_id_map);
  namemap_init(&channel_id_map);
  namemap_init(&msg_type_id_map);
}

/** Construct and return a new empty dispatch_cfg_t */
static dispatch_cfg_t *
dispatch_cfg_new(void)
{
  dispatch_cfg_t *cfg = tor_malloc_zero(sizeof(*cfg));
  cfg->items = smartlist_new();
  cfg->type_items = smartlist_new();
  return cfg;
}

/** Release all storage held in a dispatch_cfg_t */
void
dispatch_cfg_free_(dispatch_cfg_t *cfg)
{
  if (! cfg)
    return;
  SMARTLIST_FOREACH(cfg->items, pubsub_cfg_t *, item, tor_free(item));
  SMARTLIST_FOREACH(cfg->type_items,
                    pubsub_type_cfg_t *, item, tor_free(item));
  smartlist_free(cfg->items);
  smartlist_free(cfg->type_items);
  tor_free(cfg);
}

/** Construct and return a new dispatch_builder_t. */
dispatch_builder_t *
dispatch_builder_new(void)
{
  if (!namemaps_initialized)
    init_namemaps();

  dispatch_builder_t *db = tor_malloc_zero(sizeof(*db));
  db->cfg = dispatch_cfg_new();
  return db;
}

/**
 * Release all storage held by a dispatch_builder_t.
 *
 * You'll (mostly) only want to call this function on an error case: if you're
 * constructing a dispatcher_t instead, you should call
 * dispatch_builder_finalize() to consume the dispatch_builder_t.
 */
void
dispatch_builder_free_(dispatch_builder_t *db)
{
  if (db == NULL)
    return;
  dispatch_cfg_free(db->cfg);
  tor_free(db);
}

/**
 * Create and return a dispatch_connector_t for the subsystem with ID
 * <b>subsys</b> to use in adding publications, subscriptions, and types to
 * <b>builder</b>.
 **/
dispatch_connector_t *
dispatch_connector_for_subsystem(dispatch_builder_t *builder,
                                 subsys_id_t subsys)
{
  tor_assert(builder);
  ++builder->n_connectors;

  dispatch_connector_t *con = tor_malloc_zero(sizeof(*con));

  con->builder = builder;
  con->subsys_id = subsys;

  return con;
}

/**
 * Release all storage held by a dispatch_connector_t.
 **/
void
dispatch_connector_free_(dispatch_connector_t *con)
{
  if (!con)
    return;

  if (con->builder) {
    --con->builder->n_connectors;
    tor_assert(con->builder->n_connectors >= 0);
  }
  tor_free(con);
}

/* Helper macro: declare functions to map IDs to and from names for a given
 * type in a namemap_t.
 */
#define DECLARE_ID_MAP_FNS(type)                                        \
  type##_id_t                                                           \
  get_##type##_id(const char *name)                                     \
  {                                                                     \
    unsigned u = namemap_get_or_create_id(&type##_id_map, name);        \
    tor_assert(u != NAMEMAP_ERR);                                       \
    tor_assert(u != ERROR_ID);                                          \
    return (type##_id_t) u;                                             \
  }                                                                     \
  const char *                                                          \
  get_##type##_id_name(type##_id_t id)                                  \
  {                                                                     \
    return namemap_get_name(&type##_id_map, id);                        \
  }                                                                     \
  EAT_SEMICOLON

DECLARE_ID_MAP_FNS(message);
DECLARE_ID_MAP_FNS(channel);
DECLARE_ID_MAP_FNS(subsys);
DECLARE_ID_MAP_FNS(msg_type);

/**
 * Use <b>con</b> to add a request for being able to publish messages of type
 * <b>msg</b> with auxiliary data of <b>type</b> on <b>channel</b>.
 **/
int
dispatch_add_pub_(dispatch_connector_t *con,
                  pub_binding_t *out,
                  channel_id_t channel,
                  message_id_t msg,
                  msg_type_id_t type,
                  unsigned flags,
                  const char *file,
                  unsigned line)
{
  pubsub_cfg_t *cfg = tor_malloc_zero(sizeof(*cfg));

  memset(out, 0, sizeof(*out));
  cfg->is_publish = true;

  out->msg_template.sender = cfg->subsys = con->subsys_id;
  out->msg_template.channel = cfg->channel = channel;
  out->msg_template.msg = cfg->msg = msg;
  out->msg_template.type = cfg->type = type;

  cfg->flags = flags;
  cfg->added_by_file = file;
  cfg->added_by_line = line;

  /* We're grabbing a pointer to the pub_binding_t so we can tell it about
   * the dispatcher later on.
   */
  cfg->pub_binding = out;

  smartlist_add(con->builder->cfg->items, cfg);

  return 0;
}

/**
 * Use <b>con</b> to add a request for being able to publish messages of type
 * <b>msg</b> with auxiliary data of <b>type</b> on <b>channel</b>,
 * passing them to the callback in <b>recv_fn</b>.
 **/
int
dispatch_add_sub_(dispatch_connector_t *con,
                  recv_fn_t recv_fn,
                  channel_id_t channel,
                  message_id_t msg,
                  msg_type_id_t type,
                  unsigned flags,
                  const char *file,
                  unsigned line)
{
  pubsub_cfg_t *cfg = tor_malloc_zero(sizeof(*cfg));

  cfg->is_publish = false;
  cfg->subsys = con->subsys_id;
  cfg->channel = channel;
  cfg->msg = msg;
  cfg->type = type;
  cfg->flags = flags;
  cfg->added_by_file = file;
  cfg->added_by_line = line;

  cfg->recv_fn = recv_fn;

  smartlist_add(con->builder->cfg->items, cfg);
  return 0;
}

/**
 * Use <b>con</b> to define a the functions to use for manipulating the type
 * <b>type</b>.  Any function pointers left as NULL will be implemented as
 * no-ops.
 **/
int
dispatch_connector_define_type_(dispatch_connector_t *con,
                                msg_type_id_t type,
                                dispatch_typefns_t *fns,
                                const char *file,
                                unsigned line)
{
  pubsub_type_cfg_t *cfg = tor_malloc_zero(sizeof(*cfg));
  cfg->type = type;
  memcpy(&cfg->fns, fns, sizeof(*fns));
  cfg->subsys = con->subsys_id;
  cfg->added_by_file = file;
  cfg->added_by_line = line;

  smartlist_add(con->builder->cfg->type_items, cfg);
  return 0;
}

/**
 * Helper: contruct and return a new dispatch_adjacency_map from <b>cfg</b>.
 * Return NULL on error.
 **/
static dispatch_adjacency_map_t *
dispatch_build_adjacency_map(const dispatch_cfg_t *cfg)
{
  dispatch_adjacency_map_t *map = tor_malloc_zero(sizeof(*map));
  const size_t n_subsystems = namemap_get_size(&subsys_id_map);
  const size_t n_msgs = namemap_get_size(&message_id_map);

  map->n_subsystems = n_subsystems;
  map->n_msgs = n_msgs;

  map->pub_by_subsys = tor_calloc(n_subsystems, sizeof(smartlist_t*));
  map->sub_by_subsys = tor_calloc(n_subsystems, sizeof(smartlist_t*));
  map->pub_by_msg = tor_calloc(n_msgs, sizeof(smartlist_t*));
  map->sub_by_msg = tor_calloc(n_msgs, sizeof(smartlist_t*));

  SMARTLIST_FOREACH_BEGIN(cfg->items, const pubsub_cfg_t *, item) {
    dispatch_adjacency_map_add(map, item);
  } SMARTLIST_FOREACH_END(item);

  return map;
}

/**
 * Helper: add a single pubsub_cft_t to an adjacency map.
 **/
static void
dispatch_adjacency_map_add(dispatch_adjacency_map_t *map,
                           const pubsub_cfg_t *item)
{
  smartlist_t **by_subsys;
  smartlist_t **by_msg;

  tor_assert(item->subsys < map->n_subsystems);
  tor_assert(item->msg < map->n_msgs);

  if (item->is_publish) {
    by_subsys = &map->pub_by_subsys[item->subsys];
    by_msg = &map->pub_by_msg[item->msg];
  } else {
    by_subsys = &map->sub_by_subsys[item->subsys];
    by_msg = &map->sub_by_msg[item->msg];
  }

  if (! *by_subsys)
    *by_subsys = smartlist_new();
  if (! *by_msg)
    *by_msg = smartlist_new();
  smartlist_add(*by_subsys, (void*) item);
  smartlist_add(*by_msg, (void *) item);
}

/**
 * Release all storage held by m and set m to NULL.
 **/
#define dispatch_adjacency_map_free(m) \
  FREE_AND_NULL(dispatch_adjacency_map_t, dispatch_adjacency_map_free_, m)

/**
 * Free everty element of an <b>n</b>-element array of smartlists, then
 * free the array itself.
 **/
static void
dispatch_adjacency_map_free_helper(smartlist_t **lsts, size_t n)
{
  if (!lsts)
    return;

  for (unsigned i = 0; i < n; ++i) {
    smartlist_free(lsts[i]);
  }
  tor_free(lsts);
}

/**
 * Release all storage held by <b>map</b>.
 **/
static void
dispatch_adjacency_map_free_(dispatch_adjacency_map_t *map)
{
  if (!map)
    return;
  dispatch_adjacency_map_free_helper(map->pub_by_subsys, map->n_subsystems);
  dispatch_adjacency_map_free_helper(map->sub_by_subsys, map->n_subsystems);
  dispatch_adjacency_map_free_helper(map->pub_by_msg, map->n_msgs);
  dispatch_adjacency_map_free_helper(map->sub_by_msg, map->n_msgs);
  tor_free(map);
}

/**
 * Helper: return the length of <b>sl</b>, or 0 if sl is NULL.
 **/
static int
smartlist_len_opt(const smartlist_t *sl)
{
  if (sl)
    return smartlist_len(sl);
  else
    return 0;
}

/** Return a pointer to a statically allocated string encoding the
 * dispatcher flags in <b>flags</b>. */
static const char *
format_flags(unsigned flags)
{
  static char buf[32];
  buf[0] = 0;
  if (flags & DISP_FLAG_EXCL) {
    strlcat(buf, " EXCL", sizeof(buf));
  }
  if (flags & DISP_FLAG_STUB) {
    strlcat(buf, " STUB", sizeof(buf));
  }
  return buf[0] ? buf+1 : buf;
}

/**
 * Log a message containing a description of <b>cfg</b> at severity, prefixed
 * by the string <b>prefix</b>.
 */
static void
pubsub_cfg_dump(const pubsub_cfg_t *cfg, int severity, const char *prefix)
{
  if (!prefix)
    prefix = 0;

  tor_log(severity, LD_MESG,
          "%s%s %s: %s{%s} on %s (%s) <%u %u %u %u %x> [%s:%d]",
          prefix,
          get_subsys_id_name(cfg->subsys),
          cfg->is_publish ? "PUB" : "SUB",
          get_message_id_name(cfg->msg),
          get_msg_type_id_name(cfg->type),
          get_channel_id_name(cfg->channel),
          format_flags(cfg->flags),
          cfg->subsys, cfg->msg, cfg->type, cfg->channel, cfg->flags,
          cfg->added_by_file, cfg->added_by_line);
}

/**
 * Check whether there are any errors or inconsistencies for the message
 * described by <b>msg</b> in <b>map</b>.  If there are problems, log about
 * them, and return -1.  Otherwise return 0.
 **/
static int
lint_message(const dispatch_adjacency_map_t *map, message_id_t msg)
{
  /* NOTE: Some of the checks in this function are maybe over-zealous, and we
   * might not want to have them forever.  I've marked them with [?] below.
   */
  if (BUG(msg >= map->n_msgs))
    return 0; // LCOV_EXCL_LINE

  const smartlist_t *pub = map->pub_by_msg[msg];
  const smartlist_t *sub = map->sub_by_msg[msg];

  const size_t n_pub = smartlist_len_opt(pub);
  const size_t n_sub = smartlist_len_opt(sub);

  if (n_pub == 0 && n_sub == 0) {
    log_info(LD_MESG, "Nobody is publishing or subscribing to message %u "
             "(%s).",
             msg, get_message_id_name(msg));
    return 0; // No publishers or subscribers: nothing to do.
  }

  /* We'll set this to false if there are any problems. */
  bool ok = true;

  /* First make sure that if there are publishers, there are subscribers. */
  if (n_pub == 0) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) has subscribers, but no publishers.",
            msg, get_message_id_name(msg));
    ok = false;
  } else if (n_sub == 0) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) has publishers, but no subscribers.",
            msg, get_message_id_name(msg));
    ok = false;
  }

  /* The 'all' list has the publishers and the subscribers. */
  smartlist_t *all = smartlist_new();
  if (pub)
    smartlist_add_all(all, pub);
  if (sub)
    smartlist_add_all(all, sub);
  const pubsub_cfg_t *item0 = smartlist_get(all, 0);

  /* Indicates which subsystems we've found publishing/subscribing here. */
  bitarray_t *published_by = bitarray_init_zero((unsigned)map->n_subsystems);
  bitarray_t *subscribed_by = bitarray_init_zero((unsigned)map->n_subsystems);
  bool pub_excl = false, sub_excl = false, chan_same = true, type_same = true;

  /* Make sure that the messages all have the same channel and type;
   * check whether the DISP_FLAG_EXCL flag is used;
   * and if any subsystem is publishing or subscribing to it twice [??].
   */
  SMARTLIST_FOREACH_BEGIN(all, const pubsub_cfg_t *, cfg) {
    if (cfg->channel != item0->channel) {
      chan_same = false;
    }
    if (cfg->type != item0->type) {
      type_same = false;
    }
    if (cfg->flags & DISP_FLAG_EXCL) {
      if (cfg->is_publish)
        pub_excl = true;
      else
        sub_excl = true;
    }
    if (cfg->is_publish) {
      if (bitarray_is_set(published_by, cfg->subsys)) {
        log_warn(LD_MESG|LD_BUG,
                 "Message %u (%s) is configured to be published by subsystem "
                 "%u (%s) more than once.",
                 msg, get_message_id_name(msg),
                 cfg->subsys, get_subsys_id_name(cfg->subsys));
        ok = false;
      }
      bitarray_set(published_by, cfg->subsys);
    } else {
      if (bitarray_is_set(subscribed_by, cfg->subsys)) {
        log_warn(LD_MESG|LD_BUG,
                 "Message %u (%s) is configured to be subscribed by subsystem "
                 "%u (%s) more than once.",
                 msg, get_message_id_name(msg),
                 cfg->subsys, get_subsys_id_name(cfg->subsys));
        ok = false;
      }
      bitarray_set(subscribed_by, cfg->subsys);
    }
  } SMARTLIST_FOREACH_END(cfg);

  /* Check whether any subsystem is publishing and subscribing the same
   * message. [??]
   */
  for (unsigned i = 0; i < map->n_subsystems; ++i) {
    if (bitarray_is_set(published_by, i) &&
        bitarray_is_set(subscribed_by, i)) {
      log_warn(LD_MESG|LD_BUG,
               "Message %u (%s) is published and subscribed by the same "
               "subsystem %u (%s)",
               msg, get_message_id_name(msg),
               i, get_subsys_id_name(i));
      ok = false;
    }
  }

  if (! chan_same) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) is associated with multiple inconsistent "
             "channels.",
            msg, get_message_id_name(msg));
    ok = false;
  }
  if (! type_same) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) is associated with multiple inconsistent "
             "message types.",
            msg, get_message_id_name(msg));
    ok = false;
  }

  /* Enforce exclusive-ness for publishers and subscribers that have asked for
   * it.
   */
  if (pub_excl && smartlist_len(pub) > 1) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) has multiple publishers, but at least one is "
             "marked as exclusive.",
            msg, get_message_id_name(msg));
    ok = false;
  }
  if (sub_excl && smartlist_len(sub) > 1) {
    log_warn(LD_MESG|LD_BUG,
             "Message %u (%s) has multiple subscribers, but at least one is "
             "marked as exclusive.",
            msg, get_message_id_name(msg));
    ok = false;
  }

  if (!ok) {
    /* There was a problem -- let's log all the publishers and subscribers on
     * this message */
    SMARTLIST_FOREACH(all, pubsub_cfg_t *, cfg,
                      pubsub_cfg_dump(cfg, LOG_WARN, "   "));
  }

  smartlist_free(all);
  bitarray_free(published_by);
  bitarray_free(subscribed_by);

  return ok ? 0 : -1;
}

/**
 * Check all the messages in <b>map</b> for consistency.  Return 0 on success,
 * -1 on problems.
 **/
static int
dispatch_adjacency_map_check(const dispatch_adjacency_map_t *map)
{
  bool all_ok = true;
  for (unsigned i = 0; i < map->n_msgs; ++i) {
    if (lint_message(map, i) < 0) {
      all_ok = false;
    }
  }
  return all_ok ? 0 : -1;
}

/**
 * Return true if there is a recv_fn associated with <b>cfg</b> that we should
 * use.
 **/
static bool
has_recv_fn(const pubsub_cfg_t *cfg)
{
  if (cfg->is_publish)
    return false;
  if (cfg->flags & DISP_FLAG_STUB)
    return false;
  if (cfg->recv_fn == NULL)
    return false;

  return true;
}

/** Fill the fns and more_fns fields of <b>ent</b> with the recv_fn values
 * configured in <b>subscribers</b>.
 */
static void
fill_recv_fn_table(dispatch_table_entry_t *ent,
                   const smartlist_t *subscribers)
{
  /*
   * First count how many functions there are.
   */
  unsigned n = 0;
  SMARTLIST_FOREACH_BEGIN(subscribers, const pubsub_cfg_t *, cfg) {
    if (has_recv_fn(cfg))
      ++n;
  } SMARTLIST_FOREACH_END(cfg);

  /* Allocate space for more_fns if needed */
  if (n > N_FAST_FNS) {
    ent->more_fns = tor_calloc(n - N_FAST_FNS, sizeof(recv_fn_t));
  }

  /* Copy the functions into ent. */
  unsigned i = 0;
  SMARTLIST_FOREACH_BEGIN(subscribers, const pubsub_cfg_t *, cfg) {
    if (has_recv_fn(cfg)) {
      if (i < N_FAST_FNS) {
        ent->fns[i] = cfg->recv_fn;
      } else {
        ent->more_fns[i - N_FAST_FNS] = cfg->recv_fn;
      }
      ++i;
    }
  } SMARTLIST_FOREACH_END(cfg);

  /* Set n_enabled and n_fns. See note in dispatch_table_entry_t. */
  tor_assert(i == n);
  ent->n_enabled = ent->n_fns = n;
}

/**
 * Given an adjacency map, construct and return a new dispatch table for
 * each message type, indexed by message ID.  Set *<b>n_msgs_out</b> to the
 * length of the table.
 **/
static dispatch_table_entry_t *
construct_dispatch_table(const dispatch_adjacency_map_t *map,
                         size_t *n_msgs_out)
{
  const size_t n_msgs = *n_msgs_out = map->n_msgs;

  dispatch_table_entry_t *table =
    tor_calloc(n_msgs, sizeof(dispatch_table_entry_t));

  for (unsigned msg = 0; msg < map->n_msgs; ++msg) {
    const smartlist_t *publist = map->pub_by_msg[msg];
    const smartlist_t *sublist = map->sub_by_msg[msg];
    dispatch_table_entry_t *ent = &table[msg];

    const pubsub_cfg_t *item0;
    if (smartlist_len_opt(sublist) == 0) {
      if (smartlist_len_opt(publist) == 0)
        continue; // should have been caught by lint above.

      item0 = smartlist_get(publist, 0);
    } else {
      item0 = smartlist_get(sublist, 0);
    }

    ent->channel = item0->channel;
    ent->type = item0->type;

    if (sublist == NULL)
      continue;

    fill_recv_fn_table(ent, sublist);
  }

  return table;
}

/** Format an unformattable message auxiliary data item: just return a
 * copy of the string <>. */
static char *
type_fmt_nop(msg_aux_data_t arg)
{
  (void)arg;
  return tor_strdup("<>");
}

/** Free an unfreeable message auxiliary data item: do nothing. */
static void
type_free_nop(msg_aux_data_t arg)
{
  (void)arg;
}

/** Type functions to use when no type functions are provided. */
static dispatch_typefns_t nop_typefns = {
  .free_fn = type_free_nop,
  .fmt_fn = type_fmt_nop
};

/** Construct a table of typefns for the types in <b>cfg</b>, setting
 * <b>n_types_out</b> to the length of the table, and filling in any
 * unspecified defaults.
 *
 * Warn and return NULL if there are redundant declarations.
 */
static dispatch_typefns_t *
construct_type_table(const dispatch_cfg_t *cfg, size_t *n_types_out)
{
  /* Find out how many types there are.
   */
  unsigned max_type_id = 0;
  SMARTLIST_FOREACH(cfg->type_items, const pubsub_type_cfg_t *, item, {
      if (item->type > max_type_id)
        max_type_id = item->type;
  });

  /* Construct the table, and an array for pointers to use for detecting
   * double declarations. */
  const size_t n_types = *n_types_out = max_type_id + 1;
  const pubsub_type_cfg_t **typecfg =
    tor_calloc(n_types, sizeof(pubsub_type_cfg_t *));
  dispatch_typefns_t *table = tor_calloc(n_types, sizeof(dispatch_typefns_t));

  /* Fill in the table with the default no-op implementations. */
  for (size_t i = 0; i < n_types; ++i) {
    memcpy(&table[i], &nop_typefns, sizeof(dispatch_typefns_t));
  }

  bool ok = true;
  /*
   * Fill in the table, warning about duplicates.
   */
  SMARTLIST_FOREACH_BEGIN(cfg->type_items, const pubsub_type_cfg_t *, item) {
    if (typecfg[item->type]) {
      const pubsub_type_cfg_t *old = typecfg[item->type];
      log_warn(LD_MESG|LD_BUG,
               "Type %u (%s) declared twice: by %u (%s) at %s:%u "
               "and %u (%s) at %s:%u.",
               item->type, get_msg_type_id_name(item->type),
               item->subsys, get_subsys_id_name(item->subsys),
               item->added_by_file, item->added_by_line,
               old->subsys, get_subsys_id_name(old->subsys),
               old->added_by_file, old->added_by_line);
      ok = false;
      continue;
    }
    typecfg[item->type] = item;
    memcpy(&table[item->type], &item->fns, sizeof(dispatch_typefns_t));

    if (!table[item->type].free_fn)
      table[item->type].free_fn = nop_typefns.free_fn;
    if (!table[item->type].fmt_fn)
      table[item->type].fmt_fn = nop_typefns.fmt_fn;

  } SMARTLIST_FOREACH_END(item);

  tor_free(typecfg);
  if (!ok)
    tor_free(table);
  return table;
}

/**
 * Initialize the dispatch_ptr field in every relevant publish binding
 * for <b>d</b>.
 */
static void
dispatch_fill_pub_binding_backptrs(dispatcher_t *d)
{
  SMARTLIST_FOREACH_BEGIN(d->cfg->items, pubsub_cfg_t *, cfg) {
    if (cfg->pub_binding) {
      // XXXX we could skip this for STUB publishers, and for any publishers
      // XXXX where all subscribers are STUB.
      cfg->pub_binding->dispatch_ptr = d;
    }
  } SMARTLIST_FOREACH_END(cfg);
}

/**
 * Alert function to use when none is configured: do nothing.
 **/
static void
alert_fn_nop(dispatcher_t *d, channel_id_t ch, void *arg)
{
  (void)d;
  (void)ch;
  (void)arg;
}

/**
 * Used in constructing a dispatcher: create its message queues.
 **/
static void
dispatch_init_queues(dispatcher_t *d)
{
  /* Count how many channels we need. */
  unsigned max_channel = 0;
  SMARTLIST_FOREACH_BEGIN(d->cfg->items, const pubsub_cfg_t *, item) {
    if (item->channel > max_channel)
      max_channel = item->channel;
  } SMARTLIST_FOREACH_END(item);

  /* Allocate and initialize their queues */
  d->n_queues = max_channel + 1;
  d->queues = tor_calloc(d->n_queues, sizeof(dispatch_queue_t));
  for (unsigned i = 0; i < d->n_queues; ++i) {
    mqueue_init(&d->queues[i].queue);
    d->queues[i].alert_fn = alert_fn_nop;
  }
}

dispatcher_t *
dispatch_builder_finalize(dispatch_builder_t *builder)
{
  dispatcher_t *dispatcher = NULL;
  dispatch_typefns_t *typefns = NULL;
  dispatch_adjacency_map_t *map = dispatch_build_adjacency_map(builder->cfg);

  tor_assert_nonfatal(builder->n_connectors == 0);

  if (!map)
    goto err; // should be impossible

  if (dispatch_adjacency_map_check(map) < 0)
    goto err;

  size_t n_msgs = 0;
  size_t n_types = 0;

  typefns = construct_type_table(builder->cfg, &n_types);
  if (!typefns)
    goto err;

  dispatch_table_entry_t *table = construct_dispatch_table(map, &n_msgs);
  if (! table)
    goto err; // should be impossible

  dispatcher = tor_malloc_zero(sizeof(*dispatcher));
  dispatcher->cfg = builder->cfg;
  dispatcher->n_msgs = n_msgs;
  dispatcher->n_types = n_types;
  builder->cfg = NULL; // prevent double-free
  dispatcher->table = table;
  dispatcher->typefns = typefns;
  typefns = NULL; // prevent double-free

  dispatch_fill_pub_binding_backptrs(dispatcher);

  dispatch_init_queues(dispatcher);

 err:
  dispatch_adjacency_map_free(map);
  dispatch_builder_free(builder);
  tor_free(typefns);
  return dispatcher;
}
