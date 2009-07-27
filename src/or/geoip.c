/* Copyright (c) 2007-2009, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file geoip.c
 * \brief Functions related to maintaining an IP-to-country database and to
 *    summarizing client connections by country.
 */

#define GEOIP_PRIVATE
#include "or.h"
#include "ht.h"

static void clear_geoip_db(void);
static void dump_geoip_stats(void);
static void dump_entry_stats(void);

/** An entry from the GeoIP file: maps an IP range to a country. */
typedef struct geoip_entry_t {
  uint32_t ip_low; /**< The lowest IP in the range, in host order */
  uint32_t ip_high; /**< The highest IP in the range, in host order */
  intptr_t country; /**< An index into geoip_countries */
} geoip_entry_t;

/** For how many periods should we remember per-country request history? */
#define REQUEST_HIST_LEN 1
/** How long are the periods for which we should remember request history? */
#define REQUEST_HIST_PERIOD (24*60*60)

/** A per-country record for GeoIP request history. */
typedef struct geoip_country_t {
  char countrycode[3];
  uint32_t n_v2_ns_requests[REQUEST_HIST_LEN];
  uint32_t n_v3_ns_requests[REQUEST_HIST_LEN];
} geoip_country_t;

/** A list of geoip_country_t */
static smartlist_t *geoip_countries = NULL;
/** A map from lowercased country codes to their position in geoip_countries.
 * The index is encoded in the pointer, and 1 is added so that NULL can mean
 * not found. */
static strmap_t *country_idxplus1_by_lc_code = NULL;
/** A list of all known geoip_entry_t, sorted by ip_low. */
static smartlist_t *geoip_entries = NULL;

/** Return the index of the <b>country</b>'s entry in the GeoIP DB
 * if it is a valid 2-letter country code, otherwise return -1.
 */
country_t
geoip_get_country(const char *country)
{
  void *_idxplus1;
  intptr_t idx;

  _idxplus1 = strmap_get_lc(country_idxplus1_by_lc_code, country);
  if (!_idxplus1)
    return -1;

  idx = ((uintptr_t)_idxplus1)-1;
  return (country_t)idx;
}

/** Add an entry to the GeoIP table, mapping all IPs between <b>low</b> and
 * <b>high</b>, inclusive, to the 2-letter country code <b>country</b>.
 */
static void
geoip_add_entry(uint32_t low, uint32_t high, const char *country)
{
  intptr_t idx;
  geoip_entry_t *ent;
  void *_idxplus1;

  if (high < low)
    return;

  _idxplus1 = strmap_get_lc(country_idxplus1_by_lc_code, country);

  if (!_idxplus1) {
    geoip_country_t *c = tor_malloc_zero(sizeof(geoip_country_t));
    strlcpy(c->countrycode, country, sizeof(c->countrycode));
    tor_strlower(c->countrycode);
    smartlist_add(geoip_countries, c);
    idx = smartlist_len(geoip_countries) - 1;
    strmap_set_lc(country_idxplus1_by_lc_code, country, (void*)(idx+1));
  } else {
    idx = ((uintptr_t)_idxplus1)-1;
  }
  {
    geoip_country_t *c = smartlist_get(geoip_countries, idx);
    tor_assert(!strcasecmp(c->countrycode, country));
  }
  ent = tor_malloc_zero(sizeof(geoip_entry_t));
  ent->ip_low = low;
  ent->ip_high = high;
  ent->country = idx;
  smartlist_add(geoip_entries, ent);
}

/** Add an entry to the GeoIP table, parsing it from <b>line</b>.  The
 * format is as for geoip_load_file(). */
/*private*/ int
geoip_parse_entry(const char *line)
{
  unsigned int low, high;
  char b[3];
  if (!geoip_countries) {
    geoip_countries = smartlist_create();
    geoip_entries = smartlist_create();
    country_idxplus1_by_lc_code = strmap_new();
  }
  while (TOR_ISSPACE(*line))
    ++line;
  if (*line == '#')
    return 0;
  if (sscanf(line,"%u,%u,%2s", &low, &high, b) == 3) {
    geoip_add_entry(low, high, b);
    return 0;
  } else if (sscanf(line,"\"%u\",\"%u\",\"%2s\",", &low, &high, b) == 3) {
    geoip_add_entry(low, high, b);
    return 0;
  } else {
    log_warn(LD_GENERAL, "Unable to parse line from GEOIP file: %s",
             escaped(line));
    return -1;
  }
}

/** Sorting helper: return -1, 1, or 0 based on comparison of two
 * geoip_entry_t */
static int
_geoip_compare_entries(const void **_a, const void **_b)
{
  const geoip_entry_t *a = *_a, *b = *_b;
  if (a->ip_low < b->ip_low)
    return -1;
  else if (a->ip_low > b->ip_low)
    return 1;
  else
    return 0;
}

/** bsearch helper: return -1, 1, or 0 based on comparison of an IP (a pointer
 * to a uint32_t in host order) to a geoip_entry_t */
static int
_geoip_compare_key_to_entry(const void *_key, const void **_member)
{
  const uint32_t addr = *(uint32_t *)_key;
  const geoip_entry_t *entry = *_member;
  if (addr < entry->ip_low)
    return -1;
  else if (addr > entry->ip_high)
    return 1;
  else
    return 0;
}

/** Return 1 if we should collect geoip stats on bridge users, and
 * include them in our extrainfo descriptor. Else return 0. */
int
should_record_bridge_info(or_options_t *options)
{
  return options->BridgeRelay && options->BridgeRecordUsageByCountry;
}

/** Clear the GeoIP database and reload it from the file
 * <b>filename</b>. Return 0 on success, -1 on failure.
 *
 * Recognized line formats are:
 *   INTIPLOW,INTIPHIGH,CC
 * and
 *   "INTIPLOW","INTIPHIGH","CC","CC3","COUNTRY NAME"
 * where INTIPLOW and INTIPHIGH are IPv4 addresses encoded as 4-byte unsigned
 * integers, and CC is a country code.
 *
 * It also recognizes, and skips over, blank lines and lines that start
 * with '#' (comments).
 */
int
geoip_load_file(const char *filename, or_options_t *options)
{
  FILE *f;
  const char *msg = "";
  int severity = options_need_geoip_info(options, &msg) ? LOG_WARN : LOG_INFO;
  clear_geoip_db();
  if (!(f = fopen(filename, "r"))) {
    log_fn(severity, LD_GENERAL, "Failed to open GEOIP file %s.  %s",
           filename, msg);
    return -1;
  }
  if (!geoip_countries) {
    geoip_country_t *geoip_unresolved;
    geoip_countries = smartlist_create();
    /* Add a geoip_country_t for requests that could not be resolved to a
     * country as first element (index 0) to geoip_countries. */
    geoip_unresolved = tor_malloc_zero(sizeof(geoip_country_t));
    strlcpy(geoip_unresolved->countrycode, "??",
            sizeof(geoip_unresolved->countrycode));
    smartlist_add(geoip_countries, geoip_unresolved);
    country_idxplus1_by_lc_code = strmap_new();
  }
  if (geoip_entries) {
    SMARTLIST_FOREACH(geoip_entries, geoip_entry_t *, e, tor_free(e));
    smartlist_free(geoip_entries);
  }
  geoip_entries = smartlist_create();
  log_notice(LD_GENERAL, "Parsing GEOIP file.");
  while (!feof(f)) {
    char buf[512];
    if (fgets(buf, (int)sizeof(buf), f) == NULL)
      break;
    /* FFFF track full country name. */
    geoip_parse_entry(buf);
  }
  /*XXXX abort and return -1 if no entries/illformed?*/
  fclose(f);

  smartlist_sort(geoip_entries, _geoip_compare_entries);

  /* Okay, now we need to maybe change our mind about what is in which
   * country. */
  refresh_all_country_info();

  return 0;
}

/** Given an IP address in host order, return a number representing the
 * country to which that address belongs, or -1 for unknown.  The return value
 * will always be less than geoip_get_n_countries().  To decode it,
 * call geoip_get_country_name().
 */
int
geoip_get_country_by_ip(uint32_t ipaddr)
{
  geoip_entry_t *ent;
  if (!geoip_entries)
    return -1;
  ent = smartlist_bsearch(geoip_entries, &ipaddr, _geoip_compare_key_to_entry);
  return ent ? (int)ent->country : -1;
}

/** Return the number of countries recognized by the GeoIP database. */
int
geoip_get_n_countries(void)
{
  return (int) smartlist_len(geoip_countries);
}

/** Return the two-letter country code associated with the number <b>num</b>,
 * or "??" for an unknown value. */
const char *
geoip_get_country_name(country_t num)
{
  if (geoip_countries && num >= 0 && num < smartlist_len(geoip_countries)) {
    geoip_country_t *c = smartlist_get(geoip_countries, num);
    return c->countrycode;
  } else
    return "??";
}

/** Return true iff we have loaded a GeoIP database.*/
int
geoip_is_loaded(void)
{
  return geoip_countries != NULL && geoip_entries != NULL;
}

/** Entry in a map from IP address to the last time we've seen an incoming
 * connection from that IP address. Used by bridges only, to track which
 * countries have them blocked. */
typedef struct clientmap_entry_t {
  HT_ENTRY(clientmap_entry_t) node;
  uint32_t ipaddr;
  unsigned int last_seen_in_minutes:30;
  unsigned int action:2;
} clientmap_entry_t;

#define ACTION_MASK 3

/** Map from client IP address to last time seen. */
static HT_HEAD(clientmap, clientmap_entry_t) client_history =
     HT_INITIALIZER();
/** Time at which we started tracking client IP history. */
static time_t client_history_starts = 0;

/** When did the current period of checking per-country request history
 * start? */
static time_t current_request_period_starts = 0;
/** How many older request periods are we remembering? */
static int n_old_request_periods = 0;

/** Hashtable helper: compute a hash of a clientmap_entry_t. */
static INLINE unsigned
clientmap_entry_hash(const clientmap_entry_t *a)
{
  return ht_improve_hash((unsigned) a->ipaddr);
}
/** Hashtable helper: compare two clientmap_entry_t values for equality. */
static INLINE int
clientmap_entries_eq(const clientmap_entry_t *a, const clientmap_entry_t *b)
{
  return a->ipaddr == b->ipaddr && a->action == b->action;
}

HT_PROTOTYPE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
             clientmap_entries_eq);
HT_GENERATE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
            clientmap_entries_eq, 0.6, malloc, realloc, free);

/** How often do we update our estimate which share of v2 and v3 directory
 * requests is sent to us? We could as well trigger updates of shares from
 * network status updates, but that means adding a lot of calls into code
 * that is independent from geoip stats (and keeping them up-to-date). We
 * are perfectly fine with an approximation of 15-minute granularity. */
#define REQUEST_SHARE_INTERVAL (15 * 60)

/** When did we last determine which share of v2 and v3 directory requests
 * is sent to us? */
static time_t last_time_determined_shares = 0;

/** Sum of products of v2 shares times the number of seconds for which we
 * consider these shares as valid. */
static double v2_share_times_seconds;

/** Sum of products of v3 shares times the number of seconds for which we
 * consider these shares as valid. */
static double v3_share_times_seconds;

/** Number of seconds we are determining v2 and v3 shares. */
static int share_seconds;

/** Try to determine which fraction of v2 and v3 directory requests aimed at
 * caches will be sent to us at time <b>now</b> and store that value in
 * order to take a mean value later on. */
static void
geoip_determine_shares(time_t now)
{
  double v2_share = 0.0, v3_share = 0.0;
  if (router_get_my_share_of_directory_requests(&v2_share, &v3_share) < 0)
    return;
  if (last_time_determined_shares) {
    v2_share_times_seconds += v2_share *
        ((double) (now - last_time_determined_shares));
    v3_share_times_seconds += v3_share *
        ((double) (now - last_time_determined_shares));
    share_seconds += now - last_time_determined_shares;
  }
  last_time_determined_shares = now;
}

#ifdef ENABLE_DIRREQ_STATS
/** Calculate which fraction of v2 and v3 directory requests aimed at caches
 * have been sent to us since the last call of this function up to time
 * <b>now</b>. Set *<b>v2_share_out</b> and *<b>v3_share_out</b> to the
 * fractions of v2 and v3 protocol shares we expect to have seen. Reset
 * counters afterwards. Return 0 on success, -1 on failure (e.g. when zero
 * seconds have passed since the last call).*/
static int
geoip_get_mean_shares(time_t now, double *v2_share_out,
                         double *v3_share_out)
{
  geoip_determine_shares(now);
  if (!share_seconds)
    return -1;
  *v2_share_out = v2_share_times_seconds / ((double) share_seconds);
  *v3_share_out = v3_share_times_seconds / ((double) share_seconds);
  v2_share_times_seconds = v3_share_times_seconds = 0.0;
  share_seconds = 0;
  return 0;
}
#endif

/** Note that we've seen a client connect from the IP <b>addr</b> (host order)
 * at time <b>now</b>. Ignored by all but bridges and directories if
 * configured accordingly. */
void
geoip_note_client_seen(geoip_client_action_t action,
                       uint32_t addr, time_t now)
{
  or_options_t *options = get_options();
  clientmap_entry_t lookup, *ent;
  if (action == GEOIP_CLIENT_CONNECT) {
#ifdef ENABLE_ENTRY_STATS
    if (!options->EntryStatistics)
      return;
#else
    if (!(options->BridgeRelay && options->BridgeRecordUsageByCountry))
      return;
#endif
    /* Did we recently switch from bridge to relay or back? */
    if (client_history_starts > now)
      return;
  } else {
#ifndef ENABLE_DIRREQ_STATS
    return;
#else
    if (options->BridgeRelay || options->BridgeAuthoritativeDir ||
        !options->DirReqStatistics)
      return;
#endif
  }

  /* Rotate the current request period. */
  while (current_request_period_starts + REQUEST_HIST_PERIOD < now) {
    if (!geoip_countries)
      geoip_countries = smartlist_create();
    if (!current_request_period_starts) {
      current_request_period_starts = now;
      break;
    }
    /* Also discard all items in the client history that are too old.
     * (This only works here because bridge and directory stats are
     * independent. Otherwise, we'd only want to discard those items
     * with action GEOIP_CLIENT_NETWORKSTATUS{_V2}.) */
    geoip_remove_old_clients(current_request_period_starts);
    /* Before rotating, write the current stats to disk. */
    dump_geoip_stats();
    if (get_options()->EntryStatistics)
      dump_entry_stats();
    /* Now rotate request period */
    SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c, {
        memmove(&c->n_v2_ns_requests[0], &c->n_v2_ns_requests[1],
                sizeof(uint32_t)*(REQUEST_HIST_LEN-1));
        memmove(&c->n_v3_ns_requests[0], &c->n_v3_ns_requests[1],
                sizeof(uint32_t)*(REQUEST_HIST_LEN-1));
        c->n_v2_ns_requests[REQUEST_HIST_LEN-1] = 0;
        c->n_v3_ns_requests[REQUEST_HIST_LEN-1] = 0;
      });
    current_request_period_starts += REQUEST_HIST_PERIOD;
    if (n_old_request_periods < REQUEST_HIST_LEN-1)
      ++n_old_request_periods;
  }

  lookup.ipaddr = addr;
  lookup.action = (int)action;
  ent = HT_FIND(clientmap, &client_history, &lookup);
  if (ent) {
    ent->last_seen_in_minutes = now / 60;
  } else {
    ent = tor_malloc_zero(sizeof(clientmap_entry_t));
    ent->ipaddr = addr;
    ent->last_seen_in_minutes = now / 60;
    ent->action = (int)action;
    HT_INSERT(clientmap, &client_history, ent);
  }

  if (action == GEOIP_CLIENT_NETWORKSTATUS ||
      action == GEOIP_CLIENT_NETWORKSTATUS_V2) {
    int country_idx = geoip_get_country_by_ip(addr);
    if (country_idx < 0)
      country_idx = 0; /** unresolved requests are stored at index 0. */
    if (country_idx >= 0 && country_idx < smartlist_len(geoip_countries)) {
      geoip_country_t *country = smartlist_get(geoip_countries, country_idx);
      if (action == GEOIP_CLIENT_NETWORKSTATUS)
        ++country->n_v3_ns_requests[REQUEST_HIST_LEN-1];
      else
        ++country->n_v2_ns_requests[REQUEST_HIST_LEN-1];
    }

    /* Periodically determine share of requests that we should see */
    if (last_time_determined_shares + REQUEST_SHARE_INTERVAL < now)
      geoip_determine_shares(now);
  }

  if (!client_history_starts) {
    client_history_starts = now;
    current_request_period_starts = now;
  }
}

/** HT_FOREACH helper: remove a clientmap_entry_t from the hashtable if it's
 * older than a certain time. */
static int
_remove_old_client_helper(struct clientmap_entry_t *ent, void *_cutoff)
{
  time_t cutoff = *(time_t*)_cutoff / 60;
  if (ent->last_seen_in_minutes < cutoff) {
    tor_free(ent);
    return 1;
  } else {
    return 0;
  }
}

/** Forget about all clients that haven't connected since <b>cutoff</b>.
 * If <b>cutoff</b> is in the future, clients won't be added to the history
 * until this time is reached. This is useful to prevent relays that switch
 * to bridges from reporting unbelievable numbers of clients. */
void
geoip_remove_old_clients(time_t cutoff)
{
  clientmap_HT_FOREACH_FN(&client_history,
                          _remove_old_client_helper,
                          &cutoff);
  if (client_history_starts < cutoff)
    client_history_starts = cutoff;
}

#ifdef ENABLE_DIRREQ_STATS
/** How many responses are we giving to clients requesting v2 network
 * statuses? */
static uint32_t ns_v2_responses[GEOIP_NS_RESPONSE_NUM];

/** How many responses are we giving to clients requesting v3 network
 * statuses? */
static uint32_t ns_v3_responses[GEOIP_NS_RESPONSE_NUM];
#endif

/** Note that we've rejected a client's request for a v2 or v3 network
 * status, encoded in <b>action</b> for reason <b>reason</b> at time
 * <b>now</b>. */
void
geoip_note_ns_response(geoip_client_action_t action,
                       geoip_ns_response_t response)
{
#ifdef ENABLE_DIRREQ_STATS
  static int arrays_initialized = 0;
  if (!get_options()->DirReqStatistics)
    return;
  if (!arrays_initialized) {
    memset(ns_v2_responses, 0, sizeof(ns_v2_responses));
    memset(ns_v3_responses, 0, sizeof(ns_v3_responses));
    arrays_initialized = 1;
  }
  tor_assert(action == GEOIP_CLIENT_NETWORKSTATUS ||
             action == GEOIP_CLIENT_NETWORKSTATUS_V2);
  tor_assert(response < GEOIP_NS_RESPONSE_NUM);
  if (action == GEOIP_CLIENT_NETWORKSTATUS)
    ns_v3_responses[response]++;
  else
    ns_v2_responses[response]++;
#else
  (void) action;
  (void) response;
#endif
}

/** Do not mention any country from which fewer than this number of IPs have
 * connected.  This conceivably avoids reporting information that could
 * deanonymize users, though analysis is lacking. */
#define MIN_IPS_TO_NOTE_COUNTRY 1
/** Do not report any geoip data at all if we have fewer than this number of
 * IPs to report about. */
#define MIN_IPS_TO_NOTE_ANYTHING 1
/** When reporting geoip data about countries, round up to the nearest
 * multiple of this value. */
#define IP_GRANULARITY 8

/** Return the time at which we started recording geoip data. */
time_t
geoip_get_history_start(void)
{
  return client_history_starts;
}

/** Helper type: used to sort per-country totals by value. */
typedef struct c_hist_t {
  char country[3]; /**< Two-letter country code. */
  unsigned total; /**< Total IP addresses seen in this country. */
} c_hist_t;

/** Sorting helper: return -1, 1, or 0 based on comparison of two
 * geoip_entry_t.  Sort in descending order of total, and then by country
 * code. */
static int
_c_hist_compare(const void **_a, const void **_b)
{
  const c_hist_t *a = *_a, *b = *_b;
  if (a->total > b->total)
    return -1;
  else if (a->total < b->total)
    return 1;
  else
    return strcmp(a->country, b->country);
}

/** When there are incomplete directory requests at the end of a 24-hour
 * period, consider those requests running for longer than this timeout as
 * failed, the others as still running. */
#define DIRREQ_TIMEOUT (10*60)

/** Entry in a map from either conn->global_identifier for direct requests
 * or a unique circuit identifier for tunneled requests to request time,
 * response size, and completion time of a network status request. Used to
 * measure download times of requests to derive average client
 * bandwidths. */
typedef struct dirreq_map_entry_t {
  HT_ENTRY(dirreq_map_entry_t) node;
  /** Unique identifier for this network status request; this is either the
   * conn->global_identifier of the dir conn (direct request) or a new
   * locally unique identifier of a circuit (tunneled request). This ID is
   * only unique among other direct or tunneled requests, respectively. */
  uint64_t dirreq_id;
  unsigned int state:3; /**< State of this directory request. */
  unsigned int type:1; /**< Is this a direct or a tunneled request? */
  unsigned int completed:1; /**< Is this request complete? */
  unsigned int action:2; /**< Is this a v2 or v3 request? */
  /** When did we receive the request and started sending the response? */
  struct timeval request_time;
  size_t response_size; /**< What is the size of the response in bytes? */
  struct timeval completion_time; /**< When did the request succeed? */
} dirreq_map_entry_t;

/** Map of all directory requests asking for v2 or v3 network statuses in
 * the current geoip-stats interval. Values are
 * of type *<b>dirreq_map_entry_t</b>. */
static HT_HEAD(dirreqmap, dirreq_map_entry_t) dirreq_map =
     HT_INITIALIZER();

static int
dirreq_map_ent_eq(const dirreq_map_entry_t *a,
                  const dirreq_map_entry_t *b)
{
  return a->dirreq_id == b->dirreq_id && a->type == b->type;
}

static unsigned
dirreq_map_ent_hash(const dirreq_map_entry_t *entry)
{
  unsigned u = (unsigned) entry->dirreq_id;
  u += entry->type << 20;
  return u;
}

HT_PROTOTYPE(dirreqmap, dirreq_map_entry_t, node, dirreq_map_ent_hash,
             dirreq_map_ent_eq);
HT_GENERATE(dirreqmap, dirreq_map_entry_t, node, dirreq_map_ent_hash,
            dirreq_map_ent_eq, 0.6, malloc, realloc, free);

/** Helper: Put <b>entry</b> into map of directory requests using
 * <b>tunneled</b> and <b>dirreq_id</b> as key parts. If there is
 * already an entry for that key, print out a BUG warning and return. */
static void
_dirreq_map_put(dirreq_map_entry_t *entry, dirreq_type_t type,
               uint64_t dirreq_id)
{
  dirreq_map_entry_t *old_ent;
  tor_assert(entry->type == type);
  tor_assert(entry->dirreq_id == dirreq_id);

  /* XXXX022 once we're sure the bug case never happens, we can switch
   * to HT_INSERT */
  old_ent = HT_REPLACE(dirreqmap, &dirreq_map, entry);
  if (old_ent && old_ent != entry) {
    log_warn(LD_BUG, "Error when putting directory request into local "
             "map. There was already an entry for the same identifier.");
    return;
  }
}

/** Helper: Look up and return an entry in the map of directory requests
 * using <b>tunneled</b> and <b>dirreq_id</b> as key parts. If there
 * is no such entry, return NULL. */
static dirreq_map_entry_t *
_dirreq_map_get(dirreq_type_t type, uint64_t dirreq_id)
{
  dirreq_map_entry_t lookup;
  lookup.type = type;
  lookup.dirreq_id = dirreq_id;
  return HT_FIND(dirreqmap, &dirreq_map, &lookup);
}

/** Note that an either direct or tunneled (see <b>type</b>) directory
 * request for a network status with unique ID <b>dirreq_id</b> of size
 * <b>response_size</b> and action <b>action</b> (either v2 or v3) has
 * started. */
void
geoip_start_dirreq(uint64_t dirreq_id, size_t response_size,
                   geoip_client_action_t action, dirreq_type_t type)
{
  dirreq_map_entry_t *ent;
  if (!get_options()->DirReqStatistics)
    return;
  ent = tor_malloc_zero(sizeof(dirreq_map_entry_t));
  ent->dirreq_id = dirreq_id;
  tor_gettimeofday(&ent->request_time);
  ent->response_size = response_size;
  ent->action = action;
  ent->type = type;
  _dirreq_map_put(ent, type, dirreq_id);
}

/** Change the state of the either direct or tunneled (see <b>type</b>)
 * directory request with <b>dirreq_id</b> to <b>new_state</b> and
 * possibly mark it as completed. If no entry can be found for the given
 * key parts (e.g., if this is a directory request that we are not
 * measuring, or one that was started in the previous measurement period),
 * or if the state cannot be advanced to <b>new_state</b>, do nothing. */
void
geoip_change_dirreq_state(uint64_t dirreq_id, dirreq_type_t type,
                          dirreq_state_t new_state)
{
  dirreq_map_entry_t *ent;
  if (!get_options()->DirReqStatistics)
    return;
  ent = _dirreq_map_get(type, dirreq_id);
  if (!ent)
    return;
  if (new_state == DIRREQ_IS_FOR_NETWORK_STATUS)
    return;
  if (new_state - 1 != ent->state)
    return;
  ent->state = new_state;
  if ((type == DIRREQ_DIRECT &&
         new_state == DIRREQ_FLUSHING_DIR_CONN_FINISHED) ||
      (type == DIRREQ_TUNNELED &&
         new_state == DIRREQ_OR_CONN_BUFFER_FLUSHED)) {
    tor_gettimeofday(&ent->completion_time);
    ent->completed = 1;
  }
}

#ifdef ENABLE_DIRREQ_STATS
/** Return a newly allocated comma-separated string containing statistics
 * on network status downloads. The string contains the number of completed
 * requests, timeouts, and still running requests as well as the download
 * times by deciles and quartiles. Return NULL if we have not observed
 * requests for long enough. */
static char *
geoip_get_dirreq_history(geoip_client_action_t action,
                           dirreq_type_t type)
{
  char *result = NULL;
  smartlist_t *dirreq_times = NULL;
  uint32_t complete = 0, timeouts = 0, running = 0;
  int i = 0, bufsize = 1024, written;
  dirreq_map_entry_t **ptr, **next, *ent;
  struct timeval now;

  tor_gettimeofday(&now);
  if (action != GEOIP_CLIENT_NETWORKSTATUS &&
      action != GEOIP_CLIENT_NETWORKSTATUS_V2)
    return NULL;
  dirreq_times = smartlist_create();
  for (ptr = HT_START(dirreqmap, &dirreq_map); ptr; ptr = next) {
    ent = *ptr;
    if (ent->action != action || ent->type != type) {
      next = HT_NEXT(dirreqmap, &dirreq_map, ptr);
      continue;
    } else {
      if (ent->completed) {
        uint32_t *bytes_per_second = tor_malloc_zero(sizeof(uint32_t));
        uint32_t time_diff = (uint32_t) tv_mdiff(&ent->request_time,
                                                 &ent->completion_time);
        if (time_diff == 0)
          time_diff = 1; /* Avoid DIV/0; "instant" answers are impossible
                          * anyway by law of nature or something.. */
        *bytes_per_second = 1000 * ent->response_size / time_diff;
        smartlist_add(dirreq_times, bytes_per_second);
        complete++;
      } else {
        if (tv_mdiff(&ent->request_time, &now) / 1000 > DIRREQ_TIMEOUT)
          timeouts++;
        else
          running++;
      }
      next = HT_NEXT_RMV(dirreqmap, &dirreq_map, ptr);
      tor_free(ent);
    }
  }
#define DIR_REQ_GRANULARITY 4
  complete = round_uint32_to_next_multiple_of(complete,
                                              DIR_REQ_GRANULARITY);
  timeouts = round_uint32_to_next_multiple_of(timeouts,
                                              DIR_REQ_GRANULARITY);
  running = round_uint32_to_next_multiple_of(running,
                                             DIR_REQ_GRANULARITY);
  result = tor_malloc_zero(bufsize);
  written = tor_snprintf(result, bufsize, "complete=%u,timeout=%u,"
                         "running=%u", complete, timeouts, running);
  if (written < 0)
    return NULL;
#define MIN_DIR_REQ_RESPONSES 16
  if (complete >= MIN_DIR_REQ_RESPONSES) {
    uint32_t *dltimes = tor_malloc(sizeof(uint32_t) * complete);
    SMARTLIST_FOREACH(dirreq_times, uint32_t *, dlt, {
      dltimes[i++] = *dlt;
      tor_free(dlt);
    });
    median_uint32(dltimes, complete); /* sort */
    written = tor_snprintf(result + written, bufsize - written,
                           ",min=%u,d1=%u,d2=%u,q1=%u,d3=%u,d4=%u,md=%u,"
                           "d6=%u,d7=%u,q3=%u,d8=%u,d9=%u,max=%u",
                           dltimes[0],
                           dltimes[1*complete/10-1],
                           dltimes[2*complete/10-1],
                           dltimes[1*complete/4-1],
                           dltimes[3*complete/10-1],
                           dltimes[4*complete/10-1],
                           dltimes[5*complete/10-1],
                           dltimes[6*complete/10-1],
                           dltimes[7*complete/10-1],
                           dltimes[3*complete/4-1],
                           dltimes[8*complete/10-1],
                           dltimes[9*complete/10-1],
                           dltimes[complete-1]);
    tor_free(dltimes);
  }
  if (written < 0)
    result = NULL;
  smartlist_free(dirreq_times);
  return result;
}
#endif

/** How long do we have to have observed per-country request history before we
 * are willing to talk about it? */
#define GEOIP_MIN_OBSERVATION_TIME (12*60*60)

/** Return a newly allocated comma-separated string containing entries for all
 * the countries from which we've seen enough clients connect. The entry
 * format is cc=num where num is the number of IPs we've seen connecting from
 * that country, and cc is a lowercased country code. Returns NULL if we don't
 * want to export geoip data yet. */
char *
geoip_get_client_history(time_t now, geoip_client_action_t action)
{
  char *result = NULL;
  int min_observation_time = GEOIP_MIN_OBSERVATION_TIME;
#ifdef ENABLE_DIRREQ_STATS
  min_observation_time = DIR_RECORD_USAGE_MIN_OBSERVATION_TIME;
#endif
  if (!geoip_is_loaded())
    return NULL;
  if (client_history_starts < (now - min_observation_time)) {
    char buf[32];
    smartlist_t *chunks = NULL;
    smartlist_t *entries = NULL;
    int n_countries = geoip_get_n_countries();
    int i;
    clientmap_entry_t **ent;
    unsigned *counts = tor_malloc_zero(sizeof(unsigned)*n_countries);
    unsigned total = 0;
    unsigned granularity = IP_GRANULARITY;
#ifdef ENABLE_DIRREQ_STATS
    granularity = DIR_RECORD_USAGE_GRANULARITY;
#endif
    HT_FOREACH(ent, clientmap, &client_history) {
      int country;
      if ((*ent)->action != (int)action)
        continue;
      country = geoip_get_country_by_ip((*ent)->ipaddr);
      if (country < 0)
        country = 0; /** unresolved requests are stored at index 0. */
      tor_assert(0 <= country && country < n_countries);
      ++counts[country];
      ++total;
    }
    /* Don't record anything if we haven't seen enough IPs. */
    if (total < MIN_IPS_TO_NOTE_ANYTHING)
      goto done;
    /* Make a list of c_hist_t */
    entries = smartlist_create();
    for (i = 0; i < n_countries; ++i) {
      unsigned c = counts[i];
      const char *countrycode;
      c_hist_t *ent;
      /* Only report a country if it has a minimum number of IPs. */
      if (c >= MIN_IPS_TO_NOTE_COUNTRY) {
        c = round_to_next_multiple_of(c, granularity);
        countrycode = geoip_get_country_name(i);
        ent = tor_malloc(sizeof(c_hist_t));
        strlcpy(ent->country, countrycode, sizeof(ent->country));
        ent->total = c;
        smartlist_add(entries, ent);
      }
    }
    /* Sort entries. Note that we must do this _AFTER_ rounding, or else
     * the sort order could leak info. */
    smartlist_sort(entries, _c_hist_compare);

    /* Build the result. */
    chunks = smartlist_create();
    SMARTLIST_FOREACH(entries, c_hist_t *, ch, {
        tor_snprintf(buf, sizeof(buf), "%s=%u", ch->country, ch->total);
        smartlist_add(chunks, tor_strdup(buf));
      });
    result = smartlist_join_strings(chunks, ",", 0, NULL);
  done:
    tor_free(counts);
    if (chunks) {
      SMARTLIST_FOREACH(chunks, char *, c, tor_free(c));
      smartlist_free(chunks);
    }
    if (entries) {
      SMARTLIST_FOREACH(entries, c_hist_t *, c, tor_free(c));
      smartlist_free(entries);
    }
  }
  return result;
}

/** Return a newly allocated string holding the per-country request history
 * for <b>action</b> in a format suitable for an extra-info document, or NULL
 * on failure. */
char *
geoip_get_request_history(time_t now, geoip_client_action_t action)
{
  smartlist_t *entries, *strings;
  char *result;
  unsigned granularity = IP_GRANULARITY;
  int min_observation_time = GEOIP_MIN_OBSERVATION_TIME;
#ifdef ENABLE_DIRREQ_STATS
  granularity = DIR_RECORD_USAGE_GRANULARITY;
  min_observation_time = DIR_RECORD_USAGE_MIN_OBSERVATION_TIME;
#endif

  if (client_history_starts >= (now - min_observation_time))
    return NULL;
  if (action != GEOIP_CLIENT_NETWORKSTATUS &&
      action != GEOIP_CLIENT_NETWORKSTATUS_V2)
    return NULL;
  if (!geoip_countries)
    return NULL;

  entries = smartlist_create();
  SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c, {
      uint32_t *n = (action == GEOIP_CLIENT_NETWORKSTATUS)
        ? c->n_v3_ns_requests : c->n_v2_ns_requests;
      uint32_t tot = 0;
      int i;
      c_hist_t *ent;
      for (i=0; i < REQUEST_HIST_LEN; ++i)
        tot += n[i];
      if (!tot)
        continue;
      ent = tor_malloc_zero(sizeof(c_hist_t));
      strlcpy(ent->country, c->countrycode, sizeof(ent->country));
      ent->total = round_to_next_multiple_of(tot, granularity);
      smartlist_add(entries, ent);
  });
  smartlist_sort(entries, _c_hist_compare);

  strings = smartlist_create();
  SMARTLIST_FOREACH(entries, c_hist_t *, ent, {
      char buf[32];
      tor_snprintf(buf, sizeof(buf), "%s=%u", ent->country, ent->total);
      smartlist_add(strings, tor_strdup(buf));
    });
  result = smartlist_join_strings(strings, ",", 0, NULL);
  SMARTLIST_FOREACH(strings, char *, cp, tor_free(cp));
  SMARTLIST_FOREACH(entries, c_hist_t *, ent, tor_free(ent));
  smartlist_free(strings);
  smartlist_free(entries);
  return result;
}

/** Store all our geoip statistics into $DATADIR/dirreq-stats. */
static void
dump_geoip_stats(void)
{
#ifdef ENABLE_DIRREQ_STATS
  time_t now = time(NULL);
  time_t request_start;
  char *filename = get_datadir_fname("dirreq-stats");
  char *data_v2 = NULL, *data_v3 = NULL;
  char since[ISO_TIME_LEN+1], written[ISO_TIME_LEN+1];
  open_file_t *open_file = NULL;
  double v2_share = 0.0, v3_share = 0.0;
  FILE *out;
  int i;

  if (!get_options()->DirReqStatistics)
    goto done;

  data_v2 = geoip_get_client_history(now, GEOIP_CLIENT_NETWORKSTATUS_V2);
  data_v3 = geoip_get_client_history(now, GEOIP_CLIENT_NETWORKSTATUS);
  format_iso_time(since, geoip_get_history_start());
  format_iso_time(written, now);
  out = start_writing_to_stdio_file(filename, OPEN_FLAGS_APPEND,
                                    0600, &open_file);
  if (!out)
    goto done;
  if (fprintf(out, "written %s\nstarted-at %s\nns-ips %s\nns-v2-ips %s\n",
              written, since,
              data_v3 ? data_v3 : "", data_v2 ? data_v2 : "") < 0)
    goto done;
  tor_free(data_v2);
  tor_free(data_v3);

  request_start = current_request_period_starts -
    (n_old_request_periods * REQUEST_HIST_PERIOD);
  format_iso_time(since, request_start);
  data_v2 = geoip_get_request_history(now, GEOIP_CLIENT_NETWORKSTATUS_V2);
  data_v3 = geoip_get_request_history(now, GEOIP_CLIENT_NETWORKSTATUS);
  if (fprintf(out, "requests-start %s\nn-ns-reqs %s\nn-v2-ns-reqs %s\n",
              since,
              data_v3 ? data_v3 : "", data_v2 ? data_v2 : "") < 0)
    goto done;
#define RESPONSE_GRANULARITY 8
  for (i = 0; i < GEOIP_NS_RESPONSE_NUM; i++) {
    ns_v2_responses[i] = round_uint32_to_next_multiple_of(
                               ns_v2_responses[i], RESPONSE_GRANULARITY);
    ns_v3_responses[i] = round_uint32_to_next_multiple_of(
                               ns_v3_responses[i], RESPONSE_GRANULARITY);
  }
#undef RESPONSE_GRANULARITY
  if (fprintf(out, "n-ns-resp ok=%u,not-enough-sigs=%u,unavailable=%u,"
                   "not-found=%u,not-modified=%u,busy=%u\n",
                   ns_v3_responses[GEOIP_SUCCESS],
                   ns_v3_responses[GEOIP_REJECT_NOT_ENOUGH_SIGS],
                   ns_v3_responses[GEOIP_REJECT_UNAVAILABLE],
                   ns_v3_responses[GEOIP_REJECT_NOT_FOUND],
                   ns_v3_responses[GEOIP_REJECT_NOT_MODIFIED],
                   ns_v3_responses[GEOIP_REJECT_BUSY]) < 0)
    goto done;
  if (fprintf(out, "n-v2-ns-resp ok=%u,unavailable=%u,"
                   "not-found=%u,not-modified=%u,busy=%u\n",
                   ns_v2_responses[GEOIP_SUCCESS],
                   ns_v2_responses[GEOIP_REJECT_UNAVAILABLE],
                   ns_v2_responses[GEOIP_REJECT_NOT_FOUND],
                   ns_v2_responses[GEOIP_REJECT_NOT_MODIFIED],
                   ns_v2_responses[GEOIP_REJECT_BUSY]) < 0)
    goto done;
  memset(ns_v2_responses, 0, sizeof(ns_v2_responses));
  memset(ns_v3_responses, 0, sizeof(ns_v3_responses));
  if (!geoip_get_mean_shares(now, &v2_share, &v3_share)) {
    if (fprintf(out, "v2-ns-share %0.2lf%%\n", v2_share*100) < 0)
      goto done;
    if (fprintf(out, "v3-ns-share %0.2lf%%\n", v3_share*100) < 0)
      goto done;
  }

  data_v2 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS_V2,
                                       DIRREQ_DIRECT);
  data_v3 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS,
                                       DIRREQ_DIRECT);
  if (fprintf(out, "ns-direct-dl %s\nns-v2-direct-dl %s\n",
              data_v3 ? data_v3 : "", data_v2 ? data_v2 : "") < 0)
    goto done;
  tor_free(data_v2);
  tor_free(data_v3);
  data_v2 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS_V2,
                                       DIRREQ_TUNNELED);
  data_v3 = geoip_get_dirreq_history(GEOIP_CLIENT_NETWORKSTATUS,
                                       DIRREQ_TUNNELED);
  if (fprintf(out, "ns-tunneled-dl %s\nns-v2-tunneled-dl %s\n",
              data_v3 ? data_v3 : "", data_v2 ? data_v2 : "") < 0)
    goto done;

  finish_writing_to_file(open_file);
  open_file = NULL;
 done:
  if (open_file)
    abort_writing_to_file(open_file);
  tor_free(filename);
  tor_free(data_v2);
  tor_free(data_v3);
#endif
}

/** Store all our geoip statistics as entry guards into
 * $DATADIR/entry-stats. */
static void
dump_entry_stats(void)
{
#ifdef ENABLE_ENTRY_STATS
  time_t now = time(NULL);
  char *filename = get_datadir_fname("entry-stats");
  char *data = NULL;
  char since[ISO_TIME_LEN+1], written[ISO_TIME_LEN+1];
  open_file_t *open_file = NULL;
  FILE *out;

  data = geoip_get_client_history(now, GEOIP_CLIENT_CONNECT);
  format_iso_time(since, geoip_get_history_start());
  format_iso_time(written, now);
  out = start_writing_to_stdio_file(filename, OPEN_FLAGS_APPEND,
                                    0600, &open_file);
  if (!out)
    goto done;
  if (fprintf(out, "written %s\nstarted-at %s\nips %s\n",
              written, since, data ? data : "") < 0)
    goto done;

  finish_writing_to_file(open_file);
  open_file = NULL;
 done:
  if (open_file)
    abort_writing_to_file(open_file);
  tor_free(filename);
  tor_free(data);
#endif
}

/** Helper used to implement GETINFO ip-to-country/... controller command. */
int
getinfo_helper_geoip(control_connection_t *control_conn,
                     const char *question, char **answer)
{
  (void)control_conn;
  if (geoip_is_loaded() && !strcmpstart(question, "ip-to-country/")) {
    int c;
    uint32_t ip;
    struct in_addr in;
    question += strlen("ip-to-country/");
    if (tor_inet_aton(question, &in) != 0) {
      ip = ntohl(in.s_addr);
      c = geoip_get_country_by_ip(ip);
      *answer = tor_strdup(geoip_get_country_name(c));
    }
  }
  return 0;
}

/** Release all storage held by the GeoIP database. */
static void
clear_geoip_db(void)
{
  if (geoip_countries) {
    SMARTLIST_FOREACH(geoip_countries, geoip_country_t *, c, tor_free(c));
    smartlist_free(geoip_countries);
  }
  if (country_idxplus1_by_lc_code)
    strmap_free(country_idxplus1_by_lc_code, NULL);
  if (geoip_entries) {
    SMARTLIST_FOREACH(geoip_entries, geoip_entry_t *, ent, tor_free(ent));
    smartlist_free(geoip_entries);
  }
  geoip_countries = NULL;
  country_idxplus1_by_lc_code = NULL;
  geoip_entries = NULL;
}

/** Release all storage held in this file. */
void
geoip_free_all(void)
{
  {
    clientmap_entry_t **ent, **next, *this;
    for (ent = HT_START(clientmap, &client_history); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(clientmap, &client_history, ent);
      tor_free(this);
    }
    HT_CLEAR(clientmap, &client_history);
  }
  {
    dirreq_map_entry_t **ent, **next, *this;
    for (ent = HT_START(dirreqmap, &dirreq_map); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(dirreqmap, &dirreq_map, ent);
      tor_free(this);
    }
    HT_CLEAR(dirreqmap, &dirreq_map);
  }

  clear_geoip_db();
}

