/* Copyright (c) 2007-2011, The Tor Project, Inc. */
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

/** An entry from the GeoIP file: maps an IP range to a country. */
typedef struct geoip_entry_t {
  uint32_t ip_low; /**< The lowest IP in the range, in host order */
  uint32_t ip_high; /**< The highest IP in the range, in host order */
  intptr_t country; /**< An index into geoip_countries */
} geoip_entry_t;

/** For how many periods should we remember per-country request history? */
#define REQUEST_HIST_LEN 3
/** How long are the periods for which we should remember request history? */
#define REQUEST_HIST_PERIOD (8*60*60)

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
 * if it is a valid 2-letter country code, otherwise return zero.
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
    geoip_countries = smartlist_create();
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
  time_t last_seen; /* The last 2 bits of this value hold the client
                     * operation. */
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
  return a->ipaddr == b->ipaddr;
}

HT_PROTOTYPE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
             clientmap_entries_eq);
HT_GENERATE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
            clientmap_entries_eq, 0.6, malloc, realloc, free);

/** Note that we've seen a client connect from the IP <b>addr</b> (host order)
 * at time <b>now</b>. Ignored by all but bridges. */
void
geoip_note_client_seen(geoip_client_action_t action,
                       uint32_t addr, time_t now)
{
  or_options_t *options = get_options();
  clientmap_entry_t lookup, *ent;
  if (action == GEOIP_CLIENT_CONNECT) {
    if (!(options->BridgeRelay && options->BridgeRecordUsageByCountry))
      return;
    /* Did we recently switch from bridge to relay or back? */
    if (client_history_starts > now)
      return;
  } else {
#ifndef ENABLE_GEOIP_STATS
    return;
#else
    if (options->BridgeRelay || options->BridgeAuthoritativeDir ||
        !options->DirRecordUsageByCountry)
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

  /* We use the low 3 bits of the time to encode the action. Since we're
   * potentially remembering tons of clients, we don't want to make
   * clientmap_entry_t larger than it has to be. */
  now = (now & ~ACTION_MASK) | (((int)action) & ACTION_MASK);
  lookup.ipaddr = addr;
  ent = HT_FIND(clientmap, &client_history, &lookup);
  if (ent) {
    ent->last_seen = now;
  } else {
    ent = tor_malloc_zero(sizeof(clientmap_entry_t));
    ent->ipaddr = addr;
    ent->last_seen = now;
    HT_INSERT(clientmap, &client_history, ent);
  }

  if (action == GEOIP_CLIENT_NETWORKSTATUS ||
      action == GEOIP_CLIENT_NETWORKSTATUS_V2) {
    int country_idx = geoip_get_country_by_ip(addr);
    if (country_idx >= 0 && country_idx < smartlist_len(geoip_countries)) {
      geoip_country_t *country = smartlist_get(geoip_countries, country_idx);
      if (action == GEOIP_CLIENT_NETWORKSTATUS)
        ++country->n_v3_ns_requests[REQUEST_HIST_LEN-1];
      else
        ++country->n_v2_ns_requests[REQUEST_HIST_LEN-1];
    }
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
  time_t cutoff = *(time_t*)_cutoff;
  if (ent->last_seen < cutoff) {
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

/** How long do we have to have observed per-country request history before we
 * are willing to talk about it? */
#define GEOIP_MIN_OBSERVATION_TIME (12*60*60)

/** Return the lowest x such that x is at least <b>number</b>, and x modulo
 * <b>divisor</b> == 0. */
static INLINE unsigned
round_to_next_multiple_of(unsigned number, unsigned divisor)
{
  number += divisor - 1;
  number -= number % divisor;
  return number;
}

/** Return a newly allocated comma-separated string containing entries for all
 * the countries from which we've seen enough clients connect. The entry
 * format is cc=num where num is the number of IPs we've seen connecting from
 * that country, and cc is a lowercased country code. Returns NULL if we don't
 * want to export geoip data yet. */
char *
geoip_get_client_history(time_t now, geoip_client_action_t action)
{
  char *result = NULL;
  if (!geoip_is_loaded())
    return NULL;
  if (client_history_starts < (now - GEOIP_MIN_OBSERVATION_TIME)) {
    char buf[32];
    smartlist_t *chunks = NULL;
    smartlist_t *entries = NULL;
    int n_countries = geoip_get_n_countries();
    int i;
    clientmap_entry_t **ent;
    unsigned *counts = tor_malloc_zero(sizeof(unsigned)*n_countries);
    unsigned total = 0;
    unsigned granularity = IP_GRANULARITY;
#ifdef ENABLE_GEOIP_STATS
    if (get_options()->DirRecordUsageByCountry)
      granularity = get_options()->DirRecordUsageGranularity;
#endif
    HT_FOREACH(ent, clientmap, &client_history) {
      int country;
      if (((*ent)->last_seen & ACTION_MASK) != (int)action)
        continue;
      country = geoip_get_country_by_ip((*ent)->ipaddr);
      if (country < 0)
        continue;
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
#ifdef ENABLE_GEOIP_STATS
  if (get_options()->DirRecordUsageByCountry)
    granularity = get_options()->DirRecordUsageGranularity;
#endif

  if (client_history_starts >= (now - GEOIP_MIN_OBSERVATION_TIME))
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

/** Store all our geoip statistics into $DATADIR/geoip-stats. */
void
dump_geoip_stats(void)
{
#ifdef ENABLE_GEOIP_STATS
  time_t now = time(NULL);
  time_t request_start;
  char *filename = get_datadir_fname("geoip-stats");
  char *data_v2 = NULL, *data_v3 = NULL;
  char since[ISO_TIME_LEN+1], written[ISO_TIME_LEN+1];
  open_file_t *open_file = NULL;
  double v2_share = 0.0, v3_share = 0.0;
  FILE *out;

  data_v2 = geoip_get_client_history(now, GEOIP_CLIENT_NETWORKSTATUS_V2);
  data_v3 = geoip_get_client_history(now, GEOIP_CLIENT_NETWORKSTATUS);
  format_iso_time(since, geoip_get_history_start());
  format_iso_time(written, now);
  out = start_writing_to_stdio_file(filename, OPEN_FLAGS_REPLACE,
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
  if (!router_get_my_share_of_directory_requests(&v2_share, &v3_share)) {
    if (fprintf(out, "v2-ns-share %0.2lf%%\n", v2_share*100) < 0)
      goto done;
    if (fprintf(out, "v3-ns-share %0.2lf%%\n", v3_share*100) < 0)
      goto done;
  }

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
  clientmap_entry_t **ent, **next, *this;
  for (ent = HT_START(clientmap, &client_history); ent != NULL; ent = next) {
    this = *ent;
    next = HT_NEXT_RMV(clientmap, &client_history, ent);
    tor_free(this);
  }
  HT_CLEAR(clientmap, &client_history);

  clear_geoip_db();
}

