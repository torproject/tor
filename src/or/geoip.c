/* Copyright (c) 2007, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id: /tor/trunk/src/or/networkstatus.c 15493 2007-12-16T18:33:25.055570Z nickm  $ */
const char geoip_c_id[] =
  "$Id: /tor/trunk/src/or/networkstatus.c 15493 2007-12-16T18:33:25.055570Z nickm  $";

#define GEOIP_PRIVATE
#include "or.h"
#include "ht.h"

/** DOCDOC this whole file */

typedef struct geoip_entry_t {
  uint32_t ip_low;
  uint32_t ip_high;
  int country;
} geoip_entry_t;

static smartlist_t *geoip_countries = NULL;
static strmap_t *country_idxplus1_by_lc_code = NULL;
static smartlist_t *geoip_entries = NULL;

void
geoip_add_entry(uint32_t low, uint32_t high, const char *country)
{
  uintptr_t idx;
  geoip_entry_t *ent;
  void *_idxplus1 = strmap_get_lc(country_idxplus1_by_lc_code, country);

  if (!_idxplus1) {
    char *c = tor_strdup(country);
    tor_strlower(c);
    smartlist_add(geoip_countries, c);
    idx = smartlist_len(geoip_countries) - 1;
    strmap_set_lc(country_idxplus1_by_lc_code, country, (void*)(idx+1));
  } else {
    idx = ((uintptr_t)_idxplus1)-1;
  }
  tor_assert(!strcasecmp(smartlist_get(geoip_countries, idx), country));
  ent = tor_malloc_zero(sizeof(geoip_entry_t));
  ent->ip_low = low;
  ent->ip_high = high;
  ent->country = idx;
  smartlist_add(geoip_entries, ent);
}

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

int
geoip_load_file(const char *filename)
{
  FILE *f;
  geoip_free_all();
  if (!(f = fopen(filename, "r"))) {
    log_warn(LD_GENERAL, "Failed to open GEOIP file %s.", filename);
    return -1;
  }
  geoip_countries = smartlist_create();
  geoip_entries = smartlist_create();
  country_idxplus1_by_lc_code = strmap_new();
  log_info(LD_GENERAL, "Parsing GEOIP file.");
  while (!feof(f)) {
    char buf[512];
    unsigned int low, high;
    char b[3];
    if (fgets(buf, sizeof(buf), f) == NULL)
      break;
    /* XXXX020 track full country name. */
    if (sscanf(buf,"%u,%u,%2s", &low, &high, b) == 3) {
      geoip_add_entry(low, high, b);
    } else if (sscanf(buf,"\"%u\",\"%u\",\"%2s\",", &low, &high, b) == 3) {
      geoip_add_entry(low, high, b);
    } else {
      log_warn(LD_GENERAL, "Unable to parse line from GEOIP file: %s",
               escaped(buf));
    }
  }
  /*XXXX020 abort and return -1 if no entries/illformed?*/
  fclose(f);

  smartlist_sort(geoip_entries, _geoip_compare_entries);
  return 0;
}

int
geoip_get_country_by_ip(uint32_t ipaddr)
{
  geoip_entry_t *ent;
  if (!geoip_entries)
    return -1;
  ent = smartlist_bsearch(geoip_entries, &ipaddr, _geoip_compare_key_to_entry);
  return ent ? ent->country : -1;
}

int
geoip_get_n_countries(void)
{
  return smartlist_len(geoip_countries);
}

const char *
geoip_get_country_name(int num)
{
  if (geoip_countries && num >= 0 && num < smartlist_len(geoip_countries))
    return smartlist_get(geoip_countries, num);
  else
    return "??";
}

int
geoip_is_loaded(void)
{
  return geoip_countries != NULL && geoip_entries != NULL;
}

/** DOCDOC */
typedef struct clientmap_entry_t {
  HT_ENTRY(clientmap_entry_t) node;
  uint32_t ipaddr;
  time_t last_seen;
} clientmap_entry_t;

static HT_HEAD(clientmap, clientmap_entry_t) client_history =
     HT_INITIALIZER();
static time_t client_history_starts = 0;

static INLINE unsigned
clientmap_entry_hash(const clientmap_entry_t *a)
{
  return ht_improve_hash((unsigned) a->ipaddr);
}
static INLINE int
clientmap_entries_eq(const clientmap_entry_t *a, const clientmap_entry_t *b)
{
  return a->ipaddr == b->ipaddr;
}

HT_PROTOTYPE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
             clientmap_entries_eq);
HT_GENERATE(clientmap, clientmap_entry_t, node, clientmap_entry_hash,
            clientmap_entries_eq, 0.6, malloc, realloc, free);

/** DOCDOC */
void
geoip_note_client_seen(uint32_t addr, time_t now)
{
  or_options_t *options = get_options();
  clientmap_entry_t lookup, *ent;
  if (!(options->BridgeRelay && options->BridgeRecordUsageByCountry))
    return;
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
  if (!client_history_starts)
    client_history_starts = now;
}

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

void
geoip_remove_old_clients(time_t cutoff)
{
  clientmap_HT_FOREACH_FN(&client_history,
                          _remove_old_client_helper,
                          &cutoff);
  if (client_history_starts < cutoff)
    client_history_starts = cutoff;
}

#define MIN_IPS_TO_NOTE_COUNTRY 8
#define MIN_IPS_TO_NOTE_ANYTHING 16
#define IP_GRANULARITY 8

time_t
geoip_get_history_start(void)
{
  return client_history_starts;
}

char *
geoip_get_client_history(time_t now)
{
  char *result = NULL;
  if (!geoip_is_loaded())
    return NULL;
  if (client_history_starts < (now - 12*60*60)) {
    char buf[32];
    smartlist_t *chunks = NULL;
    int n_countries = geoip_get_n_countries();
    int i;
    clientmap_entry_t **ent;
    unsigned *counts = tor_malloc_zero(sizeof(unsigned)*n_countries);
    unsigned total = 0;
    HT_FOREACH(ent, clientmap, &client_history) {
      int country = geoip_get_country_by_ip((*ent)->ipaddr);
      if (country < 0)
        continue;
      tor_assert(0 <= country && country < n_countries);
      ++counts[country];
      ++total;
    }
    if (total < MIN_IPS_TO_NOTE_ANYTHING)
      goto done;
    chunks = smartlist_create();
    for (i = 0; i < n_countries; ++i) {
      unsigned c = counts[i];
      const char *countrycode;
      if (c >= MIN_IPS_TO_NOTE_COUNTRY) {
        c -= c % IP_GRANULARITY;
        countrycode = geoip_get_country_name(i);
        tor_snprintf(buf, sizeof(buf), "%s=%u", countrycode, c);
        smartlist_add(chunks, tor_strdup(buf));
      }
    }
    result = smartlist_join_strings(chunks, ",", 0, NULL);
  done:
    tor_free(counts);
    if (chunks) {
      SMARTLIST_FOREACH(chunks, char *, c, tor_free(c));
      smartlist_free(chunks);
    }
  }
  return result;
}

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

void
geoip_free_all(void)
{
  if (geoip_countries) {
    SMARTLIST_FOREACH(geoip_countries, char *, cp, tor_free(cp));
    smartlist_free(geoip_countries);
  }
  if (country_idxplus1_by_lc_code)
    strmap_free(country_idxplus1_by_lc_code, NULL);
  if (geoip_entries) {
    SMARTLIST_FOREACH(geoip_entries, geoip_entry_t *, ent, tor_free(ent));
    smartlist_free(geoip_entries);
  }
  {
    clientmap_entry_t **ent, **next, *this;
    for (ent = HT_START(clientmap, &client_history); ent != NULL; ent = next) {
      this = *ent;
      next = HT_NEXT_RMV(clientmap, &client_history, ent);
      tor_free(this);
    }
    HT_CLEAR(clientmap, &client_history);
  }
  geoip_countries = NULL;
  country_idxplus1_by_lc_code = NULL;
  geoip_entries = NULL;
}

