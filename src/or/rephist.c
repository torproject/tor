/* Copyright 2004 Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

typedef struct link_history_t {
  time_t since;
  unsigned long n_extend_ok;
  unsigned long n_extend_fail;
} link_history_t;

typedef struct or_history_t {
  time_t since;
  unsigned long n_conn_ok;
  unsigned long n_conn_fail;
  unsigned long uptime;
  unsigned long downtime;
  time_t up_since;
  time_t down_since;
  strmap_t *link_history_map;
} or_history_t;

static strmap_t *history_map;

static or_history_t *get_or_history(const char* nickname)
{
  or_history_t *hist;
  hist = (or_history_t*) strmap_get(history_map, nickname);
  if (!hist) {
    hist = tor_malloc_zero(sizeof(or_history_t));
    hist->link_history_map = strmap_new();
    hist->since = time(NULL);
    strmap_set(history_map, nickname, hist);
  }
  return hist;
}

static link_history_t *get_link_history(const char *from_name,
					const char *to_name)
{
  or_history_t *orhist;
  link_history_t *lhist;
  orhist = get_or_history(from_name);
  lhist = (link_history_t*) strmap_get(orhist->link_history_map, to_name);
  if (!lhist) {
    lhist = tor_malloc_zero(sizeof(link_history_t));
    lhist->since = time(NULL);
    strmap_set(orhist->link_history_map, to_name, lhist);
  }
  return lhist;
}

static void update_or_history(or_history_t *hist, time_t when)
{
  assert(hist);
  if (hist->up_since) {
    assert(!hist->down_since);
    hist->uptime += (when - hist->up_since);
    hist->up_since = when;
  } else if (hist->down_since) {
    hist->downtime += (when - hist->down_since);
    hist->down_since = when;
  }
}

void rep_hist_init(void)
{
  history_map = strmap_new();
}

void rep_hist_note_connect_failed(const char* nickname, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(nickname);
  ++hist->n_conn_fail;
  if (hist->up_since) {
    hist->uptime += (when - hist->up_since);
    hist->up_since = 0;
  }
  if (!hist->down_since)
    hist->down_since = when;
}

void rep_hist_note_connect_succeeded(const char* nickname, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(nickname);
  ++hist->n_conn_ok;
  if (hist->down_since) {
    hist->downtime += (when - hist->down_since);
    hist->down_since = 0;
  }
  if (!hist->up_since)
    hist->up_since = when;
}
void rep_hist_note_connection_died(const char* nickname, time_t when)
{
  or_history_t *hist;
  hist = get_or_history(nickname);
  if (hist->up_since) {
    hist->uptime += (when - hist->up_since);
    hist->up_since = 0;
  }
  if (!hist->down_since)
    hist->down_since = when;
}

void rep_hist_note_extend_succeeded(const char *from_name,
				    const char *to_name)
{
  link_history_t *hist;
  hist = get_link_history(from_name, to_name);
  ++hist->n_extend_ok;
}
void rep_hist_note_extend_failed(const char *from_name, const char *to_name)
{
  link_history_t *hist;
  hist = get_link_history(from_name, to_name);
  ++hist->n_extend_fail;
}

void rep_hist_dump_status(time_t now)
{
  strmap_iter_t *lhist_it;
  strmap_iter_t *orhist_it;
  const char *name1, *name2;
  or_history_t *or_history;
  link_history_t *link_history;
  double uptime;
  char buffer[2048];
  char *cp;
  int len;

  log(LOG_WARN, "--------------- Dumping history information:");

  for (orhist_it = strmap_iter_init(history_map); !strmap_iter_done(orhist_it);
       orhist_it = strmap_iter_next(history_map,orhist_it)) {
    strmap_iter_get(orhist_it, &name1, (void**)&or_history);

    update_or_history(or_history, now);

    uptime = ((double)or_history->uptime) / or_history->downtime;
    log(LOG_WARN, "OR %s: %ld/%ld good connection attempts; uptime %.2f%%",
	name1,
	or_history->n_conn_ok, or_history->n_conn_fail+or_history->n_conn_ok,
	uptime*100.0);

    strcpy(buffer, "    Good extend attempts: ");
    len = strlen(buffer);
    for (lhist_it = strmap_iter_init(or_history->link_history_map);
	 !strmap_iter_done(lhist_it);
	 lhist_it = strmap_iter_next(or_history->link_history_map, lhist_it)) {
      strmap_iter_get(lhist_it, &name2, (void**)&link_history);
      len += snprintf(buffer+len, 2048-len, "%s(%ld/%ld); ", name2,
		      link_history->n_extend_ok,
		      link_history->n_extend_ok+link_history->n_extend_fail);
      if (len >= 2048) {
	buffer[2047]='\0';
	break;
      }
    }
    log(LOG_WARN, buffer);
  }
}



/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
