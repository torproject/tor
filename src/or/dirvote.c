/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2007 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char dirvote_c_id[] =
  "$Id$";

#define DIRVOTE_PRIVATE
#include "or.h"

/**
 * \file dirvote.c
 * \brief Functions to compute directory consensus, and schedule voting.
 **/

static int dirvote_add_signatures_to_pending_consensus(
                       const char *detached_signatures_body,
                       const char **msg_out);
static char *list_v3_auth_ids(void);

/* =====
 * Voting and consensus generation
 * ===== */

/** Clear all storage held in <b>ns</b>. */
void
networkstatus_vote_free(networkstatus_vote_t *ns)
{
  if (!ns)
    return;

  tor_free(ns->client_versions);
  tor_free(ns->server_versions);
  if (ns->known_flags) {
    SMARTLIST_FOREACH(ns->known_flags, char *, c, tor_free(c));
    smartlist_free(ns->known_flags);
  }
  if (ns->voters) {
    SMARTLIST_FOREACH(ns->voters, networkstatus_voter_info_t *, voter,
    {
      tor_free(voter->nickname);
      tor_free(voter->address);
      tor_free(voter->contact);
    });
    smartlist_free(ns->voters);
  }
  if (ns->cert)
    authority_cert_free(ns->cert);

  if (ns->routerstatus_list) {
    if (ns->is_vote) {
      SMARTLIST_FOREACH(ns->routerstatus_list, vote_routerstatus_t *, rs,
      {
        tor_free(rs->version);
        tor_free(rs);
      });
    } else {
      SMARTLIST_FOREACH(ns->routerstatus_list, routerstatus_t *, rs,
                        tor_free(rs));
    }

    smartlist_free(ns->routerstatus_list);
  }

  memset(ns, 11, sizeof(*ns));
  tor_free(ns);
}

/** Return the voter info from <b>vote</b> for the voter whose identity digest
 * is <b>identity</b>, or NULL if no such voter is associated with
 * <b>vote</b>. */
networkstatus_voter_info_t *
networkstatus_get_voter_by_id(networkstatus_vote_t *vote,
                              const char *identity)
{
  if (!vote || !vote->voters)
    return NULL;
  SMARTLIST_FOREACH(vote->voters, networkstatus_voter_info_t *, voter,
    if (!memcmp(voter->identity_digest, identity, DIGEST_LEN))
      return voter);
  return NULL;
}

/** Helper for sorting a list of time_t*. */
static int
_compare_times(const void **_a, const void **_b)
{
  const time_t *a = *_a, *b = *_b;
  if (*a<*b)
    return -1;
  else if (*a>*b)
    return 1;
  else
    return 0;
}

/** Helper for sorting a list of int*. */
static int
_compare_ints(const void **_a, const void **_b)
{
  const int *a = *_a, *b = *_b;
  if (*a<*b)
    return -1;
  else if (*a>*b)
    return 1;
  else
    return 0;
}

/** Given a list of one or more time_t*, return the (low) median. */
/*static*/ time_t
median_time(smartlist_t *times)
{
  int idx;
  tor_assert(smartlist_len(times));
  smartlist_sort(times, _compare_times);
  idx = (smartlist_len(times)-1)/2;
  return *(time_t*)smartlist_get(times, idx);
}

/** Given a list of one or more int*, return the (low) median. */
/*static*/ int
median_int(smartlist_t *ints)
{
  int idx;
  tor_assert(smartlist_len(ints));
  smartlist_sort(ints, _compare_ints);
  idx = (smartlist_len(ints)-1)/2;
  return *(int*)smartlist_get(ints, idx);
}

/** Given a vote <b>vote</b> (not a consensus!), return its associated
 * networkstatus_voter_info_t.*/
static networkstatus_voter_info_t *
get_voter(const networkstatus_vote_t *vote)
{
  tor_assert(vote);
  tor_assert(vote->is_vote);
  tor_assert(vote->voters);
  tor_assert(smartlist_len(vote->voters) == 1);
  return smartlist_get(vote->voters, 0);
}

/** Helper for sorting networkstatus_vote_t votes (not consensuses) by the
 * hash of their voters' identity digests. */
static int
_compare_votes_by_authority_id(const void **_a, const void **_b)
{
  const networkstatus_vote_t *a = *_a, *b = *_b;
  return memcmp(get_voter(a)->identity_digest,
                get_voter(b)->identity_digest, DIGEST_LEN);
}

/** Given a sorted list of strings <b>in</b>, add every member to <b>out</b>
 * that occurs more than <b>min</b> times. */
static void
get_frequent_members(smartlist_t *out, smartlist_t *in, int min)
{
  char *cur = NULL;
  int count = 0;
  SMARTLIST_FOREACH(in, char *, cp,
  {
    if (cur && !strcmp(cp, cur)) {
      ++count;
    } else {
      if (count > min)
        smartlist_add(out, cur);
      cur = cp;
      count = 1;
    }
  });
  if (count > min)
    smartlist_add(out, cur);
}

/** Given a sorted list of strings <b>lst</b>, return the member that appears
 * most.  Break ties in favor of later-occurring members. */
static const char *
get_most_frequent_member(smartlist_t *lst)
{
  const char *most_frequent = NULL;
  int most_frequent_count = 0;

  const char *cur = NULL;
  int count = 0;

  SMARTLIST_FOREACH(lst, const char *, s,
  {
    if (cur && !strcmp(s, cur)) {
      ++count;
    } else {
      if (count >= most_frequent_count) {
        most_frequent = cur;
        most_frequent_count = count;
      }
      cur = s;
      count = 1;
    }
  });
  if (count >= most_frequent_count) {
    most_frequent = cur;
    most_frequent_count = count;
  }
  return most_frequent;
}

/** Return 0 if and only if <b>a</b> and <b>b</b> are routerstatuses
 * that come from the same routerinfo, with the same derived elements.
 */
static int
compare_vote_rs(const vote_routerstatus_t *a, const vote_routerstatus_t *b)
{
  int r;
  if ((r = memcmp(a->status.identity_digest, b->status.identity_digest,
                  DIGEST_LEN)))
    return r;
  if ((r = memcmp(a->status.descriptor_digest, b->status.descriptor_digest,
                  DIGEST_LEN)))
    return r;
  if ((r = (b->status.published_on - a->status.published_on)))
    return r;
  if ((r = strcmp(b->status.nickname, a->status.nickname)))
    return r;
  if ((r = (((int)b->status.addr) - ((int)a->status.addr))))
    return r;
  if ((r = (((int)b->status.or_port) - ((int)a->status.or_port))))
    return r;
  if ((r = (((int)b->status.dir_port) - ((int)a->status.dir_port))))
    return r;
  return 0;
}

/** Helper for sorting routerlists based on compare_vote_rs. */
static int
_compare_vote_rs(const void **_a, const void **_b)
{
  const vote_routerstatus_t *a = *_a, *b = *_b;
  return compare_vote_rs(a,b);
}

/** Given a list of vote_routerstatus_t, all for the same router identity,
 * return whichever is most frequent, breaking ties in favor of more
 * recently published vote_routerstatus_t.
 */
static vote_routerstatus_t *
compute_routerstatus_consensus(smartlist_t *votes)
{
  vote_routerstatus_t *most = NULL, *cur = NULL;
  int most_n = 0, cur_n = 0;
  time_t most_published = 0;

  smartlist_sort(votes, _compare_vote_rs);
  SMARTLIST_FOREACH(votes, vote_routerstatus_t *, rs,
  {
    if (cur && !compare_vote_rs(cur, rs)) {
      ++cur_n;
    } else {
      if (cur_n > most_n ||
          (cur && cur_n == most_n &&
           cur->status.published_on > most_published)) {
        most = cur;
        most_n = cur_n;
        most_published = cur->status.published_on;
      }
      cur_n = 1;
      cur = rs;
    }
  });

  if (cur_n > most_n ||
      (cur && cur_n == most_n && cur->status.published_on > most_published)) {
    most = cur;
    most_n = cur_n;
    most_published = cur->status.published_on;
  }

  tor_assert(most);
  return most;
}

/** Given a list of strings in <b>lst</b>, set the DIGEST_LEN-byte digest at
 * <b>digest_out</b> to the hash of the concatenation of those strings. */
static void
hash_list_members(char *digest_out, smartlist_t *lst)
{
  crypto_digest_env_t *d = crypto_new_digest_env();
  SMARTLIST_FOREACH(lst, const char *, cp,
                    crypto_digest_add_bytes(d, cp, strlen(cp)));
  crypto_digest_get_digest(d, digest_out, DIGEST_LEN);
  crypto_free_digest_env(d);
}

/** Given a list of vote networkstatus_vote_t in <b>votes</b>, our public
 * authority <b>identity_key</b>, our private authority <b>signing_key</b>,
 * and the number of <b>total_authorities</b> that we believe exist in our
 * voting quorum, generate the text of a new v3 consensus vote, and return the
 * value in a newly allocated string.
 *
 * Note: this function DOES NOT check whether the votes are from
 * recognized authorities.   (dirvote_add_vote does that.) */
char *
networkstatus_compute_consensus(smartlist_t *votes,
                                int total_authorities,
                                crypto_pk_env_t *identity_key,
                                crypto_pk_env_t *signing_key)
{
  smartlist_t *chunks;
  char *result = NULL;

  time_t valid_after, fresh_until, valid_until;
  int vote_seconds, dist_seconds;
  char *client_versions = NULL, *server_versions = NULL;
  smartlist_t *flags;
  tor_assert(total_authorities >= smartlist_len(votes));

  if (!smartlist_len(votes)) {
    log_warn(LD_DIR, "Can't compute a consensus from no votes.");
    return NULL;
  }
  flags = smartlist_create();

  /* Compute medians of time-related things, and figure out how many
   * routers we might need to talk about. */
  {
    smartlist_t *va_times = smartlist_create();
    smartlist_t *fu_times = smartlist_create();
    smartlist_t *vu_times = smartlist_create();
    smartlist_t *votesec_list = smartlist_create();
    smartlist_t *distsec_list = smartlist_create();
    int n_versioning_clients = 0, n_versioning_servers = 0;
    smartlist_t *combined_client_versions = smartlist_create();
    smartlist_t *combined_server_versions = smartlist_create();
    int j;
    SMARTLIST_FOREACH(votes, networkstatus_vote_t *, v,
    {
      tor_assert(v->is_vote);
      smartlist_add(va_times, &v->valid_after);
      smartlist_add(fu_times, &v->fresh_until);
      smartlist_add(vu_times, &v->valid_until);
      smartlist_add(votesec_list, &v->vote_seconds);
      smartlist_add(distsec_list, &v->dist_seconds);
      if (v->client_versions) {
        smartlist_t *cv = smartlist_create();
        ++n_versioning_clients;
        smartlist_split_string(cv, v->client_versions, ",",
                               SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
        sort_version_list(cv, 1);
        smartlist_add_all(combined_client_versions, cv);
        smartlist_free(cv); /* elements get freed later. */
      }
      if (v->server_versions) {
        smartlist_t *sv = smartlist_create();
        ++n_versioning_servers;
        smartlist_split_string(sv, v->server_versions, ",",
                               SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
        sort_version_list(sv, 1);
        smartlist_add_all(combined_server_versions, sv);
        smartlist_free(sv); /* elements get freed later. */
      }
      SMARTLIST_FOREACH(v->known_flags, const char *, cp,
                        smartlist_add(flags, tor_strdup(cp)));
    });
    valid_after = median_time(va_times);
    fresh_until = median_time(fu_times);
    valid_until = median_time(vu_times);
    vote_seconds = median_int(votesec_list);
    dist_seconds = median_int(distsec_list);

    /*
    SMARTLIST_FOREACH(va_times, int*, i,
                      printf("VA: %d\n", *i));
    SMARTLIST_FOREACH(fu_times, int*, i,
                      printf("FU: %d\n", *i));
    printf("%d..%d\n", (int)valid_after, (int)valid_until);
    */

    tor_assert(valid_after+MIN_VOTE_INTERVAL <= fresh_until);
    tor_assert(fresh_until+MIN_VOTE_INTERVAL <= valid_until);
    tor_assert(vote_seconds >= MIN_VOTE_SECONDS);
    tor_assert(dist_seconds >= MIN_DIST_SECONDS);

    for (j = 0; j < 2; ++j) {
      smartlist_t *lst =
        j ? combined_server_versions : combined_client_versions;
      int min = (j ? n_versioning_servers : n_versioning_clients) / 2;
      smartlist_t *good = smartlist_create();
      char *res;
      sort_version_list(lst, 0);
      get_frequent_members(good, lst, min);
      res = smartlist_join_strings(good, ",", 0, NULL);
      if (j)
        server_versions = res;
      else
        client_versions = res;
      SMARTLIST_FOREACH(lst, char *, cp, tor_free(cp));
      smartlist_free(good);
      smartlist_free(lst);
    }

    smartlist_sort_strings(flags);
    smartlist_uniq_strings(flags);

    smartlist_free(va_times);
    smartlist_free(fu_times);
    smartlist_free(vu_times);
    smartlist_free(votesec_list);
    smartlist_free(distsec_list);
  }

  chunks = smartlist_create();

  {
    char buf[1024];
    char va_buf[ISO_TIME_LEN+1], fu_buf[ISO_TIME_LEN+1],
      vu_buf[ISO_TIME_LEN+1];
    char *flaglist;
    format_iso_time(va_buf, valid_after);
    format_iso_time(fu_buf, fresh_until);
    format_iso_time(vu_buf, valid_until);
    flaglist = smartlist_join_strings(flags, " ", 0, NULL);

    tor_snprintf(buf, sizeof(buf),
                 "network-status-version 3\n"
                 "vote-status consensus\n"
                 "valid-after %s\n"
                 "fresh-until %s\n"
                 "valid-until %s\n"
                 "voting-delay %d %d\n"
                 "client-versions %s\n"
                 "server-versions %s\n"
                 "known-flags %s\n",
                 va_buf, fu_buf, vu_buf,
                 vote_seconds, dist_seconds,
                 client_versions, server_versions, flaglist);
    smartlist_add(chunks, tor_strdup(buf));

    tor_free(flaglist);
  }

  /* Sort the votes. */
  smartlist_sort(votes, _compare_votes_by_authority_id);
  /* Add the authority sections. */
  SMARTLIST_FOREACH(votes, networkstatus_vote_t *, v,
  {
    char buf[1024];
    struct in_addr in;
    char ip[INET_NTOA_BUF_LEN];
    char fingerprint[HEX_DIGEST_LEN+1];
    char votedigest[HEX_DIGEST_LEN+1];
    networkstatus_voter_info_t *voter = get_voter(v);

    in.s_addr = htonl(voter->addr);
    tor_inet_ntoa(&in, ip, sizeof(ip));
    base16_encode(fingerprint, sizeof(fingerprint), voter->identity_digest,
                  DIGEST_LEN);
    base16_encode(votedigest, sizeof(votedigest), voter->vote_digest,
                  DIGEST_LEN);

    tor_snprintf(buf, sizeof(buf),
                 "dir-source %s %s %s %s %d %d\n"
                 "contact %s\n"
                 "vote-digest %s\n",
                 voter->nickname, fingerprint, voter->address, ip,
                    voter->dir_port,
                    voter->or_port,
                 voter->contact,
                 votedigest);
    smartlist_add(chunks, tor_strdup(buf));
  });

  /* Add the actual router entries. */
  {
    int *index; /* index[j] is the current index into votes[j]. */
    int *size; /* size[j] is the number of routerstatuses in votes[j]. */
    int *flag_counts; /* The number of voters that list flag[j] for the
                       * currently considered router. */
    int i;
    smartlist_t *matching_descs = smartlist_create();
    smartlist_t *chosen_flags = smartlist_create();
    smartlist_t *versions = smartlist_create();

    int *n_voter_flags; /* n_voter_flags[j] is the number of flags that
                         * votes[j] knows about. */
    int *n_flag_voters; /* n_flag_voters[f] is the number of votes that care
                         * about flags[f]. */
    int **flag_map; /* flag_map[j][b] is an index f such that flag_map[f]
                     * is the same flag as votes[j]->known_flags[b]. */
    int *named_flag; /* Index of the flag "Named" for votes[j] */

    index = tor_malloc_zero(sizeof(int)*smartlist_len(votes));
    size = tor_malloc_zero(sizeof(int)*smartlist_len(votes));
    n_voter_flags = tor_malloc_zero(sizeof(int) * smartlist_len(votes));
    n_flag_voters = tor_malloc_zero(sizeof(int) * smartlist_len(flags));
    flag_map = tor_malloc_zero(sizeof(int*) * smartlist_len(votes));
    named_flag = tor_malloc_zero(sizeof(int*) * smartlist_len(votes));
    for (i = 0; i < smartlist_len(votes); ++i)
      named_flag[i] = -1;
    SMARTLIST_FOREACH(votes, networkstatus_vote_t *, v,
    {
      flag_map[v_sl_idx] = tor_malloc_zero(
                           sizeof(int)*smartlist_len(v->known_flags));
      SMARTLIST_FOREACH(v->known_flags, const char *, fl,
      {
        int p = smartlist_string_pos(flags, fl);
        tor_assert(p >= 0);
        flag_map[v_sl_idx][fl_sl_idx] = p;
        ++n_flag_voters[p];
        if (!strcmp(fl, "Named"))
          named_flag[v_sl_idx] = fl_sl_idx;
      });
      n_voter_flags[v_sl_idx] = smartlist_len(v->known_flags);
      size[v_sl_idx] = smartlist_len(v->routerstatus_list);
    });

    /* Now go through all the votes */
    flag_counts = tor_malloc(sizeof(int) * smartlist_len(flags));
    while (1) {
      vote_routerstatus_t *rs;
      routerstatus_t rs_out;
      const char *lowest_id = NULL;
      const char *chosen_version;
      const char *chosen_name = NULL;
      int naming_conflict = 0;
      int n_listing = 0;
      int i;
      char buf[256];

      /* Of the next-to-be-considered digest in each voter, which is first? */
      SMARTLIST_FOREACH(votes, networkstatus_vote_t *, v, {
        if (index[v_sl_idx] < size[v_sl_idx]) {
          rs = smartlist_get(v->routerstatus_list, index[v_sl_idx]);
          if (!lowest_id ||
              memcmp(rs->status.identity_digest, lowest_id, DIGEST_LEN) < 0)
            lowest_id = rs->status.identity_digest;
        }
      });
      if (!lowest_id) /* we're out of routers. */
        break;

      memset(flag_counts, 0, sizeof(int)*smartlist_len(flags));
      smartlist_clear(matching_descs);
      smartlist_clear(chosen_flags);
      smartlist_clear(versions);

      /* Okay, go through all the entries for this digest. */
      SMARTLIST_FOREACH(votes, networkstatus_vote_t *, v, {
        if (index[v_sl_idx] >= size[v_sl_idx])
          continue; /* out of entries. */
        rs = smartlist_get(v->routerstatus_list, index[v_sl_idx]);
        if (memcmp(rs->status.identity_digest, lowest_id, DIGEST_LEN))
          continue; /* doesn't include this router. */
        /* At this point, we know that we're looking at a routersatus with
         * identity "lowest".
         */
        ++index[v_sl_idx];
        ++n_listing;

        smartlist_add(matching_descs, rs);
        if (rs->version && rs->version[0])
          smartlist_add(versions, rs->version);

        /* Tally up all the flags. */
        for (i = 0; i < n_voter_flags[v_sl_idx]; ++i) {
          if (rs->flags & (U64_LITERAL(1) << i))
            ++flag_counts[flag_map[v_sl_idx][i]];
        }
        if (rs->flags & (U64_LITERAL(1) << named_flag[v_sl_idx])) {
          if (chosen_name && strcmp(chosen_name, rs->status.nickname)) {
            log_notice(LD_DIR, "Conflict on naming for router: %s vs %s",
                       chosen_name, rs->status.nickname);
            naming_conflict = 1;
          }
          chosen_name = rs->status.nickname;
        }

      });

      /* We don't include this router at all unless more than half of
       * the authorities we believe in list it. */
      if (n_listing <= total_authorities/2)
        continue;

      /* Figure out the most popular opinion of what the most recent
       * routerinfo and its contents are. */
      rs = compute_routerstatus_consensus(matching_descs);
      /* Copy bits of that into rs_out. */
      tor_assert(!memcmp(lowest_id, rs->status.identity_digest, DIGEST_LEN));
      memcpy(rs_out.identity_digest, lowest_id, DIGEST_LEN);
      memcpy(rs_out.descriptor_digest, rs->status.descriptor_digest,
             DIGEST_LEN);
      rs_out.addr = rs->status.addr;
      rs_out.published_on = rs->status.published_on;
      rs_out.dir_port = rs->status.dir_port;
      rs_out.or_port = rs->status.or_port;

      if (chosen_name && !naming_conflict) {
        strlcpy(rs_out.nickname, chosen_name, sizeof(rs_out.nickname));
      } else {
        strlcpy(rs_out.nickname, rs->status.nickname, sizeof(rs_out.nickname));
      }

      /* Set the flags. */
      smartlist_add(chosen_flags, (char*)"s"); /* for the start of the line. */
      SMARTLIST_FOREACH(flags, const char *, fl,
      {
        if (strcmp(fl, "Named")) {
          if (flag_counts[fl_sl_idx] > n_flag_voters[fl_sl_idx]/2)
            smartlist_add(chosen_flags, (char*)fl);
        } else {
          if (!naming_conflict && flag_counts[fl_sl_idx])
            smartlist_add(chosen_flags, (char*)"Named");
        }
      });

      /* Pick the version. */
      if (smartlist_len(versions)) {
        sort_version_list(versions, 0);
        chosen_version = get_most_frequent_member(versions);
      } else {
        chosen_version = NULL;
      }

      /* Okay!! Now we can write the descriptor... */
      /*     First line goes into "buf". */
      routerstatus_format_entry(buf, sizeof(buf), &rs_out, NULL, 1);
      smartlist_add(chunks, tor_strdup(buf));
      /*     Second line is all flags.  The "\n" is missing. */
      smartlist_add(chunks,
                    smartlist_join_strings(chosen_flags, " ", 0, NULL));
      /*     Now the version line. */
      if (chosen_version) {
        smartlist_add(chunks, tor_strdup("\nv "));
        smartlist_add(chunks, tor_strdup(chosen_version));
      }
      smartlist_add(chunks, tor_strdup("\n"));

      /* And the loop is over and we move on to the next router */
    }

    tor_free(index);
    tor_free(size);
    tor_free(n_voter_flags);
    tor_free(n_flag_voters);
    for (i = 0; i < smartlist_len(votes); ++i)
      tor_free(flag_map[i]);
    tor_free(flag_map);
    tor_free(flag_counts);
    smartlist_free(matching_descs);
    smartlist_free(chosen_flags);
    smartlist_free(versions);
  }

  /* Add a signature. */
  {
    char digest[DIGEST_LEN];
    char fingerprint[HEX_DIGEST_LEN+1];
    char signing_key_fingerprint[HEX_DIGEST_LEN+1];

    char buf[4096];
    smartlist_add(chunks, tor_strdup("directory-signature "));

    /* Compute the hash of the chunks. */
    hash_list_members(digest, chunks);

    /* Get the fingerprints */
    crypto_pk_get_fingerprint(identity_key, fingerprint, 0);
    crypto_pk_get_fingerprint(signing_key, signing_key_fingerprint, 0);

    /* add the junk that will go at the end of the line. */
    tor_snprintf(buf, sizeof(buf), "%s %s\n", fingerprint,
                 signing_key_fingerprint);
    /* And the signature. */
    if (router_append_dirobj_signature(buf, sizeof(buf), digest,
                                       signing_key)) {
      log_warn(LD_BUG, "Couldn't sign consensus networkstatus.");
      return NULL; /* This leaks, but it should never happen. */
    }
    smartlist_add(chunks, tor_strdup(buf));
  }

  result = smartlist_join_strings(chunks, "", 0, NULL);

  tor_free(client_versions);
  tor_free(server_versions);
  smartlist_free(flags);
  SMARTLIST_FOREACH(chunks, char *, cp, tor_free(cp));
  smartlist_free(chunks);

  {
    networkstatus_vote_t *c;
    if (!(c = networkstatus_parse_vote_from_string(result, 0))) {
      log_err(LD_BUG,"Generated a networkstatus consensus we couldn't "
              "parse.");
      tor_free(result);
      return NULL;
    }
    networkstatus_vote_free(c);
  }

  return result;
}

/** Check whether the signature on <b>voter</b> is correctly signed by
 * the signing key of <b>cert</b>. Return -1 if <b>cert</b> doesn't match the
 * signing key; otherwise set the good_signature or bad_signature flag on
 * <b>voter</b>, and return 0. */
/* (private; exposed for testing.) */
int
networkstatus_check_voter_signature(networkstatus_vote_t *consensus,
                                    networkstatus_voter_info_t *voter,
                                    authority_cert_t *cert)
{
  char d[DIGEST_LEN];
  char *signed_digest;
  size_t signed_digest_len;
  if (crypto_pk_get_digest(cert->signing_key, d)<0)
    return -1;
  if (memcmp(voter->signing_key_digest, d, DIGEST_LEN))
    return -1;
  signed_digest_len = crypto_pk_keysize(cert->signing_key);
  signed_digest = tor_malloc(signed_digest_len);
  if (crypto_pk_public_checksig(cert->signing_key,
                                signed_digest,
                                voter->signature,
                                voter->signature_len) != DIGEST_LEN ||
      memcmp(signed_digest, consensus->networkstatus_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "Got a bad signature on a networkstatus vote");
    voter->bad_signature = 1;
  } else {
    voter->good_signature = 1;
  }
  return 0;
}

/** Given a v3 networkstatus consensus in <b>consensus</b>, check every
 * as-yet-unchecked signature on <b>consensus.  Return 0 if there are enough
 * good signatures from recognized authorities on it, and -1 otherwise. */
int
networkstatus_check_consensus_signature(networkstatus_vote_t *consensus)
{
  int n_good = 0;
  int n_missing_key = 0;
  int n_bad = 0;
  int n_unknown = 0;
  int n_no_signature = 0;
  int n_required = get_n_authorities(V3_AUTHORITY)/2 + 1;

  tor_assert(! consensus->is_vote);

  SMARTLIST_FOREACH(consensus->voters, networkstatus_voter_info_t *, voter,
  {
    if (!voter->good_signature && !voter->bad_signature && voter->signature) {
      /* we can try to check the signature. */
      authority_cert_t *cert =
        authority_cert_get_by_digests(voter->identity_digest,
                                      voter->signing_key_digest);
      if (! cert) {
        ++n_unknown;
        continue;
      }
      if (networkstatus_check_voter_signature(consensus, voter, cert) < 0) {
        ++n_missing_key;
        continue;
      }
    }
    if (voter->good_signature)
      ++n_good;
    else if (voter->bad_signature)
      ++n_bad;
    else
      ++n_no_signature;
  });

  log_notice(LD_DIR,
             "%d unknown, %d missing key, %d good, %d bad, %d no signature, "
             "%d required", n_unknown, n_missing_key, n_good, n_bad,
             n_no_signature, n_required);

  if (n_good >= n_required)
    return 0;
  else
    return -1;
}

/** Given a consensus vote <b>target</b> and a list of
 * notworkstatus_voter_info_t in <b>src_voter_list</b> that correspond to the
 * same consensus, check whether there are any new signatures in
 * <b>src_voter_list</b> that should be added to <b>target.  (A signature
 * should be added if we have no signature for that voter in <b>target</b>
 * yet, or if we have no verifiable signature and the new signature is
 * verifiable.)  Set *<b>new_signatures_out</b> to a newly allocated string
 * holding the newly added signatures; set *<b>regenerate_out</b> to true if
 * we replaced a signature and 0 otherwise.  Return the number of signatures
 * added or changed. */
static int
networkstatus_add_signatures_impl(networkstatus_vote_t *target,
                                  smartlist_t *src_voter_list,
                                  char **new_signatures_out,
                                  int *regenerate_out)
{
  smartlist_t *added_signatures, *sigs;
  int r;
  tor_assert(target);
  tor_assert(!target->is_vote);
  tor_assert(new_signatures_out);
  tor_assert(regenerate_out);

  added_signatures = smartlist_create();

  /* For each voter in src... */
  SMARTLIST_FOREACH(src_voter_list, networkstatus_voter_info_t *, src_voter,
    {
      networkstatus_voter_info_t *target_voter =
        networkstatus_get_voter_by_id(target, src_voter->identity_digest);
      authority_cert_t *cert;
      /* If the target a doesn't know about this voter, then forget it. */
      if (!target_voter)
        continue;

      /* If the target already has a good signature from this voter, then skip
       * this one. */
      if (target_voter->good_signature)
        continue;

      /* Try checking the signature if we haven't already. */
      if (!src_voter->good_signature && !src_voter->bad_signature) {
        cert = authority_cert_get_by_digests(src_voter->identity_digest,
                                             src_voter->signing_key_digest);
        if (cert) {
          networkstatus_check_voter_signature(target, src_voter, cert);
        }
      }
      /* If this signature is good, or we don't have ay signature yet,
       * then add it. */
      if (src_voter->good_signature || !target_voter->signature) {
        if (target_voter->signature)
          *regenerate_out = 1;
        tor_free(target_voter->signature);
        target_voter->signature =
          tor_memdup(src_voter->signature, src_voter->signature_len);
        memcpy(target_voter->signing_key_digest, src_voter->signing_key_digest,
               DIGEST_LEN);
        target_voter->signature_len = src_voter->signature_len;
        target_voter->good_signature = 1;
        target_voter->bad_signature = 0;
        smartlist_add(added_signatures, target_voter);
      }
    });

  sigs = smartlist_create();
  SMARTLIST_FOREACH(added_signatures, networkstatus_voter_info_t *, v,
    {
      char buf[4096];
      char sk[HEX_DIGEST_LEN+1];
      char ik[HEX_DIGEST_LEN+1];
      tor_assert(v->signature);

      base16_encode(sk, sizeof(sk), v->signing_key_digest, DIGEST_LEN);
      base16_encode(ik, sizeof(ik), v->identity_digest, DIGEST_LEN);
      tor_snprintf(buf, sizeof(buf), "directory-signature %s %s\n"
                   "-----BEGIN SIGNATURE-----\n", ik, sk);
      smartlist_add(sigs, tor_strdup(buf));
      base64_encode(buf, sizeof(buf), v->signature, v->signature_len);
      strlcat(buf, "-----END SIGNATURE-----\n", sizeof(buf));
      smartlist_add(sigs, tor_strdup(buf));
    });

  *new_signatures_out = smartlist_join_strings(sigs, "", 0, NULL);
  SMARTLIST_FOREACH(sigs, char *, cp, tor_free(cp));
  smartlist_free(sigs);
  r = smartlist_len(added_signatures);
  smartlist_free(added_signatures);
  return r;
}

/** As networkstatus_add_consensus_signature_impl, but takes new signatures
 * from the consensus in <b>src</b>. */
int
networkstatus_add_consensus_signatures(networkstatus_vote_t *target,
                                       networkstatus_vote_t *src,
                                       char **new_signatures_out,
                                       int *regenerate_out)
{
  tor_assert(src);
  tor_assert(! src->is_vote);

  *new_signatures_out = NULL;

  /* Are they the same consensus? */
  if (memcmp(target->networkstatus_digest, src->networkstatus_digest,
             DIGEST_LEN))
    return -1;
  if (target == src)
    return 0;

  return networkstatus_add_signatures_impl(target, src->voters,
                                           new_signatures_out,
                                           regenerate_out);
}

/** As networkstatus_add_consensus_signature_impl, but takes new signatures
 * from the detached signatures document <b>sigs</b>. */
int
networkstatus_add_detached_signatures(networkstatus_vote_t *target,
                                      ns_detached_signatures_t *sigs,
                                      char **new_signatures_out,
                                      int *regenerate_out)
{
  tor_assert(sigs);

  *new_signatures_out = NULL;

  /* Are they the same consensus? */
  if (memcmp(target->networkstatus_digest, sigs->networkstatus_digest,
             DIGEST_LEN))
    return -1;

  return networkstatus_add_signatures_impl(target, sigs->signatures,
                                           new_signatures_out,
                                           regenerate_out);
}

/** Return a newly allocated string holding the detached-signatures document
 * corresponding to the signatures on <b>consensus</b>. */
char *
networkstatus_get_detached_signatures(networkstatus_vote_t *consensus)
{
  smartlist_t *elements;
  char buf[4096];
  char *result = NULL;
  int n_sigs = 0;
  tor_assert(consensus);
  tor_assert(! consensus->is_vote);

  elements = smartlist_create();

  {
    char va_buf[ISO_TIME_LEN+1], fu_buf[ISO_TIME_LEN+1],
      vu_buf[ISO_TIME_LEN+1];
    char d[HEX_DIGEST_LEN+1];

    base16_encode(d, sizeof(d), consensus->networkstatus_digest, DIGEST_LEN);
    format_iso_time(va_buf, consensus->valid_after);
    format_iso_time(fu_buf, consensus->fresh_until);
    format_iso_time(vu_buf, consensus->valid_until);

    tor_snprintf(buf, sizeof(buf),
                 "consensus-digest %s\n"
                 "valid-after %s\n"
                 "fresh-until %s\n"
                 "valid-until %s\n", d, va_buf, fu_buf, vu_buf);
    smartlist_add(elements, tor_strdup(buf));
  }

  SMARTLIST_FOREACH(consensus->voters, networkstatus_voter_info_t *, v,
    {
      char sk[HEX_DIGEST_LEN+1];
      char id[HEX_DIGEST_LEN+1];
      if (!v->signature || v->bad_signature)
        continue;
      ++n_sigs;
      base16_encode(sk, sizeof(sk), v->signing_key_digest, DIGEST_LEN);
      base16_encode(id, sizeof(id), v->identity_digest, DIGEST_LEN);
      tor_snprintf(buf, sizeof(buf),
                   "directory-signature %s %s\n-----BEGIN SIGNATURE-----\n",
                   id, sk);
      smartlist_add(elements, tor_strdup(buf));
      base64_encode(buf, sizeof(buf), v->signature, v->signature_len);
      strlcat(buf, "-----END SIGNATURE-----\n", sizeof(buf));
      smartlist_add(elements, tor_strdup(buf));
    });

  result = smartlist_join_strings(elements, "", 0, NULL);

  SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
  smartlist_free(elements);
  if (!n_sigs)
    tor_free(result);
  return result;
}

/** Release all storage held in <b>s</b>. */
void
ns_detached_signatures_free(ns_detached_signatures_t *s)
{
  if (s->signatures) {
    SMARTLIST_FOREACH(s->signatures, networkstatus_voter_info_t *, v,
      {
        tor_free(v->signature);
        tor_free(v);
      });
    smartlist_free(s->signatures);
  }
  tor_free(s);
}

/* =====
 * Certificate functions
 * ===== */

/** Free storage held in <b>cert</b>. */
void
authority_cert_free(authority_cert_t *cert)
{
  if (!cert)
    return;

  tor_free(cert->cache_info.signed_descriptor_body);
  if (cert->signing_key)
    crypto_free_pk_env(cert->signing_key);
  if (cert->identity_key)
    crypto_free_pk_env(cert->identity_key);

  tor_free(cert);
}

/** Allocate and return a new authority_cert_t with the same contents as
 * <b>cert</b>. */
authority_cert_t *
authority_cert_dup(authority_cert_t *cert)
{
  authority_cert_t *out = tor_malloc(sizeof(authority_cert_t));
  tor_assert(cert);

  memcpy(out, cert, sizeof(authority_cert_t));
  /* Now copy pointed-to things. */
  out->cache_info.signed_descriptor_body =
    tor_strndup(cert->cache_info.signed_descriptor_body,
                cert->cache_info.signed_descriptor_len);
  out->cache_info.saved_location = SAVED_NOWHERE;
  out->identity_key = crypto_pk_dup_key(cert->identity_key);
  out->signing_key = crypto_pk_dup_key(cert->signing_key);

  return out;
}

/* =====
 * Vote scheduling
 * ===== */

/** Set *<b>timing_out</b> to the intervals at which we would like to vote.
 * Note that these aren't the intervals we'll use to vote; they're the ones
 * that we'll vote to use. */
void
dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out)
{
  or_options_t *options = get_options();

  tor_assert(timing_out);

  timing_out->vote_interval = options->V3AuthVotingInterval;
  timing_out->n_intervals_valid = options->V3AuthNIntervalsValid;
  timing_out->vote_delay = options->V3AuthVoteDelay;
  timing_out->dist_delay = options->V3AuthDistDelay;
}

/** Return the start of the next interval of size <b>interval</b> (in seconds)
 * after <b>now</b>.  Midnight always starts a fresh interval, and if the last
 * interval of a day would be truncated to less than half its size, it is
 * rolled into the previous interval. */
time_t
dirvote_get_start_of_next_interval(time_t now, int interval)
{
  struct tm tm;
  time_t midnight_today;
  time_t midnight_tomorrow;
  time_t next;

  tor_gmtime_r(&now, &tm);
  tm.tm_hour = 0;
  tm.tm_min = 0;
  tm.tm_sec = 0;

  midnight_today = tor_timegm(&tm);
  midnight_tomorrow = midnight_today + (24*60*60);

  next = midnight_today + ((now-midnight_today)/interval + 1)*interval;

  /* Intervals never cross midnight. */
  if (next > midnight_tomorrow)
    next = midnight_tomorrow;

  /* If the interval would only last half as long as it's supposed to, then
   * skip over to the next day. */
  if (next + interval/2 > midnight_tomorrow)
    next = midnight_tomorrow;

  return next;
}

/** Scheduling information for a voting interval. */
static struct {
  /** When do we generate and distribute our vote for this interval? */
  time_t voting_starts;
  /** When do we give up on getting more votes and generate a consensus? */
  time_t voting_ends;
  /** When do we publish the consensus? */
  time_t interval_starts;

  /** When do we discard old votes and pending detached signatures? */
  time_t discard_old_votes;

  /* True iff we have generated and distributed our vote. */
  int have_voted;
  /* True iff we have built a consensus and sent the signatures around. */
  int have_built_consensus;
  /* True iff we have published our consensus. */
  int have_published_consensus;
} voting_schedule = {0,0,0,0,0,0,0};

/** Set voting_schedule to hold the timing for the next vote we should be
 * doing. */
void
dirvote_recalculate_timing(time_t now)
{
  /* XXXX020 call this when inputs may have changed (i.e., whenver we get a
   * fresh consensus.) */
  int interval, vote_delay, dist_delay;
  time_t start;
  time_t end;
  networkstatus_vote_t *consensus = networkstatus_get_latest_consensus();

  memset(&voting_schedule, 0, sizeof(voting_schedule));

  if (consensus) {
    interval = consensus->fresh_until - consensus->valid_after;
    vote_delay = consensus->vote_seconds;
    dist_delay = consensus->dist_seconds;
  } else {
    interval = 30*60;
    vote_delay = dist_delay = 300;
  }

  tor_assert(interval > 0);

  if (vote_delay + dist_delay > interval/2)
    vote_delay = dist_delay = interval / 4;

  start = voting_schedule.interval_starts =
    dirvote_get_start_of_next_interval(now,interval);
  end = dirvote_get_start_of_next_interval(start+1, interval);

  tor_assert(end > start);

  voting_schedule.voting_ends = start - vote_delay;
  voting_schedule.voting_starts = start - vote_delay - dist_delay;

  voting_schedule.discard_old_votes = start +
    ((end-start) - vote_delay - dist_delay)/2 ;
}

/** Entry point: Take whatever voting actions are pending as of <b>now</b>. */
void
dirvote_act(time_t now)
{
  if (!voting_schedule.voting_starts) {
    char *keys = list_v3_auth_ids();
    authority_cert_t *c = get_my_v3_authority_cert();
    log_notice(LD_DIR, "Scheduling voting.  Known authority IDs are %s."
               "Mine is %s.",
               keys, hex_str(c->cache_info.identity_digest, DIGEST_LEN));
    tor_free(keys);
    dirvote_recalculate_timing(now);
  }
  if (voting_schedule.voting_starts < now && !voting_schedule.have_voted) {
    log_notice(LD_DIR, "Time to vote.");
    dirvote_perform_vote();
    voting_schedule.have_voted = 1;
  }
  /* XXXX020 after a couple minutes here, start trying to fetch votes. */
  if (voting_schedule.voting_ends < now &&
      !voting_schedule.have_built_consensus) {
    log_notice(LD_DIR, "Time to compute a consensus.");
    dirvote_compute_consensus();
    /* XXXX020 we will want to try again later if we haven't got enough
     * votes yet. */
    voting_schedule.have_built_consensus = 1;
  }
  if (voting_schedule.interval_starts < now &&
      !voting_schedule.have_published_consensus) {
    log_notice(LD_DIR, "Time to publish the consensus.");
    dirvote_publish_consensus();
    /* XXXX020 we will want to try again later if we haven't got enough
     * signatures yet. */
    voting_schedule.have_published_consensus = 1;
  }
  if (voting_schedule.discard_old_votes < now) {
    log_notice(LD_DIR, "Time to discard old votes.");
    dirvote_clear_pending_votes();
    dirvote_recalculate_timing(now);
  }
}

/** A vote networkstatus_vote_t and its unparsed body: held around so we can
 * use it to generate a consensus (at voting_ends) and so we can serve it to
 * other authorities that might want it. */
typedef struct pending_vote_t {
  cached_dir_t *vote_body;
  networkstatus_vote_t *vote;
} pending_vote_t;

/** List of pending_vote_t for the current vote. */
static smartlist_t *pending_vote_list = NULL;
/** The body of the consensus that we're currently building.  Once we
 * have it built, it goes into dirserv.c */
static char *pending_consensus_body = NULL;
/** The detached signatures for the consensus that we're currently
 * building. */
static char *pending_consensus_signatures = NULL;
/** The parsed in-progress consensus document. */
static networkstatus_vote_t *pending_consensus = NULL;
/** List of ns_detached_signatures_t: hold signatures that get posted to us
 * before we have generated the consensus on our own. */
static smartlist_t *pending_consensus_signature_list = NULL;

/** Generate a networkstatus vote and post it to all the v3 authorities.
 * (V3 Authority only) */
void
dirvote_perform_vote(void)
{
  cached_dir_t *new_vote = generate_v3_networkstatus();
  pending_vote_t *pending_vote;
  int status;
  const char *msg = "";

  if (!new_vote)
    return;

  if (!(pending_vote = dirvote_add_vote(new_vote->dir, &msg, &status))) {
    log_warn(LD_DIR, "Couldn't store my own vote! (I told myself, '%s'.)",
             msg);
    return;
  }

  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_VOTE,
                               ROUTER_PURPOSE_GENERAL,
                               V3_AUTHORITY,
                               pending_vote->vote_body->dir,
                               pending_vote->vote_body->dir_len, 0);
  log_notice(LD_DIR, "Vote posted.");
}

/** Drop all currently pending votes, consensus, and detached signatures. */
void
dirvote_clear_pending_votes(void)
{
  if (pending_vote_list) {
    SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, v, {
        cached_dir_decref(v->vote_body);
        v->vote_body = NULL;
        networkstatus_vote_free(v->vote);
        tor_free(v);
      });
    smartlist_clear(pending_vote_list);
  }
  if (pending_consensus_signature_list) {
    SMARTLIST_FOREACH(pending_consensus_signature_list, char *, cp,
                      tor_free(cp));
    smartlist_clear(pending_consensus_signature_list);
  }
  tor_free(pending_consensus_body);
  tor_free(pending_consensus_signatures);
  if (pending_consensus) {
    networkstatus_vote_free(pending_consensus);
    pending_consensus = NULL;
  }
}

/* XXXX020 delete me. */
static char *
list_v3_auth_ids(void)
{
  smartlist_t *known_v3_keys = smartlist_create();
  char *keys;
  SMARTLIST_FOREACH(router_get_trusted_dir_servers(),
                    trusted_dir_server_t *, ds,
       if (!tor_digest_is_zero(ds->v3_identity_digest))
         smartlist_add(known_v3_keys,
              tor_strdup(hex_str(ds->v3_identity_digest, DIGEST_LEN))));
  keys = smartlist_join_strings(known_v3_keys, ", ", 0, NULL);
  SMARTLIST_FOREACH(known_v3_keys, char *, cp, tor_free(cp));
  smartlist_free(known_v3_keys);
  return keys;
}

/** Called when we have received a networkstatus vote in <b>vote_body</b>.
 * Parse and validate it, and on success store it as a pending vote (which we
 * then return).  Return NULL on failure.  Sets *<b>msg_out</b> and
 * *<b>status_out</b> to an HTTP response and status code.  (V3 authority
 * only) */
pending_vote_t *
dirvote_add_vote(const char *vote_body, const char **msg_out, int *status_out)
{
  networkstatus_vote_t *vote;
  networkstatus_voter_info_t *vi;
  trusted_dir_server_t *ds;
  pending_vote_t *pending_vote = NULL;
  tor_assert(vote_body);
  tor_assert(msg_out);
  tor_assert(status_out);
  *status_out = 0;

  if (!pending_vote_list)
    pending_vote_list = smartlist_create();
  *msg_out = NULL;

  vote = networkstatus_parse_vote_from_string(vote_body, 1);
  if (!vote) {
    *msg_out = "Unable to parse vote";
    goto err;
  }
  tor_assert(smartlist_len(vote->voters) == 1);
  vi = get_voter(vote);
  tor_assert(vi->good_signature == 1);
  ds = trusteddirserver_get_by_v3_auth_digest(vi->identity_digest);
  if (!ds || !(ds->type & V3_AUTHORITY)) {
    char *keys = list_v3_auth_ids();
    log_warn(LD_DIR, "Got a vote from an authority with authority key ID %s. "
             "This authority %s.  Known v3 key IDs are: %s",
             hex_str(vi->identity_digest, DIGEST_LEN),
             ds?"is not recognized":"is recognized, but is not listed as v3",
             keys);
    tor_free(keys);

    *msg_out = "Vote not from a recognized v3 authority";
    goto err;
  }
  tor_assert(vote->cert);
  if (!authority_cert_get_by_digests(vote->cert->cache_info.identity_digest,
                                     vote->cert->signing_key_digest)) {
    /* Hey, it's a new cert! */
    trusted_dirs_load_certs_from_string(
                               vote->cert->cache_info.signed_descriptor_body,
                               0 /* from_store */);
    if (!authority_cert_get_by_digests(vote->cert->cache_info.identity_digest,
                                       vote->cert->signing_key_digest)) {
      log_warn(LD_BUG, "We added a cert, but still couldn't find it.");
    }
  }

  /* Is it for the right period? */
  if (vote->valid_after != voting_schedule.interval_starts) {
    char tbuf1[ISO_TIME_LEN+1], tbuf2[ISO_TIME_LEN+1];
    format_iso_time(tbuf1, vote->valid_after);
    format_iso_time(tbuf2, voting_schedule.interval_starts);
    log_warn(LD_DIR, "Rejecting vote with valid-after time of %s; we were "
             "expecting %s", tbuf1, tbuf2);
    *msg_out = "Bad valid-after time";
    goto err;
  }

  /* Now see whether we already have a vote from this authority.*/
  SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, v, {
      if (! memcmp(v->vote->cert->cache_info.identity_digest,
                   vote->cert->cache_info.identity_digest,
                   DIGEST_LEN)) {
        networkstatus_voter_info_t *vi_old = get_voter(v->vote);
        if (!memcmp(vi_old->vote_digest, vi->vote_digest, DIGEST_LEN)) {
          /* Ah, it's the same vote. Not a problem. */
          log_info(LD_DIR, "Discarding a vote we already have.");
          *status_out = 200;
          *msg_out = "ok";
          goto err;
        } else if (v->vote->published < vote->published) {
          log_notice(LD_DIR, "Replacing an older pending vote from this "
                     "directory.");
          cached_dir_decref(v->vote_body);
          networkstatus_vote_free(v->vote);
          v->vote_body = new_cached_dir(tor_strdup(vote_body),
                                        vote->published);
          v->vote = vote;
          *msg_out = "ok";
          return v;
        } else {
          *msg_out = "Already have a newer pending vote";
          goto err;
        }
      }
    });

  pending_vote = tor_malloc_zero(sizeof(pending_vote_t));
  pending_vote->vote_body = new_cached_dir(tor_strdup(vote_body),
                                           vote->published);
  pending_vote->vote = vote;
  smartlist_add(pending_vote_list, pending_vote);
  if (!*status_out)
    *status_out = 200;
  *msg_out = "ok";
  return pending_vote;
 err:
  if (vote)
    networkstatus_vote_free(vote);
  if (!*msg_out)
    *msg_out = "Error adding vote";
  if (!*status_out)
    *status_out = 400;
  return NULL;
}

/** Try to compute a v3 networkstatus consensus from the currently pending
 * votes.  Return 0 on success, -1 on failure.  Store the consensus in
 * pending_consensus: it won't be ready to be published until we have
 * everybody else's signatures collected too. (V3 Authoritity only) */
int
dirvote_compute_consensus(void)
{
  /* Have we got enough votes to try? */
  int n_votes, n_voters;
  smartlist_t *votes = NULL;
  char *consensus_body = NULL, *signatures = NULL;
  networkstatus_vote_t *consensus = NULL;
  authority_cert_t *my_cert;

  if (!pending_vote_list)
    pending_vote_list = smartlist_create();

  n_voters = get_n_authorities(V3_AUTHORITY);
  n_votes = smartlist_len(pending_vote_list);
  if (n_votes <= n_voters/2) {
    log_warn(LD_DIR, "We don't have enough votes to generate a consensus.");
    goto err;
  }

  if (!(my_cert = get_my_v3_authority_cert())) {
    log_warn(LD_DIR, "Can't generate consensus without a certificate.");
    goto err;
  }

  votes = smartlist_create();
  SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, v,
                    smartlist_add(votes, v->vote));

  consensus_body = networkstatus_compute_consensus(
        votes, n_voters,
        my_cert->identity_key,
        get_my_v3_authority_signing_key());
  if (!consensus_body) {
    log_warn(LD_DIR, "Couldn't generate a consensus at all!");
    goto err;
  }
  consensus = networkstatus_parse_vote_from_string(consensus_body, 0);
  if (!consensus) {
    log_warn(LD_DIR, "Couldn't parse consensus we generated!");
    goto err;
  }
  /* 'Check' our own signature, to mark it valid. */
  networkstatus_check_consensus_signature(consensus);

  signatures = networkstatus_get_detached_signatures(consensus);
  if (!signatures) {
    log_warn(LD_DIR, "Couldn't extract signatures.");
    goto err;
  }

  tor_free(pending_consensus_body);
  pending_consensus_body = consensus_body;
  tor_free(pending_consensus_signatures);
  pending_consensus_signatures = signatures;

  if (pending_consensus)
    networkstatus_vote_free(pending_consensus);
  pending_consensus = consensus;

  if (pending_consensus_signature_list) {
    int n_sigs = 0;
    /* we may have gotten signatures for this consensus before we built
     * it ourself.  Add them now. */
    SMARTLIST_FOREACH(pending_consensus_signature_list, char *, sig,
      {
        const char *msg = NULL;
        n_sigs += dirvote_add_signatures_to_pending_consensus(sig, &msg);
        tor_free(sig);
      });
    if (n_sigs)
      log_notice(LD_DIR, "Added %d pending signatures while building "
                 "consensus.", n_sigs);
    smartlist_clear(pending_consensus_signature_list);
  }

  log_notice(LD_DIR, "Consensus computed; uploading signature(s)");

  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_SIGNATURES,
                               ROUTER_PURPOSE_GENERAL,
                               V3_AUTHORITY,
                               pending_consensus_signatures,
                               strlen(pending_consensus_signatures), 0);
  log_notice(LD_DIR, "Signature(s) posted.");

  return 0;
 err:
  if (votes)
    smartlist_free(votes);
  tor_free(consensus_body);
  tor_free(signatures);
  networkstatus_vote_free(consensus);

  return -1;
}

/** Helper: we just got the <b>deteached_signatures_body</b> sent to us as
 * signatures on the currently pending consensus.  Add them to the consensus
 * as appropriate.  Return the number of signatures added. (?) */
static int
dirvote_add_signatures_to_pending_consensus(
                       const char *detached_signatures_body,
                       const char **msg_out)
{
  ns_detached_signatures_t *sigs = NULL;
  int r = -1, regenerate=0;
  char *new_signatures = NULL;
  size_t siglen;

  tor_assert(detached_signatures_body);
  tor_assert(msg_out);

  /* Only call if we have a pending consensus right now. */
  tor_assert(pending_consensus);
  tor_assert(pending_consensus_body);
  tor_assert(pending_consensus_signatures);

  *msg_out = NULL;

  if (!(sigs = networkstatus_parse_detached_signatures(
                               detached_signatures_body, NULL))) {
    *msg_out = "Couldn't parse detached signatures.";
    goto err;
  }

  r = networkstatus_add_detached_signatures(pending_consensus,
                                            sigs,
                                            &new_signatures,
                                            &regenerate);

  // XXXX020 originally, this test was regenerate && r >= 0).  But one
  // code path is simpler than 2.
  if (new_signatures && (siglen = strlen(new_signatures)) && r >= 0) {
    /* XXXX This should really be its own function. */
    char *new_detached =
      networkstatus_get_detached_signatures(pending_consensus);
    const char *src;
    char *dst;
    size_t new_consensus_len =
      strlen(pending_consensus_body) + strlen(new_detached) + 1;
    pending_consensus_body = tor_realloc(pending_consensus_body,
                                         new_consensus_len);
    dst = strstr(pending_consensus_body, "directory-signature ");
    tor_assert(dst);
    src = strstr(new_detached, "directory-signature ");
    tor_assert(src);
    strlcpy(dst, src, new_consensus_len - (dst-pending_consensus_body));

    /* XXXX020 remove this once it fails to crash. */
    {
      ns_detached_signatures_t *sigs =
        networkstatus_parse_detached_signatures(new_detached, NULL);
      networkstatus_vote_t *v = networkstatus_parse_vote_from_string(
                                                 pending_consensus_body, 0);
      tor_assert(sigs);
      ns_detached_signatures_free(sigs);
      tor_assert(v);
      networkstatus_vote_free(v);
    }
    tor_free(pending_consensus_signatures);
    pending_consensus_signatures = new_detached;
  }
#if 0
  else if (new_signatures && (siglen = strlen(new_signatures)) && r >= 0) {
    size_t siglen = strlen(new_signatures);
    size_t len = strlen(pending_consensus_body);
    pending_consensus_body = tor_realloc(pending_consensus_body,
                                         len+siglen+1);
    memcpy(pending_consensus_body+len, new_signatures, siglen+1);

    len = strlen(pending_consensus_signatures);
    pending_consensus_signatures = tor_realloc(pending_consensus_signatures,
                                               len+siglen+1);
    memcpy(pending_consensus_signatures+len, new_signatures, siglen+1);

    log_info(LD_DIR, "Added %d new signatures to the pending consensus.", r);
  }
#endif

  *msg_out = "ok";
  goto done;
 err:
  if (!msg_out)
    *msg_out = "Unrecognized error while adding detached signatures.";
 done:
  tor_free(new_signatures);
  if (sigs)
    ns_detached_signatures_free(sigs);
  return r;
}

/** Helper: we just got the <b>deteached_signatures_body</b> sent to us as
 * signatures on the currently pending consensus.  Add them to the pending
 * consensus (if we have one); otherwise queue them until we have a
 * consensus. */
int
dirvote_add_signatures(const char *detached_signatures_body)
{
  /*XXXX020 return value is senseless. */
  if (pending_consensus) {
    const char *msg=NULL;
    log_notice(LD_DIR, "Got a signature. Adding it to the pending consensus.");
    return dirvote_add_signatures_to_pending_consensus(
                                         detached_signatures_body, &msg);
  } else {
    log_notice(LD_DIR, "Got a signature. Queueing it for the next consensus.");
    if (!pending_consensus_signature_list)
      pending_consensus_signature_list = smartlist_create();
    smartlist_add(pending_consensus_signature_list,
                  tor_strdup(detached_signatures_body));
    return 0;
  }
}

/** Replace the consensus that we're currently serving with the one that we've
 * been building. (V3 Authority only) */
int
dirvote_publish_consensus(void)
{
  /* Can we actually publish it yet? */
  if (!pending_consensus ||
      networkstatus_check_consensus_signature(pending_consensus)<0) {
    log_warn(LD_DIR, "Not enough info to publish pending consensus");
    return -1;
  }

  if (networkstatus_set_current_consensus(pending_consensus_body, 0))
    log_warn(LD_DIR, "Error publishing consensus");
  else
    log_warn(LD_DIR, "Consensus published.");

  return 0;
}

/** Release all static storage held in dirvote.c */
void
dirvote_free_all(void)
{
  dirvote_clear_pending_votes();
  if (pending_vote_list) {
    /* now empty as a result of clear_pending_votes. */
    smartlist_free(pending_vote_list);
    pending_vote_list = NULL;
  }
  tor_free(pending_consensus_body);
  tor_free(pending_consensus_signatures);
  if (pending_consensus) {
    networkstatus_vote_free(pending_consensus);
    pending_consensus = NULL;
  }
  if (pending_consensus_signature_list) {
    /* now empty as a result of clear_pending_votes. */
    smartlist_free(pending_consensus_signature_list);
    pending_consensus_signature_list = NULL;
  }
}

/* ====
 * Access to pending items.
 * ==== */

/** Return the body of the consensus that we're currently trying to build. */
const char *
dirvote_get_pending_consensus(void)
{
  return pending_consensus_body;
}

/** Return the signatures that we know for the consensus that we're currently
 * trying to build */
const char *
dirvote_get_pending_detached_signatures(void)
{
  return pending_consensus_signatures;
}

/** Return the vote for the authority with the v3 authority identity key
 * digest <b>id</b>.  If <b>id</b> is NULL, return our own vote. May return
 * NULL if we have no vote for the authority in question. */
const cached_dir_t *
dirvote_get_vote(const char *id)
{
  if (!pending_vote_list)
    return NULL;
  if (id == NULL) {
    authority_cert_t *c = get_my_v3_authority_cert();
    if (c)
      id = c->cache_info.identity_digest;
    else
      return NULL;
  }
  SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, pv,
       if (!memcmp(get_voter(pv->vote)->identity_digest, id, DIGEST_LEN))
         return pv->vote_body);
  return NULL;
}

