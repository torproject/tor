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
static time_t
median_time(smartlist_t *times)
{
  int idx;
  tor_assert(smartlist_len(times));
  smartlist_sort(times, _compare_times);
  idx = (smartlist_len(times)-1)/2;
  return *(time_t*)smartlist_get(times, idx);
}

/** Given a list of one or more int*, return the (low) median. */
static int
median_int(smartlist_t *ints)
{
  int idx;
  tor_assert(smartlist_len(ints));
  smartlist_sort(ints, _compare_ints);
  idx = (smartlist_len(ints)-1)/2;
  return *(time_t*)smartlist_get(ints, idx);
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
 * value in a newly allocated string. */
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
  /* XXXX020 somebody needs to check vote authority. It could be this
   * function, it could be somebody else. */
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
    /* document these XXXX020 */
    int *index;
    int *size;
    int *flag_counts;
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
    int *named_flag;

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
          if (chosen_name && strcmp(chosen_name, rs->status.nickname))
            naming_conflict = 1; /* XXXX020 warn? */
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
        /* XXXX020 fails on very long version string */
        tor_snprintf(buf, sizeof(buf), "\nv %s\n", chosen_version);
        smartlist_add(chunks, tor_strdup(buf));
      } else {
        smartlist_add(chunks, tor_strdup("\n"));
      }

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
    /* XXXX020 check return */
    router_append_dirobj_signature(buf, sizeof(buf), digest, signing_key);
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

/** Check whether the pending_signature on <b>voter</b> is correctly signed by
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
  /*XXXX020 check return*/
  crypto_pk_get_digest(cert->signing_key, d);
  if (memcmp(voter->signing_key_digest, d, DIGEST_LEN)) {
    return -1;
  }
  signed_digest_len = crypto_pk_keysize(cert->signing_key);
  signed_digest = tor_malloc(signed_digest_len);
  if (crypto_pk_public_checksig(cert->signing_key,
                                signed_digest,
                                voter->pending_signature,
                                voter->pending_signature_len) != DIGEST_LEN ||
      memcmp(signed_digest, consensus->networkstatus_digest, DIGEST_LEN)) {
    log_warn(LD_DIR, "Got a bad signature."); /*XXXX020 say more*/
    voter->bad_signature = 1;
  } else {
    voter->good_signature = 1;
  }
  tor_free(voter->pending_signature);
  return 0;
}

/** DOCDOC */
int
networkstatus_check_consensus_signature(networkstatus_vote_t *consensus)
{
  int n_good = 0;
  int n_missing_key = 0;
  int n_bad = 0;
  int n_unknown = 0;
  int n_no_signature = 0;

  tor_assert(! consensus->is_vote);

  SMARTLIST_FOREACH(consensus->voters, networkstatus_voter_info_t *, voter,
  {
    trusted_dir_server_t *ds =
      trusteddirserver_get_by_v3_auth_digest(voter->identity_digest);
    if (!ds) {
      ++n_unknown;
      continue;
    }
    if (voter->pending_signature) {
      tor_assert(!voter->good_signature && !voter->bad_signature);
      if (!ds->v3_cert ||
          networkstatus_check_voter_signature(consensus, voter,
                                              ds->v3_cert) < 0) {
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

  /* XXXX020 actually use the result. */

  return 0;
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

/** DOCDOC */
void
dirvote_get_preferred_voting_intervals(vote_timing_t *timing_out)
{
  tor_assert(timing_out);

  /* XXXX020 make these configurable. */
  timing_out->vote_interval = 3600;
  timing_out->n_intervals_valid = 3;
  timing_out->vote_delay = 300;
  timing_out->dist_delay = 300;
}

/** DOCDOC */
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

  if (next > midnight_tomorrow)
    next = midnight_tomorrow;

  return next;
}

/** DOCDOC */
static struct {
  time_t voting_starts;
  time_t voting_ends;
  time_t interval_starts;
} voting_schedule;

/** DOCDOC */
void
dirvote_recalculate_timing(time_t now)
{
  int interval, vote_delay, dist_delay;
  time_t start;
  networkstatus_vote_t *consensus = networkstatus_get_latest_consensus();

  if (consensus) {
    /* XXXX020 sanity-check these somewhere! */
    interval = consensus->fresh_until - consensus->valid_after;
    vote_delay = consensus->vote_seconds;
    dist_delay = consensus->dist_seconds;
  } else {
    /* XXXX020 is this correct according the the spec? */
    interval = 3600;
    vote_delay = dist_delay = 300;
  }

  start = voting_schedule.interval_starts =
    dirvote_get_start_of_next_interval(now,interval);
  voting_schedule.voting_ends = start - vote_delay;
  voting_schedule.voting_starts = start - vote_delay - dist_delay;
}

/** DOCDOC */
typedef struct pending_vote_t {
  cached_dir_t *vote_body;
  networkstatus_vote_t *vote;
} pending_vote_t;

/** DOCDOC */
static smartlist_t *pending_vote_list = NULL;
/** DOCDOC */
static char *pending_consensus_body = NULL;

/** DOCDOC */
void
dirvote_perform_vote(void)
{
  cached_dir_t *new_vote = generate_v3_networkstatus();
  pending_vote_t *pending_vote;
  const char *msg = "";

  if ((pending_vote = dirvote_add_vote(new_vote->dir, &msg))) {
    log_warn(LD_DIR, "Couldn't store my own vote! (I told myself, '%s'.)",
             msg);
    return;
  }

  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_VOTE,
                               ROUTER_PURPOSE_GENERAL,
                               V3_AUTHORITY,
                               pending_vote->vote_body->dir,
                               pending_vote->vote_body->dir_len, 0);
}

/** DOCDOC */
void
dirvote_clear_pending_votes(void)
{
  if (!pending_vote_list)
    return;
  SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, v, {
      cached_dir_decref(v->vote_body);
      v->vote_body = NULL;
      networkstatus_vote_free(v->vote);
      tor_free(v);
    });
  smartlist_clear(pending_vote_list);
}

/** DOCDOC */
pending_vote_t *
dirvote_add_vote(const char *vote_body, const char **msg_out)
{
  networkstatus_vote_t *vote;
  networkstatus_voter_info_t *vi;
  trusted_dir_server_t *ds;
  pending_vote_t *pending_vote = NULL;
  tor_assert(vote_body);
  tor_assert(msg_out);

  if (!pending_vote_list)
    pending_vote_list = smartlist_create();
  *msg_out = NULL;

  vote = networkstatus_parse_vote_from_string(vote_body, 1);
  if (!vote) {
    *msg_out = "Unable to parse vote";
    goto err;
  }
  tor_assert(smartlist_len(vote->voters) == 1);
  vi = smartlist_get(vote->voters, 0);
  tor_assert(vi->good_signature == 1);
  ds = trusteddirserver_get_by_v3_auth_digest(vi->identity_digest);
  if (!ds || !(ds->type & V3_AUTHORITY)) {
    *msg_out = "Vote not from a recognized v3 authority";
    goto err;
  }
  /* XXXX020 check times; make sure epochs match. */

  SMARTLIST_FOREACH(pending_vote_list, pending_vote_t *, v, {
      if (! memcmp(v->vote->cert->cache_info.identity_digest,
                   vote->cert->cache_info.identity_digest,
                   DIGEST_LEN)) {
        log_notice(LD_DIR, "We already have a pending vote from this dir");
        if (v->vote->published < vote->published) {
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

  *msg_out = "ok";
  return pending_vote;
 err:
  if (vote)
    networkstatus_vote_free(vote);
  if (!*msg_out)
    *msg_out = "Error adding vote";
  /*XXXX020 free other fields */
  return NULL;
}

/** DOCDOC */
int
dirvote_compute_consensus(void)
{
  /* Have we got enough votes to try? */
  int n_votes, n_voters;
  smartlist_t *votes = NULL;
  char *consensus_body = NULL;
  authority_cert_t *my_cert;

  if (!pending_vote_list)
    pending_vote_list = smartlist_create();

  n_voters = get_n_authorities(V3_AUTHORITY);
  n_votes = smartlist_len(pending_vote_list);
  /* XXXX020 see if there are enough to go ahead. */

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

  tor_free(pending_consensus_body);
  pending_consensus_body = consensus_body;

  return 0;
 err:
  if (votes)
    smartlist_free(votes);
  return -1;
}

