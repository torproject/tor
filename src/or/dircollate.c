/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2014, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file dircollate.c
 *
 * \brief Collation code for figuring out which identities to vote for in
 *   the directory voting process.
 */

#define DIRCOLLATE_PRIVATE
#include "dircollate.h"

static void dircollator_collate_by_rsa(dircollator_t *dc);

static void
dircollator_add_routerstatus(dircollator_t *dc,
                             int vote_num,
                             networkstatus_t *vote,
                             vote_routerstatus_t *vrs)
{
  const char *id = vrs->status.identity_digest;

  (void) vote;
  vote_routerstatus_t **vrs_lst = digestmap_get(dc->by_rsa_sha1, id);
  if (NULL == vrs_lst) {
    vrs_lst = tor_calloc(sizeof(vote_routerstatus_t *), dc->n_votes);
    digestmap_set(dc->by_rsa_sha1, id, vrs_lst);
  }

  tor_assert(vrs_lst[vote_num] == NULL);
  vrs_lst[vote_num] = vrs;
}

dircollator_t *
dircollator_new(int n_votes, int n_authorities)
{
  dircollator_t *dc = tor_malloc_zero(sizeof(dircollator_t));

  tor_assert(n_votes <= n_authorities);

  dc->n_votes = n_votes;
  dc->n_authorities = n_authorities;

  dc->by_rsa_sha1 = digestmap_new();

  return dc;
}

void
dircollator_free(dircollator_t *dc)
{
  if (!dc)
    return;

  digestmap_free(dc->by_rsa_sha1, tor_free_);

  tor_free(dc);
}

void
dircollator_add_vote(dircollator_t *dc, networkstatus_t *v)
{
  tor_assert(v->type == NS_TYPE_VOTE);
  tor_assert(dc->next_vote_num < dc->n_votes);
  tor_assert(!dc->is_collated);

  const int votenum = dc->next_vote_num++;

  SMARTLIST_FOREACH_BEGIN(v->routerstatus_list, vote_routerstatus_t *, vrs) {
    dircollator_add_routerstatus(dc, votenum, v, vrs);
  } SMARTLIST_FOREACH_END(vrs);
}

void
dircollator_collate(dircollator_t *dc)
{
  dircollator_collate_by_rsa(dc);
}

static void
dircollator_collate_by_rsa(dircollator_t *dc)
{
  tor_assert(!dc->is_collated);

  dc->all_rsa_sha1_lst = smartlist_new();

  const int total_authorities = dc->n_authorities;

  DIGESTMAP_FOREACH(dc->by_rsa_sha1, k, vote_routerstatus_t **, vrs_lst) {
    int n = 0, i;
    for (i = 0; i < dc->n_votes; ++i) {
      if (vrs_lst[i] != NULL)
        ++n;
    }

    if (n <= total_authorities / 2)
      continue;

    smartlist_add(dc->all_rsa_sha1_lst, (char *)k);
  } DIGESTMAP_FOREACH_END;

  smartlist_sort_digests(dc->all_rsa_sha1_lst);
  dc->is_collated = 1;
}

int
dircollator_n_routers(dircollator_t *dc)
{
  return smartlist_len(dc->all_rsa_sha1_lst);
}

vote_routerstatus_t **
dircollator_get_votes_for_router(dircollator_t *dc, int idx)
{
  tor_assert(idx < smartlist_len(dc->all_rsa_sha1_lst));
  return digestmap_get(dc->by_rsa_sha1,
                       smartlist_get(dc->all_rsa_sha1_lst, idx));
}

