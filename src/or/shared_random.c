/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file shared_random.c
 *
 * \brief Functions and data structure needed to accomplish the shared
 *        random protocol as defined in proposal #250.
 **/

#define SHARED_RANDOM_PRIVATE

#include "or.h"
#include "shared_random.h"
#include "config.h"
#include "confparse.h"
#include "networkstatus.h"
#include "routerkeys.h"
#include "router.h"
#include "routerlist.h"
#include "shared_random_state.h"

/* Allocate a new commit object and initializing it with <b>identity</b>
 * that MUST be provided. The digest algorithm is set to the default one
 * that is supported. The rest is uninitialized. This never returns NULL. */
static sr_commit_t *
commit_new(const char *rsa_identity_fpr)
{
  sr_commit_t *commit;

  tor_assert(rsa_identity_fpr);

  commit = tor_malloc_zero(sizeof(*commit));
  commit->alg = SR_DIGEST_ALG;
  strlcpy(commit->rsa_identity_fpr, rsa_identity_fpr,
          sizeof(commit->rsa_identity_fpr));
  return commit;
}

/* Parse the encoded commit. The format is:
 *    base64-encode( TIMESTAMP || H(REVEAL) )
 *
 * If successfully decoded and parsed, commit is updated and 0 is returned.
 * On error, return -1. */
STATIC int
commit_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  size_t offset = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_COMMIT_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_COMMIT_BASE64_LEN) {
    /* This means that if we base64 decode successfully the reveiced commit,
     * we'll end up with a bigger decoded commit thus unusable. */
    goto error;
  }

  /* Decode our encoded commit. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of a commit. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Commit from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len != SR_COMMIT_LEN) {
    log_warn(LD_BUG, "SR: Commit from authority %s decoded length doesn't "
                     "match the expected length (%d vs %d).",
             commit->rsa_identity_fpr, decoded_len, SR_COMMIT_LEN);
    goto error;
  }

  /* First is the timestamp (8 bytes). */
  commit->commit_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  offset += sizeof(uint64_t);
  /* Next is hashed reveal. */
  memcpy(commit->hashed_reveal, b64_decoded + offset,
         sizeof(commit->hashed_reveal));
  /* Copy the base64 blob to the commit. Useful for voting. */
  strlcpy(commit->encoded_commit, encoded, sizeof(commit->encoded_commit));

  return 0;

 error:
  return -1;
}

/* Parse the b64 blob at <b>encoded</b> containing reveal information and
 * store the information in-place in <b>commit</b>. Return 0 on success else
 * a negative value. */
STATIC int
reveal_decode(const char *encoded, sr_commit_t *commit)
{
  int decoded_len = 0;
  /* XXX: Needs two extra bytes for the base64 decode calculation matches
   * the binary length once decoded. #17868. */
  char b64_decoded[SR_REVEAL_LEN + 2];

  tor_assert(encoded);
  tor_assert(commit);

  if (strlen(encoded) > SR_REVEAL_BASE64_LEN) {
    /* This means that if we base64 decode successfully the received reveal
     * value, we'll end up with a bigger decoded value thus unusable. */
    goto error;
  }

  /* Decode our encoded reveal. Let's be careful here since _encoded_ is
   * coming from the network in a dirauth vote so we expect nothing more
   * than the base64 encoded length of our reveal. */
  decoded_len = base64_decode(b64_decoded, sizeof(b64_decoded),
                              encoded, strlen(encoded));
  if (decoded_len < 0) {
    log_warn(LD_BUG, "SR: Reveal from authority %s can't be decoded.",
             commit->rsa_identity_fpr);
    goto error;
  }

  if (decoded_len != SR_REVEAL_LEN) {
    log_warn(LD_BUG, "SR: Reveal from authority %s decoded length is "
                     "doesn't match the expected length (%d vs %d)",
             commit->rsa_identity_fpr, decoded_len, SR_REVEAL_LEN);
    goto error;
  }

  commit->reveal_ts = (time_t) tor_ntohll(get_uint64(b64_decoded));
  /* Copy the last part, the random value. */
  memcpy(commit->random_number, b64_decoded + 8,
         sizeof(commit->random_number));
  /* Also copy the whole message to use during verification */
  strlcpy(commit->encoded_reveal, encoded, sizeof(commit->encoded_reveal));

  return 0;

 error:
  return -1;
}

/* Cleanup both our global state and disk state. */
static void
sr_cleanup(void)
{
  sr_state_free();
}

/* Free a commit object. */
void
sr_commit_free(sr_commit_t *commit)
{
  if (commit == NULL) {
    return;
  }
  /* Make sure we do not leave OUR random number in memory. */
  memwipe(commit->random_number, 0, sizeof(commit->random_number));
  tor_free(commit);
}

/* Parse a list of arguments from a SRV value either from a vote, consensus
 * or from our disk state and return a newly allocated srv object. NULL is
 * returned on error.
 *
 * The arguments' order:
 *    num_reveals, value
 */
sr_srv_t *
sr_parse_srv(const smartlist_t *args)
{
  char *value;
  int num_reveals, ok;
  sr_srv_t *srv = NULL;

  tor_assert(args);

  if (smartlist_len(args) < 2) {
    goto end;
  }

  /* First argument is the number of reveal values */
  num_reveals = (int)tor_parse_long(smartlist_get(args, 0),
                               10, 0, INT32_MAX, &ok, NULL);
  if (!ok) {
    goto end;
  }
  srv = tor_malloc_zero(sizeof(*srv));
  srv->num_reveals = num_reveals;

  /* Second and last argument is the shared random value it self. */
  value = smartlist_get(args, 1);
  base16_decode((char *) srv->value, sizeof(srv->value), value,
                HEX_DIGEST256_LEN);
 end:
  return srv;
}

/* Parse a commit from a vote or from our disk state and return a newly
 * allocated commit object. NULL is returned on error.
 *
 * The commit's data is in <b>args</b> and the order matters very much:
 *  algname, RSA fingerprint, commit value[, reveal value]
 */
sr_commit_t *
sr_parse_commit(const smartlist_t *args)
{
  char *value;
  digest_algorithm_t alg;
  const char *rsa_identity_fpr;
  sr_commit_t *commit = NULL;

  if (smartlist_len(args) < 3) {
    goto error;
  }

  /* First argument is the algorithm. */
  value = smartlist_get(args, 0);
  alg = crypto_digest_algorithm_parse_name(value);
  if (alg != SR_DIGEST_ALG) {
    log_warn(LD_BUG, "SR: Commit algorithm %s is not recognized.",
             escaped(value));
    goto error;
  }

  /* Second argument is the RSA fingerprint of the auth */
  rsa_identity_fpr = smartlist_get(args, 1);
  if (base16_decode(digest, DIGEST_LEN, rsa_identity_fpr,
                    HEX_DIGEST_LEN) < 0) {
    log_warn(LD_DIR, "SR: RSA fingerprint '%s' not decodable",
             rsa_identity_fpr);
    goto error;
  }
  /* Let's make sure, for extra safety, that this fingerprint is known to
   * us. Even though this comes from a vote, doesn't hurt to be
   * extracareful. */
  if (trusteddirserver_get_by_v3_auth_digest(digest) == NULL) {
    log_warn(LD_DIR, "SR: Fingerprint %s is not from a recognized "
                     "authority. Discarding commit.",
             rsa_identity_fpr);
    goto error;
  }

  /* Allocate commit since we have a valid identity now. */
  commit = commit_new(rsa_identity_fpr);

  /* Third argument is the commitment value base64-encoded. */
  value = smartlist_get(args, 2);
  if (commit_decode(value, commit) < 0) {
    goto error;
  }

  /* (Optional) Fourth argument is the revealed value. */
  if (smartlist_len(args) > 3) {
    value = smartlist_get(args, 3);
    if (reveal_decode(value, commit) < 0) {
      goto error;
    }
  }

  return commit;

 error:
  sr_commit_free(commit);
  return NULL;
}

/* Initialize shared random subsystem. This MUST be called early in the boot
 * process of tor. Return 0 on success else -1 on error. */
int
sr_init(int save_to_disk)
{
  return sr_state_init(save_to_disk, 1);
}

/* Save our state to disk and cleanup everything. */
void
sr_save_and_cleanup(void)
{
  sr_state_save();
  sr_cleanup();
}
