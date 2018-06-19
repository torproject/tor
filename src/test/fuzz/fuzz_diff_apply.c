/* Copyright (c) 2016-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define CONSDIFF_PRIVATE

#include "orconfig.h"
#include "or.h"
#include "consdiff.h"

#include "fuzzing.h"

static int
mock_consensus_compute_digest_(const char *c, consensus_digest_t *d)
{
  (void)c;
  memset(d->sha3_256, 3, sizeof(d->sha3_256));
  return 0;
}

static int
mock_consensus_digest_eq_(const uint8_t *a, const uint8_t *b)
{
  (void)a;
  (void)b;
  return 1;
}

int
fuzz_init(void)
{
  MOCK(consensus_compute_digest, mock_consensus_compute_digest_);
  MOCK(consensus_digest_eq, mock_consensus_digest_eq_);
  return 0;
}

int
fuzz_cleanup(void)
{
  UNMOCK(consensus_compute_digest);
  UNMOCK(consensus_digest_eq);
  return 0;
}

int
fuzz_main(const uint8_t *stdin_buf, size_t data_size)
{
#define SEP "=====\n"
#define SEPLEN strlen(SEP)
  const uint8_t *separator = tor_memmem(stdin_buf, data_size, SEP, SEPLEN);
  if (! separator)
    return 0;
  size_t c1_len = separator - stdin_buf;
  char *c1 = tor_memdup_nulterm(stdin_buf, c1_len);
  size_t c2_len = data_size - c1_len - SEPLEN;
  char *c2 = tor_memdup_nulterm(separator + SEPLEN, c2_len);

  char *c3 = consensus_diff_apply(c1, c2);

  tor_free(c1);
  tor_free(c2);
  tor_free(c3);

  return 0;
}

