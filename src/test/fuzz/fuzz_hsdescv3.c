/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ROUTERPARSE_PRIVATE
#define HS_DESCRIPTOR_PRIVATE

#include "or.h"
#include "ed25519_cert.h" /* Trunnel interface. */
#include "crypto_ed25519.h"
#include "hs_descriptor.h"
#include "routerparse.h"
#include "util.h"

#include "fuzzing.h"

static void
mock_dump_desc__nodump(const char *desc, const char *type)
{
  (void)desc;
  (void)type;
}

static int
mock_rsa_ed25519_crosscert_check(const uint8_t *crosscert,
                                 const size_t crosscert_len,
                                 const crypto_pk_t *rsa_id_key,
                                 const ed25519_public_key_t *master_key,
                                 const time_t reject_if_expired_before)
{
  (void) crosscert;
  (void) crosscert_len;
  (void) rsa_id_key;
  (void) master_key;
  (void) reject_if_expired_before;
  return 0;
}

int
fuzz_init(void)
{
  disable_signature_checking();
  MOCK(dump_desc, mock_dump_desc__nodump);
  MOCK(rsa_ed25519_crosscert_check, mock_rsa_ed25519_crosscert_check);
  ed25519_init();
  return 0;
}

int
fuzz_cleanup(void)
{
  return 0;
}

int
fuzz_main(const uint8_t *data, size_t sz)
{
  hs_descriptor_t *desc = NULL;

  char *fuzzing_data = tor_memdup_nulterm(data, sz);

  hs_desc_decode_descriptor(fuzzing_data, NULL, &desc);
  if (desc) {
    log_debug(LD_GENERAL, "Decoding okay");
    hs_descriptor_free(desc);
  } else {
    log_debug(LD_GENERAL, "Decoding failed");
  }

  tor_free(fuzzing_data);
  return 0;
}

