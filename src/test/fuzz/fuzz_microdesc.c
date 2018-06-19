/* Copyright (c) 2016-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */
#define ROUTERPARSE_PRIVATE
#include "or.h"
#include "routerparse.h"
#include "microdesc.h"
#include "fuzzing.h"

static void
mock_dump_desc__nodump(const char *desc, const char *type)
{
  (void)desc;
  (void)type;
}

int
fuzz_init(void)
{
  disable_signature_checking();
  MOCK(dump_desc, mock_dump_desc__nodump);
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
  const char *str = (const char*) data;
  smartlist_t *result = microdescs_parse_from_string((const char *)str,
                                                     str+sz,
                                                     0, SAVED_NOWHERE, NULL);
  if (result) {
    log_debug(LD_GENERAL, "Parsing okay: %d", smartlist_len(result));
    SMARTLIST_FOREACH(result, microdesc_t *, md, microdesc_free(md));
    smartlist_free(result);
  } else {
    log_debug(LD_GENERAL, "Parsing failed");
  }
  return 0;
}

