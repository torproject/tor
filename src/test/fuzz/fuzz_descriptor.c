
#include "or.h"
#include "routerparse.h"
#include "routerlist.h"
#include "fuzzing.h"

int
fuzz_init(void)
{
  ed25519_init();
  return 0;
}

int
fuzz_main(const uint8_t *data, size_t sz)
{
  routerinfo_t *ri;
  const char *str = (const char*) data;
  ri = router_parse_entry_from_string((const char *)str,
                                      str+sz,
                                      0, 0, 0, NULL);
  if (ri)
    routerinfo_free(ri);
  return 0;
}

