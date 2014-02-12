#ifndef SIPHASH_H
#define SIPHASH_H
struct sipkey {
  uint64_t k0;
  uint64_t k1;
};
uint64_t siphash24(const void *src, unsigned long src_sz, const struct sipkey *key);

#endif
