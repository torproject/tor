/**
 * \file crypto_rand_numeric.c
 *
 * \brief Functions for retrieving uniformly distributed numbers
 *   from our PRNGs.
 **/

#include "lib/crypt_ops/crypto_rand.h"
#include "lib/log/util_bug.h"

/**
 * Return a pseudorandom integer, chosen uniformly from the values
 * between 0 and <b>max</b>-1 inclusive.  <b>max</b> must be between 1 and
 * INT_MAX+1, inclusive.
 */
int
crypto_rand_int(unsigned int max)
{
  unsigned int val;
  unsigned int cutoff;
  tor_assert(max <= ((unsigned int)INT_MAX)+1);
  tor_assert(max > 0); /* don't div by 0 */

  /* We ignore any values that are >= 'cutoff,' to avoid biasing the
   * distribution with clipping at the upper end of unsigned int's
   * range.
   */
  cutoff = UINT_MAX - (UINT_MAX%max);
  while (1) {
    crypto_rand((char*)&val, sizeof(val));
    if (val < cutoff)
      return val % max;
  }
}

/**
 * Return a pseudorandom integer, chosen uniformly from the values i such
 * that min <= i < max.
 *
 * <b>min</b> MUST be in range [0, <b>max</b>).
 * <b>max</b> MUST be in range (min, INT_MAX].
 **/
int
crypto_rand_int_range(unsigned int min, unsigned int max)
{
  tor_assert(min < max);
  tor_assert(max <= INT_MAX);

  /* The overflow is avoided here because crypto_rand_int() returns a value
   * between 0 and (max - min) inclusive. */
  return min + crypto_rand_int(max - min);
}

/**
 * As crypto_rand_int_range, but supports uint64_t.
 **/
uint64_t
crypto_rand_uint64_range(uint64_t min, uint64_t max)
{
  tor_assert(min < max);
  return min + crypto_rand_uint64(max - min);
}

/**
 * As crypto_rand_int_range, but supports time_t.
 **/
time_t
crypto_rand_time_range(time_t min, time_t max)
{
  tor_assert(min < max);
  return min + (time_t)crypto_rand_uint64(max - min);
}

/**
 * Return a pseudorandom 64-bit integer, chosen uniformly from the values
 * between 0 and <b>max</b>-1 inclusive.
 **/
uint64_t
crypto_rand_uint64(uint64_t max)
{
  uint64_t val;
  uint64_t cutoff;
  tor_assert(max < UINT64_MAX);
  tor_assert(max > 0); /* don't div by 0 */

  /* We ignore any values that are >= 'cutoff,' to avoid biasing the
   * distribution with clipping at the upper end of unsigned int's
   * range.
   */
  cutoff = UINT64_MAX - (UINT64_MAX%max);
  while (1) {
    crypto_rand((char*)&val, sizeof(val));
    if (val < cutoff)
      return val % max;
  }
}

/**
 * Return a pseudorandom double d, chosen uniformly from the range
 * 0.0 <= d < 1.0.
 **/
double
crypto_rand_double(void)
{
  /* We just use an unsigned int here; we don't really care about getting
   * more than 32 bits of resolution */
  unsigned int u;
  crypto_rand((char*)&u, sizeof(u));
#if SIZEOF_INT == 4
#define UINT_MAX_AS_DOUBLE 4294967296.0
#elif SIZEOF_INT == 8
#define UINT_MAX_AS_DOUBLE 1.8446744073709552e+19
#else
#error SIZEOF_INT is neither 4 nor 8
#endif /* SIZEOF_INT == 4 || ... */
  return ((double)u) / UINT_MAX_AS_DOUBLE;
}
