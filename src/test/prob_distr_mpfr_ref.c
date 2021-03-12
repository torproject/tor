/* Copyright 2012-2021, The Tor Project, Inc
 * See LICENSE for licensing information */

/** prob_distr_mpfr_ref.c
 *
 * Example reference file for GNU MPFR vectors tested in test_prob_distr.c .
 * Code by Riastradh.
 */

#include <complex.h>
#include <float.h>
#include <math.h>
#include <stdio.h>

/* Must come after <stdio.h> so we get mpfr_printf.  */
#include <mpfr.h>

/*  gcc -o mpfr prob_distr_mpfr_ref.c -lmpfr -lm */

/* Computes logit(p) for p = .49999 */
int
main(void)
{
  mpfr_t p, q, r;
  mpfr_init(p);
  mpfr_set_prec(p, 200);
  mpfr_init(q);
  mpfr_set_prec(q, 200);
  mpfr_init(r);
  mpfr_set_prec(r, 200);
  mpfr_set_d(p, .49999, MPFR_RNDN);
  mpfr_set_d(q, 1, MPFR_RNDN);
  /* r := q - p = 1 - p */
  mpfr_sub(r, q, p, MPFR_RNDN);
  /* q := p/r = p/(1 - p) */
  mpfr_div(q, p, r, MPFR_RNDN);
  /* r := log(q) = log(p/(1 - p)) */
  mpfr_log(r, q, MPFR_RNDN);
  mpfr_printf("mpfr 200-bit\t%.128Rg\n", r);

  /*
   * Print a double approximation to logit three different ways.  All
   * three agree bit for bit on the libms I tried, with the nextafter
   * adjustment (which is well within the 10 eps relative error bound
   * advertised).  Apparently I must have used the Goldberg expression
   * for what I wrote down in the test case.
   */
  printf("mpfr 53-bit\t%.17g\n", nextafter(mpfr_get_d(r, MPFR_RNDN), 0), 0);
  volatile double p0 = .49999;
  printf("log1p\t\t%.17g\n", nextafter(-log1p((1 - 2*p0)/p0), 0));
  volatile double x = (1 - 2*p0)/p0;
  volatile double xp1 = x + 1;
  printf("Goldberg\t%.17g\n", -x*log(xp1)/(xp1 - 1));

  /*
   * Print a bad approximation, using the naive expression, to see a
   * lot of wrong digits, far beyond the 10 eps relative error attained
   * by -log1p((1 - 2*p)/p).
   */
  printf("naive\t\t%.17g\n", log(p0/(1 - p0)));

  fflush(stdout);
  return ferror(stdout);
}
