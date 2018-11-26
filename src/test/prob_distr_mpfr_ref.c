/* Copyright 2012-2018, The Tor Project, Inc
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
  mpfr_printf("%.128Rf\n", r);
  printf("%.17g\n", nextafter(mpfr_get_d(r, MPFR_RNDN), 0));
  fflush(stdout);
  return ferror(stdout);
}
