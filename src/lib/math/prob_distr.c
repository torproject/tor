/*-
 * Copyright (c) 2018 Taylor R. Campbell
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* cc -o random random.c -lm && ./random */

#include <assert.h>
#include <float.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define validate_container_of(PTR, TYPE, FIELD)				\
	(0 * sizeof((PTR) - &((TYPE *)(((char *)(PTR)) -		\
		    offsetof(TYPE, FIELD)))->FIELD))
#define validate_const_container_of(PTR, TYPE, FIELD)			\
	(0 * sizeof((PTR) - &((const TYPE *)(((const char *)(PTR)) -	\
		    offsetof(TYPE, FIELD)))->FIELD))

#define	container_of(PTR, TYPE, FIELD)					\
	((TYPE *)(((char *)(PTR)) - offsetof(TYPE, FIELD))		\
	    + validate_container_of(PTR, TYPE, FIELD))
#define	const_container_of(PTR, TYPE, FIELD)				\
	((const TYPE *)(((const char *)(PTR)) - offsetof(TYPE, FIELD))	\
	    + validate_const_container_of(PTR, TYPE, FIELD))

#define ATTR_UNUSED __attribute__((__unused__))
#if __STDC_VERSION__ >= 201112L
#define CTASSERT(x) _Static_assert(x, #x)
#else
#if defined(__COUNTER__)
#define CTASSERT(x) CTASSERT_EXPN(x, c, __COUNTER__)
#elif defined(__INCLUDE_LEVEL__)
#define CTASSERT(x) CTASSERT_EXPN(x, __INCLUDE_LEVEL__, __LINE__)
#else
#define CTASSERT(x) CTASSERT_EXPN(x, l, __LINE__) /* hope it's unique enough */
#endif
#define CTASSERT_EXPN(x, a, b) CTASSERT_DECL(x, a, b)
#define CTASSERT_DECL(x, a, b) \
  typedef char tor_ctassert_##a##_##b[(x) ? 1 : -1] ATTR_UNUSED
#endif

/**
 * Draw an unsigned 32-bit integer uniformly at random.
 */
uint32_t
crypto_rand_uint32(void)
{
	return arc4random();
}

/**
 * Count number of one bits in 32-bit word.
 */
unsigned
bitcount32(uint32_t x)
{

	/* Count two-bit groups.  */
	x -= (x >> 1) & UINT32_C(0x55555555);

	/* Count four-bit groups.  */
	x = ((x >> 2) & UINT32_C(0x33333333)) + (x & UINT32_C(0x33333333));

	/* Count eight-bit groups.  */
	x = (x + (x >> 4)) & UINT32_C(0x0f0f0f0f);

	/* Sum all eight-bit groups, and extract the sum.  */
	return (x * UINT32_C(0x01010101)) >> 24;
}

/**
 * Count leading zeros in 32-bit word.
 */
unsigned
clz32(uint32_t x)
{

	/* Round up to a power of two.  */
	x |= x >> 1;
	x |= x >> 2;
	x |= x >> 4;
	x |= x >> 8;
	x |= x >> 16;

	/* Subtract count of one bits from 32.  */
	return (32 - bitcount32(x));
}

/*
 * Some lemmas for error bounds.
 *
 * Lemma 1.  If |d| <= 1/2, then 1/(1 + d) <= 2.
 *
 * Proof.  If 0 <= d <= 1/2, then 1 + d >= 1, so that 1/(1 + d) <= 1.
 * If -1/2 <= d <= 0, then 1 + d >= 1/2, so that 1/(1 + d) <= 2.  QED.
 *
 * Lemma 2. If b = a*(1 + d)/(1 + d') for |d'| < 1/2 and nonzero a, b,
 * then b = a*(1 + e) for |e| <= 2|d' - d|.
 *
 * Proof.  |a - b|/|a|
 *             = |a - a*(1 + d)/(1 + d')|/|a|
 *             = |1 - (1 + d)/(1 + d')|
 *             = |(1 + d' - 1 - d)/(1 + d')|
 *             = |(d' - d)/(1 + d')|
 *            <= 2|d' - d|, by Lemma 1,
 *
 * QED.
 *
 * Lemma 3.  For |d|, |d'| < 1/4,
 *
 *     |log((1 + d)/(1 + d'))| <= 4|d - d'|.
 *
 * Proof.  Write
 *
 *     log((1 + d)/(1 + d'))
 *      = log(1 + (1 + d)/(1 + d') - 1)
 *      = log(1 + (1 + d - 1 - d')/(1 + d')
 *      = log(1 + (d - d')/(1 + d')).
 *
 * By Lemma 1, |(d - d')/(1 + d')| < 2|d' - d| < 1, so the Taylor
 * series of log(1 + x) converges absolutely for (d - d')/(1 + d'),
 * and thus we have
 *
 *     |log(1 + (d - d')/(1 + d'))|
 *      = |\sum_{n=1}^\infty ((d - d')/(1 + d'))^n/n|
 *     <= \sum_{n=1}^\infty |(d - d')/(1 + d')|^n/n
 *     <= \sum_{n=1}^\infty |2(d' - d)|^n/n
 *     <= \sum_{n=1}^\infty |2(d' - d)|^n
 *      = 1/(1 - |2(d' - d)|)
 *     <= 4|d' - d|,
 *
 * QED.
 *
 * Lemma 4.  If 1/e <= 1 + x <= e, then
 *
 *     log(1 + (1 + d) x) = (1 + d') log(1 + x)
 *
 * for |d'| < 8|d|.
 *
 * Proof.  Write
 *
 *     log(1 + (1 + d) x)
 *     = log(1 + x + x*d)
 *     = log((1 + x) (1 + x + x*d)/(1 + x))
 *     = log(1 + x) + log((1 + x + x*d)/(1 + x))
 *     = log(1 + x) (1 + log((1 + x + x*d)/(1 + x))/log(1 + x)).
 *
 * The relative error is bounded by
 *
 *     |log((1 + x + x*d)/(1 + x))/log(1 + x)|
 *     <= 4|x + x*d - x|/|log(1 + x)|, by Lemma 3,
 *      = 4|x*d|/|log(1 + x)|
 *      < 8|d|,
 *
 * since in this range 0 < 1 - 1/e < x/log(1 + x) <= e - 1 < 2.  QED.
 */

/**
 * Compute the logistic function: 1/(1 + e^{-x}) = e^x/(1 + e^x).  Maps
 * a log-odds-space probability in [-\infty, +\infty] into a
 * direct-space probability in [0,1].  Inverse of logit.
 *
 * Ill-conditioned for large x; the identity logistic(-x) = 1 -
 * logistic(x) and the function logistichalf(x) = logistic(x) - 1/2 may
 * help to rearrange a computation.
 *
 * This implementation gives relative error bounded by 7 eps.
 */
double
logistic(double x)
{

	if (x <= log(DBL_EPSILON/2)) {
		/*
		 * e^x <= eps, so
		 *
		 *     |e^x - e^x/(1 + e^x)|/|e^x/(1 + e^x)|
		 *     <= |1 - 1/(1 + e^x)|*|1 + e^x|
		 *      = |e^x/(1 + e^x)|*|1 + e^x|
		 *      = |e^x|
		 *     <= eps.
		 */
		return exp(x);
	} else if (x <= -log(DBL_EPSILON/2)) {
		/*
		 * e^{-x} > 0, so 1 + e^{-x} > 1, and 0 < 1/(1 +
		 * e^{-x}) < 1; further, since e^{-x} < 1 + e^{-x}, we
		 * also have 0 < 1/(1 + e^{-x}) < 1.  Thus, if exp has
		 * relative error d0, + has relative error d1, and /
		 * has relative error d2, then we get
		 *
		 *     (1 + d2)/[(1 + (1 + d0) e^{-x})(1 + d1)]
		 *     = (1 + d0)/[1 + e^{-x} + d0 e^{-x}
		 *                     + d1 + d1 e^{-x} + d0 d1 e^{-x}]
		 *     = (1 + d0)/[(1 + e^{-x})
		 *                 * (1 + d0 e^{-x}/(1 + e^{-x})
		 *                      + d1/(1 + e^{-x})
		 *                      + d0 d1 e^{-x}/(1 + e^{-x}))].
		 *     = (1 + d0)/[(1 + e^{-x})(1 + d')]
		 *     = [1/(1 + e^{-x})] (1 + d0)/(1 + d')
		 *
		 * where
		 *
		 *     d' = d0 e^{-x}/(1 + e^{-x})
		 *          + d1/(1 + e^{-x})
		 *          + d0 d1 e^{-x}/(1 + e^{-x}).
		 *
		 * By Lemma 2 this relative error is bounded by
		 *
		 *     2|d0 - d'|
		 *      = 2|d0 - d0 e^{-x}/(1 + e^{-x})
		 *             - d1/(1 + e^{-x})
		 *             - d0 d1 e^{-x}/(1 + e^{-x})|
		 *     <= 2|d0| + 2|d0 e^{-x}/(1 + e^{-x})|
		 *             + 2|d1/(1 + e^{-x})|
		 *             + 2|d0 d1 e^{-x}/(1 + e^{-x})|
		 *     <= 2|d0| + 2|d0| + 2|d1| + 2|d0 d1|
		 *     <= 4|d0| + 2|d1| + 2|d0 d1|
		 *     <= 6 eps + 2 eps^2.
		 */
		return 1/(1 + exp(-x));
	} else {
		/*
		 * e^{-x} <= eps, so the relative error of 1 from 1/(1
		 * + e^{-x}) is
		 *
		 *     |1/(1 + e^{-x}) - 1|/|1/(1 + e^{-x})|
		 *      = |e^{-x}/(1 + e^{-x})|/|1/(1 + e^{-x})|
		 *      = |e^{-x}|
		 *     <= eps.
		 *
		 * This computation avoids an intermediate overflow
		 * exception, although the effect on the result is
		 * harmless.
		 *
		 * XXX Should maybe raise inexact here.
		 */
		return 1;
	}
}

/**
 * Compute the logistic function, translated in output by 1/2:
 * logistichalf(x) = logistic(x) - 1/2.  Well-conditioned on the entire
 * real plane, with maximum condition number 1 at 0.
 *
 * This implementation gives relative error bounded by 5 eps.
 */
double
logistichalf(double x)
{
	/*
	 * Rewrite this with the identity
	 *
	 *	1/(1 + e^{-x}) - 1/2
	 *	= (1 - 1/2 - e^{-x}/2)/(1 + e^{-x})
	 *	= (1/2 - e^{-x}/2)/(1 + e^{-x})
	 *	= (1 - e^{-x})/[2 (1 + e^{-x})]
	 *	= -(e^{-x} - 1)/[2 (1 + e^{-x})],
	 *
	 * which we can evaluate by -expm1(-x)/[2 (1 + exp(-x))].
	 *
	 * Suppose exp has error d0, + has error d1, expm1 has error
	 * d2, and / has error d3, so we evaluate
	 *
	 *	-(1 + d2) (1 + d3) (e^{-x} - 1)
	 *	  / [2 (1 + d1) (1 + (1 + d0) e^{-x})].
	 *
	 * In the denominator,
	 *
	 *	1 + (1 + d0) e^{-x}
	 *	= 1 + e^{-x} + d0 e^{-x}
	 *	= (1 + e^{-x}) (1 + d0 e^{-x}/(1 + e^{-x})),
	 *
	 * so the relative error of the numerator is
	 *
	 *	d' = d2 + d3 + d2 d3,
	 * and of the denominator,
	 *	d'' = d1 + d0 e^{-x}/(1 + e^{-x}) + d0 d1 e^{-x}/(1 + e^{-x})
	 *	    = d1 + d0 L(-x) + d0 d1 L(-x),
	 *
	 * where L(-x) is logistic(-x).  By Lemma 1 the relative error
	 * of the quotient is bounded by
	 *
	 *	2|d2 + d3 + d2 d3 - d1 - d0 L(x) + d0 d1 L(x)|,
	 *
	 * Since 0 < L(x) < 1, this is bounded by
	 *
	 *	2|d2| + 2|d3| + 2|d2 d3| + 2|d1| + 2|d0| + 2|d0 d1|
	 *	<= 4 eps + 2 eps^2.
	 */
	if (x < log(DBL_EPSILON/8)) {
		/*
		 * Avoid overflow in e^{-x}.  When x < log(eps/4), we
		 * we further have x < logit(eps/4), so that
		 * logistic(x) < eps/4.  Hence the relative error of
		 * logistic(x) - 1/2 from -1/2 is bounded by eps/2, and
		 * so the relative error of -1/2 from logistic(x) - 1/2
		 * is bounded by eps.
		 */
		return -0.5;
	} else {
		return -expm1(-x)/(2*(1 + exp(-x)));
	}
}

/**
 * Compute the logit function: log p/(1 - p).  Defined on [0,1].  Maps
 * a direct-space probability in [0,1] to a log-odds-space probability
 * in [-\infty, +\infty].  Inverse of logistic.
 *
 * Ill-conditioned near 1/2 and 1; the identity logit(1 - p) =
 * -logit(p) and the function logithalf(p0) = logit(1/2 + p0) may help
 * to rearrange a computation for p in [1/(1 + e), 1 - 1/(1 + e)].
 *
 * This implementation gives relative error bounded by 10 eps.
 */
double
logit(double p)
{

	/* logistic(-1) <= p <= logistic(+1) */
	if (1/(1 + exp(1)) <= p && p <= 1/(1 + exp(-1))) {
		/*
		 * For inputs near 1/2, we want to compute log1p(near
		 * 0) rather than log(near 1), so write this as:
		 *
		 * log(p/(1 - p)) = -log((1 - p)/p)
		 * = -log(1 + (1 - p)/p - 1)
		 * = -log(1 + (1 - p - p)/p)
		 * = -log(1 + (1 - 2p)/p).
		 *
		 * Since p = 2p/2 <= 1 <= 2*2p = 4p, the floating-point
		 * evaluation of 1 - 2p is exact; the only error arises
		 * from division and log1p.  First, note that if
		 * logistic(-1) <= p <= logistic(+1), (1 - 2p)/p lies
		 * in the bounds of Lemma 4.
		 *
		 * If division has relative error d0 and log1p has
		 * relative error d1, the outcome is
		 *
		 *     -(1 + d1) log(1 + (1 - 2p) (1 + d0)/p)
		 *     = -(1 + d1) (1 + d') log(1 + (1 - 2p)/p)
		 *     = -(1 + d1 + d' + d1 d') log(1 + (1 - 2p)/p).
		 *
		 * where |d'| < 8|d0| by Lemma 4.  The relative error
		 * is then bounded by
		 *
		 *     |d1 + d' + d1 d'|
		 *     <= |d1| + 8|d0| + 8|d1 d0|
		 *     <= 9 eps + 8 eps^2.
		 */
		return -log1p((1 - 2*p)/p);
	} else {
		/*
		 * For inputs near 0, although 1 - p may be rounded to
		 * 1, it doesn't matter much because the magnitude of
		 * the result is so much larger.  For inputs near 1, we
		 * can compute 1 - p exactly, although the precision on
		 * the input is limited so we won't ever get more than
		 * about 700 for the output.
		 *
		 * If - has relative error d0, / has relative error d1,
		 * and log has relative error d2, then
		 *
		 *     (1 + d2) log((1 + d0) p/[(1 - p)(1 + d1)])
		 *     = (1 + d2) [log(p/(1 - p)) + log((1 + d0)/(1 + d1))]
		 *     = log(p/(1 - p)) + d2 log(p/(1 - p))
		 *       + (1 + d2) log((1 + d0)/(1 + d1))
		 *     = log(p/(1 - p))*[1 + d2 +
		 *         + (1 + d2) log((1 + d0)/(1 + d1))/log(p/(1 - p))]
		 *
		 * Since 0 <= p < logistic(-1) or logistic(+1) < p <=
		 * 1, we have |log(p/(1 - p))| > 1.  Hence this error
		 * is bounded by
		 *
		 *     |d2 + (1 + d2) log((1 + d0)/(1 + d1))/log(p/(1 - p))|
		 *     <= |d2| + |(1 + d2) log((1 + d0)/(1 + d1))
		 *			    / log(p/(1 - p))|
		 *     <= |d2| + |(1 + d2) log((1 + d0)/(1 + d1))|
		 *     <= |d2| + 4|(1 + d2) (d0 - d1)|, by Lemma 3,
		 *     <= |d2| + 4|d0 - d1 + d2 d0 - d1 d0|
		 *     <= |d2| + 4|d0| + 4|d1| + 4|d2 d0| + 4|d1 d0|
		 *     <= 9 eps + 8 eps^2.
		 */
		return log(p/(1 - p));
	}
}

/**
 * Compute the logit function, translated in input by 1/2: logithalf(p)
 * = logit(1/2 + p).  Defined on [-1/2, 1/2].  Inverse of logistichalf.
 *
 * Ill-conditioned near +/-1/2.  If |p0| > 1/2 - 1/(1 + e), it may be
 * better to compute 1/2 + p0 or -1/2 - p0 and to use logit instead.
 * This implementation gives relative error bounded by 34 eps.
 */
double
logithalf(double p0)
{

	if (fabs(p0) <= 0.5 - 1/(1 + exp(1))) {
		/*
		 * logit(1/2 + p0)
		 * = log((1/2 + p0)/(1 - (1/2 + p0)))
		 * = log((1/2 + p0)/(1/2 - p0))
		 * = log(1 + (1/2 + p0)/(1/2 - p0) - 1)
		 * = log(1 + (1/2 + p0 - (1/2 - p0))/(1/2 - p0))
		 * = log(1 + (1/2 + p0 - 1/2 + p0)/(1/2 - p0))
		 * = log(1 + 2 p0/(1/2 - p0))
		 *
		 * If the error of subtraction is d0, the error of
		 * division is d1, and the error of log1p is d2, then
		 * what we compute is
		 *
		 *	(1 + d2) log(1 + (1 + d1) 2 p0/[(1 + d0) (1/2 - p0)])
		 *	= (1 + d2) log(1 + (1 + d') 2 p0/(1/2 - p0))
		 *	= (1 + d2) (1 + d'') log(1 + 2 p0/(1/2 - p0))
		 *	= (1 + d2 + d'' + d2 d'') log(1 + 2 p0/(1/2 - p0)),
		 *
		 * where |d'| < 2|d0 - d1| <= 4 eps by Lemma 2, and
		 * |d''| < 8|d'| < 32 eps by Lemma 4 since
		 *
		 *	1/e <= 1 + 2*p0/(1/2 - p0) <= e
		 *
		 * when |p0| <= 1/2 - 1/(1 + e).  Hence the relative
		 * error is bounded by
		 *
		 *	|d2 + d'' + d2 d''|
		 *	<= |d2| + |d''| + |d2 d''|
		 *	<= |d1| + 32 |d0| + 32 |d1 d0|
		 *	<= 33 eps + 32 eps^2.
		 */
		return log1p(2*p0/(0.5 - p0));
	} else {
		/*
		 * We have a choice of computing logit(1/2 + p0) or
		 * -logit(1 - (1/2 + p0)) = -logit(1/2 - p0).  It
		 * doesn't matter which way we do this: either way,
		 * since 1/2 p0 <= 1/2 <= 2 p0, the sum and difference
		 * are computed exactly.  So let's do the one that
		 * skips the final negation.
		 *
		 * The result is
		 *
		 *	(1 + d1) log((1 + d0) (1/2 + p0)/[(1 + d2) (1/2 - p0)])
		 *	= (1 + d1) (1 + log((1 + d0)/(1 + d2))
		 *			/ log((1/2 + p0)/(1/2 - p0)))
		 *	  * log((1/2 + p0)/(1/2 - p0))
		 *	= (1 + d') log((1/2 + p0)/(1/2 - p0))
		 *	= (1 + d') logit(1/2 + p0)
		 *
		 * where
		 *
		 *	d' = d1 + log((1 + d0)/(1 + d2))/logit(1/2 + p0)
		 *	     + d1 log((1 + d0)/(1 + d2))/logit(1/2 + p0).
		 *
		 * For |p| > 1/2 - 1/(1 + e), logit(1/2 + p0) > 1.
		 * Provided |d0|, |d2| < 1/4, by Lemma 3 we have
		 *
		 *	|log((1 + d0)/(1 + d2))| <= 4|d0 - d2|.
		 *
		 * Hence the relative error is bounded by
		 *
		 *	|d'| <= |d1| + 4|d0 - d2| + 4|d1| |d0 - d2|
		 *	     <= |d1| + 4|d0| + 4|d2| + 4|d1 d0| + 4|d1 d2|
		 *	     <= 9 eps + 8 eps^2.
		 */
		return log((0.5 + p0)/(0.5 - p0));
	}
}

/**
 * Compute the log of the sum of the exps.  Caller should arrange the
 * array in descending order to minimize error because I don't want to
 * deal with using temporary space and the one caller in this file
 * arranges that anyway.
 *
 * Warning: This implementation does not handle infinite or NaN inputs
 * sensibly, because I don't need that here at the moment.  (NaN, or
 * -inf and +inf together, should yield NaN; +inf and finite should
 * yield +inf; otherwise all -inf should be ignored because exp(-inf) =
 * 0.)
 */
static double
logsumexp(double *A, size_t n)
{
	double maximum, sum;
	size_t i;

	if (n == 0)
		return log(0);

	maximum = A[0];
	for (i = 1; i < n; i++) {
		if (A[i] > maximum)
			maximum = A[i];
	}

	sum = 0;
	for (i = n; i --> 0;)
		sum += exp(A[i] - maximum);

	return log(sum) + maximum;
}

/**
 * Compute log(1 - e^x).  Defined only for negative x so that e^x < 1.
 * This is the complement of a probability in log space.
 */
double
log1mexp(double x)
{

	/*
	 * We want to compute log on [0, 1/2) but log1p on [1/2, +inf),
	 * so partition x at -log(2) = log(1/2).
	 */
	if (-log(2) < x)
		return log(-expm1(x));
	else
		return log1p(-exp(x));
}

/*
 * The following random_uniform_01 is tailored for IEEE 754 binary64
 * floating-point or smaller.  It can be adapted to larger
 * floating-point formats like i387 80-bit or IEEE 754 binary128, but
 * it may require sampling more bits.
 */
CTASSERT(FLT_RADIX == 2);
CTASSERT(-DBL_MIN_EXP <= 1021);
CTASSERT(DBL_MANT_DIG <= 53);

/**
 * Draw a floating-point number in [0, 1] with uniform distribution.
 *
 * Note that the probability of returning 0 is less than 2^-1074, so
 * callers need not check for it.  However, callers that cannot handle
 * rounding to 1 must deal with that, because it occurs with
 * probability 2^-54, which is small but nonnegligible.
 */
double
random_uniform_01(void)
{
	uint32_t z, x, hi, lo;
	double s;

	/*
	 * Draw an exponent, geometrically distributed, but give up if
	 * we get a run of more than 1088 zeros, which really means the
	 * system is broken.
	 */
	z = 0;
	while ((x = crypto_rand_uint32()) == 0) {
		if (z >= 1088)
			/* Your bit sampler is broken.  Go home.  */
			return 0;
		z += 32;
	}
	z += clz32(x);

	/*
	 * Pick 32-bit halves of an odd normalized significand.
	 * Picking it odd breaks ties in the subsequent rounding, which
	 * occur only with measure zero in the uniform distribution on
	 * [0, 1].
	 */
	hi = crypto_rand_uint32() | UINT32_C(0x80000000);
	lo = crypto_rand_uint32() | UINT32_C(0x00000001);

	/* Round to nearest scaled significand in [2^63, 2^64].  */
	s = hi*(double)4294967296 + lo;

	/* Rescale into [1/2, 1] and apply exponent in one swell foop.  */
	return s * ldexp(1, -(64 + z));
}

/*
 * Geometric(p) distribution, supported on {1, 2, 3, ...}.
 */

/**
 * Compute the probability mass function Geom(n; p) of the number of
 * trials before the first success when success has probability p.
 */
double
logpmf_geometric(unsigned n, double p)
{

	if (p == 1) {
		if (n == 1)
			return 0;
		else
			return -HUGE_VAL;
	}
	return (n - 1)*log1p(-p) + log(p);
}

/*
 * Logistic(mu, sigma) distribution, supported on (-\infty,+\infty)
 *
 * This is the uniform distribution on [0,1] mapped into log-odds
 * space, scaled by sigma and translated by mu.
 *
 * pdf(x) = e^{-(x - mu)/sigma} sigma (1 + e^{-(x - mu)/sigma})^2
 * cdf(x) = 1/(1 + e^{-(x - mu)/sigma}) = logistic((x - mu)/sigma)
 * sf(x) = 1 - cdf(x) = 1 - logistic((x - mu)/sigma = logistic(-(x - mu)/sigma)
 * icdf(p) = mu + sigma log p/(1 - p) = mu + sigma logit(p)
 * isf(p) = mu + sigma log (1 - p)/p = mu - sigma logit(p)
 */

/**
 * Compute the CDF of the Logistic(mu, sigma) distribution: the
 * logistic function.  Well-conditioned for negative inputs and small
 * positive inputs; ill-conditioned for large positive inputs.
 */
double
cdf_logistic(double x, double mu, double sigma)
{
	return logistic((x - mu)/sigma);
}

/**
 * Compute the SF of the Logistic(mu, sigma) distribution: the logistic
 * function reflected over the y axis.  Well-conditioned for positive
 * inputs and small negative inputs; ill-conditioned for large negative
 * inputs.
 */
double
sf_logistic(double x, double mu, double sigma)
{
	return logistic(-(x - mu)/sigma);
}

/**
 * Compute the inverse of the CDF of the Logistic(mu, sigma)
 * distribution: the logit function.  Well-conditioned near 0;
 * ill-conditioned near 1/2 and 1.
 */
double
icdf_logistic(double p, double mu, double sigma)
{
	return mu + sigma*logit(p);
}

/**
 * Compute the inverse of the SF of the Logistic(mu, sigma)
 * distribution: the -logit function.  Well-conditioned near 0;
 * ill-conditioned near 1/2 and 1.
 */
double
isf_logistic(double p, double mu, double sigma)
{
	return mu - sigma*logit(p);
}

/*
 * LogLogistic(alpha, beta) distribution, supported on (0, +\infty).
 *
 * This is the uniform distribution on [0,1] mapped into odds space,
 * scaled by positive alpha and shaped by positive beta.
 *
 * Equivalent to computing exp of a Logistic(log alpha, 1/beta) sample.
 * (Name arises because the pdf has LogLogistic(x; alpha, beta) =
 * Logistic(log x; log alpha, 1/beta) and mathematicians got their
 * covariance contravariant.)
 *
 * pdf(x) = (beta/alpha) (x/alpha)^{beta - 1}/(1 + (x/alpha)^beta)^2
 *        = (1/e^mu sigma) (x/e^mu)^{1/sigma - 1} /
 *              (1 + (x/e^mu)^{1/sigma})^2
 * cdf(x) = 1/(1 + (x/alpha)^-beta) = 1/(1 + (x/e^mu)^{-1/sigma})
 *        = 1/(1 + (e^{log x}/e^mu)^{-1/sigma})
 *        = 1/(1 + (e^{log x - mu})^{-1/sigma})
 *        = 1/(1 + e^{-(log x - mu)/sigma})
 *        = logistic((log x - mu)/sigma)
 *        = logistic((log x - log alpha)/(1/beta))
 * sf(x) = 1 - 1/(1 + (x/alpha)^-beta)
 *       = (x/alpha)^-beta/(1 + (x/alpha)^-beta)
 *       = 1/((x/alpha)^beta + 1)
 *       = 1/(1 + (x/alpha)^beta)
 * icdf(p) = alpha (p/(1 - p))^{1/beta}
 *         = alpha e^{logit(p)/beta}
 *         = e^{mu + sigma logit(p)}
 * isf(p) = alpha ((1 - p)/p)^{1/beta}
 *        = alpha e^{-logit(p)/beta}
 *        = e^{mu - sigma logit(p)}
 */

/**
 * Compute the CDF of the LogLogistic(alpha, beta) distribution.
 * Well-conditioned for all x and alpha, and the condition number
 *
 *	-beta/[1 + (x/alpha)^{-beta}]
 *
 * grows linearly with beta.
 *
 * Loosely, the relative error of this implementation is bounded by
 *
 *	4 eps + 2 eps^2 + O(beta eps),
 *
 * so don't bother trying this for beta anywhere near as large as
 * 1/eps, around which point it levels off at 1.
 */
double
cdf_log_logistic(double x, double alpha, double beta)
{
	/*
	 * Let d0 be the error of x/alpha; d1, of pow; d2, of +; and
	 * d3, of the final quotient.  The exponentiation gives
	 *
	 *	((1 + d0) x/alpha)^{-beta}
	 *	= (x/alpha)^{-beta} (1 + d0)^{-beta}
	 *	= (x/alpha)^{-beta} (1 + (1 + d0)^{-beta} - 1)
	 *	= (x/alpha)^{-beta} (1 + d')
	 *
	 * where d' = (1 + d0)^{-beta} - 1.  If y = (x/alpha)^{-beta},
	 * the denominator is
	 *
	 *	(1 + d2) (1 + (1 + d1) (1 + d') y)
	 *	= (1 + d2) (1 + y + (d1 + d' + d1 d') y)
	 *	= 1 + y + (1 + d2) (d1 + d' + d1 d') y
	 *	= (1 + y) (1 + (1 + d2) (d1 + d' + d1 d') y/(1 + y))
	 *	= (1 + y) (1 + d''),
	 *
	 * where d'' = (1 + d2) (d1 + d' + d1 d') y/(1 + y).  The
	 * final result is
	 *
	 *	(1 + d3) / [(1 + d2) (1 + d'') (1 + y)]
	 *	= (1 + d''') / (1 + y)
	 *
	 * for |d'''| <= 2|d3 - d''| by Lemma 2 as long as |d''| < 1/2
	 * (which may not be the case for very large beta).  This
	 * relative error is therefore bounded by
	 *
	 *	|d'''|
	 *	<= 2|d3 - d''|
	 *	<= 2|d3| + 2|(1 + d2) (d1 + d' + d1 d') y/(1 + y)|
	 *	<= 2|d3| + 2|(1 + d2) (d1 + d' + d1 d')|
	 *	 = 2|d3| + 2|d1 + d' + d1 d' + d2 d1 + d2 d' + d2 d1 d'|
	 *      <= 2|d3| + 2|d1| + 2|d'| + 2|d1 d'| + 2|d2 d1| + 2|d2 d'|
	 *         + 2|d2 d1 d'|
	 *      <= 4 eps + 2 eps^2 + (2 + 2 eps + 2 eps^2) |d'|.
	 *
	 * Roughly, |d'| = |(1 + d0)^{-beta} - 1| grows like beta eps,
	 * until it levels off at 1.
	 */
	return 1/(1 + pow(x/alpha, -beta));
}

/**
 * Compute the SF of the LogLogistic(alpha, beta) distribution.
 * Well-conditioned for all x and alpha, and the condition number
 *
 *	beta/[1 + (x/alpha)^beta]
 *
 * grows linearly with beta.
 *
 * Loosely, the relative error of this implementation is bounded by
 *
 *	4 eps + 2 eps^2 + O(beta eps)
 *
 * so don't bother trying this for beta anywhere near as large as
 * 1/eps, beyond which point it grows unbounded.
 */
double
sf_log_logistic(double x, double alpha, double beta)
{
	/*
	 * The error analysis here is essentially the same as in
	 * cdf_log_logistic, except that rather than levelling off at
	 * 1, |(1 + d0)^beta - 1| grows unbounded.
	 */
	return 1/(1 + pow(x/alpha, beta));
}

/**
 * Compute the inverse of the CDF of the LogLogistic(alpha, beta)
 * distribution.  Ill-conditioned for p near 1 and beta near 0 with
 * condition number 1/[beta (1 - p)].
 */
double
icdf_log_logistic(double p, double alpha, double beta)
{
	return alpha*pow(p/(1 - p), 1/beta);
}

/**
 * Compute the inverse of the SF of the LogLogistic(alpha, beta)
 * distribution.  Ill-conditioned for p near 1 and for large beta, with
 * condition number -1/[beta (1 - p)].
 */
double
isf_log_logistic(double p, double alpha, double beta)
{
	return alpha*pow((1 - p)/p, 1/beta);
}

/*
 * Weibull(lambda, k) distribution, supported on (0, +\infty).
 *
 * pdf(x) = (k/lambda) (x/lambda)^{k - 1} e^{-(x/lambda)^k}
 * cdf(x) = 1 - e^{-(x/lambda)^k}
 * icdf(p) = lambda * (-log (1 - p))^{1/k}
 * sf(x) = e^{-(x/lambda)^k}
 * isf(p) = lambda * (-log p)^{1/k}
 */

/**
 * Compute the CDF of the Weibull(lambda, k) distribution.
 * Well-conditioned for small x and k, and for large lambda --
 * condition number
 *
 *	-k (x/lambda)^k exp(-(x/lambda)^k)/[exp(-(x/lambda)^k) - 1]
 *
 * grows linearly with k, x^k, and lambda^{-k}.
 */
double
cdf_weibull(double x, double lambda, double k)
{
	return -expm1(-pow(x/lambda, k));
}

/**
 * Compute the SF of the Weibull(lambda, k) distribution.
 * Well-conditioned for small x and k, and for large lambda --
 * condition number
 *
 *	-k (x/lambda)^k
 *
 * grows linearly with k, x^k, and lambda^{-k}.
 */
double
sf_weibull(double x, double lambda, double k)
{
	return exp(-pow(x/lambda, k));
}

/**
 * Compute the inverse of the CDF of the Weibull(lambda, k)
 * distribution.  Ill-conditioned for p near 1, and for k near 0;
 * condition number is
 *
 *	(p/(1 - p))/(k log(1 - p)).
 */
double
icdf_weibull(double p, double lambda, double k)
{
	return lambda*pow(-log1p(-p), 1/k);
}

/**
 * Compute the inverse of the SF of the Weibull(lambda, k)
 * distribution.  Ill-conditioned for p near 0, and for k near 0;
 * condition number is
 *
 *	1/(k log(p)).
 */
double
isf_weibull(double p, double lambda, double k)
{
	return lambda*pow(-log(p), 1/k);
}

/*
 * GeneralizedPareto(mu, sigma, xi), supported on (mu, +\infty) for
 * nonnegative xi, or (mu, mu - sigma/xi) for negative xi.
 *
 * Samples:
 * = mu - sigma log U, if xi = 0;
 * = mu + sigma (U^{-xi} - 1)/xi = mu + sigma*expm1(-xi log U)/xi, if xi =/= 0,
 * where U is uniform on (0,1].
 * = mu + sigma (e^{xi X} - 1)/xi,
 * where X has standard exponential distribution.
 *
 * pdf(x) = sigma^{-1} (1 + xi (x - mu)/sigma)^{-(1 + 1/xi)}
 * cdf(x) = 1 - (1 + xi (x - mu)/sigma)^{-1/xi}
 *        = 1 - e^{-log(1 + xi (x - mu)/sigma)/xi}
 *        --> 1 - e^{-(x - mu)/sigma}  as  xi --> 0
 * sf(x) = (1 + xi (x - mu)/sigma)^{-1/xi}
 *       --> e^{-(x - mu)/sigma}  as  xi --> 0
 * icdf(p) = mu + sigma*(p^{-xi} - 1)/xi
 *         = mu + sigma*expm1(-xi log p)/xi
 *         --> mu + sigma*log p  as  xi --> 0
 * isf(p) = mu + sigma*((1 - p)^{xi} - 1)/xi
 *        = mu + sigma*expm1(-xi log1p(-p))/xi
 *        --> mu + sigma*log1p(-p)  as  xi --> 0
 */

/**
 * Compute the CDF of the GeneralizedPareto(mu, sigma, xi)
 * distribution.  Well-conditioned everywhere.  For standard
 * distribution (mu=0, sigma=1), condition number
 *
 *	(x/(1 + x xi)) / ((1 + x xi)^{1/xi} - 1)
 *
 * is bounded by 1, attained only at x = 0.
 */
double
cdf_genpareto(double x, double mu, double sigma, double xi)
{
	double x_0 = (x - mu)/sigma;

	/*
	 * log(1 + xi x_0)/xi
	 * = (-1/xi) \sum_{n=1}^\infty (-xi x_0)^n/n
	 * = (-1/xi) (-xi x_0 + \sum_{n=2}^\infty (-xi x_0)^n/n)
	 * = x_0 - (1/xi) \sum_{n=2}^\infty (-xi x_0)^n/n
	 * = x_0 - x_0 \sum_{n=2}^\infty (-xi x_0)^{n-1}/n
	 * = x_0 (1 - d),
	 *
	 * where d = \sum_{n=2}^\infty (-xi x_0)^{n-1}/n.  If |xi| <
	 * eps/4|x_0|, then
	 *
	 * |d| <= \sum_{n=2}^\infty (eps/4)^{n-1}/n
	 *     <= \sum_{n=2}^\infty (eps/4)^{n-1}
	 *      = \sum_{n=1}^\infty (eps/4)^n
	 *      = (eps/4) \sum_{n=0}^\infty (eps/4)^n
	 *      = (eps/4)/(1 - eps/4)
	 *      < eps/2
	 *
	 * for any 0 < eps < 2.  Thus, the relative error of x_0 from
	 * log(1 + xi x_0)/xi is bounded by eps.
	 */
	if (fabs(xi) < 1e-17/x_0)
		return -expm1(-x_0);
	else
		return -expm1(-log1p(xi*x_0)/xi);
}

/**
 * Compute the SF of the GeneralizedPareto(mu, sigma, xi) distribution.
 * For standard distribution (mu=0, sigma=1), ill-conditioned for xi
 * near 0; condition number
 *
 *	-x (1 + x xi)^{(-1 - xi)/xi}/(1 + x xi)^{-1/xi}
 *	= -x (1 + x xi)^{-1/xi - 1}/(1 + x xi)^{-1/xi}
 *	= -(x/(1 + x xi)) (1 + x xi)^{-1/xi}/(1 + x xi)^{-1/xi}
 *	= -x/(1 + x xi)
 *
 * is bounded by 1/xi.
 */
double
sf_genpareto(double x, double mu, double sigma, double xi)
{
	double x_0 = (x - mu)/sigma;

	if (fabs(xi) < 1e-17/x_0)
		return exp(-x_0);
	else
		return exp(-log1p(xi*x_0)/xi);
}

/**
 * Compute the inverse of the CDF of the GeneralizedPareto(mu, sigma,
 * xi) distribution.  Ill-conditioned for p near 1; condition number is
 *
 *	xi (p/(1 - p))/(1 - (1 - p)^xi)
 */
double
icdf_genpareto(double p, double mu, double sigma, double xi)
{
	/*
	 * To compute f(xi) = (U^{-xi} - 1)/xi = (e^{-xi log U} - 1)/xi
	 * for xi near zero (note f(xi) --> -log U as xi --> 0), write
	 * the absolutely convergent Taylor expansion
	 *
	 * f(xi) = (1/xi)*(-xi log U + \sum_{n=2}^\infty (-xi log U)^n/n!
	 *       = -log U + (1/xi)*\sum_{n=2}^\infty (-xi log U)^n/n!
	 *       = -log U + \sum_{n=2}^\infty xi^{n-1} (-log U)^n/n!
	 *       = -log U - log U \sum_{n=2}^\infty (-xi log U)^{n-1}/n!
	 *       = -log U (1 + \sum_{n=2}^\infty (-xi log U)^{n-1}/n!).
	 *
	 * Let d = \sum_{n=2}^\infty (-xi log U)^{n-1}/n!.  What do we
	 * lose if we discard it and use -log U as an approximation to
	 * f(xi)?  If |xi| < eps/-4log U, then
	 *
	 * |d| <= \sum_{n=2}^\infty |xi log U|^{n-1}/n!
	 *     <= \sum_{n=2}^\infty (eps/4)^{n-1}/n!
	 *     <= \sum_{n=1}^\infty (eps/4)^n
	 *      = (eps/4) \sum_{n=0}^\infty (eps/4)^n
	 *      = (eps/4)/(1 - eps/4)
	 *      < eps/2,
	 *
	 * for any 0 < eps < 2.  Hence, as long as |xi| < eps/-2log U,
	 * f(xi) = -log U (1 + d) for |d| <= eps/2.  |d| is the
	 * relative error of f(xi) from -log U; from this bound, the
	 * relative error of -log U from f(xi) is at most (eps/2)/(1 -
	 * eps/2) = eps/2 + (eps/2)^2 + (eps/2)^3 + ... < eps for 0 <
	 * eps < 1.  Since -log U < 1000 for all U in (0, 1] in
	 * binary64 floating-point, we can safely cut xi off at 1e-20 <
	 * eps/4000 and attain <1ulp error from series truncation.
	 */
	if (fabs(xi) <= 1e-20)
		return mu - sigma*log1p(-p);
	else
		return mu + sigma*expm1(-xi*log1p(-p))/xi;
}

/**
 * Compute the inverse of the SF of the GeneralizedPareto(mu, sigma,
 * xi) distribution.  Ill-conditioned for p near 1; conditon number is
 *
 *	-xi/(1 - p^{-xi})
 */
double
isf_genpareto(double p, double mu, double sigma, double xi)
{
	if (fabs(xi) <= 1e-20)
		return mu - sigma*log(p);
	else
		return mu + sigma*expm1(-xi*log(p))/xi;
}

/*
 * Deterministic samplers, parametrized by uniform integer and (0,1]
 * samples.  No guarantees are made about _which_ mapping from the
 * integer and (0,1] samples these use; all that is guaranteed is the
 * distribution of the outputs conditioned on a uniform distribution on
 * the inputs.  The automatic tests below double-check the particular
 * mappings we use.
 *
 * Beware: Unlike random_uniform_01(), these are not guaranteed to be
 * supported on all possible outputs.  See Ilya Mironov, `On the
 * Significance of the Least Significant Bits for Differential
 * Privacy', for an example of what can go wrong if you try to use
 * these to conceal information from an adversary but you expose the
 * specific full-precision floating-point values.
 *
 * Note: None of these samplers use rejection sampling; they are all
 * essentially inverse-CDF transforms with tweaks.  If you were to add,
 * say, a Gamma sampler with the Marsaglia-Tsang method, you would have
 * to parametrize it by a potentially infinite stream of uniform (and
 * perhaps normal) samples rather than a fixed number, which doesn't
 * make for quite as nice automatic testing as for these.
 */

/**
 * Deterministically sample from the interval [a, b], indexed by a
 * uniform random floating-point number p0 in (0, 1].
 *
 * Note that even if p0 is nonzero, the result may be equal to a, if
 * ulp(a)/2 is nonnegligible, e.g. if a = 1.  For maximum resolution,
 * arrange |a| <= |b|.
 */
double
sample_uniform_interval(double p0, double a, double b)
{

	/*
	 * XXX Prove that the distribution is, in fact, uniform on
	 * [a,b], particularly around p0 = 1, or at least has very
	 * small deviation from uniform, quantified appropriately
	 * (e.g., like in Monahan 1984, or by KL divergence).  It
	 * almost certainly does but it would be nice to quantify the
	 * error.
	 */
	if ((a <= 0 && 0 <= b) || (b <= 0 && 0 <= a)) {
		/*
		 * When ab < 0, (1 - t) a + t b is monotonic, since for
		 * a <= b it is a sum of nondecreasing functions of t,
		 * and for b <= a, of nonincreasing functions of t.
		 * Further, clearly at 0 and 1 it attains a and b,
		 * respectively.  Hence it is bounded within [a, b].
		 */
		return (1 - p0)*a + p0*b;
	} else {
		/*
		 * a + (b - a) t is monotonic -- it is obviously a
		 * nondecreasing function of t for a <= b.  Further, it
		 * attains a at 0, and while it may overshoot b at 1,
		 * we have a
		 *
		 * Theorem.  If 0 <= t < 1, then the floating-point
		 * evaluation of a + (b - a) t is bounded in [a, b].
		 *
		 * Lemma 1.  If 0 <= t < 1 is a floating-point number,
		 * then for any normal floating-point number x except
		 * the smallest in magnitude, |round(x*t)| < |x|.
		 *
		 * Proof.  WLOG, assume x >= 0.  Since the rounding
		 * function and t |---> x*t are nondecreasing, their
		 * composition t |---> round(x*t) is also
		 * nondecreasing, so it suffices to consider the
		 * largest floating-point number below 1, in particular
		 * t = 1 - ulp(1)/2.
		 *
		 * Case I: If x is a power of two, then the next
		 * floating-point number below x is x - ulp(x)/2 = x -
		 * x*ulp(1)/2 = x*(1 - ulp(1)/2) = x*t, so, since x*t
		 * is a floating-point number, multiplication is exact,
		 * and thus round(x*t) = x*t < x.
		 *
		 * Case II: If x is not a power of two, then the
		 * greatest lower bound of real numbers rounded to x is
		 * x - ulp(x)/2 = x - ulp(T(x))/2 = x - T(x)*ulp(1)/2,
		 * where T(X) is the largest power of two below x.
		 * Anything below this bound is rounded to a
		 * floating-point number smaller than x, and x*t = x*(1
		 * - ulp(1)/2) = x - x*ulp(1)/2 < x - T(x)*ulp(1)/2
		 * since T(x) < x, so round(x*t) < x*t < x.  QED.
		 *
		 * Lemma 2.  If x and y are subnormal, then round(x +
		 * y) = x + y.
		 *
		 * Proof.  It is a matter of adding the significands,
		 * since if we treat subnormals as having an implicit
		 * zero bit before the `binary' point, their exponents
		 * are all the same.  There is at most one carry/borrow
		 * bit, which can always be acommodated either in a
		 * subnormal, or, at largest, in the implicit one bit
		 * of a normal.
		 *
		 * Lemma 3.  Let x and y be floating-point numbers.  If
		 * round(x - y) is subnormal or zero, then it is equal
		 * to x - y.
		 *
		 * Proof.  Case I (equal): round(x - y) = 0 iff x = y;
		 * hence if round(x - y) = 0, then round(x - y) = 0 = x
		 * - y.
		 *
		 * Case II (subnormal/subnormal): If x and y are both
		 * subnormal, this follows directly from Lemma 2.
		 *
		 * Case IIIa (normal/subnormal): If x is normal and y
		 * is subnormal, then x and y must share sign, or else
		 * x - y would be larger than x and thus rounded to
		 * normal.  If s is the smallest normal positive
		 * floating-point number, |x| < 2s since by
		 * construction 2s - |y| is normal for all subnormal y.
		 * This means that x and y must have the same exponent,
		 * so the difference is the difference of significands,
		 * which is exact.
		 *
		 * Case IIIb (subnormal/normal): Same as case IIIa for
		 * -(y - x).
		 *
		 * Case IV (normal/normal): If x and y are both normal,
		 * then they must share sign, or else x - y would be
		 * larger than x and thus rounded to normal.  Note that
		 * |y| < 2|x|, for if |y| >= 2|x|, then |x| - |y| <=
		 * -|x| but -|x| is normal like x.  Also, |x|/2 < |y|:
		 * if |x|/2 is subnormal, it must hold because y is
		 * normal; if |x|/2 is normal, then |x|/2 >= s, so
		 * since |x| - |y| < s,
		 *
		 *	|x|/2 = |x| - |x|/2 <= |x| - s <= |y|;
		 *
		 * that is, |x|/2 < |y| < 2|x|, so by the Sterbenz
		 * lemma, round(x - y) = x - y.  QED.
		 *
		 * Proof of theorem.  WLOG, assume 0 <= a <= b.  Since
		 * round(a + round(round(b - a)*t) is nondecreasing in
		 * t and attains a at 0, the lower end of the bound is
		 * trivial; we must show the upper end of the bound
		 * strictly.  It suffices to show this for the largest
		 * floating-point number below 1, namely 1 - ulp(1)/2.
		 *
		 * Case I: round(b - a) is normal.  Then it is at most
		 * the smallest floating-point number above b - a.  By
		 * Lemma 1, round(round(b - a)*t) < round(b - a).
		 * Since the inequality is strict, and since
		 * round(round(b - a)*t) is a floating-point number
		 * below round(b - a), and since there are no
		 * floating-point numbers between b - a and round(b -
		 * a), we must have round(round(b - a)*t) < b - a.
		 * Then since y |---> round(a + y) is nondecreasing, we
		 * must have
		 *
		 *	round(a + round(round(b - a)*t))
		 *	<= round(a + (b - a))
		 *	 = round(b) = b.
		 *
		 * Case II: round(b - a) is subnormal.  In this case,
		 * Lemma 1 falls apart -- we are not guaranteed the
		 * strict inequality.  However, by Lemma 3, the
		 * difference is exact: round(b - a) = b - a.  Thus,
		 *
		 *	round(a + round(round(b - a)*t))
		 *	<= round(a + round((b - a)*t))
		 *	<= round(a + (b - a))
		 *	 = round(b)
		 *	 = b,
		 *
		 * QED.
		 */
		if (p0 == 1)
			return b;
		return a + (b - a)*p0;
	}
}

/**
 * Deterministically sample from the standard logistic distribution,
 * indexed by a uniform random 32-bit integer s and uniform random
 * floating-point numbers t and p0 in (0, 1].
 */
double
sample_logistic(uint32_t s, double t, double p0)
{
	double sign = (s & 1) ? -1 : +1;
	double r;

	/*
	 * We carve up the interval (0, 1) into subregions to compute
	 * the inverse CDF precisely:
	 *
	 * A = (0, 1/(1 + e)] ---> (-\infty, -1]
	 * B = [1/(1 + e), 1/2] ---> [-1, 0]
	 * C = [1/2, 1 - 1/(1 + e)] ---> [0, 1]
	 * D = [1 - 1/(1 + e), 1) ---> [1, +\infty)
	 *
	 * Cases D and C are mirror images of cases A and B,
	 * respectively, so we choose between them by the sign chosen
	 * by a fair coin toss.  We choose between cases A and B by a
	 * coin toss weighted by
	 *
	 *	2/(1 + e) = 1 - [1/2 - 1/(1 + e)]/(1/2):
	 *
	 * if it comes up heads, scale p0 into a uniform (0, 1/(1 + e)]
	 * sample p; if it comes up tails, scale p0 into a uniform (0,
	 * 1/2 - 1/(1 + e)] sample and compute the inverse CDF of p =
	 * 1/2 - p0.
	 */
	if (t <= 2/(1 + exp(1))) {
		/* p uniform in (0, 1/(1 + e)], represented by p.  */
		p0 /= 1 + exp(1);
		r = logit(p0);
	} else {
		/*
		 * p uniform in [1/(1 + e), 1/2), actually represented
		 * by p0 = 1/2 - p uniform in (0, 1/2 - 1/(1 + e)], so
		 * that p = 1/2 - p.
		 */
		p0 *= 0.5 - 1/(1 + exp(1));
		r = logithalf(p0);
	}

	/*
	 * We have chosen from the negative half of the standard
	 * logistic distribution, which is symmetric with the positive
	 * half.  Now use the sign to choose uniformly between them.
	 */
	return sign*r;
}

/**
 * Deterministically sample from the logistic distribution scaled by
 * sigma and translated by mu.
 */
double
sample_logistic_locscale(uint32_t s, double t, double p0, double mu,
    double sigma)
{

	return mu + sigma*sample_logistic(s, t, p0);
}

/**
 * Deterministically sample from the standard log-logistic
 * distribution, indexed by a uniform random 32-bit integer s and a
 * uniform random floating-point number p0 in (0, 1].
 */
double
sample_log_logistic(uint32_t s, double p0)
{

	/*
	 * Carve up the interval (0, 1) into (0, 1/2] and [1/2, 1); the
	 * condition numbers of the icdf and the isf coincide at 1/2.
	 */
	p0 *= 0.5;
	if ((s & 1) == 0) {
		/* p = p0 in (0, 1/2] */
		return p0/(1 - p0);
	} else {
		/* p = 1 - p0 in [1/2, 1) */
		return (1 - p0)/p0;
	}
}

/**
 * Deterministically sample from the log-logistic distribution with
 * scale alpha and shape beta.
 */
double
sample_log_logistic_scaleshape(uint32_t s, double p0, double alpha,
    double beta)
{
	double x = sample_log_logistic(s, p0);

	return alpha*pow(x, 1/beta);
}

/**
 * Deterministically sample from the standard exponential distribution,
 * indexed by a uniform random 32-bit integer s and a uniform random
 * floating-point number p0 in (0, 1].
 */
double
sample_exponential(uint32_t s, double p0)
{
	/*
	 * We would like to evaluate log(p) for p near 0, and log1p(-p)
	 * for p near 1.  Simply carve the interval into (0, 1/2] and
	 * [1/2, 1) by a fair coin toss.
	 */
	p0 *= 0.5;
	if ((s & 1) == 0)
		/* p = p0 in (0, 1/2] */
		return -log(p0);
	else
		/* p = 1 - p0 in [1/2, 1) */
		return -log1p(-p0);
}

/**
 * Deterministically sample from the geometric distribution with
 * per-trial success probability p.
 *
 * XXX Quantify the error (KL divergence?) of this
 * ceiling-of-exponential sampler from a true geometric distribution,
 * which we could get by rejection sampling.  Relevant papers:
 *
 *	John F. Monahan, `Accuracy in Random Number Generation',
 *	Mathematics of Computation 45(172), October 1984, pp. 559--568.
 *	https://pdfs.semanticscholar.org/aca6/74b96da1df77b2224e8cfc5dd6d61a471632.pdf
 *
 *	Karl Bringmann and Tobias Friedrich, `Exact and Efficient
 *	Generation of Geometric Random Variates and Random Graphs', in
 *	Proceedings of the 40th International Colloaquium on Automata,
 *	Languages, and Programming -- ICALP 2013, Springer LNCS 7965,
 *	pp.267--278.
 *	https://doi.org/10.1007/978-3-642-39206-1_23
 *	https://people.mpi-inf.mpg.de/~kbringma/paper/2013ICALP-1.pdf
 */
unsigned
sample_geometric(uint32_t s, double p0, double p)
{
	double x = sample_exponential(s, p0);

	if (p == 1)
		return 1;
	return ceil(-x/log1p(-p));
}

/**
 * Deterministically sample from a Weibull distribution with scale
 * lambda and shape k -- just an exponential with a shape parameter in
 * addition to a scale parameter.  (Yes, lambda really is the scale,
 * _not_ the rate.)
 */
double
sample_weibull(uint32_t s, double p0, double lambda, double k)
{

	return lambda*pow(sample_exponential(s, p0), 1/k);
}

/**
 * Deterministically sample from the generalized Pareto distribution
 * with shape xi, indexed by a uniform random 32-bit integer s and a
 * uniform random floating-point number p0 in (0, 1].
 */
double
sample_genpareto(uint32_t s, double p0, double xi)
{
	double x = sample_exponential(s, p0);

	/*
	 * Write f(xi) = (e^{xi x} - 1)/xi for xi near zero as the
	 * absolutely convergent Taylor series
	 *
	 * f(x) = (1/xi) (xi x + \sum_{n=2}^\infty (xi x)^n/n!)
	 *      = x + (1/xi) \sum_{n=2}^\inty (xi x)^n/n!
	 *      = x + \sum_{n=2}^\infty xi^{n-1} x^n/n!
	 *      = x + x \sum_{n=2}^\infty (xi x)^{n-1}/n!
	 *      = x (1 + \sum_{n=2}^\infty (xi x)^{n-1}/n!).
	 *
	 * d = \sum_{n=2}^\infty (xi x)^{n-1}/n! is the relative error
	 * of f(x) from x.  If |xi| < eps/4x, then
	 *
	 * |d| <= \sum_{n=2}^\infty |xi x|^{n-1}/n!
	 *     <= \sum_{n=2}^\infty (eps/4)^{n-1}/n!
	 *     <= \sum_{n=1}^\infty (eps/4)
	 *      = (eps/4) \sum_{n=0}^\infty (eps/4)^n
	 *      = (eps/4)/(1 - eps/4)
	 *      < eps/2,
	 *
	 * for any 0 < eps < 2.  Hence, as long as |xi| < eps/2x, f(xi)
	 * = x (1 + d) for |d| <= eps/2, so x = f(xi) (1 + d') for |d'|
	 * <= eps.  What bound should we use for x?
	 *
	 * - If x is exponentially distributed, x > 200 with
	 *   probability below e^{-200} << 2^{-256}, i.e. never.
	 *
	 * - If x is computed by -log(U) for U in (0, 1], x is
	 *   guaranteed to be below 1000 in IEEE 754 binary64
	 *   floating-point.
	 *
	 * We can safely cut xi off at 1e-20 < eps/4000 and attain an
	 * error bounded by 0.5 ulp for this expression.
	 */
	return (fabs(xi) < 1e-20 ? x : expm1(xi*x)/xi);
}

/**
 * Deterministically sample from a generalized Pareto distribution with
 * shape xi, scaled by sigma and translated by mu.
 */
double
sample_genpareto_locscale(uint32_t s, double p0, double mu, double sigma,
    double xi)
{

	return mu + sigma*sample_genpareto(s, p0, xi);
}

/*
 * Tests of numerical errors in computing logit, logistic, and the
 * various cdfs, sfs, icdfs, and isfs.
 */

#define arraycount(A) (sizeof(A)/sizeof(A[0]))

static double
relerr(double expected, double actual)
{
	if (expected == 0 || isinf(expected))
		return (actual == expected ? 0 : 1);
	else
		return fabs((expected - actual)/expected);
}

/* Caller must arrange to have i and relerr_bound in scope.  */
#define CHECK_RELERR(expected, actual) do {				      \
	double check_expected = (expected);				      \
	double check_actual = (actual);					      \
	double check_relerr = relerr(expected, actual);			      \
	if (!(relerr(check_expected, check_actual) <= relerr_bound)) {	      \
		printf("%s:%d: case %zu: relerr(%s=%.17e, %s=%.17e)"	      \
		    " = %.17e > %.17e\n",				      \
		    __func__, __LINE__, i,				      \
		    #expected, check_expected,				      \
		    #actual, check_actual,				      \
		    check_relerr, relerr_bound);			      \
		ok = false;						      \
	}								      \
} while (0)

/* Caller must arrange to have i in scope.  */
#define CHECK_LE(a, b) do {						      \
	double check_a = (a);						      \
	double check_b = (b);						      \
	if (check_a > check_b) {					      \
		printf("%s:%d: case %zu: %s=%.17e > %s=%.17e\n",	      \
		    __func__, __LINE__, i,				      \
		    #a, check_a, #b, check_b);				      \
		ok = false;						      \
	}								      \
} while (0)

/**
 * Test the logit and logistic functions.  Confirm that they agree with
 * the cdf, sf, icdf, and isf of the standard Logistic distribution.
 * Confirm that the sampler for the standard logistic distribution maps
 * [0, 1] into the right subinterval for the inverse transform, for
 * this implementation.
 */
static bool
test_logit_logistic(void)
{
	static const struct {
		double x;	/* x = logit(p) */
		double p;	/* p = logistic(x) */
		double phalf;	/* p - 1/2 = logistic(x) - 1/2 */
	} cases[] = {
		{ -HUGE_VAL, 0, -0.5 },
		{ -1000, 0, -0.5 },
		{ -710, 4.47628622567513e-309, -0.5 },
		{ -708, 3.307553003638408e-308, -0.5 },
		{ -2, .11920292202211755, -.3807970779778824 },
		{ -1.0000001, .2689414017088022, -.23105859829119776 },
		{ -1, .2689414213699951, -.23105857863000487 },
		{ -0.9999999, .26894144103118883, -.2310585589688111 },
		{ -4.000000000537333e-5, .49999, -1.0000000000010001e-5 },
		{ -4.000000000533334e-5, .49999, -.00001 },
		{ -4.000000108916878e-9, .499999999, -1.0000000272292198e-9 },
		{ -4e-9, .499999999, -1e-9 },
		{ -4e-16, .5, -1e-16 },
		{ -4e-300, .5, -1e-300 },
		{ 0, .5, 0 },
		{ 4e-300, .5, 1e-300 },
		{ 4e-16, .5, 1e-16 },
		{ 3.999999886872274e-9, .500000001, 9.999999717180685e-10 },
		{ 4e-9, .500000001, 1e-9 },
		{ 4.0000000005333336e-5, .50001, .00001 },
		{ 8.000042667076272e-3, .502, .002 },
		{ 0.9999999, .7310585589688111, .2310585589688111 },
		{ 1, .7310585786300049, .23105857863000487 },
		{ 1.0000001, .7310585982911977, .23105859829119774 },
		{ 2, .8807970779778823, .3807970779778824 },
		{ 708, 1, .5 },
		{ 710, 1, .5 },
		{ 1000, 1, .5 },
		{ HUGE_VAL, 1, .5 },
	};
	double relerr_bound = 3e-15; /* >10eps */
	size_t i;
	bool ok = true;

	for (i = 0; i < arraycount(cases); i++) {
		double x = cases[i].x;
		double p = cases[i].p;
		double phalf = cases[i].phalf;

		/*
		 * cdf is logistic, icdf is logit, and symmetry for
		 * sf/isf.
		 */
		CHECK_RELERR(logistic(x), cdf_logistic(x, 0, 1));
		CHECK_RELERR(logistic(-x), sf_logistic(x, 0, 1));
		CHECK_RELERR(logit(p), icdf_logistic(p, 0, 1));
		CHECK_RELERR(-logit(p), isf_logistic(p, 0, 1));

		CHECK_RELERR(cdf_logistic(x, 0, 1), cdf_logistic(x*2, 0, 2));
		CHECK_RELERR(sf_logistic(x, 0, 1), sf_logistic(x*2, 0, 2));
		CHECK_RELERR(icdf_logistic(p, 0, 1), icdf_logistic(p, 0, 2)/2);
		CHECK_RELERR(isf_logistic(p, 0, 1), isf_logistic(p, 0, 2)/2);

		CHECK_RELERR(cdf_logistic(x, 0, 1), cdf_logistic(x/2, 0, .5));
		CHECK_RELERR(sf_logistic(x, 0, 1), sf_logistic(x/2, 0, .5));
		CHECK_RELERR(icdf_logistic(p, 0, 1), icdf_logistic(p, 0,.5)*2);
		CHECK_RELERR(isf_logistic(p, 0, 1), isf_logistic(p, 0, .5)*2);

		/*
		 * For p near 0 and p near 1/2, the arithmetic of
		 * translating by 1 loses precision.
		 */
		if (fabs(p) > DBL_EPSILON && fabs(p) < 0.4) {
			CHECK_RELERR(cdf_logistic(x, 0, 1),
			    cdf_logistic(x*2 + 1, 1, 2));
			CHECK_RELERR(sf_logistic(x, 0, 1),
			    sf_logistic(x*2 + 1, 1, 2));
			CHECK_RELERR(icdf_logistic(p, 0, 1),
			    (icdf_logistic(p, 1, 2) - 1)/2);
			CHECK_RELERR(isf_logistic(p, 0, 1),
			    (isf_logistic(p, 1, 2) - 1)/2);
		}

		CHECK_RELERR(p, logistic(x));
		CHECK_RELERR(phalf, logistichalf(x));
		if ((0 < p && p <= 1/(1 + exp(1))
			&& 0.5 + 1/(1 + exp(1)) <= p && p < 1)
		    || isinf(x)) {
			if (p <= 1/(1 + exp(1)) || 0.5 + 1/(1 + exp(1)) <= p)
				CHECK_RELERR(x, logit(p));
			CHECK_RELERR(x, logithalf(phalf));
		}
		CHECK_RELERR(-phalf, logistichalf(-x));
		if (fabs(phalf) < 0.5)
			CHECK_RELERR(-x, logithalf(-phalf));
		if (p < 1) {
			CHECK_RELERR(1 - p, logistic(-x));
			if (p > .75)
				CHECK_RELERR(-x, logit(1 - p));
		} else {
			CHECK_LE(logistic(-x), 1e-300);
		}
	}

	for (i = 0; i <= 100; i++) {
		double p0 = (double)i/100;

		CHECK_RELERR(logit(p0/(1 + M_E)), sample_logistic(0, 0, p0));
		CHECK_RELERR(-logit(p0/(1 + M_E)), sample_logistic(1, 0, p0));
		CHECK_RELERR(logithalf(p0*(0.5 - 1/(1 + M_E))),
		    sample_logistic(0, 1, p0));
		CHECK_RELERR(-logithalf(p0*(0.5 - 1/(1 + M_E))),
		    sample_logistic(1, 1, p0));
	}

	if (ok)
		printf("pass logit/logistic / logistic cdf/sf\n");
	else
		printf("fail logit/logistic / logistic cdf/sf\n");
	return ok;
}

/**
 * Test the cdf, sf, icdf, and isf of the LogLogistic distribution.
 */
static bool
test_log_logistic(void)
{
	static const struct {
		double x;
		double p;
		double np;
	} cases[] = {
		{ 0, 0, 1 },
		{ 1e-300, 1e-300, 1 },
		{ 1e-17, 1e-17, 1 },
		{ 1e-15, 1e-15, .999999999999999 },
		{ .1, .09090909090909091, .90909090909090909 },
		{ .25, .2, .8 },
		{ .5, .33333333333333333, .66666666666666667 },
		{ .75, .42857142857142855, .5714285714285714 },
		{ .9999, .49997499874993756, .5000250012500626 },
		{ .99999999, .49999999749999996, .5000000025 },
		{ .999999999999999, .49999999999999994, .5000000000000002 },
		{ 1, .5, .5 },
	};
	double relerr_bound = 3e-15;
	size_t i;
	bool ok = true;

	for (i = 0; i < arraycount(cases); i++) {
		double x = cases[i].x;
		double p = cases[i].p;
		double np = cases[i].np;

		CHECK_RELERR(p, cdf_log_logistic(x, 1, 1));
		CHECK_RELERR(p, cdf_log_logistic(x/2, .5, 1));
		CHECK_RELERR(p, cdf_log_logistic(x*2, 2, 1));
		CHECK_RELERR(p, cdf_log_logistic(sqrt(x), 1, 2));
		CHECK_RELERR(p, cdf_log_logistic(sqrt(x)/2, .5, 2));
		CHECK_RELERR(p, cdf_log_logistic(sqrt(x)*2, 2, 2));
		if (2*sqrt(DBL_MIN) < x) {
			CHECK_RELERR(p, cdf_log_logistic(x*x, 1, .5));
			CHECK_RELERR(p, cdf_log_logistic(x*x/2, .5, .5));
			CHECK_RELERR(p, cdf_log_logistic(x*x*2, 2, .5));
		}

		CHECK_RELERR(np, sf_log_logistic(x, 1, 1));
		CHECK_RELERR(np, sf_log_logistic(x/2, .5, 1));
		CHECK_RELERR(np, sf_log_logistic(x*2, 2, 1));
		CHECK_RELERR(np, sf_log_logistic(sqrt(x), 1, 2));
		CHECK_RELERR(np, sf_log_logistic(sqrt(x)/2, .5, 2));
		CHECK_RELERR(np, sf_log_logistic(sqrt(x)*2, 2, 2));
		if (2*sqrt(DBL_MIN) < x) {
			CHECK_RELERR(np, sf_log_logistic(x*x, 1, .5));
			CHECK_RELERR(np, sf_log_logistic(x*x/2, .5, .5));
			CHECK_RELERR(np, sf_log_logistic(x*x*2, 2, .5));
		}

		CHECK_RELERR(np, cdf_log_logistic(1/x, 1, 1));
		CHECK_RELERR(np, cdf_log_logistic(1/(2*x), .5, 1));
		CHECK_RELERR(np, cdf_log_logistic(2/x, 2, 1));
		CHECK_RELERR(np, cdf_log_logistic(1/sqrt(x), 1, 2));
		CHECK_RELERR(np, cdf_log_logistic(1/(2*sqrt(x)), .5, 2));
		CHECK_RELERR(np, cdf_log_logistic(2/sqrt(x), 2, 2));
		if (2*sqrt(DBL_MIN) < x && x < 1/(2*sqrt(DBL_MIN))) {
			CHECK_RELERR(np, cdf_log_logistic(1/(x*x), 1, .5));
			CHECK_RELERR(np, cdf_log_logistic(1/(2*x*x), .5, .5));
			CHECK_RELERR(np, cdf_log_logistic(2/(x*x), 2, .5));
		}

		CHECK_RELERR(p, sf_log_logistic(1/x, 1, 1));
		CHECK_RELERR(p, sf_log_logistic(1/(2*x), .5, 1));
		CHECK_RELERR(p, sf_log_logistic(2/x, 2, 1));
		CHECK_RELERR(p, sf_log_logistic(1/sqrt(x), 1, 2));
		CHECK_RELERR(p, sf_log_logistic(1/(2*sqrt(x)), .5, 2));
		CHECK_RELERR(p, sf_log_logistic(2/sqrt(x), 2, 2));
		if (2*sqrt(DBL_MIN) < x && x < 1/(2*sqrt(DBL_MIN))) {
			CHECK_RELERR(p, sf_log_logistic(1/(x*x), 1, .5));
			CHECK_RELERR(p, sf_log_logistic(1/(2*x*x), .5, .5));
			CHECK_RELERR(p, sf_log_logistic(2/(x*x), 2, .5));
		}

		CHECK_RELERR(x, icdf_log_logistic(p, 1, 1));
		CHECK_RELERR(x/2, icdf_log_logistic(p, .5, 1));
		CHECK_RELERR(x*2, icdf_log_logistic(p, 2, 1));
		CHECK_RELERR(x, icdf_log_logistic(p, 1, 1));
		CHECK_RELERR(sqrt(x)/2, icdf_log_logistic(p, .5, 2));
		CHECK_RELERR(sqrt(x)*2, icdf_log_logistic(p, 2, 2));
		CHECK_RELERR(sqrt(x), icdf_log_logistic(p, 1, 2));
		CHECK_RELERR(x*x/2, icdf_log_logistic(p, .5, .5));
		CHECK_RELERR(x*x*2, icdf_log_logistic(p, 2, .5));

		if (np < .9) {
			CHECK_RELERR(x, isf_log_logistic(np, 1, 1));
			CHECK_RELERR(x/2, isf_log_logistic(np, .5, 1));
			CHECK_RELERR(x*2, isf_log_logistic(np, 2, 1));
			CHECK_RELERR(sqrt(x), isf_log_logistic(np, 1, 2));
			CHECK_RELERR(sqrt(x)/2, isf_log_logistic(np, .5, 2));
			CHECK_RELERR(sqrt(x)*2, isf_log_logistic(np, 2, 2));
			CHECK_RELERR(x*x, isf_log_logistic(np, 1, .5));
			CHECK_RELERR(x*x/2, isf_log_logistic(np, .5, .5));
			CHECK_RELERR(x*x*2, isf_log_logistic(np, 2, .5));

			CHECK_RELERR(1/x, icdf_log_logistic(np, 1, 1));
			CHECK_RELERR(1/(2*x), icdf_log_logistic(np, .5, 1));
			CHECK_RELERR(2/x, icdf_log_logistic(np, 2, 1));
			CHECK_RELERR(1/sqrt(x), icdf_log_logistic(np, 1, 2));
			CHECK_RELERR(1/(2*sqrt(x)),
			    icdf_log_logistic(np, .5, 2));
			CHECK_RELERR(2/sqrt(x), icdf_log_logistic(np, 2, 2));
			CHECK_RELERR(1/(x*x), icdf_log_logistic(np, 1, .5));
			CHECK_RELERR(1/(2*x*x), icdf_log_logistic(np, .5, .5));
			CHECK_RELERR(2/(x*x), icdf_log_logistic(np, 2, .5));
		}

		CHECK_RELERR(1/x, isf_log_logistic(p, 1, 1));
		CHECK_RELERR(1/(2*x), isf_log_logistic(p, .5, 1));
		CHECK_RELERR(2/x, isf_log_logistic(p, 2, 1));
		CHECK_RELERR(1/sqrt(x), isf_log_logistic(p, 1, 2));
		CHECK_RELERR(1/(2*sqrt(x)), isf_log_logistic(p, .5, 2));
		CHECK_RELERR(2/sqrt(x), isf_log_logistic(p, 2, 2));
		CHECK_RELERR(1/(x*x), isf_log_logistic(p, 1, .5));
		CHECK_RELERR(1/(2*x*x), isf_log_logistic(p, .5, .5));
		CHECK_RELERR(2/(x*x), isf_log_logistic(p, 2, .5));
	}

	for (i = 0; i <= 100; i++) {
		double p0 = (double)i/100;

		CHECK_RELERR(0.5*p0/(1 - 0.5*p0), sample_log_logistic(0, p0));
		CHECK_RELERR((1 - 0.5*p0)/(0.5*p0),
		    sample_log_logistic(1, p0));
	}

	if (ok)
		printf("pass log logistic cdf/sf\n");
	else
		printf("fail log logistic cdf/sf\n");
	return ok;
}

/**
 * Test the cdf, sf, icdf, isf of the Weibull distribution.
 */
static bool
test_weibull(void)
{
	static const struct {
		double x;
		double p;
		double np;
	} cases[] = {
		{ 0, 0, 1 },
		{ 1e-300, 1e-300, 1 },
		{ 1e-17, 1e-17, 1 },
		{ .1, .09516258196404043, .9048374180359595 },
		{ .5, .3934693402873666, .6065306597126334 },
		{ .6931471805599453, .5, .5 },
		{ 1, .6321205588285577, .36787944117144233 },
		{ 10, .9999546000702375, 4.5399929762484854e-5 },
		{ 36, .9999999999999998, 2.319522830243569e-16 },
		{ 37, .9999999999999999, 8.533047625744066e-17 },
		{ 38, 1, 3.1391327920480296e-17 },
		{ 100, 1, 3.720075976020836e-44 },
		{ 708, 1, 3.307553003638408e-308 },
		{ 710, 1, 4.47628622567513e-309 },
		{ 1000, 1, 0 },
		{ HUGE_VAL, 1, 0 },
	};
	double relerr_bound = 3e-15;
	size_t i;
	bool ok = true;

	for (i = 0; i < arraycount(cases); i++) {
		double x = cases[i].x;
		double p = cases[i].p;
		double np = cases[i].np;

		CHECK_RELERR(p, cdf_weibull(x, 1, 1));
		CHECK_RELERR(p, cdf_weibull(x/2, .5, 1));
		CHECK_RELERR(p, cdf_weibull(x*2, 2, 1));
		/* For 0 < x < sqrt(DBL_MIN), x^2 loses lots of bits.  */
		if (x == 0 || sqrt(DBL_MIN) <= x) {
			CHECK_RELERR(p, cdf_weibull(x*x, 1, .5));
			CHECK_RELERR(p, cdf_weibull(x*x/2, .5, .5));
			CHECK_RELERR(p, cdf_weibull(x*x*2, 2, .5));
		}
		CHECK_RELERR(p, cdf_weibull(sqrt(x), 1, 2));
		CHECK_RELERR(p, cdf_weibull(sqrt(x)/2, .5, 2));
		CHECK_RELERR(p, cdf_weibull(sqrt(x)*2, 2, 2));
		CHECK_RELERR(np, sf_weibull(x, 1, 1));
		CHECK_RELERR(np, sf_weibull(x/2, .5, 1));
		CHECK_RELERR(np, sf_weibull(x*2, 2, 1));
		CHECK_RELERR(np, sf_weibull(x*x, 1, .5));
		CHECK_RELERR(np, sf_weibull(x*x/2, .5, .5));
		CHECK_RELERR(np, sf_weibull(x*x*2, 2, .5));
		if (x >= 10) {
			/*
			 * exp amplifies the error of sqrt(x)^2
			 * proportionally to exp(x); for large inputs
			 * this is significant.
			 */
			double t = -expm1(-x*(2*DBL_EPSILON + DBL_EPSILON));
			double relerr_bound =
			    t + DBL_EPSILON + t*DBL_EPSILON;
			if (relerr_bound < 3e-15)
				/*
				 * The tests are written only to 16
				 * decimal places anyway even if your
				 * `double' is, say, i387 binary80, for
				 * whatever reason.
				 */
				relerr_bound = 3e-15;
			CHECK_RELERR(np, sf_weibull(sqrt(x), 1, 2));
			CHECK_RELERR(np, sf_weibull(sqrt(x)/2, .5, 2));
			CHECK_RELERR(np, sf_weibull(sqrt(x)*2, 2, 2));
		}

		if (p <= 0.75) {
			/*
			 * For p near 1, not enough precision near 1 to
			 * recover x.
			 */
			CHECK_RELERR(x, icdf_weibull(p, 1, 1));
			CHECK_RELERR(x/2, icdf_weibull(p, .5, 1));
			CHECK_RELERR(x*2, icdf_weibull(p, 2, 1));
		}
		if (p >= 0.25 && !isinf(x) && np != 0) {
			/*
			 * For p near 0, not enough precision in np
			 * near 1 to recover x.  For 0, isf gives inf,
			 * even if p is precise enough for the icdf to
			 * work.
			 */
			CHECK_RELERR(x, isf_weibull(np, 1, 1));
			CHECK_RELERR(x/2, isf_weibull(np, .5, 1));
			CHECK_RELERR(x*2, isf_weibull(np, 2, 1));
		}
	}

	for (i = 0; i <= 100; i++) {
		double p0 = (double)i/100;

		CHECK_RELERR(3*sqrt(-log(p0/2)), sample_weibull(0, p0, 3, 2));
		CHECK_RELERR(3*sqrt(-log1p(-p0/2)),
		    sample_weibull(1, p0, 3, 2));
	}

	if (ok)
		printf("pass Weibull cdf/sf\n");
	else
		printf("fail Weibull cdf/sf\n");
	return ok;
}

/**
 * Test the cdf, sf, icdf, and isf of the generalized Pareto
 * distribution.
 */
static bool
test_genpareto(void)
{
	struct {
		double xi, x, p, np;
	} cases[] = {
		{ 0, 0, 0, 1 },
		{ 1e-300, .004, 3.992010656008528e-3, .9960079893439915 },
		{ 1e-300, .1, .09516258196404043, .9048374180359595 },
		{ 1e-300, 1, .6321205588285577, .36787944117144233 },
		{ 1e-300, 10, .9999546000702375, 4.5399929762484854e-5 },
		{ 1e-200, 1e-16, 9.999999999999999e-17, .9999999999999999 },
		{ 1e-16, 1e-200, 9.999999999999998e-201, 1 },
		{ 1e-16, 1e-16, 1e-16, 1 },
		{ 1e-16, .004, 3.992010656008528e-3, .9960079893439915 },
		{ 1e-16, .1, .09516258196404043, .9048374180359595 },
		{ 1e-16, 1, .6321205588285577, .36787944117144233 },
		{ 1e-16, 10, .9999546000702375, 4.539992976248509e-5 },
		{ 1e-10, 1e-6, 9.999995000001667e-7, .9999990000005 },
		{ 1e-8, 1e-8, 9.999999950000001e-9, .9999999900000001 },
		{ 1, 1e-300, 1e-300, 1 },
		{ 1, 1e-16, 1e-16, .9999999999999999 },
		{ 1, .1, .09090909090909091, .9090909090909091 },
		{ 1, 1, .5, .5 },
		{ 1, 10, .9090909090909091, .0909090909090909 },
		{ 1, 100, .9900990099009901, .0099009900990099 },
		{ 1, 1000, .999000999000999, 9.990009990009992e-4 },
		{ 10, 1e-300, 1e-300, 1 },
		{ 10, 1e-16, 9.999999999999995e-17, .9999999999999999 },
		{ 10, .1, .06696700846319258, .9330329915368074 },
		{ 10, 1, .21320655780322778, .7867934421967723 },
		{ 10, 10, .3696701667040189, .6303298332959811 },
		{ 10, 100, .49886285755007337, .5011371424499267 },
		{ 10, 1000, .6018968102992647, .3981031897007353 },
	};
	double xi[] = { -1.5, -1, -1e-30, 0, 1e-30, 1, 1.5 };
	size_t i, j;
	double relerr_bound = 3e-15;
	bool ok = true;

	for (i = 0; i < arraycount(cases); i++) {
		double xi = cases[i].xi;
		double x = cases[i].x;
		double p = cases[i].p;
		double np = cases[i].np;

		CHECK_RELERR(p, cdf_genpareto(x, 0, 1, xi));
		CHECK_RELERR(p, cdf_genpareto(x*2, 0, 2, xi));
		CHECK_RELERR(p, cdf_genpareto(x/2, 0, .5, xi));
		CHECK_RELERR(np, sf_genpareto(x, 0, 1, xi));
		CHECK_RELERR(np, sf_genpareto(x*2, 0, 2, xi));
		CHECK_RELERR(np, sf_genpareto(x/2, 0, .5, xi));

		if (p < .5) {
			CHECK_RELERR(x, icdf_genpareto(p, 0, 1, xi));
			CHECK_RELERR(x*2, icdf_genpareto(p, 0, 2, xi));
			CHECK_RELERR(x/2, icdf_genpareto(p, 0, .5, xi));
		}
		if (np < .5) {
			CHECK_RELERR(x, isf_genpareto(np, 0, 1, xi));
			CHECK_RELERR(x*2, isf_genpareto(np, 0, 2, xi));
			CHECK_RELERR(x/2, isf_genpareto(np, 0, .5, xi));
		}
	}

	for (i = 0; i < arraycount(xi); i++) {
		for (j = 0; j <= 100; j++) {
			double p0 = (j == 0 ? 2*DBL_MIN : (double)j/100);

			if (xi[i] == 0) {
				/*
				 * When xi == 0, the generalized Pareto
				 * distribution reduces to an
				 * exponential distribution.
				 */
				CHECK_RELERR(-log(p0/2),
				    sample_genpareto(0, p0, 0));
				CHECK_RELERR(-log1p(-p0/2),
				    sample_genpareto(1, p0, 0));
			} else {
				CHECK_RELERR(expm1(-xi[i]*log(p0/2))/xi[i],
				    sample_genpareto(0, p0, xi[i]));
				CHECK_RELERR((j == 0 ? DBL_MIN :
					expm1(-xi[i]*log1p(-p0/2))/xi[i]),
				    sample_genpareto(1, p0, xi[i]));
			}

			CHECK_RELERR(isf_genpareto(p0/2, 0, 1, xi[i]),
			    sample_genpareto(0, p0, xi[i]));
			CHECK_RELERR(icdf_genpareto(p0/2, 0, 1, xi[i]),
			    sample_genpareto(1, p0, xi[i]));
		}
	}

	return true;
}

/**
 * Test the deterministic sampler for uniform distribution on [a, b].
 *
 * This currently only tests whether the outcome lies within [a, b].
 */
static bool
test_uniform_interval(void)
{
	struct {
		double t, a, b;
	} cases[] = {
		{ 0, 0, 0 },
		{ 0, 0, 1 },
		{ 0, 1.0000000000000007, 3.999999999999995 },
		{ 0, 4000, 4000 },
		{ 0.42475836677491291, 4000, 4000 },
		{ 0, -DBL_MAX, DBL_MAX },
		{ 0.25, -DBL_MAX, DBL_MAX },
		{ 0.5, -DBL_MAX, DBL_MAX },
	};
	size_t i = 0;
	bool ok = true;

	for (i = 0; i < arraycount(cases); i++) {
		double t = cases[i].t;
		double a = cases[i].a;
		double b = cases[i].b;

		CHECK_LE(a, sample_uniform_interval(t, a, b));
		CHECK_LE(sample_uniform_interval(t, a, b), b);

		CHECK_LE(a, sample_uniform_interval(1 - t, a, b));
		CHECK_LE(sample_uniform_interval(1 - t, a, b), b);

		CHECK_LE(sample_uniform_interval(t, -b, -a), -a);
		CHECK_LE(-b, sample_uniform_interval(t, -b, -a));

		CHECK_LE(sample_uniform_interval(1 - t, -b, -a), -a);
		CHECK_LE(-b, sample_uniform_interval(1 - t, -b, -a));
	}

	return ok;
}

/*
 * Psi test, sometimes also called G-test.  The psi test statistic,
 * suitably scaled, has chi^2 distribution, but the psi test tends to
 * have better statistical power in practice to detect deviations than
 * the chi^2 test does.  (The chi^2 test statistic is the first term of
 * the Taylor expansion of the psi test statistic.)  The psi test is
 * generic, for any CDF; particular distributions might have higher-
 * power tests to distinguish them from predictable deviations or bugs.
 *
 * We choose the psi critical value so that a single psi test has
 * probability below alpha = 1% of spuriously failing even if all the
 * code is correct.  But the false positive rate for a suite of n tests
 * is higher: 1 - Binom(0; n, alpha) = 1 - (1 - alpha)^n.  For n = 10,
 * this is about 10%, and for n = 100 it is well over 50%.
 *
 * We can drive it down by running each test twice, and accepting it if
 * it passes at least once; in that case, it is as if we used Binom(2;
 * 2, alpha) = alpha^2 as the false positive rate for each test, and
 * for n = 10 tests, it would be 0.1%, and for n = 100 tests, still
 * only 1%.
 *
 * The critical value for a chi^2 distribution with 100 degrees of
 * freedom and false positive rate alpha = 1% was taken from:
 *
 *	NIST/SEMATECH e-Handbook of Statistical Methods, Section
 *	1.3.6.7.4 `Critical Values of the Chi-Square Distribution',
 *	<http://www.itl.nist.gov/div898/handbook/eda/section3/eda3674.htm>,
 *	retrieved 2018-10-28.
 */

static const size_t NSAMPLES = 100000;
static const unsigned NTRIALS = 2;
static const unsigned NPASSES_MIN = 1;

#define	PSI_DF	100		/* degrees of freedom */
static const double PSI_CRITICAL = 135.807; /* critical value, alpha = .01 */

/**
 * Perform a psi test on an array of sample counts, C, adding up to N
 * samples, and an array of log expected probabilities, logP,
 * representing the null hypothesis for the distribution of samples
 * counted.  Return false if the psi test rejects the null hypothesis,
 * true if otherwise.
 */
static bool
psi_test(const size_t C[PSI_DF], const double logP[PSI_DF], size_t N)
{
	double psi = 0;
	double c = 0;		/* Kahan compensation */
	double t, u;
	size_t i;

	for (i = 0; i < PSI_DF; i++) {
		/*
		 * c*log(c/(n*p)) = (1/n) * f*log(f/p) where f = c/n is
		 * the frequency, and f*log(f/p) ---> 0 as f ---> 0, so
		 * this is a reasonable choice.  Further, any mass that
		 * _fails_ to turn up in this bin will inflate another
		 * bin instead, so we don't really lose anything by
		 * ignoring empty bins even if they have high
		 * probability.
		 */
		if (C[i] == 0)
			continue;
		t = C[i]*(log((double)C[i]/N) - logP[i]) - c;
		u = psi + t;
		c = (u - psi) - t;
		psi = u;
	}
	psi *= 2;

	return psi <= PSI_CRITICAL;
}

static bool
test_stochastic_geometric(double p)
{
	double logP[PSI_DF] = {0};
	unsigned ntry = NTRIALS, npass = 0;
	unsigned i;
	size_t j;

	/* Compute logP[i] = Geom(i + 1; p).  */
	for (i = 0; i < PSI_DF - 1; i++)
		logP[i] = logpmf_geometric(i + 1, p);

	/* Compute logP[n-1] = log (1 - (P[0] + P[1] + ... + P[n-2])).  */
	logP[PSI_DF - 1] = log1mexp(logsumexp(logP, PSI_DF - 1));

	while (ntry --> 0) {
		size_t C[PSI_DF] = {0};

		for (j = 0; j < NSAMPLES; j++) {
			uint32_t s = crypto_rand_uint32();
			double p0 = random_uniform_01();
			unsigned n = sample_geometric(s, p0, p);

			if (n > PSI_DF)
				n = PSI_DF;
			C[n - 1]++;
		}

		if (psi_test(C, logP, NSAMPLES)) {
			if (++npass >= NPASSES_MIN)
				break;
		}
	}
	if (npass >= NPASSES_MIN) {
		printf("pass %s sampler\n", "geometric");
		return true;
	} else {
		printf("fail %s sampler\n", "geometric");
		return false;
	}
}

/**
 * Container for distribution parameters for sampling, CDF, &c.
 */
struct dist {
	const struct dist_ops *ops;
};

#define	DIST_BASE(OPS)	{ .ops = (OPS) }

struct dist_ops {
	const char *name;
	double (*sample)(const struct dist *);
	double (*cdf)(const struct dist *, double x);
	double (*sf)(const struct dist *, double x);
	double (*icdf)(const struct dist *, double p);
	double (*isf)(const struct dist *, double p);
};

struct uniform {
	struct dist base;
	double a;
	double b;
};

static double
uniform_sample(const struct dist *dist)
{
	const struct uniform *U = const_container_of(dist, struct uniform,
	    base);
	double p0 = random_uniform_01();

	return sample_uniform_interval(p0, U->a, U->b);
}

static double
uniform_cdf(const struct dist *dist, double x)
{
	const struct uniform *U = const_container_of(dist, struct uniform,
	    base);

	if (x < U->a)
		return 0;
	else if (x < U->b)
		return (x - U->a)/(U->b - U->a);
	else
		return 1;
}

static double
uniform_sf(const struct dist *dist, double x)
{
	const struct uniform *U = const_container_of(dist, struct uniform,
	    base);

	if (x > U->b)
		return 0;
	else if (x > U->a)
		return (U->b - x)/(U->b - U->a);
	else
		return 1;
}

static double
uniform_icdf(const struct dist *dist, double p)
{
	const struct uniform *U = const_container_of(dist, struct uniform,
	    base);
	double w = U->b - U->a;

	return (p < 0.5 ? (U->a + w*p) : (U->b - w*(1 - p)));
}

static double
uniform_isf(const struct dist *dist, double p)
{
	const struct uniform *U = const_container_of(dist, struct uniform,
	    base);
	double w = U->b - U->a;

	return (p < 0.5 ? (U->b - w*p) : (U->a + w*(1 - p)));
}

static const struct dist_ops uniform_ops = {
	.name = "uniform",
	.sample = uniform_sample,
	.cdf = uniform_cdf,
	.sf = uniform_sf,
	.icdf = uniform_icdf,
	.isf = uniform_isf,
};

struct logistic {
	struct dist base;
	double mu;
	double sigma;
};

static double
logistic_sample(const struct dist *dist)
{
	const struct logistic *L = const_container_of(dist, struct logistic,
	    base);
	uint32_t s = crypto_rand_uint32();
	double t = random_uniform_01();
	double p0 = random_uniform_01();

	return sample_logistic_locscale(s, t, p0, L->mu, L->sigma);
}

static double
logistic_cdf(const struct dist *dist, double x)
{
	const struct logistic *L = const_container_of(dist, struct logistic,
	    base);

	return cdf_logistic(x, L->mu, L->sigma);
}

static double
logistic_sf(const struct dist *dist, double x)
{
	const struct logistic *L = const_container_of(dist, struct logistic,
	    base);

	return sf_logistic(x, L->mu, L->sigma);
}

static double
logistic_icdf(const struct dist *dist, double p)
{
	const struct logistic *L = const_container_of(dist, struct logistic,
	    base);

	return icdf_logistic(p, L->mu, L->sigma);
}

static double
logistic_isf(const struct dist *dist, double p)
{
	const struct logistic *L = const_container_of(dist, struct logistic,
	    base);

	return isf_logistic(p, L->mu, L->sigma);
}

static const struct dist_ops logistic_ops = {
	.name = "logistic",
	.sample = logistic_sample,
	.cdf = logistic_cdf,
	.sf = logistic_sf,
	.icdf = logistic_icdf,
	.isf = logistic_isf,
};

struct log_logistic {
	struct dist base;
	double alpha;
	double beta;
};

static double
log_logistic_sample(const struct dist *dist)
{
	const struct log_logistic *LL = const_container_of(dist, struct
	    log_logistic, base);
	uint32_t s = crypto_rand_uint32();
	double p0 = random_uniform_01();

	return sample_log_logistic_scaleshape(s, p0, LL->alpha, LL->beta);
}

static double
log_logistic_cdf(const struct dist *dist, double x)
{
	const struct log_logistic *LL = const_container_of(dist,
	    struct log_logistic, base);

	return cdf_log_logistic(x, LL->alpha, LL->beta);
}

static double
log_logistic_sf(const struct dist *dist, double x)
{
	const struct log_logistic *LL = const_container_of(dist,
	    struct log_logistic, base);

	return sf_log_logistic(x, LL->alpha, LL->beta);
}

static double
log_logistic_icdf(const struct dist *dist, double p)
{
	const struct log_logistic *LL = const_container_of(dist,
	    struct log_logistic, base);

	return icdf_log_logistic(p, LL->alpha, LL->beta);
}

static double
log_logistic_isf(const struct dist *dist, double p)
{
	const struct log_logistic *LL = const_container_of(dist,
	    struct log_logistic, base);

	return isf_log_logistic(p, LL->alpha, LL->beta);
}

static const struct dist_ops log_logistic_ops = {
	.name = "log logistic",
	.sample = log_logistic_sample,
	.cdf = log_logistic_cdf,
	.sf = log_logistic_sf,
	.icdf = log_logistic_icdf,
	.isf = log_logistic_isf,
};

struct weibull {
	struct dist base;
	double lambda;
	double k;
};

static double
weibull_sample(const struct dist *dist)
{
	const struct weibull *W = const_container_of(dist, struct weibull,
	    base);
	uint32_t s = crypto_rand_uint32();
	double p0 = random_uniform_01();

	return sample_weibull(s, p0, W->lambda, W->k);
}

static double
weibull_cdf(const struct dist *dist, double x)
{
	const struct weibull *W = const_container_of(dist, struct weibull,
	    base);

	return cdf_weibull(x, W->lambda, W->k);
}

static double
weibull_sf(const struct dist *dist, double x)
{
	const struct weibull *W = const_container_of(dist, struct weibull,
	    base);

	return sf_weibull(x, W->lambda, W->k);
}

static double
weibull_icdf(const struct dist *dist, double p)
{
	const struct weibull *W = const_container_of(dist, struct weibull,
	    base);

	return icdf_weibull(p, W->lambda, W->k);
}

static double
weibull_isf(const struct dist *dist, double p)
{
	const struct weibull *W = const_container_of(dist, struct weibull,
	    base);

	return isf_weibull(p, W->lambda, W->k);
}

static const struct dist_ops weibull_ops = {
	.name = "Weibull",
	.sample = weibull_sample,
	.cdf = weibull_cdf,
	.sf = weibull_sf,
	.icdf = weibull_icdf,
	.isf = weibull_isf,
};

struct genpareto {
	struct dist base;
	double mu;
	double sigma;
	double xi;
};

static double
genpareto_sample(const struct dist *dist)
{
	const struct genpareto *GP = const_container_of(dist, struct genpareto,
	    base);
	uint32_t s = crypto_rand_uint32();
	double p0 = random_uniform_01();

	return sample_genpareto_locscale(s, p0, GP->mu, GP->sigma, GP->xi);
}

static double
genpareto_cdf(const struct dist *dist, double x)
{
	const struct genpareto *GP = const_container_of(dist, struct genpareto,
	    base);

	return cdf_genpareto(x, GP->mu, GP->sigma, GP->xi);
}

static double
genpareto_sf(const struct dist *dist, double x)
{
	const struct genpareto *GP = const_container_of(dist, struct genpareto,
	    base);

	return sf_genpareto(x, GP->mu, GP->sigma, GP->xi);
}

static double
genpareto_icdf(const struct dist *dist, double p)
{
	const struct genpareto *GP = const_container_of(dist, struct genpareto,
	    base);

	return icdf_genpareto(p, GP->mu, GP->sigma, GP->xi);
}

static double
genpareto_isf(const struct dist *dist, double p)
{
	const struct genpareto *GP = const_container_of(dist, struct genpareto,
	    base);

	return isf_genpareto(p, GP->mu, GP->sigma, GP->xi);
}

static const struct dist_ops genpareto_ops = {
	.name = "generalized Pareto",
	.sample = genpareto_sample,
	.cdf = genpareto_cdf,
	.sf = genpareto_sf,
	.icdf = genpareto_icdf,
	.isf = genpareto_isf,
};

/**
 * Set logP[i] = log(F(x_i) - F(x_{i-1})), where x_-1 = -inf, x_n =
 * +inf, and x_i = i*(hi - lo)/(n - 2), and where F(x) is the CDF of
 * dist.
 */
static void
bin_cdfs(const struct dist *dist, double lo, double hi, double *logP, size_t n)
{
#define	CDF(x)	dist->ops->cdf(dist, x)
#define	SF(x)	dist->ops->sf(dist, x)
	const double w = (hi - lo)/(n - 2);
	double halfway = dist->ops->icdf(dist, 0.5);
	double x_0, x_1;
	size_t i, n2 = ceil((halfway - lo)/w);

	assert(lo <= halfway);
	assert(halfway <= hi);
	assert(n2 <= n);

	x_1 = lo;
	logP[0] = log(CDF(x_1) - 0); /* 0 = CDF(-inf) */
	for (i = 1; i < n2; i++) {
		x_0 = x_1;
		x_1 = lo + i*w;
		logP[i] = log(CDF(x_1) - CDF(x_0));
	}
	x_0 = hi;
	logP[n - 1] = log(SF(x_0) - 0); /* 0 = SF(+inf) = 1 - CDF(+inf) */
	for (i = 1; i < n - n2; i++) {
		x_1 = x_0;
		x_0 = hi - i*w;
		logP[n - i - 1] = log(SF(x_0) - SF(x_1));
	}
#undef SF
#undef CDF
}

/**
 * Draw NSAMPLES samples from dist, counting the number of samples x in
 * the ith bin C[i] if x_{i-1} <= x < x_i, where x_-1 = -inf, x_n =
 * +inf, and x_i = i*(hi - lo)/(n - 2).
 */
static void
bin_samples(const struct dist *dist, double lo, double hi, size_t *C, size_t n)
{
	const double w = (hi - lo)/(n - 2);
	size_t i;

	for (i = 0; i < NSAMPLES; i++) {
		double x = dist->ops->sample(dist);
		size_t bin;

		if (x < lo)
			bin = 0;
		else if (x < hi)
			bin = 1 + (size_t)floor((x - lo)/w);
		else
			bin = n - 1;
		assert(bin < n);
		C[bin]++;
	}
}

/**
 * Sample NSAMPLES from dist, putting them in bins from -inf to lo to
 * hi to +inf, and apply up to two psi tests.  True if at least one psi
 * test passes; false if not.  False positive rate should be bounded by
 * 0.01^2 = 0.0001.
 */
static bool
test_psi_dist_sample(const struct dist *dist)
{
	double logP[PSI_DF] = {0};
	unsigned ntry = NTRIALS, npass = 0;
	double lo = dist->ops->icdf(dist, 1/(double)(PSI_DF + 2));
	double hi = dist->ops->isf(dist, 1/(double)(PSI_DF + 2));

	bin_cdfs(dist, lo, hi, logP, PSI_DF);
	while (ntry --> 0) {
		size_t C[PSI_DF] = {0};
		bin_samples(dist, lo, hi, C, PSI_DF);
		if (psi_test(C, logP, NSAMPLES)) {
			if (++npass >= NPASSES_MIN)
				break;
		}
	}
	if (npass >= NPASSES_MIN) {
		printf("pass %s sampler\n", dist->ops->name);
		return true;
	} else {
		printf("fail %s sampler\n", dist->ops->name);
		return false;
	}
}

static bool
test_stochastic_uniform(void)
{
	const struct uniform uniform01 = {
		.base = DIST_BASE(&uniform_ops),
		.a = 0,
		.b = 1,
	};
	const struct uniform uniform_pos = {
		.base = DIST_BASE(&uniform_ops),
		.a = 1.23,
		.b = 4.56,
	};
	const struct uniform uniform_neg = {
		.base = DIST_BASE(&uniform_ops),
		.a = -10,
		.b = -1,
	};
	const struct uniform uniform_cross = {
		.base = DIST_BASE(&uniform_ops),
		.a = -1.23,
		.b = 4.56,
	};
	const struct uniform uniform_subnormal = {
		.base = DIST_BASE(&uniform_ops),
		.a = 4e-324,
		.b = 4e-310,
	};
	const struct uniform uniform_subnormal_cross = {
		.base = DIST_BASE(&uniform_ops),
		.a = -4e-324,
		.b = 4e-310,
	};
	bool ok = true;

	ok &= test_psi_dist_sample(&uniform01.base);
	ok &= test_psi_dist_sample(&uniform_pos.base);
	ok &= test_psi_dist_sample(&uniform_neg.base);
	ok &= test_psi_dist_sample(&uniform_cross.base);
	ok &= test_psi_dist_sample(&uniform_subnormal.base);
	ok &= test_psi_dist_sample(&uniform_subnormal_cross.base);

	return ok;
}

static bool
test_stochastic_logistic(double mu, double sigma)
{
	const struct logistic dist = {
		.base = DIST_BASE(&logistic_ops),
		.mu = mu,
		.sigma = sigma,
	};

	/* XXX Consider some fancier logistic test.  */
	return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_log_logistic(double alpha, double beta)
{
	const struct log_logistic dist = {
		.base = DIST_BASE(&log_logistic_ops),
		.alpha = alpha,
		.beta = beta,
	};

	/* XXX Consider some fancier log logistic test.  */
	return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_weibull(double lambda, double k)
{
	const struct weibull dist = {
		.base = DIST_BASE(&weibull_ops),
		.lambda = lambda,
		.k = k,
	};

	/*
	 * XXX Consider applying a Tiku-Singh test:
	 *
	 *	M.L. Tiku and M. Singh, `Testing the two-parameter
	 *	Weibull distribution', Communications in Statistics --
	 *	Theory and Methods A10(9), 1981, 907--918.
	 *	https://www.tandfonline.com/doi/pdf/10.1080/03610928108828082?needAccess=true
	 */
	return test_psi_dist_sample(&dist.base);
}

static bool
test_stochastic_genpareto(double mu, double sigma, double xi)
{
	const struct genpareto dist = {
		.base = DIST_BASE(&genpareto_ops),
		.mu = mu,
		.sigma = sigma,
		.xi = xi,
	};

	/* XXX Consider some fancier GPD test.  */
	return test_psi_dist_sample(&dist.base);
}

int
main(void)
{
	bool ok = true;

	ok &= test_logit_logistic();
	ok &= test_log_logistic();
	ok &= test_weibull();
	ok &= test_genpareto();
	ok &= test_uniform_interval();

	/* XXX parameters pulled from arse, should choose with greater care */
	ok &= test_stochastic_geometric(0.1);
	ok &= test_stochastic_geometric(0.5);
	ok &= test_stochastic_geometric(0.9);
	ok &= test_stochastic_geometric(1);
	ok &= test_stochastic_uniform();
	ok &= test_stochastic_logistic(0, 1);
	ok &= test_stochastic_logistic(0, 1e-16);
	ok &= test_stochastic_logistic(1, 10);
	ok &= test_stochastic_logistic(-10, 100);
	ok &= test_stochastic_log_logistic(1, 1);
	ok &= test_stochastic_log_logistic(1, 10);
	ok &= test_stochastic_log_logistic(M_E, 1e-1);
	ok &= test_stochastic_log_logistic(exp(-10), 1e-2);
	ok &= test_stochastic_weibull(1, 0.5);
	ok &= test_stochastic_weibull(1, 1);
	ok &= test_stochastic_weibull(1, 1.5);
	ok &= test_stochastic_weibull(1, 2);
	ok &= test_stochastic_weibull(10, 1);
	ok &= test_stochastic_genpareto(0, 1, -0.25);
	ok &= test_stochastic_genpareto(0, 1, -1e-30);
	ok &= test_stochastic_genpareto(0, 1, 0);
	ok &= test_stochastic_genpareto(0, 1, 1e-30);
	ok &= test_stochastic_genpareto(0, 1, 0.25);
	ok &= test_stochastic_genpareto(-1, 1, -0.25);
	ok &= test_stochastic_genpareto(1, 2, 0.25);

	return !ok;
}
