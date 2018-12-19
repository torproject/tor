
/**
 * \file prob_distr.h
 *
 * \brief Header for prob_distr.c
 **/

#ifndef TOR_PROB_DISTR_H
#define TOR_PROB_DISTR_H

#include "lib/cc/compat_compiler.h"
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"

/**
 * Container for distribution parameters for sampling, CDF, &c.
 */
struct dist {
  const struct dist_ops *ops;
};

#define DIST_BASE(OPS)  { .ops = (OPS) }

struct dist_ops {
  const char *name;
  double (*sample)(const struct dist *);
  double (*cdf)(const struct dist *, double x);
  double (*sf)(const struct dist *, double x);
  double (*icdf)(const struct dist *, double p);
  double (*isf)(const struct dist *, double p);
};

/* Geometric distribution */

double geometric_sample(double p);

/* Pareto distribution */

struct genpareto {
  struct dist base;
  double mu;
  double sigma;
  double xi;
};

double genpareto_sample(const struct dist *dist);
double genpareto_cdf(const struct dist *dist, double x);
double genpareto_sf(const struct dist *dist, double x);
double genpareto_icdf(const struct dist *dist, double p);
double genpareto_isf(const struct dist *dist, double p);

extern const struct dist_ops genpareto_ops;

/* Weibull distribution */

struct weibull {
  struct dist base;
  double lambda;
  double k;
};

double weibull_sample(const struct dist *dist);
double weibull_cdf(const struct dist *dist, double x);
double weibull_sf(const struct dist *dist, double x);
double weibull_icdf(const struct dist *dist, double p);
double weibull_isf(const struct dist *dist, double p);

extern const struct dist_ops weibull_ops;

/* Log-logistic distribution */

struct log_logistic {
  struct dist base;
  double alpha;
  double beta;
};

double log_logistic_sample(const struct dist *dist);
double log_logistic_cdf(const struct dist *dist, double x);
double log_logistic_sf(const struct dist *dist, double x);
double log_logistic_icdf(const struct dist *dist, double p);
double log_logistic_isf(const struct dist *dist, double p);

extern const struct dist_ops log_logistic_ops;

/* Logistic distribution */

struct logistic {
  struct dist base;
  double mu;
  double sigma;
};

double logistic_sample(const struct dist *dist);
double logistic_cdf(const struct dist *dist, double x);
double logistic_sf(const struct dist *dist, double x);
double logistic_icdf(const struct dist *dist, double p);
double logistic_isf(const struct dist *dist, double p);

extern const struct dist_ops logistic_ops;

/* Uniform distribution */

struct uniform {
  struct dist base;
  double a;
  double b;
};

double uniform_sample(const struct dist *dist);
double uniform_cdf(const struct dist *dist, double x);
double uniform_sf(const struct dist *dist, double x);
double uniform_icdf(const struct dist *dist, double p);
double uniform_isf(const struct dist *dist, double p);

extern const struct dist_ops uniform_ops;

/** Only by unittests */

#ifdef PROB_DISTR_PRIVATE

STATIC double logithalf(double p0);
STATIC double logit(double p);

STATIC double random_uniform_01(void);

STATIC double logistic(double x);
STATIC double cdf_logistic(double x, double mu, double sigma);
STATIC double sf_logistic(double x, double mu, double sigma);
STATIC double icdf_logistic(double p, double mu, double sigma);
STATIC double isf_logistic(double p, double mu, double sigma);
STATIC double sample_logistic(uint32_t s, double t, double p0);

STATIC double cdf_log_logistic(double x, double alpha, double beta);
STATIC double sf_log_logistic(double x, double alpha, double beta);
STATIC double icdf_log_logistic(double p, double alpha, double beta);
STATIC double isf_log_logistic(double p, double alpha, double beta);
STATIC double sample_log_logistic(uint32_t s, double p0);

STATIC double cdf_weibull(double x, double lambda, double k);
STATIC double sf_weibull(double x, double lambda, double k);
STATIC double icdf_weibull(double p, double lambda, double k);
STATIC double isf_weibull(double p, double lambda, double k);
STATIC double sample_weibull(uint32_t s, double p0, double lambda, double k);

STATIC double sample_uniform_interval(double p0, double a, double b);

STATIC double cdf_genpareto(double x, double mu, double sigma, double xi);
STATIC double sf_genpareto(double x, double mu, double sigma, double xi);
STATIC double icdf_genpareto(double p, double mu, double sigma, double xi);
STATIC double isf_genpareto(double p, double mu, double sigma, double xi);
STATIC double sample_genpareto(uint32_t s, double p0, double xi);

#endif

#endif
