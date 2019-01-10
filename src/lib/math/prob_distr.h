
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
#define DIST_BASE_TYPED(OPS, OBJ, TYPE)                         \
  DIST_BASE((OPS) + 0*sizeof(&(OBJ) - (const TYPE *)&(OBJ)))

const char *dist_name(const struct dist *);
double dist_sample(const struct dist *);
double dist_cdf(const struct dist *, double x);
double dist_sf(const struct dist *, double x);
double dist_icdf(const struct dist *, double p);
double dist_isf(const struct dist *, double p);

struct dist_ops {
  const char *name;
  double (*sample)(const struct dist *);
  double (*cdf)(const struct dist *, double x);
  double (*sf)(const struct dist *, double x);
  double (*icdf)(const struct dist *, double p);
  double (*isf)(const struct dist *, double p);
};

/* Geometric distribution on positive number of trials before first success */

struct geometric {
  struct dist base;
  double p; /* success probability */
};

extern const struct dist_ops geometric_ops;

#define GEOMETRIC(OBJ)                                      \
  DIST_BASE_TYPED(&geometric_ops, OBJ, struct geometric)

/* Pareto distribution */

struct genpareto {
  struct dist base;
  double mu;
  double sigma;
  double xi;
};

extern const struct dist_ops genpareto_ops;

#define GENPARETO(OBJ)                                      \
  DIST_BASE_TYPED(&genpareto_ops, OBJ, struct genpareto)

/* Weibull distribution */

struct weibull {
  struct dist base;
  double lambda;
  double k;
};

extern const struct dist_ops weibull_ops;

#define WEIBULL(OBJ)                                    \
  DIST_BASE_TYPED(&weibull_ops, OBJ, struct weibull)

/* Log-logistic distribution */

struct log_logistic {
  struct dist base;
  double alpha;
  double beta;
};

extern const struct dist_ops log_logistic_ops;

#define LOG_LOGISTIC(OBJ)                                       \
  DIST_BASE_TYPED(&log_logistic_ops, OBJ, struct log_logistic)

/* Logistic distribution */

struct logistic {
  struct dist base;
  double mu;
  double sigma;
};

extern const struct dist_ops logistic_ops;

#define LOGISTIC(OBJ)                                   \
  DIST_BASE_TYPED(&logistic_ops, OBJ, struct logistic)

/* Uniform distribution */

struct uniform {
  struct dist base;
  double a;
  double b;
};

extern const struct dist_ops uniform_ops;

#define UNIFORM(OBJ)                                    \
  DIST_BASE_TYPED(&uniform_ops, OBJ, struct uniform)

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
