/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * Tests for confparse.c's features that support multiple configuration
 * formats and configuration objects.
 */

#include "orconfig.h"

#include "core/or/or.h"
#include "lib/encoding/confline.h"
#include "app/config/confparse.h"
#include "test/test.h"
#include "test/log_test_helpers.h"

/*
 * Set up a few objects: a pasture_cfg is toplevel; it has a llama_cfg and an
 * alpaca_cfg.
 */

typedef struct {
  uint32_t magic;
  char *address;
  int opentopublic;
  config_suite_t *subobjs;
} pasture_cfg_t;

typedef struct {
  char *llamaname;
  int cuteness;
  uint32_t magic;
  int eats_meat; /* deprecated; llamas are never carnivorous. */
} llama_cfg_t;

typedef struct {
  uint32_t magic;
  int fuzziness;
  char *alpacaname;
  int n_wings; /* deprecated; alpacas don't have wings. */
} alpaca_cfg_t;

/*
 * Make the above into configuration objects.
 */

static pasture_cfg_t pasture_cfg_t_dummy;
static llama_cfg_t llama_cfg_t_dummy;
static alpaca_cfg_t alpaca_cfg_t_dummy;

#define PV(name, type, dflt) \
  CONFIG_VAR_ETYPE(pasture_cfg_t, #name, type, name, 0, dflt)
#define LV(name, type, dflt) \
  CONFIG_VAR_ETYPE(llama_cfg_t, #name, type, name, 0, dflt)
#define AV(name, type, dflt) \
  CONFIG_VAR_ETYPE(alpaca_cfg_t, #name, type, name, 0, dflt)
static const config_var_t pasture_vars[] = {
  PV(address, STRING, NULL),
  PV(opentopublic, BOOL, "1"),
  END_OF_CONFIG_VARS
};
static const config_var_t llama_vars[] =
{
  LV(llamaname, STRING, NULL),
  LV(eats_meat, BOOL, NULL),
  LV(cuteness, POSINT, "100"),
  END_OF_CONFIG_VARS
};
static const config_var_t alpaca_vars[] =
{
  AV(alpacaname, STRING, NULL),
  AV(fuzziness, POSINT, "50"),
  AV(n_wings, POSINT, "0"),
  END_OF_CONFIG_VARS
};

static config_deprecation_t llama_deprecations[] = {
  { "eats_meat", "Llamas are herbivores." },
  {NULL,NULL}
};

static config_deprecation_t alpaca_deprecations[] = {
  { "n_wings", "Alpacas are quadrupeds." },
  {NULL,NULL}
};

static config_abbrev_t llama_abbrevs[] = {
  { "gracia", "cuteness", 0, 0 },
  { "gentillesse", "cuteness", 0, 0 },
  { NULL, NULL, 0, 0 },
};

static const config_format_t pasture_fmt = {
  sizeof(pasture_cfg_t),
  {
    "pasture_cfg_t",
    8989,
    offsetof(pasture_cfg_t, magic)
  },
  .vars = pasture_vars,
  .config_suite_offset = offsetof(pasture_cfg_t, subobjs),
};

static const config_format_t llama_fmt = {
  sizeof(llama_cfg_t),
  {
    "llama_cfg_t",
    0x11aa11,
    offsetof(llama_cfg_t, magic)
  },
  .vars = llama_vars,
  .config_suite_offset = -1,
  .deprecations = llama_deprecations,
  .abbrevs = llama_abbrevs,
};

static const config_format_t alpaca_fmt = {
  sizeof(alpaca_cfg_t),
  {
    "alpaca_cfg_t",
    0xa15aca,
    offsetof(alpaca_cfg_t, magic)
  },
  .vars = alpaca_vars,
  .config_suite_offset = -1,
  .deprecations = alpaca_deprecations,
};

static config_mgr_t *
get_mgr(bool freeze)
{
  config_mgr_t *mgr = config_mgr_new(&pasture_fmt);
  tt_int_op(0, OP_EQ, config_mgr_add_format(mgr, &llama_fmt));
  tt_int_op(1, OP_EQ, config_mgr_add_format(mgr, &alpaca_fmt));
  if (freeze)
    config_mgr_freeze(mgr);
  return mgr;

 done:
  config_mgr_free(mgr);
  return NULL;
}

static void
test_confmgr_init(void *arg)
{
  (void)arg;
  config_mgr_t *mgr = get_mgr(true);
  smartlist_t *vars = NULL;
  tt_ptr_op(mgr, OP_NE, NULL);

  vars = config_mgr_list_vars(mgr);
  tt_int_op(smartlist_len(vars), OP_EQ, 8); // 8 vars total.

  tt_str_op("cuteness", OP_EQ, config_find_option_name(mgr, "CUTENESS"));
  tt_str_op("cuteness", OP_EQ, config_find_option_name(mgr, "GRACIA"));
  smartlist_free(vars);

  vars = config_mgr_list_deprecated_vars(mgr); // 2 deprecated vars.
  tt_int_op(smartlist_len(vars), OP_EQ, 2);
  tt_assert(smartlist_contains_string(vars, "eats_meat"));
  tt_assert(smartlist_contains_string(vars, "n_wings"));

  tt_str_op("Llamas are herbivores.", OP_EQ,
            config_find_deprecation(mgr, "EATS_MEAT"));
  tt_str_op("Alpacas are quadrupeds.", OP_EQ,
            config_find_deprecation(mgr, "N_WINGS"));

 done:
  smartlist_free(vars);
  config_mgr_free(mgr);
}

#define CONFMGR_TEST(name, flags)                       \
  { #name, test_confmgr_ ## name, flags, NULL, NULL }

struct testcase_t confmgr_tests[] = {
  CONFMGR_TEST(init, 0),
  END_OF_TESTCASES
};
