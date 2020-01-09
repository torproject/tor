/* Copyright (c) 2017-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file hs_ob.c
 * \brief Implement Onion Balance specific code.
 *
 * \details
 *
 * XXX:
 **/

#define HS_OB_PRIVATE

#include "lib/confmgt/confmgt.h"
#include "lib/encoding/confline.h"

#include "hs_ob.h"

/* Options config magic number. */
#define OB_OPTIONS_MAGIC 0x631DE7EA

/* Helper macros. */
#define VAR(varname, conftype, member, initvalue)                          \
  CONFIG_VAR_ETYPE(ob_options_t, varname, conftype, member, 0, initvalue)
#define V(member,conftype,initvalue)        \
  VAR(#member, conftype, member, initvalue)

/* Dummy instance of ob_options_t, used for type-checking its members with
 * CONF_CHECK_VAR_TYPE. */
DUMMY_TYPECHECK_INSTANCE(ob_options_t);

/* Array of variables for the config file options. */
static const config_var_t config_vars[] = {
  V(MasterOnionAddress, LINELIST, NULL),

  END_OF_CONFIG_VARS
};

/* "Extra" variable in the state that receives lines we can't parse. This
 * lets us preserve options from versions of Tor newer than us. */
static const struct_member_t config_extra_vars = {
  .name = "__extra",
  .type = CONFIG_TYPE_LINELIST,
  .offset = offsetof(ob_options_t, ExtraLines),
};

/* Configuration format of ob_options_t. */
static const config_format_t config_format = {
  .size = sizeof(ob_options_t),
  .magic = {
     "ob_options_t",
     OB_OPTIONS_MAGIC,
     offsetof(ob_options_t, magic_),
  },
  .vars = config_vars,
  .extra = &config_extra_vars,
};

/* Global configuration manager for the config file. */
static config_mgr_t *config_options_mgr = NULL;

/* Return the configuration manager for the config file. */
static const config_mgr_t *
get_config_options_mgr(void)
{
  if (PREDICT_UNLIKELY(config_options_mgr == NULL)) {
    config_options_mgr = config_mgr_new(&config_format);
    config_mgr_freeze(config_options_mgr);
  }
  return config_options_mgr;
}

#define ob_option_free(val) \
  FREE_AND_NULL(ob_options_t, ob_option_free_, (val))

/** Helper: Free a config options object. */
static void
ob_option_free_(ob_options_t *opts)
{
  if (opts == NULL) {
    return;
  }
  config_free(get_config_options_mgr(), opts);
}

/** Return an allocated config options object. */
static ob_options_t *
ob_option_new(void)
{
  ob_options_t *opts = config_new(get_config_options_mgr());
  config_init(get_config_options_mgr(), opts);
  return opts;
}

/** Helper function: From the configuration line value which is an onion
 * address with the ".onion" extension, find the public key and put it in
 * pkey_out.
 *
 * On success, true is returned. Else, false and pkey is untouched. */
static bool
get_onion_public_key(const char *value, ed25519_public_key_t *pkey_out)
{
  char address[HS_SERVICE_ADDR_LEN_BASE32 + 1];

  tor_assert(value);
  tor_assert(pkey_out);

  if (strcmpend(value, ".onion")) {
    /* Not a .onion extension, bad format. */
    return false;
  }

  /* Length validation. The -1 is because sizeof() counts the NUL byte. */
  if (strlen(value) >
      (HS_SERVICE_ADDR_LEN_BASE32 + sizeof(".onion") - 1)) {
    /* Too long, bad format. */
    return false;
  }

  /* We don't want the .onion so we add 2 because size - 1 is copied with
   * strlcpy() in order to accomodate the NUL byte and sizeof() counts the NUL
   * byte so we need to remove them from the equation. */
  strlcpy(address, value, strlen(value) - sizeof(".onion") + 2);

  if (hs_parse_address_no_log(address, pkey_out, NULL, NULL, NULL) < 0) {
    return false;
  }

  /* Success. */
  return true;
}

/** Parse the given ob options in opts and set the service config object
 * accordingly.
 *
 * Return 1 on success else 0. */
static int
ob_option_parse(hs_service_config_t *config, const ob_options_t *opts)
{
  int ret = 0;
  config_line_t *line;

  tor_assert(config);
  tor_assert(opts);

  for (line = opts->MasterOnionAddress; line; line = line->next) {
    /* Allocate config list if need be. */
    if (!config->ob_master_pubkeys) {
      config->ob_master_pubkeys = smartlist_new();
    }
    ed25519_public_key_t *pubkey = tor_malloc_zero(sizeof(*pubkey));

    if (!get_onion_public_key(line->value, pubkey)) {
      log_warn(LD_REND, "OnionBalance: MasterOnionAddress %s is invalid",
               line->value);
      tor_free(pubkey);
      goto end;
    }
    smartlist_add(config->ob_master_pubkeys, pubkey);
  }
  /* Success. */
  ret = 1;

 end:
  /* No keys added, we free the list since no list means no onion balance
   * support for this tor instance. */
  if (smartlist_len(config->ob_master_pubkeys) == 0) {
    smartlist_free(config->ob_master_pubkeys);
  }
  return ret;
}

/** Read and parse the config file at fname on disk. The service config object
 * is populated with the options if any.
 *
 * Return 1 on success else 0. This is to follow the "ok" convention in
 * hs_config.c. */
int
hs_ob_parse_config_file(hs_service_config_t *config)
{
  static const char *fname = "ob_config";
  int ret = 0;
  char *content = NULL, *errmsg = NULL, *config_file_path = NULL;
  ob_options_t *options = NULL;
  config_line_t *lines = NULL;

  tor_assert(config);

  /* Read file from disk. */
  config_file_path = hs_path_from_filename(config->directory_path, fname);
  content = read_file_to_str(config_file_path, 0, NULL);
  if (!content) {
    log_warn(LD_FS, "OnionBalance: Unable to read config file %s",
             escaped(config_file_path));
    goto end;
  }

  /* Parse lines. */
  if (config_get_lines(content, &lines, 0) < 0) {
    goto end;
  }

  options = ob_option_new();
  config_assign(get_config_options_mgr(), options, lines, 0, &errmsg);
  if (errmsg) {
    log_warn(LD_REND, "OnionBalance: Unable to parse config file: %s",
             errmsg);
    tor_free(errmsg);
    goto end;
  }

  /* Parse the options and set the service config object with the details. */
  ret = ob_option_parse(config, options);

 end:
  config_free_lines(lines);
  ob_option_free(options);
  tor_free(content);
  tor_free(config_file_path);
  return ret;
}
