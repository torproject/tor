/* Copyright (c) 2001, Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file crypto_nss_mgt.c
 *
 * \brief Manage the NSS library (if used)
 **/

#include "lib/crypt_ops/crypto_nss_mgt.h"

#include "lib/log/log.h"
#include "lib/log/util_bug.h"

#include <nss.h>
#include <pk11func.h>
#include <ssl.h>

#include <prerror.h>
#include <prtypes.h>
#include <prinit.h>

const char *
crypto_nss_get_version_str(void)
{
  return NSS_GetVersion();
}
const char *
crypto_nss_get_header_version_str(void)
{
  return NSS_VERSION;
}

/** A password function that always returns NULL. */
static char *
nss_password_func_always_fail(PK11SlotInfo *slot,
                              PRBool retry,
                              void *arg)
{
  (void) slot;
  (void) retry;
  (void) arg;
  return NULL;
}

void
crypto_nss_early_init(void)
{
  PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
  PK11_SetPasswordFunc(nss_password_func_always_fail);

  /* Eventually we should use NSS_Init() instead -- but that wants a
     directory. The documentation says that we can't use this if we want
     to use OpenSSL. */
  if (NSS_NoDB_Init(NULL) == SECFailure) {
    log_err(LD_CRYPTO, "Unable to initialize NSS.");
    crypto_nss_log_errors(LOG_ERR, "initializing NSS");
    tor_assert_unreached();
  }

  if (NSS_SetDomesticPolicy() == SECFailure) {
    log_err(LD_CRYPTO, "Unable to set NSS cipher policy.");
    crypto_nss_log_errors(LOG_ERR, "setting cipher policy");
    tor_assert_unreached();
  }
}

void
crypto_nss_log_errors(int severity, const char *doing)
{
  PRErrorCode code = PR_GetError();
  /* XXXX how do I convert errors to strings? */
  if (doing) {
    tor_log(severity, LD_CRYPTO, "NSS error %u while %s", code, doing);
  } else {
    tor_log(severity, LD_CRYPTO, "NSS error %u", code);
  }
}

int
crypto_nss_late_init(void)
{
  /* Possibly, SSL_OptionSetDefault? */

  return 0;
}

void
crypto_nss_global_cleanup(void)
{
  NSS_Shutdown();
}
