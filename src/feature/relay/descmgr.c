/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * @file descmgr.c
 * @brief Make descriptors to describe ourselves
 *
 * This module are the functions to generate our own routerinfo_t and
 * extrainfo_t, and to encode those to signed strings for upload to the
 * directory authorities.
 **/

#define MAKEDESC_PRIVATE
#include "orconfig.h"
#include "core/or/or.h"
#include "feature/relay/descmgr.h"

#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/or/policies.h"
#include "core/or/protover.h"
#include "feature/client/transports.h"
#include "feature/control/control_events.h"
#include "feature/dircache/dirserv.h"
#include "feature/dirclient/dirclient.h"
#include "feature/dircommon/directory.h"
#include "feature/dirparse/routerparse.h"
#include "feature/dirparse/signing.h"
#include "feature/hibernate/hibernate.h"
#include "feature/nodelist/networkstatus.h"
#include "feature/nodelist/nickname.h"
#include "feature/nodelist/nodefamily.h"
#include "feature/nodelist/nodelist.h"
#include "feature/nodelist/routerinfo.h"
#include "feature/nodelist/routerlist.h"
#include "feature/nodelist/torcert.h"
#include "feature/relay/dns.h"
#include "feature/relay/relay_config.h"
#include "feature/relay/router.h"
#include "feature/relay/routerkeys.h"
#include "feature/relay/routermode.h"
#include "lib/geoip/geoip.h"
#include "feature/stats/geoip_stats.h"
#include "feature/stats/rephist.h"
#include "lib/crypt_ops/crypto_ed25519.h"
#include "lib/crypt_ops/crypto_curve25519.h"
#include "lib/crypt_ops/crypto_format.h"
#include "lib/encoding/confline.h"
#include "lib/osinfo/uname.h"
#include "lib/version/torversion.h"

#include "core/or/port_cfg_st.h"

#include "feature/nodelist/authority_cert_st.h"
#include "feature/nodelist/extrainfo_st.h"
#include "feature/nodelist/networkstatus_st.h"
#include "feature/nodelist/node_st.h"
#include "feature/nodelist/routerinfo_st.h"
#include "feature/nodelist/routerstatus_st.h"

/*
 * OR descriptor generation.
 */

/** My routerinfo. */
static routerinfo_t *desc_routerinfo = NULL;
/** My extrainfo */
static extrainfo_t *desc_extrainfo = NULL;
/** Why did we most recently decide to regenerate our descriptor?  Used to
 * tell the authorities why we're sending it to them. */
static const char *desc_gen_reason = "uninitialized reason";
/** Since when has our descriptor been "clean"?  0 if we need to regenerate it
 * now. */
STATIC time_t desc_clean_since = 0;
/** Why did we mark the descriptor dirty? */
STATIC const char *desc_dirty_reason = "Tor just started";
/** Boolean: do we need to regenerate the above? */
static int desc_needs_upload = 0;

/** Set <b>platform</b> (max length <b>len</b>) to a NUL-terminated short
 * string describing the version of Tor and the operating system we're
 * currently running on.
 */
STATIC void
get_platform_str(char *platform, size_t len)
{
  tor_snprintf(platform, len, "Tor %s on %s",
               get_short_version(), get_uname());
}

/* XXX need to audit this thing and count fenceposts. maybe
 *     refactor so we don't have to keep asking if we're
 *     near the end of maxlen?
 */
#define DEBUG_ROUTER_DUMP_ROUTER_TO_STRING

/** OR only: Given a routerinfo for this router, and an identity key to sign
 * with, encode the routerinfo as a signed server descriptor and return a new
 * string encoding the result, or NULL on failure.
 *
 * In addition to the fields in router, this function calls
 * onion_key_lifetime(), get_options(), and we_are_hibernating(), and uses the
 * results to populate some fields in the descriptor.
 */
STATIC char *
router_dump_router_to_string(routerinfo_t *router,
                             const crypto_pk_t *ident_key,
                             const crypto_pk_t *tap_key,
                             const curve25519_keypair_t *ntor_keypair,
                             const ed25519_keypair_t *signing_keypair)
{
  char *address = NULL;
  char *onion_pkey = NULL; /* Onion key, PEM-encoded. */
  crypto_pk_t *rsa_pubkey = NULL;
  char *identity_pkey = NULL; /* Identity key, PEM-encoded. */
  char digest[DIGEST256_LEN];
  char published[ISO_TIME_LEN+1];
  char fingerprint[FINGERPRINT_LEN+1];
  char *extra_info_line = NULL;
  size_t onion_pkeylen, identity_pkeylen;
  char *family_line = NULL;
  char *extra_or_address = NULL;
  const or_options_t *options = get_options();
  smartlist_t *chunks = NULL;
  char *output = NULL;
  const int emit_ed_sigs = signing_keypair &&
    router->cache_info.signing_key_cert;
  char *ed_cert_line = NULL;
  char *rsa_tap_cc_line = NULL;
  char *ntor_cc_line = NULL;
  char *proto_line = NULL;

  /* Make sure the identity key matches the one in the routerinfo. */
  if (!crypto_pk_eq_keys(ident_key, router->identity_pkey)) {
    log_warn(LD_BUG,"Tried to sign a router with a private key that didn't "
             "match router's public key!");
    goto err;
  }
  if (emit_ed_sigs) {
    if (!router->cache_info.signing_key_cert->signing_key_included ||
        !ed25519_pubkey_eq(&router->cache_info.signing_key_cert->signed_key,
                           &signing_keypair->pubkey)) {
      log_warn(LD_BUG, "Tried to sign a router descriptor with a mismatched "
               "ed25519 key chain %d",
               router->cache_info.signing_key_cert->signing_key_included);
      goto err;
    }
  }

  /* record our fingerprint, so we can include it in the descriptor */
  if (crypto_pk_get_fingerprint(router->identity_pkey, fingerprint, 1)<0) {
    log_err(LD_BUG,"Error computing fingerprint");
    goto err;
  }

  if (emit_ed_sigs) {
    /* Encode ed25519 signing cert */
    char ed_cert_base64[256];
    char ed_fp_base64[ED25519_BASE64_LEN+1];
    if (base64_encode(ed_cert_base64, sizeof(ed_cert_base64),
                    (const char*)router->cache_info.signing_key_cert->encoded,
                    router->cache_info.signing_key_cert->encoded_len,
                    BASE64_ENCODE_MULTILINE) < 0) {
      log_err(LD_BUG,"Couldn't base64-encode signing key certificate!");
      goto err;
    }
    ed25519_public_to_base64(ed_fp_base64,
                            &router->cache_info.signing_key_cert->signing_key);
    tor_asprintf(&ed_cert_line, "identity-ed25519\n"
                 "-----BEGIN ED25519 CERT-----\n"
                 "%s"
                 "-----END ED25519 CERT-----\n"
                 "master-key-ed25519 %s\n",
                 ed_cert_base64, ed_fp_base64);
  }

  /* PEM-encode the onion key */
  rsa_pubkey = router_get_rsa_onion_pkey(router->onion_pkey,
                                         router->onion_pkey_len);
  if (crypto_pk_write_public_key_to_string(rsa_pubkey,
                                           &onion_pkey,&onion_pkeylen)<0) {
    log_warn(LD_BUG,"write onion_pkey to string failed!");
    goto err;
  }

  /* PEM-encode the identity key */
  if (crypto_pk_write_public_key_to_string(router->identity_pkey,
                                        &identity_pkey,&identity_pkeylen)<0) {
    log_warn(LD_BUG,"write identity_pkey to string failed!");
    goto err;
  }

  /* Cross-certify with RSA key */
  if (tap_key && router->cache_info.signing_key_cert &&
      router->cache_info.signing_key_cert->signing_key_included) {
    char buf[256];
    int tap_cc_len = 0;
    uint8_t *tap_cc =
      make_tap_onion_key_crosscert(tap_key,
                            &router->cache_info.signing_key_cert->signing_key,
                            router->identity_pkey,
                            &tap_cc_len);
    if (!tap_cc) {
      log_warn(LD_BUG,"make_tap_onion_key_crosscert failed!");
      goto err;
    }

    if (base64_encode(buf, sizeof(buf), (const char*)tap_cc, tap_cc_len,
                      BASE64_ENCODE_MULTILINE) < 0) {
      log_warn(LD_BUG,"base64_encode(rsa_crosscert) failed!");
      tor_free(tap_cc);
      goto err;
    }
    tor_free(tap_cc);

    tor_asprintf(&rsa_tap_cc_line,
                 "onion-key-crosscert\n"
                 "-----BEGIN CROSSCERT-----\n"
                 "%s"
                 "-----END CROSSCERT-----\n", buf);
  }

  /* Cross-certify with onion keys */
  if (ntor_keypair && router->cache_info.signing_key_cert &&
      router->cache_info.signing_key_cert->signing_key_included) {
    int sign = 0;
    char buf[256];
    /* XXXX Base the expiration date on the actual onion key expiration time?*/
    tor_cert_t *cert =
      make_ntor_onion_key_crosscert(ntor_keypair,
                         &router->cache_info.signing_key_cert->signing_key,
                         router->cache_info.published_on,
                         get_onion_key_lifetime(), &sign);
    if (!cert) {
      log_warn(LD_BUG,"make_ntor_onion_key_crosscert failed!");
      goto err;
    }
    tor_assert(sign == 0 || sign == 1);

    if (base64_encode(buf, sizeof(buf),
                      (const char*)cert->encoded, cert->encoded_len,
                      BASE64_ENCODE_MULTILINE)<0) {
      log_warn(LD_BUG,"base64_encode(ntor_crosscert) failed!");
      tor_cert_free(cert);
      goto err;
    }
    tor_cert_free(cert);

    tor_asprintf(&ntor_cc_line,
                 "ntor-onion-key-crosscert %d\n"
                 "-----BEGIN ED25519 CERT-----\n"
                 "%s"
                 "-----END ED25519 CERT-----\n", sign, buf);
  }

  /* Encode the publication time. */
  format_iso_time(published, router->cache_info.published_on);

  if (router->declared_family && smartlist_len(router->declared_family)) {
    char *family = smartlist_join_strings(router->declared_family,
                                          " ", 0, NULL);
    tor_asprintf(&family_line, "family %s\n", family);
    tor_free(family);
  } else {
    family_line = tor_strdup("");
  }

  if (!tor_digest_is_zero(router->cache_info.extra_info_digest)) {
    char extra_info_digest[HEX_DIGEST_LEN+1];
    base16_encode(extra_info_digest, sizeof(extra_info_digest),
                  router->cache_info.extra_info_digest, DIGEST_LEN);
    if (!tor_digest256_is_zero(router->cache_info.extra_info_digest256)) {
      char d256_64[BASE64_DIGEST256_LEN+1];
      digest256_to_base64(d256_64, router->cache_info.extra_info_digest256);
      tor_asprintf(&extra_info_line, "extra-info-digest %s %s\n",
                   extra_info_digest, d256_64);
    } else {
      tor_asprintf(&extra_info_line, "extra-info-digest %s\n",
                   extra_info_digest);
    }
  }

  if (router->ipv6_orport &&
      tor_addr_family(&router->ipv6_addr) == AF_INET6) {
    char addr[TOR_ADDR_BUF_LEN];
    const char *a;
    a = tor_addr_to_str(addr, &router->ipv6_addr, sizeof(addr), 1);
    if (a) {
      tor_asprintf(&extra_or_address,
                   "or-address %s:%d\n", a, router->ipv6_orport);
      log_debug(LD_OR, "My or-address line is <%s>", extra_or_address);
    }
  }

  if (router->protocol_list) {
    tor_asprintf(&proto_line, "proto %s\n", router->protocol_list);
  } else {
    proto_line = tor_strdup("");
  }

  address = tor_dup_ip(router->addr);
  chunks = smartlist_new();

  /* Generate the easy portion of the router descriptor. */
  smartlist_add_asprintf(chunks,
                    "router %s %s %d 0 %d\n"
                    "%s"
                    "%s"
                    "platform %s\n"
                    "%s"
                    "published %s\n"
                    "fingerprint %s\n"
                    "uptime %ld\n"
                    "bandwidth %d %d %d\n"
                    "%s%s"
                    "onion-key\n%s"
                    "signing-key\n%s"
                    "%s%s"
                    "%s%s%s",
    router->nickname,
    address,
    router->or_port,
    router_should_advertise_dirport(options, router->dir_port),
    ed_cert_line ? ed_cert_line : "",
    extra_or_address ? extra_or_address : "",
    router->platform,
    proto_line,
    published,
    fingerprint,
    get_uptime(),
    (int) router->bandwidthrate,
    (int) router->bandwidthburst,
    (int) router->bandwidthcapacity,
    extra_info_line ? extra_info_line : "",
    (options->DownloadExtraInfo || options->V3AuthoritativeDir) ?
                         "caches-extra-info\n" : "",
    onion_pkey, identity_pkey,
    rsa_tap_cc_line ? rsa_tap_cc_line : "",
    ntor_cc_line ? ntor_cc_line : "",
    family_line,
    we_are_hibernating() ? "hibernating 1\n" : "",
    "hidden-service-dir\n");

  if (options->ContactInfo && strlen(options->ContactInfo)) {
    const char *ci = options->ContactInfo;
    if (strchr(ci, '\n') || strchr(ci, '\r'))
      ci = escaped(ci);
    smartlist_add_asprintf(chunks, "contact %s\n", ci);
  }

  if (options->BridgeRelay) {
    char *bd = NULL;

    if (options->BridgeDistribution && strlen(options->BridgeDistribution)) {
      bd = tor_strdup(options->BridgeDistribution);
    } else {
      bd = tor_strdup("any");
    }

    // Make sure our value is lowercased in the descriptor instead of just
    // forwarding what the user wrote in their torrc directly.
    tor_strlower(bd);

    smartlist_add_asprintf(chunks, "bridge-distribution-request %s\n", bd);
    tor_free(bd);
  }

  if (router->onion_curve25519_pkey) {
    char kbuf[128];
    base64_encode(kbuf, sizeof(kbuf),
                  (const char *)router->onion_curve25519_pkey->public_key,
                  CURVE25519_PUBKEY_LEN, BASE64_ENCODE_MULTILINE);
    smartlist_add_asprintf(chunks, "ntor-onion-key %s", kbuf);
  } else {
    /* Authorities will start rejecting relays without ntor keys in 0.2.9 */
    log_err(LD_BUG, "A relay must have an ntor onion key");
    goto err;
  }

  /* Write the exit policy to the end of 's'. */
  if (!router->exit_policy || !smartlist_len(router->exit_policy)) {
    smartlist_add_strdup(chunks, "reject *:*\n");
  } else if (router->exit_policy) {
    char *exit_policy = router_dump_exit_policy_to_string(router,1,0);

    if (!exit_policy)
      goto err;

    smartlist_add_asprintf(chunks, "%s\n", exit_policy);
    tor_free(exit_policy);
  }

  if (router->ipv6_exit_policy) {
    char *p6 = write_short_policy(router->ipv6_exit_policy);
    if (p6 && strcmp(p6, "reject 1-65535")) {
      smartlist_add_asprintf(chunks,
                            "ipv6-policy %s\n", p6);
    }
    tor_free(p6);
  }

  if (router_should_advertise_begindir(options,
                                   router->supports_tunnelled_dir_requests)) {
    smartlist_add_strdup(chunks, "tunnelled-dir-server\n");
  }

  /* Sign the descriptor with Ed25519 */
  if (emit_ed_sigs)  {
    smartlist_add_strdup(chunks, "router-sig-ed25519 ");
    crypto_digest_smartlist_prefix(digest, DIGEST256_LEN,
                                   ED_DESC_SIGNATURE_PREFIX,
                                   chunks, "", DIGEST_SHA256);
    ed25519_signature_t sig;
    char buf[ED25519_SIG_BASE64_LEN+1];
    if (ed25519_sign(&sig, (const uint8_t*)digest, DIGEST256_LEN,
                     signing_keypair) < 0)
      goto err;
    ed25519_signature_to_base64(buf, &sig);

    smartlist_add_asprintf(chunks, "%s\n", buf);
  }

  /* Sign the descriptor with RSA */
  smartlist_add_strdup(chunks, "router-signature\n");

  crypto_digest_smartlist(digest, DIGEST_LEN, chunks, "", DIGEST_SHA1);

  {
    char *sig;
    if (!(sig = router_get_dirobj_signature(digest, DIGEST_LEN, ident_key))) {
      log_warn(LD_BUG, "Couldn't sign router descriptor");
      goto err;
    }
    smartlist_add(chunks, sig);
  }

  /* include a last '\n' */
  smartlist_add_strdup(chunks, "\n");

  output = smartlist_join_strings(chunks, "", 0, NULL);

#ifdef DEBUG_ROUTER_DUMP_ROUTER_TO_STRING
  {
    char *s_dup;
    const char *cp;
    routerinfo_t *ri_tmp;
    cp = s_dup = tor_strdup(output);
    ri_tmp = router_parse_entry_from_string(cp, NULL, 1, 0, NULL, NULL);
    if (!ri_tmp) {
      log_err(LD_BUG,
              "We just generated a router descriptor we can't parse.");
      log_err(LD_BUG, "Descriptor was: <<%s>>", output);
      goto err;
    }
    tor_free(s_dup);
    routerinfo_free(ri_tmp);
  }
#endif /* defined(DEBUG_ROUTER_DUMP_ROUTER_TO_STRING) */

  goto done;

 err:
  tor_free(output); /* sets output to NULL */
 done:
  if (chunks) {
    SMARTLIST_FOREACH(chunks, char *, cp, tor_free(cp));
    smartlist_free(chunks);
  }
  crypto_pk_free(rsa_pubkey);
  tor_free(address);
  tor_free(family_line);
  tor_free(onion_pkey);
  tor_free(identity_pkey);
  tor_free(extra_or_address);
  tor_free(ed_cert_line);
  tor_free(rsa_tap_cc_line);
  tor_free(ntor_cc_line);
  tor_free(extra_info_line);
  tor_free(proto_line);

  return output;
}

/**
 * OR only: Given <b>router</b>, produce a string with its exit policy.
 * If <b>include_ipv4</b> is true, include IPv4 entries.
 * If <b>include_ipv6</b> is true, include IPv6 entries.
 */
char *
router_dump_exit_policy_to_string(const routerinfo_t *router,
                                  int include_ipv4,
                                  int include_ipv6)
{
  if ((!router->exit_policy) || (router->policy_is_reject_star)) {
    return tor_strdup("reject *:*");
  }

  return policy_dump_to_string(router->exit_policy,
                               include_ipv4,
                               include_ipv6);
}

/** Load the contents of <b>filename</b>, find the last line starting with
 * <b>end_line</b>, ensure that its timestamp is not more than 25 hours in
 * the past or more than 1 hour in the future with respect to <b>now</b>,
 * and write the file contents starting with that line to *<b>out</b>.
 * Return 1 for success, 0 if the file does not exist or is empty, or -1
 * if the file does not contain a line matching these criteria or other
 * failure. */
static int
load_stats_file(const char *filename, const char *end_line, time_t now,
                char **out)
{
  int r = -1;
  char *fname = get_datadir_fname(filename);
  char *contents, *start = NULL, *tmp, timestr[ISO_TIME_LEN+1];
  time_t written;
  switch (file_status(fname)) {
    case FN_FILE:
      /* X022 Find an alternative to reading the whole file to memory. */
      if ((contents = read_file_to_str(fname, 0, NULL))) {
        tmp = strstr(contents, end_line);
        /* Find last block starting with end_line */
        while (tmp) {
          start = tmp;
          tmp = strstr(tmp + 1, end_line);
        }
        if (!start)
          goto notfound;
        if (strlen(start) < strlen(end_line) + 1 + sizeof(timestr))
          goto notfound;
        strlcpy(timestr, start + 1 + strlen(end_line), sizeof(timestr));
        if (parse_iso_time(timestr, &written) < 0)
          goto notfound;
        if (written < now - (25*60*60) || written > now + (1*60*60))
          goto notfound;
        *out = tor_strdup(start);
        r = 1;
      }
     notfound:
      tor_free(contents);
      break;
    /* treat empty stats files as if the file doesn't exist */
    case FN_NOENT:
    case FN_EMPTY:
      r = 0;
      break;
    case FN_ERROR:
    case FN_DIR:
    default:
      break;
  }
  tor_free(fname);
  return r;
}

/** Add header strings to chunks, based on the extrainfo object extrainfo,
 * and ed25519 keypair signing_keypair, if emit_ed_sigs is true.
 * Helper for extrainfo_dump_to_string().
 * Returns 0 on success, negative on failure. */
static int
extrainfo_dump_to_string_header_helper(
                                     smartlist_t *chunks,
                                     const extrainfo_t *extrainfo,
                                     const ed25519_keypair_t *signing_keypair,
                                     int emit_ed_sigs)
{
  char identity[HEX_DIGEST_LEN+1];
  char published[ISO_TIME_LEN+1];
  char *ed_cert_line = NULL;
  char *pre = NULL;
  int rv = -1;

  base16_encode(identity, sizeof(identity),
                extrainfo->cache_info.identity_digest, DIGEST_LEN);
  format_iso_time(published, extrainfo->cache_info.published_on);
  if (emit_ed_sigs) {
    if (!extrainfo->cache_info.signing_key_cert->signing_key_included ||
        !ed25519_pubkey_eq(&extrainfo->cache_info.signing_key_cert->signed_key,
                           &signing_keypair->pubkey)) {
      log_warn(LD_BUG, "Tried to sign a extrainfo descriptor with a "
               "mismatched ed25519 key chain %d",
               extrainfo->cache_info.signing_key_cert->signing_key_included);
      goto err;
    }
    char ed_cert_base64[256];
    if (base64_encode(ed_cert_base64, sizeof(ed_cert_base64),
                 (const char*)extrainfo->cache_info.signing_key_cert->encoded,
                 extrainfo->cache_info.signing_key_cert->encoded_len,
                 BASE64_ENCODE_MULTILINE) < 0) {
      log_err(LD_BUG,"Couldn't base64-encode signing key certificate!");
      goto err;
    }
    tor_asprintf(&ed_cert_line, "identity-ed25519\n"
                 "-----BEGIN ED25519 CERT-----\n"
                 "%s"
                 "-----END ED25519 CERT-----\n", ed_cert_base64);
  } else {
    ed_cert_line = tor_strdup("");
  }

  /* This is the first chunk in the file. If the file is too big, other chunks
   * are removed. So we must only add one chunk here. */
  tor_asprintf(&pre, "extra-info %s %s\n%spublished %s\n",
               extrainfo->nickname, identity,
               ed_cert_line,
               published);
  smartlist_add(chunks, pre);

  rv = 0;
  goto done;

 err:
  rv = -1;

 done:
  tor_free(ed_cert_line);
  return rv;
}

/** Add pluggable transport and statistics strings to chunks, skipping
 * statistics if write_stats_to_extrainfo is false.
 * Helper for extrainfo_dump_to_string().
 * Can not fail. */
static void
extrainfo_dump_to_string_stats_helper(smartlist_t *chunks,
                                      int write_stats_to_extrainfo)
{
  const or_options_t *options = get_options();
  char *contents = NULL;
  time_t now = time(NULL);

  /* If the file is too big, these chunks are removed, starting with the last
   * chunk. So each chunk must be a complete line, and the file must be valid
   * after each chunk. */

  /* Add information about the pluggable transports we support, even if we
   * are not publishing statistics. This information is needed by BridgeDB
   * to distribute bridges. */
  if (options->ServerTransportPlugin) {
    char *pluggable_transports = pt_get_extra_info_descriptor_string();
    if (pluggable_transports)
      smartlist_add(chunks, pluggable_transports);
  }

  if (options->ExtraInfoStatistics && write_stats_to_extrainfo) {
    log_info(LD_GENERAL, "Adding stats to extra-info descriptor.");
    /* Bandwidth usage stats don't have their own option */
    {
      contents = rep_hist_get_bandwidth_lines();
      smartlist_add(chunks, contents);
    }
    /* geoip hashes aren't useful unless we are publishing other stats */
    if (geoip_is_loaded(AF_INET))
      smartlist_add_asprintf(chunks, "geoip-db-digest %s\n",
                             geoip_db_digest(AF_INET));
    if (geoip_is_loaded(AF_INET6))
      smartlist_add_asprintf(chunks, "geoip6-db-digest %s\n",
                             geoip_db_digest(AF_INET6));
    if (options->DirReqStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"dirreq-stats",
                        "dirreq-stats-end", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->HiddenServiceStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"hidserv-stats",
                        "hidserv-stats-end", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->EntryStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"entry-stats",
                        "entry-stats-end", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->CellStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"buffer-stats",
                        "cell-stats-end", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->ExitPortStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"exit-stats",
                        "exit-stats-end", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->ConnDirectionStatistics &&
        load_stats_file("stats"PATH_SEPARATOR"conn-stats",
                        "conn-bi-direct", now, &contents) > 0) {
      smartlist_add(chunks, contents);
    }
    if (options->PaddingStatistics) {
      contents = rep_hist_get_padding_count_lines();
      if (contents)
        smartlist_add(chunks, contents);
    }
    /* bridge statistics */
    if (should_record_bridge_info(options)) {
      const char *bridge_stats = geoip_get_bridge_stats_extrainfo(now);
      if (bridge_stats) {
        smartlist_add_strdup(chunks, bridge_stats);
      }
    }
  }
}

/** Add an ed25519 signature of chunks to chunks, using the ed25519 keypair
 * signing_keypair.
 * Helper for extrainfo_dump_to_string().
 * Returns 0 on success, negative on failure. */
static int
extrainfo_dump_to_string_ed_sig_helper(
                                     smartlist_t *chunks,
                                     const ed25519_keypair_t *signing_keypair)
{
  char sha256_digest[DIGEST256_LEN];
  ed25519_signature_t ed_sig;
  char buf[ED25519_SIG_BASE64_LEN+1];
  int rv = -1;

  /* These are two of the three final chunks in the file. If the file is too
   * big, other chunks are removed. So we must only add two chunks here. */
  smartlist_add_strdup(chunks, "router-sig-ed25519 ");
  crypto_digest_smartlist_prefix(sha256_digest, DIGEST256_LEN,
                                 ED_DESC_SIGNATURE_PREFIX,
                                 chunks, "", DIGEST_SHA256);
  if (ed25519_sign(&ed_sig, (const uint8_t*)sha256_digest, DIGEST256_LEN,
                   signing_keypair) < 0)
    goto err;
  ed25519_signature_to_base64(buf, &ed_sig);

  smartlist_add_asprintf(chunks, "%s\n", buf);

  rv = 0;
  goto done;

 err:
  rv = -1;

 done:
  return rv;
}

/** Add an RSA signature of extrainfo_string to chunks, using the RSA key
 * ident_key.
 * Helper for extrainfo_dump_to_string().
 * Returns 0 on success, negative on failure. */
static int
extrainfo_dump_to_string_rsa_sig_helper(smartlist_t *chunks,
                                        crypto_pk_t *ident_key,
                                        const char *extrainfo_string)
{
  char sig[DIROBJ_MAX_SIG_LEN+1];
  char digest[DIGEST_LEN];
  int rv = -1;

  memset(sig, 0, sizeof(sig));
  if (router_get_extrainfo_hash(extrainfo_string, strlen(extrainfo_string),
                                digest) < 0 ||
      router_append_dirobj_signature(sig, sizeof(sig), digest, DIGEST_LEN,
                                     ident_key) < 0) {
    log_warn(LD_BUG, "Could not append signature to extra-info "
                     "descriptor.");
    goto err;
  }
  smartlist_add_strdup(chunks, sig);

  rv = 0;
  goto done;

 err:
  rv = -1;

 done:
  return rv;
}

/** Write the contents of <b>extrainfo</b>, to * *<b>s_out</b>, signing them
 * with <b>ident_key</b>.
 *
 * If ExtraInfoStatistics is 1, also write aggregated statistics and related
 * configuration data before signing. Most statistics also have an option that
 * enables or disables that particular statistic.
 *
 * Always write pluggable transport lines.
 *
 * Return 0 on success, negative on failure. */
STATIC int
extrainfo_dump_to_string(char **s_out, extrainfo_t *extrainfo,
                         crypto_pk_t *ident_key,
                         const ed25519_keypair_t *signing_keypair)
{
  int result;
  static int write_stats_to_extrainfo = 1;
  char *s = NULL, *cp, *s_dup = NULL;
  smartlist_t *chunks = smartlist_new();
  extrainfo_t *ei_tmp = NULL;
  const int emit_ed_sigs = signing_keypair &&
    extrainfo->cache_info.signing_key_cert;
  int rv = 0;

  rv = extrainfo_dump_to_string_header_helper(chunks, extrainfo,
                                              signing_keypair,
                                              emit_ed_sigs);
  if (rv < 0)
    goto err;

  extrainfo_dump_to_string_stats_helper(chunks, write_stats_to_extrainfo);

  if (emit_ed_sigs) {
    rv = extrainfo_dump_to_string_ed_sig_helper(chunks, signing_keypair);
    if (rv < 0)
      goto err;
  }

  /* This is one of the three final chunks in the file. If the file is too big,
   * other chunks are removed. So we must only add one chunk here. */
  smartlist_add_strdup(chunks, "router-signature\n");
  s = smartlist_join_strings(chunks, "", 0, NULL);

  while (strlen(s) > MAX_EXTRAINFO_UPLOAD_SIZE - DIROBJ_MAX_SIG_LEN) {
    /* So long as there are at least two chunks (one for the initial
     * extra-info line and one for the router-signature), we can keep removing
     * things. If emit_ed_sigs is true, we also keep 2 additional chunks at the
     * end for the ed25519 signature. */
    const int required_chunks = emit_ed_sigs ? 4 : 2;
    if (smartlist_len(chunks) > required_chunks) {
      /* We remove the next-to-last or 4th-last element (remember, len-1 is the
       * last element), since we need to keep the router-signature elements. */
      int idx = smartlist_len(chunks) - required_chunks;
      char *e = smartlist_get(chunks, idx);
      smartlist_del_keeporder(chunks, idx);
      log_warn(LD_GENERAL, "We just generated an extra-info descriptor "
                           "with statistics that exceeds the 50 KB "
                           "upload limit. Removing last added "
                           "statistics.");
      tor_free(e);
      tor_free(s);
      s = smartlist_join_strings(chunks, "", 0, NULL);
    } else {
      log_warn(LD_BUG, "We just generated an extra-info descriptors that "
                       "exceeds the 50 KB upload limit.");
      goto err;
    }
  }

  rv = extrainfo_dump_to_string_rsa_sig_helper(chunks, ident_key, s);
  if (rv < 0)
    goto err;

  tor_free(s);
  s = smartlist_join_strings(chunks, "", 0, NULL);

  cp = s_dup = tor_strdup(s);
  ei_tmp = extrainfo_parse_entry_from_string(cp, NULL, 1, NULL, NULL);
  if (!ei_tmp) {
    if (write_stats_to_extrainfo) {
      log_warn(LD_GENERAL, "We just generated an extra-info descriptor "
                           "with statistics that we can't parse. Not "
                           "adding statistics to this or any future "
                           "extra-info descriptors.");
      write_stats_to_extrainfo = 0;
      result = extrainfo_dump_to_string(s_out, extrainfo, ident_key,
                                        signing_keypair);
      goto done;
    } else {
      log_warn(LD_BUG, "We just generated an extrainfo descriptor we "
                       "can't parse.");
      goto err;
    }
  }

  *s_out = s;
  s = NULL; /* prevent free */
  result = 0;
  goto done;

 err:
  result = -1;

 done:
  tor_free(s);
  SMARTLIST_FOREACH(chunks, char *, chunk, tor_free(chunk));
  smartlist_free(chunks);
  tor_free(s_dup);
  extrainfo_free(ei_tmp);

  return result;
}

/** A list of nicknames that we've warned about including in our family,
 * for one reason or another. */
static smartlist_t *warned_family = NULL;

/**
 * Return a new smartlist containing the family members configured in
 * <b>options</b>.  Warn about invalid or missing entries.  Return NULL
 * if this relay should not declare a family.
 **/
STATIC smartlist_t *
get_my_declared_family(const or_options_t *options)
{
  if (!options->MyFamily)
    return NULL;

  if (options->BridgeRelay)
    return NULL;

  if (!warned_family)
    warned_family = smartlist_new();

  smartlist_t *declared_family = smartlist_new();
  config_line_t *family;

  /* First we try to get the whole family in the form of hexdigests. */
  for (family = options->MyFamily; family; family = family->next) {
    char *name = family->value;
    const node_t *member;
    if (options->Nickname && !strcasecmp(name, options->Nickname))
      continue; /* Don't list ourself by nickname, that's redundant */
    else
      member = node_get_by_nickname(name, 0);

    if (!member) {
      /* This node doesn't seem to exist, so warn about it if it is not
       * a hexdigest. */
      int is_legal = is_legal_nickname_or_hexdigest(name);
      if (!smartlist_contains_string(warned_family, name) &&
          !is_legal_hexdigest(name)) {
        if (is_legal)
          log_warn(LD_CONFIG,
                   "There is a router named %s in my declared family, but "
                   "I have no descriptor for it. I'll use the nickname "
                   "as is, but this may confuse clients. Please list it "
                   "by identity digest instead.", escaped(name));
        else
          log_warn(LD_CONFIG, "There is a router named %s in my declared "
                   "family, but that isn't a legal digest or nickname. "
                   "Skipping it.", escaped(name));
        smartlist_add_strdup(warned_family, name);
      }
      if (is_legal) {
        smartlist_add_strdup(declared_family, name);
      }
    } else {
      /* List the node by digest. */
      char *fp = tor_malloc(HEX_DIGEST_LEN+2);
      fp[0] = '$';
      base16_encode(fp+1,HEX_DIGEST_LEN+1,
                    member->identity, DIGEST_LEN);
      smartlist_add(declared_family, fp);

      if (! is_legal_hexdigest(name) &&
          !smartlist_contains_string(warned_family, name)) {
        /* Warn if this node was not specified by hexdigest. */
        log_warn(LD_CONFIG, "There is a router named %s in my declared "
                 "family, but it wasn't listed by digest. Please consider "
                 "saying %s instead, if that's what you meant.",
                 escaped(name), fp);
        smartlist_add_strdup(warned_family, name);
      }
    }
  }

  /* Now declared_family should have the closest we can come to the
   * identities that the user wanted.
   *
   * Unlike older versions of Tor, we _do_ include our own identity: this
   * helps microdescriptor compression, and helps in-memory compression
   * on clients. */
  nodefamily_t *nf = nodefamily_from_members(declared_family,
                                     router_get_my_id_digest(),
                                     NF_WARN_MALFORMED,
                                     NULL);
  SMARTLIST_FOREACH(declared_family, char *, s, tor_free(s));
  smartlist_free(declared_family);
  if (!nf) {
    return NULL;
  }

  char *s = nodefamily_format(nf);
  nodefamily_free(nf);

  smartlist_t *result = smartlist_new();
  smartlist_split_string(result, s, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  tor_free(s);

  if (smartlist_len(result) == 1) {
    /* This is a one-element list containing only ourself; instead return
     * nothing */
    const char *singleton = smartlist_get(result, 0);
    bool is_me = false;
    if (singleton[0] == '$') {
      char d[DIGEST_LEN];
      int n = base16_decode(d, sizeof(d), singleton+1, strlen(singleton+1));
      if (n == DIGEST_LEN &&
          fast_memeq(d, router_get_my_id_digest(), DIGEST_LEN)) {
        is_me = true;
      }
    }
    if (!is_me) {
      // LCOV_EXCL_START
      log_warn(LD_BUG, "Found a singleton family list with an element "
               "that wasn't us! Element was %s", escaped(singleton));
      // LCOV_EXCL_STOP
    } else {
      SMARTLIST_FOREACH(result, char *, cp, tor_free(cp));
      smartlist_free(result);
      return NULL;
    }
  }

  return result;
}

/* Like router_check_descriptor_address_consistency, but specifically for the
 * ORPort or DirPort.
 * listener_type is either CONN_TYPE_OR_LISTENER or CONN_TYPE_DIR_LISTENER. */
static void
router_check_descriptor_address_port_consistency(uint32_t ipv4h_desc_addr,
                                                 int listener_type)
{
  tor_assert(listener_type == CONN_TYPE_OR_LISTENER ||
             listener_type == CONN_TYPE_DIR_LISTENER);

  /* The first advertised Port may be the magic constant CFG_AUTO_PORT.
   */
  int port_v4_cfg = get_first_advertised_port_by_type_af(listener_type,
                                                         AF_INET);
  if (port_v4_cfg != 0 &&
      !port_exists_by_type_addr32h_port(listener_type,
                                        ipv4h_desc_addr, port_v4_cfg, 1)) {
        const tor_addr_t *port_addr = get_first_advertised_addr_by_type_af(
                                                                listener_type,
                                                                AF_INET);
        /* If we're building a descriptor with no advertised address,
         * something is terribly wrong. */
        tor_assert(port_addr);

        tor_addr_t desc_addr;
        char port_addr_str[TOR_ADDR_BUF_LEN];
        char desc_addr_str[TOR_ADDR_BUF_LEN];

        tor_addr_to_str(port_addr_str, port_addr, TOR_ADDR_BUF_LEN, 0);

        tor_addr_from_ipv4h(&desc_addr, ipv4h_desc_addr);
        tor_addr_to_str(desc_addr_str, &desc_addr, TOR_ADDR_BUF_LEN, 0);

        const char *listener_str = (listener_type == CONN_TYPE_OR_LISTENER ?
                                    "OR" : "Dir");
        log_warn(LD_CONFIG, "The IPv4 %sPort address %s does not match the "
                 "descriptor address %s. If you have a static public IPv4 "
                 "address, use 'Address <IPv4>' and 'OutboundBindAddress "
                 "<IPv4>'. If you are behind a NAT, use two %sPort lines: "
                 "'%sPort <PublicPort> NoListen' and '%sPort <InternalPort> "
                 "NoAdvertise'.",
                 listener_str, port_addr_str, desc_addr_str, listener_str,
                 listener_str, listener_str);
      }
}

/* Tor relays only have one IPv4 address in the descriptor, which is derived
 * from the Address torrc option, or guessed using various methods in
 * router_pick_published_address().
 * Warn the operator if there is no ORPort on the descriptor address
 * ipv4h_desc_addr.
 * Warn the operator if there is no DirPort on the descriptor address.
 * This catches a few common config errors:
 *  - operators who expect ORPorts and DirPorts to be advertised on the
 *    ports' listen addresses, rather than the torrc Address (or guessed
 *    addresses in the absence of an Address config). This includes
 *    operators who attempt to put their ORPort and DirPort on different
 *    addresses;
 *  - discrepancies between guessed addresses and configured listen
 *    addresses (when the Address option isn't set).
 * If a listener is listening on all IPv4 addresses, it is assumed that it
 * is listening on the configured Address, and no messages are logged.
 * If an operators has specified NoAdvertise ORPorts in a NAT setting,
 * no messages are logged, unless they have specified other advertised
 * addresses.
 * The message tells operators to configure an ORPort and DirPort that match
 * the Address (using NoListen if needed).
 */
static void
router_check_descriptor_address_consistency(uint32_t ipv4h_desc_addr)
{
  router_check_descriptor_address_port_consistency(ipv4h_desc_addr,
                                                   CONN_TYPE_OR_LISTENER);
  router_check_descriptor_address_port_consistency(ipv4h_desc_addr,
                                                   CONN_TYPE_DIR_LISTENER);
}

/** Allocate a fresh, unsigned routerinfo for this OR, without any of the
 * fields that depend on the corresponding extrainfo.
 *
 * On success, set ri_out to the new routerinfo, and return 0.
 * Caller is responsible for freeing the generated routerinfo.
 *
 * Returns a negative value and sets ri_out to NULL on temporary error.
 */
MOCK_IMPL(STATIC int,
router_build_fresh_unsigned_routerinfo,(routerinfo_t **ri_out))
{
  routerinfo_t *ri = NULL;
  uint32_t addr;
  char platform[256];
  int hibernating = we_are_hibernating();
  const or_options_t *options = get_options();
  int result = TOR_ROUTERINFO_ERROR_INTERNAL_BUG;

  if (BUG(!ri_out)) {
    result = TOR_ROUTERINFO_ERROR_INTERNAL_BUG;
    goto err;
  }

  if (router_pick_published_address(options, &addr, 0) < 0) {
    log_warn(LD_CONFIG, "Don't know my address while generating descriptor");
    result = TOR_ROUTERINFO_ERROR_NO_EXT_ADDR;
    goto err;
  }

  /* Log a message if the address in the descriptor doesn't match the ORPort
   * and DirPort addresses configured by the operator. */
  router_check_descriptor_address_consistency(addr);

  ri = tor_malloc_zero(sizeof(routerinfo_t));
  ri->cache_info.routerlist_index = -1;
  ri->nickname = tor_strdup(options->Nickname);
  ri->addr = addr;
  ri->or_port = router_get_advertised_or_port(options);
  ri->dir_port = router_get_advertised_dir_port(options, 0);
  ri->supports_tunnelled_dir_requests =
    directory_permits_begindir_requests(options);
  ri->cache_info.published_on = time(NULL);
  /* get_onion_key() must invoke from main thread */
  router_set_rsa_onion_pkey(get_onion_key(), &ri->onion_pkey,
                            &ri->onion_pkey_len);

  ri->onion_curve25519_pkey =
    tor_memdup(&get_current_curve25519_keypair()->pubkey,
               sizeof(curve25519_public_key_t));

  /* For now, at most one IPv6 or-address is being advertised. */
  {
    const port_cfg_t *ipv6_orport = NULL;
    SMARTLIST_FOREACH_BEGIN(get_configured_ports(), const port_cfg_t *, p) {
      if (p->type == CONN_TYPE_OR_LISTENER &&
          ! p->server_cfg.no_advertise &&
          ! p->server_cfg.bind_ipv4_only &&
          tor_addr_family(&p->addr) == AF_INET6) {
        /* Like IPv4, if the relay is configured using the default
         * authorities, disallow internal IPs. Otherwise, allow them. */
        const int default_auth = using_default_dir_authorities(options);
        if (! tor_addr_is_internal(&p->addr, 0) || ! default_auth) {
          ipv6_orport = p;
          break;
        } else {
          char addrbuf[TOR_ADDR_BUF_LEN];
          log_warn(LD_CONFIG,
                   "Unable to use configured IPv6 address \"%s\" in a "
                   "descriptor. Skipping it. "
                   "Try specifying a globally reachable address explicitly.",
                   tor_addr_to_str(addrbuf, &p->addr, sizeof(addrbuf), 1));
        }
      }
    } SMARTLIST_FOREACH_END(p);
    if (ipv6_orport) {
      tor_addr_copy(&ri->ipv6_addr, &ipv6_orport->addr);
      ri->ipv6_orport = ipv6_orport->port;
    }
  }

  ri->identity_pkey = crypto_pk_dup_key(get_server_identity_key());
  if (BUG(crypto_pk_get_digest(ri->identity_pkey,
                           ri->cache_info.identity_digest) < 0)) {
    result = TOR_ROUTERINFO_ERROR_DIGEST_FAILED;
    goto err;
  }
  ri->cache_info.signing_key_cert =
    tor_cert_dup(get_master_signing_key_cert());

  get_platform_str(platform, sizeof(platform));
  ri->platform = tor_strdup(platform);

  ri->protocol_list = tor_strdup(protover_get_supported_protocols());

  /* compute ri->bandwidthrate as the min of various options */
  ri->bandwidthrate = relay_get_effective_bwrate(options);

  /* and compute ri->bandwidthburst similarly */
  ri->bandwidthburst = relay_get_effective_bwburst(options);

  /* Report bandwidth, unless we're hibernating or shutting down */
  ri->bandwidthcapacity = hibernating ? 0 : rep_hist_bandwidth_assess();

  if (dns_seems_to_be_broken() || has_dns_init_failed()) {
    /* DNS is screwed up; don't claim to be an exit. */
    policies_exit_policy_append_reject_star(&ri->exit_policy);
  } else {
    policies_parse_exit_policy_from_options(options,ri->addr,&ri->ipv6_addr,
                                            &ri->exit_policy);
  }
  ri->policy_is_reject_star =
    policy_is_reject_star(ri->exit_policy, AF_INET, 1) &&
    policy_is_reject_star(ri->exit_policy, AF_INET6, 1);

  if (options->IPv6Exit) {
    char *p_tmp = policy_summarize(ri->exit_policy, AF_INET6);
    if (p_tmp)
      ri->ipv6_exit_policy = parse_short_policy(p_tmp);
    tor_free(p_tmp);
  }

  ri->declared_family = get_my_declared_family(options);

  if (options->BridgeRelay) {
    ri->purpose = ROUTER_PURPOSE_BRIDGE;
    /* Bridges shouldn't be able to send their descriptors unencrypted,
     anyway, since they don't have a DirPort, and always connect to the
     bridge authority anonymously.  But just in case they somehow think of
     sending them on an unencrypted connection, don't allow them to try. */
    ri->cache_info.send_unencrypted = 0;
  } else {
    ri->purpose = ROUTER_PURPOSE_GENERAL;
    ri->cache_info.send_unencrypted = 1;
  }

  goto done;

 err:
  routerinfo_free(ri);
  *ri_out = NULL;
  return result;

 done:
  *ri_out = ri;
  return 0;
}

/** Allocate and return a fresh, unsigned extrainfo for this OR, based on the
 * routerinfo ri.
 *
 * Uses options->Nickname to set the nickname, and options->BridgeRelay to set
 * ei->cache_info.send_unencrypted.
 *
 * If ri is NULL, logs a BUG() warning and returns NULL.
 * Caller is responsible for freeing the generated extrainfo.
 */
static extrainfo_t *
router_build_fresh_unsigned_extrainfo(const routerinfo_t *ri)
{
  extrainfo_t *ei = NULL;
  const or_options_t *options = get_options();

  if (BUG(!ri))
    return NULL;

  /* Now generate the extrainfo. */
  ei = tor_malloc_zero(sizeof(extrainfo_t));
  ei->cache_info.is_extrainfo = 1;
  strlcpy(ei->nickname, options->Nickname, sizeof(ei->nickname));
  ei->cache_info.published_on = ri->cache_info.published_on;
  ei->cache_info.signing_key_cert =
    tor_cert_dup(get_master_signing_key_cert());

  memcpy(ei->cache_info.identity_digest, ri->cache_info.identity_digest,
         DIGEST_LEN);

  if (options->BridgeRelay) {
    /* See note in router_build_fresh_routerinfo(). */
    ei->cache_info.send_unencrypted = 0;
  } else {
    ei->cache_info.send_unencrypted = 1;
  }

  return ei;
}

/** Dump the extrainfo descriptor body for ei, sign it, and add the body and
 * signature to ei->cache_info. Note that the extrainfo body is determined by
 * ei, and some additional config and statistics state: see
 * extrainfo_dump_to_string() for details.
 *
 * Return 0 on success, -1 on temporary error.
 * If ei is NULL, logs a BUG() warning and returns -1.
 * On error, ei->cache_info is not modified.
 */
static int
router_dump_and_sign_extrainfo_descriptor_body(extrainfo_t *ei)
{
  if (BUG(!ei))
    return -1;

  if (extrainfo_dump_to_string(&ei->cache_info.signed_descriptor_body,
                               ei, get_server_identity_key(),
                               get_master_signing_keypair()) < 0) {
    log_warn(LD_BUG, "Couldn't generate extra-info descriptor.");
    return -1;
  }

  ei->cache_info.signed_descriptor_len =
    strlen(ei->cache_info.signed_descriptor_body);

  router_get_extrainfo_hash(ei->cache_info.signed_descriptor_body,
                            ei->cache_info.signed_descriptor_len,
                            ei->cache_info.signed_descriptor_digest);
  crypto_digest256((char*) ei->digest256,
                   ei->cache_info.signed_descriptor_body,
                   ei->cache_info.signed_descriptor_len,
                   DIGEST_SHA256);

  return 0;
}

/** Allocate and return a fresh, signed extrainfo for this OR, based on the
 * routerinfo ri.
 *
 * If ri is NULL, logs a BUG() warning and returns NULL.
 * Caller is responsible for freeing the generated extrainfo.
 */
STATIC extrainfo_t *
router_build_fresh_signed_extrainfo(const routerinfo_t *ri)
{
  int result = -1;
  extrainfo_t *ei = NULL;

  if (BUG(!ri))
    return NULL;

  ei = router_build_fresh_unsigned_extrainfo(ri);
  /* router_build_fresh_unsigned_extrainfo() should not fail. */
  if (BUG(!ei))
    goto err;

  result = router_dump_and_sign_extrainfo_descriptor_body(ei);
  if (result < 0)
    goto err;

  goto done;

 err:
  extrainfo_free(ei);
  return NULL;

 done:
  return ei;
}

/** Set the fields in ri that depend on ei.
 *
 * If ei is NULL, logs a BUG() warning and zeroes the relevant fields.
 */
STATIC void
router_update_routerinfo_from_extrainfo(routerinfo_t *ri,
                                        const extrainfo_t *ei)
{
  if (BUG(!ei)) {
    /* Just to be safe, zero ri->cache_info.extra_info_digest here. */
    memset(ri->cache_info.extra_info_digest, 0, DIGEST_LEN);
    memset(ri->cache_info.extra_info_digest256, 0, DIGEST256_LEN);
    return;
  }

  /* Now finish the router descriptor. */
  memcpy(ri->cache_info.extra_info_digest,
         ei->cache_info.signed_descriptor_digest,
         DIGEST_LEN);
  memcpy(ri->cache_info.extra_info_digest256,
         ei->digest256,
         DIGEST256_LEN);
}

/** Dump the descriptor body for ri, sign it, and add the body and signature to
 * ri->cache_info. Note that the descriptor body is determined by ri, and some
 * additional config and state: see router_dump_router_to_string() for details.
 *
 * Return 0 on success, and a negative value on temporary error.
 * If ri is NULL, logs a BUG() warning and returns a negative value.
 * On error, ri->cache_info is not modified.
 */
STATIC int
router_dump_and_sign_routerinfo_descriptor_body(routerinfo_t *ri)
{
  if (BUG(!ri))
    return TOR_ROUTERINFO_ERROR_INTERNAL_BUG;

  if (! (ri->cache_info.signed_descriptor_body =
          router_dump_router_to_string(ri, get_server_identity_key(),
                                       get_onion_key(),
                                       get_current_curve25519_keypair(),
                                       get_master_signing_keypair())) ) {
    log_warn(LD_BUG, "Couldn't generate router descriptor.");
    return TOR_ROUTERINFO_ERROR_CANNOT_GENERATE;
  }

  ri->cache_info.signed_descriptor_len =
    strlen(ri->cache_info.signed_descriptor_body);

  router_get_router_hash(ri->cache_info.signed_descriptor_body,
                         strlen(ri->cache_info.signed_descriptor_body),
                         ri->cache_info.signed_descriptor_digest);

  return 0;
}

/** Build a fresh routerinfo, signed server descriptor, and signed extrainfo
 * document for this OR.
 *
 * Set r to the generated routerinfo, e to the generated extrainfo document.
 * Failure to generate an extra-info document is not an error and is indicated
 * by setting e to NULL.
 * Return 0 on success, and a negative value on temporary error.
 * Caller is responsible for freeing generated documents on success.
 */
int
router_build_fresh_descriptor(routerinfo_t **r, extrainfo_t **e)
{
  int result = TOR_ROUTERINFO_ERROR_INTERNAL_BUG;
  routerinfo_t *ri = NULL;
  extrainfo_t *ei = NULL;

  if (BUG(!r))
    goto err;

  if (BUG(!e))
    goto err;

  result = router_build_fresh_unsigned_routerinfo(&ri);
  if (result < 0) {
    goto err;
  }
  /* If ri is NULL, then result should be negative. So this check should be
   * unreachable. */
  if (BUG(!ri)) {
    result = TOR_ROUTERINFO_ERROR_INTERNAL_BUG;
    goto err;
  }

  ei = router_build_fresh_signed_extrainfo(ri);

  /* Failing to create an ei is not an error. */
  if (ei) {
    router_update_routerinfo_from_extrainfo(ri, ei);
  }

  result = router_dump_and_sign_routerinfo_descriptor_body(ri);
  if (result < 0)
    goto err;

  if (ei) {
     if (BUG(routerinfo_incompatible_with_extrainfo(ri->identity_pkey, ei,
                                                    &ri->cache_info, NULL))) {
       result = TOR_ROUTERINFO_ERROR_INTERNAL_BUG;
       goto err;
     }
  }

  goto done;

 err:
  routerinfo_free(ri);
  extrainfo_free(ei);
  *r = NULL;
  *e = NULL;
  return result;

 done:
  *r = ri;
  *e = ei;
  return 0;
}

/** If <b>force</b> is true, or our descriptor is out-of-date, rebuild a fresh
 * routerinfo, signed server descriptor, and extra-info document for this OR.
 * Return 0 on success, -1 on temporary error.
 */
int
router_rebuild_descriptor(int force)
{
  int err = 0;
  routerinfo_t *ri;
  extrainfo_t *ei;
  uint32_t addr;
  const or_options_t *options = get_options();

  if (desc_clean_since && !force)
    return 0;

  if (router_pick_published_address(options, &addr, 0) < 0 ||
      router_get_advertised_or_port(options) == 0) {
    /* Stop trying to rebuild our descriptor every second. We'll
     * learn that it's time to try again when ip_address_changed()
     * marks it dirty. */
    desc_clean_since = time(NULL);
    return TOR_ROUTERINFO_ERROR_DESC_REBUILDING;
  }

  log_info(LD_OR, "Rebuilding relay descriptor%s", force ? " (forced)" : "");

  err = router_build_fresh_descriptor(&ri, &ei);
  if (err < 0) {
    return err;
  }

  routerinfo_free(desc_routerinfo);
  desc_routerinfo = ri;
  extrainfo_free(desc_extrainfo);
  desc_extrainfo = ei;

  desc_clean_since = time(NULL);
  desc_needs_upload = 1;
  desc_gen_reason = desc_dirty_reason;
  if (BUG(desc_gen_reason == NULL)) {
    desc_gen_reason = "descriptor was marked dirty earlier, for no reason.";
  }
  desc_dirty_reason = NULL;
  control_event_my_descriptor_changed();
  return 0;
}

/** If our router descriptor ever goes this long without being regenerated
 * because something changed, we force an immediate regenerate-and-upload. */
#define FORCE_REGENERATE_DESCRIPTOR_INTERVAL (18*60*60)

/** If our router descriptor seems to be missing or unacceptable according
 * to the authorities, regenerate and reupload it _this_ often. */
#define FAST_RETRY_DESCRIPTOR_INTERVAL (90*60)

/** Mark descriptor out of date if it's been "too long" since we last tried
 * to upload one. */
void
mark_my_descriptor_dirty_if_too_old(time_t now)
{
  networkstatus_t *ns;
  const routerstatus_t *rs;
  const char *retry_fast_reason = NULL; /* Set if we should retry frequently */
  const time_t slow_cutoff = now - FORCE_REGENERATE_DESCRIPTOR_INTERVAL;
  const time_t fast_cutoff = now - FAST_RETRY_DESCRIPTOR_INTERVAL;

  /* If it's already dirty, don't mark it. */
  if (! desc_clean_since)
    return;

  /* If it's older than FORCE_REGENERATE_DESCRIPTOR_INTERVAL, it's always
   * time to rebuild it. */
  if (desc_clean_since < slow_cutoff) {
    mark_my_descriptor_dirty("time for new descriptor");
    return;
  }
  /* Now we see whether we want to be retrying frequently or no.  The
   * rule here is that we'll retry frequently if we aren't listed in the
   * live consensus we have, or if the publication time of the
   * descriptor listed for us in the consensus is very old, or if the
   * consensus lists us as "stale" and we haven't regenerated since the
   * consensus was published. */
  ns = networkstatus_get_live_consensus(now);
  if (ns) {
    rs = networkstatus_vote_find_entry(ns,
                                       (const char*)router_get_my_id_digest());
    if (rs == NULL)
      retry_fast_reason = "not listed in consensus";
    else if (rs->published_on < slow_cutoff)
      retry_fast_reason = "version listed in consensus is quite old";
    else if (rs->is_staledesc && ns->valid_after > desc_clean_since)
      retry_fast_reason = "listed as stale in consensus";
  }

  if (retry_fast_reason && desc_clean_since < fast_cutoff)
    mark_my_descriptor_dirty(retry_fast_reason);
}

/** Call when the current descriptor is out of date. */
void
mark_my_descriptor_dirty(const char *reason)
{
  const or_options_t *options = get_options();
  if (BUG(reason == NULL)) {
    reason = "marked descriptor dirty for unspecified reason";
  }
  if (server_mode(options) && options->PublishServerDescriptor_)
    log_info(LD_OR, "Decided to publish new relay descriptor: %s", reason);
  desc_clean_since = 0;
  if (!desc_dirty_reason)
    desc_dirty_reason = reason;
}

/** OR only: If <b>force</b> is true, or we haven't uploaded this
 * descriptor successfully yet, try to upload our signed descriptor to
 * all the directory servers we know about.
 */
void
router_upload_dir_desc_to_dirservers(int force)
{
  const routerinfo_t *ri;
  extrainfo_t *ei;
  char *msg;
  size_t desc_len, extra_len = 0, total_len;
  dirinfo_type_t auth = get_options()->PublishServerDescriptor_;

  ri = router_get_my_routerinfo();
  if (!ri) {
    log_info(LD_GENERAL, "No descriptor; skipping upload");
    return;
  }
  ei = router_get_my_extrainfo();
  if (auth == NO_DIRINFO)
    return;
  if (!force && !desc_needs_upload)
    return;

  log_info(LD_OR, "Uploading relay descriptor to directory authorities%s",
           force ? " (forced)" : "");

  desc_needs_upload = 0;

  desc_len = ri->cache_info.signed_descriptor_len;
  extra_len = ei ? ei->cache_info.signed_descriptor_len : 0;
  total_len = desc_len + extra_len + 1;
  msg = tor_malloc(total_len);
  memcpy(msg, ri->cache_info.signed_descriptor_body, desc_len);
  if (ei) {
    memcpy(msg+desc_len, ei->cache_info.signed_descriptor_body, extra_len);
  }
  msg[desc_len+extra_len] = 0;

  directory_post_to_dirservers(DIR_PURPOSE_UPLOAD_DIR,
                               (auth & BRIDGE_DIRINFO) ?
                                 ROUTER_PURPOSE_BRIDGE :
                                 ROUTER_PURPOSE_GENERAL,
                               auth, msg, desc_len, extra_len);
  tor_free(msg);
}

/** Return a routerinfo for this OR, rebuilding a fresh one if
 * necessary.  Return NULL on error, or if called on an OP. */
MOCK_IMPL(const routerinfo_t *,
router_get_my_routerinfo,(void))
{
  return router_get_my_routerinfo_with_err(NULL);
}

/** Return routerinfo of this OR. Rebuild it from
 * scratch if needed. Set <b>*err</b> to 0 on success or to
 * appropriate TOR_ROUTERINFO_ERROR_* value on failure.
 */
MOCK_IMPL(const routerinfo_t *,
router_get_my_routerinfo_with_err,(int *err))
{
  if (!server_mode(get_options())) {
    if (err)
      *err = TOR_ROUTERINFO_ERROR_NOT_A_SERVER;

    return NULL;
  }

  if (!desc_clean_since) {
    int rebuild_err = router_rebuild_descriptor(0);
    if (rebuild_err < 0) {
      if (err)
        *err = rebuild_err;

      return NULL;
    }
  }

  if (!desc_routerinfo) {
    if (err)
      *err = TOR_ROUTERINFO_ERROR_DESC_REBUILDING;

    return NULL;
  }

  if (err)
    *err = 0;

  return desc_routerinfo;
}

/** OR only: Return a signed server descriptor for this OR, rebuilding a fresh
 * one if necessary.  Return NULL on error.
 */
const char *
router_get_my_descriptor(void)
{
  const char *body;
  const routerinfo_t *me = router_get_my_routerinfo();
  if (! me)
    return NULL;
  tor_assert(me->cache_info.saved_location == SAVED_NOWHERE);
  body = signed_descriptor_get_body(&me->cache_info);
  /* Make sure this is nul-terminated. */
  tor_assert(!body[me->cache_info.signed_descriptor_len]);
  log_debug(LD_GENERAL,"my desc is '%s'", body);
  return body;
}

/** Return the extrainfo document for this OR, or NULL if we have none.
 * Rebuilt it (and the server descriptor) if necessary. */
extrainfo_t *
router_get_my_extrainfo(void)
{
  if (!server_mode(get_options()))
    return NULL;
  if (router_rebuild_descriptor(0))
    return NULL;
  return desc_extrainfo;
}

/** Return a human-readable string describing what triggered us to generate
 * our current descriptor, or NULL if we don't know. */
const char *
router_get_descriptor_gen_reason(void)
{
  return desc_gen_reason;
}

/** Forget that we have issued any router-related warnings, so that we'll
 * warn again if we see the same errors. */
void
router_reset_warnings(void)
{
  if (warned_family) {
    SMARTLIST_FOREACH(warned_family, char *, cp, tor_free(cp));
    smartlist_clear(warned_family);
  }
}

/**
 * Release all storage held in descmgr.c
 **/
void
makedesc_free_all(void)
{
  routerinfo_free(desc_routerinfo);
  extrainfo_free(desc_extrainfo);

  if (warned_family) {
    SMARTLIST_FOREACH(warned_family, char *, cp, tor_free(cp));
    smartlist_free(warned_family);
  }
}
