/* Copyright (c) 2003, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tortls.c
 * \brief Wrapper functions to present a consistent interface to
 * TLS, SSL, and X.509 functions from OpenSSL.
 **/

/* (Unlike other tor functions, these
 * are prefixed with tor_ in order to avoid conflicting with OpenSSL
 * functions and variables.)
 */

#include "orconfig.h"

#if defined (WINCE)
#include <WinSock2.h>
#endif

#include <assert.h>
#ifdef MS_WINDOWS /*wrkard for dtls1.h >= 0.9.8m of "#include <winsock.h>"*/
 #define WIN32_WINNT 0x400
 #define _WIN32_WINNT 0x400
 #define WIN32_LEAN_AND_MEAN
 #if defined(_MSC_VER) && (_MSC_VER < 1300)
    #include <winsock.h>
 #else
    #include <winsock2.h>
    #include <ws2tcpip.h>
 #endif
#endif
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x00907000l
#error "We require OpenSSL >= 0.9.7"
#endif

#define CRYPTO_PRIVATE /* to import prototypes from crypto.h */

#include "crypto.h"
#include "tortls.h"
#include "util.h"
#include "torlog.h"
#include "container.h"
#include "ht.h"
#include <string.h>

/* Enable the "v2" TLS handshake.
 */
#define V2_HANDSHAKE_SERVER
#define V2_HANDSHAKE_CLIENT

/* Copied from or.h */
#define LEGAL_NICKNAME_CHARACTERS \
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

/** How long do identity certificates live? (sec) */
#define IDENTITY_CERT_LIFETIME  (365*24*60*60)

#define ADDR(tls) (((tls) && (tls)->address) ? tls->address : "peer")

/* We redefine these so that we can run correctly even if the vendor gives us
 * a version of OpenSSL that does not match its header files.  (Apple: I am
 * looking at you.)
 */
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x00040000L
#endif
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x0010
#endif

/** Does the run-time openssl version look like we need
 * SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_op = 0;
/** Does the run-time openssl version look like we need
 * SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_flag = 0;

/** Holds a SSL_CTX object and related state used to configure TLS
 * connections.
 */
typedef struct tor_tls_context_t {
  int refcnt;
  SSL_CTX *ctx;
  X509 *my_cert;
  X509 *my_id_cert;
  crypto_pk_env_t *key;
} tor_tls_context_t;

/** Holds a SSL object and its associated data.  Members are only
 * accessed from within tortls.c.
 */
struct tor_tls_t {
  HT_ENTRY(tor_tls_t) node;
  tor_tls_context_t *context; /** A link to the context object for this tls. */
  SSL *ssl; /**< An OpenSSL SSL object. */
  int socket; /**< The underlying file descriptor for this TLS connection. */
  char *address; /**< An address to log when describing this connection. */
  enum {
    TOR_TLS_ST_HANDSHAKE, TOR_TLS_ST_OPEN, TOR_TLS_ST_GOTCLOSE,
    TOR_TLS_ST_SENTCLOSE, TOR_TLS_ST_CLOSED, TOR_TLS_ST_RENEGOTIATE,
  } state : 3; /**< The current SSL state, depending on which operations have
                * completed successfully. */
  unsigned int isServer:1; /**< True iff this is a server-side connection */
  unsigned int wasV2Handshake:1; /**< True iff the original handshake for
                                  * this connection used the updated version
                                  * of the connection protocol (client sends
                                  * different cipher list, server sends only
                                  * one certificate). */
 /** True iff we should call negotiated_callback when we're done reading. */
  unsigned int got_renegotiate:1;
  size_t wantwrite_n; /**< 0 normally, >0 if we returned wantwrite last
                       * time. */
  /** Last values retrieved from BIO_number_read()/write(); see
   * tor_tls_get_n_raw_bytes() for usage.
   */
  unsigned long last_write_count;
  unsigned long last_read_count;
  /** If set, a callback to invoke whenever the client tries to renegotiate
   * the handshake. */
  void (*negotiated_callback)(tor_tls_t *tls, void *arg);
  /** Argument to pass to negotiated_callback. */
  void *callback_arg;
};

#ifdef V2_HANDSHAKE_CLIENT
/** An array of fake SSL_CIPHER objects that we use in order to trick OpenSSL
 * in client mode into advertising the ciphers we want.  See
 * rectify_client_ciphers() for details. */
static SSL_CIPHER *CLIENT_CIPHER_DUMMIES = NULL;
/** A stack of SSL_CIPHER objects, some real, some fake.
 * See rectify_client_ciphers() for details. */
static STACK_OF(SSL_CIPHER) *CLIENT_CIPHER_STACK = NULL;
#endif

/** Helper: compare tor_tls_t objects by its SSL. */
static INLINE int
tor_tls_entries_eq(const tor_tls_t *a, const tor_tls_t *b)
{
  return a->ssl == b->ssl;
}

/** Helper: return a hash value for a tor_tls_t by its SSL. */
static INLINE unsigned int
tor_tls_entry_hash(const tor_tls_t *a)
{
#if SIZEOF_INT == SIZEOF_VOID_P
  return ((unsigned int)(uintptr_t)a->ssl);
#else
  return (unsigned int) ((((uint64_t)a->ssl)>>2) & UINT_MAX);
#endif
}

/** Map from SSL* pointers to tor_tls_t objects using those pointers.
 */
static HT_HEAD(tlsmap, tor_tls_t) tlsmap_root = HT_INITIALIZER();

HT_PROTOTYPE(tlsmap, tor_tls_t, node, tor_tls_entry_hash,
             tor_tls_entries_eq)
HT_GENERATE(tlsmap, tor_tls_t, node, tor_tls_entry_hash,
            tor_tls_entries_eq, 0.6, malloc, realloc, free)

/** Helper: given a SSL* pointer, return the tor_tls_t object using that
 * pointer. */
static INLINE tor_tls_t *
tor_tls_get_by_ssl(const SSL *ssl)
{
  tor_tls_t search, *result;
  memset(&search, 0, sizeof(search));
  search.ssl = (SSL*)ssl;
  result = HT_FIND(tlsmap, &tlsmap_root, &search);
  return result;
}

static void tor_tls_context_decref(tor_tls_context_t *ctx);
static void tor_tls_context_incref(tor_tls_context_t *ctx);
static X509* tor_tls_create_certificate(crypto_pk_env_t *rsa,
                                        crypto_pk_env_t *rsa_sign,
                                        const char *cname,
                                        const char *cname_sign,
                                        unsigned int lifetime);
static void tor_tls_unblock_renegotiation(tor_tls_t *tls);
static tor_tls_context_t *tor_tls_context_new(crypto_pk_env_t *identity,
                                              unsigned int key_lifetime);

/** Global tls context. We keep it here because nobody else needs to
 * touch it. */
static tor_tls_context_t *global_tls_context = NULL;
/** True iff tor_tls_init() has been called. */
static int tls_library_is_initialized = 0;

/* Module-internal error codes. */
#define _TOR_TLS_SYSCALL    (_MIN_TOR_TLS_ERROR_VAL - 2)
#define _TOR_TLS_ZERORETURN (_MIN_TOR_TLS_ERROR_VAL - 1)

#include "tortls_states.h"

/** Return the symbolic name of an OpenSSL state. */
static const char *
ssl_state_to_string(int ssl_state)
{
  static char buf[40];
  int i;
  for (i = 0; state_map[i].name; ++i) {
    if (state_map[i].state == ssl_state)
      return state_map[i].name;
  }
  tor_snprintf(buf, sizeof(buf), "Unknown state %d", ssl_state);
  return buf;
}

/** Log all pending tls errors at level <b>severity</b>.  Use
 * <b>doing</b> to describe our current activities.
 */
static void
tls_log_errors(tor_tls_t *tls, int severity, int domain, const char *doing)
{
  const char *state = NULL;
  int st;
  unsigned long err;
  const char *msg, *lib, *func, *addr;
  addr = tls ? tls->address : NULL;
  st = (tls && tls->ssl) ? tls->ssl->state : -1;
  while ((err = ERR_get_error()) != 0) {
    msg = (const char*)ERR_reason_error_string(err);
    lib = (const char*)ERR_lib_error_string(err);
    func = (const char*)ERR_func_error_string(err);
    if (!state)
      state = (st>=0)?ssl_state_to_string(st):"---";
    if (!msg) msg = "(null)";
    if (!lib) lib = "(null)";
    if (!func) func = "(null)";
    if (doing) {
      log(severity, domain, "TLS error while %s%s%s: %s (in %s:%s:%s)",
          doing, addr?" with ":"", addr?addr:"",
          msg, lib, func, state);
    } else {
      log(severity, domain, "TLS error%s%s: %s (in %s:%s:%s)",
          addr?" with ":"", addr?addr:"",
          msg, lib, func, state);
    }
  }
}

/** Convert an errno (or a WSAerrno on windows) into a TOR_TLS_* error
 * code. */
static int
tor_errno_to_tls_error(int e)
{
#if defined(MS_WINDOWS)
  switch (e) {
    case WSAECONNRESET: // most common
      return TOR_TLS_ERROR_CONNRESET;
    case WSAETIMEDOUT:
      return TOR_TLS_ERROR_TIMEOUT;
    case WSAENETUNREACH:
    case WSAEHOSTUNREACH:
      return TOR_TLS_ERROR_NO_ROUTE;
    case WSAECONNREFUSED:
      return TOR_TLS_ERROR_CONNREFUSED; // least common
    default:
      return TOR_TLS_ERROR_MISC;
  }
#else
  switch (e) {
    case ECONNRESET: // most common
      return TOR_TLS_ERROR_CONNRESET;
    case ETIMEDOUT:
      return TOR_TLS_ERROR_TIMEOUT;
    case EHOSTUNREACH:
    case ENETUNREACH:
      return TOR_TLS_ERROR_NO_ROUTE;
    case ECONNREFUSED:
      return TOR_TLS_ERROR_CONNREFUSED; // least common
    default:
      return TOR_TLS_ERROR_MISC;
  }
#endif
}

/** Given a TOR_TLS_* error code, return a string equivalent. */
const char *
tor_tls_err_to_string(int err)
{
  if (err >= 0)
    return "[Not an error.]";
  switch (err) {
    case TOR_TLS_ERROR_MISC: return "misc error";
    case TOR_TLS_ERROR_IO: return "unexpected close";
    case TOR_TLS_ERROR_CONNREFUSED: return "connection refused";
    case TOR_TLS_ERROR_CONNRESET: return "connection reset";
    case TOR_TLS_ERROR_NO_ROUTE: return "host unreachable";
    case TOR_TLS_ERROR_TIMEOUT: return "connection timed out";
    case TOR_TLS_CLOSE: return "closed";
    case TOR_TLS_WANTREAD: return "want to read";
    case TOR_TLS_WANTWRITE: return "want to write";
    default: return "(unknown error code)";
  }
}

#define CATCH_SYSCALL 1
#define CATCH_ZERO    2

/** Given a TLS object and the result of an SSL_* call, use
 * SSL_get_error to determine whether an error has occurred, and if so
 * which one.  Return one of TOR_TLS_{DONE|WANTREAD|WANTWRITE|ERROR}.
 * If extra&CATCH_SYSCALL is true, return _TOR_TLS_SYSCALL instead of
 * reporting syscall errors.  If extra&CATCH_ZERO is true, return
 * _TOR_TLS_ZERORETURN instead of reporting zero-return errors.
 *
 * If an error has occurred, log it at level <b>severity</b> and describe the
 * current action as <b>doing</b>.
 */
static int
tor_tls_get_error(tor_tls_t *tls, int r, int extra,
                  const char *doing, int severity, int domain)
{
  int err = SSL_get_error(tls->ssl, r);
  int tor_error = TOR_TLS_ERROR_MISC;
  switch (err) {
    case SSL_ERROR_NONE:
      return TOR_TLS_DONE;
    case SSL_ERROR_WANT_READ:
      return TOR_TLS_WANTREAD;
    case SSL_ERROR_WANT_WRITE:
      return TOR_TLS_WANTWRITE;
    case SSL_ERROR_SYSCALL:
      if (extra&CATCH_SYSCALL)
        return _TOR_TLS_SYSCALL;
      if (r == 0) {
        log(severity, LD_NET, "TLS error: unexpected close while %s (%s)",
            doing, ssl_state_to_string(tls->ssl->state));
        tor_error = TOR_TLS_ERROR_IO;
      } else {
        int e = tor_socket_errno(tls->socket);
        log(severity, LD_NET,
            "TLS error: <syscall error while %s> (errno=%d: %s; state=%s)",
            doing, e, tor_socket_strerror(e),
            ssl_state_to_string(tls->ssl->state));
        tor_error = tor_errno_to_tls_error(e);
      }
      tls_log_errors(tls, severity, domain, doing);
      return tor_error;
    case SSL_ERROR_ZERO_RETURN:
      if (extra&CATCH_ZERO)
        return _TOR_TLS_ZERORETURN;
      log(severity, LD_NET, "TLS connection closed while %s in state %s",
          doing, ssl_state_to_string(tls->ssl->state));
      tls_log_errors(tls, severity, domain, doing);
      return TOR_TLS_CLOSE;
    default:
      tls_log_errors(tls, severity, domain, doing);
      return TOR_TLS_ERROR_MISC;
  }
}

/** Initialize OpenSSL, unless it has already been initialized.
 */
static void
tor_tls_init(void)
{
  if (!tls_library_is_initialized) {
    long version;
    SSL_library_init();
    SSL_load_error_strings();

    version = SSLeay();

    /* OpenSSL 0.9.8l introduced SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
     * here, but without thinking too hard about it: it turns out that the
     * flag in question needed to be set at the last minute, and that it
     * conflicted with an existing flag number that had already been added
     * in the OpenSSL 1.0.0 betas.  OpenSSL 0.9.8m thoughtfully replaced
     * the flag with an option and (it seems) broke anything that used
     * SSL3_FLAGS_* for the purpose.  So we need to know how to do both,
     * and we mustn't use the SSL3_FLAGS option with anything besides
     * OpenSSL 0.9.8l.
     *
     * No, we can't just set flag 0x0010 everywhere.  It breaks Tor with
     * OpenSSL 1.0.0beta3 and later.  On the other hand, we might be able to
     * set option 0x00040000L everywhere.
     *
     * No, we can't simply detect whether the flag or the option is present
     * in the headers at build-time: some vendors (notably Apple) like to
     * leave their headers out of sync with their libraries.
     *
     * Yes, it _is_ almost as if the OpenSSL developers decided that no
     * program should be allowed to use renegotiation unless it first passed
     * a test of intelligence and determination.
     */
    if (version >= 0x009080c0L && version < 0x009080d0L) {
      log_notice(LD_GENERAL, "OpenSSL %s looks like version 0.9.8l; "
                 "I will try SSL3_FLAGS to enable renegotation.",
                 SSLeay_version(SSLEAY_VERSION));
      use_unsafe_renegotiation_flag = 1;
      use_unsafe_renegotiation_op = 1;
    } else if (version >= 0x009080d0L) {
      log_notice(LD_GENERAL, "OpenSSL %s looks like version 0.9.8m or later; "
                 "I will try SSL_OP to enable renegotiation",
                 SSLeay_version(SSLEAY_VERSION));
      use_unsafe_renegotiation_op = 1;
    } else if (version < 0x009080c0L) {
      log_notice(LD_GENERAL, "OpenSSL %s [%lx] looks like it's older than "
                 "0.9.8l, but some vendors have backported 0.9.8l's "
                 "renegotiation code to earlier versions, and some have "
                 "backported the code from 0.9.8m or 0.9.8n.  I'll set both "
                 "SSL3_FLAGS and SSL_OP just to be safe.",
                 SSLeay_version(SSLEAY_VERSION), version);
      use_unsafe_renegotiation_flag = 1;
      use_unsafe_renegotiation_op = 1;
    } else {
      log_info(LD_GENERAL, "OpenSSL %s has version %lx",
               SSLeay_version(SSLEAY_VERSION), version);
    }

    tls_library_is_initialized = 1;
  }
}

/** Free all global TLS structures. */
void
tor_tls_free_all(void)
{
  if (global_tls_context) {
    tor_tls_context_decref(global_tls_context);
    global_tls_context = NULL;
  }
  if (!HT_EMPTY(&tlsmap_root)) {
    log_warn(LD_MM, "Still have entries in the tlsmap at shutdown.");
  }
  HT_CLEAR(tlsmap, &tlsmap_root);
#ifdef V2_HANDSHAKE_CLIENT
  if (CLIENT_CIPHER_DUMMIES)
    tor_free(CLIENT_CIPHER_DUMMIES);
  if (CLIENT_CIPHER_STACK)
    sk_SSL_CIPHER_free(CLIENT_CIPHER_STACK);
#endif
}

/** We need to give OpenSSL a callback to verify certificates. This is
 * it: We always accept peer certs and complete the handshake.  We
 * don't validate them until later.
 */
static int
always_accept_verify_cb(int preverify_ok,
                        X509_STORE_CTX *x509_ctx)
{
  (void) preverify_ok;
  (void) x509_ctx;
  return 1;
}

/** Return a newly allocated X509 name with commonName <b>cname</b>. */
static X509_NAME *
tor_x509_name_new(const char *cname)
{
  int nid;
  X509_NAME *name;
  if (!(name = X509_NAME_new()))
    return NULL;
  if ((nid = OBJ_txt2nid("commonName")) == NID_undef) goto error;
  if (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
                                   (unsigned char*)cname, -1, -1, 0)))
    goto error;
  return name;
 error:
  X509_NAME_free(name);
  return NULL;
}

/** Generate and sign an X509 certificate with the public key <b>rsa</b>,
 * signed by the private key <b>rsa_sign</b>.  The commonName of the
 * certificate will be <b>cname</b>; the commonName of the issuer will be
 * <b>cname_sign</b>. The cert will be valid for <b>cert_lifetime</b> seconds
 * starting from now.  Return a certificate on success, NULL on
 * failure.
 */
static X509 *
tor_tls_create_certificate(crypto_pk_env_t *rsa,
                           crypto_pk_env_t *rsa_sign,
                           const char *cname,
                           const char *cname_sign,
                           unsigned int cert_lifetime)
{
  time_t start_time, end_time;
  EVP_PKEY *sign_pkey = NULL, *pkey=NULL;
  X509 *x509 = NULL;
  X509_NAME *name = NULL, *name_issuer=NULL;

  tor_tls_init();

  start_time = time(NULL);

  tor_assert(rsa);
  tor_assert(cname);
  tor_assert(rsa_sign);
  tor_assert(cname_sign);
  if (!(sign_pkey = _crypto_pk_env_get_evp_pkey(rsa_sign,1)))
    goto error;
  if (!(pkey = _crypto_pk_env_get_evp_pkey(rsa,0)))
    goto error;
  if (!(x509 = X509_new()))
    goto error;
  if (!(X509_set_version(x509, 2)))
    goto error;
  if (!(ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)start_time)))
    goto error;

  if (!(name = tor_x509_name_new(cname)))
    goto error;
  if (!(X509_set_subject_name(x509, name)))
    goto error;
  if (!(name_issuer = tor_x509_name_new(cname_sign)))
    goto error;
  if (!(X509_set_issuer_name(x509, name_issuer)))
    goto error;

  if (!X509_time_adj(X509_get_notBefore(x509),0,&start_time))
    goto error;
  end_time = start_time + cert_lifetime;
  if (!X509_time_adj(X509_get_notAfter(x509),0,&end_time))
    goto error;
  if (!X509_set_pubkey(x509, pkey))
    goto error;
  if (!X509_sign(x509, sign_pkey, EVP_sha1()))
    goto error;

  goto done;
 error:
  if (x509) {
    X509_free(x509);
    x509 = NULL;
  }
 done:
  tls_log_errors(NULL, LOG_WARN, LD_NET, "generating certificate");
  if (sign_pkey)
    EVP_PKEY_free(sign_pkey);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (name)
    X509_NAME_free(name);
  if (name_issuer)
    X509_NAME_free(name_issuer);
  return x509;
}

/** List of ciphers that servers should select from.*/
#define SERVER_CIPHER_LIST                         \
  (TLS1_TXT_DHE_RSA_WITH_AES_256_SHA ":"           \
   TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":"           \
   SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA)
/* Note: to set up your own private testing network with link crypto
 * disabled, set your Tors' cipher list to
 * (SSL3_TXT_RSA_NULL_SHA).  If you do this, you won't be able to communicate
 * with any of the "real" Tors, though. */

#ifdef V2_HANDSHAKE_CLIENT
#define CIPHER(id, name) name ":"
#define XCIPHER(id, name)
/** List of ciphers that clients should advertise, omitting items that
 * our OpenSSL doesn't know about. */
static const char CLIENT_CIPHER_LIST[] =
#include "./ciphers.inc"
  ;
#undef CIPHER
#undef XCIPHER

/** Holds a cipher that we want to advertise, and its 2-byte ID. */
typedef struct cipher_info_t { unsigned id; const char *name; } cipher_info_t;
/** A list of all the ciphers that clients should advertise, including items
 * that OpenSSL might not know about. */
static const cipher_info_t CLIENT_CIPHER_INFO_LIST[] = {
#define CIPHER(id, name) { id, name },
#define XCIPHER(id, name) { id, #name },
#include "./ciphers.inc"
#undef CIPHER
#undef XCIPHER
};

/** The length of CLIENT_CIPHER_INFO_LIST and CLIENT_CIPHER_DUMMIES. */
static const int N_CLIENT_CIPHERS =
  sizeof(CLIENT_CIPHER_INFO_LIST)/sizeof(CLIENT_CIPHER_INFO_LIST[0]);
#endif

#ifndef V2_HANDSHAKE_CLIENT
#undef CLIENT_CIPHER_LIST
#define CLIENT_CIPHER_LIST  (TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":"      \
                             SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA)
#endif

/** Remove a reference to <b>ctx</b>, and free it if it has no more
 * references. */
static void
tor_tls_context_decref(tor_tls_context_t *ctx)
{
  tor_assert(ctx);
  if (--ctx->refcnt == 0) {
    SSL_CTX_free(ctx->ctx);
    X509_free(ctx->my_cert);
    X509_free(ctx->my_id_cert);
    crypto_free_pk_env(ctx->key);
    tor_free(ctx);
  }
}

/** Increase the reference count of <b>ctx</b>. */
static void
tor_tls_context_incref(tor_tls_context_t *ctx)
{
  ++ctx->refcnt;
}

/** Create a new global TLS context.
 *
 * You can call this function multiple times.  Each time you call it,
 * it generates new certificates; all new connections will use
 * the new SSL context.
 */
int
tor_tls_context_init(crypto_pk_env_t *identity, unsigned int key_lifetime)
{
  tor_tls_context_t *new_ctx = tor_tls_context_new(identity,
                                                   key_lifetime);
  tor_tls_context_t *old_ctx = global_tls_context;

  if (new_ctx != NULL) {
    global_tls_context = new_ctx;

    /* Free the old context if one existed. */
    if (old_ctx != NULL) {
      /* This is safe even if there are open connections: we reference-
       * count tor_tls_context_t objects. */
      tor_tls_context_decref(old_ctx);
    }
  }

  return ((new_ctx != NULL) ? 0 : -1);
}

/** Create a new TLS context for use with Tor TLS handshakes.
 * <b>identity</b> should be set to the identity key used to sign the
 * certificate.
 */
static tor_tls_context_t *
tor_tls_context_new(crypto_pk_env_t *identity, unsigned int key_lifetime)
{
  crypto_pk_env_t *rsa = NULL;
  EVP_PKEY *pkey = NULL;
  tor_tls_context_t *result = NULL;
  X509 *cert = NULL, *idcert = NULL;
  char *nickname = NULL, *nn2 = NULL;

  tor_tls_init();
  nickname = crypto_random_hostname(8, 20, "www.", ".net");
  nn2 = crypto_random_hostname(8, 20, "www.", ".net");

  /* Generate short-term RSA key. */
  if (!(rsa = crypto_new_pk_env()))
    goto error;
  if (crypto_pk_generate_key(rsa)<0)
    goto error;
  /* Create certificate signed by identity key. */
  cert = tor_tls_create_certificate(rsa, identity, nickname, nn2,
                                    key_lifetime);
  /* Create self-signed certificate for identity key. */
  idcert = tor_tls_create_certificate(identity, identity, nn2, nn2,
                                      IDENTITY_CERT_LIFETIME);
  if (!cert || !idcert) {
    log(LOG_WARN, LD_CRYPTO, "Error creating certificate");
    goto error;
  }

  result = tor_malloc_zero(sizeof(tor_tls_context_t));
  result->refcnt = 1;
  result->my_cert = X509_dup(cert);
  result->my_id_cert = X509_dup(idcert);
  result->key = crypto_pk_dup_key(rsa);

#ifdef EVERYONE_HAS_AES
  /* Tell OpenSSL to only use TLS1 */
  if (!(result->ctx = SSL_CTX_new(TLSv1_method())))
    goto error;
#else
  /* Tell OpenSSL to use SSL3 or TLS1 but not SSL2. */
  if (!(result->ctx = SSL_CTX_new(SSLv23_method())))
    goto error;
  SSL_CTX_set_options(result->ctx, SSL_OP_NO_SSLv2);
#endif
  SSL_CTX_set_options(result->ctx, SSL_OP_SINGLE_DH_USE);

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  SSL_CTX_set_options(result->ctx,
                      SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif
  /* Yes, we know what we are doing here.  No, we do not treat a renegotiation
   * as authenticating any earlier-received data.
   */
  if (use_unsafe_renegotiation_op) {
    SSL_CTX_set_options(result->ctx,
                        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  }
  /* Don't actually allow compression; it uses ram and time, but the data
   * we transmit is all encrypted anyway. */
  if (result->ctx->comp_methods)
    result->ctx->comp_methods = NULL;
#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_CTX_set_mode(result->ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
  if (cert && !SSL_CTX_use_certificate(result->ctx,cert))
    goto error;
  X509_free(cert); /* We just added a reference to cert. */
  cert=NULL;
  if (idcert) {
    X509_STORE *s = SSL_CTX_get_cert_store(result->ctx);
    tor_assert(s);
    X509_STORE_add_cert(s, idcert);
    X509_free(idcert); /* The context now owns the reference to idcert */
    idcert = NULL;
  }
  SSL_CTX_set_session_cache_mode(result->ctx, SSL_SESS_CACHE_OFF);
  tor_assert(rsa);
  if (!(pkey = _crypto_pk_env_get_evp_pkey(rsa,1)))
    goto error;
  if (!SSL_CTX_use_PrivateKey(result->ctx, pkey))
    goto error;
  EVP_PKEY_free(pkey);
  pkey = NULL;
  if (!SSL_CTX_check_private_key(result->ctx))
    goto error;
  {
    crypto_dh_env_t *dh = crypto_dh_new();
    SSL_CTX_set_tmp_dh(result->ctx, _crypto_dh_env_get_dh(dh));
    crypto_dh_free(dh);
  }
  SSL_CTX_set_verify(result->ctx, SSL_VERIFY_PEER,
                     always_accept_verify_cb);
  /* let us realloc bufs that we're writing from */
  SSL_CTX_set_mode(result->ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

  if (rsa)
    crypto_free_pk_env(rsa);
  tor_free(nickname);
  tor_free(nn2);
  return result;

 error:
  tls_log_errors(NULL, LOG_WARN, LD_NET, "creating TLS context");
  tor_free(nickname);
  tor_free(nn2);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (rsa)
    crypto_free_pk_env(rsa);
  if (result)
    tor_tls_context_decref(result);
  if (cert)
    X509_free(cert);
  if (idcert)
    X509_free(idcert);
  return NULL;
}

#ifdef V2_HANDSHAKE_SERVER
/** Return true iff the cipher list suggested by the client for <b>ssl</b> is
 * a list that indicates that the client knows how to do the v2 TLS connection
 * handshake. */
static int
tor_tls_client_is_using_v2_ciphers(const SSL *ssl, const char *address)
{
  int i;
  SSL_SESSION *session;
  /* If we reached this point, we just got a client hello.  See if there is
   * a cipher list. */
  if (!(session = SSL_get_session((SSL *)ssl))) {
    log_info(LD_NET, "No session on TLS?");
    return 0;
  }
  if (!session->ciphers) {
    log_info(LD_NET, "No ciphers on session");
    return 0;
  }
  /* Now we need to see if there are any ciphers whose presence means we're
   * dealing with an updated Tor. */
  for (i = 0; i < sk_SSL_CIPHER_num(session->ciphers); ++i) {
    SSL_CIPHER *cipher = sk_SSL_CIPHER_value(session->ciphers, i);
    const char *ciphername = SSL_CIPHER_get_name(cipher);
    if (strcmp(ciphername, TLS1_TXT_DHE_RSA_WITH_AES_128_SHA) &&
        strcmp(ciphername, TLS1_TXT_DHE_RSA_WITH_AES_256_SHA) &&
        strcmp(ciphername, SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA) &&
        strcmp(ciphername, "(NONE)")) {
      log_debug(LD_NET, "Got a non-version-1 cipher called '%s'", ciphername);
      // return 1;
      goto dump_list;
    }
  }
  return 0;
 dump_list:
  {
    smartlist_t *elts = smartlist_create();
    char *s;
    for (i = 0; i < sk_SSL_CIPHER_num(session->ciphers); ++i) {
      SSL_CIPHER *cipher = sk_SSL_CIPHER_value(session->ciphers, i);
      const char *ciphername = SSL_CIPHER_get_name(cipher);
      smartlist_add(elts, (char*)ciphername);
    }
    s = smartlist_join_strings(elts, ":", 0, NULL);
    log_debug(LD_NET, "Got a non-version-1 cipher list from %s.  It is: '%s'",
              address, s);
    tor_free(s);
    smartlist_free(elts);
  }
  return 1;
}

/** Invoked when we're accepting a connection on <b>ssl</b>, and the connection
 * changes state. We use this:
 * <ul><li>To alter the state of the handshake partway through, so we
 *         do not send or request extra certificates in v2 handshakes.</li>
 * <li>To detect renegotiation</li></ul>
 */
static void
tor_tls_server_info_callback(const SSL *ssl, int type, int val)
{
  tor_tls_t *tls;
  (void) val;
  if (type != SSL_CB_ACCEPT_LOOP)
    return;
  if (ssl->state != SSL3_ST_SW_SRVR_HELLO_A)
    return;

  tls = tor_tls_get_by_ssl(ssl);
  if (tls) {
    /* Check whether we're watching for renegotiates.  If so, this is one! */
    if (tls->negotiated_callback)
      tls->got_renegotiate = 1;
  } else {
    log_warn(LD_BUG, "Couldn't look up the tls for an SSL*. How odd!");
  }

  /* Now check the cipher list. */
  if (tor_tls_client_is_using_v2_ciphers(ssl, ADDR(tls))) {
    /*XXXX_TLS keep this from happening more than once! */

    /* Yes, we're casting away the const from ssl.  This is very naughty of us.
     * Let's hope openssl doesn't notice! */

    /* Set SSL_MODE_NO_AUTO_CHAIN to keep from sending back any extra certs. */
    SSL_set_mode((SSL*) ssl, SSL_MODE_NO_AUTO_CHAIN);
    /* Don't send a hello request. */
    SSL_set_verify((SSL*) ssl, SSL_VERIFY_NONE, NULL);

    if (tls) {
      tls->wasV2Handshake = 1;
    } else {
      log_warn(LD_BUG, "Couldn't look up the tls for an SSL*. How odd!");
    }
  }
}
#endif

/** Replace *<b>ciphers</b> with a new list of SSL ciphersuites: specifically,
 * a list designed to mimic a common web browser.  Some of the ciphers in the
 * list won't actually be implemented by OpenSSL: that's okay so long as the
 * server doesn't select them, and the server won't select anything besides
 * what's in SERVER_CIPHER_LIST.
 *
 * [If the server <b>does</b> select a bogus cipher, we won't crash or
 * anything; we'll just fail later when we try to look up the cipher in
 * ssl->cipher_list_by_id.]
 */
static void
rectify_client_ciphers(STACK_OF(SSL_CIPHER) **ciphers)
{
#ifdef V2_HANDSHAKE_CLIENT
  if (PREDICT_UNLIKELY(!CLIENT_CIPHER_STACK)) {
    /* We need to set CLIENT_CIPHER_STACK to an array of the ciphers
     * we want.*/
    int i = 0, j = 0;

    /* First, create a dummy SSL_CIPHER for every cipher. */
    CLIENT_CIPHER_DUMMIES =
      tor_malloc_zero(sizeof(SSL_CIPHER)*N_CLIENT_CIPHERS);
    for (i=0; i < N_CLIENT_CIPHERS; ++i) {
      CLIENT_CIPHER_DUMMIES[i].valid = 1;
      CLIENT_CIPHER_DUMMIES[i].id = CLIENT_CIPHER_INFO_LIST[i].id | (3<<24);
      CLIENT_CIPHER_DUMMIES[i].name = CLIENT_CIPHER_INFO_LIST[i].name;
    }

    CLIENT_CIPHER_STACK = sk_SSL_CIPHER_new_null();
    tor_assert(CLIENT_CIPHER_STACK);

    log_debug(LD_NET, "List was: %s", CLIENT_CIPHER_LIST);
    for (j = 0; j < sk_SSL_CIPHER_num(*ciphers); ++j) {
      SSL_CIPHER *cipher = sk_SSL_CIPHER_value(*ciphers, j);
      log_debug(LD_NET, "Cipher %d: %lx %s", j, cipher->id, cipher->name);
    }

    /* Then copy as many ciphers as we can from the good list, inserting
     * dummies as needed. */
    j=0;
    for (i = 0; i < N_CLIENT_CIPHERS; ) {
      SSL_CIPHER *cipher = NULL;
      if (j < sk_SSL_CIPHER_num(*ciphers))
        cipher = sk_SSL_CIPHER_value(*ciphers, j);
      if (cipher && ((cipher->id >> 24) & 0xff) != 3) {
        log_debug(LD_NET, "Skipping v2 cipher %s", cipher->name);
        ++j;
      } else if (cipher &&
                 (cipher->id & 0xffff) == CLIENT_CIPHER_INFO_LIST[i].id) {
        log_debug(LD_NET, "Found cipher %s", cipher->name);
        sk_SSL_CIPHER_push(CLIENT_CIPHER_STACK, cipher);
        ++j;
        ++i;
      } else {
        log_debug(LD_NET, "Inserting fake %s", CLIENT_CIPHER_DUMMIES[i].name);
        sk_SSL_CIPHER_push(CLIENT_CIPHER_STACK, &CLIENT_CIPHER_DUMMIES[i]);
        ++i;
      }
    }
  }

  sk_SSL_CIPHER_free(*ciphers);
  *ciphers = sk_SSL_CIPHER_dup(CLIENT_CIPHER_STACK);
  tor_assert(*ciphers);

#else
    (void)ciphers;
#endif
}

/** Create a new TLS object from a file descriptor, and a flag to
 * determine whether it is functioning as a server.
 */
tor_tls_t *
tor_tls_new(int sock, int isServer)
{
  BIO *bio = NULL;
  tor_tls_t *result = tor_malloc_zero(sizeof(tor_tls_t));

  tor_assert(global_tls_context); /* make sure somebody made it first */
  if (!(result->ssl = SSL_new(global_tls_context->ctx))) {
    tls_log_errors(NULL, LOG_WARN, LD_NET, "creating SSL object");
    tor_free(result);
    return NULL;
  }

#ifdef SSL_set_tlsext_host_name
  /* Browsers use the TLS hostname extension, so we should too. */
  {
    char *fake_hostname = crypto_random_hostname(4,25, "www.",".com");
    SSL_set_tlsext_host_name(result->ssl, fake_hostname);
    tor_free(fake_hostname);
  }
#endif

  if (!SSL_set_cipher_list(result->ssl,
                     isServer ? SERVER_CIPHER_LIST : CLIENT_CIPHER_LIST)) {
    tls_log_errors(NULL, LOG_WARN, LD_NET, "setting ciphers");
#ifdef SSL_set_tlsext_host_name
    SSL_set_tlsext_host_name(result->ssl, NULL);
#endif
    SSL_free(result->ssl);
    tor_free(result);
    return NULL;
  }
  if (!isServer)
    rectify_client_ciphers(&result->ssl->cipher_list);
  result->socket = sock;
  bio = BIO_new_socket(sock, BIO_NOCLOSE);
  if (! bio) {
    tls_log_errors(NULL, LOG_WARN, LD_NET, "opening BIO");
#ifdef SSL_set_tlsext_host_name
    SSL_set_tlsext_host_name(result->ssl, NULL);
#endif
    SSL_free(result->ssl);
    tor_free(result);
    return NULL;
  }
  HT_INSERT(tlsmap, &tlsmap_root, result);
  SSL_set_bio(result->ssl, bio, bio);
  tor_tls_context_incref(global_tls_context);
  result->context = global_tls_context;
  result->state = TOR_TLS_ST_HANDSHAKE;
  result->isServer = isServer;
  result->wantwrite_n = 0;
  result->last_write_count = BIO_number_written(bio);
  result->last_read_count = BIO_number_read(bio);
  if (result->last_write_count || result->last_read_count) {
    log_warn(LD_NET, "Newly created BIO has read count %lu, write count %lu",
             result->last_read_count, result->last_write_count);
  }
#ifdef V2_HANDSHAKE_SERVER
  if (isServer) {
    SSL_set_info_callback(result->ssl, tor_tls_server_info_callback);
  }
#endif

  /* Not expected to get called. */
  tls_log_errors(NULL, LOG_WARN, LD_NET, "creating tor_tls_t object");
  return result;
}

/** Make future log messages about <b>tls</b> display the address
 * <b>address</b>.
 */
void
tor_tls_set_logged_address(tor_tls_t *tls, const char *address)
{
  tor_assert(tls);
  tor_free(tls->address);
  tls->address = tor_strdup(address);
}

/** Set <b>cb</b> to be called with argument <b>arg</b> whenever <b>tls</b>
 * next gets a client-side renegotiate in the middle of a read.  Do not
 * invoke this function until <em>after</em> initial handshaking is done!
 */
void
tor_tls_set_renegotiate_callback(tor_tls_t *tls,
                                 void (*cb)(tor_tls_t *, void *arg),
                                 void *arg)
{
  tls->negotiated_callback = cb;
  tls->callback_arg = arg;
  tls->got_renegotiate = 0;
#ifdef V2_HANDSHAKE_SERVER
  if (cb) {
    SSL_set_info_callback(tls->ssl, tor_tls_server_info_callback);
  } else {
    SSL_set_info_callback(tls->ssl, NULL);
  }
#endif
}

/** If this version of openssl requires it, turn on renegotiation on
 * <b>tls</b>.
 */
static void
tor_tls_unblock_renegotiation(tor_tls_t *tls)
{
  /* Yes, we know what we are doing here.  No, we do not treat a renegotiation
   * as authenticating any earlier-received data. */
  if (use_unsafe_renegotiation_flag) {
    tls->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
  }
  if (use_unsafe_renegotiation_op) {
    SSL_set_options(tls->ssl,
                    SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
  }
}

/** If this version of openssl supports it, turn off renegotiation on
 * <b>tls</b>.  (Our protocol never requires this for security, but it's nice
 * to use belt-and-suspenders here.)
 */
void
tor_tls_block_renegotiation(tor_tls_t *tls)
{
  tls->ssl->s3->flags &= ~SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
}

/** Return whether this tls initiated the connect (client) or
 * received it (server). */
int
tor_tls_is_server(tor_tls_t *tls)
{
  tor_assert(tls);
  return tls->isServer;
}

/** Release resources associated with a TLS object.  Does not close the
 * underlying file descriptor.
 */
void
tor_tls_free(tor_tls_t *tls)
{
  tor_tls_t *removed;
  if (!tls)
    return;
  tor_assert(tls->ssl);
  removed = HT_REMOVE(tlsmap, &tlsmap_root, tls);
  if (!removed) {
    log_warn(LD_BUG, "Freeing a TLS that was not in the ssl->tls map.");
  }
#ifdef SSL_set_tlsext_host_name
  SSL_set_tlsext_host_name(tls->ssl, NULL);
#endif
  SSL_free(tls->ssl);
  tls->ssl = NULL;
  tls->negotiated_callback = NULL;
  if (tls->context)
    tor_tls_context_decref(tls->context);
  tor_free(tls->address);
  tor_free(tls);
}

/** Underlying function for TLS reading.  Reads up to <b>len</b>
 * characters from <b>tls</b> into <b>cp</b>.  On success, returns the
 * number of characters read.  On failure, returns TOR_TLS_ERROR,
 * TOR_TLS_CLOSE, TOR_TLS_WANTREAD, or TOR_TLS_WANTWRITE.
 */
int
tor_tls_read(tor_tls_t *tls, char *cp, size_t len)
{
  int r, err;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_OPEN);
  tor_assert(len<INT_MAX);
  r = SSL_read(tls->ssl, cp, (int)len);
  if (r > 0) {
#ifdef V2_HANDSHAKE_SERVER
    if (tls->got_renegotiate) {
      /* Renegotiation happened! */
      log_info(LD_NET, "Got a TLS renegotiation from %s", ADDR(tls));
      if (tls->negotiated_callback)
        tls->negotiated_callback(tls, tls->callback_arg);
      tls->got_renegotiate = 0;
    }
#endif
    return r;
  }
  err = tor_tls_get_error(tls, r, CATCH_ZERO, "reading", LOG_DEBUG, LD_NET);
  if (err == _TOR_TLS_ZERORETURN || err == TOR_TLS_CLOSE) {
    log_debug(LD_NET,"read returned r=%d; TLS is closed",r);
    tls->state = TOR_TLS_ST_CLOSED;
    return TOR_TLS_CLOSE;
  } else {
    tor_assert(err != TOR_TLS_DONE);
    log_debug(LD_NET,"read returned r=%d, err=%d",r,err);
    return err;
  }
}

/** Underlying function for TLS writing.  Write up to <b>n</b>
 * characters from <b>cp</b> onto <b>tls</b>.  On success, returns the
 * number of characters written.  On failure, returns TOR_TLS_ERROR,
 * TOR_TLS_WANTREAD, or TOR_TLS_WANTWRITE.
 */
int
tor_tls_write(tor_tls_t *tls, const char *cp, size_t n)
{
  int r, err;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_OPEN);
  tor_assert(n < INT_MAX);
  if (n == 0)
    return 0;
  if (tls->wantwrite_n) {
    /* if WANTWRITE last time, we must use the _same_ n as before */
    tor_assert(n >= tls->wantwrite_n);
    log_debug(LD_NET,"resuming pending-write, (%d to flush, reusing %d)",
              (int)n, (int)tls->wantwrite_n);
    n = tls->wantwrite_n;
    tls->wantwrite_n = 0;
  }
  r = SSL_write(tls->ssl, cp, (int)n);
  err = tor_tls_get_error(tls, r, 0, "writing", LOG_INFO, LD_NET);
  if (err == TOR_TLS_DONE) {
    return r;
  }
  if (err == TOR_TLS_WANTWRITE || err == TOR_TLS_WANTREAD) {
    tls->wantwrite_n = n;
  }
  return err;
}

/** Perform initial handshake on <b>tls</b>.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_handshake(tor_tls_t *tls)
{
  int r;
  int oldstate;
  tor_assert(tls);
  tor_assert(tls->ssl);
  tor_assert(tls->state == TOR_TLS_ST_HANDSHAKE);
  check_no_tls_errors();
  oldstate = tls->ssl->state;
  if (tls->isServer) {
    log_debug(LD_HANDSHAKE, "About to call SSL_accept on %p (%s)", tls,
              ssl_state_to_string(tls->ssl->state));
    r = SSL_accept(tls->ssl);
  } else {
    log_debug(LD_HANDSHAKE, "About to call SSL_connect on %p (%s)", tls,
              ssl_state_to_string(tls->ssl->state));
    r = SSL_connect(tls->ssl);
  }
  if (oldstate != tls->ssl->state)
    log_debug(LD_HANDSHAKE, "After call, %p was in state %s",
              tls, ssl_state_to_string(tls->ssl->state));
  /* We need to call this here and not earlier, since OpenSSL has a penchant
   * for clearing its flags when you say accept or connect. */
  tor_tls_unblock_renegotiation(tls);
  r = tor_tls_get_error(tls,r,0, "handshaking", LOG_INFO, LD_HANDSHAKE);
  if (ERR_peek_error() != 0) {
    tls_log_errors(tls, tls->isServer ? LOG_INFO : LOG_WARN, LD_HANDSHAKE,
                   "handshaking");
    return TOR_TLS_ERROR_MISC;
  }
  if (r == TOR_TLS_DONE) {
    tls->state = TOR_TLS_ST_OPEN;
    if (tls->isServer) {
      SSL_set_info_callback(tls->ssl, NULL);
      SSL_set_verify(tls->ssl, SSL_VERIFY_PEER, always_accept_verify_cb);
      /* There doesn't seem to be a clear OpenSSL API to clear mode flags. */
      tls->ssl->mode &= ~SSL_MODE_NO_AUTO_CHAIN;
#ifdef V2_HANDSHAKE_SERVER
      if (tor_tls_client_is_using_v2_ciphers(tls->ssl, ADDR(tls))) {
        /* This check is redundant, but back when we did it in the callback,
         * we might have not been able to look up the tor_tls_t if the code
         * was buggy.  Fixing that. */
        if (!tls->wasV2Handshake) {
          log_warn(LD_BUG, "For some reason, wasV2Handshake didn't"
                   " get set. Fixing that.");
        }
        tls->wasV2Handshake = 1;
        log_debug(LD_HANDSHAKE,
                  "Completed V2 TLS handshake with client; waiting "
                  "for renegotiation.");
      } else {
        tls->wasV2Handshake = 0;
      }
#endif
    } else {
#ifdef V2_HANDSHAKE_CLIENT
      /* If we got no ID cert, we're a v2 handshake. */
      X509 *cert = SSL_get_peer_certificate(tls->ssl);
      STACK_OF(X509) *chain = SSL_get_peer_cert_chain(tls->ssl);
      int n_certs = sk_X509_num(chain);
      if (n_certs > 1 || (n_certs == 1 && cert != sk_X509_value(chain, 0))) {
        log_debug(LD_HANDSHAKE, "Server sent back multiple certificates; it "
                  "looks like a v1 handshake on %p", tls);
        tls->wasV2Handshake = 0;
      } else {
        log_debug(LD_HANDSHAKE,
                  "Server sent back a single certificate; looks like "
                  "a v2 handshake on %p.", tls);
        tls->wasV2Handshake = 1;
      }
      if (cert)
        X509_free(cert);
#endif
      if (SSL_set_cipher_list(tls->ssl, SERVER_CIPHER_LIST) == 0) {
        tls_log_errors(NULL, LOG_WARN, LD_HANDSHAKE, "re-setting ciphers");
        r = TOR_TLS_ERROR_MISC;
      }
    }
  }
  return r;
}

/** Client only: Renegotiate a TLS session.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD, or
 * TOR_TLS_WANTWRITE.
 */
int
tor_tls_renegotiate(tor_tls_t *tls)
{
  int r;
  tor_assert(tls);
  /* We could do server-initiated renegotiation too, but that would be tricky.
   * Instead of "SSL_renegotiate, then SSL_do_handshake until done" */
  tor_assert(!tls->isServer);
  if (tls->state != TOR_TLS_ST_RENEGOTIATE) {
    int r = SSL_renegotiate(tls->ssl);
    if (r <= 0) {
      return tor_tls_get_error(tls, r, 0, "renegotiating", LOG_WARN,
                               LD_HANDSHAKE);
    }
    tls->state = TOR_TLS_ST_RENEGOTIATE;
  }
  r = SSL_do_handshake(tls->ssl);
  if (r == 1) {
    tls->state = TOR_TLS_ST_OPEN;
    return TOR_TLS_DONE;
  } else
    return tor_tls_get_error(tls, r, 0, "renegotiating handshake", LOG_INFO,
                             LD_HANDSHAKE);
}

/** Shut down an open tls connection <b>tls</b>.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_shutdown(tor_tls_t *tls)
{
  int r, err;
  char buf[128];
  tor_assert(tls);
  tor_assert(tls->ssl);

  while (1) {
    if (tls->state == TOR_TLS_ST_SENTCLOSE) {
      /* If we've already called shutdown once to send a close message,
       * we read until the other side has closed too.
       */
      do {
        r = SSL_read(tls->ssl, buf, 128);
      } while (r>0);
      err = tor_tls_get_error(tls, r, CATCH_ZERO, "reading to shut down",
                              LOG_INFO, LD_NET);
      if (err == _TOR_TLS_ZERORETURN) {
        tls->state = TOR_TLS_ST_GOTCLOSE;
        /* fall through... */
      } else {
        return err;
      }
    }

    r = SSL_shutdown(tls->ssl);
    if (r == 1) {
      /* If shutdown returns 1, the connection is entirely closed. */
      tls->state = TOR_TLS_ST_CLOSED;
      return TOR_TLS_DONE;
    }
    err = tor_tls_get_error(tls, r, CATCH_SYSCALL|CATCH_ZERO, "shutting down",
                            LOG_INFO, LD_NET);
    if (err == _TOR_TLS_SYSCALL) {
      /* The underlying TCP connection closed while we were shutting down. */
      tls->state = TOR_TLS_ST_CLOSED;
      return TOR_TLS_DONE;
    } else if (err == _TOR_TLS_ZERORETURN) {
      /* The TLS connection says that it sent a shutdown record, but
       * isn't done shutting down yet.  Make sure that this hasn't
       * happened before, then go back to the start of the function
       * and try to read.
       */
      if (tls->state == TOR_TLS_ST_GOTCLOSE ||
         tls->state == TOR_TLS_ST_SENTCLOSE) {
        log(LOG_WARN, LD_NET,
            "TLS returned \"half-closed\" value while already half-closed");
        return TOR_TLS_ERROR_MISC;
      }
      tls->state = TOR_TLS_ST_SENTCLOSE;
      /* fall through ... */
    } else {
      return err;
    }
  } /* end loop */
}

/** Return true iff this TLS connection is authenticated.
 */
int
tor_tls_peer_has_cert(tor_tls_t *tls)
{
  X509 *cert;
  cert = SSL_get_peer_certificate(tls->ssl);
  tls_log_errors(tls, LOG_WARN, LD_HANDSHAKE, "getting peer certificate");
  if (!cert)
    return 0;
  X509_free(cert);
  return 1;
}

/** Warn that a certificate lifetime extends through a certain range. */
static void
log_cert_lifetime(X509 *cert, const char *problem)
{
  BIO *bio = NULL;
  BUF_MEM *buf;
  char *s1=NULL, *s2=NULL;
  char mytime[33];
  time_t now = time(NULL);
  struct tm tm;

  if (problem)
    log_warn(LD_GENERAL,
             "Certificate %s: is your system clock set incorrectly?",
             problem);

  if (!(bio = BIO_new(BIO_s_mem()))) {
    log_warn(LD_GENERAL, "Couldn't allocate BIO!"); goto end;
  }
  if (!(ASN1_TIME_print(bio, X509_get_notBefore(cert)))) {
    tls_log_errors(NULL, LOG_WARN, LD_NET, "printing certificate lifetime");
    goto end;
  }
  BIO_get_mem_ptr(bio, &buf);
  s1 = tor_strndup(buf->data, buf->length);

  (void)BIO_reset(bio);
  if (!(ASN1_TIME_print(bio, X509_get_notAfter(cert)))) {
    tls_log_errors(NULL, LOG_WARN, LD_NET, "printing certificate lifetime");
    goto end;
  }
  BIO_get_mem_ptr(bio, &buf);
  s2 = tor_strndup(buf->data, buf->length);

  strftime(mytime, 32, "%b %d %H:%M:%S %Y GMT", tor_gmtime_r(&now, &tm));

  log_warn(LD_GENERAL,
           "(certificate lifetime runs from %s through %s. Your time is %s.)",
           s1,s2,mytime);

 end:
  /* Not expected to get invoked */
  tls_log_errors(NULL, LOG_WARN, LD_NET, "getting certificate lifetime");
  if (bio)
    BIO_free(bio);
  tor_free(s1);
  tor_free(s2);
}

/** Helper function: try to extract a link certificate and an identity
 * certificate from <b>tls</b>, and store them in *<b>cert_out</b> and
 * *<b>id_cert_out</b> respectively.  Log all messages at level
 * <b>severity</b>.
 *
 * Note that a reference is added to cert_out, so it needs to be
 * freed. id_cert_out doesn't. */
static void
try_to_extract_certs_from_tls(int severity, tor_tls_t *tls,
                              X509 **cert_out, X509 **id_cert_out)
{
  X509 *cert = NULL, *id_cert = NULL;
  STACK_OF(X509) *chain = NULL;
  int num_in_chain, i;
  *cert_out = *id_cert_out = NULL;

  if (!(cert = SSL_get_peer_certificate(tls->ssl)))
    return;
  *cert_out = cert;
  if (!(chain = SSL_get_peer_cert_chain(tls->ssl)))
    return;
  num_in_chain = sk_X509_num(chain);
  /* 1 means we're receiving (server-side), and it's just the id_cert.
   * 2 means we're connecting (client-side), and it's both the link
   * cert and the id_cert.
   */
  if (num_in_chain < 1) {
    log_fn(severity,LD_PROTOCOL,
           "Unexpected number of certificates in chain (%d)",
           num_in_chain);
    return;
  }
  for (i=0; i<num_in_chain; ++i) {
    id_cert = sk_X509_value(chain, i);
    if (X509_cmp(id_cert, cert) != 0)
      break;
  }
  *id_cert_out = id_cert;
}

/** If the provided tls connection is authenticated and has a
 * certificate chain that is currently valid and signed, then set
 * *<b>identity_key</b> to the identity certificate's key and return
 * 0.  Else, return -1 and log complaints with log-level <b>severity</b>.
 */
int
tor_tls_verify(int severity, tor_tls_t *tls, crypto_pk_env_t **identity_key)
{
  X509 *cert = NULL, *id_cert = NULL;
  EVP_PKEY *id_pkey = NULL;
  RSA *rsa;
  int r = -1;

  *identity_key = NULL;

  try_to_extract_certs_from_tls(severity, tls, &cert, &id_cert);
  if (!cert)
    goto done;
  if (!id_cert) {
    log_fn(severity,LD_PROTOCOL,"No distinct identity certificate found");
    goto done;
  }
  if (!(id_pkey = X509_get_pubkey(id_cert)) ||
      X509_verify(cert, id_pkey) <= 0) {
    log_fn(severity,LD_PROTOCOL,"X509_verify on cert and pkey returned <= 0");
    tls_log_errors(tls, severity, LD_HANDSHAKE, "verifying certificate");
    goto done;
  }

  rsa = EVP_PKEY_get1_RSA(id_pkey);
  if (!rsa)
    goto done;
  *identity_key = _crypto_new_pk_env_rsa(rsa);

  r = 0;

 done:
  if (cert)
    X509_free(cert);
  if (id_pkey)
    EVP_PKEY_free(id_pkey);

  /* This should never get invoked, but let's make sure in case OpenSSL
   * acts unexpectedly. */
  tls_log_errors(tls, LOG_WARN, LD_HANDSHAKE, "finishing tor_tls_verify");

  return r;
}

/** Check whether the certificate set on the connection <b>tls</b> is
 * expired or not-yet-valid, give or take <b>tolerance</b>
 * seconds. Return 0 for valid, -1 for failure.
 *
 * NOTE: you should call tor_tls_verify before tor_tls_check_lifetime.
 */
int
tor_tls_check_lifetime(tor_tls_t *tls, int tolerance)
{
  time_t now, t;
  X509 *cert;
  int r = -1;

  now = time(NULL);

  if (!(cert = SSL_get_peer_certificate(tls->ssl)))
    goto done;

  t = now + tolerance;
  if (X509_cmp_time(X509_get_notBefore(cert), &t) > 0) {
    log_cert_lifetime(cert, "not yet valid");
    goto done;
  }
  t = now - tolerance;
  if (X509_cmp_time(X509_get_notAfter(cert), &t) < 0) {
    log_cert_lifetime(cert, "already expired");
    goto done;
  }

  r = 0;
 done:
  if (cert)
    X509_free(cert);
  /* Not expected to get invoked */
  tls_log_errors(tls, LOG_WARN, LD_NET, "checking certificate lifetime");

  return r;
}

/** Return the number of bytes available for reading from <b>tls</b>.
 */
int
tor_tls_get_pending_bytes(tor_tls_t *tls)
{
  tor_assert(tls);
  return SSL_pending(tls->ssl);
}

/** If <b>tls</b> requires that the next write be of a particular size,
 * return that size.  Otherwise, return 0. */
size_t
tor_tls_get_forced_write_size(tor_tls_t *tls)
{
  return tls->wantwrite_n;
}

/** Sets n_read and n_written to the number of bytes read and written,
 * respectively, on the raw socket used by <b>tls</b> since the last time this
 * function was called on <b>tls</b>. */
void
tor_tls_get_n_raw_bytes(tor_tls_t *tls, size_t *n_read, size_t *n_written)
{
  BIO *wbio, *tmpbio;
  unsigned long r, w;
  r = BIO_number_read(SSL_get_rbio(tls->ssl));
  /* We want the number of bytes actually for real written.  Unfortunately,
   * sometimes OpenSSL replaces the wbio on tls->ssl with a buffering bio,
   * which makes the answer turn out wrong.  Let's cope with that.  Note
   * that this approach will fail if we ever replace tls->ssl's BIOs with
   * buffering bios for reasons of our own.  As an alternative, we could
   * save the original BIO for  tls->ssl in the tor_tls_t structure, but
   * that would be tempting fate. */
  wbio = SSL_get_wbio(tls->ssl);
  if (wbio->method == BIO_f_buffer() && (tmpbio = BIO_next(wbio)) != NULL)
    wbio = tmpbio;
  w = BIO_number_written(wbio);

  /* We are ok with letting these unsigned ints go "negative" here:
   * If we wrapped around, this should still give us the right answer, unless
   * we wrapped around by more than ULONG_MAX since the last time we called
   * this function.
   */
  *n_read = (size_t)(r - tls->last_read_count);
  *n_written = (size_t)(w - tls->last_write_count);
  if (*n_read > INT_MAX || *n_written > INT_MAX) {
    log_warn(LD_BUG, "Preposterously large value in tor_tls_get_n_raw_bytes. "
             "r=%lu, last_read=%lu, w=%lu, last_written=%lu",
             r, tls->last_read_count, w, tls->last_write_count);
  }
  tls->last_read_count = r;
  tls->last_write_count = w;
}

/** Implement check_no_tls_errors: If there are any pending OpenSSL
 * errors, log an error message. */
void
_check_no_tls_errors(const char *fname, int line)
{
  if (ERR_peek_error() == 0)
    return;
  log(LOG_WARN, LD_CRYPTO, "Unhandled OpenSSL errors found at %s:%d: ",
      tor_fix_source_file(fname), line);
  tls_log_errors(NULL, LOG_WARN, LD_NET, NULL);
}

/** Return true iff the initial TLS connection at <b>tls</b> did not use a v2
 * TLS handshake. Output is undefined if the handshake isn't finished. */
int
tor_tls_used_v1_handshake(tor_tls_t *tls)
{
  if (tls->isServer) {
#ifdef V2_HANDSHAKE_SERVER
    return ! tls->wasV2Handshake;
#endif
  } else {
#ifdef V2_HANDSHAKE_CLIENT
    return ! tls->wasV2Handshake;
#endif
  }
  return 1;
}

/** Examine the amount of memory used and available for buffers in <b>tls</b>.
 * Set *<b>rbuf_capacity</b> to the amount of storage allocated for the read
 * buffer and *<b>rbuf_bytes</b> to the amount actually used.
 * Set *<b>wbuf_capacity</b> to the amount of storage allocated for the write
 * buffer and *<b>wbuf_bytes</b> to the amount actually used. */
void
tor_tls_get_buffer_sizes(tor_tls_t *tls,
                         size_t *rbuf_capacity, size_t *rbuf_bytes,
                         size_t *wbuf_capacity, size_t *wbuf_bytes)
{
  if (tls->ssl->s3->rbuf.buf)
    *rbuf_capacity = tls->ssl->s3->rbuf.len;
  else
    *rbuf_capacity = 0;
  if (tls->ssl->s3->wbuf.buf)
    *wbuf_capacity = tls->ssl->s3->wbuf.len;
  else
    *wbuf_capacity = 0;
  *rbuf_bytes = tls->ssl->s3->rbuf.left;
  *wbuf_bytes = tls->ssl->s3->wbuf.left;
}

