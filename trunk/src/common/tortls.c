/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

/* TLS wrappers for The Onion Router.  (Unlike other tor functions, these
 * are prefixed with tor_ in order to avoid conflicting with OpenSSL
 * functions and variables.)
 */

#include "./crypto.h"
#include "./tortls.h"
#include "./util.h"
#include "./log.h"

#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/asn1.h>
#include <openssl/bio.h>

struct tor_tls_context_st {
  SSL_CTX *ctx;
};

struct tor_tls_st {
  SSL *ssl;
  int socket;
  enum { 
    TOR_TLS_ST_HANDSHAKE, TOR_TLS_ST_OPEN, TOR_TLS_ST_GOTCLOSE, 
    TOR_TLS_ST_SENTCLOSE, TOR_TLS_ST_CLOSED
  } state;
  int isServer;
};

static X509* tor_tls_create_certificate(crypto_pk_env_t *rsa, 
                                        const char *nickname); 

/* global tls context, keep it here because nobody else needs to touch it */
static tor_tls_context *global_tls_context=NULL;
static int tls_library_is_initialized = 0;

#define _TOR_TLS_SYSCALL    -6
#define _TOR_TLS_ZERORETURN -5


/* These functions are declared in crypto.c but not exported. */
EVP_PKEY *_crypto_pk_env_get_evp_pkey(crypto_pk_env_t *env);
crypto_pk_env_t *_crypto_new_pk_env_rsa(RSA *rsa);

static void
tls_log_error(int severity, const char *doing)
{
  const char *msg = (const char*)ERR_reason_error_string(ERR_get_error());
  if (!msg) msg = "(null)";
  if (doing) {
    log(severity, "TLS error while %s: %s", doing, msg);
  } else {
    log(severity, "TLS error: %s", msg);
  }
}

#define CATCH_SYSCALL 1
#define CATCH_ZERO    2

static int
tor_tls_get_error(tor_tls *tls, int r, int extra,
		  const char *doing, int severity)
{
  int err = SSL_get_error(tls->ssl, r);
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
      log(severity, "TLS error: <syscall error>.");
      return TOR_TLS_ERROR;
    case SSL_ERROR_ZERO_RETURN:
      if (extra&CATCH_ZERO)
	return _TOR_TLS_ZERORETURN;
      log(severity, "TLS error: Zero return");
      return TOR_TLS_ERROR;
    default:
      tls_log_error(severity, doing);
      return TOR_TLS_ERROR;
  }
}

static void
tor_tls_init() {
  if (!tls_library_is_initialized) {
    SSL_library_init();
    SSL_load_error_strings();
    crypto_global_init();
    OpenSSL_add_all_algorithms();
    tls_library_is_initialized = 1;
  }
}

static int always_accept_verify_cb(int preverify_ok, 
                                   X509_STORE_CTX *x509_ctx)
{
  /* We always accept peer certs and complete the handshake.  We don't validate
   * them until later. */
  return 1;
}

/* Generate a self-signed certificate with the private key 'rsa' and
 * commonName 'nickname', and write it, PEM-encoded, to the file named
 * by 'certfile'.  Return 0 on success, -1 for failure.
 */
X509 *
tor_tls_create_certificate(crypto_pk_env_t *rsa, 
                           const char *nickname)
{
  time_t start_time, end_time;
  EVP_PKEY *pkey = NULL;
  X509 *x509 = NULL;
  X509_NAME *name = NULL;
  BIO *out = NULL;
  int nid;
  int err;
  
  tor_tls_init();

  start_time = time(NULL);

  assert(rsa && nickname);
  if (!(pkey = _crypto_pk_env_get_evp_pkey(rsa)))
    return NULL;
  if (!(x509 = X509_new()))
    goto error;
  if (!(X509_set_version(x509, 2)))
    goto error;
  if (!(ASN1_INTEGER_set(X509_get_serialNumber(x509), (long)start_time)))
    goto error;
  
  if (!(name = X509_NAME_new()))
    goto error;
  if ((nid = OBJ_txt2nid("organizationName")) == NID_undef) goto error;
  if (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
                                   "TOR", -1, -1, 0))) goto error;
  if ((nid = OBJ_txt2nid("commonName")) == NID_undef) goto error;
  if (!(X509_NAME_add_entry_by_NID(name, nid, MBSTRING_ASC,
                                   (char*)nickname, -1, -1, 0))) goto error;
  
  if (!(X509_set_issuer_name(x509, name)))
    goto error;
  if (!(X509_set_subject_name(x509, name)))
    goto error;
  if (!X509_time_adj(X509_get_notBefore(x509),0,&start_time))
    goto error;
  end_time = start_time + 24*60*60*365;
  if (!X509_time_adj(X509_get_notAfter(x509),0,&end_time))
    goto error;
  if (!X509_set_pubkey(x509, pkey))
    goto error;
  if (!X509_sign(x509, pkey, EVP_sha1()))
    goto error;

  err = 0;
  goto done;
 error:
  err = 1;
 done:
  if (out)
    BIO_free(out);
  if (x509 && err)
    X509_free(x509);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (name)
    X509_NAME_free(name);
  return x509;
}


#ifdef EVERYONE_HAS_AES
/* Everybody is running OpenSSL 0.9.7 or later, so no backward compatibiliy
 * is needed. */
#define CIPHER_LIST TLS1_TXT_DHE_RSA_WITH_AES_128_SHA
#elif defined(TLS1_TXT_DHE_RSA_WITH_AES_128_SHA)
/* Some people are running OpenSSL before 0.9.7, but we aren't.  
 * We can support AES and 3DES.
 */
#define CIPHER_LIST (TLS1_TXT_DHE_RSA_WITH_AES_128_SHA ":" \
		     SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA)
#else
/* We're running OpenSSL before 0.9.7. We only support 3DES. */
#define CIPHER_LIST SSL3_TXT_EDH_RSA_DES_192_CBC3_SHA
#endif

/* Create a new TLS context.  If we are going to be using it as a
 * server, it must have isServer set to true, certfile set to a
 * filename for a certificate file, and RSA set to the private key
 * used for that certificate. Return -1 if failure, else 0.
 */
int
tor_tls_context_new(crypto_pk_env_t *rsa,
                    int isServer, const char *nickname)
{
  crypto_dh_env_t *dh = NULL;
  EVP_PKEY *pkey = NULL;
  tor_tls_context *result;
  X509 *cert = NULL;
  
  tor_tls_init();

  if (rsa) {
    cert = tor_tls_create_certificate(rsa, nickname);
    if (!cert) {
      log(LOG_ERR, "Error creating certificate");
      return NULL;
    }
  }

  result = tor_malloc(sizeof(tor_tls_context));
  result->ctx = NULL;
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
  if (!SSL_CTX_set_cipher_list(result->ctx, CIPHER_LIST))
    goto error;
  if (cert && !SSL_CTX_use_certificate(result->ctx,cert))
    goto error;
  SSL_CTX_set_session_cache_mode(result->ctx, SSL_SESS_CACHE_OFF);
  if (rsa) {
    if (!(pkey = _crypto_pk_env_get_evp_pkey(rsa)))
      goto error;
    if (!SSL_CTX_use_PrivateKey(result->ctx, pkey))
      goto error;
    EVP_PKEY_free(pkey);
    pkey = NULL;
    if (cert) {
      if (!SSL_CTX_check_private_key(result->ctx))
        goto error;
    }
  }
  dh = crypto_dh_new();
  SSL_CTX_set_tmp_dh(result->ctx, dh->dh);
  crypto_dh_free(dh);
  SSL_CTX_set_verify(result->ctx, SSL_VERIFY_PEER, 
                     always_accept_verify_cb);
  
  global_tls_context = result;
  return 0;

 error:
  if (pkey)
    EVP_PKEY_free(pkey);
  if (dh)
    crypto_dh_free(dh);
  if (result && result->ctx)
    SSL_CTX_free(result->ctx);
  if (result)
    free(result);

  return -1;
}

/* Create a new TLS object from a TLS context, a filedescriptor, and 
 * a flag to determine whether it is functioning as a server.
 */
tor_tls *
tor_tls_new(int sock, int isServer)
{
  tor_tls *result = tor_malloc(sizeof(tor_tls));
  assert(global_tls_context); /* make sure somebody made it first */
  if (!(result->ssl = SSL_new(global_tls_context->ctx)))
    return NULL;
  result->socket = sock;
  SSL_set_fd(result->ssl, sock);
  result->state = TOR_TLS_ST_HANDSHAKE;
  result->isServer = isServer;
  return result;
}

/* Release resources associated with a TLS object.  Does not close the
 * underlying file descriptor.
 */
void
tor_tls_free(tor_tls *tls)
{
  SSL_free(tls->ssl);
  free(tls);
}

/* Underlying function for TLS reading.  Reads up to 'len' characters
 * from 'tls' into 'cp'.  On success, returns the number of characters
 * read.  On failure, returns TOR_TLS_ERROR, TOR_TLS_CLOSE,
 * TOR_TLS_WANTREAD, or TOR_TLS_WANTWRITE.
 */
int
tor_tls_read(tor_tls *tls, char *cp, int len)
{
  int r, err;
  assert(tls && tls->ssl);
  assert(tls->state == TOR_TLS_ST_OPEN);
  r = SSL_read(tls->ssl, cp, len);
  if (r > 0)
    return r;
  err = tor_tls_get_error(tls, r, CATCH_ZERO, "reading", LOG_ERR);
  if (err == _TOR_TLS_ZERORETURN) {
    tls->state = TOR_TLS_ST_CLOSED;
    return TOR_TLS_CLOSE;
  } else {
    assert(err != TOR_TLS_DONE);
    return err;
  }
}

/* Underlying function for TLS writing.  Write up to 'n' characters
 * from 'cp' onto 'tls'.  On success, returns the number of characters
 * written.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD, 
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_write(tor_tls *tls, char *cp, int n)
{
  int r, err;
  assert(tls && tls->ssl);
  assert(tls->state == TOR_TLS_ST_OPEN);
  if (n == 0)
    return 0;
  r = SSL_write(tls->ssl, cp, n);
  err = tor_tls_get_error(tls, r, 0, "writing", LOG_ERR);
  if (err == TOR_TLS_DONE) {
    return r;
  } else {
    return err;
  }  
}

/* Perform initial handshake on 'tls'.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_handshake(tor_tls *tls)
{
  int r;
  assert(tls && tls->ssl);
  assert(tls->state == TOR_TLS_ST_HANDSHAKE);
  if (tls->isServer) {
    r = SSL_accept(tls->ssl);
  } else {
    r = SSL_connect(tls->ssl);
  }
  r = tor_tls_get_error(tls,r,0, "handshaking", LOG_ERR);
  if (r == TOR_TLS_DONE) {
    tls->state = TOR_TLS_ST_OPEN; 
  }
  return r;
}
  
/* Shut down an open tls connection 'tls'.  When finished, returns
 * TOR_TLS_DONE.  On failure, returns TOR_TLS_ERROR, TOR_TLS_WANTREAD,
 * or TOR_TLS_WANTWRITE.
 */
int
tor_tls_shutdown(tor_tls *tls)
{
  int r, err;
  char buf[128];
  assert(tls && tls->ssl);

  while (1) {
    if (tls->state == TOR_TLS_ST_SENTCLOSE) {
      /* If we've already called shutdown once to send a close message,
       * we read until the other side has closed too.
       */
      do {
	r = SSL_read(tls->ssl, buf, 128);
      } while (r>0);
      err = tor_tls_get_error(tls, r, CATCH_ZERO, "reading to shut down", 
			      LOG_ERR);
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
			    LOG_ERR);
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
	log(LOG_ERR, 
	    "TLS returned \"half-closed\" value while already half-closed");
	return TOR_TLS_ERROR;
      }
      tls->state = TOR_TLS_ST_SENTCLOSE;
      /* fall through ... */
    } else {
      return err;
    }
  } /* end loop */
}

/* Return true iff this TLS connection is authenticated.
 */
int
tor_tls_peer_has_cert(tor_tls *tls)
{
  X509 *cert;
  if (!(cert = SSL_get_peer_certificate(tls->ssl)))
    return 0;
  X509_free(cert);
  return 1;
}

/* If the provided tls connection is authenticated and has a
 * certificate that is currently valid and is correctly self-signed,
 * return its public key.  Otherwise return NULL.
 */
crypto_pk_env_t *
tor_tls_verify(tor_tls *tls)
{
  X509 *cert = NULL;
  EVP_PKEY *pkey = NULL;
  RSA *rsa = NULL;
  time_t now;
  crypto_pk_env_t *r = NULL;
  if (!(cert = SSL_get_peer_certificate(tls->ssl)))
    return NULL;
  
  now = time(NULL);
  if (X509_cmp_time(X509_get_notBefore(cert), &now) > 0)
    goto done;
  if (X509_cmp_time(X509_get_notAfter(cert), &now) < 0)
    goto done;
  
  /* Get the public key. */
  if (!(pkey = X509_get_pubkey(cert)))
    goto done;
  if (X509_verify(cert, pkey) <= 0)
    goto done;

  rsa = EVP_PKEY_get1_RSA(pkey);
  EVP_PKEY_free(pkey);
  pkey = NULL;
  if (!rsa)
    goto done;

  r = _crypto_new_pk_env_rsa(rsa);
  rsa = NULL;
  
 done:
  if (cert)
    X509_free(cert);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (rsa)
    RSA_free(rsa);
  return r;
}

