/**
 * crypto.c
 * Crypto calls.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 */

#include <malloc.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "../common/log.h"

#include "crypto.h"

int crypt_f(unsigned char *buf, size_t buflen, crypt_path_t **cpath, size_t cpathlen)
{
  int i=0;
  int retval = 0;
  unsigned char *ciphertext = NULL;
  crypt_path_t *thishop;
  
  /* allocate the ciphertext buffer */
  ciphertext = (unsigned char *)malloc(buflen);
  if (!ciphertext)
  {
    log(LOG_ERR,"Error allocating memory.");
    return -1;
  }
  
  for (i=0; i < cpathlen; i++) /* moving from last to first hop 
				* Remember : cpath is in reverse order, i.e. last hop first
				*/
  {
    log(LOG_DEBUG,"crypt_f() : Processing hop %u",cpathlen-i);
    thishop = cpath[i];
    
    /* encrypt */
    retval = EVP_EncryptUpdate(&thishop->f_ctx,ciphertext, &buflen, buf, buflen);
    if (!retval) /* error */
    {
      log(LOG_ERR,"Error performing encryption:%s",ERR_reason_error_string(ERR_get_error()));
      free(ciphertext);
      return -1;
    }
    
    /* copy ciphertext back to buf */
    memcpy((void *)buf,(void *)ciphertext,buflen);
  }
  free((void *)ciphertext);

  return 0;
}
 
int crypt_b(unsigned char *buf, size_t buflen, crypt_path_t **cpath, size_t cpathlen)
{
  int i=0;
  int retval=0;
  unsigned char *plaintext=NULL;
  crypt_path_t *thishop;

  /* allocate the plaintext buffer */
  plaintext = (unsigned char *)malloc(buflen);
  if (!plaintext)
  {
    log(LOG_ERR,"Error allocating memory.");
    return -1;
  }
  
  for (i=cpathlen-1; i >= 0; i--) /* moving from first to last hop 
				* Remember : cpath is in reverse order, i.e. last hop first
				*/
  {
    thishop = cpath[i];
    
    /* encrypt */
    retval = EVP_DecryptUpdate(&thishop->b_ctx,plaintext, &buflen, buf, buflen);
    if (!retval) /* error */
    {
      log(LOG_ERR,"Error performing decryption:%s",ERR_reason_error_string(ERR_get_error()));
      free(plaintext);
      return -1;
    }
    
    /* copy plaintext back to buf */
    memcpy((void *)buf,(void *)plaintext,buflen);
  }
  
  free(plaintext);
  
  return 0;
}
