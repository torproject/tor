/**
 * key.c 
 * Key management.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.5  2002/03/12 23:28:26  mp292
 * Removed calls to ERR_load_crypto_strings() (libcrypt).
 *
 * Revision 1.4  2002/01/27 19:23:03  mp292
 * Fixed a bug in parameter checking.
 *
 * Revision 1.3  2002/01/26 18:50:11  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2002/01/04 07:19:03  badbytes
 * Key generation moved to a separate utility (orkeygen).
 *
 * Revision 1.1  2001/12/14 12:16:33  badbytes
 * Added routine for reading a private key from a file.
 *
 */

#include <string.h>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "key.h"
#include "log.h"
#include "config.h"

RSA *load_prkey(unsigned char *keyfile)
{
  RSA *rsa_private=NULL;
  FILE *f_pr;
  int retval = 0;
  
  if (keyfile) /* non-NULL filename */
  {
    if (strspn(keyfile,CONFIG_LEGAL_FILENAME_CHARACTERS) == strlen(keyfile)) /* filename contains legal characters only */
    {
      /* open the keyfile */
      f_pr=fopen(keyfile,"r");
      if (!f_pr)
      {
	log(LOG_ERR,"Failed to open keyfile %s.",keyfile);
	return NULL;
      }
      
      /* read the private key */
      rsa_private = PEM_read_RSAPrivateKey(f_pr,&rsa_private,NULL,NULL);
      fclose(f_pr);
      if (!rsa_private)
      {
	log(LOG_ERR,"Error reading private key : %s",ERR_reason_error_string(ERR_get_error()));
	return NULL;
      }
      
      /* check the private key */
      retval = RSA_check_key(rsa_private);
      if (retval == 0)
      {
	log(LOG_ERR,"Private key read but is invalid : %s.", ERR_reason_error_string(ERR_get_error()));
	RSA_free(rsa_private);
	return NULL;
      }
      else if (retval == -1)
      {
	log(LOG_ERR,"Private key read but validity checking failed : %s",ERR_reason_error_string(ERR_get_error()));
	RSA_free(rsa_private);
	return NULL;
      }
      else if (retval == 1)
      {
	return rsa_private;
      }
    } /* filename contains legal characters only */
  }
  
  return NULL; /* report error */
}
