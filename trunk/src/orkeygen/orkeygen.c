/**
 * orkeygen.c 
 * Key generation utility. 
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.3  2002/09/24 10:43:57  arma
 * laying the groundwork for dynamic router lists
 *
 * revamped the router reading section
 *
 * reference counting for crypto pk env's (so we can dup them)
 *
 * we now read and write pem pk keys from string rather than from FILE*,
 *   in anticipation of fetching directories over a socket
 *   (so now on startup we slurp in the whole file, then parse it as a string)
 *
 * fixed a bug in the proxy side, where you could get some circuits
 *   wedged if they showed up while the connection was being made
 *
 * Revision 1.2  2002/07/25 08:18:05  badbytes
 * Updated to use crypto.h instead of OpenSSL.
 *
 * Revision 1.1.1.1  2002/06/26 22:45:50  arma
 * initial commit: current code
 *
 * Revision 1.1  2002/01/04 07:19:27  badbytes
 * Key generation utility.
 *
 *
 */

/* likely obsoleted by:
 *
 * openssl genrsa -out private.pem 1024
 * openssl rsa -in private.pem -pubout -out public.pem
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include "../common/crypto.h"

int main(int argc, char *argv[])
{

  char *file_pr = argv[1];
  char *file_pu = argv[2];
  
  FILE *f_pr = NULL;
  FILE *f_pu = NULL;
  
  crypto_pk_env_t *env;
 
  int retval = 0;
  
  
  if (argc < 3)
  {
    printf("Need two files, for private and public key in that order.\n");
    exit(1);
  }
  
  crypto_global_init();
  
  env = crypto_new_pk_env(CRYPTO_PK_RSA);
  if (!env)
  {
    printf("Could not create a crypto environment.");
    exit(1);
  }
  
  /* generate the key */
  if (crypto_pk_generate_key(env)) /* error has occured */
  {
    printf("%s",crypto_perror());
    exit(1);
  }
  else /* keys generated */
  {
    retval = crypto_pk_check_key(env);
    if (retval == 1)
    {
      printf("Generated key seems to be valid.\n");
      /* open the output files */
      f_pr = fopen(file_pr,"w");
      if (!f_pr)
      {
	perror("fopen");
	crypto_free_pk_env(env);
	exit(1);
      }
      
      f_pu = fopen(file_pu,"w");
      if (!f_pu)
      {
	perror("fopen");
	crypto_free_pk_env(env);
	exit(1);
      }
      
      /* write the private key */
      if (crypto_pk_write_private_key_to_file(env, f_pr) == -1)
      {
	printf("%s",crypto_perror());
	fclose(f_pr);
	fclose(f_pu);
        crypto_free_pk_env(env);
	exit(1);
      }
      
      /* write the public key */
      if (crypto_pk_write_public_key_to_file(env, f_pu) == -1)
      {
	printf("%s",crypto_perror());
	fclose(f_pr);
	fclose(f_pu);
        crypto_free_pk_env(env);
	exit(1);
      }
      
      printf("Keys written to files %s (public) and %s (private).\n",file_pu,file_pr);
    }
    else if (retval == 0)
    {
      printf("Generated key seems to be invalid. Exiting.\n");
      crypto_free_pk_env(env);
      exit(1);
    }
    else if (retval == -1)
    {
      printf("%s",crypto_perror());
      crypto_free_pk_env(env);
      exit(1);
    }
  }
     
  crypto_free_pk_env(env);
  crypto_global_cleanup();
  fclose(f_pu);
  fclose(f_pr);
  exit(0);
  
 }
