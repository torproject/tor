/**
 * orkeygen.c 
 * Key generation utility. 
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/01/04 07:19:27  badbytes
 * Key generation utility.
 *
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>

int main(int argc, char *argv[])
{

  char *file_pr = argv[1];
  char *file_pu = argv[2];
  
  FILE *f_pr = NULL;
  FILE *f_pu = NULL;
  
  RSA *rsa_key = NULL;
 
  int retval = 0;
  
  
  if (argc < 3)
  {
    printf("Need two files, for private and public key in that order.\n");
    exit(1);
  }
  
  /* generate the key */
  rsa_key = RSA_generate_key(1024,65535,NULL,NULL);
  if (!rsa_key) /* error has occured */
  {
    printf("%s",ERR_reason_error_string(ERR_get_error()));
    exit(1);
  }
  else /* keys generated */
  {
    retval = RSA_check_key(rsa_key);
    if (retval == 1)
    {
      printf("Generated key seems to be valid.\n");
      /* open the output files */
      f_pr = fopen(file_pr,"w");
      if (!f_pr)
      {
	perror("fopen");
	RSA_free(rsa_key);
	exit(1);
      }
      
      f_pu = fopen(file_pu,"w");
      if (!f_pu)
      {
	perror("fopen");
	RSA_free(rsa_key);
	exit(1);
      }
      
      /* write the private key */
      retval = PEM_write_RSAPrivateKey(f_pr,rsa_key,NULL,NULL,0,0,NULL);
      if (retval == 0)
      {
	printf("%s",ERR_reason_error_string(ERR_get_error()));
	fclose(f_pr);
	fclose(f_pu);
	RSA_free(rsa_key);
	exit(1);
      }
      
      /* write the public key */
      retval = PEM_write_RSAPublicKey(f_pu,rsa_key);
      if (retval == 0)
      {
	printf("%s",ERR_reason_error_string(ERR_get_error()));
	fclose(f_pr);
	fclose(f_pu);
	RSA_free(rsa_key);
	exit(1);
      }
      
      printf("Keys written to files %s (public) and %s (private).\n",file_pu,file_pr);
    }
    else if (retval == 0)
    {
      printf("Generated key seems to be invalid. Exiting.\n");
      RSA_free(rsa_key);
      exit(1);
    }
    else if (retval == -1)
    {
      printf("%s",ERR_reason_error_string(ERR_get_error()));
      RSA_free(rsa_key);
      exit(1);
    }
  }
     
  RSA_free(rsa_key);
  fclose(f_pu);
  fclose(f_pr);
  exit(0);
  
 }
