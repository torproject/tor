/**
 * auth.h
 * Key exchange with an onion router.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/03/28 11:00:57  badbytes
 * Key exchange with an onion router.
 *
 */
#include <openssl/rand.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../common/log.h"

#include "auth.h"

/* send session keys and bandwidth info to the router */
int send_auth(int or_sock, uint32_t bandwidth, RSA *pkey, unsigned char *f_session_key, unsigned char *b_session_key)
{
  int retval;
  int x;
  unsigned char message[20]; /* bandwidth(32bits), forward key(64bits), backward key(64bits) */
  unsigned char cipher[128];
  if ((or_sock <= 0) || (bandwidth <= 0) || !pkey || !f_session_key || !b_session_key) /* invalid parameters */
    return -1;
  
  bandwidth = htonl(bandwidth); /* convert to network order */
  
  /* generate the session keys */
  retval = RAND_bytes(f_session_key, 8);
  if (!retval)
  {
    log(LOG_ERR,"Not enough randomness to generate a session key.");
    return -1;
  }
  retval = RAND_bytes(b_session_key, 8);
  if (!retval)
  {
    log(LOG_ERR,"Not enough randomness to generate a session key.");
    return -1;
  }
  
  /* compose the message */
  memcpy((void *)message, (void *)&bandwidth, 4);
  memcpy((void *)(message + 4), (void *)f_session_key, 8);
  memcpy((void *)(message + 12), (void *)b_session_key, 8);
  printf("f_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",f_session_key[x]);
  }
  printf("\nb_session_key: ");
  for(x=0;x<8;x++) {
    printf("%d ",b_session_key[x]);
  }
  printf("\n");
  
  /* encrypt with RSA */
  retval = RSA_public_encrypt(20, message, cipher, pkey, RSA_PKCS1_PADDING);
  if (retval == -1)
  {
    log(LOG_ERR,"Public key encryption failed.");
    return -1;
  }
  
  /* send the ciphertext */
  retval = send(or_sock, cipher, 128, 0);
  if (retval < 128)
  {
    log(LOG_ERR,"Connection to router lost while exchanging session keys.");
    return -1;
  }
  
  return 0;
}
