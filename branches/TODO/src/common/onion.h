/**
 * onion.h 
 * Routines for creating/manipulating onions.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.17  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.16  2002/03/25 09:11:23  badbytes
 * Added a list of onions being tracked for replay attacks.
 *
 * Revision 1.15  2002/01/26 19:24:29  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.14  2002/01/18 20:40:40  mp292
 * Fixed a bug in en/decrypt_onion() functions.
 *
 * Revision 1.13  2002/01/17 23:48:31  mp292
 * Added some extra debugging messages to fix a bug in encrypt_onion() which
 * seems to corrupt the routent *route list.
 *
 * Revision 1.12  2002/01/11 15:47:17  badbytes
 * *** empty log message ***
 *
 * Revision 1.11  2002/01/09 07:55:23  badbytes
 * Ciphers got out of sync. Hopefully fixed.
 *
 * Revision 1.10  2002/01/04 13:48:54  badbytes
 * Changed unsigned short/long to uint16_t and uint32_t respectively.
 *
 * Revision 1.9  2001/12/19 08:29:00  badbytes
 * Macro DEFAULT_CIPHER now holds the default crypto algorithm
 *
 * Revision 1.8  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.7  2001/12/18 07:26:47  badbytes
 * Added a new definition of onion_layer_t, depending on the byte order.
 *
 * Revision 1.6  2001/12/17 13:35:17  badbytes
 * Still writing handle_connection()
 *
 * Revision 1.5  2001/12/14 14:44:37  badbytes
 * chooselen() tested
 *
 * Revision 1.4  2001/12/14 13:31:08  badbytes
 * peel_onion() was redundant, removed it
 *
 * Revision 1.3  2001/12/14 13:14:03  badbytes
 * Split types.h into routent.h and ss.h. Keeping them all in one file created unnecesary dependencies.
 *
 * Revision 1.2  2001/12/14 12:44:47  badbytes
 * Minor modifications to reflect new paths ...
 *
 * Revision 1.1  2001/12/14 12:41:12  badbytes
 * Moved from op/ as it will be reused by other modules.
 *
 * Revision 1.1  2001/12/13 15:15:10  badbytes
 * Started coding the onion proxy.
 *
 */

#ifndef __ONION_H

#include <endian.h>
#include <stdint.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>

#include "routent.h"
#include "version.h"

/* available cipher functions */
#define ONION_CIPHER_IDENTITY 0
#define ONION_CIPHER_DES 1
#define ONION_CIPHER_RC4 2

/* default cipher function */
#define ONION_DEFAULT_CIPHER ONION_CIPHER_DES

typedef struct
{
  int zero:1;
  int version:7;
  int backf:4;
  int forwf:4;
  uint16_t port;
  uint32_t addr;
  time_t expire;
  unsigned char keyseed[16];
} onion_layer_t;

typedef struct
{
  unsigned int forwf;
  unsigned int backf;
  char digest2[20]; /* second SHA output for onion_layer_t.keyseed */
  char digest3[20]; /* third SHA output for onion_layer_t.keyseed */
  
  /* IVs */
  char f_iv[16];
  char b_iv[16];
  
  /* cipher contexts */
  EVP_CIPHER_CTX f_ctx;
  EVP_CIPHER_CTX b_ctx;
  
} crypt_path_t;

typedef struct
{
  time_t expire;
  char digest[20]; /* SHA digest of the onion */
  void *prev;
  void *next;
} tracked_onion_t;

/* returns an array of indexes into a router array that define a new route through the OR network
 * int cw is the coin weight to use when choosing the route 
 * order of routers is from last to first */
unsigned int *new_route(double cw, routent_t **rarray, size_t rarray_len, size_t *rlen);

/* creates a new onion from route, stores it and its length into bufp and lenp respectively */
/* if cpathp not NULL then also compute the corresponding crypt_path */ 
unsigned char *create_onion(routent_t **rarray, size_t rarray_len, unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp);

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
unsigned char *encrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *pkey);

/* decrypts the onion */
unsigned char *decrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *prkey);

/* deletes the first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, size_t n);

/* create a new tracked_onion entry */
tracked_onion_t *new_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion);

/* delete a tracked onion entry */
void remove_tracked_onion(tracked_onion_t *to, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion);

/* find a tracked onion in the linked list of tracked onions */
tracked_onion_t *id_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t *tracked_onions);

#define __ONION_H
#endif
