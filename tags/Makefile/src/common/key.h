/**
 * key.h 
 * Routines for generating key pairs and loading private keys.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.3  2002/01/26 18:50:11  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.2  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.1  2001/12/14 12:16:33  badbytes
 * Added routine for reading a private key from a file.
 *
 */

#ifndef __KEY_H
#include <openssl/rsa.h>

/* read the private key in keyfile into memory  */
RSA *load_prkey(unsigned char *keyfile);

#define __KEY_H
#endif
