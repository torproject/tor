/**
 * crypto.h
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

#include "../common/onion.h"

int crypt_f(unsigned char *buf, size_t buflen, crypt_path_t **cpath, size_t cpathlen);

int crypt_b(unsigned char *buf, size_t buflen, crypt_path_t **cpath, size_t cpathlen);
