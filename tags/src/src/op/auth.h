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

#include <openssl/rsa.h>
#include <stdint.h>

/* send session keys and bandwidth info to the router */
int send_auth(int or_sock, uint32_t bandwidth, RSA *pkey, unsigned char *f_session_key, unsigned char *b_session_key);
