/**
 * buffers.h
 * Buffers.
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


#include <stdint.h>

#include "../common/onion.h"

int buffer_data(uint16_t aci, unsigned char *buf, size_t buflen, unsigned char **outbuf, size_t *outbuflen, size_t *outbuf_dataoffset, size_t *outbuf_datalen, crypt_path_t **cpath, size_t cpathlen);
int buffer_create(uint16_t aci, unsigned char *onion, size_t onionlen, unsigned char **outbuf, size_t *outbuflen, size_t *outbuf_dataoffset, size_t *outbuf_datalen, crypt_path_t **cpath, size_t cpathlen);
