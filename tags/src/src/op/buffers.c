/**
 * buffers.c
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


#include <unistd.h>
#include <openssl/evp.h>

#include "../common/cell.h"
#include "../common/log.h"

#include "buffers.h"
#include "crypto.h"
#include "op.h"

int buffer_data(uint16_t aci, unsigned char *buf, size_t buflen, unsigned char **outbuf, size_t *outbuflen, size_t *outbuf_dataoffset, size_t *outbuf_datalen, crypt_path_t **cpath, size_t cpathlen)
{
  int retval;
  int i;
  cell_t *cellbuf;
  cell_t *c;
  size_t cellbuflen;
  size_t cells;
  unsigned char *tmpbuf; /* temporary buffer for realloc() operations */
  
  if (!buf || !outbuf || !outbuflen) /* invalid parameters */
    return -1;
  
  /* split the plaintext into DATA cells */
  retval = pack_data(aci,buf, buflen, (unsigned char **)&cellbuf, &cellbuflen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"buffer_data() : Could not pack data into cells.");
    return -1;
  }
  log(LOG_DEBUG,"buffer_data() : DATA cells created.");
  
  cells = cellbuflen/(sizeof(cell_t));
  /* encrypt the cells */
  for (i=0; i<cells; i++)
  {
    c = cellbuf+i;
    /* encrypt the payload length */
    retval = crypt_f((unsigned char *)&c->length, 1, cpath, cpathlen);
    if (retval == -1)
    {
      log(LOG_ERR,"Could not encrypt the payload length of a DATA cell.");
      free((void *)cellbuf);
      return -1;
    }
    /* encrypt the payload */
    retval = crypt_f((unsigned char *)c->payload, CELL_PAYLOAD_SIZE, cpath, cpathlen);
    if (retval == -1)
    {
      log(LOG_ERR,"Could not encrypt the payload of a DATA cell.");
      free((void *)cellbuf);
      return -1;
    }
  }

  /* now copy the cells into the output buffer */
  if (*outbuflen-*outbuf_dataoffset-*outbuf_datalen < cellbuflen) /* increase the buffer size if necessary */
  {
    /* allocate a new buffer (in OP_DEFAULT_BUFSIZE chunks)*/
    tmpbuf = (unsigned char *)malloc(((cellbuflen+*outbuf_datalen)/OP_DEFAULT_BUFSIZE+1)*OP_DEFAULT_BUFSIZE);
    if (!tmpbuf)
    {
      log(LOG_ERR,"Error allocating memory.");
      free((void *)cellbuf);
      return -1;
    }
    /* copy old data to the new buffer */
    memcpy((void *)tmpbuf,(void *)(*outbuf+*outbuf_dataoffset),*outbuf_datalen);
    /* replace the old buffer with the new one */
    if (*outbuf)
      free((void *)*outbuf);
    *outbuf = tmpbuf;
    *outbuflen = ((cellbuflen+*outbuf_datalen)/OP_DEFAULT_BUFSIZE+1) * OP_DEFAULT_BUFSIZE;
    *outbuf_dataoffset = 0;
  }
  memcpy((void *)(*outbuf + *outbuf_dataoffset + *outbuf_datalen), (void *)cellbuf, cellbuflen);
  *outbuf_datalen += cellbuflen;
  
  return 0;
}

int buffer_create(uint16_t aci, unsigned char *onion, size_t onionlen, unsigned char **outbuf, size_t *outbuflen, size_t *outbuf_dataoffset, size_t *outbuf_datalen, crypt_path_t **cpath, size_t cpathlen)
{
  int retval;
  cell_t *cellbuf;
  size_t cells;
  size_t cellbuflen;
  unsigned char *tmpbuf; /* temporary buffer for realloc() operations */
  
  if (!onion || !outbuf || !outbuflen || !outbuf_dataoffset || !outbuf_datalen) /* invalid parameters */
    return -1;
  
  retval = pack_create(aci,onion, onionlen, (unsigned char **)&cellbuf, &cellbuflen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"buffer_create() : Could not pack the onion into cells.");
    return -1;
  }
  log(LOG_DEBUG,"buffer_create() : CREATE cells created.");

  cells = cellbuflen/(sizeof(cell_t));

  /* now copy the cells into the output buffer */
  if (*outbuflen-*outbuf_dataoffset-*outbuf_datalen < cellbuflen) /* increase the buffer size if necessary */
  {
    /* allocate a new buffer (in OP_DEFAULT_BUFSIZE chunks)*/
    tmpbuf = (unsigned char *)malloc(((cellbuflen+*outbuf_datalen)/OP_DEFAULT_BUFSIZE+1)*OP_DEFAULT_BUFSIZE);
    if (!tmpbuf)
    {
      log(LOG_ERR,"Error allocating memory.");
      free((void *)cellbuf);
      return -1;
    }
    /* copy old data to the new buffer */
    memcpy((void *)tmpbuf,(void *)(*outbuf+*outbuf_dataoffset),*outbuf_datalen);
    /* replace the old buffer with the new one */
    if (*outbuf)
      free((void *)*outbuf);
    *outbuf = tmpbuf;
    *outbuflen = ((cellbuflen+*outbuf_datalen)/OP_DEFAULT_BUFSIZE+1) * OP_DEFAULT_BUFSIZE;
    *outbuf_dataoffset = 0;
  }
  memcpy((void *)(*outbuf + *outbuf_dataoffset + *outbuf_datalen), (void *)cellbuf, cellbuflen);
  *outbuf_datalen += cellbuflen;
  
  return 0;
}
