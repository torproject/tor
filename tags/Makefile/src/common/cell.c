/**
 * cell.c
 * Cell manipulation.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.16  2002/06/14 20:41:19  mp292
 * Parameter checking error - thanks Roger.
 *
 * Revision 1.15  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.14  2002/04/02 10:19:37  badbytes
 * Stricter parameter checking.
 *
 * Revision 1.13  2002/03/12 23:30:19  mp292
 * Removed some memory overruns.
 *
 * Revision 1.12  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.11  2002/02/03 22:41:45  mp292
 * Changes to cell size.
 *
 * Revision 1.10  2002/01/21 20:57:19  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.9  2002/01/17 15:00:43  mp292
 * Fixed a bug which caused malloc() generate a seg fault.
 *
 * Revision 1.8  2002/01/16 23:01:54  mp292
 * First phase of system testing completed (main functionality).
 *
 * Revision 1.7  2002/01/14 13:05:37  badbytes
 * System testing in progress.
 *
 * Revision 1.6  2002/01/10 13:15:54  badbytes
 * Fixed ACI size from 32bits to 16bits.
 *
 * Revision 1.5  2002/01/07 13:06:06  badbytes
 * cell.ACI is now cell.aci
 *
 * Revision 1.4  2002/01/07 09:26:00  badbytes
 * Added pack_create() and pack_data().
 *
 * Revision 1.3  2002/01/07 07:48:34  badbytes
 * fixed new_create_cell()
 *
 * Revision 1.2  2002/01/04 12:11:54  badbytes
 * Syntax errors fixed.
 *
 * Revision 1.1  2002/01/04 12:08:34  badbytes
 * Added functions for cell creation.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
  
#include <openssl/rand.h>

#include "cell.h"
#include "log.h"

cell_t *new_padding_cell()
{
  cell_t *c = NULL;
  int retval;
  
  c = malloc(sizeof(cell_t));
  if (!c) /* malloc() error */
    return NULL;

  retval = RAND_pseudo_bytes((unsigned char *)c,sizeof(cell_t));
  if (retval == -1) /* RAND_pseudo_bytes() error */
  {
    free((void *)c);
    return NULL;
  } /* RAND_pseudo_bytes() error */

  c->command = CELL_PADDING;
  
  return c;
}

cell_t *new_destroy_cell(uint16_t aci)
{
  cell_t *c = NULL;
  int retval;

  if (aci) /* valid ACI */
  {
    c = (cell_t *)malloc(sizeof(cell_t));
    if (!c) /* malloc error */
      return NULL;
    
    retval = RAND_pseudo_bytes((unsigned char *)c+3,sizeof(cell_t)-3);
    if (retval == -1) /* RAND_pseudo_bytes() error */
    {
      free((void *)c);
      return NULL;
    } /* RAND_pseudo_bytes() error */
    
    c->aci = aci;
    c->command = CELL_DESTROY;
    
    return c;
  } /* valid ACI */
  else /* invalid ACI */
    return NULL;
}

cell_t *new_ack_cell(uint16_t aci)
{
  cell_t *c = NULL;
  int retval;
  
  if (aci) /* valid ACI */
  {
    c = (cell_t *)malloc(sizeof(cell_t));
    if (!c) /* malloc error */
      return NULL;
    
    retval = RAND_pseudo_bytes((unsigned char *)c+3,sizeof(cell_t)-3);
    if (retval == -1) /* RAND_pseudo_bytes() error */
    {
      free((void *)c);
      return NULL;
    } /* RAND_pseudo_bytes() error */
    
    c->aci = aci;
    c->command = CELL_ACK;
    
    return c;
  } /* valid ACI */
  else /* invalid ACI */
    return NULL;
}

cell_t *new_nack_cell(uint16_t aci)
{
  cell_t *c = NULL;
  int retval;
  
  if (aci) /* valid ACI */
  {
    c = (cell_t *)malloc(sizeof(cell_t));
    if (!c) /* malloc error */
      return NULL;
    
    retval = RAND_pseudo_bytes((unsigned char *)c+3,sizeof(cell_t)-3);
    if (retval == -1) /* RAND_pseudo_bytes() error */
    {
      free((void *)c);
      return NULL;
    } /* RAND_pseudo_bytes() error */
    
    c->aci = aci;
    c->command = CELL_NACK;
    
    return c;
  } /* valid ACI */
  else /* invalid ACI */
    return NULL;
}

cell_t *new_create_cell(uint16_t aci, unsigned char length, unsigned char *buf)
{
  cell_t *c = NULL;
  int retval;

  if ((aci) && (buf) && (length <= CELL_PAYLOAD_SIZE)) /* valid parameters */
  {
    c = (cell_t *)malloc(sizeof(cell_t));
    if (!c) /* malloc() error */
      return NULL;
    
    c->command = CELL_CREATE;
    c->aci = aci;
    c->length = length;
    c->seq = 0;
    
    memcpy((void *)c->payload, (void *)buf, length);
    retval = RAND_pseudo_bytes((unsigned char *)(c->payload+length),CELL_PAYLOAD_SIZE-length);
    if (retval == -1) /* RAND_pseudo_bytes() error */
    {
      free((void *)c);
      return NULL;
    } /* RAND_pseudo_bytes() error */
    
    return c;
  } /* valid parameters */
  else /* invalid parameters */
    return NULL;
}


cell_t *new_data_cell(uint16_t aci, unsigned char length, unsigned char *buf)
{
  cell_t *c = NULL;
  int retval;

  if ((aci) && (buf) && (length <= CELL_PAYLOAD_SIZE)) /* valid parameters */
  {
    c = malloc(sizeof(cell_t));
    if (!c) /* malloc() error */
      return NULL;
    
    c->command = CELL_DATA;
    c->aci = aci;
    c->length = length;
    c->seq = 0;
    
    memcpy((void *)c->payload, (void *)buf, length);
    retval = RAND_pseudo_bytes((unsigned char *)(c->payload+length),CELL_PAYLOAD_SIZE-length);
    if (retval == -1) /* RAND_pseudo_bytes() error */
    {
      free((void *)c);
      return NULL;
    } /* RAND_pseudo_bytes() error */
    
    return c;
  } /* valid parameters */
  else /* invalid parameters */
    return NULL;
}

int pack_create(uint16_t aci, unsigned char *onion, uint32_t onionlen, unsigned char **cellbuf, unsigned int *cellbuflen)
{
  cell_t *c;
  unsigned char *buf;
  unsigned int buflen;
  unsigned int cells;
  unsigned int dataleft;
  unsigned int i;
  
  if ((aci) && (onion) && (cellbuf) && (cellbuflen) && (onionlen)) /* valid parameters */
  {
    /* copy the onion into a buffer, prepend with onion length */
    buflen = onionlen+4;
    buf = (unsigned char *)malloc(buflen);
    if (!buf) /* malloc() error */
      return -1;
  
    log(LOG_DEBUG,"pack_create() : Setting onion length to %u.",onionlen);
    onionlen=htonl(onionlen);
    memcpy((void *)buf,(void *)&onionlen,4);
    onionlen=ntohl(onionlen);
    memcpy((void *)(buf+4),(void *)onion,onionlen);
  
    /* calculate number of cells required */
    if (buflen%CELL_PAYLOAD_SIZE == 0)
      cells = buflen/CELL_PAYLOAD_SIZE;
    else
      cells = buflen/CELL_PAYLOAD_SIZE+1;
  
    /* allocate memory for the cells */
    *cellbuflen = cells * sizeof(cell_t);
    *cellbuf = malloc(*cellbuflen);
    if (!*cellbuf) /* malloc() error */
      return -1;
    
    log(LOG_DEBUG,"pack_create() : Allocated memory for %u cells.",cells);
  
    /* create cells one by one */
    dataleft = buflen;
    for(i=0; i<cells; i++)
    {
      log(LOG_DEBUG,"pack_create() : Packing %u bytes of data.",dataleft);
      if (dataleft >= CELL_PAYLOAD_SIZE)
      {
	c = new_create_cell(aci,CELL_PAYLOAD_SIZE,buf+i*CELL_PAYLOAD_SIZE);
	dataleft -= CELL_PAYLOAD_SIZE;
      }
      else
	c = new_create_cell(aci,dataleft,buf+i*CELL_PAYLOAD_SIZE);
      
      if (!c) /* cell creation failed */
      {
	free((void *)*cellbuf);
	return -1;
      } /* cell creation failed */
      
      log(LOG_DEBUG,"pack_create() : new_create_cell succeeded; copying the cell into output buffer");
      /* cell has been created, now copy into buffer */
      memcpy((void *)(*cellbuf+i*sizeof(cell_t)),(void *)c,sizeof(cell_t));
      free((void *)c);
    }
  
    free(buf);
    return 0;
  } /* valid parameters */
  else /* invalid parameters */
    return -1;
}

int pack_data(uint16_t aci,unsigned char *buf, size_t buflen, unsigned char **cellbuf, unsigned int *cellbuflen)
{
  cell_t *c;
  unsigned int cells;
  unsigned int dataleft;
  unsigned int i;
  
  if ((aci) && (buf) && (cellbuf) && (cellbuflen) && (buflen)) /* valid parameters */
  {
    /* calculate number of cells required */
    if (buflen%CELL_PAYLOAD_SIZE == 0)
      cells = buflen/CELL_PAYLOAD_SIZE;
    else
      cells = buflen/CELL_PAYLOAD_SIZE+1;
  
    /* allocate memory for the cells */
    *cellbuf = malloc(cells * sizeof(cell_t));
    if (!*cellbuf) /* malloc() error */
      return -1;

    log(LOG_DEBUG,"pack_data() : Allocated memory for %u cells.",cells);
    /* create cells one by one */
    dataleft = buflen;
    for(i=0; i<cells; i++)
    {
      log(LOG_DEBUG,"pack_data() : Packing %u bytes of data.",dataleft);
      if (dataleft >= CELL_PAYLOAD_SIZE)
      {
	c = new_data_cell(aci,CELL_PAYLOAD_SIZE,buf+i*CELL_PAYLOAD_SIZE);
	dataleft -= CELL_PAYLOAD_SIZE;
      }
      else
	c = new_data_cell(aci,dataleft,buf+i*CELL_PAYLOAD_SIZE);

      if (!c) /* cell creation failed */
      {
	free((void *)*cellbuf);
	return -1;
      } /* cell creation failed */
      
      /* cell has been created, now copy into buffer */
      memcpy((void *)(*cellbuf+i*sizeof(cell_t)),(void *)c,sizeof(cell_t));
      free((void *)c);
    }
  
    *cellbuflen = cells * sizeof(cell_t);
    return 0;
  } /* valid parameters */
  else /* invalid parameters */
    return -1;
}
