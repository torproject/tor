/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

static cell_t *new_create_cell(uint16_t aci, unsigned char length, unsigned char *buf)
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

int pack_create(uint16_t aci, unsigned char *onion, uint32_t onionlen, unsigned char **cellbuf, unsigned int *cellbuflen)
{
  cell_t *c;
  unsigned char *buf;
  unsigned int buflen;
  unsigned int cells;
  unsigned int dataleft;
  unsigned int i;
  
  assert(aci && onion && onionlen && cellbuf && cellbuflen);

  /* copy the onion into a buffer, prepend with onion length */
  buflen = onionlen+4;
  buf = (unsigned char *)malloc(buflen);
  if (!buf) /* malloc() error */
    return -1;
  
  log(LOG_DEBUG,"pack_create() : Setting onion length to %u.",onionlen);
  *(uint32_t*)buf = htonl(onionlen);
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
}

