/**
 * opcell.c
 * Onion Proxy Cell
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/03/03 12:08:18  mp292
 * Added a new type of cell - used for data going between the onion proxy and
 * the first or hop. Payload size identical to that of a normal cell.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
  
#include <openssl/rand.h>

#include "opcell.h"
#include "log.h"

opcell_t *new_padding_opcell()
{
  opcell_t *c = NULL;
  int retval;
  
  c = malloc(sizeof(opcell_t));
  if (!c) /* malloc() error */
    return NULL;

  retval = RAND_pseudo_bytes((unsigned char *)c,sizeof(opcell_t));
  if (retval == -1) /* RAND_pseudo_bytes() error */
  {
    free((void *)c);
    return NULL;
  } /* RAND_pseudo_bytes() error */

  c->command = OPCELL_PADDING;
  
  return c;
}

opcell_t *new_data_opcell(unsigned char length, unsigned char *buf)
{
  opcell_t *c = NULL;
  int retval;

  if ((length <= OPCELL_PAYLOAD_SIZE) && (buf)) /* valid parameters */
  {
    c = malloc(sizeof(opcell_t));
    if (!c) /* malloc() error */
      return NULL;
    
    c->command = OPCELL_DATA;
    c->length = length;
    
    memcpy((void *)c->payload, (void *)buf, length);
    retval = RAND_pseudo_bytes((unsigned char *)(c->payload+length),OPCELL_PAYLOAD_SIZE-length);
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

