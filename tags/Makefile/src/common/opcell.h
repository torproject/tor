/**
 * opcell.h 
 * Onion Proxy Cell.
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

#ifndef __OPCELL_H

#include <stdint.h>

#include "cell.h"

#define OPCELL_PAYLOAD_SIZE CELL_PAYLOAD_SIZE

#define OPCELL_PADDING 0
#define OPCELL_DATA 1

/* cell definition */
typedef struct 
{
  unsigned char command;
  unsigned char length; /* of payload */
  unsigned char payload[OPCELL_PAYLOAD_SIZE];
} opcell_t;

opcell_t *new_data_opcell(unsigned char length, unsigned char *buf);
opcell_t *new_padding_opcell();

#define __OPCELL_H
#endif

