/**
 * cell.h 
 * Cell definition.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.14  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.13  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.12  2002/02/09 17:51:52  mp292
 * CELL_ACK should be 4 not 3
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
 * Revision 1.8  2002/01/14 13:05:37  badbytes
 * System testing in progress.
 *
 * Revision 1.7  2002/01/10 13:15:54  badbytes
 * Fixed ACI size from 32bits to 16bits.
 *
 * Revision 1.6  2002/01/09 08:10:32  badbytes
 * *** empty log message ***
 *
 * Revision 1.5  2002/01/07 13:03:28  badbytes
 * cell.ACI is now cell.aci
 *
 * Revision 1.4  2002/01/07 09:26:00  badbytes
 * Added pack_create() and pack_data().
 *
 * Revision 1.3  2002/01/07 07:48:34  badbytes
 * fixed new_create_cell()
 *
 * Revision 1.2  2002/01/04 12:08:34  badbytes
 * Added functions for cell creation.
 *
 * Revision 1.1  2002/01/04 10:02:07  badbytes
 * Added cell definition.
 *
 */

#ifndef __CELL_H

#include <unistd.h>
#include <stdint.h>

/* cell commands */
#define CELL_PADDING 0
#define CELL_CREATE 1
#define CELL_DATA 2
#define CELL_DESTROY 3
#define CELL_ACK 4
#define CELL_NACK 5

#define CELL_PAYLOAD_SIZE 120

/* cell definition */
typedef struct 
{
  uint16_t aci; /* Anonymous Connection Identifier */
  unsigned char command;
  unsigned char length; /* of payload */
  uint32_t seq; /* sequence number */
  unsigned char payload[120];
} cell_t;

cell_t *new_padding_cell(void);
cell_t *new_create_cell(uint16_t aci, unsigned char length, unsigned char *buf);
cell_t *new_destroy_cell(uint16_t aci);
cell_t *new_data_cell(uint16_t aci, unsigned char length, unsigned char *buf);
cell_t *new_ack_cell(uint16_t aci);
cell_t *new_nack_cell(uint16_t aci);

int pack_create(uint16_t aci, unsigned char *onion, uint32_t onionlen, unsigned char **cellbuf, unsigned int *cellbuflen);
int pack_data(uint16_t aci, unsigned char *buf, size_t buflen, unsigned char **cellbuf, unsigned int *cellbuflen);

#define __CELL_H
#endif

