/*
 * routent.h
 * Onion Router and related definitions.
 * 
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.25  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.24  2002/03/29 09:54:19  badbytes
 * Fixed type of routentEX.min_interval to struct timeval.
 *
 * Revision 1.23  2002/03/21 07:20:59  badbytes
 * Added a dependency to <sys/time.h>.
 *
 * Revision 1.22  2002/03/12 23:37:14  mp292
 * Additional flag - destory_buf saying whether the buffer should be destroyed
 * when the destroy cell is sent.
 *
 * Revision 1.21  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.20  2002/02/09 16:58:53  mp292
 * Postponed implementtion of POLICY_DROP_CONNECTIONS due to problems. Need to
 * discuss with Andrei first.
 *
 * Revision 1.19  2002/02/09 16:54:59  mp292
 * routentEX now contains a per anonymous connection packet count
 *
 * Revision 1.18  2002/01/29 00:59:16  mp292
 * Slight changes in the way timers are kept, c.f. changes in the network funnel.
 *
 * Revision 1.17  2002/01/28 21:37:36  mp292
 * Router's output buffer is now dynamic. Time of last output to the router
 * added to routentEX.
 *
 * Revision 1.16  2002/01/26 19:26:55  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.15  2002/01/18 22:55:40  mp292
 * Added a cell buffer to struct routent so that a cell can be received in
 * several bursts of data. This prevents a DoS attack on the network funnel.
 *
 * Revision 1.14  2002/01/14 13:05:37  badbytes
 * System testing in progress.
 *
 * Revision 1.13  2002/01/11 15:47:17  badbytes
 * *** empty log message ***
 *
 * Revision 1.12  2002/01/10 08:28:33  badbytes
 * routent and routentEX related routines
 *
 * Revision 1.11  2002/01/08 15:13:30  badbytes
 * Added cipher context to routentEX
 *
 * Revision 1.10  2002/01/08 13:18:48  badbytes
 * Added a connection buffer to routentEX
 *
 * Revision 1.9  2002/01/08 13:02:16  badbytes
 * routentEX now contains f_key and b_key, 56-bit DES keys for link encryption
 *
 * Revision 1.8  2002/01/03 11:17:01  badbytes
 * routentEX.max and routentEX.min values changed to 32bit not 64bit.
 *
 * Revision 1.7  2002/01/03 11:04:16  badbytes
 * *** empty log message ***
 *
 * Revision 1.6  2002/01/03 11:03:14  badbytes
 * Added an extended version of routent which includes link utilisation info.
 *
 * Revision 1.5  2001/12/18 15:26:34  badbytes
 * Added #inclusion of <stdint.h>
 *
 * Revision 1.4  2001/12/18 15:19:41  badbytes
 * In struct routent, changed long and short types to uint32_t and uint16_t
 *
 * Revision 1.3  2001/12/18 10:37:47  badbytes
 * Header files now only apply if they were not previously included from somewhere else.
 *
 * Revision 1.2  2001/12/17 13:35:17  badbytes
 * Still writing handle_connection()
 *
 * Revision 1.1  2001/12/14 13:14:03  badbytes
 * Split types.h into routent.h and ss.h. Keeping them all in one file created unnecesary dependencies.
 *
 */

#ifndef __ROUTENT_H
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <sys/timeb.h>

#include "cell.h"

/* per-anonymous-connection cell buffer */
typedef struct
{
  uint16_t aci;
  int policy;
  unsigned int cells;
  unsigned char *buf;
  unsigned int buflen;
  unsigned int offset; /* offset to the position of the first cell in the buffer */
  cell_t dc; /* static buffer for the destroy cell - so we are always able to destroy a connection */
  unsigned char dc_set; /* flag that signifies presence of a destroy cell */
  unsigned char destroy_buf; /* flag that signifies that the buffer shuld be destroyed when the destroy cell is sent */

  /* POLICY_DROP_CELLS only */
  unsigned int win_size; /* window size for the connection (number of cells)*/
  unsigned int win_avail; /* available window size */
  uint32_t seq_out; /* next sequence number to use for outgoing cells */
  uint32_t seq_in; /* next expected sequence number */
  uint32_t ack; /* next expected ack/nack */
  struct timeval last_ack; /* time of last ACK/NACK  */

  void *prev;
  void *next;
} conn_buf_t;

/* onion router as seen by the onion proxy */
typedef struct 
{
  char *address;
  uint32_t addr; /* address in network byte order */
  uint16_t port; /* network port in network byte order */
  uint16_t entry_port; /* entry port in network byte order */
  RSA *pkey;
  void *next;
} routent_t;

/* onion router as seen by other routers */
typedef struct
{
  char *address;
  
  uint32_t addr;
  uint16_t port;
  
  RSA *pkey; /* public RSA key */
  /* 64-bit DES keys for link encryption */
  char f_key[8];
  char b_key[8];
  char f_iv[8];
  char b_iv[8];
  EVP_CIPHER_CTX f_ctx;
  EVP_CIPHER_CTX b_ctx;
  
  /* link info */
  uint32_t min;
  uint32_t max;
  struct timeval  min_interval;
  
  /* time when last data was sent to that router */
  struct timeval lastsend;
  
  /* socket */
  int s;

  /* connection buffers */
  conn_buf_t *conn_bufs; /* linked list of connection buffers */
  conn_buf_t *last_conn_buf; /* last item in the list */
  unsigned int next_to_service; /* offset to the connection buffer that is next in turn to be serviced */
  
  /* cell buffer */
  unsigned char cellbuf[128];
  unsigned int celllen;
  
  void *next;
} routentEX_t;

routentEX_t *id_router(routentEX_t **routerarray, size_t rarray_len, uint32_t addr, uint16_t port);
routentEX_t *id_routerbys(routentEX_t **routerarray, size_t rarray_len, int s);

conn_buf_t *new_conn_buf(uint16_t aci, int policy, conn_buf_t **conn_bufs, conn_buf_t **last_conn_buf);
int remove_conn_buf(conn_buf_t *conn_buf, conn_buf_t **conn_bufs, conn_buf_t **last_conn_buf);
conn_buf_t *id_conn_buf(conn_buf_t *conn_bufs, uint16_t aci);

#define __ROUTENT_H
#endif
