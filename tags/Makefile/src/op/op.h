/**
 * op.h
 * Onion Proxy
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.7  2002/03/28 11:01:43  badbytes
 * Now does link-encryption and link-padding.
 *
 * Revision 1.6  2002/03/12 23:40:32  mp292
 * Started on op<->router connection padding.
 *
 * Revision 1.5  2002/01/29 02:22:58  mp292
 * Put a timeout on all network I/O.
 *
 * Revision 1.4  2002/01/26 23:01:55  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.3  2001/12/18 11:52:27  badbytes
 * Coding completed. Proceeding to test.
 *
 * Revision 1.2  2001/12/17 13:36:15  badbytes
 * Writing handle_connection()
 *
 * Revision 1.1  2001/12/13 15:15:11  badbytes
 * Started coding the onion proxy.
 *
 */

#ifndef __OP_H

#define __OP_H

/* choosing the length of a route uses a weighted coin
 * this is the default value for it */
#define OP_DEFAULT_COIN_WEIGHT 0.8

/* default connection timeout */
#define OP_DEFAULT_CONN_TIMEOUT 120 /* 120s */

/* default connection bandwidth */
#define OP_DEFAULT_BANDWIDTH 1 /* 1kb/s */

/* default buffer size per connection */
#define OP_DEFAULT_BUFSIZE 4096 /* 4kb */

#endif
