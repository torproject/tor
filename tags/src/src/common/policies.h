/**
 * policies.h
 * Traffic shaping policies for the network funnel.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.2  2002/03/12 23:42:37  mp292
 * Various bugfixes.
 *
 * Revision 1.1  2002/03/03 00:03:49  mp292
 * Moved from or/network (merged core and network funnel into a single thread).
 *
 * Revision 1.3  2002/02/09 17:00:42  mp292
 * Added core_sock to list of parameters for comms with the router core.
 *
 * Revision 1.2  2002/02/03 22:40:44  mp292
 * Changes to cell size.
 *
 * Revision 1.1  2002/02/03 20:34:38  mp292
 * Traffic shaping policies for the network funnel.
 * 
 */


/* traffic shaping policies */
#define POLICY_DROP_CONNECTIONS 0 /* buffer data and drop the connections that cannot be allocated resources */
#define POLICY_DROP_CELLS 1 /* buffer data and drop cells, which can't be bufered, do re-transmission */

#define DEFAULT_POLICY POLICY_DROP_CONNECTIONS

#define DEFAULT_ACK_TIMEOUT 3000 /* ms */
#define DEFAULT_WINDOW_SIZE 5 /* cells */
