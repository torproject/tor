/**
 * routers.h
 * Routines for loading the list of routers and their public RSA keys.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.11  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 * Revision 1.10  2002/01/26 22:22:09  mp292
 * Prevented duplicate definitions.
 *
 * Revision 1.9  2002/01/26 22:19:15  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.8  2001/12/17 08:42:45  badbytes
 * getrouters() now returns an array of routers and also writes the length of the array to an int*.
 *
 * Revision 1.7  2001/12/14 14:08:50  badbytes
 * getrouters() now returns an array of pointers rather than a linked list
 *
 * Revision 1.6  2001/12/14 14:05:56  badbytes
 * Added routent** make_rarray(routent_t* list);
 *
 * Revision 1.5  2001/12/14 13:32:18  badbytes
 * No longer contains the definition of routent_t. This is now in common/routent_t.h
 *
 * Revision 1.4  2001/12/14 13:25:17  badbytes
 * Moved back from common/
 *
 * Revision 1.2  2001/12/14 11:24:57  badbytes
 * Tested.
 *
 * Revision 1.1  2001/12/13 15:15:11  badbytes
 * Started coding the onion proxy.
 *
 */

#ifndef __ROUTERS_H

#define __ROUTERS_H

#include <openssl/rsa.h>
#include "../common/routent.h"

#define OP_ROUTERLIST_SEPCHARS " \t\n"

#define OP_PUBLICKEY_BEGIN_TAG "-----BEGIN RSA PUBLIC KEY-----\n"

/* load the list of routers into memory */
routent_t **getrouters(char *routerfile, size_t *listlenp);

/* free the router list pointed to by list */
void delete_routerlist(routent_t *list);

/* create an NULL-terminated array of pointers pointing to elements of a router list */
routent_t **make_rarray(routent_t* list, size_t *listlenp);

#endif
