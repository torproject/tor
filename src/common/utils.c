/*
 * utils.c
 * Miscellaneous utils.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.6  2002/03/03 00:06:45  mp292
 * Modifications to support re-transmission.
 *
 * Revision 1.5  2002/01/29 02:22:41  mp292
 * Bugfix.
 *
 * Revision 1.4  2002/01/29 00:58:23  mp292
 * Timeout parametes to read_tout() and write_tout() are now pointers.
 *
 * Revision 1.3  2002/01/27 19:24:16  mp292
 * Added read_tout(), write_tout() which read/write from a blocking socket but
 * impose a timeout on the I/O operation.
 *
 * Revision 1.2  2002/01/26 19:30:09  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.1  2001/12/14 09:18:00  badbytes
 * *** empty log message ***
 *
 */

#include <ctype.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>

#include "utils.h"
#include "log.h"

/* converts string to lower case */
unsigned char *stolower(unsigned char *str)
{
  int i=0;
  
  if (str) /* valid parameters */
  {
    for (i=0; str[i] != 0; i++)
      str[i] = tolower(str[i]);
  
    return str;
  }
  else return NULL;
}

/* reads data from a descriptor, just like read(), but imposes a timeout */
/* the timeout refers to the connection being idle, not to a time limit in which the data
 * should be received*/
int read_tout(int s, unsigned char *buf, size_t buflen, int flags, struct timeval *conn_tout)
{
  int retval=0;
  int received = 0;
  struct timeval tout;
  
  fd_set mask,rmask;

  FD_ZERO(&mask);
  FD_SET(s,&mask);
  
  while(1)
  {
    rmask=mask;
    tout = *conn_tout;
    retval = select(s+1,&rmask,NULL,NULL,&tout);
    if (retval == -1)
    {
      if (errno == EINTR)
	continue;
      else
	return -1;
    }
    
    if (FD_ISSET(s,&rmask))
    {
      retval = read(s,buf+received,buflen-received);
      if (retval <= 0)
	return -1;
      else
      {
	received += retval;
	if ((received < buflen) && (flags == MSG_WAITALL))
	  continue;
	else
	  return received;
      }
    }
    else
      return -1;
  }
}

/* writes data to a file descriptor, just like write(), but imposes a timeout */
/* again this refers to the connection being idle, not a time limit in which the data should
 * be sent */
int write_tout(int s, unsigned char *buf, size_t buflen, struct timeval *conn_tout)
{
  int retval = 0;
  int sent = 0;
  fd_set mask,wmask;
  struct timeval tout;
  
  FD_ZERO(&mask);
  FD_SET(s,&mask);
  
  while(1)
  {
    wmask = mask;
    tout = *conn_tout;
    retval = select(s+1,NULL,&wmask,NULL, &tout);
    if (retval == -1)
    {
      if (errno == EINTR)
	continue;
      else
	return -1;
    }
    
    if (FD_ISSET(s,&wmask))
    {
      retval = write(s,buf+sent,buflen-sent);
      if (retval < 0)
	return -1;
      else
      {
	sent += retval;
	if (sent < buflen)
	  continue;
	else
	  return sent;
      }
    }
    else
      return -1;
  }
}

