/*
 * http.c 
 * HTTP parsers.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.2  2002/04/02 14:27:33  badbytes
 * Final finishes.
 *
 * Revision 1.1  2002/03/12 23:46:14  mp292
 * HTTP-related routines.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../common/log.h"
#include "../common/utils.h"

#include "http.h"

int http_get_line(int s, unsigned char **line, size_t *len, struct timeval *conn_tout)
{
  int retval =0; /* function return value */
  unsigned char buf[HTTPAP_MAXLEN]; /* line buffer */
  unsigned int buflen = 0; /* length of the received data */
  char got_cr = 0; /* received a CR character and hence expecting a LF */
  unsigned char c; /* input character */

  if (!line || !len) /* invalid parameters */
    return -1;
  
  while(1)
  {
    retval = read_tout(s, &c, 1, MSG_WAITALL, conn_tout);
    if (retval < 1)
      return -1;
    
    if (buflen >= HTTPAP_MAXLEN)
      return -1;
    
    buf[buflen++] = c;
    
    if (got_cr)
    {
      if (c != HTTPAP_LF)
	return -1;
      else
	break;
    }
    else
    {
      if (c == HTTPAP_CR)
	got_cr = 1;
    }
  }
  
  *len = buflen;
  if (buflen)
  {
    *line = (unsigned char *)malloc(buflen+1);
    if (!*line)
      return -1;
    else
    {
      memcpy((void *)*line,(void *)buf,buflen);
      (*line)[buflen] = 0; /* add the terminating null character */
    }
  }
  else
    *line = NULL;

  return 0;
}

int http_get_version(unsigned char *rl, unsigned char **http_ver)
{
  unsigned char *start;
  unsigned char *end;
  
  if (!rl || !http_ver) /* invalid parameters */
    return -1;
  
  start = strrchr(rl, ' ');
  if (!start)
    return -1;
  
  end = strrchr(rl, HTTPAP_CR);
  if (!end)
    return -1;
  
  start++;
  *http_ver = (unsigned char *)malloc(end-start+1);
  if (!*http_ver)
    return -1;
  
  strncpy(*http_ver, start, end-start);
  (*http_ver)[end-start] = 0; /* terminating NULL character */
  
  return 0;
}

int http_get_dest(unsigned char *rl, unsigned char **addr, unsigned char **port)
{
  unsigned char *start;
  unsigned char *end;
  unsigned char *colon;

  if (!rl || !addr || !port) /* invalid parameters */
    return -1;
  
  start = strchr(rl, ' ');
  if (!start)
    return -1;
  start++;
  /* make sure this is really an http:// address */
  if (strncmp(start,"http://",7))
    return -1;
  
  start += 7;
  
  end = strchr(start,'/');
  if (!end)
    return -1;
  
  /* check for a :port in the address */
  colon = strchr(start,':');
  if (colon)
  {
    colon++;
    *port = (unsigned char *)malloc(end-colon+1);
    if (!*port)
      return -1;
    strncpy(*port,colon, end-colon);
    (*port)[end-colon] = 0; /* terminating NULL character */
    end = colon-1;
  }
  else
    *port = NULL;
  
  /* extract the server address */
  *addr = (unsigned char *)malloc(end-start+1);
  if (!*addr)
  {
    if (*port)
      free((void *)*port);
    return -1;
  }
  strncpy(*addr,start, end-start);
  (*addr)[end-start] = 0; /* terminating NULL character */
  
  return 0;
}

int http_get_header_name(unsigned char *rl, unsigned char **hname)
{
  unsigned char *end;
  
  if (!rl || !hname) /* invalid parameters */
    return -1;
  
  end = strchr(rl, ':');
  if (!end)
    return -1;
  
  *hname = (unsigned char *)malloc(end-rl+1);
  if (!*hname)
    return -1;
  
  strncpy(*hname,rl,end-rl);
  (*hname)[end-rl] = 0;
  
  return 0;
}
