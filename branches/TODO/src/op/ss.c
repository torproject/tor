/**
 * ss.c
 * Standard structure processing.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.1  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 */


#include <malloc.h>
#include <unistd.h>

#include "../common/log.h"
#include "../common/version.h"
#include "../common/utils.h"

#include "ss.h"

/* read the standard structure, check if it's acceptable and send an appropriate error code
 * Returns : 
 *   -1 processing error
 *    0 OK
 *    1 no error, but standard structure rejected
 */
int process_ss(int s, struct timeval *conn_toutp, ss_t **ssp, char **addrp, int *addrlenp, char **portp, int *portlenp)
{
  int retval = 0;
  int len = 0; /* number of bytes read */
  ss_t *ss; /* standard structure */
  char errcode = SS_ERROR_SUCCESS; /* error code which we send back to the client */
  char inbuf;
  char *addr = NULL; /* destination address */
  int addrlen = 0;
  char *port = NULL; /* destination port */
  int portlen = 0;
  char *tmp = NULL; /* temporary storage */
  
  if ((!ssp) || (!addrp) || (!addrlenp) || (!portp) || (!portlenp)) /* invalid parameters */
    return -1;
  
  /* allocate memory for SS */
  ss = malloc(sizeof(ss_t));
  if (!ss)
  {
    log(LOG_ERR,"Error allocating memory.");
    return -1;
  }
  
  log(LOG_DEBUG,"Allocated memory for ss.");
  
  len = 0;
  while (len < sizeof(ss_t)) /* need to make sure the entire ss is read */
  {
    retval = read_tout(s,(char *)ss+len,sizeof(ss_t)-len,0, conn_toutp);
    if (retval <= 0)
    {
      free(ss);
      log(LOG_ERR,"Could not receive standard structure.");
      return -1;
    }
    len +=retval;
  }
  
  if ((ss->version == 0) || (ss->version != VERSION)) /* unsupported version */
  {
    log(LOG_DEBUG,"Unsupported version.");
    free(ss);
    errcode = SS_ERROR_VERSION_UNSUPPORTED;
    write_tout(s,&errcode,1,conn_toutp);
    return -1;
  }
  
  if (ss->addr_fmt != SS_ADDR_FMT_ASCII_HOST_PORT) /* unrecognized address format */
  {
    log(LOG_DEBUG,"Unrecognized address format.");
    free(ss);
    errcode = SS_ERROR_ADDR_FMT_UNSUPPORTED;
    write_tout(s,&errcode,1,conn_toutp);
    return -1;
  }
  
  /* allocate memory for the destination address - 512 bytes maximum */
  addrlen=512;
  addr = malloc(addrlen);
  if (!addr)
  {
    free(ss);
    log(LOG_ERR,"Error allocating memory.");
    return -1;
  }
  
  /* now read the destination address */
  len = 0;
  do /* need to keep going until the entire string is read in */
  {
    if (len == addrlen) /* we've run out of space, abort */
    {
      free(ss);
      free(addr);
      log(LOG_ERR,"Client tried to send address > 512 characters.");
      errcode = SS_ERROR_INVALID_ADDRESS;
      write_tout(s,&errcode,1,conn_toutp);
      return -1;
    }
    retval = read_tout(s,(void *)&inbuf, 1, 0, conn_toutp);
    if (retval <= 0)
    {
      free(ss);
      free(addr);
      log(LOG_ERR,"Error receiving destination address.");
      return -1;
    }
    *(addr+len) = inbuf;
    len++;
  } while (inbuf != 0);

  
  /* allocate memory for the destination port - 6 bytes maximum */
  portlen = 6;
  port = malloc(portlen);
  if (!port)
  {
    free(ss);
    log(LOG_ERR,"Error allocating memory.");
    free(addr);
    return -1;
  }
  /* now read the destination port */
  len = 0;
  do /* keep going until the entire string is read in */
  {
    if (len == portlen) /* no more space, abort */
    {
      free(ss);
      free(addr);
      free(port);
      log(LOG_ERR,"Client tried to send port > 6 characters.");
      errcode = SS_ERROR_INVALID_PORT;
      write_tout(s,&errcode,1,conn_toutp);
      return -1;
    }
    retval = read_tout(s,(void *)&inbuf, 1, 0, conn_toutp);
    if (retval <= 0)
    {
      free(ss);
      free(addr);
      free(port);
      log(LOG_ERR,"Error receiving destination port.");
      return -1;
    }
    *(port+len)=inbuf;
    len++;
  } while (inbuf != 0);

  /* send a success error code back to the client */
  errcode = SS_ERROR_SUCCESS;
  write_tout(s,&errcode,1,conn_toutp);
  
  /* done, now save */
  addrlen = strlen(addr)+1;
  tmp = addr;
  addr = realloc(addr,addrlen);
  /* if realloc() fails, we just ignore it and use the previously allocated memory, although this may be wasteful */
  if (!addr)
    addr=tmp; /* restore previous state */
  else
    addr[addrlen-1]=0;
  
  portlen = strlen(port)+1;
  tmp=port;
  port = realloc(port,portlen);
  if (!port)
    port=tmp;
  else
    port[portlen-1]=0;
  
  *ssp = ss;
  *addrp = addr;
  *addrlenp = addrlen;
  *portp = port;
  *portlenp = portlen;
  
  return 0;
}
