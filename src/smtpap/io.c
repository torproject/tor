#include <sys/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <malloc.h>

#include "../common/log.h"
#include "../common/utils.h"

#include "smtpap.h"
#include "io.h"

/* connection timeout */
extern struct timeval *conn_toutp;

/* printf-like function used to send messages to a socket */
int sendmessage(int s, char *buf, size_t buflen, const char *format, ...)
{
  int retval = 0;
  va_list ap;
  
  if (!buf)
    return -1;
  
  va_start(ap,format);
  retval = vsnprintf(buf,buflen, format, ap);
  va_end(ap);
  
  if (retval < 0) 
  {
    log(LOG_DEBUG,"sendmessage() : could not print to buffer");
    return -1;
  }

  log(LOG_DEBUG,"sendmessage() : printed this to buffer : %s",buf);
  
  retval = write_tout(s,buf,(size_t)retval, conn_toutp);
  if (retval < 0)
  {
    log(LOG_DEBUG,"sendmessage() : could not send");
    return -1;
  }
  
  return retval;
}

/* receive a response from the recipient SMTP server into *op_in
 * Can handle multi-line responses. */
int receive(int s, char **inbuf,size_t *inbuflen, int flags)
{
  int inputlen = 0; /* running total length of the input */
  int inputerror = 0; /* has an error occured? */
  int retval = 0; /* used for saving function return values */
  
  /* for processing multi-line responses */
  int i=0;
  
  /* storing old values of *inbuf and *inbuflen */
  char *inbuf_old = NULL;
  size_t inbuflen_old=0;
  
  if ((!inbuf) || (!*inbuf) || (!inbuflen))
    return -1;

  /* saving old values in case we need to restore them */
  inbuf_old = *inbuf;
  inbuflen_old = *inbuflen;

  do
  {
    if (inputlen == *inbuflen-1) /* we need to increase the buffer size */
    {
      /* increase the size of the buffer */
      *inbuflen += 512;
      
      *inbuf = (char *)realloc(*inbuf,(size_t)*inbuflen);
      if (!*inbuf)
      {
	log(LOG_ERR,"Could not allocate memory.");
	*inbuf = inbuf_old;
	*inbuflen = inbuflen_old;
	inputerror = 1;
	break;
      }
    }
    
    retval=read_tout(s,*inbuf+inputlen,(size_t)(*inbuflen-inputlen-1),flags, conn_toutp); /* subtract 1 from inbuflen to leave space for \0 */
    if (retval <= 0)
    {
      log(LOG_ERR,"Error occured while receiving data.");
      inputerror = 1;
      break;
    }
    else
    {
      inputerror = 0;
      inputlen += retval;

      /* exit clause if we have received CRLF, otherwise we need to keep reading*/
      /* also keep on reading if it's a multi-line response */
      if (inputlen >= SMTPAP_CRLF_LEN)
      {
	if (!strncmp(*inbuf+inputlen-SMTPAP_CRLF_LEN,SMTPAP_CRLF,SMTPAP_CRLF_LEN)) /* entire line received */
	{
	  /* now check wether we should expect more lines */
	  /* find the <CRLF> sequence which occurs one before last */
	  for(i=inputlen-SMTPAP_CRLF_LEN-1; i > 0; i--) /* move backwards, start just before the final CRLF */
	  {
	    if ((*inbuf)[i] == SMTPAP_LF) /* got a LF */
	    {
	      /* check for a CR preceding it */
	      if ((*inbuf)[i-1] == SMTPAP_CR) /* got a CR */
		break;
	    }
	  }
	  if (i==0) /* correct the offset if no CRLF found */
	    i=-1;

	  /* check the 4th character after the <CRLF> to see if it is - or <SP> */
	  if ((*inbuf)[i+4] != '-') /* no more lines */
	    break;
	}
      }
    }
  } while(1); 
  
  if (!inputerror)
  {
    (*inbuf)[inputlen]=0; /* add the terminating NULL character */
    return inputlen;
  }

  return -1;
}
