/**
 * smtpap.c 
 * SMTP Application Proxy for Onion Routing
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.2  2002/07/12 18:14:17  montrose
 * removed loglevel from global namespace. severity level is set using log() with a NULL format argument now. example: log(LOG_ERR,NULL);
 *
 * Revision 1.1.1.1  2002/06/26 22:45:50  arma
 * initial commit: current code
 *
 * Revision 1.32  2002/04/02 14:29:49  badbytes
 * Final finishes.
 *
 * Revision 1.31  2002/03/25 08:03:17  badbytes
 * Added header sanitization.
 *
 * Revision 1.30  2002/03/02 23:54:06  mp292
 * Fixed missing CRLFs at the end of error messages.
 *
 * Revision 1.29  2002/01/29 01:00:10  mp292
 * All network operations are now timeoutable.
 *
 * Revision 1.28  2002/01/28 21:38:18  mp292
 * Fixed bugs in RSET handling. Added Anonimize option which signifies whether
 * the router should falsify the identity of the sender or not.
 *
 * Revision 1.27  2002/01/26 22:45:02  mp292
 * Now handles SS_ERROR_INVALID_PORT.
 *
 * Revision 1.26  2002/01/26 22:33:21  mp292
 * Removed hard-coded values for onion proxy return codes. Also fixed a bug in
 * parameter checking.
 *
 * Revision 1.25  2002/01/26 21:58:27  mp292
 * Added some missing parameter checking.
 *
 * Revision 1.24  2002/01/26 21:50:17  mp292
 * Reviewed according to Secure-Programs-HOWTO. Still need to deal with network
 * timeouts.
 *
 * Revision 1.23  2002/01/18 21:07:02  mp292
 * (a) THe form of HELO is now HELO Anonymous.Smtp.Daemon rather than the real
 * address. (b) The user *can* now specify a default SMTP daemon to route through
 * although this is insecure and not recommended.
 *
 * Revision 1.22  2002/01/16 23:01:58  mp292
 * First phase of system testing completed (main functionality).
 *
 * Revision 1.21  2002/01/16 17:04:01  mp292
 * Bug in checking whether incoming connection is local or not.
 *
 * Revision 1.20  2002/01/09 09:18:22  badbytes
 * Now handles EINTR error from accept().
 *
 * Revision 1.19  2001/12/19 11:15:27  badbytes
 * Corrected AF_INET to PF_INET in socket() calls.
 *
 * Revision 1.18  2001/12/19 08:36:04  badbytes
 * Incorrect error checking in recv() calls caused zombies ... fixed
 *
 * Revision 1.17  2001/12/18 14:42:46  badbytes
 * Variable name op_port_str was incorrectly named, changed to dest_port_str
 *
 * Revision 1.16  2001/12/18 13:20:16  badbytes
 * Some error messages did not include a terminating <CRLF>
 *
 * Revision 1.15  2001/12/18 12:37:23  badbytes
 * Found an overflow bug ...
 *
 * Revision 1.14  2001/12/18 09:17:31  badbytes
 * Corrected a spelling mistake in print_usage()
 *
 * Revision 1.13  2001/12/14 13:13:24  badbytes
 * Changed types.h references to ss.h
 *
 * Revision 1.12  2001/12/14 09:17:25  badbytes
 * Moved function stolower(char *str) from smtpap.c to common/utils.c
 *
 * Revision 1.11  2001/12/13 13:51:05  badbytes
 * Fixed a bug in processing command-line parameters.
 *
 * Revision 1.10  2001/12/13 13:36:44  badbytes
 * Now accepts the -l command-line option which specifies the logging threshold.
 *
 * Revision 1.9  2001/12/12 16:02:29  badbytes
 * Testing completed.
 *
 * Revision 1.8  2001/12/11 16:30:20  badbytes
 * Some bugs removed, still testing though.
 *
 * Revision 1.7  2001/12/11 14:12:20  badbytes
 * Onion Proxy connection setup completed. Proceeding to test.
 *
 * Revision 1.6  2001/12/11 10:43:21  badbytes
 * MAIL and RCPT handling completed. Still coding connection to Onion Proxy.
 *
 * Revision 1.5  2001/12/10 16:10:35  badbytes
 * Wrote a tokenize() function to help with parsing input from SMTP clients.
 *
 * Revision 1.4  2001/12/07 15:02:43  badbytes
 * Server setup code completed.
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
#include <signal.h>
#include <wait.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../common/log.h"
#include "../common/config.h"
#include "../common/ss.h"
#include "../common/utils.h"
#include "../common/version.h"

#include "smtpap.h"
#include "io.h"

struct timeval conn_tout;
struct timeval *conn_toutp = &conn_tout;

/* valid command-line options */
static const char *args = "hf:p:l:";

/* valid config file options */
static config_opt_t options[] =
{
  {"OnionProxy", CONFIG_TYPE_INT, {0}, 0},
  {"MaxConn", CONFIG_TYPE_INT, {0}, 0},
  {"Anonimize", CONFIG_TYPE_INT, {0}, 0},
  {"ConnTimeout", CONFIG_TYPE_INT, {0}, 0},
  {0}
};
enum opts {
  OnionProxy=0,MaxConn, Anonimize, ConnTimeout
};

/* number of open connections */
int connections=0;

/* prints help on using smtpap */
void print_usage()
{
  char *program = "smtpap";
  
  printf("\n%s - SMTP application proxy for Onion Routing.\nUsage : %s -f config [-p port -l loglevel -h]\n-h : display this help\n-f config : config file\n-p port : port number which %s should bind to\n-l loglevel : logging threshold; one of alert|crit|err|warning|notice|info|debug\n\n", program,program,program);
}

/* used for reaping zombie processes */
void sigchld_handler(int s)
{
  while (wait(NULL) > 0);
  connections--;
}

/* takes the contents of a RCPT command in a null-terminated string and retrieves the address
 * of the corresponding recipient domain*/
char *extract_smtp_dest(char *rcptbuf)
{
  char *dest_smtp=NULL;
  char *pos1, *pos2;

  if (!rcptbuf)
    return NULL;
  
  pos1 = (char *)strchr(rcptbuf,'@');
  if (pos1 == NULL)
    return NULL;
  
  pos2 = (char *)strpbrk(pos1,SMTPAP_PATH_SEPCHARS);
  if (pos2 == NULL)
    return NULL;
  else 
  {
    dest_smtp = (char *)malloc((size_t)(pos2-pos1));
    if (!dest_smtp)
    {
      log(LOG_ERR,"Could not allocate memory.");
      return NULL;
    }
    else
    {
      strncpy(dest_smtp,pos1+1,(size_t)(pos2-pos1-1));
      dest_smtp[pos2-pos1-1] = 0;
    }
  }
  
  return dest_smtp;
}

/* process a DATA stream and remove any e-mail headers */
int sanitize_data(unsigned char **buf, int *buflen)
{
  unsigned char *offset; /* offset to data after the last header */
  unsigned char *crlf = NULL;
  unsigned char *colon = NULL;
  unsigned char *line;
  unsigned char *newbuf;
  int newbuflen;
  
  if ((!buf) || (!buflen)) /* invalid parameters */
    return -1;
  
  offset = *buf;
  line = *buf;
  /* process the data line by line and discard anything that looks like a header */
  while(1)
  {
    /* find the end of line */
    crlf = strstr(line, SMTPAP_CRLF);
    if (crlf)
    {
      colon = (unsigned char *)memchr((void *)line,(int)':',crlf-line);
      if (!colon)
	break; /* this doesn't seem to be a header, can stop */
      else
	offset = crlf + 2; /* discard this line */
      
      line = crlf + 2; /* move on to the next line */
    }
    else /* no more CRLFs found, end of data */
      /* NB : there is no need to check the current line at this stage as this will be of the form <CRLF>.<CRLF> */
      /*      we should never reach this point in the code anyway, the '.' will be trapped as a non-header line in the above code */
      break;
  }
  
  if (offset != *buf) /* data changed */
  {
    newbuflen = *buflen - (offset - *buf);
    newbuf = (unsigned char *)malloc(newbuflen+1); /* leave space for a terminating NULL character */
    if (!newbuf) /* malloc() error */
      return -1;
    else
    {
      /* copy into the new buffer */
      memcpy((void *)newbuf, (void *)offset, newbuflen);
      newbuf[newbuflen] = 0;
      
      /* replace the old buffer with the new one */
      free((void *)*buf);
      *buf = newbuf;
      *buflen = newbuflen;
    }
  }
  
  return 0;
}

/* main logic of smtpap */
int handle_connection(int s, struct hostent *local, struct sockaddr_in remote, u_short op_port)
{
  int retval = 0;
  int state = 0; /* 0 - start / RSET received
		  * 1 - connection not local, waiting for QUIT
		  * 2 - connection local, waiting for HELO/EHLO
		  * 3 - HELO/EHLO received, waiting for MAIL
		  * 4 - MAIL received, waiting for RCPT
		  * 5 - waiting for DATA
		  * 6 - DATA received, accepting data
		  *   - data accepted, back to state 3
		  */
  int islocal = 0;
  char *cp;
  int i=0;
  char message[512]; /* for storing outgoing messages */
  char *inbuf = NULL; /* for storing incoming messages */
  char *token = NULL; /* next token in the incoming message */
  char *tmpbuf = NULL; /* temporary buffer for copying data */
  char *mailbuf = NULL; /* storing the MAIL command */
  char **rcptarray = NULL; /* storing a NULL-terminated array of RCPT commands */
  char *rcptbuf = NULL; /* storing a single RCPT command */
  int tmpbuflen = 0; /* length of tmpbuflen in bytes */
  int inbuflen = 0; /* length of inbuf in bytes */
  int inputlen = 0; /* length of actual input in bytes */
  int mailbuflen=0; /* etc ... */
  int rcptbuflen=0;
  int inputerror=0; /* error occured when receiving data from the client */
  
  /* the following is used for conecting to the SMTP host through the OR network */
  char *dest_addr_str = NULL; /* for storing the ASCII address of the destination SMTP */
  int sop=-1; /* socket for connecting to the onion proxy */
  struct sockaddr_in op_addr; /* stores the address of the onion proxy */
  ss_t ss; /* standard structure */
  char dest_port_str[6]; /* ascii representation of the destination port */
  /* input and output buffers for talking to the onion proxy */
  char *op_out = NULL;
  char *op_in = NULL;
  int op_outlen = 0;
  int op_inlen = 0;
  
  int partial_dataend = 0; /* used for recognising the <CRLF>.<CRLF> sequence that ends the DATA segment */

  if (!local)
    return -1;
  
  log(LOG_DEBUG, "handle_connection() : Local address = %s.", inet_ntoa(*(struct in_addr *)local->h_addr));
  log(LOG_DEBUG, "handle_connection() : Remote address = %s.", inet_ntoa(remote.sin_addr));
  
  /* first check that the connection is from the local host, otherwise reject */
  if (*(uint32_t *)&remote.sin_addr == inet_addr("127.0.0.1"))
          islocal = 1;
  for (i=0; (local->h_addr_list[i] != NULL) && (!islocal); i++)
  {
    cp = local->h_addr_list[i];
    log(LOG_DEBUG,"handle_connection() : Checking if connection is from address %s.",inet_ntoa(*(struct in_addr *)cp));
    if (!memcmp(&remote.sin_addr, cp, sizeof(struct in_addr)))
      islocal = 1;
  }
  
  if (islocal)
  {
    log(LOG_DEBUG,"handle_connection() : Connection seems to be local. Will accept.");
    state = 2;
    sendmessage(s, (char *)message, (size_t)512, "220 This is smtpap v1.0 running on %s.%s",local->h_name,SMTPAP_CRLF);
  }
  else
  {
    log(LOG_DEBUG,"handle_connection() : Connection doesn't seem to be local. Will reject.");
    state = 1;
    sendmessage(s,(char *)message, (size_t)512,"554 smtpap v1.0 Connection refused. Only local connections allowed.%s",SMTPAP_CRLF);
  }
  
  /* initially allocate 512 bytes for incoming message buffer */
  inbuf = (char *)malloc((size_t)512);
  if (!inbuf)
  {
    log(LOG_ERR,"Could not allocate memory.");
    return -1;
  }
  inbuflen = 512;

  /* initially allocate 512 bytes for the temporary buffer */
  tmpbuf = (char *)malloc((size_t)512);
  if (!tmpbuf)
  {
    log(LOG_ERR,"Could not allocate memory.");
    free(inbuf);
    return -1;
  }
  tmpbuflen = 512;
  
  while(1)
  {
    inputlen = 0;
    do
    {
      if (inputlen == inbuflen-1) /* we need to increase the buffer size */
      {
	/* increase the size of the buffers */
	inbuflen += 512;
	tmpbuflen += 512;
	
	inbuf = (char *)realloc(inbuf,(size_t)inbuflen);
	if (!inbuf)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  inputerror = 1;
	  break;
	}
	
	tmpbuf = (char *)realloc(tmpbuf,(size_t)tmpbuflen);
	if (!tmpbuf)
	{
	  log(LOG_ERR,"Could not allocate memory.");
	  free(inbuf);
	  inputerror = 1;
	  break;
	}
      }
      
      retval=read_tout(s,inbuf+inputlen,(size_t)(inbuflen-inputlen-1),0, conn_toutp); /* subtract 1 from inbuflen to leave space for \0 */
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
	
	/* exit clause if we have received CRLF or SMTPAP_ENDDATA, otherwise we need to keep reading*/
	if ( (state == 6) && (inputlen >= SMTPAP_ENDDATA_LEN) )
	{
	  if (!strncmp(inbuf+inputlen-SMTPAP_ENDDATA_LEN,SMTPAP_ENDDATA,SMTPAP_ENDDATA_LEN))
	    break;
	}
	else if ( (state != 6) && (inputlen >= SMTPAP_CRLF_LEN) )
	{
	  if (!strncmp(inbuf+inputlen-SMTPAP_CRLF_LEN,SMTPAP_CRLF,SMTPAP_CRLF_LEN))
	    break;
	}
      }
    } while(1); 
    
    if (inputerror != 0)
      break;
    
    if (*inbuf == EOF)
    {
      log(LOG_DEBUG,"handle_connection() : Received EOF. Exiting.");
      break;
    }
    
    inbuf[inputlen]=0; /* add the terminating NULL character */
    log(LOG_DEBUG, "Received this from client : %s",inbuf);
    
    /* save a copy of inbuf into tmpbuf, because calls to strtok() will change it */
    strcpy(tmpbuf,inbuf);
    
    /* now handle input depending on the state */
    
    /* first check for a quit */
    token = stolower((char *)strtok(inbuf,SMTPAP_SEPCHARS));
    log(LOG_DEBUG,"handle_connection() : First token is %s.",token);
    if ((!strcmp(token,SMTPAP_QUIT)) && (state != 6)) /* QUIT command - but doesn't count in state 6
									* That's when we are receiving DATA input
									*/
    {
      sendmessage(s,(char *)message, (size_t)512,"221 %s closing connection. Goodbye.%s",local->h_name,SMTPAP_CRLF);
      break;
    }
    /* check for a RSET */
    if ((!strcmp(token,SMTPAP_RSET)) && (state !=6)) /* RSET command - again, doesn't count in state 6 */
    {
      sendmessage(s,(char *)message,(size_t)512,"250 RSET received.%s",SMTPAP_CRLF);
      /* clean up message state */
      if (mailbuf != NULL)
      {
	free(mailbuf);
	mailbuf = NULL;
      }
      if (rcptarray != NULL)
      {
	free(rcptarray);
	rcptarray = NULL;
      }
      if (rcptbuf != NULL)
      {
	free(rcptbuf);
	rcptbuf=NULL;
      }
      
      close(sop);
      
      /* set state to 2/3 (depending on wether we have recieved HELO yet) and loop back and start again */
      if (state != 2)
	state=3;

      continue;
    }
    
    if (state == 1)
    {
      sendmessage(s,(char *)message, (size_t)512,"503 Connection refused. Please QUIT.%s",SMTPAP_CRLF);
    }
    else if (state == 2)
    {
      if ((!strcmp(token,SMTPAP_HELO)) || (!strcmp(token,SMTPAP_EHLO)))
      {
	token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	if (!token) /* no more tokens in inbuf */
	{
	  log(LOG_DEBUG,"handle_connection() : handle_connection : Received HELO/EHLO without arguments.");
	  sendmessage(s,(char *)message,(size_t)512,"500 HELO/EHLO requires domain address.%s",SMTPAP_CRLF);
	}
	else
	{
	  log(LOG_DEBUG,"handle_connection() : handle_connection : Received HELO/EHLO with the following domain address : %s.",token);
	  state =3;
	  sendmessage(s,(char *)message,(size_t)512,"250 Hello user at %s. Pleased to meet you.%s",inet_ntoa(remote.sin_addr),SMTPAP_CRLF);
	}
      }
      else
	sendmessage(s,(char *)message,(size_t)512,"503 Expecting either HELO/EHLO or QUIT.%s",SMTPAP_CRLF);
    }
    else if (state == 3)
    {
      int further_check=0;
      if ((!strncmp(token,SMTPAP_MAIL,SMTPAP_MAIL_LEN)))
      {
	token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	if (!token)
	{
	  sendmessage(s,(char *)message,(size_t)512,"500 MAIL requires From:<sender@address> .%s",SMTPAP_CRLF);
	}
	else
	{
	  stolower(token);
	  if (!strcmp(token,"from:")) /* from: separate from the address */
	  {
	    token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	    if (token == NULL) /* expected another parameter but it's not there */
	    {
	      log(LOG_DEBUG,"handle_connection() : Received MAIL From: without an address.");
	      sendmessage(s,(char *)message,(size_t)512,"500 MAIL From: requires sender address.%s",SMTPAP_CRLF);
	      further_check = 0;
	    }
	    else /* continue further checking */
	      further_check = 1;
	  }
	  else if (!strcmp(token,"from")) /* probably from : address */
	  {
	    token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	    if (token == NULL) /* not enough parameters */
	    {
	      log(LOG_DEBUG,"handle_connection() : Received Mail From with no other parameters.");
	      sendmessage(s,(char *)message,(size_t)512, "500 MAIL From: requires sender address.%s",SMTPAP_CRLF);
	      further_check=0;
	    }
	    else if ( (token[0] == ':') && (token[1]!='\0') ) /* contains :address */
	    {
	      token++;
	      further_check=1;
	    }
	    else if ( (token[0] == ':') && (token[1]=='\0') )/* the address is in the next token */
	    {
	      token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	      if (token == NULL) /* not enough parameters */
	      {
		log(LOG_DEBUG,"handle_connection() : Received Mail From : with no other parameters.");
		sendmessage(s,(char *)message,(size_t)512,"500 MAIL From: requires sender address.%s",SMTPAP_CRLF);
		further_check = 0;
	      }
	      else /* continue further checking */
		further_check =1;
	    }
	    else /* couldn't find a colon (:) */
	    {
	      log(LOG_DEBUG,"handle_connection() : Couldn't find a colon in the received MAIL command.");
	      sendmessage(s,(char *)message,(size_t)512,"500 There is a colon (:) missing in that command.%s",SMTPAP_CRLF);
	      further_check = 1;
	    }
	  }
	  else /* probably from:address */
	  {
	    if (!strncmp(token,"from:",5)) /* string starts with from: */
	    {
	      token += 5; /* skip the from: bit */
	      further_check = 1; /* continue further checking */
	    }
	    else /* error */
	    {
	      log(LOG_DEBUG,"handle_connection() : MAIL parameters don't start with from: .");
	      sendmessage(s,(char *)message,(size_t)512,"500 MAIL requires From:<sender@address>.%s",SMTPAP_CRLF);
	      further_check=0;
	    }
	  }
	  if (further_check == 1) /* check that this is in the correct, format - we can't handle anything else
				  * but straightforward <user@host> representation, <> optional
				  */
	  {
	    if (((cp = (char *)strchr(token,',')) != NULL) || ((cp = (char *)strchr(token,':')) != NULL)) /* path contains , or : - can't cope with that */
	    {
	      log(LOG_DEBUG,"handle_connection() : The client is probably trying to specify a reverse path, which I can't handle.");
	      sendmessage(s,(char *)message,(size_t)512,"500 I can only handle a simple return address.%s",SMTPAP_CRLF);
	    }
	    else if ((cp = (char *)strchr(token,'@')) == NULL) /* no @, that is most likely a problem :-) */
	    {
	      log(LOG_DEBUG,"handle_connection() : The client specified a sender address with no @.");
	      sendmessage(s,(char *)message,(size_t)512,"500 Domain name required.%s",SMTPAP_CRLF);
	    }
	    else /* the mail command seems to be OK, save it */
	    {
	      if (mailbuf != NULL)
		free(mailbuf);
	      mailbuflen = strlen(tmpbuf) + 1;
	      mailbuf = (char *)malloc(mailbuflen);
	      if (!mailbuf)
	      {
		log(LOG_ERR,"Could not allocate memory.");
		sendmessage(s,(char *)message,(size_t)512,"451 Insufficient memory.%s",SMTPAP_CRLF);
	      }
	      else
	      {
		strncpy(mailbuf,tmpbuf,mailbuflen);
		mailbuf[mailbuflen-1] = '\0'; /* add the terminating NULL character */
		log(LOG_DEBUG,"handle_connection() : MAIL command saved as %s.",mailbuf);
		
		/* send an OK response to the client */
		sendmessage(s,(char *)message,(size_t)512,"250 Sender address OK.%s",SMTPAP_CRLF);
		state=4;
	      }
	    }
	  }
	}
      }
      else
	sendmessage(s,(char *)message, (size_t)512,"503 Need MAIL first.%s",SMTPAP_CRLF);
    }
    else if(state == 4)
    {
      int further_check=0;
      if ((!strcmp(token,SMTPAP_RCPT)))
      {
	token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	if (!token)
	{
	  sendmessage(s,(char *)message,(size_t)512,"500 RCPT requires To:<recipient@address> .%s",SMTPAP_CRLF);
	}
	else
	{
	  stolower(token);
	  if (!strcmp(token,"to:")) /* to: separate from the address */
	  {
	    token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	    if (token == NULL) /* expected another parameter but it's not there */
	    {
	      log(LOG_DEBUG,"handle_connection() : Received RCPT To: without an address.");
	      sendmessage(s,(char *)message,(size_t)512,"500 RCPT To: requires recipient address.%s",SMTPAP_CRLF);
	      further_check = 0;
	    }
	    else /* continue further checking */
	      further_check = 1;
	  }
	  else if (!strcmp(token,"to")) /* probably to : address or to :address */
	  {
	    token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	    if (token == NULL) /* not enough parameters */
	    {
	      log(LOG_DEBUG,"handle_connection() : Received RCPT To with no other parameters.");
	      sendmessage(s,(char *)message,(size_t)512, "500 RCPT To: requires recipient address.%s",SMTPAP_CRLF);
	      further_check=0;
	    }
	    else if ( (token[0] == ':') && (token[1]!='\0') ) /* contains :address */
	    {
	      token++;
	      further_check=1;
	    }
	    else if ( (token[0] == ':') && (token[1]=='\0') )/* the address is in the next token */
	    {
	      token = (char *)strtok(NULL,SMTPAP_SEPCHARS);
	      if (token == NULL) /* not enough parameters */
	      {
		log(LOG_DEBUG,"handle_connection() : Received RCPT To : with no other parameters.");
		sendmessage(s,(char *)message,(size_t)512,"500 RCPT To: requires recipient address.%s",SMTPAP_CRLF);
		further_check = 0;
	      }
	      else /* continue further checking */
		further_check =1;
	    }
	    else /* couldn't find a colon (:) */
	    {
	      log(LOG_DEBUG,"handle_connection() : Couldn't find a colon in the received RCPT command.");
	      sendmessage(s,(char *)message,(size_t)512,"500 There is a colon (:) missing in that command.%s",SMTPAP_CRLF);
	      further_check = 1;
	    }
	  }
	  else /* probably to:address */
	  {
	    if (!strncmp(token,"to:",3)) /* string starts with from: */
	    {
	      token += 3; /* skip the to: bit */
	      further_check = 1; /* continue further checking */
	    }
	    else /* error */
	    {
	      log(LOG_DEBUG,"handle_connection() : RCPT parameters don't start with to: .");
	      sendmessage(s,(char *)message,(size_t)512,"500 RCPT requires To:<recipient@address>.%s",SMTPAP_CRLF);
	      further_check=0;
	    }
	  }
	  if (further_check == 1) /* check that this is in the correct, format - we can't handle anything else
				  * but straightforward <user@host> representation, <> optional
				  */
	  {
	    if (((cp = (char *)strchr(token,',')) != NULL) || ((cp = (char *)strchr(token,':')) != NULL)) /* path contains , or : - can't cope with that */
	    {
	      log(LOG_DEBUG,"handle_connection() : The client is probably trying to specify a forward path, which I can't handle.");
	      sendmessage(s,(char *)message,(size_t)512,"500 I can only handle a simple recipient address.%s",SMTPAP_CRLF);
	    }
	    else if ((cp = (char *)strchr(token,'@')) == NULL) /* no @, that is most likely a problem :-) */
	    {
	      log(LOG_DEBUG,"handle_connection() : The client specified a recipient address with no @.");
	      sendmessage(s,(char *)message,(size_t)512,"500 Domain name required.%s",SMTPAP_CRLF);
	    }
	    else /* the rcpt command seems to be OK, save it */
	    {
	      if (rcptbuf != NULL)
	      {
		free(rcptbuf);
		rcptbuf = NULL;
	      }
	      rcptbuflen = strlen(tmpbuf) + 1;
	      rcptbuf = (char *)malloc(rcptbuflen);
	      if (!rcptbuf)
	      {
		log(LOG_ERR,"Could not allocate memory.");
		sendmessage(s,(char *)message,(size_t)512,"451 Insufficient memory.%s",SMTPAP_CRLF);
	      }
	      else
	      {
		strncpy(rcptbuf,tmpbuf,rcptbuflen);
		rcptbuf[rcptbuflen-1] = '\0'; /* add the terminating NULL character */
		log(LOG_DEBUG,"handle_connection() : handle_connection : RCPT command saved.");
		
		/* attempt to connect to the destination SMTP server through the OR network */
		/* first extract the destination address */
		dest_addr_str = extract_smtp_dest(rcptbuf);
		log(LOG_DEBUG,"handle_connection() : handle_connection : called extract_smtp_dest()");
		if (!dest_addr_str)
		{
		  log(LOG_DEBUG,"handle_connection() : Could not extract a destination SMTP address from the specified recipient address.");
		  sendmessage(s,(char *)message,(size_t)512,"550 Could not extract destination domain.%s",SMTPAP_CRLF);
		}
		else
		{
		  /* fill in the standard structure */
		  ss.version = VERSION;
		  ss.protocol= SS_PROTOCOL_SMTP;
		  ss.retry_count = 0;
		  ss.addr_fmt = SS_ADDR_FMT_ASCII_HOST_PORT;
		  
		  /* open a socket for connecting to the proxy */
		  sop = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		  if (sop < 0)
		  {
		    log(LOG_DEBUG,"handle_connection() : handle_connection : Error opening socket.");
		    sendmessage(s,(char *)message,(size_t)512,"451 Could not connect to the onion proxy.%s",SMTPAP_CRLF);
		    if (dest_addr_str != NULL) {
		      free(dest_addr_str);
		      dest_addr_str = NULL;
		    }
		  }
		  else
		  {
		    log(LOG_DEBUG,"handle_connection() : handle_connection : Socket opened.");
		    memset((void *)&op_addr,0,sizeof(op_addr)); /* clear the structure first */
		    /* set up the sockaddr_in structure */
		    op_addr.sin_family=AF_INET;
		    op_addr.sin_port=htons(op_port);
		    memcpy((void *)&op_addr.sin_addr,local->h_addr,local->h_length);
		    log(LOG_DEBUG,"handle_connection() : Trying to connect to %s at port %u.",inet_ntoa(*((struct in_addr *)local->h_addr)),op_port);
		    
		    /* try to connect */
		    retval = connect(sop,(struct sockaddr *)&op_addr,sizeof(op_addr));
		    if (retval == -1)
		    {
		      sendmessage(s,(char *)message,(size_t)512,"451 Could not connect to the onion proxy.%s",SMTPAP_CRLF);
		      close(sop);
		      if (dest_addr_str != NULL)
		      {
			free(dest_addr_str);
			dest_addr_str = NULL;
		      }
		    }
		    else /* connection established, now send the standard structure + address and wait for a response */
		    {
		      /* write the message to the op_out buffer */
		      snprintf(dest_port_str,6,"%u",htons(SMTPAP_DEFAULT_SMTP_PORT));

		      if (op_out != NULL)
		      {
			free(op_out);
			op_out = NULL;
		      }

		      op_outlen = sizeof(ss) /* standard structure */
			+ strlen(dest_addr_str) /* destination address */
			  + 1 /* terminating NULL character */
			+ strlen(dest_port_str)
			  + 1; /* terminating NULL character */
		      op_out = (char *)malloc(op_outlen);

		      if (!op_out) /* error */
		      {
			log(LOG_DEBUG,"handle_connection() : handle_connection : Could not allocate memory.");
			sendmessage(s,(char *)message,(size_t)512,"451 Insufficient memory.%s",SMTPAP_CRLF);
			close(sop);
			if (dest_addr_str != NULL)
			{
			  free(dest_addr_str);
			  dest_addr_str = NULL;
			}
		      }
		      else
		      {
			memcpy(op_out,(void *)&ss,sizeof(ss));
			strcpy(op_out+sizeof(ss), dest_addr_str);
			strcpy(op_out+sizeof(ss)+strlen(dest_addr_str)+1,dest_port_str);
			/* now send the message */
			retval = write_tout(sop,op_out,op_outlen,conn_toutp);
			/* now clean up the buffers */
			op_outlen = 0;
			free(op_out);
			free(dest_addr_str);
			if (retval == -1) /* send failed */
			{
			  log(LOG_DEBUG,"handle_connection() : handle_connection : send() failed.");
			  sendmessage(s,(char *)message,(size_t)512,"451 Could not send to onion proxy.%s",SMTPAP_CRLF);
			  close(sop);
			}
			else /* send seemed to have succeeded */
			{
			  /* wait for the return code */
			  op_inlen = 1;
			  op_in = (char *)malloc(op_inlen);
			  if (!op_in) /* memory allocation failed */
			  {
			    log(LOG_DEBUG,"handle_connection() : handle_conection : Could not allocate memory.");
			    sendmessage(s,(char *)message,(size_t)512,"451 Insufficient memory.%s",SMTPAP_CRLF);
			    close(sop);
			  }
			  else
			  {
			    retval = read_tout(sop,op_in,1,0, conn_toutp);
			    if (retval <= 0) /* recv() failed */
			    {
			      log(LOG_DEBUG,"handle_connection() : handle_connection : recv() failed.");
			      sendmessage(s,(char *)message,(size_t)512,"451 Could not receive data from the onion proxy.%s",SMTPAP_CRLF);
			      close(sop);
			    }
			    else
			    {
			      if (!(*op_in)) /* onion proxy says OK */
			      {
				log(LOG_DEBUG,"handle_connection() : handle_connection : received E_SUCCESS from onion proxy");
				/* clean up */
				free(op_in);
				op_inlen=0;
				
				/* allocate both op_in and op_out 512 bytes, the maximum size of an SMTP line */
				op_outlen=512;
				op_inlen=512;
				op_out = (char *)malloc(512);
				op_in = (char *)malloc(512);
				if ((!op_out) || (!op_in))
				{
				  log(LOG_DEBUG,"handle_connection() : handle_connection : Could not allocate memory.");
				  sendmessage(s,(char *)message,(size_t)512,"451 Insufficient memory.%s",SMTPAP_CRLF);
				  close(sop);
				}
				else
				{
				  /* receive the greeting message from the recipient */
				  retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
				  if (retval == -1) /* could not receive greeting */
				  {
				    
				    log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving greeting from recipient.");
				    sendmessage(s,(char *)message,(size_t)512,"451 Error receiving data from the recipient.%s",SMTPAP_CRLF);
				  }
				  else /* received greeting */
				  {
				    /* send HELO command */
				    retval = sendmessage(sop,(char *)op_out,(size_t)op_outlen,"HELO ANONYMOUS.smtp.daemon%s",SMTPAP_CRLF);
				    if (retval == -1)
				    {
				      sendmessage(s,(char *)message,(size_t)512,"451 Error sending HELO to the recipient.");
				      close(sop);
				    }
				    else
				    {
				      
				      retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
				      if (retval == -1)
				      {
					log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving HELO response from recipient");
					sendmessage(s,(char *)message,(size_t)512,"451 Error receiving data from the recipient.%s",SMTPAP_CRLF);
					close(sop);
				      }
				      else
				      {
					op_in[retval]=0;
					log(LOG_DEBUG,"handle_connection() : handle_connection : Received this from recipient : %s.",op_in);
					if (op_in[0] == '2') /* success */
					{
					  /* send MAIL */
					  if (options[Anonimize].r.i)
					    retval = sendmessage(sop,(char *)op_out,(size_t)op_outlen,"MAIL From:anonymous@anon.net%s",SMTPAP_CRLF);
					  else
					    retval = write_tout(sop,mailbuf,mailbuflen-1,conn_toutp);
					  if (retval == -1)
					  {
					    log(LOG_DEBUG,"handle_connection() : handle_connection : error sending MAIL to recipient");
					    sendmessage(s,(char *)message,(size_t)512,"451 Error sending MAIL to the recipient.%s",SMTPAP_CRLF);
					    sendmessage(sop,(char *)op_out,(size_t)op_outlen,"%s%s",SMTPAP_QUIT,SMTPAP_CRLF);
					    close(sop);
					  }
					  else
					  {
					    retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
					    if (retval == -1)
					    {
					      log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving MAIL response from recipient");
					      sendmessage(s,(char *)message,(size_t)512,"451 Error receiving data from the recipient.%s",SMTPAP_CRLF);
					      close(sop);
					    }
					    else
					    {
					      op_in[retval]=0;
					      log(LOG_DEBUG,"handle_connection() : handle_connection : Received this from recipient : %s.",op_in);
					      if (op_in[0] == '2') /* success */
					      {
						/* send RCPT */
						retval = write_tout(sop,rcptbuf,rcptbuflen-1,conn_toutp); /* rcptbuflen includes the terminating NULL character but we don't want to send that */
						if (retval == -1)
						{
						  log(LOG_DEBUG,"handle_connection() : handle_connection : error sending RCPT to recipient");
						  sendmessage(s,(char *)message,(size_t)512,"451 Error sending RCPT to the recipient.%s",SMTPAP_CRLF);
						  sendmessage(sop,(char *)op_out,(size_t)op_outlen,"%s%s",SMTPAP_QUIT,SMTPAP_CRLF);
						  close(sop);
						}
						else
						{
						  retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
						  if (retval == -1)
						  {
						    log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving RCPT response from recipient");
						    sendmessage(s,(char *)message,(size_t)512,"451 Error receiving data from the recipient.%s",SMTPAP_CRLF);
						    close(sop);
						  }
						  else
						  {
						    op_in[retval]=0;
						    log(LOG_DEBUG,"handle_connection() : handle_connection : Received this from recipient : %s.",op_in);
						    if (op_in[0] == '2') /* success */
						    {
						      sendmessage(s,(char *)message,(size_t)512,"250 Recipient OK.%s",SMTPAP_CRLF);
						      state = 5;
						    }
						    else /* didn't like my RCPT */
						    {
						      log(LOG_DEBUG,"handle_connection() : handle_connection : RCPT unsuccessful");
						      sendmessage(sop,(char *)op_out,(size_t)op_outlen,"%s%s",SMTPAP_QUIT,SMTPAP_CRLF);
						      close(sop);
						      sendmessage(s,(char *)message,(size_t)512,"500 Recipient SMTP daemon rejected my RCPT.%s",SMTPAP_CRLF);
						    }
						  }
						}
					      }
					      else /* didn't like my MAIL */
					      {
						log(LOG_DEBUG,"handle_connection() : handle_connection : MAIL unsuccessful");
						sendmessage(sop,(char *)op_out,(size_t)op_outlen,"%s%s",SMTPAP_QUIT,SMTPAP_CRLF);
						close(sop);
						sendmessage(s,(char *)message,(size_t)512,"500 Recipient SMTP daemon rejected my MAIL.%s",SMTPAP_CRLF);
					      }
					    }
					  }
					}
					else
					{
					  log(LOG_DEBUG,"handle_connection() : handle_connection : HELO unsuccessful");
					  sendmessage(sop,(char *)op_out,(size_t)op_outlen,"%s%s",SMTPAP_QUIT,SMTPAP_CRLF);
					  close(sop);
					  sendmessage(s,(char *)message,(size_t)512,"500 Recipient SMTP daemon rejected my HELO.%s",SMTPAP_CRLF);
					}
				      }
				    }
				  }
				}
			      }
			      else
			      {
				log(LOG_DEBUG,"handle_connection() : handle_connection : onion proxy returned non-zero error code %d.",*op_in);
				close(sop);
				switch(*op_in)
				{
				 case SS_ERROR_VERSION_UNSUPPORTED :
				  sendmessage(s,(char *)message,(size_t)512,"500 Onion proxy returned an error (Protocol version not supported).%s",SMTPAP_CRLF);
				  break;
				 case SS_ERROR_ADDR_FMT_UNSUPPORTED:
				  sendmessage(s,(char *)message,(size_t)512,"500 Onion proxy returned an error (Address format not recognised).%s",SMTPAP_CRLF);
				  break;
				 case SS_ERROR_INVALID_ADDRESS:
				  sendmessage(s,(char *)message,(size_t)512,"500 Onion proxy returned an error (Invalid destination address).%s",SMTPAP_CRLF);
				  break;
				 case SS_ERROR_INVALID_PORT:
				  sendmessage(s,(char *)message,(size_t)512,"500 Onion proxy returned an error (Invalid destination port).%s",SMTPAP_CRLF);
				  break;
				 default :
				  sendmessage(s,(char *)message,(size_t)512,"500 Onion proxy returned unexpected error code %d.%s",*op_in,SMTPAP_CRLF);
				  break;
				}
				/* clean up */
				free(op_in);
				op_inlen=0;
			      }
			    }
			  }
			}
		      }
		    }
		  }
		}
	      }
	    }
	  }
	}
      }
      else
	sendmessage(s,(char *)message, (size_t)512,"503 Need RCPT first.%s",SMTPAP_CRLF);
    }
    else if (state == 5)
    {
      if ((!strcmp(token,SMTPAP_DATA))) /* received data */
      {
	partial_dataend = 0;
	retval = write_tout(sop, tmpbuf, strlen(tmpbuf), conn_toutp); /* send DATA */
	if (retval == -1) /* send(0) failed */
	{
	  log(LOG_DEBUG,"handle_connection() : handle_connection : Failed to send DATA to recipient.");
	  sendmessage(s,(char *)message,(size_t)512,"451 Error sending DATA to the recipient.%s",SMTPAP_CRLF);
	}
	else /* get response from the recipient */
	{
	  retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
	  if (retval == -1)
	  {
	    log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving DATA response from recipient");
	    sendmessage(s,(char *)message,(size_t)512,"451 Error receiving data from the recipient.%s",SMTPAP_CRLF);
	  }
	  else
	  {
	    op_in[retval]=0;
	    log(LOG_DEBUG,"handle_connection() : handle_connection : Received this from recipient : %s.",op_in);
	    if (op_in[0] == '3') /* success */
	    {
	      sendmessage(s,(char *)message,(size_t)512,"354 Enter mail, end with \".\" on a line by itself%s",SMTPAP_CRLF);
	      state = 6;
	    }
	    else /* didn't like my DATA */
	    {
	      log(LOG_DEBUG,"handle_connection() : handle_connection : DATA unsuccessful");
	      sendmessage(s,(char *)message,(size_t)512,"500 Recipient SMTP daemon rejected my DATA.%s",SMTPAP_CRLF);
	    }
	  }	  
	}
      }
      else
	sendmessage(s,(char *)message, (size_t)512,"503 Expecting DATA.%s",SMTPAP_CRLF);
    }
    else if (state == 6)
    {
      /* sanitize the data stream if necessary */
      if (options[Anonimize].r.i == 1)
      {
	log(LOG_DEBUG,"handle_connection() : Sanitizing headers ...");
	retval = sanitize_data((unsigned char **)&tmpbuf, &inputlen);
      }
      
      if ((!retval) || (!options[Anonimize].r.i)) /* sanitization successsful (or wasn't necessary)? */
      {
	log(LOG_DEBUG,"handle_connection() : Attempting to send ...");
	/* forward to recipient */
	retval = write_tout(sop,tmpbuf, inputlen, conn_toutp);
	if (retval == -1)
	{
	  log(LOG_DEBUG,"handle_connection() : handle_connection : Failed to forward data to recipient.");
	  sendmessage(sop, (char *)op_out, (size_t)op_outlen,"451 Failed to forward data to the recipient.%s",SMTPAP_CRLF);
	}
	else
	{
	  /* get the response */
	  retval = receive(sop,&op_in,(size_t *)&op_inlen,0);
	  if (retval == -1)
	  {
	    log(LOG_DEBUG,"handle_connection() : handle_connection : error receiving response from recipient");
	    sendmessage(s,(char *)message,(size_t)512,"451 Data sent but did not receive a response from the recipient%s.",SMTPAP_CRLF);
	  }
	  else
	  {
	    op_in[retval]=0;
	    log(LOG_DEBUG,"handle_connection() : handle_connection : Received this from recipient : %s.",op_in);
	    if (op_in[0] == '2') /* success */
	    {
	      sendmessage(s,(char *)message,(size_t)512,"250 Message accepted for delivery.%s",SMTPAP_CRLF);
	      sendmessage(sop, (char *)op_out, (size_t)op_outlen,"QUIT%s",SMTPAP_CRLF);
	    }
	    else /* didn't like my DATA */
	    {
	      log(LOG_DEBUG,"handle_connection() : handle_connection : DATA unsuccessful");
	      sendmessage(s,(char *)message,(size_t)512,"500 Recipient SMTP daemon rejected my DATA.%s",SMTPAP_CRLF);
	    }
	  }
	}
      }
      else /* sanitization error */
      {
	log(LOG_ERR,"Unable to sanitize an incoming message. Will reject.");
	sendmessage(sop,(char *)op_out, (size_t)op_outlen,"400 Failed to sanitize the data stream.%s", SMTPAP_CRLF);
      }
      
      /* after state 6 we go back to state 3, regardless of wether the transfer was succesful or not */
      state = 3;
      close(sop);
      free(op_in);op_in=NULL;
      free(op_out);op_out=NULL;
    }
    else /* unexpected state */
    {
      log(LOG_DEBUG,"handle_connection() : handle_connection : Unexpected state!");
      log(LOG_ERR,"An unexpected error has occured. Closing connection.");
      sendmessage(s,(char *)message,(size_t)512,"500 An unexpected error has ocurred. Closing connection.%s",SMTPAP_CRLF);
      break;
    }
  }

  /* clean up */
  if (inbuf != NULL)
    free(inbuf);
  if (tmpbuf != NULL)
    free(tmpbuf);
  if (mailbuf != NULL)
    free(mailbuf);
  if (rcptbuf != NULL)
    free(rcptbuf);
  if (rcptarray != NULL)
    free(rcptarray);
  if (dest_addr_str != NULL)
    free(dest_addr_str);
  if (op_in != NULL)
    free(op_in);
  if (op_out != NULL)
    free(op_out);
  close(sop);
  close(s);
  
  return retval;
}

int main(int argc, char *argv[])
{
  int loglevel = LOG_DEBUG;
  int retval = 0;
  
  char c; /* command-line option */
  
  /* configuration file */
  char *conf_filename = NULL;
  FILE *cf = NULL;
  
  struct hostent *local_host;
  char local_hostname[512];
  
  struct sockaddr_in local, remote; /* local and remote address info */
  
  int request_sock; /* where we listen for connections */
  int new_sock; /* for accepted connections */
  
  size_t sin_size; /* for accept() calls */
  
  u_short p; /* smtp proxy port */
  u_short op_port; /* onion proxy port */
  
  /* used for reaping zombie processes */
  struct sigaction sa;
  
  char *errtest = NULL; /* for detecting strtoul() errors */

  /* set default listening port */
  p = htons(SMTPAP_LISTEN_PORT);
  
  /* deal with program arguments */
  if ((argc < 2) && (argc > 5)) /* to few or too many arguments*/
  {
    print_usage();
    return -1;
  }
  
  opterr = 0;
  while ((c = getopt(argc,argv,args)) != -1)
  {
    switch(c)
    {
     case 'f': /* config file */
      conf_filename = optarg;
      break;
     case 'p':
      p = htons((u_short)strtoul(optarg,&errtest,0));
      if (errtest == optarg) /* error */
      {
	log(LOG_ERR,"Error : -p must be followed by an unsigned positive integer value.");
	print_usage();
	return -1;
      }
      break;
     case 'h':
      print_usage();
      return 0;
      break;
    case 'l':
      if (!strcmp(optarg,"emerg"))
	loglevel = LOG_EMERG;
      else if (!strcmp(optarg,"alert"))
	loglevel = LOG_ALERT;
      else if (!strcmp(optarg,"crit"))
	loglevel = LOG_CRIT;
      else if (!strcmp(optarg,"err"))
	loglevel = LOG_ERR;
      else if (!strcmp(optarg,"warning"))
	loglevel = LOG_WARNING;
      else if (!strcmp(optarg,"notice"))
	loglevel = LOG_NOTICE;
      else if (!strcmp(optarg,"info"))
	loglevel = LOG_INFO;
      else if (!strcmp(optarg,"debug"))
	loglevel = LOG_DEBUG;
      else
      {
	log(LOG_ERR,"Error : argument to -l must be one of alert|crit|err|warning|notice|info|debug.");
	print_usage();
	return -1;
      }
      break;
     case '?':
      if (isprint(c))
	log(LOG_ERR,"Missing argument or unknown option '-%c'.",optopt);
      else
	log(LOG_ERR,"Unknown option character 'x%x'.",optopt);
      print_usage();
      return -1;
      break;
     default:
      abort();
    }
  }
    
  log(loglevel,NULL); /* assign severity level for logger */

  /* the -f option is mandatory */
  if (conf_filename == NULL)
  {
    log(LOG_ERR,"You must specify a config file with the -f option. See help (-h).");
    return -1;
  }
  
  /* load config file */
  cf = open_config(conf_filename);
  if (!cf)
  {
    log(LOG_ERR,"Could not open configuration file %s.",conf_filename);
    return -1;
  }
  retval = parse_config(cf,options);
  if (retval)
    return -1;

  if (options[OnionProxy].err != 1)
  {
    log(LOG_ERR,"The OnionProxy option is mandatory.");
    return -1;
  }
  
  if (options[MaxConn].err != 1)
  {
    log(LOG_ERR,"The MaxConn option is mandatory.");
    return -1;
  }
  
  if (options[Anonimize].err != 1)
  {
    log(LOG_ERR,"The Anonimize option is mandatory.");
    return -1;
  }
  else if ((options[Anonimize].r.i != 0) && (options[Anonimize].r.i != 1))
  {
    log(LOG_ERR,"The Anonimize option takes the values 1 or 0.");
    return -1;
  }
  
  if (options[ConnTimeout].err != 1)
  {
    conn_tout.tv_sec = SMTPAP_DEFAULT_CONN_TIMEOUT;
  }
  else
  {
    if (!options[ConnTimeout].r.i)
      conn_toutp = NULL;
    else
      conn_tout.tv_sec = options[ConnTimeout].r.i;
  }
  conn_tout.tv_usec = 0;
  
  op_port = (u_short)options[OnionProxy].r.i;
  
  /* get local address so that we know where to get the onion proxy when we need it */
  retval = gethostname(local_hostname, (size_t)512);
  if (retval < 0)
  {
    log(LOG_ERR,"Error getting local hostname");
    return -1;
  }
  local_host = gethostbyname(local_hostname);
  if (!local_host)
  {
    log(LOG_ERR,"Error getting local address.");
    return -1;
  }
  log(LOG_DEBUG,"main() : Got local address : %s.",local_hostname);
  
  /* get the server up and running */
  request_sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (request_sock < 0)
  {
    log(LOG_ERR,"Error opening socket.");
    return -1;
  }
  log(LOG_DEBUG,"Socket opened.");
  memset((void *)&local,0,sizeof(local)); /* clear the structure first */
  /* set up the sockaddr_in structure */
  local.sin_family=AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port=p;
  /* bind it to the socket */
  retval = bind(request_sock,(struct sockaddr *)&local, sizeof(local));
  if (retval < 0)
  {
    log(LOG_ERR,"Error binding socket to local port %d.",ntohs(p));
    return retval;
  }
  log(LOG_DEBUG,"Socket bound to port %d.",ntohs(p));
  /* listen for connections */
  retval = listen(request_sock,SOMAXCONN);
  if (retval < 0)
  {
    log(LOG_ERR,"Could not listen for connections.");
    return retval;
  }
  log(LOG_DEBUG,"Listening for connections.");
  /* server should now be up and running */

  /* install the signal handler for making sure zombie processes are killed */
  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  retval = sigaction(SIGCHLD,&sa,NULL);
  if (retval < 0)
  {
    log(LOG_ERR,"Could not install a signal handler.");
    return -1;
  }

  /* main server loop */
  /* I use a forking server technique - this isn't the most efficient way to do it,
   * but it is simpler. */
  while(1) 
  {
    sin_size = sizeof(struct sockaddr_in);
    new_sock = accept(request_sock,(struct sockaddr *)&remote,&sin_size);
    if (new_sock == -1)
    {
      if (errno != EINTR)
	log(LOG_ERR,"Could not accept socket connection.");
      else
	log(LOG_DEBUG,"Interrupt received.");
      continue;
    }
    if (connections >= options[MaxConn].r.i)
    {
      log(LOG_NOTICE,"Number of maximum connections reached. Rejecting incoming request.");
      close(new_sock);
      continue;
    }
    
    log(LOG_DEBUG,"Accepted a connection from %s.",inet_ntoa(remote.sin_addr));
    connections++;
    
    if (!fork()) /* this is the child process */
    {
      close(request_sock); /* the child doesn't need the request socket anymore */

      /* Main logic of smtpap. */
      retval = handle_connection(new_sock, local_host, remote, op_port);
      /* End main logic */
      
      exit(retval); /* done, exit */
    }
    
    close(new_sock); /* don't need this anymore */
  }

  return retval;

}

