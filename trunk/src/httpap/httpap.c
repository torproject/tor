/**
 * httpap.c 
 * HTTP Application Proxy for Onion Routing
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.5  2002/07/20 02:01:18  arma
 * bugfixes: don't hang waiting for new children to die; accept HTTP/1.1
 *
 * Revision 1.4  2002/07/19 18:48:19  arma
 * slightly less noisy
 *
 * Revision 1.3  2002/07/12 18:14:16  montrose
 * removed loglevel from global namespace. severity level is set using log() with a NULL format argument now. example: log(LOG_ERR,NULL);
 *
 * Revision 1.2  2002/07/02 09:16:16  arma
 * httpap now prepends dest_addr and dest_port strings with their length.
 *
 * also, it now sets the listening socket option SO_REUSEADDR
 *
 * Revision 1.1.1.1  2002/06/26 22:45:50  arma
 * initial commit: current code
 *
 * Revision 1.4  2002/06/14 20:45:26  mp292
 * Extra debugging message.
 *
 * Revision 1.3  2002/04/02 14:27:33  badbytes
 * Final finishes.
 *
 * Revision 1.2  2002/03/12 23:40:58  mp292
 * Tested.
 *
 * Revision 1.1  2002/03/11 00:21:53  mp292
 * Coding completed. Pending testing.
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

#include "httpap.h"
#include "http.h"

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

/* prints help on using httpap */
void print_usage()
{
  char *program = "httpap";
  
  printf("\n%s - HTTP application proxy for Onion Routing.\nUsage : %s -f config [-p port -l loglevel -h]\n-h : display this help\n-f config : config file\n-p port : port number which %s should bind to\n-l loglevel : logging threshold; one of alert|crit|err|warning|notice|info|debug\n\n", program,program,program);
}

/* used for reaping zombie processes */
void sigchld_handler(int s)
{
  while((waitpid (-1, NULL, WNOHANG)) > 0) {
//  while (wait(NULL) > 0);
    connections--;
  }
}

int handle_connection(int new_sock, struct hostent *local, struct sockaddr_in remote, uint16_t op_port)
{
  int retval = 0;
  int i;
  char islocal = 0; /* is the accepted connection local? */
  
  char *cp; /* character pointer used for checking whether the connection is local */

  unsigned char *line; /* one line of input */
  int len; /* length of the line */
  
  uint16_t stringlen; /* used for sending how long a string is before the actual string */
  unsigned char *http_ver; /* HTTP version of the incoming request */
  unsigned char *addr; /* destination address */
  unsigned char *port; /* destination port */
  unsigned char *header_name; /* name of a request header */
  
  uint16_t portn; /* destination port converted into an integer */
  char *errtest; /* error check when converting the port into an integer */
  
  ss_t ss; /* standard structure */
  unsigned char errcode; /* error code returned by the onion proxy */
  
  int sop; /* socket for connecting to the onion proxy */
  struct sockaddr_in op_addr; /* onion proxy address */
  
  /* for use with select() */
  fd_set mask,rmask;
  int maxfd;
  
  unsigned char buf[1024]; /* data buffer */
  
  log(LOG_DEBUG, "handle_connection() : Local address = %s.", inet_ntoa(*(struct in_addr *)local->h_addr));
  log(LOG_DEBUG, "handle_connection() : Remote address = %s.", inet_ntoa(remote.sin_addr));
  
  /* first check that the connection is from the local host, otherwise it will be rejected */
  if (*(uint32_t *)&remote.sin_addr == inet_addr("127.0.0.1"))
          islocal = 1;
  for (i=0; (local->h_addr_list[i] != NULL) && (!islocal); i++)
  {
    cp = local->h_addr_list[i];
    log(LOG_DEBUG,"handle_connection() : Checking if connection is from address %s.",inet_ntoa(*(struct in_addr *)cp));
    if (!memcmp(&remote.sin_addr, cp, sizeof(struct in_addr)))
      islocal = 1;
  }
  
  /* bypass this check for testing purposes */
  islocal = 1;
  
  /* reject a non-local connection */
  if (!islocal)
  {    
    close(new_sock);
    return 0;
  }
  
  /* get the request-line */
  retval = http_get_line(new_sock, &line, &len, conn_toutp);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection : Malformed input or connection lost.");
    write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
    close(new_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection : Received this from client : %s.", line);
  
  /* check the HTTP version */
  retval = http_get_version(line, &http_ver);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection : Unable to extract the HTTP version of the incoming request.");
    write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection : Client's version is : %s.",http_ver);
//  if (strcmp(http_ver, HTTPAP_VERSION)) /* not supported */
//  {
//    log(LOG_DEBUG,"handle_connection : Client's version is %s, I only support HTTP/1.0.",http_ver);
//    write_tout(new_sock, HTTPAP_STATUS_LINE_VERSION_NOT_SUPPORTED, strlen(HTTPAP_STATUS_LINE_VERSION_NOT_SUPPORTED), conn_toutp);
//    return -1;
//  }
  free((void *)http_ver);
  
  /* extract the destination address and port */
  retval = http_get_dest(line, &addr, &port);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection : Unable to extract destination address and port number.");
    write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
    return -1;
  }
  if (!port) /* no destination port specified, assume the default */
  {
    port = (unsigned char *)malloc(6);
    if (!port)
    {
      log(LOG_ERR,"Insufficient memory.");
      write_tout(new_sock, HTTPAP_STATUS_LINE_UNEXPECTED, strlen(HTTPAP_STATUS_LINE_UNEXPECTED), conn_toutp);
      return -1;
    }
    snprintf(port,6,"%u",htons(HTTPAP_DEFAULT_HTTP_PORT));
  }
  else
  {
    log(LOG_DEBUG,"handle_connection() : Destination address is %s.",addr);
    log(LOG_DEBUG,"handle_connection() : Destination port is %s.",port);
  
    /* conver the port to an integer */
    portn = (uint16_t)strtoul(port,&errtest,0);
    if ((*port == '\0') || (*errtest != '\0')) /* port conversion was unsuccessful */
    {
      log(LOG_DEBUG,"handle_connection : Unable to convert destination port.");
      write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
      return -1;
    }
    
    /* convert to network order and write back to a string */
    free((void *)port);
    port = (unsigned char *)malloc(6);
    if (!port)
    {
      log(LOG_ERR,"Insufficient memory.");
      write_tout(new_sock, HTTPAP_STATUS_LINE_UNEXPECTED, strlen(HTTPAP_STATUS_LINE_UNEXPECTED), conn_toutp);
      return -1;
    }
    
    snprintf(port,6,"%u",htons(portn));
  }
  
  /* create a standard structure */
  ss.version = VERSION;
  ss.protocol = SS_PROTOCOL_HTTP;
  ss.retry_count = 0;
  ss.addr_fmt = SS_ADDR_FMT_ASCII_HOST_PORT;
  
  /* open a socket for connecting to the proxy */
  sop = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (sop < 0)
  {
    log(LOG_DEBUG,"handle_connection() : Error opening socket.");
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNEXPECTED, strlen(HTTPAP_STATUS_LINE_UNEXPECTED), conn_toutp);
    return -1;
  }

  log(LOG_DEBUG,"handle_connection() : Socket opened.");
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
    log(LOG_DEBUG,"handle_connection() : Connection to the onion proxy failed.");
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
    close(sop);
    return -1;
  }
  
  /* send the standard structure and the destination address+port */
  retval = write_tout(sop,(unsigned char *)&ss, sizeof(ss), conn_toutp);
  if (retval < sizeof(ss))
  {
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
    close(sop);
    return -1;    
  }
  /* patch so the OP doesn't have to guess how long the string is. Note
   * we're *no longer* sending the NULL character. */
  stringlen = htons(strlen(addr));
  write_tout(sop,(char *)&stringlen,sizeof(uint16_t), conn_toutp);
  retval = write_tout(sop,addr,strlen(addr), conn_toutp);
  if (retval < strlen(addr))
  {
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
    close(sop);
    return -1;
  }
  /* patch so the OP doesn't have to guess how long the string is. Note
   * we're *no longer* sending the NULL character. */
  stringlen = htons(strlen(port));
  write_tout(sop,(char *)&stringlen,sizeof(short int), conn_toutp);
  retval = write_tout(sop,port,strlen(port), conn_toutp);
  if (retval < strlen(port))
  {
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
    close(sop);
    return -1;
  }
  
  /* wait for a return code */
  retval = read_tout(sop, &errcode, 1, MSG_WAITALL, conn_toutp);
  if (retval < 1)
  {
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
    close(sop);
    return -1;
  }
  
  if (!errcode) /* onion proxy says OK */
  {
    /* send the request-line */
    retval = write_tout(sop, line, strlen(line), conn_toutp);
    if (retval < strlen(line))
    {
      write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
      close(new_sock);
      return -1;
    }
    free((void *)line);
    
    /* read the request headers (if any) and sanitize if necessary */
    while(1)
    {
      retval = http_get_line(new_sock, &line, &len, conn_toutp);
      if (retval == -1)
      {
	log(LOG_DEBUG,"handle_connection() : Malformed input or connection lost.");
	write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
	close(new_sock);
	return -1;
      }
      log(LOG_DEBUG,"handle_connection() : Received this from client : %s.", line);
      
      if (len == 2) /* empty line (CRLF only) signifying the end of headers  */
      {
	log(LOG_DEBUG,"handle_connection() : Empty line received.");
	retval = write_tout(sop,line,strlen(line),conn_toutp);
	if (retval < strlen(line))
	{
	  write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
	  close(new_sock);
	  return -1;
	}
	free((void *)line);
	break;
      }
      else /* process the header */
      {
	retval = http_get_header_name(line, &header_name);
	if (retval == -1)
	{
	  log(LOG_DEBUG,"handle_connection : Unable to extract header name.");
	  write_tout(new_sock, HTTPAP_STATUS_LINE_BAD_REQUEST, strlen(HTTPAP_STATUS_LINE_BAD_REQUEST), conn_toutp);
	  return -1;
	}
	log(LOG_DEBUG,"handle_connection : Identified the header as %s.", header_name);
	
	/* discard the Proxy-Connection header */
	if (!strcmp(header_name,HTTPAP_HEADER_PROXY_CONNECTION))
	  free((void *)line);
	else if (options[Anonimize].r.i) /* did the user request anonimization? */
	{
	  if (!strcmp(header_name,HTTPAP_HEADER_USER_AGENT))
	    free((void *)line);
	  else if (!strcmp(header_name, HTTPAP_HEADER_REFERER))
	    free((void *)line);
	  else
	  {
	    retval = write_tout(sop, line, strlen(line), conn_toutp);
	    if (retval < strlen(line))
	    {
	      write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
	      close(new_sock);
	      return -1;
	    }
	  }
	}
	else
	{
	  retval = write_tout(sop, line, strlen(line), conn_toutp);
	  if (retval < strlen(line))
	  {
	    write_tout(new_sock, HTTPAP_STATUS_LINE_UNAVAILABLE, strlen(HTTPAP_STATUS_LINE_UNAVAILABLE), conn_toutp);
	    close(new_sock);
	    return -1;
	  }
	}
	
	free((void *)header_name);
      }
    }
    
    /* forward data in both directions until one of the principals closes it */
    /* set up for select() */
    log(LOG_DEBUG,"Header processed, forwarding data in both directions.");
    FD_ZERO(&mask);
    FD_ZERO(&rmask);
    FD_SET(new_sock, &mask);
    FD_SET(sop, &mask);
    if (sop > new_sock)
      maxfd = sop;
    else
      maxfd = new_sock;
    
    while(1)
    {
      rmask = mask;
      retval = select(maxfd+1,&rmask,NULL,NULL,NULL);
      if (retval < 0)
      {
	log(LOG_DEBUG,"handle_connection() : select() returned a negative integer");
	break;
      }
      
      if (FD_ISSET(sop,&rmask)) /* data from the onion proxy */
      {
	retval = read_tout(sop,buf,1024,0,conn_toutp);
	if (retval <= 0)
	{
	  log(LOG_DEBUG,"handle_connection : Conection to the onion proxy lost.");
	  close(sop);
	  close(new_sock);
	  break;
	}
//	log(LOG_DEBUG,"handle_connection() : Received %u bytes from the onion proxy.",retval);
	
	retval = write_tout(new_sock, buf, retval, conn_toutp);
	if (retval <= 0)
	{
	  log(LOG_DEBUG, "handle_connection : Connection to the client lost.");
	  close(sop);
	  close(new_sock);
	  break;
	}
      }
      
      if (FD_ISSET(new_sock, &rmask))
      {
	retval = read_tout(new_sock,buf,1024,0,conn_toutp);
	if (retval <= 0)
	{
	  log(LOG_DEBUG,"handle_connection : Conection to the client lost.");
	  close(sop);
	  close(new_sock);
	  break;
	}
	log(LOG_DEBUG,"handle_connection() : Received %u bytes from the client.",retval);
	
	retval = write_tout(sop, buf, retval, conn_toutp);
	if (retval <= 0)
	{
	  log(LOG_DEBUG, "handle_connection : Connection to the onion proxy lost.");
	  close(sop);
	  close(new_sock);
	  break;
	}
      }
    }
    
  }
  else
  {
    log(LOG_DEBUG,"handle_connection() : Onion proxy returned a non-zero error code (%d)!", errcode);
    write_tout(new_sock, HTTPAP_STATUS_LINE_UNEXPECTED, strlen(HTTPAP_STATUS_LINE_UNEXPECTED), conn_toutp);
    close(sop);
    return -1;
  }
  
  return 0;
}

int main(int argc, char *argv[])
{
  int loglevel = LOG_DEBUG;
  int retval = 0;
  
  char c; /* command-line option */
  int one=1;
  
  /* configuration file */
  char *conf_filename = NULL;
  FILE *cf = NULL;
  
  struct hostent *local_host;
  char local_hostname[512];
  
  struct sockaddr_in local, remote; /* local and remote address info */
  
  int request_sock; /* where we listen for connections */
  int new_sock; /* for accepted connections */
  
  size_t sin_size; /* for accept() calls */
  
  u_short p; /* http proxy port */
  u_short op_port; /* onion proxy port */
  
  /* used for reaping zombie processes */
  struct sigaction sa;
  
  char *errtest = NULL; /* for detecting strtoul() errors */
  
  /* set default listening port */
  p = htons(HTTPAP_LISTEN_PORT);
  
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
  
  log(loglevel,NULL);  /* assign severity level for logger */

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
    conn_tout.tv_sec = HTTPAP_DEFAULT_CONN_TIMEOUT;
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

  setsockopt(request_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

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

      /* Main logic of httpap. */
      retval = handle_connection(new_sock, local_host, remote, op_port);
      /* End main logic */
      
      exit(retval); /* done, exit */
    }
    
    close(new_sock); /* don't need this anymore */
  }

  return retval;

}

