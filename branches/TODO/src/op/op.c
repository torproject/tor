/**
 * op.c 
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
 * Revision 1.37  2002/06/14 20:45:56  mp292
 * *** empty log message ***
 *
 * Revision 1.36  2002/04/02 14:28:01  badbytes
 * Final finishes.
 *
 * Revision 1.35  2002/04/02 10:21:07  badbytes
 * *** empty log message ***
 *
 * Revision 1.34  2002/03/29 08:35:12  badbytes
 * Link encryption is now done on the entire cell header for simplicity.
 *
 * Revision 1.33  2002/03/28 17:57:59  badbytes
 * Bug fix.
 *
 * Revision 1.32  2002/03/28 11:01:43  badbytes
 * Now does link-encryption and link-padding.
 *
 * Revision 1.31  2002/03/12 23:40:32  mp292
 * Started on op<->router connection padding.
 *
 * Revision 1.30  2002/01/29 02:22:58  mp292
 * Put a timeout on all network I/O.
 *
 * Revision 1.29  2002/01/26 23:01:55  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.28  2002/01/18 20:42:06  mp292
 * Reflects changes to common/onion.c:new_route()
 *
 * Revision 1.27  2002/01/17 23:49:15  mp292
 * Added size of public key to one of the debugging messages.
 *
 * Revision 1.26  2002/01/16 23:01:58  mp292
 * First phase of system testing completed (main functionality).
 *
 * Revision 1.25  2002/01/16 17:01:56  mp292
 * There was a bug in checking whether the incoming connection is local or not.
 *
 * Revision 1.24  2002/01/16 16:09:32  mp292
 * A pointer cast was missing. Fixed.
 *
 * Revision 1.23  2002/01/14 13:05:39  badbytes
 * System testing in progress.
 *
 * Revision 1.22  2002/01/11 15:47:25  badbytes
 * *** empty log message ***
 *
 * Revision 1.21  2002/01/09 09:18:35  badbytes
 * Now handles EINTR error from accept().
 *
 * Revision 1.20  2002/01/09 07:57:18  badbytes
 * Ciphers got out of sync, hopefully fixed.
 *
 * Revision 1.19  2001/12/19 11:15:41  badbytes
 * Corrected AF_INET to PF_INET in socket() calls.
 *
 * Revision 1.18  2001/12/19 08:38:38  badbytes
 * Zombie problems hopefully fixed.
 *
 * Revision 1.17  2001/12/19 08:29:29  badbytes
 * Tested. Still some problems with zombies in both op and smtpap.
 *
 * Revision 1.16  2001/12/18 15:51:58  badbytes
 * Connection with onion router established. Will continue testing tomorrow.
 *
 * Revision 1.15  2001/12/18 14:12:05  badbytes
 * Tested up to connect() to onion router.
 *
 * Revision 1.14  2001/12/18 12:21:11  badbytes
 * Forgot to convert port to network order :-)
 *
 * Revision 1.13  2001/12/18 11:52:27  badbytes
 * Coding completed. Proceeding to test.
 *
 * Revision 1.12  2001/12/17 13:36:15  badbytes
 * Writing handle_connection()
 *
 * Revision 1.11  2001/12/17 08:42:44  badbytes
 * getrouters() now returns an array of routers and also writes the length of the array to an int*.
 *
 * Revision 1.10  2001/12/14 14:45:13  badbytes
 * Added range checking for CoinWeight.
 *
 * Revision 1.9  2001/12/14 14:08:50  badbytes
 * getrouters() now returns an array of pointers rather than a linked list
 *
 * Revision 1.8  2001/12/14 13:31:20  badbytes
 * *** empty log message ***
 *
 * Revision 1.7  2001/12/14 13:17:12  badbytes
 * Corrected references to types.h
 *
 * Revision 1.6  2001/12/14 13:00:30  badbytes
 * Changed my mind, routers.c and routers.h stay where they are :-)
 *
 * Revision 1.5  2001/12/14 12:56:55  badbytes
 * Moved routers* to common/
 *
 * Revision 1.4  2001/12/14 12:42:50  badbytes
 * References to onion.h and onion.o now point to the common/ directory.
 *
 * Revision 1.3  2001/12/14 12:40:26  badbytes
 * Was being stupid - op doesn't need a private key!! Have removed ...
 *
 * Revision 1.2  2001/12/14 11:27:16  badbytes
 * Configuration and server setup completed.
 *
 * Revision 1.1  2001/12/13 15:15:11  badbytes
 * Started coding the onion proxy.
 *
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <wait.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "../common/log.h"
#include "../common/version.h"
#include "../common/onion.h"
#include "../common/utils.h"
#include "../common/cell.h"
#include "../common/scheduler.h"

#include "config.h"
#include "routers.h"
#include "args.h"
#include "auth.h"
#include "op.h"
#include "ss.h"
#include "crypto.h"
#include "buffers.h"

/* global variables */

/* default logging threshold */
int loglevel = LOG_ERR;
struct timeval conn_tout;
struct timeval *conn_toutp = &conn_tout; 

/* valid command-line options */
static char *args = "hf:p:l:";

/* valid config file options */
static config_opt_t options[] =
{
  {"RouterFile", CONFIG_TYPE_STRING, {0}, 0},
  {"CoinWeight", CONFIG_TYPE_DOUBLE, {0}, 0},
  {"MaxConn", CONFIG_TYPE_INT, {0}, 0},
  {"ConnTimeout", CONFIG_TYPE_INT, {0}, 0},
  {"Bandwidth", CONFIG_TYPE_INT, {0}, 0},
  {0}
};
enum opts {
  RouterFile=0, CoinWeight, MaxConn, ConnTimeout, Bandwidth
};

int connections = 0; /* number of active connections */

/* local host info */
struct hostent *local_host;
char local_hostname[512];
  
struct sockaddr_in local, remote; /* local and remote address info */
struct sockaddr_in or_addr; /* onion router address */

int request_sock; /* where we listen for connections */
int new_sock; /* for accepted connections */
int or_sock; /* for connecting to the first onion router */

/* router array */
routent_t **routerarray = NULL;
int rarray_len = 0;

/* end of global variables */

void send_to_router(int s,unsigned char **outbuf, size_t *outbuflen, size_t *outbuf_dataoffset, size_t *outbuf_datalen, struct timeval *lastsend, struct timeval *interval, sched_t *scheduler, EVP_CIPHER_CTX *ctx)
{
  int retval;
  int cells;
  int datacells;
  int paddingcells;
  int i;
  int x;
  char *px;
  struct timeval now;
  cell_t cipher;
  cell_t *padding;
  int cipherlen;
  unsigned long elapsed;
  
  /* calculate the number of cells that need to be sent */
  retval = gettimeofday(&now,NULL);
  if (retval == -1)
  {
    log(LOG_ERR,"Could not get current time!");
    return;
  }
  
  elapsed = 1000000*(now.tv_sec-lastsend->tv_sec) + now.tv_usec-lastsend->tv_usec;
  
  if (elapsed < 1000000)
  {
    cells = ((options[Bandwidth].r.i) * 512) / /* number of bytes per second, divided by two */
      (1000000/elapsed);  /* fractions of second since last send */
  }
  else
  {
    cells = ((options[Bandwidth].r.i) * 512) * /* number of bytes per second, divided by two */
      (elapsed/1000000); /* 1/fractions of second since last send */
  }
  cells /= sizeof(cell_t);

  datacells = (*outbuf_datalen)/sizeof(cell_t); /* number of data cells available */
  if (datacells > cells)
    datacells = cells;
  paddingcells = cells - datacells;
  
  /* send the data cells first */
  for (i=0; i<datacells; i++)
  {
    /* link-encrypt the cell header */
    printf("Cell header plaintext: ");
    for(x=0;x<8;x++) {
      printf("%u ",*(char *)(*outbuf+*outbuf_dataoffset+x));
    }
    printf("\n");
    retval = EVP_EncryptUpdate(ctx, (unsigned char *)&cipher, &cipherlen, *outbuf+*outbuf_dataoffset, 8);
    if (!retval)
    {
      log(LOG_ERR,"Link encryption failed. Exiting.");
      exit(-1);
    }
    printf("Cell header crypttext: ");
    px = (char *)&cipher;
    for(x=0;x<8;x++) {
      printf("%u ",px[x]);
    }
    printf("\n");

    /* copy the payload */
    memcpy((void *)cipher.payload, (void *)(*outbuf+*outbuf_dataoffset+8), CELL_PAYLOAD_SIZE);
    
    /* send the cell */
    log(LOG_DEBUG,"send_to_router(): Trying to send a data/create cell to router.");
    retval = write_tout(s,(unsigned char *)&cipher, sizeof(cell_t), conn_toutp);
    if (retval < sizeof(cell_t))
    {
      log(LOG_ERR,"Connection to the router seems to be lost. Exiting.");
      exit(-1);
    }
    *outbuf_dataoffset += sizeof(cell_t);
    *outbuf_datalen -= sizeof(cell_t);
    
  }
  
  /* send padding */
  for (i=0; i<cells-datacells; i++)
  {
    padding = new_padding_cell();
    if (!padding)
    {
      log(LOG_ERR,"Memory allocation error. Exiting.");
      exit(-1);
    }
    
    /* link encrypt the cell header */
    retval = EVP_EncryptUpdate(ctx, (unsigned char *)&cipher, &cipherlen, (unsigned char *)padding, 8);
    if (!retval)
    {
      log(LOG_ERR,"Link encryption failed. Exiting.");
      exit(-1);
    }
    
    /* copy the payload */
    memcpy((void *)cipher.payload, (void *)((unsigned char *)padding+8), CELL_PAYLOAD_SIZE);
    
    /* send the cell */
    log(LOG_DEBUG,"send_to_router(): Trying to send a padding cell to router.");
    retval = write_tout(s, (unsigned char *)&cipher, sizeof(cell_t), conn_toutp);
    if (retval < sizeof(cell_t))
    {
      log(LOG_ERR,"Connection to the router seems to be lost. Exiting.");
      exit(-1);
    }
    
    free((void *)padding);
  }
  
  /* update scheduler state, if we've sent anything to the router */
  if (cells)
  {
    retval = update_sched_entry(scheduler, *lastsend, *interval, now, *interval);
    if (retval == -1)
    {
      log(LOG_ERR,"Scheduler error. Exiting.");
      exit(-1);
    }
    memcpy((void *)lastsend,(void *)&now, sizeof(struct timeval));
  }
  
}

/* deal with a client */
int handle_connection()
{
  int retval = 0;
  int routelen = 0; /* length of the route */
  unsigned int *route = NULL; /* hops in the route as an array of indexes into rarray */
  routent_t *firsthop = NULL;
  
  uint32_t aci; /* ACI for this connection */
  
  unsigned char *onion = NULL; /* holds the onion */
  int onionlen = 0; /* onion length in host order */

  crypt_path_t **cpath = NULL; /* defines the crypt operations that need to be performed on incoming/outgoing data */
  char *dest_addr = NULL; /* destination address in ASCII format */
  
  int dest_addrlen = 0;
  char *dest_port = NULL; /* destination port in ASCII format */
  int dest_portlen = 0;
  ss_t *ss; /* standard structure */
  
  uint32_t router_addr_net; /* address of the first onion router in network order */
  
  unsigned char inbuf[1024]; /* buffer for forwarding data between ap and or */
  
  unsigned char *outbuf = NULL; /* buffer for cells which are to be transmitted to the first core onion router in the route */
  size_t outbuflen = 0;
  size_t outbuf_dataoffset = 0; /* offset to the beginning of the data */
  size_t outbuf_datalen = 0; /* length of the data stored in the buffer */
  
  cell_t cellbuf;
  int cellbuflen = 0;
  
  struct timeval lastsend; /* time of last transmission to the onion router */
  struct timeval interval; /* transmission interval */
  
  /* link encryption */
  unsigned char f_session_key[8];
  unsigned char f_session_iv[8] = {0,0,0,0,0,0,0,0};
  unsigned char b_session_key[8];
  unsigned char b_session_iv[8] = {0,0,0,0,0,0,0,0};
  EVP_CIPHER_CTX f_ctx;
  EVP_CIPHER_CTX b_ctx;
  
  /* scheduler */
  sched_t *scheduler;
  
  /* for use with select() */
  fd_set rmask, mask;
  int maxfd;
  struct timeval *timeout;
  
  /* get the standard structure */
  retval = process_ss(new_sock, conn_toutp, &ss,&dest_addr, &dest_addrlen, &dest_port, &dest_portlen);
  if (retval == -1)
  {
    log(LOG_ERR,"Error processing the standard structure.");
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Destination = %s:%s",dest_addr,dest_port);
  
  /* choose a route */
  route = (unsigned int *)new_route(options[CoinWeight].r.d, routerarray,rarray_len, &routelen);
  if (!route)
  {
    log(LOG_ERR,"Error choosing a route through the OR network.");
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Chosen a route of length %u : ",routelen);
  for (retval=routelen-1;retval>=0;retval--)
  {
    log(LOG_DEBUG,"handle_connection() : %u : %s:%u, %u",routelen-retval,(routerarray[route[retval]])->address,ntohs((routerarray[route[retval]])->port),RSA_size((routerarray[route[retval]])->pkey));
  }
  
  /* allocate memory for the crypt path */
  cpath = malloc(routelen * sizeof(crypt_path_t *));
  if (!cpath)
  {
    log(LOG_ERR,"Error allocating memory.");
    free(route);
    return -1;
  }
  /* create an onion and calculate crypto keys */
  onion = create_onion(routerarray,rarray_len,route,routelen,&onionlen,cpath);
  if (!onion)
  {
    log(LOG_ERR,"Error creating an onion.");
    free(route);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Created an onion of size %u bytes.",onionlen);
  log(LOG_DEBUG,"handle_connection() : Crypt path :");
  for (retval=0;retval<routelen;retval++)
  {
    log(LOG_DEBUG,"handle_connection() : %u/%u",(cpath[retval])->forwf, (cpath[retval])->backf);
  }
  
  /* connect to first onion router */
  or_sock = socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if (or_sock < 0)
  {
    free(route);
    free(onion);
    free(cpath);
    close(new_sock);
    log(LOG_ERR,"Error creating socket.");
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Socket created.");

  firsthop = routerarray[route[routelen-1]];
  memset((void *)&or_addr,0,sizeof(or_addr));
  or_addr.sin_family=AF_INET;
  or_addr.sin_port=firsthop->entry_port;
  router_addr_net = firsthop->addr;
  memcpy(&or_addr.sin_addr,&router_addr_net,sizeof(struct sockaddr_in));
  log(LOG_DEBUG,"handle_connection() : Trying to connect to %s:%u",inet_ntoa(or_addr.sin_addr), ntohs(or_addr.sin_port));
  retval = connect(or_sock,(struct sockaddr *)&or_addr, sizeof(or_addr));
  if (retval == -1)
  {
    log(LOG_ERR,"Could not connect to onion router.");
    free(route);
    free(onion);
    free(cpath);
    close(or_sock);
    close(new_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Connected to first onion router.");

  /* send session key and bandwidth info */
  retval = send_auth(or_sock, options[Bandwidth].r.i, firsthop->pkey, f_session_key, b_session_key);
  if (retval == -1)
  {
    close(or_sock);
    close(new_sock);
    log(LOG_ERR,"Lost connection to an onion router. Exiting.");
    return -1;
  }
  /* initialize crypto engines */
  EVP_CIPHER_CTX_init(&f_ctx);
  EVP_CIPHER_CTX_init(&b_ctx);
  EVP_EncryptInit(&f_ctx, EVP_des_ofb(), f_session_key, f_session_iv);
  EVP_DecryptInit(&b_ctx, EVP_des_ofb(), b_session_key, b_session_iv);
  
  /* chose an ACI */
  do
  {
    retval = RAND_pseudo_bytes((unsigned char *)&aci, 2);
    if (retval==-1)
    {
      log(LOG_ERR,"Random data generator doesn't seem to work. Exiting.");
      return -1;
    }
  } while(!aci); /* don't allow zero ACIs */
  log(LOG_DEBUG,"handle_connection() : ACI %u chosen.",aci);
  
  /* initialize last time of transmission to now */
  retval = gettimeofday(&lastsend, NULL);
  if (retval == -1)
  {
    log(LOG_ERR,"Could not get current time.");
    return -1;
  }
  /* calculate the transmission interval */
  interval.tv_sec = 0;
  interval.tv_usec = 250000/options[Bandwidth].r.i;
  /* initialize the scheduler */
  scheduler = new_sched();
  if (!scheduler)
  {
    log(LOG_ERR,"Could not initialize scheduler.");
    return -1;
  }
  retval = add_sched_entry(scheduler, lastsend, interval);
  if (retval == -1)
  {
    log(LOG_ERR,"Could not initialize scheduler.");
    return -1;
  }
  timeout = NULL;
  
  /* write the onion into the output buffer */
  retval = buffer_create(aci, (unsigned char *)onion, onionlen, &outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, cpath, routelen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection() : Could not buffer the onion.");
    close(or_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Onion buffered for output.");

  /* send standard structure */
  log(LOG_DEBUG,"handle_connection() : Calling send_crypt ... routelen=%u, sizeof(SS) = %u",routelen,sizeof(ss_t));
  retval = buffer_data(aci, (unsigned char *)ss, sizeof(ss_t), &outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, cpath, routelen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection() : Could not buffer the standard structure for output.");
    close(or_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Buffered the standard structure header.");
  retval = buffer_data(aci, dest_addr,dest_addrlen, &outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, cpath, routelen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection() : Could not buffer the standard structure (dest. address) for output.");
    close(or_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Buffered the destination address.");
  retval = buffer_data(aci, dest_port, dest_portlen, &outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, cpath, routelen);
  if (retval == -1)
  {
    log(LOG_DEBUG,"handle_connection() : Could not buffer the standard structure (dest. port) for output.");
    close(or_sock);
    return -1;
  }
  log(LOG_DEBUG,"handle_connection() : Buffered the destination port.");

  
  /* forward data in both directions, crypt as necessary */
  /* use select() */

  FD_ZERO(&mask);
  FD_SET(new_sock, &mask);
  FD_SET(or_sock, &mask);
  if (new_sock > or_sock)
    maxfd = new_sock;
  else
    maxfd = or_sock;

  while(1)
  {
    rmask = mask;
    
    /* delete old timeout */
    if (timeout)
      free((void *)timeout);
    /* get the new one */
    retval = sched_trigger(scheduler, &timeout);
    if (retval == -1)
    {
      log(LOG_DEBUG,"Scheduler error.");
      break;
    }
    retval = select(maxfd+1,&rmask,NULL,NULL,timeout);
    if (retval < 0)
    {
      log(LOG_DEBUG,"handle_connection() : select() returned negative integer");
      break;
    }
    
    if (FD_ISSET(new_sock,&rmask))
    {
      log(LOG_DEBUG,"handle_connection() : FD_ISSET(new_sock)");
      retval = read_tout(new_sock, inbuf, 1024, 0, conn_toutp);
      if (retval <= 0)
      {
	log(LOG_DEBUG,"handle_connection() : Received EOF on new_sock.");
	break;
      }
      log(LOG_DEBUG,"handle_connection() : Received %u bytes from client.",retval);
      retval = buffer_data(aci, inbuf, retval, &outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, cpath, routelen);
     
      if (retval < 0)
      {
	log(LOG_DEBUG,"handle_connection() : Could not buffer data for output to OR.");
	break;
      }
      log(LOG_DEBUG,"handle_connection() : Buffered %u bytes for output to the OR.",retval);
    }
    
    if (FD_ISSET(or_sock, &rmask))
    {
      log(LOG_DEBUG,"handle_connection() : FD_ISSET(or_sock)");
      /* read the remainder of the cell (or whatever we can get) */
      retval = read_tout(or_sock, ((unsigned char *)&cellbuf)+cellbuflen, sizeof(cell_t) - cellbuflen, 0, conn_toutp);
      if (retval <= 0)
      {
	log(LOG_DEBUG,"handle_connection() : Received EOF on or_sock.");
	break;
      }
      log(LOG_DEBUG,"handle_connection() : Received %u bytes from router.",retval);
      cellbuflen += retval;
      
      if (cellbuflen == sizeof(cell_t)) /* received an entire cell */
      {
	/* link decrypt the cell header */
	retval = EVP_DecryptUpdate(&b_ctx, (unsigned char *)inbuf, &cellbuflen, (unsigned char *)&cellbuf, 8);
	if (!retval)
	{
	  log(LOG_ERR,"Decryption error. Closing the connection and exiting.");
	  break;
	}
	
	if (((cell_t *)inbuf)->command == CELL_PADDING) /* padding, discard */
	{
	  log(LOG_DEBUG,"Received a PADDING cell. Discarding.");
	  ; /* discard */
	}
	else if (((cell_t *)inbuf)->command == CELL_DATA) /* only process DATA cells , discard otherwise */
	{
	  /* decrypt the payload length */
	  retval = crypt_b((unsigned char *)&((cell_t *)inbuf)->length, 1, cpath, routelen);
	  if (retval == -1)
	  {
	    log(LOG_ERR,"Decryption error. Closing the connection and exiting.");
	    break;
	  }
	  
	  /* decrypt the payload */
	  retval = crypt_b((unsigned char *)cellbuf.payload, CELL_PAYLOAD_SIZE, cpath, routelen);
	  if (retval == -1)
	  {
	    log(LOG_ERR,"Decryption error. Closing the connection and exiting.");
	    break;
	  }
	  
	  /* send the payload to the application proxy */
	  retval = write_tout(new_sock, (unsigned char *)cellbuf.payload, ((cell_t *)inbuf)->length, conn_toutp);
	  if (retval < ((cell_t *)inbuf)->length)
	  {
	    log(LOG_ERR,"Connection to the application proxy seems to be lost.");
	    break;
	  }
	  log(LOG_DEBUG,"handle_connection() : Sent %u bytes to client.",retval);
	}
	else
	  log(LOG_DEBUG,"handle_connection() : Recived cell has incorrect command or ACI. Discarding.");
	
	cellbuflen = 0; /* get ready for the next cell */
      }
    }

    /* send cells to the router */
    send_to_router(or_sock,&outbuf, &outbuflen, &outbuf_dataoffset, &outbuf_datalen, &lastsend, &interval, scheduler, &f_ctx);
  }
  
  /* clean up */
  log(LOG_DEBUG,"handle_connection() : handle_connection() exiting.");
  close(or_sock);
  
  return 0;
}

/* used for reaping zombie processes */
void sigchld_handler(int s)
{
  while (wait(NULL) > 0);
  connections--;
}

int main(int argc, char *argv[])
{
  int one = 1;
  int retval = 0;
  
  char *cp; /* temporary storage */
  int i=0; /* iteration counter */
  
  char *conf_filename = NULL; /* configuration file */

  size_t sin_size; /* for accept() calls */
  
  u_short p; /* onion proxy port */
  
  /* used for reaping zombie processes */
  struct sigaction sa;

  int islocal = 0; /* is the incoming connection local? */

  struct rlimit cd_limit; /* resource limit to prevent core dumps */
  
  /* prevent core dump */
  retval = getrlimit(RLIMIT_CORE, &cd_limit);
  if (retval == -1)
  {
    log(LOG_ERR,"Could not tell the OS to prevent core dumps for the process.");
    return -1;
  }
  cd_limit.rlim_cur = 0;
  retval = setrlimit(RLIMIT_CORE, &cd_limit);
  if (retval == -1)
  {
    log(LOG_ERR,"Could not tell the OS to prevent core dumps for the process.");
    return -1;
  }
  
  /* get command-line arguments */
  retval = getargs(argc,argv,args,&p,&conf_filename,&loglevel);
  if (retval == -1)
  {
    log(LOG_ERR,"Error processing command-line arguments.");
    exit(1);
  }
  
  /* load config file */
  retval = getconfig(conf_filename,options);
  if (retval == -1)
  {
    log(LOG_ERR,"Error loading configuration file.");
    exit(1);
  }
  
  if (options[RouterFile].err != 1)
  {
    log(LOG_ERR,"RouterFile option required, but not found.");
    exit(1);
  }
  
  if (options[CoinWeight].err == -1)
  {
    log(LOG_ERR,"Error reading the CoinWeight option.");
    exit(1);
  }
  
  if (options[CoinWeight].err == 0)
  {
    /* this is optional, so if not found, set default value */
    options[CoinWeight].r.d = OP_DEFAULT_COIN_WEIGHT;
  }
  else if ((options[CoinWeight].r.d < 0) || (options[CoinWeight].r.d >= 1))
  {
    /* must be a value in [0,1) */
    log(LOG_ERR,"CoinWeight option must be >= 0 and < 1.");
    exit(1);
  }
  
  if (options[Bandwidth].err == 0)
  {
    /* optional, set to default */
    options[Bandwidth].r.i = OP_DEFAULT_BANDWIDTH;
  }
  else if (options[Bandwidth].r.i <= 0)
  {
    log(LOG_ERR,"The Bandwidth option must be an integer greater than zero.");
    exit(1);
  }
  
  if (options[ConnTimeout].err != 1)
  {
    conn_tout.tv_sec = OP_DEFAULT_CONN_TIMEOUT;
    conn_tout.tv_usec = 0;
  }
  else
  {
    if (!options[ConnTimeout].r.i)
      conn_toutp = NULL;
    else
      conn_tout.tv_sec = options[ConnTimeout].r.i;
    conn_tout.tv_usec = 0;
  }
  
  /* load the routers file */
  routerarray = getrouters(options[RouterFile].r.str,&rarray_len);
  if (!routerarray)
  {
    log(LOG_ERR,"Error loading router list.");
    exit(1);
  }
  
  /* get local address so that we know where to allow connections from*/
  retval = gethostname(local_hostname, (size_t)512);
  if (retval < 0)
  {
    log(LOG_ERR,"Error getting local hostname.");
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
  setsockopt(request_sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  log(LOG_DEBUG,"main() : Socket opened.");
  
  memset((void *)&local,0,sizeof(local)); /* clear the structure first */
  /* set up the sockaddr_in structure */
  local.sin_family=AF_INET;
  local.sin_addr.s_addr = INADDR_ANY;
  local.sin_port=htons(p);
  /* bind it to the socket */
  retval = bind(request_sock,(struct sockaddr *)&local, sizeof(local));
  if (retval < 0)
  {
    log(LOG_ERR,"Error binding socket to local port %d.",p);
    return retval;
  }
  log(LOG_DEBUG,"main() : Socket bound to port %d.",p);
  /* listen for connections */
  retval = listen(request_sock,SOMAXCONN);
  if (retval < 0)
  {
    log(LOG_ERR,"Could not listen for connections.");
    return retval;
  }
  log(LOG_DEBUG,"main() : Listening for connections.");
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
	log(LOG_DEBUG,"main() : Interrupt received.");
      continue;
    }
    
    if (connections == options[MaxConn].r.i)
    {
      close(new_sock);
      log(LOG_NOTICE,"Maximum connection limit exceeded. Rejecting incoming request.");
    }
    connections++;
    log(LOG_DEBUG,"main() : Accepted a connection from %s.",inet_ntoa(remote.sin_addr));
    
    /* see if the connection is local, otherwise reject */
    /* first check that the connection is from the local host, otherwise reject */
    if (*(uint32_t *)&remote.sin_addr == inet_addr("127.0.0.1"))
      islocal=1;
    for (i=0; (local_host->h_addr_list[i] != NULL) && (!islocal); i++)
    {
      cp = local_host->h_addr_list[i];
      if (!memcmp(&remote.sin_addr, cp,sizeof(struct in_addr)))
	islocal = 1;
    }
    
    if (!islocal)
    {
      log(LOG_DEBUG,"main() : Incoming connection is not local. Will reject.");
      close(new_sock);
    }
    else
    {
      log(LOG_DEBUG,"main() : Incoming connection seems to be local. Will accept.");
      /* fork a process to deal with the customer */
      if (!fork()) /* this is the child process */
      { 
	close(request_sock); /* the child doesn't need the request socket anymore */
	
	/* Main logic of op. */
	retval = handle_connection();
	log(LOG_DEBUG,"main() : Handle connection returned %d.",retval);
	/* End main logic */
	
	exit(retval); /* done, exit */
      } 
    
      close(new_sock); /* don't need this anymore */
    }
  }

  return retval;

}

