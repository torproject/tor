/**
 * onion.c 
 * Routines for creating/manipulating onions.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/06/26 22:45:50  arma
 * Initial revision
 *
 * Revision 1.24  2002/06/14 20:42:02  mp292
 * Bug caused infinite loop when router list had <= 2 entries.
 *
 * Revision 1.23  2002/04/02 14:27:11  badbytes
 * Final finishes.
 *
 * Revision 1.22  2002/04/02 10:20:09  badbytes
 * Memory overflow bug.
 *
 * Revision 1.21  2002/03/25 09:11:23  badbytes
 * Added a list of onions being tracked for replay attacks.
 *
 * Revision 1.20  2002/03/12 23:32:41  mp292
 * *** empty log message ***
 *
 * Revision 1.19  2002/01/27 19:23:21  mp292
 * Fixed a bug in parameter checking.
 *
 * Revision 1.18  2002/01/26 19:24:29  mp292
 * Reviewed according to Secure-Programs-HOWTO.
 *
 * Revision 1.17  2002/01/18 20:40:40  mp292
 * Fixed a bug in en/decrypt_onion() functions.
 *
 * Revision 1.16  2002/01/17 23:48:31  mp292
 * Added some extra debugging messages to fix a bug in encrypt_onion() which
 * seems to corrupt the routent *route list.
 *
 * Revision 1.15  2002/01/17 15:00:43  mp292
 * Fixed a bug which caused malloc() generate a seg fault.
 *
 * Revision 1.14  2002/01/16 23:01:54  mp292
 * First phase of system testing completed (main functionality).
 *
 * Revision 1.13  2002/01/14 13:05:37  badbytes
 * System testing in progress.
 *
 * Revision 1.12  2002/01/11 15:47:17  badbytes
 * *** empty log message ***
 *
 * Revision 1.11  2002/01/09 07:58:23  badbytes
 * Fixed a bug so that backward crypto engines are now initialized with DecryptInit.
 *
 * Revision 1.10  2002/01/09 07:55:23  badbytes
 * Ciphers got out of sync. Hopefully fixed.
 *
 * Revision 1.9  2002/01/03 11:01:22  badbytes
 * *** empty log message ***
 *
 * Revision 1.8  2001/12/19 08:29:00  badbytes
 * Macro DEFAULT_CIPHER now holds the default crypto algorithm
 *
 * Revision 1.7  2001/12/18 14:12:47  badbytes
 * Default cipher is now IDENTITY, for testing purposes.
 *
 * Revision 1.6  2001/12/18 10:36:51  badbytes
 * create_onion() now also computes a crypt_path
 *
 * Revision 1.5  2001/12/17 13:35:17  badbytes
 * Still writing handle_connection()
 *
 * Revision 1.4  2001/12/14 14:44:37  badbytes
 * chooselen() tested
 *
 * Revision 1.3  2001/12/14 13:30:48  badbytes
 * peel_onion() was redundant, removed it
 *
 * Revision 1.2  2001/12/14 13:14:03  badbytes
 * Split types.h into routent.h and ss.h. Keeping them all in one file created unnecesary dependencies.
 *
 * Revision 1.1  2001/12/14 12:41:12  badbytes
 * Moved from op/ as it will be reused by other modules.
 *
 * Revision 1.1  2001/12/13 15:15:10  badbytes
 * Started coding the onion proxy.
 *
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "onion.h"
#include "log.h"

/* uses a weighted coin with weight cw to choose a route length */
int chooselen(double cw)
{
  int len = 2;
  int retval = 0;
  unsigned char coin;
  
  if ((cw < 0) || (cw >= 1)) /* invalid parameter */
    return -1;
  
  while(1)
  {
    retval = RAND_pseudo_bytes(&coin,1);
    if (retval == -1)
      return -1;
    
    if (coin > cw*255) /* don't extend */
      break;
    else
      len++;
  }
  
  return len;
}

/* returns an array of pointers to routent that define a new route through the OR network
 * int cw is the coin weight to use when choosing the route 
 * order of routers is from last to first
 */
unsigned int *new_route(double cw, routent_t **rarray, size_t rarray_len, size_t *rlen)
{
  int routelen = 0;
  int i = 0;
  int retval = 0;
  unsigned int *route = NULL;
  unsigned int oldchoice, choice;
  
  if ( (cw >= 0) && (cw < 1) && (rarray) && (rlen) ) /* valid parameters */
  {
    routelen = chooselen(cw);
    if (routelen == -1)
    {
      log(LOG_ERR,"Choosing route length failed.");
      return NULL;
    }
    log(LOG_DEBUG,"new_route(): Chosen route length %u.",routelen);
  
    /* allocate memory for the new route */
    route = (unsigned int *)malloc(routelen * sizeof(unsigned int));
    if (!route)
    {
      log(LOG_ERR,"Memory allocation failed.");
      return NULL;
    }
 
    oldchoice = rarray_len;
    for(i=0;i<routelen;i++)
    {
      log(LOG_DEBUG,"new_route() : Choosing hop %u.",i);
      retval = RAND_pseudo_bytes((unsigned char *)&choice,sizeof(unsigned int));
      if (retval == -1)
      {
	free((void *)route);
	return NULL;
      }

      choice = choice % (rarray_len);
      log(LOG_DEBUG,"new_route() : Chosen router %u.",choice);
      if (choice == oldchoice) /* same router */
      {
	/* try again  */
	i--;
	continue;
      }
      oldchoice = choice;
      route[i] = choice;
    }
   
    *rlen = routelen;
    return route;
  } /* valid parameters */
  else /* invalid parameters */
    return NULL;
}

/* creates a new onion from route, stores it and its length into bufp and lenp respectively */
unsigned char *create_onion(routent_t **rarray, size_t rarray_len, unsigned int *route, size_t routelen, size_t *lenp, crypt_path_t **cpathp)
{
  int i,j;
  int retval = 0;
  onion_layer_t *layer = NULL;
  crypt_path_t *hop = NULL;
  unsigned char *retbuf = NULL;
  unsigned char *bufp;
  routent_t *router;

  if ( (rarray) && (route) && (lenp) ) /* valid parameters */
  {
    /* calculate the size of the onion */
    *lenp = routelen * 28 + 100; /* 28 bytes per layer + 100 bytes padding for the innermost layer */
    log(LOG_DEBUG,"create_onion() : Size of the onion is %u.",*lenp);
    
    /* allocate memory for the onion */
    bufp = (unsigned char *)malloc(*lenp);
    if (!bufp)
    {
      log(LOG_ERR,"Error allocating memory.");
      return NULL;
    }
    log(LOG_DEBUG,"create_onion() : Allocated memory for the onion.");
    
    for (retval=0; retval<routelen;retval++)
    {
      log(LOG_DEBUG,"create_onion() : %u : %s:%u, %u/%u",routelen-retval,inet_ntoa(*((struct in_addr *)&((rarray[route[retval]])->addr))),ntohs((rarray[route[retval]])->port),(rarray[route[retval]])->pkey,RSA_size((rarray[route[retval]])->pkey));
    }
    
    layer = (onion_layer_t *)(bufp + *lenp - 128); /* pointer to innermost layer */
    /* create the onion layer by layer, starting with the innermost */
    for (i=0;i<routelen;i++)
    {
      router = rarray[route[i]];
      
      log(LOG_DEBUG,"create_onion() : %u",router);
      log(LOG_DEBUG,"create_onion() : This router is %s:%u",inet_ntoa(*((struct in_addr *)&router->addr)),ntohs(router->port));
      log(LOG_DEBUG,"create_onion() : Key pointer = %u.",router->pkey);
      log(LOG_DEBUG,"create_onion() : Key size = %u.",RSA_size(router->pkey)); 
      
      /* 0 bit */
      layer->zero = 0;
      /* version */
      layer->version = VERSION;
      /* Back F + Forw F both use DES OFB*/
      layer->backf = ONION_DEFAULT_CIPHER;
      layer->forwf = ONION_DEFAULT_CIPHER;
      /* Dest Port */
      if (i) /* not last hop */
	layer->port = rarray[route[i-1]]->port;
      else
	layer->port = 0;
      /* Dest Addr */
      if (i) /* not last hop */
	layer->addr = rarray[route[i-1]]->addr;
      else
	layer->addr = 0;
      /* Expiration Time */
      layer->expire = time(NULL) + 3600; /* NOW + 1 hour */
      /* Key Seed Material */
      retval = RAND_bytes(layer->keyseed,16);
      if (retval < 1) /* error */
      {
	log(LOG_ERR,"Error generating random data.");
	free((void *)bufp);
	if (cpathp)
	{
	  for (j=0;j<i;j++)
	    free((void *)cpathp[i]);
	}
	return NULL;
      }
      log(LOG_DEBUG,"create_onion() : Onion layer %u built : %u, %u, %u, %s, %u.",i+1,layer->zero,layer->backf,layer->forwf,inet_ntoa(*((struct in_addr *)&layer->addr)),ntohs(layer->port));
      
      /* build up the crypt_path */
      if (cpathp)
      {
	cpathp[i] = (crypt_path_t *)malloc(sizeof(crypt_path_t));
	if (!cpathp[i])
	{
	  log(LOG_ERR,"Error allocating memory.");
	  free((void *)bufp);
	  for (j=0;j<i;j++)
	    free((void *)cpathp[i]);
	}
      
	log(LOG_DEBUG,"create_onion() : Building hop %u of crypt path.",i+1);
	hop = cpathp[i];
	/* set crypto functions */
	hop->backf = layer->backf;
	hop->forwf = layer->forwf;
	
	/* calculate keys */
	SHA1(layer->keyseed,16,hop->digest3);
	log(LOG_DEBUG,"create_onion() : First SHA pass performed.");
	SHA1(hop->digest3,20,hop->digest2);
	log(LOG_DEBUG,"create_onion() : Second SHA pass performed.");
	SHA1(hop->digest2,20,hop->digest3);
	log(LOG_DEBUG,"create_onion() : Third SHA pass performed.");
	log(LOG_DEBUG,"create_onion() : Keys generated.");
	/* set IVs */
	memset((void *)hop->f_iv,0,16);
	memset((void *)hop->b_iv,0,16);
	
	/* initialize cipher contexts */
	EVP_CIPHER_CTX_init(&hop->f_ctx);
	EVP_CIPHER_CTX_init(&hop->b_ctx);
	
	/* initialize cipher engines */
	switch(layer->forwf)
	{
	 case ONION_CIPHER_DES :
	  retval = EVP_EncryptInit(&hop->f_ctx, EVP_des_ofb(), hop->digest3, hop->f_iv);
	  break;
	 case ONION_CIPHER_RC4 :
	  retval = EVP_EncryptInit(&hop->f_ctx, EVP_rc4(), hop->digest3, hop->f_iv);
	  break;
	 case ONION_CIPHER_IDENTITY :
	  retval = EVP_EncryptInit(&hop->f_ctx, EVP_enc_null(), hop->digest3, hop->f_iv);
	  break;
	}
	if (!retval) /* cipher initialization failed */
	{
	  log(LOG_ERR,"Could not initialize crypto engines.");
	  free((void *)bufp);
	  for (j=0;j<i;j++)
	    free((void *)cpathp[i]);
	  return NULL;
	}
	switch(layer->backf)
	{
	 case ONION_CIPHER_DES :
	  retval = EVP_DecryptInit(&hop->b_ctx, EVP_des_ofb(), hop->digest2, hop->b_iv);
	  break;
	 case ONION_CIPHER_RC4 :
	  retval = EVP_DecryptInit(&hop->b_ctx, EVP_rc4(), hop->digest2, hop->b_iv);
	  break;
	 case ONION_CIPHER_IDENTITY :
	  retval = EVP_DecryptInit(&hop->b_ctx, EVP_enc_null(), hop->digest2, hop->b_iv);
	  break;
	}
	if (!retval) /* cipher initialization failed */
	{
	  log(LOG_ERR,"Could not initialize crypto engines.");
	  free((void *)bufp);
	  for (j=0;j<i;j++)
	    free((void *)cpathp[i]);
	  return NULL;
	}
	
	log(LOG_DEBUG,"create_onion() : Built corresponding crypt path hop.");
      }
      
      /* padding if this is the innermost layer */
      if (!i)
      {
	retval=RAND_pseudo_bytes((unsigned char *)layer + 28,100);
	if (retval == -1) /* error */
	{
	  log(LOG_ERR,"Error generating pseudo-random data.");
	  free((void *)bufp);
	  if (cpathp)
	  {
	    for (j=0;j<i;j++)
	      free((void *)cpathp[i]);
	  }
	  return NULL;
	}
	log(LOG_DEBUG,"create_onion() : This is the innermost layer. Adding 100 bytes of padding.");
      }
      
      /* encrypt */
      retbuf = encrypt_onion(layer,128+(i*28),router->pkey);
      if (!retbuf)
      {
	log(LOG_ERR,"Error encrypting onion layer.");
	free((void *)bufp);
	if (cpathp)
	{
	  for (j=0;j<i;j++)
	    free((void *)cpathp[i]);
	}
	return NULL;
      }
      log(LOG_DEBUG,"create_onion() : Encrypted layer.");
      
      /* calculate pointer to next layer */
      layer = (onion_layer_t *)bufp + (routelen-i-2)*sizeof(onion_layer_t);
    }

    return bufp;
  } /* valid parameters */
  else
    return NULL;
}

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
unsigned char *encrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *pkey)
{
  unsigned char *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char *retbuf = NULL;
  unsigned char iv[8];
  int retval = 0;
  int outlen = 0;
  
  EVP_CIPHER_CTX ctx; /* cipher context */
 
  if ( (onion) && (pkey) ) /* valid parameters */
  {
    memset((void *)iv,0,8);
    
    log(LOG_DEBUG,"Onion layer : %u, %u, %u, %s, %u.",onion->zero,onion->backf,onion->forwf,inet_ntoa(*((struct in_addr *)&onion->addr)),ntohs(onion->port));
    /* allocate space for tmpbuf */
    tmpbuf = (unsigned char *)malloc(onionlen);
    if (!tmpbuf)
    {
      log(LOG_ERR,"Could not allocate memory.");
      return NULL;
    }
    log(LOG_DEBUG,"encrypt_onion() : allocated %u bytes of memory for the encrypted onion (at %u).",onionlen,tmpbuf);
  
    /* get key1 = SHA1(KeySeed) */
    retbuf = SHA1(((onion_layer_t *)onion)->keyseed,16,digest);
    if (!retbuf)
    {
      log(LOG_ERR,"Error computing SHA1 digest.");
      free((void *)tmpbuf);
      return NULL;
    }
    log(LOG_DEBUG,"encrypt_onion() : Computed DES key.");
    
    log(LOG_DEBUG,"encrypt_onion() : Trying to RSA encrypt.");
    /* encrypt 128 bytes with RSA *pkey */
    retval = RSA_public_encrypt(128, (unsigned char *)onion, tmpbuf, pkey, RSA_NO_PADDING); 
    if (retval == -1) 
    { 
      log(LOG_ERR,"Error RSA-encrypting data :%s",ERR_reason_error_string(ERR_get_error())); 
      free((void *)tmpbuf); 
      return NULL; 
    }
  
    log(LOG_DEBUG,"encrypt_onion() : RSA encrypted first 128 bytes of the onion."); 
    
    /* now encrypt the rest with DES OFB */
    
    EVP_CIPHER_CTX_init(&ctx); 
    retval = EVP_EncryptInit(&ctx,EVP_des_ofb(),digest,iv);
    if (!retval) /* error */ 
    { 
      log(LOG_ERR,"Error initializing DES engine:%s",ERR_reason_error_string(ERR_get_error())); 
      free((void *)tmpbuf); 
      return NULL; 
    } 
    
    retval = EVP_EncryptUpdate(&ctx,(unsigned char *)tmpbuf+128,&outlen,(unsigned char *)onion+128,onionlen-128);
    if (!retval) /* error */
    { 
      log(LOG_ERR,"Error performing DES encryption:%s",ERR_reason_error_string(ERR_get_error())); 
      free((void *)tmpbuf); 
      return NULL; 
    }
    log(LOG_DEBUG,"encrypt_onion() : DES OFB encrypted the rest of the onion.");
  
    EVP_CIPHER_CTX_cleanup(&ctx);
  
    /* now copy tmpbuf to onion */
    memcpy((void *)onion,(void *)tmpbuf,onionlen);
    log(LOG_DEBUG,"encrypt_onion() : Copied cipher to original onion buffer.");
    free((void *)tmpbuf);
    return (unsigned char *)onion;
  } /* valid parameters */
  else
    return NULL;
}

/* decrypts the first 128 bytes using RSA and prkey, decrypts the rest with DES OFB with key1 */
unsigned char *decrypt_onion(onion_layer_t *onion, uint32_t onionlen, RSA *prkey)
{
  void *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char *retbuf = NULL;
  unsigned char iv[8];
  int retval = 0;
  int outlen = 0;
  
  EVP_CIPHER_CTX ctx; /* cipher context */
  
  if ( (onion) && (prkey) ) /* valid parameters */
  {
    memset((void *)iv,0,8);
    
    /* allocate space for tmpbuf */
    tmpbuf = malloc(onionlen);
    if (!tmpbuf)
    {
      log(LOG_ERR,"Could not allocate memory.");
      return NULL;
    }
    log(LOG_DEBUG,"decrypt_onion() : Allocated memory for the temporary buffer.");

    /* decrypt 128 bytes with RSA *prkey */
    retval = RSA_private_decrypt(128, (unsigned char*)onion, (unsigned char *)tmpbuf, prkey, RSA_NO_PADDING);
    if (retval == -1)
    {
      log(LOG_ERR,"Error RSA-decrypting data :%s",ERR_reason_error_string(ERR_get_error()));
      free((void *)tmpbuf);
      return NULL;
    }
    log(LOG_DEBUG,"decrypt_onion() : RSA decryption complete.");
    
    /* get key1 = SHA1(KeySeed) */
    retbuf = SHA1(((onion_layer_t *)tmpbuf)->keyseed,16,digest);
    if (!retbuf)
    {
      log(LOG_ERR,"Error computing SHA1 digest.");
      free((void *)tmpbuf);
      return NULL;
    }
    log(LOG_DEBUG,"decrypt_onion() : Computed DES key.");
    
    /* now decrypt the rest with DES OFB */
    EVP_CIPHER_CTX_init(&ctx);
    retval = EVP_DecryptInit(&ctx,EVP_des_ofb(),digest,iv);
    if (!retval) /* error */
    {
      log(LOG_ERR,"Error initializing DES engine:%s",ERR_reason_error_string(ERR_get_error()));
      free((void *)tmpbuf);
      return NULL;
    }
    retval = EVP_DecryptUpdate(&ctx,(unsigned char *)tmpbuf+128,&outlen,(unsigned char *)onion+128,onionlen-128);
    if (!retval) /* error */
    {
      log(LOG_ERR,"Error performing DES decryption:%s",ERR_reason_error_string(ERR_get_error()));
      free((void *)tmpbuf);
      return NULL;
    }
    
    EVP_CIPHER_CTX_cleanup(&ctx);
    log(LOG_DEBUG,"decrypt_onion() : DES decryption complete.");
    
    /* now copy tmpbuf to onion */
    memcpy((void *)onion,(void *)tmpbuf,onionlen);
    free((void *)tmpbuf);
    return (unsigned char *)onion;
  } /* valid parameters */
  else
    return NULL;
}

/* delete first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, size_t n)
{
  if (onion) /* valid parameter */
  {
    memmove((void *)onion,(void *)(onion+n),onionlen-n);
    RAND_pseudo_bytes(onion+onionlen-n,n);
  }
}

/* create a new tracked_onion entry */
tracked_onion_t *new_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion)
{
  tracked_onion_t *to = NULL;
  
  if (!onion || !tracked_onions || !last_tracked_onion) /* invalid parameters */
    return NULL;
  
  to = (tracked_onion_t *)malloc(sizeof(tracked_onion_t));
  if (!to)
    return NULL;
  
  to->expire = ((onion_layer_t *)onion)->expire; /* set the expiration date */
  /* compute the SHA digest */
  SHA1(onion, onionlen, to->digest);
  if (!to->digest)
  {
    log(LOG_DEBUG,"new_tracked_onion() : Failed to compute a SHA1 digest of the onion.");
    free((void *)to);
    return NULL;
  }
  
  to->next = NULL;
  
  if (!*tracked_onions)
  {
    to->prev = NULL;
    *tracked_onions = to;
  }
  else
  {
    to->prev = (void *)*last_tracked_onion;
    (*last_tracked_onion)->next = (void *)to;
  }
  *last_tracked_onion = to;
  
  return to;
}

/* delete a tracked onion entry */
void remove_tracked_onion(tracked_onion_t *to, tracked_onion_t **tracked_onions, tracked_onion_t **last_tracked_onion)
{
  if (!*tracked_onions || !*last_tracked_onion || !to)
    return;
  
  if (to->prev)
    ((tracked_onion_t *)to->prev)->next = to->next;
  if (to->next)
    ((tracked_onion_t *)to->next)->prev = to->prev;
  
  if (to == *tracked_onions)
    *tracked_onions = (tracked_onion_t *)to->next;
  
  if (to == *last_tracked_onion)
    *last_tracked_onion = (tracked_onion_t *)to->prev;
  
  free((void *)to);
  
  return;
}

/* find a tracked onion in the linked list of tracked onions */
tracked_onion_t *id_tracked_onion(unsigned char *onion, uint32_t onionlen, tracked_onion_t *tracked_onions)
{
  tracked_onion_t *to = tracked_onions;
  unsigned char digest[20];
  
  /* compute the SHA digest of the onion */
  SHA1(onion,onionlen, digest);
  
  while(to)
  {
    if (!memcmp((void *)digest, (void *)to->digest, 20))
      return to;
    to = (tracked_onion_t *)to->next;
  }
  
  return NULL;
}

