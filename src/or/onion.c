/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

extern int global_role; /* from main.c */

/********* START VARIABLES **********/

tracked_onion_t *tracked_onions = NULL; /* linked list of tracked onions */
tracked_onion_t *last_tracked_onion = NULL;

/********* END VARIABLES ************/


int decide_aci_type(uint32_t local_addr, uint16_t local_port,
                    uint32_t remote_addr, uint16_t remote_port) {

  if(local_addr > remote_addr)
    return ACI_TYPE_HIGHER;
  if(local_addr < remote_addr)
    return ACI_TYPE_LOWER;
  if(local_port > remote_port)
    return ACI_TYPE_HIGHER;
   /* else */
   return ACI_TYPE_LOWER; 
}

int process_onion(circuit_t *circ, connection_t *conn) {
  aci_t aci_type;
  struct sockaddr_in me; /* my router identity */

  if(learn_my_address(&me) < 0)
    return -1;

  if(!decrypt_onion((onion_layer_t *)circ->onion,circ->onionlen,getprivatekey())) {
    log(LOG_DEBUG,"command_process_create_cell(): decrypt_onion() failed, closing circuit.");
    return -1;
  }
  log(LOG_DEBUG,"command_process_create_cell(): Onion decrypted.");

  /* check freshness */
  if (((onion_layer_t *)circ->onion)->expire < time(NULL)) /* expired onion */
  { 
    log(LOG_NOTICE,"I have just received an expired onion. This could be a replay attack.");
    return -1;
  }

  aci_type = decide_aci_type(ntohl(me.sin_addr.s_addr), ntohs(me.sin_port),
             ((onion_layer_t *)circ->onion)->addr,((onion_layer_t *)circ->onion)->port);
      
  if(circuit_init(circ, aci_type) < 0) { 
    log(LOG_ERR,"process_onion(): init_circuit() failed.");
    return -1;
  }

  /* check for replay */
  if(id_tracked_onion(circ->onion, circ->onionlen, tracked_onions)) {
    log(LOG_NOTICE,"process_onion(): I have just received a replayed onion. This could be a replay attack.");
    return -1;
  }

  /* track the new onion */
  if(!new_tracked_onion(circ->onion,circ->onionlen, &tracked_onions, &last_tracked_onion)) {
    log(LOG_DEBUG,"process_onion(): Onion tracking failed. Will ignore.");
  }

  return 0;
}

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
    retval = crypto_pseudo_rand(1, &coin);
    if (retval)
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
unsigned int *new_route(double cw, routerinfo_t **rarray, int rarray_len, int *routelen)
{
  int i, j;
  int num_acceptable_routers = 0;
  unsigned int *route = NULL;
  unsigned int oldchoice, choice;
  
  assert((cw >= 0) && (cw < 1) && (rarray) && (routelen) ); /* valid parameters */

  *routelen = chooselen(cw);
  if (*routelen == -1) {
    log(LOG_ERR,"Choosing route length failed.");
    return NULL;
  }
  log(LOG_DEBUG,"new_route(): Chosen route length %d.",*routelen);

  for(i=0;i<rarray_len;i++) {
    log(LOG_DEBUG,"Contemplating whether router %d is a new option...",i);
    if( (global_role & ROLE_OR_CONNECT_ALL) &&
      !connection_exact_get_by_addr_port(rarray[i]->addr, rarray[i]->or_port)) {
      log(LOG_DEBUG,"Nope, %d is not connected.",i);
      goto next_i_loop;
    }
    for(j=0;j<i;j++) {
      if(!crypto_pk_cmp_keys(rarray[i]->pkey, rarray[j]->pkey)) {
        /* these guys are twins. so we've already counted him. */
        log(LOG_DEBUG,"Nope, %d is a twin of %d.",i,j);
        goto next_i_loop;
      }
    }
    num_acceptable_routers++;
    log(LOG_DEBUG,"I like %d. num_acceptable_routers now %d.",i, num_acceptable_routers);
    next_i_loop:
      ; /* our compiler may need an explicit statement after the label */
  }
      
  if(num_acceptable_routers < *routelen) {
    log(LOG_DEBUG,"new_route(): Cutting routelen from %d to %d.",*routelen, num_acceptable_routers);
    *routelen = num_acceptable_routers;
  }

  if(*routelen < 1) {
    log(LOG_ERR,"new_route(): Didn't find any acceptable routers. Failing.");
    return NULL;
  }

  /* allocate memory for the new route */
  route = (unsigned int *)malloc(*routelen * sizeof(unsigned int));
  if (!route) {
    log(LOG_ERR,"Memory allocation failed.");
    return NULL;
  }
 
  oldchoice = rarray_len;
  for(i=0;i<*routelen;i++) {
    log(LOG_DEBUG,"new_route(): Choosing hop %u.",i);
    if(crypto_pseudo_rand(sizeof(unsigned int),(unsigned char *)&choice)) {
      free((void *)route);
      return NULL;
    }

    choice = choice % (rarray_len);
    log(LOG_DEBUG,"new_route(): Contemplating router %u.",choice);
    if(choice == oldchoice ||
      (oldchoice < rarray_len && !crypto_pk_cmp_keys(rarray[choice]->pkey, rarray[oldchoice]->pkey)) ||
      ((global_role & ROLE_OR_CONNECT_ALL) && !connection_twin_get_by_addr_port(rarray[choice]->addr, rarray[choice]->or_port))) {
      /* Same router as last choice, or router twin,
       *   or no routers with that key are connected to us.
       * Try again. */
      log(LOG_DEBUG,"new_route(): Picked a router %d that won't work as next hop.",choice);
      i--;
      continue;  
    }
    log(LOG_DEBUG,"new_route(): Chosen router %u for hop %u.",choice,i);
    oldchoice = choice;
    route[i] = choice;
  }
   
  return route;
}

crypto_cipher_env_t *
create_onion_cipher(int cipher_type, char *key, char *iv, int encrypt_mode)
{
  switch (cipher_type) {
    case ONION_CIPHER_DES:
      cipher_type = CRYPTO_CIPHER_DES;
      break;
    case ONION_CIPHER_RC4 :
      cipher_type = ONION_CIPHER_RC4;
      break;
    case ONION_CIPHER_IDENTITY :
      cipher_type = CRYPTO_CIPHER_IDENTITY;
      break;
    default:
      log(LOG_ERR, "Unknown cipher type %d", cipher_type);
      return NULL;
  }
  return crypto_create_init_cipher(cipher_type, key, iv, encrypt_mode);
}

/* creates a new onion from route, stores it and its length into buf and len respectively */
unsigned char *create_onion(routerinfo_t **rarray, int rarray_len, unsigned int *route, int routelen, int *len, crypt_path_t **cpath)
{
  int i,j;
  onion_layer_t *layer = NULL;
  crypt_path_t *hop = NULL;
  unsigned char *buf;
  routerinfo_t *router;
  unsigned char iv[16];
  struct in_addr netaddr;

  assert(rarray && route && len && routelen);

  /* calculate the size of the onion */
  *len = routelen * 28 + 100; /* 28 bytes per layer + 100 bytes padding for the innermost layer */
  log(LOG_DEBUG,"create_onion() : Size of the onion is %u.",*len);
    
  /* allocate memory for the onion */
  buf = (unsigned char *)malloc(*len);
  if (!buf) {
    log(LOG_ERR,"Error allocating memory.");
    return NULL;
  }
  log(LOG_DEBUG,"create_onion() : Allocated memory for the onion.");
    
  for (i=0; i<routelen;i++) {
    netaddr.s_addr = htonl((rarray[route[i]])->addr);

    log(LOG_DEBUG,"create_onion(): %u : %s:%u, %u/%u",routelen-i,
        inet_ntoa(netaddr),
        (rarray[route[i]])->or_port,
        (rarray[route[i]])->pkey,
        crypto_pk_keysize((rarray[route[i]])->pkey));
  }
    
  layer = (onion_layer_t *)(buf + *len - 128); /* pointer to innermost layer */
  /* create the onion layer by layer, starting with the innermost */
  for (i=0;i<routelen;i++) {
    router = rarray[route[i]];
      
//      log(LOG_DEBUG,"create_onion() : %u",router);
//      log(LOG_DEBUG,"create_onion() : This router is %s:%u",inet_ntoa(*((struct in_addr *)&router->addr)),router->or_port);
//      log(LOG_DEBUG,"create_onion() : Key pointer = %u.",router->pkey);
//      log(LOG_DEBUG,"create_onion() : Key size = %u.",crypto_pk_keysize(router->pkey)); 
      
    /* 0 bit */
    layer->zero = 0;
    /* version */
    layer->version = OR_VERSION;
    /* Back F + Forw F both use DES OFB*/
    layer->backf = ONION_DEFAULT_CIPHER;
    layer->forwf = ONION_DEFAULT_CIPHER;
    /* Dest Port */
    if (i) /* not last hop */
      layer->port = rarray[route[i-1]]->or_port;
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
    if(crypto_rand(16, layer->keyseed)) { /* error */
      log(LOG_ERR,"Error generating random data.");
      goto error;
    }
//      log(LOG_DEBUG,"create_onion() : Onion layer %u built : %u, %u, %u, %s, %u.",i+1,layer->zero,layer->backf,layer->forwf,inet_ntoa(*((struct in_addr *)&layer->addr)),layer->port);
      
    /* build up the crypt_path */
    if(cpath) {
      cpath[i] = (crypt_path_t *)malloc(sizeof(crypt_path_t));
      if(!cpath[i]) {
        log(LOG_ERR,"Error allocating memory.");
        goto error;
      }
      
      log(LOG_DEBUG,"create_onion() : Building hop %u of crypt path.",i+1);
      hop = cpath[i];
      /* set crypto functions */
      hop->backf = layer->backf;
      hop->forwf = layer->forwf;
	
      /* calculate keys */
      crypto_SHA_digest(layer->keyseed,16,hop->digest3);
      log(LOG_DEBUG,"create_onion() : First SHA pass performed.");
      crypto_SHA_digest(hop->digest3,20,hop->digest2);
      log(LOG_DEBUG,"create_onion() : Second SHA pass performed.");
      crypto_SHA_digest(hop->digest2,20,hop->digest3);
      log(LOG_DEBUG,"create_onion() : Third SHA pass performed.");
      log(LOG_DEBUG,"create_onion() : Keys generated.");
      /* set IV to zero */
      memset((void *)iv,0,16);
	
      /* initialize cipher engines */
      if (! (hop->f_crypto = create_onion_cipher(hop->forwf, hop->digest3, iv, 1))) { 
        /* cipher initialization failed */
        log(LOG_ERR,"Could not create a crypto environment.");
        goto error;
      }
	
      if (! (hop->b_crypto = create_onion_cipher(hop->backf, hop->digest2, iv, 0))) { 
        /* cipher initialization failed */
        log(LOG_ERR,"Could not create a crypto environment.");
        goto error;
      }
 
      log(LOG_DEBUG,"create_onion() : Built corresponding crypt path hop.");
    }
      
    /* padding if this is the innermost layer */
    if (!i) {
      if (crypto_pseudo_rand(100, (unsigned char *)layer + 28)) { /* error */
        log(LOG_ERR,"Error generating pseudo-random data.");
        goto error;
      }
      log(LOG_DEBUG,"create_onion() : This is the innermost layer. Adding 100 bytes of padding.");
    }
      
    /* encrypt */

    if(! encrypt_onion(layer,128+(i*28),router->pkey)) {
      log(LOG_ERR,"Error encrypting onion layer.");
      goto error;
    }
    log(LOG_DEBUG,"create_onion() : Encrypted layer.");
      
    /* calculate pointer to next layer */
    layer = (onion_layer_t *)(buf + (routelen-i-2)*sizeof(onion_layer_t));
  }

  return buf;
 error:
  if (buf)
    free((void *)buf);
  if (cpath) {
    for (j=0;j<i;j++) {
      if(cpath[i]->f_crypto)
        crypto_free_cipher_env(cpath[i]->f_crypto);
      if(cpath[i]->b_crypto)
        crypto_free_cipher_env(cpath[i]->b_crypto);
      free((void *)cpath[i]);
    }
  }
  return NULL;
}

/* encrypts 128 bytes of the onion with the specified public key, the rest with 
 * DES OFB with the key as defined in the outter layer */
unsigned char *encrypt_onion(onion_layer_t *onion, uint32_t onionlen, crypto_pk_env_t *pkey)
{
  unsigned char *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char iv[8];
  
  crypto_cipher_env_t *crypt_env = NULL; /* crypto environment */
 
  assert(onion && pkey);

  memset((void *)iv,0,8);
    
  log(LOG_DEBUG,"Onion layer : %u, %u, %u, %s, %u.",onion->zero,onion->backf,onion->forwf,inet_ntoa(*((struct in_addr *)&onion->addr)),onion->port);
  /* allocate space for tmpbuf */
  tmpbuf = (unsigned char *)malloc(onionlen);
  if (!tmpbuf) {
    log(LOG_ERR,"Could not allocate memory.");
    return NULL;
  }
  log(LOG_DEBUG,"encrypt_onion() : allocated %u bytes of memory for the encrypted onion (at %u).",onionlen,tmpbuf);
  
  /* get key1 = SHA1(KeySeed) */
  if (crypto_SHA_digest(((onion_layer_t *)onion)->keyseed,16,digest)) {
    log(LOG_ERR,"Error computing SHA1 digest.");
    goto error;
  }
  log(LOG_DEBUG,"encrypt_onion() : Computed DES key.");
    
  log(LOG_DEBUG,"encrypt_onion() : Trying to RSA encrypt.");
  /* encrypt 128 bytes with RSA *pkey */
  if (crypto_pk_public_encrypt(pkey, (unsigned char *)onion, 128, tmpbuf, RSA_NO_PADDING) == -1) {
    log(LOG_ERR,"Error RSA-encrypting data :%s",crypto_perror());
    goto error;
  }

  log(LOG_DEBUG,"encrypt_onion() : RSA encrypted first 128 bytes of the onion."); 
    
  /* now encrypt the rest with DES OFB */
  crypt_env = crypto_create_init_cipher(CRYPTO_CIPHER_DES, digest, iv, 1);
  if (!crypt_env) {
    log(LOG_ERR,"Error creating the crypto environment.");
    goto error;
  }
    
  if (crypto_cipher_encrypt(crypt_env,(unsigned char *)onion+128, onionlen-128, (unsigned char *)tmpbuf+128)) { /* error */
    log(LOG_ERR,"Error performing DES encryption:%s",crypto_perror()); 
    goto error;
  }
  log(LOG_DEBUG,"encrypt_onion() : DES OFB encrypted the rest of the onion.");
    
  /* now copy tmpbuf to onion */
  memcpy((void *)onion,(void *)tmpbuf,onionlen);
  log(LOG_DEBUG,"encrypt_onion() : Copied cipher to original onion buffer.");
  free((void *)tmpbuf);
  crypto_free_cipher_env(crypt_env);
  return (unsigned char *)onion;

 error:
  if (tmpbuf)
    free((void *)tmpbuf);
  if (crypt_env)
    crypto_free_cipher_env(crypt_env);
  return NULL;
}

/* decrypts the first 128 bytes using RSA and prkey, decrypts the rest with DES OFB with key1 */
unsigned char *decrypt_onion(onion_layer_t *onion, uint32_t onionlen, crypto_pk_env_t *prkey)
{
  void *tmpbuf = NULL; /* temporary buffer for crypto operations */
  unsigned char digest[20]; /* stores SHA1 output - 160 bits */
  unsigned char iv[8];
  
  crypto_cipher_env_t *crypt_env =NULL; /* crypto environment */
  
  if ( (onion) && (prkey) ) { /* valid parameters */
    memset((void *)iv,0,8);
    
    /* allocate space for tmpbuf */
    tmpbuf = malloc(onionlen);
    if (!tmpbuf) {
      log(LOG_ERR,"Could not allocate memory.");
      return NULL;
    }
    log(LOG_DEBUG,"decrypt_onion() : Allocated memory for the temporary buffer.");

    /* decrypt 128 bytes with RSA *prkey */
    if (crypto_pk_private_decrypt(prkey, (unsigned char*)onion, 128, (unsigned char *)tmpbuf, RSA_NO_PADDING) == -1)
    {
      log(LOG_ERR,"Error RSA-decrypting data :%s",crypto_perror());
      goto error;
    }
    log(LOG_DEBUG,"decrypt_onion() : RSA decryption complete.");
    
    /* get key1 = SHA1(KeySeed) */
    if (crypto_SHA_digest(((onion_layer_t *)tmpbuf)->keyseed,16,digest))
    {
      log(LOG_ERR,"Error computing SHA1 digest.");
      goto error;
    }
    log(LOG_DEBUG,"decrypt_onion() : Computed DES key.");
    
    /* now decrypt the rest with DES OFB */
    crypt_env = crypto_create_init_cipher(CRYPTO_CIPHER_DES, digest, iv, 0);
    if (!crypt_env) {
      log(LOG_ERR,"Error creating crypto environment");
      goto error;
    }
 
    if (crypto_cipher_decrypt(crypt_env,(unsigned char *)onion+128, onionlen-128,(unsigned char *)tmpbuf+128)) {
      log(LOG_ERR,"Error performing DES decryption:%s",crypto_perror());
      goto error;
    }
    
    log(LOG_DEBUG,"decrypt_onion() : DES decryption complete.");
    
    /* now copy tmpbuf to onion */
    memcpy((void *)onion,(void *)tmpbuf,onionlen);
    free((void *)tmpbuf);
    crypto_free_cipher_env(crypt_env);
    return (unsigned char *)onion;
  } /* valid parameters */
  else
    return NULL;

 error:
  if (tmpbuf)
    free((void *)tmpbuf);
  if (crypt_env)
    crypto_free_cipher_env(crypt_env);
  return NULL;
}

/* delete first n bytes of the onion and pads the end with n bytes of random data */
void pad_onion(unsigned char *onion, uint32_t onionlen, int n)
{
  if (onion) /* valid parameter */
  {
    memmove((void *)onion,(void *)(onion+n),onionlen-n);
    crypto_pseudo_rand(n, onion+onionlen-n);
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
  if (crypto_SHA_digest(onion, onionlen, to->digest))
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
  crypto_SHA_digest(onion,onionlen, digest);
  
  while(to)
  {
    if (!memcmp((void *)digest, (void *)to->digest, 20))
      return to;
    to = (tracked_onion_t *)to->next;
  }
  
  return NULL;
}
