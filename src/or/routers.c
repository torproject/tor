/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * routers.c 
 * Routines for loading the list of routers and their public RSA keys.
 *
 * Matej Pfajfar <mp292@cam.ac.uk>
 */

#define OR_PUBLICKEY_END_TAG "-----END RSA PUBLIC KEY-----\n"

#include "or.h"

extern int global_role; /* from main.c */

/* static function prototypes */
static int router_is_me(uint32_t or_address, uint16_t or_listenport, uint16_t my_or_listenport);
static void routerlist_free(routerinfo_t *list);
static routerinfo_t **make_rarray(routerinfo_t* list, int *len);
static char *eat_whitespace(char *s);
static char *find_whitespace(char *s);
static routerinfo_t *router_get_entry_from_string(char **s);

/* private function, to determine whether the current entry in the router list is actually us */
static int router_is_me(uint32_t or_address, uint16_t or_listenport, uint16_t my_or_listenport)
{
  /* local host information */
  char localhostname[512];
  struct hostent *localhost;
  struct in_addr *a;
  char *tmp1;
  
  char *addr = NULL;
  int i = 0;

  if(!ROLE_IS_OR(global_role)) {
    /* we're not an OR. This obviously isn't us. */
    return 0;
  }
  
  /* obtain local host information */
  if (gethostname(localhostname,512) < 0) {
    log(LOG_ERR,"router_is_me(): Error obtaining local hostname.");
    return -1;
  }
  localhost = gethostbyname(localhostname);
  if (!localhost) {
    log(LOG_ERR,"router_is_me(): Error obtaining local host info.");
    return -1;
  }
  
  /* check host addresses for a match with or_address above */
  addr = localhost->h_addr_list[i++]; /* set to the first local address */
  while(addr)
  {
    a = (struct in_addr *)addr;

    tmp1 = strdup(inet_ntoa(*a)); /* can't call inet_ntoa twice in the same
				     printf, since it overwrites its static
				     memory each time */
    log(LOG_DEBUG,"router_is_me(): Comparing '%s' to '%s'.",tmp1,
       inet_ntoa( *((struct in_addr *)&or_address) ) );
    free(tmp1);
    if (!memcmp((void *)&or_address, (void *)addr, sizeof(uint32_t))) { /* addresses match */
      log(LOG_DEBUG,"router_is_me(): Addresses match. Comparing ports.");
      if (or_listenport == my_or_listenport) { /* ports also match */
        log(LOG_DEBUG,"router_is_me(): Ports match too.");
        return 1;
      }
    }
    
    addr = localhost->h_addr_list[i++];
  }
  
  return 0;
}

/* delete a list of routers from memory */
static void routerlist_free(routerinfo_t *list)
{
  routerinfo_t *tmp = NULL;
  
  if (!list)
    return;
  
  do
  {
    tmp=list->next;
    free((void *)list->address);
    crypto_free_pk_env(list->pkey);
    free((void *)list);
    list = tmp;
  }
  while (list != NULL);
  
  return;
}

void rarray_free(routerinfo_t **list) {
  if(!list)
    return;
  routerlist_free(*list);
  free(list);
}

/* create a NULL-terminated array of pointers pointing to elements of a router list */
/* this is done in two passes through the list - inefficient but irrelevant as this is
 * only done once when op/or start up */
static routerinfo_t **make_rarray(routerinfo_t* list, int *len)
{
  routerinfo_t *tmp=NULL;
  int listlen = 0;
  routerinfo_t **array=NULL;
  routerinfo_t **p=NULL;
  
  if ((!list) || (!len))
    return NULL;
  
  /* get the length of the list */
  tmp = list;
  do
  {
    listlen++;
    tmp = tmp->next;
  }
  while (tmp != NULL);
  
  array = malloc((listlen+1)*sizeof(routerinfo_t *));
  if (!array)
  {
    log(LOG_ERR,"Error allocating memory.");
    return NULL;
  }
  
  tmp=list;
  p = array;
  do
  {
    *p = tmp;
    p++;
    tmp = tmp->next;
  }
  while(tmp != NULL);
  *p=NULL;
  
  *len = listlen;
  return array;
}


/* load the router list */
routerinfo_t **router_get_list_from_file(char *routerfile, int *len, uint16_t or_listenport)
{
  routerinfo_t *routerlist=NULL;
  routerinfo_t *router;
  int fd; /* router file */
  struct stat statbuf;
  char *string;
  char *tmps;

  assert(routerfile && len);
  
  if (strcspn(routerfile,CONFIG_LEGAL_FILENAME_CHARACTERS) != 0) {
    log(LOG_ERR,"router_get_list_from_file(): Filename %s contains illegal characters.",routerfile);
    return NULL;
  }
  
  if(stat(routerfile, &statbuf) < 0) {
    log(LOG_ERR,"router_get_list_from_file(): Could not stat %s.",routerfile);
    return NULL;
  }

  /* open the router list */
  fd = open(routerfile,O_RDONLY,0);
  if (fd<0) {
    log(LOG_ERR,"router_get_list_from_file(): Could not open %s.",routerfile);
    return NULL;
  }

  string = malloc(statbuf.st_size+1);
  if(!string) {
    log(LOG_ERR,"router_get_list_from_file(): Out of memory.");
    return NULL;
  }

  if(read(fd,string,statbuf.st_size) != statbuf.st_size) {
    log(LOG_ERR,"router_get_list_from_file(): Couldn't read all %d bytes of file '%s'.",statbuf.st_size,routerfile);
    return NULL;
  }
  close(fd);
  
  string[statbuf.st_size] = 0; /* null terminate it */
  tmps = string;
  while(*tmps) { /* while not at the end of the string */
    router = router_get_entry_from_string(&tmps);
    if(router == NULL) {
      routerlist_free(routerlist);
      free(string);
      return NULL;
    }
    if(!router_is_me(router->addr, router->or_port, or_listenport)) {
      router->next = routerlist;
      routerlist = router;
    }
    tmps = eat_whitespace(tmps);
  }
  free(string);
  return make_rarray(routerlist, len);
} 

/* return the first char of s that is not whitespace and not a comment */
static char *eat_whitespace(char *s) {
  assert(s);

  while(isspace(*s) || *s == '#') {
    while(isspace(*s))
      s++;
    if(*s == '#') { /* read to a \n or \0 */
      while(*s && *s != '\n')
        s++;
      if(!*s)
        return s;
    }
  }
  return s;
}

/* return the first char of s that is whitespace or '#' or '\0 */
static char *find_whitespace(char *s) {
  assert(s);

  while(*s && !isspace(*s) && *s != '#')
    s++;

  return s;
}

/* reads a single router entry from s.
 * updates s so it points to after the router it just read.
 * mallocs a new router, returns it if all goes well, else returns NULL.
 */
static routerinfo_t *router_get_entry_from_string(char **s) {
  routerinfo_t *router;
  char *next;
  struct hostent *rent;

  router = malloc(sizeof(routerinfo_t));
  if (!router) {
    log(LOG_ERR,"router_get_entry_from_string(): Could not allocate memory.");
    return NULL;
  }
  memset(router,0,sizeof(routerinfo_t)); /* zero it out first */

#define NEXT_TOKEN(s, next)    \
  *s = eat_whitespace(*s);     \
  next = find_whitespace(*s);  \
  if(!*next) {                 \
    goto router_read_failed;   \
  }                            \
  *next = 0;

  /* read router->address */
  NEXT_TOKEN(s, next);
  router->address = strdup(*s);
  *s = next+1;

  rent = (struct hostent *)gethostbyname(router->address);
  if (!rent) {
    log(LOG_ERR,"router_get_entry_from_string(): Could not get address for router %s.",router->address);
    goto router_read_failed;
  }
  assert(rent->h_length == 4);
  memcpy(&router->addr, rent->h_addr,rent->h_length);

  /* read router->or_port */
  NEXT_TOKEN(s, next);
  router->or_port = atoi(*s);
  if(!router->or_port) {
    log(LOG_ERR,"router_get_entry_from_string(): or_port '%s' unreadable or 0. Failing.",*s);
    goto router_read_failed;
  }
  *s = next+1;
  
  /* read router->op_port */
  NEXT_TOKEN(s, next);
  router->op_port = atoi(*s);
  *s = next+1;
  
  /* read router->ap_port */
  NEXT_TOKEN(s, next);
  router->ap_port = atoi(*s);
  *s = next+1;
  
  /* read router->dir_port */
  NEXT_TOKEN(s, next);
  router->dir_port = atoi(*s);
  *s = next+1;

  /* read router->bandwidth */
  NEXT_TOKEN(s, next);
  router->bandwidth = atoi(*s);
  if(!router->bandwidth) {
    log(LOG_ERR,"router_get_entry_from_string(): bandwidth '%s' unreadable or 0. Failing.",*s);
    goto router_read_failed;
  }
  *s = next+1;

  log(LOG_DEBUG,"or_port %d, op_port %d, ap_port %d, dir_port %d, bandwidth %d.",
    router->or_port, router->op_port, router->ap_port, router->dir_port, router->bandwidth);

  *s = eat_whitespace(*s); 
  next = strstr(*s,OR_PUBLICKEY_END_TAG);
  router->pkey = crypto_new_pk_env(CRYPTO_PK_RSA);
  if(!next || !router->pkey) {
    log(LOG_ERR,"router_get_entry_from_string(): Couldn't find pk in string");
    goto router_read_failed;
  }
  
  /* now advance *s so it's at the end of this router entry */
  next = strchr(next, '\n');
  assert(next); /* can't fail, we just checked it was here */
  *next = 0;
  log(LOG_DEBUG,"Key about to be read is: '%s'",*s);
  if((crypto_pk_read_public_key_from_string(router->pkey, *s, strlen(*s))<0)) {
    log(LOG_ERR,"router_get_entry_from_string(): Couldn't read pk from string");
    goto router_read_failed;
  }
  log(LOG_DEBUG,"router_get_entry_from_string(): Public key size = %u.", crypto_pk_keysize(router->pkey));

  if (crypto_pk_keysize(router->pkey) != 128) { /* keys MUST be 1024 bits in size */
    log(LOG_ERR,"Key for router %s:%u is not 1024 bits. All keys must be exactly 1024 bits long.",
      router->address,router->or_port);
    goto router_read_failed;
  }

//  test_write_pkey(router->pkey);  

  *s = next+1;

  /* success */
  return(router);

router_read_failed:
  if(router->address)
    free(router->address);
  if(router->pkey)
    crypto_free_pk_env(router->pkey);
  free(router);
  return NULL;
}

#if 0
void test_write_pkey(crypto_pk_env_t *pkey) {
  char *string;
  int len;

  log(LOG_DEBUG,"Trying test write.");
  if(crypto_pk_write_public_key_to_string(pkey,&string,&len)<0) {
    log(LOG_DEBUG,"router_get_entry_from_string(): write pkey to string failed\n");
    return;
  }
  log(LOG_DEBUG,"I did it: len %d, string '%s'.",len,string);
  free(string);
}
#endif

