/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#define OR_PUBLICKEY_END_TAG "-----END RSA PUBLIC KEY-----\n"

#include "or.h"

/****************************************************************************/

/* router array */
static routerinfo_t **router_array = NULL;
static int rarray_len = 0;

extern or_options_t options; /* command-line and config-file options */
extern routerinfo_t *my_routerinfo; /* from main.c */

/****************************************************************************/

/* static function prototypes */
static void routerlist_free(routerinfo_t *list);
static routerinfo_t **make_rarray(routerinfo_t* list, int *len);
static char *eat_whitespace(char *s);
static char *find_whitespace(char *s);
static routerinfo_t *router_get_entry_from_string(char **s);
static void router_add_exit_policy(routerinfo_t *router, char *string);
static void router_free_exit_policy(routerinfo_t *router);

/****************************************************************************/

int learn_my_address(struct sockaddr_in *me) {
  /* local host information */
  char localhostname[512];
  struct hostent *localhost;

  /* obtain local host information */
  if(gethostname(localhostname,512) < 0) {
    log(LOG_ERR,"Error obtaining local hostname.");
    return -1;
  }
  log(LOG_DEBUG,"learn_my_address(): localhostname is '%s'.",localhostname);
  localhost = gethostbyname(localhostname);
  if (!localhost) {
    log(LOG_ERR,"Error obtaining local host info.");
    return -1;
  }
  memset(me,0,sizeof(struct sockaddr_in));
  me->sin_family = AF_INET;
  memcpy((void *)&me->sin_addr,(void *)localhost->h_addr,sizeof(struct in_addr));
  me->sin_port = htons(options.ORPort);
  log(LOG_DEBUG,"learn_my_address(): chose address as '%s'.",inet_ntoa(me->sin_addr));

  return 0;
}

void router_retry_connections(void) {
  int i;
  routerinfo_t *router;

  for (i=0;i<rarray_len;i++) {
    router = router_array[i];
    if(!connection_exact_get_by_addr_port(router->addr,router->or_port)) { /* not in the list */
      log(LOG_DEBUG,"retry_all_connections(): connecting to OR %s:%u.",router->address,router->or_port);
      connection_or_connect_as_or(router);
    }
  }
}

routerinfo_t *router_pick_directory_server(void) {
  /* currently, pick the first router with a positive dir_port */
  int i;
  routerinfo_t *router;
  
  if(!router_array)
    return NULL;

  for(i=0;i<rarray_len;i++) {
    router = router_array[i];
    if(router->dir_port > 0)
      return router;
  }

  return NULL;
}

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  assert(router_array);

  for(i=0;i<rarray_len;i++) {
    router = router_array[i];
    if ((router->addr == addr) && (router->or_port == port))
      return router;
  }

  return NULL;
}

routerinfo_t *router_get_first_in_route(unsigned int *route, int routelen) {
  return router_array[route[routelen-1]];
}

/* a wrapper around new_route. put all these in routers.c perhaps? */
unsigned int *router_new_route(int *routelen) {
  return new_route(options.CoinWeight, router_array, rarray_len, routelen);
}

/* a wrapper around create_onion */
unsigned char *router_create_onion(unsigned int *route, int routelen, int *len, crypt_path_t **cpath) {
  return create_onion(router_array,rarray_len,route,routelen,len,cpath);
}

/* return 1 if addr and port corresponds to my addr and my or_listenport. else 0,
 * or -1 for failure.
 */
int router_is_me(uint32_t addr, uint16_t port)
{
  struct sockaddr_in me; /* my router identity */

  if(!options.ORPort) {
    /* we're not an OR. This obviously isn't us. */
    return 0;
  }
 
  if(learn_my_address(&me) < 0)
    return -1;

  if(ntohl(me.sin_addr.s_addr) == addr && ntohs(me.sin_port) == port)
    return 1;

  return 0;

#if 0
  /* local host information */
  char localhostname[512];
  struct hostent *localhost;
  struct in_addr *a;
  char *tmp1;
  
  char *addr = NULL;
  int i = 0;

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
#endif
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

void router_forget_router(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  router = router_get_by_addr_port(addr,port);
  if(!router) /* we don't seem to know about him in the first place */
    return;

  /* now walk down router_array until we get to router */
  for(i=0;i<rarray_len;i++)
    if(router_array[i] == router)
      break;

  assert(i != rarray_len); /* if so then router_get_by_addr_port should have returned null */

//  free(router); /* don't actually free; we'll free it when we free the whole thing */

//  log(LOG_DEBUG,"router_forget_router(): Forgot about router %d:%d",addr,port);
  for(; i<rarray_len-1;i++)
    router_array[i] = router_array[i+1];
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
int router_get_list_from_file(char *routerfile)
{
  int fd; /* router file */
  struct stat statbuf;
  char *string;

  assert(routerfile);
  
  if (strcspn(routerfile,CONFIG_LEGAL_FILENAME_CHARACTERS) != 0) {
    log(LOG_ERR,"router_get_list_from_file(): Filename %s contains illegal characters.",routerfile);
    return -1;
  }
  
  if(stat(routerfile, &statbuf) < 0) {
    log(LOG_ERR,"router_get_list_from_file(): Could not stat %s.",routerfile);
    return -1;
  }

  /* open the router list */
  fd = open(routerfile,O_RDONLY,0);
  if (fd<0) {
    log(LOG_ERR,"router_get_list_from_file(): Could not open %s.",routerfile);
    return -1;
  }

  string = malloc(statbuf.st_size+1);
  if(!string) {
    log(LOG_ERR,"router_get_list_from_file(): Out of memory.");
    return -1;
  }

  if(read(fd,string,statbuf.st_size) != statbuf.st_size) {
    log(LOG_ERR,"router_get_list_from_file(): Couldn't read all %d bytes of file '%s'.",statbuf.st_size,routerfile);
    free(string);
    close(fd);
    return -1;
  }
  close(fd);
  
  string[statbuf.st_size] = 0; /* null terminate it */

  if(router_get_list_from_string(string) < 0) {
    log(LOG_ERR,"router_get_list_from_file(): The routerfile itself was corrupt.");
    free(string);
    return -1;
  }

  free(string);
  return 0;
} 

int router_get_list_from_string(char *s) {
  routerinfo_t *routerlist=NULL;
  routerinfo_t *router;
  routerinfo_t **new_router_array;
  int new_rarray_len;

  assert(s);

  while(*s) { /* while not at the end of the string */
    router = router_get_entry_from_string(&s);
    if(router == NULL) {
      routerlist_free(routerlist);
      return -1;
    }
    switch(router_is_me(router->addr, router->or_port)) {
      case 0: /* it's not me */
        router->next = routerlist;
        routerlist = router;
        break;
      case 1: /* it is me */
        if(!my_routerinfo) /* save it, so we can use it for directories */
          my_routerinfo = router;
        else
          routerlist_free(router);        
        break;
      default:
        log(LOG_ERR,"router_get_list_from_string(): router_is_me returned error.");
        routerlist_free(routerlist);
        return -1;
    }
    s = eat_whitespace(s);
  }
 
  new_router_array = make_rarray(routerlist, &new_rarray_len);
  if(new_router_array) { /* success! replace the old one */
    rarray_free(router_array); /* free the old one first */
    router_array = new_router_array;
    rarray_len = new_rarray_len;
    return 0;
  }
  return -1;
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

/* Bug: if find_whitespace returns a '#', we'll squish it. */
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
  router->addr = ntohl(router->addr); /* get it back into host order */

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
//  log(LOG_DEBUG,"Key about to be read is: '%s'",*s);
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
  while(**s != '\n') {
    /* pull in a line of exit policy */
    next = strchr(*s, '\n');
    if(!next)
      goto router_read_failed;
    *next = 0;
    router_add_exit_policy(router, *s);
    *s = next+1;
  }

  return router;


router_read_failed:
  if(router->address)
    free(router->address);
  if(router->pkey)
    crypto_free_pk_env(router->pkey);
  router_free_exit_policy(router);
  free(router);
  return NULL;
}

static void router_free_exit_policy(routerinfo_t *router) {
  struct exit_policy_t *tmpe;

  while(router->exit_policy) {
    tmpe = router->exit_policy;
    router->exit_policy = tmpe->next;
    free(tmpe->string);
    free(tmpe->address);
    free(tmpe->port);
    free(tmpe);
  }
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

static void router_add_exit_policy(routerinfo_t *router, char *string) {
  struct exit_policy_t *tmpe, *newe;
  char *n;

  string = eat_whitespace(string);
  if(!*string) /* it was all whitespace or comment */
    return;

  newe = malloc(sizeof(struct exit_policy_t));
  memset(newe,0,sizeof(struct exit_policy_t));

  newe->string = strdup(string);
  if(!strncasecmp(string,"reject ",strlen("reject "))) {
    newe->policy_type = EXIT_POLICY_REJECT;
  } else if(!strncasecmp(string,"accept ",strlen("accept "))) {
    newe->policy_type = EXIT_POLICY_ACCEPT;
  } else {
    goto policy_read_failed;
  }

  string = eat_whitespace(string + strlen("reject "));
  if(!*string) {
    goto policy_read_failed;
  }

  n = strchr(string,':');
  if(!n)
    goto policy_read_failed;
  *n = 0;
  newe->address = strdup(string);
  string = n+1;
  n = find_whitespace(string);
  *n = 0;
  newe->port = strdup(string);

  log(LOG_DEBUG,"router_add_exit_policy(): type %d, address '%s', port '%s'.",
      newe->policy_type, newe->address, newe->port);

  /* now link newe onto the end of exit_policy */

  if(!router->exit_policy) {
    router->exit_policy = newe;
    return;
  }

  for(tmpe=router->exit_policy; tmpe->next; tmpe=tmpe->next) ;
  tmpe->next = newe;

  return;

policy_read_failed:
  assert(newe->string);
  log(LOG_INFO,"router_add_exit_policy(): Couldn't parse line '%s'. Dropping", newe->string);
  if(newe->string)
    free(newe->string);
  if(newe->address)
    free(newe->address);
  if(newe->port)
    free(newe->port);
  free(newe);
  return;

}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/

