/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#define OR_PUBLICKEY_BEGIN_TAG "-----BEGIN RSA PUBLIC KEY-----\n"
#define OR_PUBLICKEY_END_TAG "-----END RSA PUBLIC KEY-----\n"
#define OR_SIGNATURE_BEGIN_TAG "-----BEGIN SIGNATURE-----\n"
#define OR_SIGNATURE_END_TAG "-----END SIGNATURE-----\n"

#define _GNU_SOURCE
/* XXX this is required on rh7 to make strptime not complain. how bad
 * is this for portability?
 */

#include "or.h"
#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif

/****************************************************************************/

/* router array */
static directory_t *directory = NULL;

extern or_options_t options; /* command-line and config-file options */
static routerinfo_t *my_routerinfo;

/****************************************************************************/

struct directory_token;
typedef struct directory_token directory_token_t;

/* static function prototypes */
void routerlist_free(routerinfo_t *list);
static char *eat_whitespace(char *s);
static char *eat_whitespace_no_nl(char *s);
static char *find_whitespace(char *s);
static void router_free_exit_policy(routerinfo_t *router);
static int router_add_exit_policy(routerinfo_t *router, 
                                  directory_token_t *tok);
static int router_resolve_directory(directory_t *dir);
static int init_descriptor(void);

/****************************************************************************/

int learn_my_address(struct sockaddr_in *me) {
  /* local host information */
  char localhostname[256];
  struct hostent *localhost;
  static struct sockaddr_in answer;
  static int already_learned=0;

  if(!already_learned) {
    /* obtain local host information */
    if(gethostname(localhostname,sizeof(localhostname)) < 0) {
      log_fn(LOG_WARNING,"Error obtaining local hostname");
      return -1;
    }
    log_fn(LOG_DEBUG,"localhostname is '%s'.",localhostname);
    localhost = gethostbyname(localhostname);
    if (!localhost) {
      log_fn(LOG_WARNING,"Error obtaining local host info.");
      /* XXX maybe this is worse than warning? bad things happen when we don't know ourselves */
      return -1;
    }
    memset(&answer,0,sizeof(struct sockaddr_in));
    answer.sin_family = AF_INET;
    memcpy((void *)&answer.sin_addr,(void *)localhost->h_addr,sizeof(struct in_addr));
    answer.sin_port = htons((uint16_t) options.ORPort);
    log_fn(LOG_DEBUG,"chose address as '%s'.",inet_ntoa(answer.sin_addr));
    if (!strncmp("127.",inet_ntoa(answer.sin_addr), 4) &&
        strcasecmp(localhostname, "localhost")) {
      /* We're a loopback IP but we're not called localhost.  Uh oh! */
      log_fn(LOG_WARNING, "Got a loopback address: /etc/hosts may be wrong");
    }
    already_learned = 1;
  }
  memcpy(me,&answer,sizeof(struct sockaddr_in));
  return 0;
}

void router_retry_connections(void) {
  int i;
  routerinfo_t *router;

  for (i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if(!connection_exact_get_by_addr_port(router->addr,router->or_port)) { /* not in the list */
      log_fn(LOG_DEBUG,"connecting to OR %s:%u.",router->address,router->or_port);
      connection_or_connect(router);
    }
  }
}

routerinfo_t *router_pick_directory_server(void) {
  /* pick the first running router with a positive dir_port */
  int i;
  routerinfo_t *router;
  
  if(!directory)
    return NULL;

  for(i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if(router->dir_port > 0 && router->is_running)
      return router;
  }

  return NULL;
}

void router_upload_desc_to_dirservers(void) {
  int i;
  routerinfo_t *router;

  if(!directory)
    return;

  if (!router_get_my_descriptor()) {
    log_fn(LOG_WARNING, "No descriptor; skipping upload");
    return;
  }

  for(i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if(router->dir_port > 0)
      directory_initiate_command(router, DIR_CONN_STATE_CONNECTING_UPLOAD);
  }
}

routerinfo_t *router_get_by_addr_port(uint32_t addr, uint16_t port) {
  int i;
  routerinfo_t *router;

  assert(directory);

  for(i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if ((router->addr == addr) && (router->or_port == port))
      return router;
  }
  return NULL;
}

routerinfo_t *router_get_by_link_pk(crypto_pk_env_t *pk) 
{
  int i;
  routerinfo_t *router;

  assert(directory);

  for(i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if (0 == crypto_pk_cmp_keys(router->link_pkey, pk))
      return router;
  }
  return NULL;
}

routerinfo_t *router_get_by_nickname(char *nickname)
{
  int i;
  routerinfo_t *router;

  assert(directory);

  for(i=0;i<directory->n_routers;i++) {
    router = directory->routers[i];
    if (0 == strcmp(router->nickname, nickname))
      return router;
  }
  return NULL;
}

void router_get_directory(directory_t **pdirectory) {
  *pdirectory = directory;
}

/* return 1 if addr and port corresponds to my addr and my or_listenport. else 0,
 * or -1 for failure.
 */
int router_is_me(uint32_t addr, uint16_t port)
{
  /* XXXX Should this check the key too? */
  struct sockaddr_in me; /* my router identity */

  if(!options.OnionRouter) {
    /* we're not an OR. This obviously isn't us. */
    return 0;
  }
 
  if(learn_my_address(&me) < 0)
    return -1;
    /* XXX people call this function like a boolean. that's bad news: -1 is true. */

  if(ntohl(me.sin_addr.s_addr) == addr && ntohs(me.sin_port) == port)
    return 1;

  return 0;

}

/* delete a list of routers from memory */
void routerinfo_free(routerinfo_t *router)
{
  struct exit_policy_t *e = NULL, *etmp = NULL;
  
  if (!router)
    return;

  if (router->address)
    free(router->address);
  if (router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if (router->link_pkey)
    crypto_free_pk_env(router->link_pkey);
  if (router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  e = router->exit_policy;
  while (e) {
    etmp = e->next;
    if (e->string) free(e->string);
    if (e->address) free(e->address);
    if (e->port) free(e->port);
    free(e);
    e = etmp;
  }
  free(router);
}

void directory_free(directory_t *directory)
{
  int i;
  for (i = 0; i < directory->n_routers; ++i)
    routerinfo_free(directory->routers[i]);
  if (directory->routers)
    free(directory->routers);
  if(directory->software_versions)
    free(directory->software_versions);
  free(directory);
}

void router_mark_as_down(char *nickname) {
  routerinfo_t *router = router_get_by_nickname(nickname);
  if(!router) /* we don't seem to know about him in the first place */
    return;
  log_fn(LOG_DEBUG,"Marking %s as down.",router->nickname);
  router->is_running = 0;
}

/* load the router list */
int router_get_list_from_file(char *routerfile)
{
  char *string;

  string = read_file_to_str(routerfile);
  if(!string) {
    log_fn(LOG_WARNING,"Failed to load routerfile %s.",routerfile);
    return -1;
  }
  
  if(router_get_list_from_string(string) < 0) {
    log_fn(LOG_WARNING,"The routerfile itself was corrupt.");
    free(string);
    return -1;
  }

  free(string);
  return 0;
} 


typedef enum {
  K_ACCEPT,
  K_DIRECTORY_SIGNATURE,
  K_RECOMMENDED_SOFTWARE,
  K_REJECT, 
  K_ROUTER, 
  K_SIGNED_DIRECTORY,
  K_SIGNING_KEY,
  K_ONION_KEY,
  K_LINK_KEY,
  K_ROUTER_SIGNATURE,
  K_PUBLISHED,
  K_RUNNING_ROUTERS,
  K_PLATFORM,
  _SIGNATURE, 
  _PUBLIC_KEY, 
  _ERR, 
  _EOF 
} directory_keyword;

struct token_table_ent { char *t; int v; };

static struct token_table_ent token_table[] = {
  { "accept", K_ACCEPT },
  { "directory-signature", K_DIRECTORY_SIGNATURE },
  { "reject", K_REJECT },
  { "router", K_ROUTER },
  { "recommended-software", K_RECOMMENDED_SOFTWARE },
  { "signed-directory", K_SIGNED_DIRECTORY },
  { "signing-key", K_SIGNING_KEY },
  { "onion-key", K_ONION_KEY },
  { "link-key", K_LINK_KEY },
  { "router-signature", K_ROUTER_SIGNATURE },
  { "published", K_PUBLISHED },
  { "running-routers", K_RUNNING_ROUTERS },
  { "platform", K_PLATFORM },
  { NULL, -1 }
};

#define MAX_ARGS 1024
struct directory_token {
  directory_keyword tp;
  union {
    struct {
      char *args[MAX_ARGS+1]; 
      int n_args;
    } cmd;
    char *signature;
    char *error;
    crypto_pk_env_t *public_key;
  } val;
};

/* Free any malloced resources allocated for a token.  Don't call this if
   you inherit the reference to those resources.
 */
static void
router_release_token(directory_token_t *tok)
{
  switch (tok->tp) 
    {
    case _SIGNATURE:
      free(tok->val.signature);
      break;
    case _PUBLIC_KEY:
      crypto_free_pk_env(tok->val.public_key);
      break;
    default:
      break;
    }
}

static int
_router_get_next_token(char **s, directory_token_t *tok) {
  char *next;
  crypto_pk_env_t *pkey = NULL;
  char *signature = NULL;
  int i, done;

  tok->tp = _ERR;
  tok->val.error = "";

  *s = eat_whitespace(*s);
  if (!**s) {
    tok->tp = _EOF;
    return 0;
  } else if (**s == '-') {
    next = strchr(*s, '\n');
    if (! next) { tok->val.error = "No newline at EOF"; return -1; }
    ++next;
    if (! strncmp(*s, OR_PUBLICKEY_BEGIN_TAG, next-*s)) {
      next = strstr(*s, OR_PUBLICKEY_END_TAG);
      if (!next) { tok->val.error = "No public key end tag found"; return -1; }
      next = strchr(next, '\n'); /* Part of OR_PUBLICKEY_END_TAG; can't fail.*/
      ++next;
      if (!(pkey = crypto_new_pk_env(CRYPTO_PK_RSA))) 
        return -1;
      if (crypto_pk_read_public_key_from_string(pkey, *s, next-*s)) {
        crypto_free_pk_env(pkey);
        tok->val.error = "Couldn't parse public key.";
        return -1;
      }
      tok->tp = _PUBLIC_KEY;
      tok->val.public_key = pkey;
      *s = next;
      return 0;
    } else if (! strncmp(*s, OR_SIGNATURE_BEGIN_TAG, next-*s)) {
      /* Advance past newline; can't fail. */
      *s = strchr(*s, '\n'); 
      ++*s;
      /* Find end of base64'd data */
      next = strstr(*s, OR_SIGNATURE_END_TAG);
      if (!next) { tok->val.error = "No signature end tag found"; return -1; }
      
      signature = tor_malloc(256);
      i = base64_decode(signature, 256, *s, next-*s);
      if (i<0) {
        free(signature);
        tok->val.error = "Error decoding signature."; return -1;
      } else if (i != 128) {
        free(signature);
        tok->val.error = "Bad length on decoded signature."; return -1;
      }
      tok->tp = _SIGNATURE;
      tok->val.signature = signature;

      next = strchr(next, '\n'); /* Part of OR_SIGNATURE_END_TAG; can't fail.*/
      *s = next+1;
      return 0;
    } else {
      tok->val.error = "Unrecognized begin line"; return -1;
    }
  } else {
    next = find_whitespace(*s);
    if (!next) {
      tok->val.error = "Unexpected EOF"; return -1;
    }
    for (i = 0 ; token_table[i].t ; ++i) {
      if (!strncmp(token_table[i].t, *s, next-*s)) {
        tok->tp = token_table[i].v;
        i = 0;
        done = (*next == '\n');
        *s = eat_whitespace_no_nl(next);
        while (**s != '\n' && i <= MAX_ARGS && !done) {
          next = find_whitespace(*s);
          if (*next == '\n')
            done = 1;
          *next = 0;
          tok->val.cmd.args[i++] = *s;
          *s = eat_whitespace_no_nl(next+1);
        };
        tok->val.cmd.n_args = i;
        if (i > MAX_ARGS) {
          tok->tp = _ERR;
          tok->val.error = "Too many arguments"; return -1;
        }
        return 0;
      }
    }
    tok->val.error = "Unrecognized command"; return -1;
  }
}

#ifdef DEBUG_ROUTER_TOKENS
static void 
router_dump_token(directory_token_t *tok) {
  int i;
  switch(tok->tp) 
    {
    case _SIGNATURE:
      puts("(signature)");
      return;
    case _PUBLIC_KEY:
      puts("(public key)");
      return;
    case _ERR:
      printf("(Error: %s\n)", tok->val.error);
      return;
    case _EOF:
      puts("EOF");
      return;
    case K_ACCEPT: printf("Accept"); break;
    case K_DIRECTORY_SIGNATURE: printf("Directory-Signature"); break;
    case K_REJECT: printf("Reject"); break;
    case K_RECOMMENDED_SOFTWARE: printf("Server-Software"); break;
    case K_ROUTER: printf("Router"); break;
    case K_SIGNED_DIRECTORY: printf("Signed-Directory"); break;
    case K_SIGNING_KEY: printf("Signing-Key"); break;
    case K_ONION_KEY: printf("Onion-key"); break;
    case K_LINK_KEY: printf("Link-key"); break;
    case K_ROUTER_SIGNATURE: printf("Router-signature"); break;
    case K_PUBLISHED: printf("Published"); break;
    case K_RUNNING_ROUTERS: printf("Running-routers"); break;
    case K_PLATFORM: printf("Platform"); break;
    default:
      printf("?????? %d\n", tok->tp); return;
    }
  for (i = 0; i < tok->val.cmd.n_args; ++i) {
    printf(" \"%s\"", tok->val.cmd.args[i]);
  }
  printf("\n");
  return;
}
static int
router_get_next_token(char **s, directory_token_t *tok) {
  int i;
  i = _router_get_next_token(s, tok);
  router_dump_token(tok);
  return i;
}
#else
#define router_get_next_token _router_get_next_token
#endif


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

static char *eat_whitespace_no_nl(char *s) {
  while(*s == ' ' || *s == '\t') 
    ++s;
  return s;
}

/* return the first char of s that is whitespace or '#' or '\0 */
static char *find_whitespace(char *s) {
  assert(s);

  while(*s && !isspace(*s) && *s != '#')
    s++;

  return s;
}

int router_get_list_from_string(char *s) 
{
  if (router_get_list_from_string_impl(&s, &directory, -1, NULL)) {
    log(LOG_WARNING, "Error parsing router file");
    return -1;
  }
  if (router_resolve_directory(directory)) {
    log(LOG_WARNING, "Error resolving directory");
    return -1;
  }
  return 0;
}

static int router_get_hash_impl(char *s, char *digest, const char *start_str,
                                const char *end_str) 
{
  char *start, *end;
  start = strstr(s, start_str);
  if (!start) {
    log_fn(LOG_WARNING,"couldn't find \"%s\"",start_str);
    return -1;
  }
  end = strstr(start+strlen(start_str), end_str);
  if (!end) {
    log_fn(LOG_WARNING,"couldn't find \"%s\"",end_str);
    return -1;
  }
  end = strchr(end, '\n');
  if (!end) {
    log_fn(LOG_WARNING,"couldn't find EOL");
    return -1;
  }
  ++end;
  
  if (crypto_SHA_digest(start, end-start, digest)) {
    log_fn(LOG_WARNING,"couldn't compute digest");
    return -1;
  }

  return 0;
}

int router_get_dir_hash(char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "signed-directory","directory-signature");
}
int router_get_router_hash(char *s, char *digest)
{
  return router_get_hash_impl(s,digest,
                              "router ","router-signature");
}

/* return 0 if myversion is in start. Else return -1. */
int compare_recommended_versions(char *myversion, char *start) {
  int len_myversion = strlen(myversion);
  char *comma;
  char *end = start + strlen(start);

  log_fn(LOG_DEBUG,"checking '%s' in '%s'.", myversion, start);
  
  for(;;) {
    comma = strchr(start, ',');
    if( ((comma ? comma : end) - start == len_myversion) &&
       !strncmp(start, myversion, len_myversion)) /* only do strncmp if the length matches */
        return 0; /* success, it's there */
    if(!comma)
      return -1; /* nope */
    start = comma+1;
  }
}

int router_get_dir_from_string(char *s, crypto_pk_env_t *pkey)
{
  if (router_get_dir_from_string_impl(s, &directory, pkey)) {
    log_fn(LOG_WARNING, "Couldn't parse directory.");
    return -1;
  }
  if (router_resolve_directory(directory)) {
    log_fn(LOG_WARNING, "Error resolving directory");
    return -1;
  }
  if (compare_recommended_versions(VERSION, directory->software_versions) < 0) {
    log(LOG_WARNING, "You are running tor version %s, which is no longer supported.\nPlease upgrade to one of %s.", VERSION, RECOMMENDED_SOFTWARE_VERSIONS);
    if(options.IgnoreVersion) {
      log(LOG_WARNING, "IgnoreVersion is set. If it breaks, we told you so.");
    } else {
      log(LOG_ERR,"Set IgnoreVersion config variable if you want to proceed.");
      fflush(0);
      exit(0);
    }
  }

  return 0;
}

int router_get_dir_from_string_impl(char *s, directory_t **dest,
                                    crypto_pk_env_t *pkey)
{
  directory_token_t tok;
  char digest[20];
  char signed_digest[128];
  directory_t *new_dir = NULL;
  char *versions;
  struct tm published;
  time_t published_on;
  const char *good_nickname_lst[1024];
  int n_good_nicknames;
  
#define NEXT_TOK()                                                      \
  do {                                                                  \
    if (router_get_next_token(&s, &tok)) {                              \
      log_fn(LOG_WARNING, "Error reading directory: %s", tok.val.error);\
      return -1;                                                        \
    } } while (0)
#define TOK_IS(type,name)                                               \
  do {                                                                  \
    if (tok.tp != type) {                                               \
      router_release_token(&tok);                                       \
      log_fn(LOG_WARNING, "Error reading directory: expected %s", name);\
      return -1;                                                        \
    } } while(0)

  if (router_get_dir_hash(s, digest)) {
    log_fn(LOG_WARNING, "Unable to compute digest of directory");
    goto err;
  }
  log(LOG_DEBUG,"Received directory hashes to %02x:%02x:%02x:%02x",
      ((int)digest[0])&0xff,((int)digest[1])&0xff,
      ((int)digest[2])&0xff,((int)digest[3])&0xff);

  NEXT_TOK();
  TOK_IS(K_SIGNED_DIRECTORY, "signed-directory");

  NEXT_TOK();
  TOK_IS(K_PUBLISHED, "published");
  if (tok.val.cmd.n_args != 2) {
    log_fn(LOG_WARNING, "Invalid published line");
    goto err;
  }
  tok.val.cmd.args[1][-1] = ' ';
  if (!strptime(tok.val.cmd.args[0], "%Y-%m-%d %H:%M:%S", &published)) {
    log_fn(LOG_WARNING, "Published time was unparseable"); goto err;
  }
  published_on = timegm(&published);  

  NEXT_TOK();
  TOK_IS(K_RECOMMENDED_SOFTWARE, "recommended-software");
  if (tok.val.cmd.n_args != 1) {
    log_fn(LOG_WARNING, "Invalid recommended-software line");
    goto err;
  }
  versions = strdup(tok.val.cmd.args[0]);
  
  NEXT_TOK();
  TOK_IS(K_RUNNING_ROUTERS, "running-routers");
  n_good_nicknames = tok.val.cmd.n_args;
  memcpy(good_nickname_lst, tok.val.cmd.args, n_good_nicknames*sizeof(char *));

  if (router_get_list_from_string_impl(&s, &new_dir,
                                       n_good_nicknames, good_nickname_lst)) {
    log_fn(LOG_WARNING, "Error reading routers from directory");
    goto err;
  }
  new_dir->software_versions = versions;
  new_dir->published_on = published_on;

  NEXT_TOK();
  TOK_IS(K_DIRECTORY_SIGNATURE, "directory-signature");
  NEXT_TOK();
  TOK_IS(_SIGNATURE, "signature");
  if (pkey) {
    if (crypto_pk_public_checksig(pkey, tok.val.signature, 128, signed_digest)
        != 20) {
      log_fn(LOG_WARNING, "Error reading directory: invalid signature.");
      free(tok.val.signature);
      goto err;
    }
    log(LOG_DEBUG,"Signed directory hash starts %02x:%02x:%02x:%02x",
        ((int)signed_digest[0])&0xff,((int)signed_digest[1])&0xff,
        ((int)signed_digest[2])&0xff,((int)signed_digest[3])&0xff);
    if (memcmp(digest, signed_digest, 20)) {
      log_fn(LOG_WARNING, "Error reading directory: signature does not match.");
      free(tok.val.signature);
      goto err;
    }
  }
  free(tok.val.signature);

  NEXT_TOK();
  TOK_IS(_EOF, "end of directory");

  if (*dest) 
    directory_free(*dest);
  *dest = new_dir;

  return 0;

 err:
  if (new_dir)
    directory_free(new_dir);
  return -1;
#undef NEXT_TOK
#undef TOK_IS
}

int router_get_list_from_string_impl(char **s, directory_t **dest, 
                                     int n_good_nicknames, 
                                     const char **good_nickname_lst)
{
  routerinfo_t *router;
  routerinfo_t **rarray;
  int rarray_len = 0;
  int i;

  assert(s && *s);

  rarray = (routerinfo_t **)tor_malloc((sizeof(routerinfo_t *))*MAX_ROUTERS_IN_DIR);

  while (1) {
    *s = eat_whitespace(*s);
    if (strncmp(*s, "router ", 7)!=0)
      break;
    router = router_get_entry_from_string(s);
    if (!router) {
      log_fn(LOG_WARNING, "Error reading router");
      return -1;
    }
    if (rarray_len >= MAX_ROUTERS_IN_DIR) {
      log_fn(LOG_WARNING, "too many routers");
      routerinfo_free(router);
      continue;
    } 
    if (n_good_nicknames>=0) {
      router->is_running = 0;
      for (i = 0; i < n_good_nicknames; ++i) {
        if (0==strcasecmp(good_nickname_lst[i], router->nickname)) {
          router->is_running = 1;
          break;
        }
      }
    } else {
      router->is_running = 1; /* start out assuming all dirservers are up */
    }
    rarray[rarray_len++] = router;
    log_fn(LOG_DEBUG,"just added router #%d.",rarray_len);
  }
 
  if (*dest) 
    directory_free(*dest);
  *dest = (directory_t *)tor_malloc(sizeof(directory_t));
  (*dest)->routers = rarray;
  (*dest)->n_routers = rarray_len;
  (*dest)->software_versions = NULL;
  return 0;
}

static int 
router_resolve(routerinfo_t *router)
{
  struct hostent *rent;

  rent = (struct hostent *)gethostbyname(router->address);
  if (!rent) {
    log_fn(LOG_WARNING,"Could not get address for router %s.",router->address);
    return -1; 
  }
  assert(rent->h_length == 4);
  memcpy(&router->addr, rent->h_addr,rent->h_length);
  router->addr = ntohl(router->addr); /* get it back into host order */

  return 0;
}

static int 
router_resolve_directory(directory_t *dir)
{
  int i, max, remove;
  if (!dir)
    dir = directory;

  max = dir->n_routers;
  for (i = 0; i < max; ++i) {
    remove = 0;
    if (router_resolve(dir->routers[i])) {
      log_fn(LOG_WARNING, "Couldn't resolve router %s; removing",
             dir->routers[i]->address);
      remove = 1;
      routerinfo_free(dir->routers[i]);
    } else if (router_is_me(dir->routers[i]->addr, dir->routers[i]->or_port)) {
      my_routerinfo = dir->routers[i];
      remove = 1;
    }
    if (remove) {
      dir->routers[i] = dir->routers[--max];
      --dir->n_routers;
      --i;
    }
  }
  
  return 0;
}

/* reads a single router entry from s.
 * updates s so it points to after the router it just read.
 * mallocs a new router, returns it if all goes well, else returns NULL.
 */
routerinfo_t *router_get_entry_from_string(char**s) {
  routerinfo_t *router = NULL;
  char signed_digest[128];
  char digest[128];
  directory_token_t _tok;
  directory_token_t *tok = &_tok;
  struct tm published;

#define NEXT_TOKEN()                                                     \
  do { if (router_get_next_token(s, tok)) {                              \
      log_fn(LOG_WARNING, "Error reading directory: %s", tok->val.error);\
      goto err;                                                          \
    } } while(0)

#define ARGS tok->val.cmd.args

  if (router_get_router_hash(*s, digest) < 0)
    return NULL;

  NEXT_TOKEN();

  if (tok->tp != K_ROUTER) {
    router_release_token(tok);
    log_fn(LOG_WARNING,"Entry does not start with \"router\"");
    return NULL;
  }

  router = tor_malloc(sizeof(routerinfo_t));
  memset(router,0,sizeof(routerinfo_t)); /* zero it out first */
  /* C doesn't guarantee that NULL is represented by 0 bytes.  You'll
     thank me for this someday. */
  router->onion_pkey = router->identity_pkey = router->link_pkey = NULL; 

  if (tok->val.cmd.n_args != 6) {
    log_fn(LOG_WARNING,"Wrong # of arguments to \"router\"");
    goto err;
  }
  if (!(router->nickname = strdup(ARGS[0])))
    goto err;
  if (strlen(router->nickname) > MAX_NICKNAME_LEN)
    goto err;
  if (strspn(router->nickname, LEGAL_NICKNAME_CHARACTERS) != 
      strlen(router->nickname))
    goto err;
  
  /* read router.address */
  if (!(router->address = strdup(ARGS[1])))
    goto err;
  router->addr = 0;

  /* Read router->or_port */
  router->or_port = atoi(ARGS[2]);
  if(!router->or_port) {
    log_fn(LOG_WARNING,"or_port unreadable or 0. Failing.");
    goto err;
  }
  
  /* Router->ap_port */
  router->ap_port = atoi(ARGS[3]);
  
  /* Router->dir_port */
  router->dir_port = atoi(ARGS[4]);

  /* Router->bandwidth */
  router->bandwidth = atoi(ARGS[5]);
  if (!router->bandwidth) {
    log_fn(LOG_WARNING,"bandwidth unreadable or 0. Failing.");
  }
  
  log_fn(LOG_DEBUG,"or_port %d, ap_port %d, dir_port %d, bandwidth %d.",
    router->or_port, router->ap_port, router->dir_port, router->bandwidth);

  /* XXX Later, require platform before published. */
  NEXT_TOKEN();
  if (tok->tp == K_PLATFORM) {
    NEXT_TOKEN();
  }
  
  if (tok->tp != K_PUBLISHED) {
    log_fn(LOG_WARNING, "Missing published time"); goto err;
  }
  if (tok->val.cmd.n_args != 2) {
    log_fn(LOG_WARNING, "Wrong number of arguments to published"); goto err;
  }
  ARGS[1][-1] = ' '; /* Re-insert space. */
  if (!strptime(ARGS[0], "%Y-%m-%d %H:%M:%S", &published)) {
    log_fn(LOG_WARNING, "Published time was unparseable"); goto err;
  }
  router->published_on = timegm(&published);

  NEXT_TOKEN();
  if (tok->tp != K_ONION_KEY) {
    log_fn(LOG_WARNING, "Missing onion-key"); goto err;
  }
  NEXT_TOKEN();
  if (tok->tp != _PUBLIC_KEY) {
    log_fn(LOG_WARNING, "Missing onion key"); goto err;
  } /* XXX Check key length */
  router->onion_pkey = tok->val.public_key;

  NEXT_TOKEN();
  if (tok->tp != K_LINK_KEY) {
    log_fn(LOG_WARNING, "Missing link-key");  goto err;
  }
  NEXT_TOKEN();
  if (tok->tp != _PUBLIC_KEY) {
    log_fn(LOG_WARNING, "Missing link key"); goto err;
  } /* XXX Check key length */
  router->link_pkey = tok->val.public_key;

  NEXT_TOKEN();
  if (tok->tp != K_SIGNING_KEY) {
    log_fn(LOG_WARNING, "Missing signing-key"); goto err;
  }
  NEXT_TOKEN();
  if (tok->tp != _PUBLIC_KEY) {
    log_fn(LOG_WARNING, "Missing signing key"); goto err;
  }
  router->identity_pkey = tok->val.public_key;

  NEXT_TOKEN();
  while (tok->tp == K_ACCEPT || tok->tp == K_REJECT) {
    router_add_exit_policy(router, tok);
    NEXT_TOKEN();
  }
  
  if (tok->tp != K_ROUTER_SIGNATURE) {
    log_fn(LOG_WARNING,"Missing router signature");
    goto err;
  }
  NEXT_TOKEN();
  if (tok->tp != _SIGNATURE) {
    log_fn(LOG_WARNING,"Missing router signature");
    goto err;
  }
  assert (router->identity_pkey);

  if (crypto_pk_public_checksig(router->identity_pkey, tok->val.signature,
                                128, signed_digest) != 20) {
    log_fn(LOG_WARNING, "Invalid signature");
    goto err;
  }
  if (memcmp(digest, signed_digest, 20)) {
    log_fn(LOG_WARNING, "Mismatched signature");
    goto err;
  }
  
  return router;

 err:
  router_release_token(tok); 
  if(router->address)
    free(router->address);
  if(router->link_pkey)
    crypto_free_pk_env(router->link_pkey);
  if(router->onion_pkey)
    crypto_free_pk_env(router->onion_pkey);
  if(router->identity_pkey)
    crypto_free_pk_env(router->identity_pkey);
  router_free_exit_policy(router);
  free(router);
  return NULL;
#undef ARGS
#undef NEXT_TOKEN
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

static int router_add_exit_policy(routerinfo_t *router, 
                                  directory_token_t *tok) {
  struct exit_policy_t *tmpe, *newe;
  char *arg, *colon;

  if (tok->val.cmd.n_args != 1)
    return -1;
  arg = tok->val.cmd.args[0];

  newe = tor_malloc(sizeof(struct exit_policy_t));
  memset(newe,0,sizeof(struct exit_policy_t));
  
  newe->string = tor_malloc(8+strlen(arg));
  if (tok->tp == K_REJECT) {
    strcpy(newe->string, "reject ");
    newe->policy_type = EXIT_POLICY_REJECT;
  } else {
    assert(tok->tp == K_ACCEPT);
    strcpy(newe->string, "accept ");
    newe->policy_type = EXIT_POLICY_ACCEPT;
  }
  strcat(newe->string, arg);
  
  colon = strchr(arg,':');
  if(!colon)
    goto policy_read_failed;
  *colon = 0;
  newe->address = strdup(arg);
  newe->port = strdup(colon+1);

  log_fn(LOG_DEBUG,"%s %s:%s",
      newe->policy_type == EXIT_POLICY_REJECT ? "reject" : "accept",
      newe->address, newe->port);

  /* now link newe onto the end of exit_policy */

  if(!router->exit_policy) {
    router->exit_policy = newe;
    return 0;
  }

  for(tmpe=router->exit_policy; tmpe->next; tmpe=tmpe->next) ;
  tmpe->next = newe;

  return 0;

policy_read_failed:
  assert(newe->string);
  log_fn(LOG_WARNING,"Couldn't parse line '%s'. Dropping", newe->string);
  if(newe->string)
    free(newe->string);
  if(newe->address)
    free(newe->address);
  if(newe->port)
    free(newe->port);
  free(newe);
  return -1;
}

/* Return 0 if my exit policy says to allow connection to conn.
 * Else return -1.
 */
int router_compare_to_exit_policy(connection_t *conn) {
  struct exit_policy_t *tmpe;

  if(!my_routerinfo) {
    log_fn(LOG_WARNING, "my_routerinfo undefined! Rejected.");
    return -1;
  }

  for(tmpe=my_routerinfo->exit_policy; tmpe; tmpe=tmpe->next) {
    assert(tmpe->address);
    assert(tmpe->port);

    /* Totally ignore the address field of the exit policy, for now. */

    if(!strcmp(tmpe->port,"*") || atoi(tmpe->port) == conn->port) {
      log_fn(LOG_INFO,"Port '%s' matches '%d'. %s.",
          tmpe->port, conn->port,
          tmpe->policy_type == EXIT_POLICY_ACCEPT ? "Accepting" : "Rejecting");
      if(tmpe->policy_type == EXIT_POLICY_ACCEPT)
        return 0;
      else
        return -1;
    }
  }

  return 0; /* accept all by default. */
}


static char descriptor[8192];
/* XXX should this replace my_routerinfo? */
static routerinfo_t *desc_routerinfo = NULL; 
const char *router_get_my_descriptor(void) {
  if (!desc_routerinfo) {
    if (init_descriptor())
      return NULL;
  }
  log_fn(LOG_DEBUG,"my desc is '%s'",descriptor);
  return descriptor;
}
const routerinfo_t *router_get_desc_routerinfo(void) {
  if (!desc_routerinfo) {
    if (init_descriptor()) 
      return NULL;
  }
  return desc_routerinfo;
}

static int init_descriptor(void) {
  routerinfo_t *ri;
  char localhostname[256];
  char *address = options.Address;

  if(!address) { /* if not specified in config, we find a default */
    if(gethostname(localhostname,sizeof(localhostname)) < 0) {
      log_fn(LOG_WARNING,"Error obtaining local hostname");
      return -1;
    }
    address = localhostname;
  }
  ri = tor_malloc(sizeof(routerinfo_t));
  ri->address = strdup(address);
  ri->nickname = strdup(options.Nickname);
  /* No need to set addr. */
  ri->or_port = options.ORPort;
  ri->ap_port = options.APPort;
  ri->dir_port = options.DirPort;
  ri->published_on = time(NULL);
  ri->onion_pkey = crypto_pk_dup_key(get_onion_key());
  ri->link_pkey = crypto_pk_dup_key(get_link_key());
  ri->identity_pkey = crypto_pk_dup_key(get_identity_key());
  ri->bandwidth = options.TotalBandwidth;
  ri->exit_policy = NULL; /* XXX implement this. */
  if (desc_routerinfo)
    routerinfo_free(desc_routerinfo);
  desc_routerinfo = ri;
  if (router_dump_router_to_string(descriptor, 8192, ri, get_identity_key())<0) {
    log_fn(LOG_WARNING, "Couldn't dump router to string.");
    return -1;
  }
  return 0;
}

static void get_platform_str(char *platform, int len)
{
#ifdef HAVE_UNAME
  struct utsname u;
  if (!uname(&u)) {
    snprintf(platform, len-1, "Tor %s on %s %s %s %s %s",
             VERSION, u.sysname, u.nodename, u.release, u.version, u.machine);
    platform[len-1] = '\0';
    return;
  } else
#endif
    {
      snprintf(platform, len-1, "Tor %s", VERSION);
    }
}

int router_dump_router_to_string(char *s, int maxlen, routerinfo_t *router,
                                 crypto_pk_env_t *ident_key) {
  char *onion_pkey;
  char *link_pkey;
  char *identity_pkey;
  char platform[256];
  char digest[20];
  char signature[128];
  char published[32];
  int onion_pkeylen, link_pkeylen, identity_pkeylen;
  int written;
  int result=0;
  struct exit_policy_t *tmpe;
  
  get_platform_str(platform, sizeof(platform));

  if(crypto_pk_write_public_key_to_string(router->onion_pkey,
                                          &onion_pkey,&onion_pkeylen)<0) {
    log_fn(LOG_WARNING,"write onion_pkey to string failed!");
    return -1;
  }

  if(crypto_pk_write_public_key_to_string(router->identity_pkey,
                                          &identity_pkey,&identity_pkeylen)<0) {
    log_fn(LOG_WARNING,"write identity_pkey to string failed!");
    return -1;
  }

  if(crypto_pk_write_public_key_to_string(router->link_pkey,
                                          &link_pkey,&link_pkeylen)<0) {
    log_fn(LOG_WARNING,"write link_pkey to string failed!");
    return -1;
  }
  strftime(published, 32, "%Y-%m-%d %H:%M:%S", gmtime(&router->published_on));
  
  result = snprintf(s, maxlen, 
                    "router %s %s %d %d %d %d\n"
                    "platform %s\n"
                    "published %s\n"
                    "onion-key\n%s"
                    "link-key\n%s"
                    "signing-key\n%s",
    router->nickname,             
    router->address,
    router->or_port,
    router->ap_port,
    router->dir_port,
    router->bandwidth,
    platform,
    published,
    onion_pkey, link_pkey, identity_pkey);

  free(onion_pkey);
  free(link_pkey);
  free(identity_pkey);

  if(result < 0 || result >= maxlen) {
    /* apparently different glibcs do different things on snprintf error.. so check both */
    return -1;
  }
  written = result;

  for(tmpe=router->exit_policy; tmpe; tmpe=tmpe->next) {
    result = snprintf(s+written, maxlen-written, "%s %s:%s\n", 
      tmpe->policy_type == EXIT_POLICY_ACCEPT ? "accept" : "reject",
      tmpe->address, tmpe->port);
    if(result < 0 || result+written > maxlen) {
      /* apparently different glibcs do different things on snprintf error.. so check both */
      return -1;
    }
    written += result;
  }
  if (written > maxlen-256) /* Not enough room for signature. */
    return -1;

  strcat(s+written, "router-signature\n");
  written += strlen(s+written);
  s[written] = '\0';
  if (router_get_router_hash(s, digest) < 0)
    return -1;

  if (crypto_pk_private_sign(ident_key, digest, 20, signature) < 0) {
    log_fn(LOG_WARNING, "Error signing digest");
    return -1;
  }
  strcat(s+written, "-----BEGIN SIGNATURE-----\n");
  written += strlen(s+written);
  if (base64_encode(s+written, maxlen-written, signature, 128) < 0) {
    log_fn(LOG_WARNING, "Couldn't base64-encode signature");
    return -1;
  }
  written += strlen(s+written);
  strcat(s+written, "-----END SIGNATURE-----\n");
  written += strlen(s+written);
  
  if (written > maxlen-2) 
    return -1;
  /* include a last '\n' */
  s[written] = '\n';
  s[written+1] = 0;
  return written+1;
}



/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
