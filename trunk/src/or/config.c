/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

const char *basename(const char *filename) {
  char *result;
  /* XXX This won't work on windows. */
  result = strrchr(filename, '/');
  if (result)
    return result;
  else
    return filename;
}

/* open configuration file for reading */
FILE *config_open(const unsigned char *filename) {
  assert(filename);
  if (strspn(filename,CONFIG_LEGAL_FILENAME_CHARACTERS) != strlen(filename)) {
    /* filename has illegal letters */
    return NULL;
  }
  return fopen(filename, "r");
}

/* close configuration file */
int config_close(FILE *f) {
  assert(f);
  return fclose(f);
}

struct config_line *config_get_commandlines(int argc, char **argv) {
  struct config_line *new;
  struct config_line *front = NULL;
  char *s;
  int i = 1;

  while(i < argc-1) { 
    if(!strcmp(argv[i],"-f")) {
//      log(LOG_DEBUG,"Commandline: skipping over -f.");
      i+=2; /* this is the config file option. ignore it. */
      continue;
    }

    new = malloc(sizeof(struct config_line));
    s = argv[i];
    while(*s == '-')
      s++;
    new->key = strdup(s);
    new->value = strdup(argv[i+1]);

    log(LOG_DEBUG,"Commandline: parsed keyword '%s', value '%s'",
      new->key, new->value);
    new->next = front;
    front = new;
    i += 2;
  }
  return front;
}

/* parse the config file and strdup into key/value strings. Return list.
 * Warn and ignore mangled lines. */
struct config_line *config_get_lines(FILE *f) {
  struct config_line *new;
  struct config_line *front = NULL;
  char line[CONFIG_LINE_MAXLEN];
  int lineno=0; /* current line number */
  char *s;
  char *start, *end;

  assert(f);

  fseek(f,0,SEEK_SET); /* make sure we start at the beginning of file */

  while(fgets(line, CONFIG_LINE_MAXLEN, f)) {
    lineno++;

    /* first strip comments */
    s = strchr(line,'#');
    if(s) {
      *s = 0; /* stop the line there */
    }

    /* walk to the end, remove end whitespace */
    s = index(line, 0); /* now we're at the null */
    do {
      *s = 0;
      s--;
    } while (isspace(*s));

    start = line;
    while(isspace(*start))
      start++;
    if(*start == 0)
      continue; /* this line has nothing on it */

    end = start;
    while(*end && !isspace(*end))
      end++;
    s = end;
    while(*s && isspace(*s))
      s++;
    if(!*end || !*s) { /* only a keyword on this line. no value. */
      log(LOG_WARNING,"Config line %d has keyword '%s' but no value. Skipping.",lineno,s);
    }
    *end = 0; /* null it out */

    /* prepare to parse the string into key / value */
    new = malloc(sizeof(struct config_line));
    new->key = strdup(start);
    new->value = strdup(s);

    log(LOG_DEBUG,"Config line %d: parsed keyword '%s', value '%s'",
      lineno, new->key, new->value);
    new->next = front;
    front = new;
  }

  return front;
}

void config_free_lines(struct config_line *front) {
  struct config_line *tmp;

  while(front) {
    tmp = front;
    front = tmp->next;

    free(tmp->key);
    free(tmp->value);
    free(tmp);
  }
}

int config_compare(struct config_line *c, char *key, int type, void *arg) {
  int i;

  if(strncasecmp(c->key,key,strlen(c->key)))
    return 0;

  /* it's a match. cast and assign. */
  log(LOG_DEBUG,"config_compare(): Recognized keyword '%s' as %s, using value '%s'.",c->key,key,c->value);

  switch(type) {
    case CONFIG_TYPE_INT:   
      *(int *)arg = atoi(c->value);
      break;
    case CONFIG_TYPE_BOOL:
      i = atoi(c->value);
      if (i != 0 && i != 1) {
        log(LOG_ERR, "Boolean keyword '%s' expects 0 or 1", c->key);
        return 0;
      }
      *(int *)arg = i;
      break;
    case CONFIG_TYPE_STRING:
      *(char **)arg = strdup(c->value);
      break;
    case CONFIG_TYPE_DOUBLE:
      *(double *)arg = atof(c->value);
      break;
  }
  return 1;
}

void config_assign(or_options_t *options, struct config_line *list) {

  /* iterate through list. for each item convert as appropriate and assign to 'options'. */

  while(list) {
    if(

    /* order matters here! abbreviated arguments use the first match. */

    /* string options */
    config_compare(list, "LogLevel",       CONFIG_TYPE_STRING, &options->LogLevel) ||
    config_compare(list, "PrivateKeyFile", CONFIG_TYPE_STRING, &options->PrivateKeyFile) ||
    config_compare(list, "RouterFile",     CONFIG_TYPE_STRING, &options->RouterFile) ||

    /* int options */
    config_compare(list, "MaxConn",         CONFIG_TYPE_INT, &options->MaxConn) ||
    config_compare(list, "APPort",          CONFIG_TYPE_INT, &options->APPort) ||
    config_compare(list, "OPPort",          CONFIG_TYPE_INT, &options->OPPort) ||
    config_compare(list, "ORPort",          CONFIG_TYPE_INT, &options->ORPort) ||
    config_compare(list, "DirPort",         CONFIG_TYPE_INT, &options->DirPort) ||
    config_compare(list, "DirFetchPeriod",  CONFIG_TYPE_INT, &options->DirFetchPeriod) ||
    config_compare(list, "KeepalivePeriod", CONFIG_TYPE_INT, &options->KeepalivePeriod) ||
    config_compare(list, "MaxOnionsPending",CONFIG_TYPE_INT, &options->MaxOnionsPending) ||

    config_compare(list, "Daemon",          CONFIG_TYPE_BOOL, &options->Daemon) ||
    config_compare(list, "TrafficShaping",  CONFIG_TYPE_BOOL, &options->TrafficShaping) ||
    config_compare(list, "LinkPadding",     CONFIG_TYPE_BOOL, &options->LinkPadding) ||

    /* float options */
    config_compare(list, "CoinWeight",     CONFIG_TYPE_DOUBLE, &options->CoinWeight)

    ) {
      /* then we're ok. it matched something. */
    } else {
      log(LOG_WARNING,"config_assign(): Ignoring unknown keyword '%s'.",list->key);
    }

    list = list->next;
  }  
}

/* return 0 if success, <0 if failure. */
int getconfig(int argc, char **argv, or_options_t *options) {
  struct config_line *cl;
  FILE *cf;
  char fname[256];
  int i;
  const char *cmd;
  int result = 0;

/* give reasonable defaults for each option */
  memset(options,0,sizeof(or_options_t));
  options->Daemon = 0;
  options->LogLevel = "debug";
  options->loglevel = LOG_DEBUG;
  options->CoinWeight = 0.8;
  options->LinkPadding = 0;
  options->DirFetchPeriod = 600;
  options->KeepalivePeriod = 300;
  options->MaxOnionsPending = 10;
//  options->ReconnectPeriod = 6001;

/* get config lines from /etc/torrc and assign them */
  cmd = basename(argv[0]);
  snprintf(fname,256,"/etc/%src",cmd);

  cf = config_open(fname);
  if(cf) {
    /* we got it open. pull out the config lines. */
    cl = config_get_lines(cf);
    config_assign(options,cl);
    config_free_lines(cl);
    config_close(cf);
  }
  /* if we failed to open it, ignore */

/* learn config file name, get config lines, assign them */
  i = 1;
  while(i < argc-1 && strcmp(argv[i],"-f")) {
//    log(LOG_DEBUG,"examining arg %d (%s), it's not -f.",i,argv[i]);
    i++;
  }
  if(i < argc-1) { /* we found one */
    log(LOG_DEBUG,"Opening specified config file '%s'",argv[i+1]);
    cf = config_open(argv[i+1]);
    if(!cf) { /* it's defined but not there. that's no good. */
      log(LOG_ERR, "Unable to open configuration file '%s'.",argv[i+1]);
      return -1;
    }
    cl = config_get_lines(cf);
    config_assign(options,cl);
    config_free_lines(cl);
    config_close(cf);
  }
 
/* go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  config_assign(options,cl);
  config_free_lines(cl);

/* print config */
  if (options->loglevel == LOG_DEBUG) {
    printf("LogLevel=%s\n",
           options->LogLevel);
    printf("RouterFile=%s, PrivateKeyFile=%s\n",
           options->RouterFile ? options->RouterFile : "(undefined)",
           options->PrivateKeyFile ? options->PrivateKeyFile : "(undefined)");
    printf("ORPort=%d, OPPort=%d, APPort=%d DirPort=%d\n",
           options->ORPort,options->OPPort,
           options->APPort,options->DirPort);
    printf("CoinWeight=%6.4f, MaxConn=%d, TrafficShaping=%d, LinkPadding=%d\n",
           options->CoinWeight,
           options->MaxConn,
           options->TrafficShaping,
           options->LinkPadding);
    printf("DirFetchPeriod=%d KeepalivePeriod=%d\n",
           options->DirFetchPeriod,
           options->KeepalivePeriod);
    printf("Daemon=%d\n", options->Daemon);
  }

/* Validate options */

  if(options->LogLevel) {
    if(!strcmp(options->LogLevel,"emerg"))
      options->loglevel = LOG_EMERG;
    else if(!strcmp(options->LogLevel,"alert"))
      options->loglevel = LOG_ALERT;
    else if(!strcmp(options->LogLevel,"crit"))
      options->loglevel = LOG_CRIT;
    else if(!strcmp(options->LogLevel,"err"))
      options->loglevel = LOG_ERR;
    else if(!strcmp(options->LogLevel,"warning"))
      options->loglevel = LOG_WARNING;
    else if(!strcmp(options->LogLevel,"notice"))
      options->loglevel = LOG_NOTICE;
    else if(!strcmp(options->LogLevel,"info"))
      options->loglevel = LOG_INFO;
    else if(!strcmp(options->LogLevel,"debug"))
      options->loglevel = LOG_DEBUG;
    else {
      log(LOG_ERR,"LogLevel must be one of emerg|alert|crit|err|warning|notice|info|debug.");
      result = -1;
    }
  }

  if(options->RouterFile == NULL) {
    log(LOG_ERR,"RouterFile option required, but not found.");
    result = -1;
  }

  if(options->ORPort < 0) {
    log(LOG_ERR,"ORPort option required and must be a positive integer value.");
    result = -1;
  }

  if(options->ORPort > 0 && options->PrivateKeyFile == NULL) {
    log(LOG_ERR,"PrivateKeyFile option required for OR, but not found.");
    result = -1;
  }

  if(options->OPPort < 0) {
    log(LOG_ERR,"OPPort option can't be negative.");
    result = -1;
  }

  if(options->APPort < 0) {
    log(LOG_ERR,"APPort option can't be negative.");
    result = -1;
  }

  if(options->DirPort < 0) {
    log(LOG_ERR,"DirPort option can't be negative.");
    result = -1;
  }

  if(options->APPort > 1 &&
     (options->CoinWeight < 0.0 || options->CoinWeight >= 1.0)) {
    log(LOG_ERR,"CoinWeight option must be >=0.0 and <1.0.");
    result = -1;
  }

  if(options->MaxConn < 1) {
    log(LOG_ERR,"MaxConn option must be a non-zero positive integer.");
    result = -1;
  }

  if(options->MaxConn >= MAXCONNECTIONS) {
    log(LOG_ERR,"MaxConn option must be less than %d.", MAXCONNECTIONS);
    result = -1;
  }

  if(options->DirFetchPeriod < 1) {
    log(LOG_ERR,"DirFetchPeriod option must be positive.");
    result = -1;
  }

  if(options->KeepalivePeriod < 1) {
    log(LOG_ERR,"KeepalivePeriod option must be positive.");
    result = -1;
  }

  return result;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
