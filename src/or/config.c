/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/* enumeration of types which option values can take */
#define CONFIG_TYPE_STRING  0
#define CONFIG_TYPE_CHAR    1
#define CONFIG_TYPE_INT     2
#define CONFIG_TYPE_LONG    3
#define CONFIG_TYPE_DOUBLE  4
#define CONFIG_TYPE_BOOL    5

#define CONFIG_LINE_MAXLEN 1024

struct config_line {
  char *key;
  char *value;
  struct config_line *next;
};

static FILE *config_open(const unsigned char *filename);
static int config_close(FILE *f);
static struct config_line *config_get_commandlines(int argc, char **argv);
static struct config_line *config_get_lines(FILE *f);
static void config_free_lines(struct config_line *front);
static int config_compare(struct config_line *c, char *key, int type, void *arg);
static void config_assign(or_options_t *options, struct config_line *list);

/* open configuration file for reading */
static FILE *config_open(const unsigned char *filename) {
  assert(filename);
  if (strspn(filename,CONFIG_LEGAL_FILENAME_CHARACTERS) != strlen(filename)) {
    /* filename has illegal letters */
    return NULL;
  }
  return fopen(filename, "r");
}

/* close configuration file */
static int config_close(FILE *f) {
  assert(f);
  return fclose(f);
}

static struct config_line *config_get_commandlines(int argc, char **argv) {
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

    new = tor_malloc(sizeof(struct config_line));
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
static struct config_line *config_get_lines(FILE *f) {
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
    s = strchr(line, 0); /* now we're at the null */
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
    new = tor_malloc(sizeof(struct config_line));
    new->key = strdup(start);
    new->value = strdup(s);

    log(LOG_DEBUG,"Config line %d: parsed keyword '%s', value '%s'",
      lineno, new->key, new->value);
    new->next = front;
    front = new;
  }

  return front;
}

static void config_free_lines(struct config_line *front) {
  struct config_line *tmp;

  while(front) {
    tmp = front;
    front = tmp->next;

    free(tmp->key);
    free(tmp->value);
    free(tmp);
  }
}

static int config_compare(struct config_line *c, char *key, int type, void *arg) {
  int i;

  if(strncasecmp(c->key,key,strlen(c->key)))
    return 0;

  /* it's a match. cast and assign. */
  log_fn(LOG_DEBUG,"Recognized keyword '%s' as %s, using value '%s'.",c->key,key,c->value);

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

static void config_assign(or_options_t *options, struct config_line *list) {

  /* iterate through list. for each item convert as appropriate and assign to 'options'. */

  while(list) {
    if(

    /* order matters here! abbreviated arguments use the first match. */

    /* string options */
    config_compare(list, "LogLevel",       CONFIG_TYPE_STRING, &options->LogLevel) ||
    config_compare(list, "DataDirectory",  CONFIG_TYPE_STRING, &options->DataDirectory) ||
    config_compare(list, "RouterFile",     CONFIG_TYPE_STRING, &options->RouterFile) ||
    config_compare(list, "Nickname",       CONFIG_TYPE_STRING, &options->Nickname) ||

    /* int options */
    config_compare(list, "MaxConn",         CONFIG_TYPE_INT, &options->MaxConn) ||
    config_compare(list, "APPort",          CONFIG_TYPE_INT, &options->APPort) ||
    config_compare(list, "ORPort",          CONFIG_TYPE_INT, &options->ORPort) ||
    config_compare(list, "DirPort",         CONFIG_TYPE_INT, &options->DirPort) ||
    config_compare(list, "DirFetchPeriod",  CONFIG_TYPE_INT, &options->DirFetchPeriod) ||
    config_compare(list, "KeepalivePeriod", CONFIG_TYPE_INT, &options->KeepalivePeriod) ||
    config_compare(list, "MaxOnionsPending",CONFIG_TYPE_INT, &options->MaxOnionsPending) ||
    config_compare(list, "NewCircuitPeriod",CONFIG_TYPE_INT, &options->NewCircuitPeriod) ||
    config_compare(list, "TotalBandwidth",  CONFIG_TYPE_INT, &options->TotalBandwidth) ||
    config_compare(list, "NumCpus",         CONFIG_TYPE_INT, &options->NumCpus) ||

    config_compare(list, "OnionRouter",     CONFIG_TYPE_BOOL, &options->OnionRouter) ||
    config_compare(list, "Daemon",          CONFIG_TYPE_BOOL, &options->Daemon) ||
    config_compare(list, "TrafficShaping",  CONFIG_TYPE_BOOL, &options->TrafficShaping) ||
    config_compare(list, "LinkPadding",     CONFIG_TYPE_BOOL, &options->LinkPadding) ||
    config_compare(list, "IgnoreVersion",   CONFIG_TYPE_BOOL, &options->IgnoreVersion) ||

    /* float options */
    config_compare(list, "CoinWeight",     CONFIG_TYPE_DOUBLE, &options->CoinWeight)

    ) {
      /* then we're ok. it matched something. */
    } else {
      log_fn(LOG_WARNING,"Ignoring unknown keyword '%s'.",list->key);
    }

    list = list->next;
  }  
}

/* return 0 if success, <0 if failure. */
int getconfig(int argc, char **argv, or_options_t *options) {
  struct config_line *cl;
  FILE *cf;
  char *fname;
  int i;
  int result = 0;

/* give reasonable values for each option. Defaults to zero. */
  memset(options,0,sizeof(or_options_t));
  options->LogLevel = "debug";
  options->loglevel = LOG_DEBUG;
  options->DataDirectory = NULL;
  options->CoinWeight = 0.8;
  options->MaxConn = 900;
  options->DirFetchPeriod = 600;
  options->KeepalivePeriod = 300;
  options->MaxOnionsPending = 10;
  options->NewCircuitPeriod = 60; /* once a minute */
  options->TotalBandwidth = 800000; /* at most 800kB/s total sustained incoming */
  options->NumCpus = 1;

/* learn config file name, get config lines, assign them */
  i = 1;
  while(i < argc-1 && strcmp(argv[i],"-f")) {
    i++;
  }
  if(i < argc-1) { /* we found one */
    fname = argv[i+1];
  } else { /* didn't find one, try /etc/torrc */
    fname = "/etc/torrc";
  }
  log(LOG_DEBUG,"Opening config file '%s'",fname);

  cf = config_open(fname);
  if(!cf) { /* it's defined but not there. that's no good. */
    log(LOG_ERR, "Unable to open configuration file '%s'.",fname);
    return -1;
  }

  cl = config_get_lines(cf);
  config_assign(options,cl);
  config_free_lines(cl);
  config_close(cf);
 
/* go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  config_assign(options,cl);
  config_free_lines(cl);

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
    log(LOG_ERR,"ORPort option can't be negative.");
    result = -1;
  }

  if(options->OnionRouter && options->ORPort == 0) {
    log(LOG_ERR,"If OnionRouter is set, then ORPort must be positive.");
    result = -1;
  }

  if(options->OnionRouter && options->DataDirectory == NULL) {
    log(LOG_ERR,"DataDirectory option required for OnionRouter, but not found.");
    result = -1;
  }

  if(options->OnionRouter && options->Nickname == NULL) {
    log_fn(LOG_ERR,"Nickname required for OnionRouter, but not found.");
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
