/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
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

#define CONFIG_LINE_MAXLEN 4096

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
    new->key = tor_strdup(s);
    new->value = tor_strdup(argv[i+1]);

    log(LOG_DEBUG,"Commandline: parsed keyword '%s', value '%s'",
      new->key, new->value);
    new->next = front;
    front = new;
    i += 2;
  }
  return front;
}

/* parse the config file and strdup into key/value strings. Return list,
 * or NULL if parsing the file failed.
 * Warn and ignore mangled lines. */
static struct config_line *config_get_lines(FILE *f) {
  struct config_line *new;
  struct config_line *front = NULL;
  char line[CONFIG_LINE_MAXLEN];
  int result;
  char *key, *value;

  while( (result=parse_line_from_file(line,sizeof(line),f,&key,&value)) > 0) {
    new = tor_malloc(sizeof(struct config_line));
    new->key = tor_strdup(key);
    new->value = tor_strdup(value);

    new->next = front;
    front = new;
  }
  if(result < 0)
    return NULL;
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
        log(LOG_WARN, "Boolean keyword '%s' expects 0 or 1", c->key);
        return 0;
      }
      *(int *)arg = i;
      break;
    case CONFIG_TYPE_STRING:
      tor_free(*(char **)arg);
      *(char **)arg = tor_strdup(c->value);
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
    config_compare(list, "Address",        CONFIG_TYPE_STRING, &options->Address) ||

    config_compare(list, "DebugLogFile",   CONFIG_TYPE_STRING, &options->DebugLogFile) ||
    config_compare(list, "DataDirectory",  CONFIG_TYPE_STRING, &options->DataDirectory) ||
    config_compare(list, "DirPort",        CONFIG_TYPE_INT, &options->DirPort) ||
    config_compare(list, "DirBindAddress", CONFIG_TYPE_STRING, &options->DirBindAddress) ||
    config_compare(list, "DirFetchPostPeriod",CONFIG_TYPE_INT, &options->DirFetchPostPeriod) ||

    config_compare(list, "ExitNodes",      CONFIG_TYPE_STRING, &options->ExitNodes) ||
    config_compare(list, "EntryNodes",     CONFIG_TYPE_STRING, &options->EntryNodes) ||
    config_compare(list, "ExitPolicy",     CONFIG_TYPE_STRING, &options->ExitPolicy) ||

    config_compare(list, "Group",          CONFIG_TYPE_STRING, &options->Group) ||

    config_compare(list, "IgnoreVersion",  CONFIG_TYPE_BOOL, &options->IgnoreVersion) ||

    config_compare(list, "KeepalivePeriod",CONFIG_TYPE_INT, &options->KeepalivePeriod) ||

    config_compare(list, "LogLevel",       CONFIG_TYPE_STRING, &options->LogLevel) ||
    config_compare(list, "LogFile",        CONFIG_TYPE_STRING, &options->LogFile) ||
    config_compare(list, "LinkPadding",    CONFIG_TYPE_BOOL, &options->LinkPadding) ||

    config_compare(list, "MaxConn",        CONFIG_TYPE_INT, &options->MaxConn) ||
    config_compare(list, "MaxOnionsPending",CONFIG_TYPE_INT, &options->MaxOnionsPending) ||

    config_compare(list, "Nickname",       CONFIG_TYPE_STRING, &options->Nickname) ||
    config_compare(list, "NewCircuitPeriod",CONFIG_TYPE_INT, &options->NewCircuitPeriod) ||
    config_compare(list, "NumCpus",        CONFIG_TYPE_INT, &options->NumCpus) ||

    config_compare(list, "ORPort",         CONFIG_TYPE_INT, &options->ORPort) ||
    config_compare(list, "ORBindAddress",  CONFIG_TYPE_STRING, &options->ORBindAddress) ||

    config_compare(list, "PidFile",        CONFIG_TYPE_STRING, &options->PidFile) ||
    config_compare(list, "PathlenCoinWeight",CONFIG_TYPE_DOUBLE, &options->PathlenCoinWeight) ||

    config_compare(list, "RouterFile",     CONFIG_TYPE_STRING, &options->RouterFile) ||
    config_compare(list, "RunAsDaemon",    CONFIG_TYPE_BOOL, &options->RunAsDaemon) ||
    config_compare(list, "RecommendedVersions",CONFIG_TYPE_STRING, &options->RecommendedVersions) ||

    config_compare(list, "SocksPort",      CONFIG_TYPE_INT, &options->SocksPort) ||
    config_compare(list, "SocksBindAddress",CONFIG_TYPE_STRING,&options->SocksBindAddress) ||

    config_compare(list, "TotalBandwidth", CONFIG_TYPE_INT, &options->TotalBandwidth) ||
    config_compare(list, "TrafficShaping", CONFIG_TYPE_BOOL, &options->TrafficShaping) ||

    config_compare(list, "User",           CONFIG_TYPE_STRING, &options->User)
    ) {
      /* then we're ok. it matched something. */
    } else {
      log_fn(LOG_WARN,"Ignoring unknown keyword '%s'.",list->key);
    }

    list = list->next;
  }  
}

/* prints the usage of tor. */
void print_usage(void) {
  printf("tor -f <torrc> [args]\n"
         "-d <file>\t\tDebug file\n"
         "-m <max>\t\tMax number of connections\n"
         "-l <level>\t\tLog level\n"
         "-t <bandwidth>\t\tTotal bandwidth\n"
         "-r <file>\t\tList of known routers\n");
  printf("\nClient options:\n"
         "-e \"nick1 nick2 ...\"\t\tExit nodes\n"
         "-s <IP>\t\t\tPort to bind to for Socks\n"
         );
  printf("\nServer options:\n"
         "-n <nick>\t\tNickname of router\n"
         "-o <port>\t\tOR port to bind to\n"
         "-p <file>\t\tPID file\n"
         );
}

void free_options(or_options_t *options) {
  tor_free(options->LogLevel);
  tor_free(options->LogFile);
  tor_free(options->DebugLogFile);
  tor_free(options->DataDirectory);
  tor_free(options->RouterFile);
  tor_free(options->Nickname);
  tor_free(options->Address);
  tor_free(options->PidFile);
  tor_free(options->ExitNodes);
  tor_free(options->EntryNodes);
  tor_free(options->ExitPolicy);
  tor_free(options->SocksBindAddress);
  tor_free(options->ORBindAddress);
  tor_free(options->DirBindAddress);
  tor_free(options->RecommendedVersions);
  tor_free(options->User);
  tor_free(options->Group);
}

void init_options(or_options_t *options) {
/* give reasonable values for each option. Defaults to zero. */
  memset(options,0,sizeof(or_options_t));
  options->LogLevel = tor_strdup("warn");
  options->ExitNodes = tor_strdup("");
  options->EntryNodes = tor_strdup("");
  options->ExitPolicy = tor_strdup("reject 127.0.0.1:*");
  options->SocksBindAddress = tor_strdup("127.0.0.1");
  options->ORBindAddress = tor_strdup("0.0.0.0");
  options->DirBindAddress = tor_strdup("0.0.0.0");
  options->RecommendedVersions = tor_strdup("none");
  options->loglevel = LOG_INFO;
  options->PidFile = NULL; // tor_strdup("tor.pid");
  options->DataDirectory = NULL;
  options->PathlenCoinWeight = 0.3;
  options->MaxConn = 900;
  options->DirFetchPostPeriod = 600;
  options->KeepalivePeriod = 300;
  options->MaxOnionsPending = 100;
  options->NewCircuitPeriod = 60; /* once a minute */
  options->TotalBandwidth = 800000; /* at most 800kB/s total sustained incoming */
  options->NumCpus = 1;
}

/* return 0 if success, <0 if failure. */
int getconfig(int argc, char **argv, or_options_t *options) {
  struct config_line *cl;
  FILE *cf;
  char *fname;
  int i;
  int result = 0;
  static int first_load = 1;
  static char **backup_argv;
  static int backup_argc;
  char *previous_pidfile = NULL;
  int previous_runasdaemon = 0;

  if(first_load) { /* first time we're called. save commandline args */
    backup_argv = argv;
    backup_argc = argc;
    first_load = 0;
  } else { /* we're reloading. need to clean up old ones first. */
    argv = backup_argv;
    argc = backup_argc;

    /* record some previous values, so we can fail if they change */
    previous_pidfile = tor_strdup(options->PidFile);
    previous_runasdaemon = options->RunAsDaemon;
    free_options(options);
  }
  init_options(options); 

  if(argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1],"--help"))) {
    print_usage();
    exit(0);
  }

/* learn config file name, get config lines, assign them */
  i = 1;
  while(i < argc-1 && strcmp(argv[i],"-f")) {
    i++;
  }
  if(i < argc-1) { /* we found one */
    fname = argv[i+1];
  } else { /* didn't find one, try CONFDIR */
    fname = CONFDIR "/torrc";
  }
  log(LOG_DEBUG,"Opening config file '%s'",fname);

  cf = config_open(fname);
  if(!cf) {
    log(LOG_WARN, "Unable to open configuration file '%s'.",fname);
    return -1;
  }

  cl = config_get_lines(cf);
  if(!cl) return -1;
  config_assign(options,cl);
  config_free_lines(cl);
  config_close(cf);
 
/* go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  config_assign(options,cl);
  config_free_lines(cl);

/* Validate options */

  /* first check if any of the previous options have changed but aren't allowed to */
  if(previous_pidfile && strcmp(previous_pidfile,options->PidFile)) {
    log_fn(LOG_WARN,"During reload, PidFile changed from %s to %s. Failing.",
           previous_pidfile, options->PidFile);
    return -1;
  }
  tor_free(previous_pidfile);

  if(previous_runasdaemon && !options->RunAsDaemon) {
    log_fn(LOG_WARN,"During reload, change from RunAsDaemon=1 to =0 not allowed. Failing.");
    return -1;
  }

  if(options->LogLevel) {
    if(!strcmp(options->LogLevel,"err"))
      options->loglevel = LOG_ERR;
    else if(!strcmp(options->LogLevel,"warn"))
      options->loglevel = LOG_WARN;
    else if(!strcmp(options->LogLevel,"info"))
      options->loglevel = LOG_INFO;
    else if(!strcmp(options->LogLevel,"debug"))
      options->loglevel = LOG_DEBUG;
    else {
      log(LOG_WARN,"LogLevel must be one of err|warn|info|debug.");
      result = -1;
    }
  }

  if(options->RouterFile == NULL) {
    log(LOG_WARN,"RouterFile option required, but not found.");
    result = -1;
  }

  if(options->ORPort < 0) {
    log(LOG_WARN,"ORPort option can't be negative.");
    result = -1;
  }

  if(options->ORPort && options->DataDirectory == NULL) {
    log(LOG_WARN,"DataDirectory option required if ORPort is set, but not found.");
    result = -1;
  }

  if(options->ORPort && options->Nickname == NULL) {
    log_fn(LOG_WARN,"Nickname required if ORPort is set, but not found.");
    result = -1;
  }

  if(options->SocksPort < 0) {
    log(LOG_WARN,"SocksPort option can't be negative.");
    result = -1;
  }

  if(options->SocksPort == 0 && options->ORPort == 0) {
    log(LOG_WARN,"SocksPort and ORPort are both undefined? Quitting.");
    result = -1;
  } 

  if(options->DirPort < 0) {
    log(LOG_WARN,"DirPort option can't be negative.");
    result = -1;
  }

  if(options->SocksPort > 1 &&
     (options->PathlenCoinWeight < 0.0 || options->PathlenCoinWeight >= 1.0)) {
    log(LOG_WARN,"PathlenCoinWeight option must be >=0.0 and <1.0.");
    result = -1;
  }

  if(options->MaxConn < 1) {
    log(LOG_WARN,"MaxConn option must be a non-zero positive integer.");
    result = -1;
  }

  if(options->MaxConn >= MAXCONNECTIONS) {
    log(LOG_WARN,"MaxConn option must be less than %d.", MAXCONNECTIONS);
    result = -1;
  }

  if(options->DirFetchPostPeriod < 1) {
    log(LOG_WARN,"DirFetchPostPeriod option must be positive.");
    result = -1;
  }

  if(options->KeepalivePeriod < 1) {
    log(LOG_WARN,"KeepalivePeriod option must be positive.");
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
