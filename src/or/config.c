/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * /file config.c
 *
 * /brief Code to parse and interpret configuration files.
 *
 **/

#include "or.h"
#ifdef MS_WINDOWS
#include <shlobj.h>
#endif

/** Enumeration of types which option values can take */
typedef enum config_type_t {
  CONFIG_TYPE_STRING = 0, /**< An arbitrary string. */
  CONFIG_TYPE_UINT, /**< A non-negative integer less than MAX_INT */
  CONFIG_TYPE_DOUBLE, /**< A floating-point value */
  CONFIG_TYPE_BOOL, /**< A boolean value, expressed as 0 or 1. */
  CONFIG_TYPE_CSV, /**< A list of strings, separated by commas and optional
                    * whitespace. */
  CONFIG_TYPE_LINELIST, /**< Uninterpreted config lines */
  CONFIG_TYPE_OBSOLETE, /**< Obsolete (ignored) option. */
} config_type_t;

/** Largest allowed config line */
#define CONFIG_LINE_T_MAXLEN 4096

static struct config_line_t *config_get_commandlines(int argc, char **argv);
static int config_get_lines(FILE *f, struct config_line_t **result);
static void config_free_lines(struct config_line_t *front);
static int config_compare(struct config_line_t *c, const char *key, config_type_t type, void *arg);
static int config_assign(or_options_t *options, struct config_line_t *list);
static int parse_dir_server_line(const char *line);

/** Helper: Read a list of configuration options from the command line. */
static struct config_line_t *config_get_commandlines(int argc, char **argv) {
  struct config_line_t *new;
  struct config_line_t *front = NULL;
  char *s;
  int i = 1;

  while(i < argc-1) {
    if(!strcmp(argv[i],"-f")) {
//      log(LOG_DEBUG,"Commandline: skipping over -f.");
      i+=2; /* this is the config file option. ignore it. */
      continue;
    }

    new = tor_malloc(sizeof(struct config_line_t));
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

/** Helper: allocate a new configuration option mapping 'key' to 'val',
 * prepend it to 'front', and return the newly allocated config_line_t */
static struct config_line_t *
config_line_prepend(struct config_line_t *front,
                    const char *key,
                    const char *val)
{
  struct config_line_t *newline;
  newline = tor_malloc(sizeof(struct config_line_t));
  newline->key = tor_strdup(key);
  newline->value = tor_strdup(val);
  newline->next = front;
  return newline;
}

/** Helper: parse the config file and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the file
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines. */
static int config_get_lines(FILE *f,
                            struct config_line_t **result) {

  struct config_line_t *front = NULL;
  char line[CONFIG_LINE_T_MAXLEN];
  int r;
  char *key, *value;

  while( (r=parse_line_from_file(line,sizeof(line),f,&key,&value)) > 0) {
    front = config_line_prepend(front, key, value);
  }
  if(r < 0) {
    *result = NULL;
    return -1;
  } else {
    *result = front;
    return 0;
  }
}

/**
 * Free all the configuration lines on the linked list <b>front</b>.
 */
static void config_free_lines(struct config_line_t *front) {
  struct config_line_t *tmp;

  while(front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** Search the linked list <b>c</b> for any option whose key is <b>key</b>.
 * If such an option is found, interpret it as of type <b>type</b>, and store
 * the result in <b>arg</b>.  If the option is misformatted, log a warning and
 * skip it.
 */
static int config_compare(struct config_line_t *c, const char *key, config_type_t type, void *arg) {
  int i, ok;

  if(strncasecmp(c->key,key,strlen(c->key)))
    return 0;

  if(strcasecmp(c->key,key)) {
    tor_free(c->key);
    c->key = tor_strdup(key);
  }

  /* it's a match. cast and assign. */
  log_fn(LOG_DEBUG,"Recognized keyword '%s' as %s, using value '%s'.",c->key,key,c->value);

  switch(type) {
    case CONFIG_TYPE_UINT:
      i = tor_parse_long(c->value,10,0,INT_MAX,&ok,NULL);
      if(!ok) {
        log(LOG_WARN, "Int keyword '%s %s' is malformed or out of bounds. Skipping.",
            c->key,c->value);
        return 0;
      }
      *(int *)arg = i;
      break;
    case CONFIG_TYPE_BOOL:
      i = tor_parse_long(c->value,10,0,1,&ok,NULL);
      if (!ok) {
        log(LOG_WARN, "Boolean keyword '%s' expects 0 or 1. Skipping.", c->key);
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
    case CONFIG_TYPE_CSV:
      if(*(smartlist_t**)arg == NULL)
        *(smartlist_t**)arg = smartlist_create();
      smartlist_split_string(*(smartlist_t**)arg, c->value, ",",
                             SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
      break;
    case CONFIG_TYPE_LINELIST:
      /* Note: this reverses the order that the lines appear in.  That's
       * just fine, since we build up the list of lines reversed in the
       * first place. */
      *(struct config_line_t**)arg =
        config_line_prepend(*(struct config_line_t**)arg, c->key, c->value);
      break;
    case CONFIG_TYPE_OBSOLETE:
      log_fn(LOG_WARN, "Skipping obsolete configuration option '%s'", c->key);
      break;
  }
  return 1;
}

/** Iterate through the linked list of options <b>list</b>.
 * For each item, convert as appropriate and assign to <b>options</b>.
 * If an item is unrecognized, return -1 immediately,
 * else return 0 for success. */
static int config_assign(or_options_t *options, struct config_line_t *list) {

  while(list) {
    if(

    /* order matters here! abbreviated arguments use the first match. */

    /* string options */
    config_compare(list, "Address",        CONFIG_TYPE_STRING, &options->Address) ||
    config_compare(list, "AllowUnverifiedNodes", CONFIG_TYPE_CSV, &options->AllowUnverifiedNodes) ||
    config_compare(list, "AuthoritativeDirectory",CONFIG_TYPE_BOOL, &options->AuthoritativeDir) ||

    config_compare(list, "BandwidthRate",  CONFIG_TYPE_UINT, &options->BandwidthRate) ||
    config_compare(list, "BandwidthBurst", CONFIG_TYPE_UINT, &options->BandwidthBurst) ||

    config_compare(list, "ClientOnly",     CONFIG_TYPE_BOOL, &options->ClientOnly) ||
    config_compare(list, "ContactInfo",    CONFIG_TYPE_STRING, &options->ContactInfo) ||

    config_compare(list, "DebugLogFile",   CONFIG_TYPE_STRING, &options->DebugLogFile) ||
    config_compare(list, "DataDirectory",  CONFIG_TYPE_STRING, &options->DataDirectory) ||
    config_compare(list, "DirPort",        CONFIG_TYPE_UINT, &options->DirPort) ||
    config_compare(list, "DirBindAddress", CONFIG_TYPE_LINELIST, &options->DirBindAddress) ||
    config_compare(list, "DirFetchPostPeriod",CONFIG_TYPE_UINT, &options->DirFetchPostPeriod) ||
    config_compare(list, "DirServer",      CONFIG_TYPE_LINELIST, &options->DirServers) ||

    config_compare(list, "ExitNodes",      CONFIG_TYPE_STRING, &options->ExitNodes) ||
    config_compare(list, "EntryNodes",     CONFIG_TYPE_STRING, &options->EntryNodes) ||
    config_compare(list, "StrictExitNodes", CONFIG_TYPE_BOOL, &options->StrictExitNodes) ||
    config_compare(list, "StrictEntryNodes", CONFIG_TYPE_BOOL, &options->StrictEntryNodes) ||
    config_compare(list, "ExitPolicy",     CONFIG_TYPE_LINELIST, &options->ExitPolicy) ||
    config_compare(list, "ExcludeNodes",   CONFIG_TYPE_STRING, &options->ExcludeNodes) ||

    config_compare(list, "FascistFirewall",CONFIG_TYPE_BOOL, &options->FascistFirewall) ||
    config_compare(list, "FirewallPorts",CONFIG_TYPE_CSV, &options->FirewallPorts) ||

    config_compare(list, "Group",          CONFIG_TYPE_STRING, &options->Group) ||

    config_compare(list, "HttpProxy",      CONFIG_TYPE_STRING, &options->HttpProxy) ||
    config_compare(list, "HiddenServiceDir", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
    config_compare(list, "HiddenServicePort", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
    config_compare(list, "HiddenServiceNodes", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||
    config_compare(list, "HiddenServiceExcludeNodes", CONFIG_TYPE_LINELIST, &options->RendConfigLines)||

    config_compare(list, "IgnoreVersion",  CONFIG_TYPE_BOOL, &options->IgnoreVersion) ||

    config_compare(list, "KeepalivePeriod",CONFIG_TYPE_UINT, &options->KeepalivePeriod) ||

    config_compare(list, "LogLevel",       CONFIG_TYPE_LINELIST, &options->LogOptions) ||
    config_compare(list, "LogFile",        CONFIG_TYPE_LINELIST, &options->LogOptions) ||
    config_compare(list, "LinkPadding",    CONFIG_TYPE_OBSOLETE, NULL) ||

    config_compare(list, "MaxConn",        CONFIG_TYPE_UINT, &options->MaxConn) ||
    config_compare(list, "MaxOnionsPending",CONFIG_TYPE_UINT, &options->MaxOnionsPending) ||

    config_compare(list, "Nickname",       CONFIG_TYPE_STRING, &options->Nickname) ||
    config_compare(list, "NewCircuitPeriod",CONFIG_TYPE_UINT, &options->NewCircuitPeriod) ||
    config_compare(list, "NumCpus",        CONFIG_TYPE_UINT, &options->NumCpus) ||

    config_compare(list, "ORPort",         CONFIG_TYPE_UINT, &options->ORPort) ||
    config_compare(list, "ORBindAddress",  CONFIG_TYPE_LINELIST, &options->ORBindAddress) ||
    config_compare(list, "OutboundBindAddress",CONFIG_TYPE_STRING, &options->OutboundBindAddress) ||

    config_compare(list, "PidFile",        CONFIG_TYPE_STRING, &options->PidFile) ||
    config_compare(list, "PathlenCoinWeight",CONFIG_TYPE_DOUBLE, &options->PathlenCoinWeight) ||

    config_compare(list, "RouterFile",     CONFIG_TYPE_STRING, &options->RouterFile) ||
    config_compare(list, "RunAsDaemon",    CONFIG_TYPE_BOOL, &options->RunAsDaemon) ||
    config_compare(list, "RunTesting",     CONFIG_TYPE_BOOL, &options->RunTesting) ||
    config_compare(list, "RecommendedVersions",CONFIG_TYPE_STRING, &options->RecommendedVersions) ||
    config_compare(list, "RendNodes",      CONFIG_TYPE_STRING, &options->RendNodes) ||
    config_compare(list, "RendExcludeNodes",CONFIG_TYPE_STRING, &options->RendExcludeNodes) ||

    config_compare(list, "SocksPort",      CONFIG_TYPE_UINT, &options->SocksPort) ||
    config_compare(list, "SocksBindAddress",CONFIG_TYPE_LINELIST,&options->SocksBindAddress) ||
    config_compare(list, "SocksPolicy",     CONFIG_TYPE_LINELIST,&options->SocksPolicy) ||

    config_compare(list, "TrafficShaping", CONFIG_TYPE_OBSOLETE, NULL) ||

    config_compare(list, "User",           CONFIG_TYPE_STRING, &options->User)


    ) {
      /* then we're ok. it matched something. */
    } else {
      log_fn(LOG_WARN,"Unknown keyword '%s'. Failing.",list->key);
      return -1;
    }

    list = list->next;
  }
  return 0;
}

const char default_dirservers_string[] =
"router moria1 18.244.0.188 9001 9021 9031\n"
"platform Tor 0.0.6rc1 on Linux moria.mit.edu i686\n"
"published 2004-04-25 21:54:28\n"
"bandwidth 800000 10000000\n"
"onion-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBANoIvHieyHUTzIacbnWOnyTyzGrLOdXqbcjz2GGMxyHEd5K1bO1ZBNHP\n"
"9i5qLQpN5viFk2K2rEGuG8tFgDEzSWZEtBqv3NVfUdiumdERWMBwlaQ0MVK4C+jf\n"
"y5gZ8KI3o9ZictgPS1AQF+Kk932/vIHTuRIUKb4ILTnQilNvID0NAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"signing-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAMHa0ZC/jo2Q2DrwKYF/6ZbmZ27PFYG91u4gUzzmZ/VXLpZ8wNzEV3oW\n"
"nt+I61048fBiC1frT1/DZ351n2bLSk9zJbB6jyGZJn0380FPRX3+cXyXS0Gq8Ril\n"
"xkhMQf5XuNFUb8UmYPSOH4WErjvYjKvU+gfjbK/82Jo9SuHpYz+BAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"reject 0.0.0.0/255.0.0.0:*\n"
"reject 169.254.0.0/255.255.0.0:*\n"
"reject 127.0.0.0/255.0.0.0:*\n"
"reject 192.168.0.0/255.255.0.0:*\n"
"reject 10.0.0.0/255.0.0.0:*\n"
"reject 172.16.0.0/255.240.0.0:*\n"
"accept *:20-22\n"
"accept *:53\n"
"accept *:79-80\n"
"accept *:110\n"
"accept *:143\n"
"accept *:443\n"
"accept *:873\n"
"accept *:993\n"
"accept *:995\n"
"accept *:1024-65535\n"
"reject *:*\n"
"router-signature\n"
"-----BEGIN SIGNATURE-----\n"
"o1eAoRHDAEAXsnh5wN++vIwrupd+DbAJ2p3wxHDrmqxTpygzxxCnyQyhMfX03ua2\n"
"4iplyNlwyFwzWcw0sk31otlO2HBYXT1V9G0YxGtKMOeOBMHjfGbUjGvEALHzWi4z\n"
"8DXGJp13zgnUyP4ZA6xaGROwcT6oB5e7UlztvvpGxTg=\n"
"-----END SIGNATURE-----\n"
"\n"
"router moria2 18.244.0.188 9002 9022 9032\n"
"platform Tor 0.0.6rc1 on Linux moria.mit.edu i686\n"
"published 2004-04-25 21:54:30\n"
"bandwidth 800000 10000000\n"
"onion-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAM4Cc/npgYC54XrYLC+grVxJp7PDmNO2DRRJOxKttBBtvLpnR1UaueTi\n"
"kyknT5kmlx+ihgZF/jmye//2dDUp2+kK/kSkpRV4xnDLXZmed+sNSQxqmm9TtZQ9\n"
"/hjpxhp5J9HmUTYhntBs+4E4CUKokmrI6oRLoln4SA39AX9QLPcnAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"signing-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAOcrht/y5rkaahfX7sMe2qnpqoPibsjTSJaDvsUtaNP/Bq0MgNDGOR48\n"
"rtwfqTRff275Edkp/UYw3G3vSgKCJr76/bqOHCmkiZrnPV1zxNfrK18gNw2Cxre0\n"
"nTA+fD8JQqpPtb8b0SnG9kwy75eS//sRu7TErie2PzGMxrf9LH0LAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"reject 0.0.0.0/255.0.0.0:*\n"
"reject 169.254.0.0/255.255.0.0:*\n"
"reject 127.0.0.0/255.0.0.0:*\n"
"reject 192.168.0.0/255.255.0.0:*\n"
"reject 10.0.0.0/255.0.0.0:*\n"
"reject 172.16.0.0/255.240.0.0:*\n"
"accept *:20-22\n"
"accept *:53\n"
"accept *:79-80\n"
"accept *:110\n"
"accept *:143\n"
"accept *:443\n"
"accept *:873\n"
"accept *:993\n"
"accept *:995\n"
"accept *:1024-65535\n"
"reject *:*\n"
"router-signature\n"
"-----BEGIN SIGNATURE-----\n"
"RKROLwP1ExjTZeg6wuN0pzYqed9IJUd5lAe9hp4ritbnmJAgS6qfww6jgx61CfUR\n"
"6SElhOLE7Q77jAdoL45Ji5pn/Y+Q+E+5lJm1E/ed9ha+YsOPaOc7z6GQ7E4mihCL\n"
"gI1vsw92+P1Ty4RHj6fyD9DhbV19nh2Qs+pvGJOS2FY=\n"
"-----END SIGNATURE-----\n"
"\n"
"router tor26 62.116.124.106 9001 9050 9030\n"
"platform Tor 0.0.6 on Linux seppia i686\n"
"published 2004-05-06 21:33:23\n"
"bandwidth 500000 10000000\n"
"onion-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAMEHdDnpj3ik1AF1xe/VqjoguH2DbANifYqXXfempu0fS+tU9FGo6dU/\n"
"fnVHAZwL9Ek9k2rMzumShi1RduK9p035R/Gk+PBBcLfvwYJ/Nat+ZO/L8jn/3bZe\n"
"ieQd9CKj2LjNGKpRNry37vkwMGIOIlegwK+2us8aXJ7sIvlNts0TAgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"signing-key\n"
"-----BEGIN RSA PUBLIC KEY-----\n"
"MIGJAoGBAMQgV2gXLbXgesWgeAsj8P1Uvm/zibrFXqwDq27lLKNgWGYGX2ax3LyT\n"
"3nzI1Y5oLs4kPKTsMM5ft9aokwf417lKoCRlZc9ptfRbgxDx90c9GtWVmkrmDvCK\n"
"ae59TMoXIiGfZiwWT6KKq5Zm9/Fu2Il3B2vHGkKJYKixmiBJRKp/AgMBAAE=\n"
"-----END RSA PUBLIC KEY-----\n"
"accept 62.245.184.24:25\n"
"accept 62.116.124.106:6666-6670\n"
"accept *:48099\n"
"reject *:*\n"
"router-signature\n"
"-----BEGIN SIGNATURE-----\n"
"qh/xRoqfLNFzPaB8VdpbdMAwRyuk5qjx4LeLVQ2pDwTZ55PqmG99+VKUNte2WTTD\n"
"7dZEA7um2rueohGe4nYmvbhJWr20/I0ZxmWDRDvFy0b5nwzDMGvLvDw95Zu/XJQ2\n"
"md32NE3y9VZCfbCN+GlvETX3fdR3Svzcm8Kzesg2/s4=\n"
"-----END SIGNATURE-----\n"
;

int config_assign_default_dirservers(void) {
  if(router_load_routerlist_from_string(default_dirservers_string, 1) < 0) {
    log_fn(LOG_WARN,"Bug: the default dirservers internal string is corrupt.");
    return -1;
  }

  return 0;
}

static void add_default_trusted_dirservers(void) {
  /* moria1 */
  parse_dir_server_line("18.244.0.188:9031 "
                        "FFCB 46DB 1339 DA84 674C 70D7 CB58 6434 C437 0441");
  /* moria2 */
  parse_dir_server_line("18.244.0.188:9032 "
                        "719B E45D E224 B607 C537 07D0 E214 3E2D 423E 74CF");
  /* tor26 */
  parse_dir_server_line("62.116.124.106:9030 "
                        "847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D");
}

/** Set <b>options</b> to a reasonable default.
 *
 * Call this function when we can't find any torrc config file.
 */
static int config_assign_defaults(or_options_t *options) {

  /* set them up as a client only */
  options->SocksPort = 9050;

  options->AllowUnverifiedNodes = smartlist_create();
  smartlist_add(options->AllowUnverifiedNodes, "middle");
  smartlist_add(options->AllowUnverifiedNodes, "rendezvous");

  config_free_lines(options->ExitPolicy);
  options->ExitPolicy = config_line_prepend(NULL, "ExitPolicy", "reject *:*");

  return 0;
}

/** Print a usage message for tor. */
static void print_usage(void) {
  printf("tor -f <torrc> [args]\n"
         "See man page for more options. This -h is probably obsolete.\n\n"
         "-b <bandwidth>\t\tbytes/second rate limiting\n"
         "-d <file>\t\tDebug file\n"
//         "-m <max>\t\tMax number of connections\n"
         "-l <level>\t\tLog level\n"
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

/**
 * Based on <b>address</b>, guess our public IP address and put it
 * in <b>addr</b>.
 */
int resolve_my_address(const char *address, uint32_t *addr) {
  struct in_addr in;
  struct hostent *rent;
  char hostname[256];
  int explicit_ip=1;

  tor_assert(addr);

  if(address) {
    strlcpy(hostname,address,sizeof(hostname));
  } else { /* then we need to guess our address */
    explicit_ip = 0; /* it's implicit */

    if(gethostname(hostname,sizeof(hostname)) < 0) {
      log_fn(LOG_WARN,"Error obtaining local hostname");
      return -1;
    }
    log_fn(LOG_DEBUG,"Guessed local host name as '%s'",hostname);
  }

  /* now we know hostname. resolve it and keep only the IP */

  if(tor_inet_aton(hostname, &in) == 0) {
    /* then we have to resolve it */
    explicit_ip = 0;
    rent = (struct hostent *)gethostbyname(hostname);
    if (!rent) {
      log_fn(LOG_WARN,"Could not resolve local Address %s. Failing.", hostname);
      return -1;
    }
    tor_assert(rent->h_length == 4);
    memcpy(&in.s_addr, rent->h_addr,rent->h_length);
  }
  if(!explicit_ip && is_internal_IP(htonl(in.s_addr))) {
    log_fn(LOG_WARN,"Address '%s' resolves to private IP '%s'. "
           "Please set the Address config option to be the IP you want to use.",
           hostname, inet_ntoa(in));
    return -1;
  }
  log_fn(LOG_DEBUG,"Resolved Address to %s.", inet_ntoa(in));
  *addr = ntohl(in.s_addr);
  return 0;
}

static char *get_default_nickname(void)
{
  char localhostname[256];
  char *cp, *out, *outp;

  if(gethostname(localhostname,sizeof(localhostname)) < 0) {
    log_fn(LOG_WARN,"Error obtaining local hostname");
    return NULL;
  }
  /* Put it in lowercase; stop at the first dot. */
  for(cp = localhostname; *cp; ++cp) {
    if (*cp == '.') {
      *cp = '\0';
      break;
    }
    *cp = tolower(*cp);
  }
  /* Strip invalid characters. */
  cp = localhostname;
  out = outp = tor_malloc(strlen(localhostname)+1);
  while (*cp) {
    if (strchr(LEGAL_NICKNAME_CHARACTERS, *cp))
      *outp++ = *cp++;
    else
      cp++;
  }
  *outp = '\0';
  /* Enforce length. */
  if (strlen(out) > MAX_NICKNAME_LEN)
    out[MAX_NICKNAME_LEN]='\0';

  return out;
}

/** Release storage held by <b>options</b> */
static void free_options(or_options_t *options) {
  config_free_lines(options->LogOptions);
  tor_free(options->ContactInfo);
  tor_free(options->DebugLogFile);
  tor_free(options->DataDirectory);
  tor_free(options->RouterFile);
  tor_free(options->Nickname);
  tor_free(options->Address);
  tor_free(options->PidFile);
  tor_free(options->ExitNodes);
  tor_free(options->EntryNodes);
  tor_free(options->ExcludeNodes);
  tor_free(options->RendNodes);
  tor_free(options->RendExcludeNodes);
  tor_free(options->OutboundBindAddress);
  tor_free(options->RecommendedVersions);
  tor_free(options->User);
  tor_free(options->Group);
  tor_free(options->HttpProxy);
  config_free_lines(options->RendConfigLines);
  config_free_lines(options->SocksBindAddress);
  config_free_lines(options->ORBindAddress);
  config_free_lines(options->DirBindAddress);
  config_free_lines(options->ExitPolicy);
  config_free_lines(options->SocksPolicy);
  config_free_lines(options->DirServers);
  if (options->FirewallPorts) {
    SMARTLIST_FOREACH(options->FirewallPorts, char *, cp, tor_free(cp));
    smartlist_free(options->FirewallPorts);
    options->FirewallPorts = NULL;
  }
}

/** Set <b>options</b> to hold reasonable defaults for most options. */
static void init_options(or_options_t *options) {
/* give reasonable values for each option. Defaults to zero. */
  memset(options,0,sizeof(or_options_t));
  options->LogOptions = NULL;
  options->ExitNodes = tor_strdup("");
  options->EntryNodes = tor_strdup("");
  options->StrictEntryNodes = options->StrictExitNodes = 0;
  options->ExcludeNodes = tor_strdup("");
  options->RendNodes = tor_strdup("");
  options->RendExcludeNodes = tor_strdup("");
  options->ExitPolicy = NULL;
  options->SocksPolicy = NULL;
  options->SocksBindAddress = NULL;
  options->ORBindAddress = NULL;
  options->DirBindAddress = NULL;
  options->OutboundBindAddress = NULL;
  options->RecommendedVersions = NULL;
  options->PidFile = NULL; // tor_strdup("tor.pid");
  options->DataDirectory = NULL;
  options->PathlenCoinWeight = 0.3;
  options->MaxConn = 900;
  options->DirFetchPostPeriod = 600;
  options->KeepalivePeriod = 300;
  options->MaxOnionsPending = 100;
  options->NewCircuitPeriod = 30; /* twice a minute */
  options->BandwidthRate = 800000; /* at most 800kB/s total sustained incoming */
  options->BandwidthBurst = 10000000; /* max burst on the token bucket */
  options->NumCpus = 1;
  options->RendConfigLines = NULL;
  options->FirewallPorts = NULL;
  options->DirServers = NULL;
}

static char *get_default_conf_file(void)
{
#ifdef MS_WINDOWS
  char *path = tor_malloc(MAX_PATH);
  if (!SUCCEEDED(SHGetSpecialFolderPath(NULL, path, CSIDL_APPDATA, 1))) {
    tor_free(path);
    return NULL;
  }
  strlcat(path,"\\tor\\torrc",MAX_PATH);
  return path;
#else
  return tor_strdup(CONFDIR "/torrc");
#endif
}

/** Read a configuration file into <b>options</b>, finding the configuration
 * file location based on the command line.  After loading the options,
 * validate them for consistency. Return 0 if success, <0 if failure. */
int getconfig(int argc, char **argv, or_options_t *options) {
  struct config_line_t *cl;
  FILE *cf;
  char *fname;
  int i;
  int result = 0;
  static int first_load = 1;
  static char **backup_argv;
  static int backup_argc;
  char *previous_pidfile = NULL;
  int previous_runasdaemon = 0;
  int previous_orport = -1;
  int using_default_torrc;

  if(first_load) { /* first time we're called. save commandline args */
    backup_argv = argv;
    backup_argc = argc;
    first_load = 0;
  } else { /* we're reloading. need to clean up old ones first. */
    argv = backup_argv;
    argc = backup_argc;

    /* record some previous values, so we can fail if they change */
    if(options->PidFile)
      previous_pidfile = tor_strdup(options->PidFile);
    previous_runasdaemon = options->RunAsDaemon;
    previous_orport = options->ORPort;
    free_options(options);
  }
  init_options(options);

  if(argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1],"--help"))) {
    print_usage();
    exit(0);
  }

  if(argc > 1 && (!strcmp(argv[1],"--version"))) {
    printf("Tor version %s.\n",VERSION);
    exit(0);
  }

/* learn config file name, get config lines, assign them */
  i = 1;
  while(i < argc-1 && strcmp(argv[i],"-f")) {
    i++;
  }
  if(i < argc-1) { /* we found one */
    fname = tor_strdup(argv[i+1]);
    using_default_torrc = 0;
  } else {
    /* didn't find one, try CONFDIR */
    char *fn;
    using_default_torrc = 1;
    fn = get_default_conf_file();
    if (fn && file_status(fn)==FN_FILE) {
      fname = fn;
    } else {
      tor_free(fn);
      fn = expand_filename("~/.torrc");
      if (fn && file_status(fn)==FN_FILE) {
        fname = fn;
      } else {
        tor_free(fn);
        fname = get_default_conf_file();
      }
    }
  }
  tor_assert(fname);
  log(LOG_DEBUG,"Opening config file '%s'",fname);

  if(config_assign_defaults(options) < 0) {
    return -1;
  }
  cf = fopen(fname, "r");
  if(!cf) {
    if(using_default_torrc == 1) {
      log(LOG_NOTICE, "Configuration file '%s' not present, using reasonable defaults.",fname);
      tor_free(fname);
    } else {
      log(LOG_WARN, "Unable to open configuration file '%s'.",fname);
      tor_free(fname);
      return -1;
    }
  } else { /* it opened successfully. use it. */
    tor_free(fname);
    if (config_get_lines(cf, &cl)<0)
      return -1;
    if(config_assign(options,cl) < 0)
      return -1;
    config_free_lines(cl);
    fclose(cf);
  }

/* go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  if(config_assign(options,cl) < 0)
    return -1;
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

  if(previous_orport == 0 && options->ORPort > 0) {
    log_fn(LOG_WARN,"During reload, change from ORPort=0 to >0 not allowed. Failing.");
    return -1;
  }

  if(options->ORPort < 0 || options->ORPort > 65535) {
    log(LOG_WARN,"ORPort option out of bounds.");
    result = -1;
  }

  if (options->Nickname == NULL) {
    if(server_mode()) {
      if (!(options->Nickname = get_default_nickname()))
        return -1;
      log_fn(LOG_NOTICE, "Choosing default nickname %s", options->Nickname);
    }
  } else {
    if (strspn(options->Nickname, LEGAL_NICKNAME_CHARACTERS) !=
        strlen(options->Nickname)) {
      log_fn(LOG_WARN, "Nickname '%s' contains illegal characters.", options->Nickname);
      result = -1;
    }
    if (strlen(options->Nickname) == 0) {
      log_fn(LOG_WARN, "Nickname must have at least one character");
      result = -1;
    }
    if (strlen(options->Nickname) > MAX_NICKNAME_LEN) {
      log_fn(LOG_WARN, "Nickname '%s' has more than %d characters.",
             options->Nickname, MAX_NICKNAME_LEN);
      result = -1;
    }
  }

  if(server_mode()) {
    /* confirm that our address isn't broken, so we can complain now */
    uint32_t tmp;
    if(resolve_my_address(options->Address, &tmp) < 0)
      result = -1;
  }

  if(options->SocksPort < 0 || options->SocksPort > 65535) {
    log(LOG_WARN,"SocksPort option out of bounds.");
    result = -1;
  }

  if(options->SocksPort == 0 && options->ORPort == 0) {
    log(LOG_WARN,"SocksPort and ORPort are both undefined? Quitting.");
    result = -1;
  }

  if(options->DirPort < 0 || options->DirPort > 65535) {
    log(LOG_WARN,"DirPort option out of bounds.");
    result = -1;
  }

  if(options->StrictExitNodes && !strlen(options->ExitNodes)) {
    log(LOG_WARN,"StrictExitNodes set, but no ExitNodes listed.");
  }

  if(options->StrictEntryNodes && !strlen(options->EntryNodes)) {
    log(LOG_WARN,"StrictEntryNodes set, but no EntryNodes listed.");
  }

  if(options->AuthoritativeDir && options->RecommendedVersions == NULL) {
    log(LOG_WARN,"Directory servers must configure RecommendedVersions.");
    result = -1;
  }

  if(options->AuthoritativeDir && !options->DirPort) {
    log(LOG_WARN,"Running as authoritative directory, but no DirPort set.");
    result = -1;
  }

  if(options->AuthoritativeDir && !options->ORPort) {
    log(LOG_WARN,"Running as authoritative directory, but no ORPort set.");
    result = -1;
  }

  if(options->AuthoritativeDir && options->ClientOnly) {
    log(LOG_WARN,"Running as authoritative directory, but ClientOnly also set.");
    result = -1;
  }

  if(options->FascistFirewall && !options->FirewallPorts) {
    options->FirewallPorts = smartlist_create();
    smartlist_add(options->FirewallPorts, tor_strdup("80"));
    smartlist_add(options->FirewallPorts, tor_strdup("443"));
  }
  if(options->FirewallPorts) {
    SMARTLIST_FOREACH(options->FirewallPorts, const char *, cp,
    { i = atoi(cp);
      if (i < 1 || i > 65535) {
        log(LOG_WARN, "Port '%s' out of range in FirewallPorts", cp);
        result=-1;
      }
    });
  }
  options->_AllowUnverified = 0;
  if(options->AllowUnverifiedNodes) {
    SMARTLIST_FOREACH(options->AllowUnverifiedNodes, const char *, cp,
    { if (!strcasecmp(cp, "entry"))
        options->_AllowUnverified |= ALLOW_UNVERIFIED_ENTRY;
      else if (!strcasecmp(cp, "exit"))
        options->_AllowUnverified |= ALLOW_UNVERIFIED_EXIT;
      else if (!strcasecmp(cp, "middle"))
        options->_AllowUnverified |= ALLOW_UNVERIFIED_MIDDLE;
      else if (!strcasecmp(cp, "introduction"))
        options->_AllowUnverified |= ALLOW_UNVERIFIED_INTRODUCTION;
      else if (!strcasecmp(cp, "rendezvous"))
        options->_AllowUnverified |= ALLOW_UNVERIFIED_RENDEZVOUS;
      else {
        log(LOG_WARN, "Unrecognized value '%s' in AllowUnverifiedNodes",
            cp);
        result=-1;
      }
    });
  }

  if(options->SocksPort >= 1 &&
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

#define MIN_DIRFETCHPOSTPERIOD 60
  if(options->DirFetchPostPeriod < MIN_DIRFETCHPOSTPERIOD) {
    log(LOG_WARN,"DirFetchPostPeriod option must be at least %d.", MIN_DIRFETCHPOSTPERIOD);
    result = -1;
  }
  if(options->DirFetchPostPeriod > MIN_ONION_KEY_LIFETIME/2) {
    log(LOG_WARN,"DirFetchPostPeriod is too large; clipping.");
    options->DirFetchPostPeriod = MIN_ONION_KEY_LIFETIME/2;
  }

  if(options->KeepalivePeriod < 1) {
    log(LOG_WARN,"KeepalivePeriod option must be positive.");
    result = -1;
  }

  if(options->HttpProxy) { /* parse it now */
    if(parse_addr_port(options->HttpProxy, NULL,
                       &options->HttpProxyAddr, &options->HttpProxyPort) < 0) {
      log(LOG_WARN,"HttpProxy failed to parse or resolve. Please fix.");
      result = -1;
    }
    options->HttpProxyAddr = ntohl(options->HttpProxyAddr); /* switch to host-order */
    if(options->HttpProxyPort == 0) { /* give it a default */
      options->HttpProxyPort = 80;
    }
  }

  
  clear_trusted_dir_servers();
  if (!options->DirServers) {
    add_default_trusted_dirservers();
  } else {
    for (cl = options->DirServers; cl; cl = cl->next) {
      if (parse_dir_server_line(cl->value)<0)
        return -1;
    }
  }

  /* XXX look at the various nicknamelists and make sure they're
   * valid and don't have hostnames that are too long.
   */

  if (rend_config_services(options) < 0) {
    result = -1;
  }

  return result;
}

static int add_single_log(struct config_line_t *level_opt,
                           struct config_line_t *file_opt,
                           int isDaemon)
{
  int levelMin=-1, levelMax=-1;
  char *cp, *tmp_sev;

  if (level_opt) {
    cp = strchr(level_opt->value, '-');
    if (cp) {
      tmp_sev = tor_strndup(level_opt->value, cp - level_opt->value);
      levelMin = parse_log_level(tmp_sev);
      if (levelMin<0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", tmp_sev);
        return -1;
      }
      tor_free(tmp_sev);
      levelMax = parse_log_level(cp+1);
      if (levelMax<0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", cp+1);
        return -1;
      }
    } else {
      levelMin = parse_log_level(level_opt->value);
      if (levelMin<0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of err|warn|notice|info|debug", level_opt->value);
        return -1;

      }
    }
  }
  if (levelMin < 0 && levelMax < 0) {
    levelMin = LOG_NOTICE;
    levelMax = LOG_ERR;
  } else if (levelMin < 0) {
    levelMin = levelMax;
  } else {
    levelMax = LOG_ERR;
  }
  if (file_opt) {
    if (add_file_log(levelMin, levelMax, file_opt->value) < 0) {
      log_fn(LOG_WARN, "Cannot write to LogFile '%s': %s.", file_opt->value,
             strerror(errno));
      return -1;
    }
    log_fn(LOG_NOTICE, "Successfully opened LogFile '%s', redirecting output.",
           file_opt->value);
  } else if (!isDaemon) {
    add_stream_log(levelMin, levelMax, "<stdout>", stdout);
    close_temp_logs();
  }
  return 0;
}

/**
 * Initialize the logs based on the configuration file.
 */
int config_init_logs(or_options_t *options)
{
  /* The order of options is:  Level? (File Level?)+
   */
  struct config_line_t *opt = options->LogOptions;

  /* Special case if no options are given. */
  if (!opt) {
    add_stream_log(LOG_NOTICE, LOG_ERR, "<stdout>", stdout);
    close_temp_logs();
    /* don't return yet, in case we want to do a debuglogfile below */
  }

  /* Special case for if first option is LogLevel. */
  if (opt && !strcasecmp(opt->key, "LogLevel")) {
    if (opt->next && !strcasecmp(opt->next->key, "LogFile")) {
      if (add_single_log(opt, opt->next, options->RunAsDaemon)<0)
        return -1;
      opt = opt->next->next;
    } else if (!opt->next) {
      if (add_single_log(opt, NULL, options->RunAsDaemon)<0)
        return -1;
      opt = opt->next;
    } else {
      ; /* give warning below */
    }
  }

  while (opt) {
    if (!strcasecmp(opt->key, "LogLevel")) {
      log_fn(LOG_WARN, "Two LogLevel options in a row without intervening LogFile");
      opt = opt->next;
    } else {
      tor_assert(!strcasecmp(opt->key, "LogFile"));
      if (opt->next && !strcasecmp(opt->next->key, "LogLevel")) {
        /* LogFile followed by LogLevel */
        if (add_single_log(opt->next, opt, options->RunAsDaemon)<0)
          return -1;
        opt = opt->next->next;
      } else {
        /* LogFile followed by LogFile or end of list. */
        if (add_single_log(NULL, opt, options->RunAsDaemon)<0)
          return -1;
        opt = opt->next;
      }
    }
  }

  if (options->DebugLogFile) {
    log_fn(LOG_WARN, "DebugLogFile is deprecated; use LogFile and LogLevel instead");
    if (add_file_log(LOG_DEBUG, LOG_ERR, options->DebugLogFile)<0)
      return -1;
  }
  return 0;
}

/**
 * Given a linked list of config lines containing "allow" and "deny" tokens,
 * parse them and place the result in <b>dest</b>.  Skip malformed lines.
 */
void
config_parse_exit_policy(struct config_line_t *cfg,
                         struct exit_policy_t **dest)
{
  struct exit_policy_t **nextp;
  smartlist_t *entries;

  if (!cfg)
    return;
  nextp = dest;
  while (*nextp)
    nextp = &((*nextp)->next);

  entries = smartlist_create();
  for (; cfg; cfg = cfg->next) {
    smartlist_split_string(entries,cfg->value,",",SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK,0);
    SMARTLIST_FOREACH(entries, const char *, ent, {
      log_fn(LOG_DEBUG,"Adding new entry '%s'",ent);
      *nextp = router_parse_exit_policy_from_string(ent);
      if(*nextp) {
        nextp = &((*nextp)->next);
      } else {
        log_fn(LOG_WARN,"Malformed exit policy %s; skipping.", ent);
      }
    });
    SMARTLIST_FOREACH(entries, char *, ent, tor_free(ent));
    smartlist_clear(entries);
  }
  smartlist_free(entries);
}

void exit_policy_free(struct exit_policy_t *p) {
  struct exit_policy_t *e;
  while (p) {
    e = p;
    p = p->next;
    tor_free(e->string);
    tor_free(e);
  }
}

static int parse_dir_server_line(const char *line)
{
  smartlist_t *items = NULL;
  int r;
  char *addrport, *address=NULL;
  uint16_t port;
  char digest[DIGEST_LEN];
  items = smartlist_create();
  smartlist_split_string(items, line, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 2);
  if (smartlist_len(items) < 2) {
    log_fn(LOG_WARN, "Too few arguments to DirServer line."); goto err;
  }
  addrport = smartlist_get(items, 0);
  if (parse_addr_port(addrport, &address, NULL, &port)<0) {
    log_fn(LOG_WARN, "Error parsing DirServer address '%s'", addrport);goto err;
  }
  if (!port) {
    log_fn(LOG_WARN, "Missing port in DirServe address '%s'",addrport);goto err;
  }

  tor_strstrip(smartlist_get(items, 1), " ");
  if (strlen(smartlist_get(items, 1)) != HEX_DIGEST_LEN) {
    log_fn(LOG_WARN, "Key digest for DirServer is wrong length."); goto err;
  }
  if (base16_decode(digest, DIGEST_LEN,
                    smartlist_get(items,1), HEX_DIGEST_LEN)<0) {
    log_fn(LOG_WARN, "Unable to decode DirServer key digest."); goto err;
  }

  log_fn(LOG_DEBUG, "Trusted dirserver at %s:%d (%s)", address,(int)port,
         (char*)smartlist_get(items,1));
  add_trusted_dir_server(address, port, digest);

  r = 0;
  goto done;
 err:
  r = -1;
 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  if (address) tor_free(address);
  return r;
}

const char *get_data_directory(or_options_t *options) {
  const char *d;
  if (options->DataDirectory)
    d = options->DataDirectory;
  else {
#ifdef MS_WINDOWS
    char *p;
    p = tor_malloc(MAX_PATH);
    if (!SUCCEEDED(SHGetSpecialFolderPath(NULL, p, CSIDL_APPDATA, 1))) {
      strlcpy(p,CONFDIR, MAX_PATH);
    }
    strlcat(p,"\\tor",MAX_PATH);
    options->DataDirectory = p;
    return p;
#else
    d = "~/.tor";
#endif
  }
  if (d && strncmp(d,"~/",2)==0) {
    char *fn = expand_filename(d);
    if(!fn) {
      log_fn(LOG_ERR,"Failed to expand filename '%s'. Exiting.",d);
      exit(1);
    }
    tor_free(options->DataDirectory);
    options->DataDirectory = fn;
  }
  return options->DataDirectory;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
