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
  CONFIG_TYPE_STRING = 0,   /**< An arbitrary string. */
  CONFIG_TYPE_UINT,         /**< A non-negative integer less than MAX_INT */
  CONFIG_TYPE_DOUBLE,       /**< A floating-point value */
  CONFIG_TYPE_BOOL,         /**< A boolean value, expressed as 0 or 1. */
  CONFIG_TYPE_CSV,          /**< A list of strings, separated by commas and optional
                              * whitespace. */
  CONFIG_TYPE_LINELIST,     /**< Uninterpreted config lines */
  CONFIG_TYPE_OBSOLETE,     /**< Obsolete (ignored) option. */
} config_type_t;

/* An abbreviation for a configuration option allowed on the command line */
typedef struct config_abbrev_t {
  const char *abbreviated;
  const char *full;
  int commandline_only;
} config_abbrev_t;

/* Handy macro for declaring "In the config file or on the command line,
 * you can abbreviate <b>tok</b>s as <b>tok</b>". */
#define PLURAL(tok) { #tok, #tok "s", 0 }

/* A list of command-line abbreviations. */
static config_abbrev_t config_abbrevs[] = {
  PLURAL(ExitNode),
  PLURAL(EntryNodes),
  PLURAL(ExcludeNode),
  PLURAL(FirewallPort),
  PLURAL(HiddenServiceNode),
  PLURAL(HiddenServiceExcludeNode),
  PLURAL(RendNode),
  PLURAL(RendExcludeNode),
  { "l",        "LogLevel" , 1},
  { NULL, NULL , 0},
};
#undef PLURAL

/** A variable allowed in the configuration file or on the command line. */
typedef struct config_var_t {
  const char *name; /**< The full keyword (case insensitive). */
  config_type_t type; /**< How to interpret the type and turn it into a value. */
  off_t var_offset; /**< Offset of the corresponding member of or_options_t. */
  const char *initvalue; /**< String (or null) describing initial value. */
} config_var_t;

/** Return the offset of <b>member</b> within the type <b>tp</b>, in bytes */
#define STRUCT_OFFSET(tp, member) ((off_t) &(((tp*)0)->member))
/** An entry for config_vars: "The option <b>name</b> has type
 * CONFIG_TYPE_<b>conftype</b>, and corresponds to
 * or_options_t.<b>member</b>"
 */
#define VAR(name,conftype,member,initvalue) \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(or_options_t, member), initvalue }
/** An entry for config_vars: "The option <b>name</b> is obsolete." */
#define OBSOLETE(name) { name, CONFIG_TYPE_OBSOLETE, 0, NULL }

/** Array of configuration options.  Until we disallow nonstandard
 * abbreviations, order is significant, since the first matching option will
 * be chosen first.
 */
static config_var_t config_vars[] = {
  VAR("Address",             STRING,   Address,              NULL),
  VAR("AllowUnverifiedNodes",CSV,      AllowUnverifiedNodes, NULL),
  VAR("AuthoritativeDirectory",BOOL,   AuthoritativeDir,     "0"),
  VAR("BandwidthRate",       UINT,     BandwidthRate,        "800000"),
  VAR("BandwidthBurst",      UINT,     BandwidthBurst,       "50000000"),
  VAR("ClientOnly",          BOOL,     ClientOnly,           "0"),
  VAR("ContactInfo",         STRING,   ContactInfo,          NULL),
  VAR("DebugLogFile",        STRING,   DebugLogFile,         NULL),
  VAR("DataDirectory",       STRING,   DataDirectory,        NULL),
  VAR("DirPort",             UINT,     DirPort,              "0"),
  VAR("DirBindAddress",      LINELIST, DirBindAddress,       NULL),
  VAR("DirFetchPostPeriod",  UINT,     DirFetchPostPeriod,   "600"),
  VAR("DirPolicy",           LINELIST, DirPolicy,            NULL),
  VAR("DirServer",           LINELIST, DirServers,           NULL),
  VAR("ExitNodes",           STRING,   ExitNodes,            NULL),
  VAR("EntryNodes",          STRING,   EntryNodes,           NULL),
  VAR("StrictExitNodes",     BOOL,     StrictExitNodes,      "0"),
  VAR("StrictEntryNodes",    BOOL,     StrictEntryNodes,     "0"),
  VAR("ExitPolicy",          LINELIST, ExitPolicy,           NULL),
  VAR("ExcludeNodes",        STRING,   ExcludeNodes,         NULL),
  VAR("FascistFirewall",     BOOL,     FascistFirewall,      "0"),
  VAR("FirewallPorts",       CSV,      FirewallPorts,        NULL),
  VAR("MyFamily",            STRING,   MyFamily,             NULL),
  VAR("NodeFamily",          LINELIST, NodeFamilies,         NULL),
  VAR("Group",               STRING,   Group,                NULL),
  VAR("HashedControlPassword",STRING,  HashedControlPassword, NULL),
  VAR("HttpProxy",           STRING,   HttpProxy,            NULL),
  VAR("HiddenServiceDir",    LINELIST, RendConfigLines,      NULL),
  VAR("HiddenServicePort",   LINELIST, RendConfigLines,      NULL),
  VAR("HiddenServiceNodes",  LINELIST, RendConfigLines,      NULL),
  VAR("HiddenServiceExcludeNodes", LINELIST, RendConfigLines,NULL),
  VAR("IgnoreVersion",       BOOL,     IgnoreVersion,        "0"),
  VAR("KeepalivePeriod",     UINT,     KeepalivePeriod,      "300"),
  VAR("LogLevel",            LINELIST, LogOptions,           NULL),
  VAR("LogFile",             LINELIST, LogOptions,           NULL),
  OBSOLETE("LinkPadding"),
  VAR("MaxConn",             UINT,     MaxConn,              "1024"),
  VAR("MaxOnionsPending",    UINT,     MaxOnionsPending,     "100"),
  VAR("MonthlyAccountingStart",UINT,   AccountingStart,      "0"),
  VAR("AccountingMaxKB",     UINT,     AccountingMaxKB,      "0"),
  VAR("Nickname",            STRING,   Nickname,             NULL),
  VAR("NewCircuitPeriod",    UINT,     NewCircuitPeriod,     "30"),
  VAR("NumCpus",             UINT,     NumCpus,              "1"),
  VAR("ORPort",              UINT,     ORPort,               "0"),
  VAR("ORBindAddress",       LINELIST, ORBindAddress,        NULL),
  VAR("OutboundBindAddress", STRING,   OutboundBindAddress,  NULL),
  VAR("PidFile",             STRING,   PidFile,              NULL),
  VAR("PathlenCoinWeight",   DOUBLE,   PathlenCoinWeight,    "0.3"),
  VAR("RedirectExit",        LINELIST, RedirectExit,         NULL),
  OBSOLETE("RouterFile"),
  VAR("RunAsDaemon",         BOOL,     RunAsDaemon,          "0"),
  VAR("RunTesting",          BOOL,     RunTesting,           "0"),
  VAR("RecommendedVersions", LINELIST, RecommendedVersions,  NULL),
  VAR("RendNodes",           STRING,   RendNodes,            NULL),
  VAR("RendExcludeNodes",    STRING,   RendExcludeNodes,     NULL),
  VAR("SocksPort",           UINT,     SocksPort,            "0"),
  VAR("SocksBindAddress",    LINELIST, SocksBindAddress,     NULL),
  VAR("SocksPolicy",         LINELIST, SocksPolicy,          NULL),
  VAR("SysLog",              LINELIST, LogOptions,           NULL),
  OBSOLETE("TrafficShaping"),
  VAR("User",                STRING,   User,                 NULL),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};
#undef VAR
#undef OBSOLETE

/** Largest allowed config line */
#define CONFIG_LINE_T_MAXLEN 4096

static struct config_line_t *config_get_commandlines(int argc, char **argv);
static int config_get_lines(FILE *f, struct config_line_t **result);
static void config_free_lines(struct config_line_t *front);
static int config_assign_line(or_options_t *options, struct config_line_t *c);
static int config_assign(or_options_t *options, struct config_line_t *list);
static int parse_dir_server_line(const char *line);
static int parse_redirect_line(or_options_t *options,
                               struct config_line_t *line);
static const char *expand_abbrev(const char *option, int commandline_only);
static config_var_t *config_find_option(const char *key);

/** If <b>option</b> is an official abbreviation for a longer option,
 * return the longer option.  Otherwise return <b>option</b>.
 * If <b>command_line</b> is set, apply all abbreviations.  Otherwise, only
 * apply abbreviations that work for the config file and the command line. */
static const char *
expand_abbrev(const char *option, int command_line)
{
  int i;
  for (i=0; config_abbrevs[i].abbreviated; ++i) {
    /* Abbreviations aren't casei. */
    if (!strcmp(option,config_abbrevs[i].abbreviated) &&
        (command_line || !config_abbrevs[i].commandline_only)) {
      return config_abbrevs[i].full;
    }
  }
  return option;
}

/** Helper: Read a list of configuration options from the command line. */
static struct config_line_t *
config_get_commandlines(int argc, char **argv)
{
  struct config_line_t *new;
  struct config_line_t *front = NULL;
  char *s;
  int i = 1;

  while (i < argc-1) {
    if (!strcmp(argv[i],"-f") ||
        !strcmp(argv[i],"--hash-password")) {
      i += 2; /* command-line option with argument. ignore them. */
      continue;
    } else if (!strcmp(argv[i],"--list-fingerprint")) {
      i += 1; /* command-line option. ignore it. */
      continue;
    }

    new = tor_malloc(sizeof(struct config_line_t));
    s = argv[i];

    while(*s == '-')
      s++;

    new->key = tor_strdup(expand_abbrev(s, 1));
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
static int
config_get_lines(FILE *f, struct config_line_t **result)
{
  struct config_line_t *front = NULL;
  char line[CONFIG_LINE_T_MAXLEN];
  int r;
  char *key, *value;

  while ((r = parse_line_from_file(line, sizeof(line), f, &key, &value)) > 0) {
    front = config_line_prepend(front, key, value);
  }

  if (r < 0) {
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
static void
config_free_lines(struct config_line_t *front)
{
  struct config_line_t *tmp;

  while (front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** If <b>key</b> is a configuration option, return the corresponding
 * config_var_t.  Otherwise, if <b>key</b> is a non-standard abbreviation,
 * warn, and return the corresponding config_var_t.  Otherwise return NULL.
 */
static config_var_t *config_find_option(const char *key)
{
  int i;
  /* First, check for an exact (case-insensitive) match */
  for (i=0; config_vars[i].name; ++i) {
    if (!strcasecmp(key, config_vars[i].name))
      return &config_vars[i];
  }
  /* If none, check for an abbreviated match */
  for (i=0; config_vars[i].name; ++i) {
    if (!strncasecmp(key, config_vars[i].name, strlen(key))) {
      log_fn(LOG_WARN, "The abbreviation '%s' is deprecated. "
          "Tell Nick and Roger to make it official, or just use '%s' instead",
             key, config_vars[i].name);
      return &config_vars[i];
    }
  }
  /* Okay, unrecogized options */
  return NULL;
}

/** If <b>c</b> is a syntactically valid configuration line, update
 * <b>options</b> with its value and return 0.  Otherwise return -1. */
static int
config_assign_line(or_options_t *options, struct config_line_t *c)
{
  int i, ok;
  config_var_t *var;
  void *lvalue;

  var = config_find_option(c->key);
  if (!var) {
    log_fn(LOG_WARN, "Unknown option '%s'.  Failing.", c->key);
    return -1;
  }

  /* Put keyword into canonical case. */
  if (strcmp(var->name, c->key)) {
    tor_free(c->key);
    c->key = tor_strdup(var->name);
  }

  lvalue = ((char*)options) + var->var_offset;
  switch(var->type) {

  case CONFIG_TYPE_UINT:
    i = tor_parse_long(c->value, 10, 0, INT_MAX, &ok, NULL);
    if (!ok) {
      log(LOG_WARN, "Int keyword '%s %s' is malformed or out of bounds. Skipping.",
          c->key,c->value);
      return 0;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_BOOL:
    i = tor_parse_long(c->value, 10, 0, 1, &ok, NULL);
    if (!ok) {
      log(LOG_WARN, "Boolean keyword '%s' expects 0 or 1. Skipping.", c->key);
      return 0;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_STRING:
    tor_free(*(char **)lvalue);
    *(char **)lvalue = tor_strdup(c->value);
    break;

  case CONFIG_TYPE_DOUBLE:
    *(double *)lvalue = atof(c->value);
    break;

  case CONFIG_TYPE_CSV:
    if (*(smartlist_t**)lvalue == NULL)
      *(smartlist_t**)lvalue = smartlist_create();

    smartlist_split_string(*(smartlist_t**)lvalue, c->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    break;

    case CONFIG_TYPE_LINELIST:
      /* Note: this reverses the order that the lines appear in.  That's
       * just fine, since we build up the list of lines reversed in the
       * first place. */
      *(struct config_line_t**)lvalue =
        config_line_prepend(*(struct config_line_t**)lvalue, c->key, c->value);
      break;

  case CONFIG_TYPE_OBSOLETE:
    log_fn(LOG_WARN, "Skipping obsolete configuration option '%s'", c->key);
    break;
  }

  return 0;
}

/** Return a canonicalized list of the options assigned for key.
 */
struct config_line_t *
config_get_assigned_option(or_options_t *options, const char *key)
{
  config_var_t *var;
  const void *value;
  char buf[32];
  struct config_line_t *result;

  var = config_find_option(key);
  if (!var) {
    log_fn(LOG_WARN, "Unknown option '%s'.  Failing.", key);
    return NULL;
  }
  value = ((char*)options) + var->var_offset;

  if (var->type == CONFIG_TYPE_LINELIST) {
    /* Linelist requires special handling: we just copy and return it. */
    const struct config_line_t *next_in = value;
    struct config_line_t **next_out = &result;
    while (next_in) {
      *next_out = tor_malloc(sizeof(struct config_line_t));
      (*next_out)->key = tor_strdup(next_in->key);
      (*next_out)->value = tor_strdup(next_in->value);
      next_in = next_in->next;
      next_out = &((*next_out)->next);
    }
    (*next_out) = NULL;
    return result;
  }

  result = tor_malloc_zero(sizeof(struct config_line_t));
  result->key = tor_strdup(var->name);
  switch(var->type)
    {
    case CONFIG_TYPE_STRING:
      result->value = tor_strdup(value ? (char*)value : "");
      break;
    case CONFIG_TYPE_UINT:
      tor_snprintf(buf, sizeof(buf), "%d", *(int*)value);
      result->value = tor_strdup(buf);
      break;
    case CONFIG_TYPE_DOUBLE:
      tor_snprintf(buf, sizeof(buf), "%f", *(double*)value);
      result->value = tor_strdup(buf);
      break;
    case CONFIG_TYPE_BOOL:
      result->value = tor_strdup(*(int*)value ? "1" : "0");
      break;
    case CONFIG_TYPE_CSV:
      if (value)
        result->value = smartlist_join_strings((smartlist_t*)value,",",0,NULL);
      else
        result->value = tor_strdup("");
      break;
    default:
      tor_free(result->key);
      tor_free(result);
      return NULL;
    }

  return result;
}

/** Iterate through the linked list of options <b>list</b>.
 * For each item, convert as appropriate and assign to <b>options</b>.
 * If an item is unrecognized, return -1 immediately,
 * else return 0 for success. */
static int
config_assign(or_options_t *options, struct config_line_t *list)
{
  while (list) {
    const char *full = expand_abbrev(list->key, 0);
    if (strcmp(full,list->key)) {
      tor_free(list->key);
      list->key = tor_strdup(full);
    }

    if (config_assign_line(options, list))
      return -1;
    list = list->next;
  }
  return 0;
}

static void
add_default_trusted_dirservers(void)
{
  /* moria1 */
  parse_dir_server_line("18.244.0.188:9031 "
                        "FFCB 46DB 1339 DA84 674C 70D7 CB58 6434 C437 0441");
  /* moria2 */
  parse_dir_server_line("18.244.0.114:80 "
                        "719B E45D E224 B607 C537 07D0 E214 3E2D 423E 74CF");
  /* tor26 */
  parse_dir_server_line("62.116.124.106:9030 "
                        "847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D");
}

/** Set <b>options</b> to a reasonable default.
 *
 * Call this function before we parse the torrc file.
 */
static int
config_assign_defaults(or_options_t *options)
{
  /* set them up as a client only */
  options->SocksPort = 9050;

  options->AllowUnverifiedNodes = smartlist_create();
  smartlist_add(options->AllowUnverifiedNodes, tor_strdup("middle"));
  smartlist_add(options->AllowUnverifiedNodes, tor_strdup("rendezvous"));

  config_free_lines(options->ExitPolicy);
  options->ExitPolicy = NULL;

  return 0;
}

/** Print a usage message for tor. */
static void
print_usage(void)
{
  printf("tor -f <torrc> [args]\n"
         "See man page for more options. This -h is probably obsolete.\n\n"
         "-b <bandwidth>\t\tbytes/second rate limiting\n"
         "-d <file>\t\tDebug file\n"
//         "-m <max>\t\tMax number of connections\n"
         "-l <level>\t\tLog level\n"
         "-r <file>\t\tList of known routers\n");
  printf("\nClient options:\n"
         "-e \"nick1 nick2 ...\"\t\tExit nodes\n"
         "-s <IP>\t\t\tPort to bind to for Socks\n");
  printf("\nServer options:\n"
         "-n <nick>\t\tNickname of router\n"
         "-o <port>\t\tOR port to bind to\n"
         "-p <file>\t\tPID file\n");
}

/**
 * Based on <b>address</b>, guess our public IP address and put it
 * in <b>addr</b>.
 */
int
resolve_my_address(const char *address, uint32_t *addr)
{
  struct in_addr in;
  struct hostent *rent;
  char hostname[256];
  int explicit_ip=1;

  tor_assert(addr);

  if (address) {
    strlcpy(hostname, address, sizeof(hostname));
  } else { /* then we need to guess our address */
    explicit_ip = 0; /* it's implicit */

    if (gethostname(hostname, sizeof(hostname)) < 0) {
      log_fn(LOG_WARN,"Error obtaining local hostname");
      return -1;
    }
    log_fn(LOG_DEBUG,"Guessed local host name as '%s'",hostname);
  }

  /* now we know hostname. resolve it and keep only the IP */

  if (tor_inet_aton(hostname, &in) == 0) {
    /* then we have to resolve it */
    explicit_ip = 0;
    rent = (struct hostent *)gethostbyname(hostname);
    if (!rent) {
      log_fn(LOG_WARN,"Could not resolve local Address %s. Failing.", hostname);
      return -1;
    }
    tor_assert(rent->h_length == 4);
    memcpy(&in.s_addr, rent->h_addr, rent->h_length);
  }

  if (!explicit_ip && is_internal_IP(htonl(in.s_addr))) {
    log_fn(LOG_WARN,"Address '%s' resolves to private IP '%s'. "
           "Please set the Address config option to be the IP you want to use.",
           hostname, inet_ntoa(in));
    return -1;
  }

  log_fn(LOG_DEBUG, "Resolved Address to %s.", inet_ntoa(in));
  *addr = ntohl(in.s_addr);
  return 0;
}

static char *
get_default_nickname(void)
{
  char localhostname[256];
  char *cp, *out, *outp;

  if (gethostname(localhostname, sizeof(localhostname)) < 0) {
    log_fn(LOG_WARN,"Error obtaining local hostname");
    return NULL;
  }

  /* Put it in lowercase; stop at the first dot. */
  for (cp = localhostname; *cp; ++cp) {
    if (*cp == '.') {
      *cp = '\0';
      break;
    }
    *cp = tolower(*cp);
  }

  /* Strip invalid characters. */
  cp = localhostname;
  out = outp = tor_malloc(strlen(localhostname) + 1);
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
static void
free_options(or_options_t *options)
{
  config_free_lines(options->LogOptions);
  tor_free(options->ContactInfo);
  tor_free(options->DebugLogFile);
  tor_free(options->DataDirectory);
  tor_free(options->Nickname);
  tor_free(options->Address);
  tor_free(options->PidFile);
  tor_free(options->ExitNodes);
  tor_free(options->EntryNodes);
  tor_free(options->ExcludeNodes);
  tor_free(options->RendNodes);
  tor_free(options->RendExcludeNodes);
  tor_free(options->OutboundBindAddress);
  tor_free(options->User);
  tor_free(options->Group);
  tor_free(options->HttpProxy);
  config_free_lines(options->RendConfigLines);
  config_free_lines(options->SocksBindAddress);
  config_free_lines(options->ORBindAddress);
  config_free_lines(options->DirBindAddress);
  config_free_lines(options->ExitPolicy);
  config_free_lines(options->SocksPolicy);
  config_free_lines(options->DirPolicy);
  config_free_lines(options->DirServers);
  config_free_lines(options->RecommendedVersions);
  config_free_lines(options->NodeFamilies);
  config_free_lines(options->RedirectExit);
  if (options->RedirectExitList) {
    SMARTLIST_FOREACH(options->RedirectExitList,
                      exit_redirect_t *, p, tor_free(p));
    smartlist_free(options->RedirectExitList);
    options->RedirectExitList = NULL;
  }
  if (options->FirewallPorts) {
    SMARTLIST_FOREACH(options->FirewallPorts, char *, cp, tor_free(cp));
    smartlist_free(options->FirewallPorts);
    options->FirewallPorts = NULL;
  }
  if (options->AllowUnverifiedNodes) {
    SMARTLIST_FOREACH(options->AllowUnverifiedNodes, char *, cp, tor_free(cp));
    smartlist_free(options->AllowUnverifiedNodes);
    options->AllowUnverifiedNodes = NULL;
  }
}

/** Set <b>options</b> to hold reasonable defaults for most options.
 * Each option defaults to zero. */
static void
init_options(or_options_t *options)
{
  memset(options,0,sizeof(or_options_t));
  options->PathlenCoinWeight = 0.3;
  options->MaxConn = 1024;
  options->DirFetchPostPeriod = 600;
  options->KeepalivePeriod = 300;
  options->MaxOnionsPending = 100;
  options->NewCircuitPeriod = 30; /* twice a minute */
  options->BandwidthRate = 800000; /* at most 800kB/s total sustained incoming */
  options->BandwidthBurst = 10000000; /* max burst on the token bucket */
  options->NumCpus = 1;
}

#ifdef MS_WINDOWS
static char *get_windows_conf_root(void)
{
  static int is_set = 0;
  static char path[MAX_PATH+1];

  LPITEMIDLIST idl;
  IMalloc *m;
  HRESULT result;

  if (is_set)
    return path;

  /* Find X:\documents and settings\username\applicatation data\ .
   * We would use SHGetSpecialFolder path, but that wasn't added until IE4.
   */
  if (!SUCCEEDED(SHGetSpecialFolderLocation(NULL, CSIDL_APPDATA,
                                            &idl))) {
    GetCurrentDirectory(MAX_PATH, path);
    is_set = 1;
    log_fn(LOG_WARN, "I couldn't find your application data folder: are you running an ancient version of Windows 95? Defaulting to '%s'", path);
    return path;
  }
  /* Convert the path from an "ID List" (whatever that is!) to a path. */
  result = SHGetPathFromIDList(idl, path);
  /* Now we need to free the */
  SHGetMalloc(&m);
  if (m) {
    m->lpVtbl->Free(m, idl);
    m->lpVtbl->Release(m);
  }
  if (!SUCCEEDED(result)) {
    return NULL;
  }
  strlcat(path,"\\tor",MAX_PATH);
  is_set = 1;
  return path;
}
#endif

static char *
get_default_conf_file(void)
{
#ifdef MS_WINDOWS
  char *path = tor_malloc(MAX_PATH);
  strlcpy(path, get_windows_conf_root(), MAX_PATH);
  strlcat(path,"\\torrc",MAX_PATH);
  return path;
#else
  return tor_strdup(CONFDIR "/torrc");
#endif
}

/** Verify whether lst is a string containing valid-looking space-separated
 * nicknames, or NULL. Return 0 on success. Warn and return -1 on failure.
 */
static int check_nickname_list(const char *lst, const char *name)
{
  int r = 0;
  smartlist_t *sl;

  if (!lst)
    return 0;
  sl = smartlist_create();
  smartlist_split_string(sl, lst, ",", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  SMARTLIST_FOREACH(sl, const char *, s,
    {
      if (!is_legal_nickname_or_hexdigest(s)) {
        log_fn(LOG_WARN, "Invalid nickname '%s' in %s line", s, name);
        r = -1;
      }
    });
  SMARTLIST_FOREACH(sl, char *, s, tor_free(s));
  smartlist_free(sl);
  return r;
}

/** Read a configuration file into <b>options</b>, finding the configuration
 * file location based on the command line.  After loading the options,
 * validate them for consistency. Return 0 if success, <0 if failure. */
int
getconfig(int argc, char **argv, or_options_t *options)
{
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

  if (first_load) { /* first time we're called. save commandline args */
    backup_argv = argv;
    backup_argc = argc;
    first_load = 0;
  } else { /* we're reloading. need to clean up old ones first. */
    argv = backup_argv;
    argc = backup_argc;

    /* record some previous values, so we can fail if they change */
    if (options->PidFile)
      previous_pidfile = tor_strdup(options->PidFile);
    previous_runasdaemon = options->RunAsDaemon;
    previous_orport = options->ORPort;
    free_options(options);
  }
  init_options(options);

  if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1],"--help"))) {
    print_usage();
    exit(0);
  }

  if (argc > 1 && (!strcmp(argv[1],"--version"))) {
    printf("Tor version %s.\n",VERSION);
    exit(0);
  }

  /* learn config file name, get config lines, assign them */
  fname = NULL;
  using_default_torrc = 1;
  options->command = CMD_RUN_TOR;
  for (i = 1; i < argc; ++i) {
    if (i < argc-1 && !strcmp(argv[i],"-f")) {
      if (fname) {
        log(LOG_WARN, "Duplicate -f options on command line.");
        tor_free(fname);
      }
      fname = tor_strdup(argv[i+1]);
      using_default_torrc = 0;
      ++i;
    } else if (!strcmp(argv[i],"--list-fingerprint")) {
      options->command = CMD_LIST_FINGERPRINT;
    } else if (!strcmp(argv[i],"--hash-password")) {
      options->command = CMD_HASH_PASSWORD;
      options->command_arg = tor_strdup(argv[i+1]);
      ++i;
    }

  }

  if (using_default_torrc) {
    /* didn't find one, try CONFDIR */
    char *fn;
    fn = get_default_conf_file();
    if (fn && file_status(fn) == FN_FILE) {
      fname = fn;
    } else {
      tor_free(fn);
      fn = expand_filename("~/.torrc");
      if (fn && file_status(fn) == FN_FILE) {
        fname = fn;
      } else {
        tor_free(fn);
        fname = get_default_conf_file();
      }
    }
  }
  tor_assert(fname);
  log(LOG_DEBUG, "Opening config file '%s'", fname);

  if (config_assign_defaults(options) < 0) {
    return -1;
  }

  cf = fopen(fname, "r");
  if (!cf) {
    if (using_default_torrc == 1) {
      log(LOG_NOTICE, "Configuration file '%s' not present, "
          "using reasonable defaults.", fname);
      tor_free(fname);
    } else {
      log(LOG_WARN, "Unable to open configuration file '%s'.", fname);
      tor_free(fname);
      return -1;
    }
  } else { /* it opened successfully. use it. */
    tor_free(fname);
    if (config_get_lines(cf, &cl)<0)
      return -1;
    if (config_assign(options,cl) < 0)
      return -1;
    config_free_lines(cl);
    fclose(cf);
  }

/* go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  if (config_assign(options,cl) < 0)
    return -1;
  config_free_lines(cl);

/* Validate options */

  /* first check if any of the previous options have changed but aren't allowed to */
  if (previous_pidfile && strcmp(previous_pidfile,options->PidFile)) {
    log_fn(LOG_WARN,"During reload, PidFile changed from %s to %s. Failing.",
           previous_pidfile, options->PidFile);
    return -1;
  }
  tor_free(previous_pidfile);

  if (previous_runasdaemon && !options->RunAsDaemon) {
    log_fn(LOG_WARN,"During reload, change from RunAsDaemon=1 to =0 not allowed. Failing.");
    return -1;
  }

  if (previous_orport == 0 && options->ORPort > 0) {
    log_fn(LOG_WARN,"During reload, change from ORPort=0 to >0 not allowed. Failing.");
    return -1;
  }

  if (options->ORPort < 0 || options->ORPort > 65535) {
    log(LOG_WARN, "ORPort option out of bounds.");
    result = -1;
  }

  if (options->Nickname == NULL) {
    if (server_mode()) {
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

  if (server_mode()) {
    /* confirm that our address isn't broken, so we can complain now */
    uint32_t tmp;
    if (resolve_my_address(options->Address, &tmp) < 0)
      result = -1;
  }

  if (options->SocksPort < 0 || options->SocksPort > 65535) {
    log(LOG_WARN, "SocksPort option out of bounds.");
    result = -1;
  }

  if (options->SocksPort == 0 && options->ORPort == 0) {
    log(LOG_WARN, "SocksPort and ORPort are both undefined? Quitting.");
    result = -1;
  }

  if (options->DirPort < 0 || options->DirPort > 65535) {
    log(LOG_WARN, "DirPort option out of bounds.");
    result = -1;
  }

  if (options->StrictExitNodes &&
      (!options->ExitNodes || !strlen(options->ExitNodes))) {
    log(LOG_WARN, "StrictExitNodes set, but no ExitNodes listed.");
  }

  if (options->StrictEntryNodes &&
      (!options->EntryNodes || !strlen(options->EntryNodes))) {
    log(LOG_WARN, "StrictEntryNodes set, but no EntryNodes listed.");
  }

  if (options->AuthoritativeDir && options->RecommendedVersions == NULL) {
    log(LOG_WARN, "Directory servers must configure RecommendedVersions.");
    result = -1;
  }

  if (options->AuthoritativeDir && !options->DirPort) {
    log(LOG_WARN, "Running as authoritative directory, but no DirPort set.");
    result = -1;
  }

  if (options->AuthoritativeDir && !options->ORPort) {
    log(LOG_WARN, "Running as authoritative directory, but no ORPort set.");
    result = -1;
  }

  if (options->AuthoritativeDir && options->ClientOnly) {
    log(LOG_WARN, "Running as authoritative directory, but ClientOnly also set.");
    result = -1;
  }

  if (options->FascistFirewall && !options->FirewallPorts) {
    options->FirewallPorts = smartlist_create();
    smartlist_add(options->FirewallPorts, tor_strdup("80"));
    smartlist_add(options->FirewallPorts, tor_strdup("443"));
  }
  if (options->FirewallPorts) {
    SMARTLIST_FOREACH(options->FirewallPorts, const char *, cp,
    {
      i = atoi(cp);
      if (i < 1 || i > 65535) {
        log(LOG_WARN, "Port '%s' out of range in FirewallPorts", cp);
        result=-1;
      }
    });
  }
  options->_AllowUnverified = 0;
  if (options->AllowUnverifiedNodes) {
    SMARTLIST_FOREACH(options->AllowUnverifiedNodes, const char *, cp, {
        if (!strcasecmp(cp, "entry"))
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

  if (options->SocksPort >= 1 &&
      (options->PathlenCoinWeight < 0.0 || options->PathlenCoinWeight >= 1.0)) {
    log(LOG_WARN, "PathlenCoinWeight option must be >=0.0 and <1.0.");
    result = -1;
  }

  if (options->MaxConn < 1) {
    log(LOG_WARN, "MaxConn option must be a non-zero positive integer.");
    result = -1;
  }

  if (options->MaxConn >= MAXCONNECTIONS) {
    log(LOG_WARN, "MaxConn option must be less than %d.", MAXCONNECTIONS);
    result = -1;
  }

#define MIN_DIRFETCHPOSTPERIOD 60
  if (options->DirFetchPostPeriod < MIN_DIRFETCHPOSTPERIOD) {
    log(LOG_WARN, "DirFetchPostPeriod option must be at least %d.", MIN_DIRFETCHPOSTPERIOD);
    result = -1;
  }
  if (options->DirFetchPostPeriod > MIN_ONION_KEY_LIFETIME / 2) {
    log(LOG_WARN, "DirFetchPostPeriod is too large; clipping.");
    options->DirFetchPostPeriod = MIN_ONION_KEY_LIFETIME / 2;
  }

  if (options->KeepalivePeriod < 1) {
    log(LOG_WARN,"KeepalivePeriod option must be positive.");
    result = -1;
  }

  if (options->AccountingStart < 0 || options->AccountingStart > 31) {
    log(LOG_WARN,"Monthy accounting must start on a day of the month, and no months have %d days.",
        options->AccountingStart);
    result = -1;
  } else if (options->AccountingStart > 28) {
    log(LOG_WARN,"Not every month has %d days.",options->AccountingStart);
    result = -1;
  }

  if (options->HttpProxy) { /* parse it now */
    if (parse_addr_port(options->HttpProxy, NULL,
                        &options->HttpProxyAddr, &options->HttpProxyPort) < 0) {
      log(LOG_WARN,"HttpProxy failed to parse or resolve. Please fix.");
      result = -1;
    }
    if (options->HttpProxyPort == 0) { /* give it a default */
      options->HttpProxyPort = 80;
    }
  }

  if (check_nickname_list(options->ExitNodes, "ExitNodes"))
    return -1;
  if (check_nickname_list(options->EntryNodes, "EntryNodes"))
    return -1;
  if (check_nickname_list(options->ExcludeNodes, "ExcludeNodes"))
    return -1;
  if (check_nickname_list(options->RendNodes, "RendNodes"))
    return -1;
  if (check_nickname_list(options->RendNodes, "RendExcludeNodes"))
    return -1;
  if (check_nickname_list(options->MyFamily, "MyFamily"))
    return -1;
  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (check_nickname_list(cl->value, "NodeFamily"))
      return -1;
  }

  if (!options->RedirectExitList)
    options->RedirectExitList = smartlist_create();
  for (cl = options->RedirectExit; cl; cl = cl->next) {
    if (parse_redirect_line(options, cl)<0)
      return -1;
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

  if (rend_config_services(options) < 0) {
    result = -1;
  }
  return result;
}

static int
add_single_log(struct config_line_t *level_opt,
               struct config_line_t *file_opt, int isDaemon)
{
  int levelMin = -1, levelMax = -1;
  char *cp, *tmp_sev;

  if (level_opt) {
    cp = strchr(level_opt->value, '-');
    if (cp) {
      tmp_sev = tor_strndup(level_opt->value, cp - level_opt->value);
      levelMin = parse_log_level(tmp_sev);
      if (levelMin < 0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
               "err|warn|notice|info|debug", tmp_sev);
        return -1;
      }
      tor_free(tmp_sev);
      levelMax = parse_log_level(cp+1);
      if (levelMax < 0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
               "err|warn|notice|info|debug", cp+1);
        return -1;
      }
    } else {
      levelMin = parse_log_level(level_opt->value);
      if (levelMin < 0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
               "err|warn|notice|info|debug", level_opt->value);
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

  if (file_opt && !strcasecmp(file_opt->key, "LogFile")) {
    if (add_file_log(levelMin, levelMax, file_opt->value) < 0) {
      log_fn(LOG_WARN, "Cannot write to LogFile '%s': %s.", file_opt->value,
             strerror(errno));
      return -1;
    }
    log_fn(LOG_NOTICE, "Successfully opened LogFile '%s', redirecting output.",
           file_opt->value);
  } else if (file_opt && !strcasecmp(file_opt->key, "SysLog")) {
#ifdef HAVE_SYSLOG_H
    if (add_syslog_log(levelMin, levelMax) < 0) {
      log_fn(LOG_WARN, "Cannot open system log facility");
      return -1;
    }
    log_fn(LOG_NOTICE, "Successfully opened system log, redirecting output.");
#else
    log_fn(LOG_WARN, "Tor was compiled without system logging enabled; can't enable SysLog.");
#endif
  } else if (!isDaemon) {
    add_stream_log(levelMin, levelMax, "<stdout>", stdout);
    close_temp_logs();
  }
  return 0;
}

/**
 * Initialize the logs based on the configuration file.
 */
int
config_init_logs(or_options_t *options)
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
    if (opt->next && (!strcasecmp(opt->next->key, "LogFile") ||
                      !strcasecmp(opt->next->key, "SysLog"))) {
      if (add_single_log(opt, opt->next, options->RunAsDaemon) < 0)
        return -1;
      opt = opt->next->next;
    } else if (!opt->next) {
      if (add_single_log(opt, NULL, options->RunAsDaemon) < 0)
        return -1;
      opt = opt->next;
    } else {
      ; /* give warning below */
    }
  }

  while (opt) {
    if (!strcasecmp(opt->key, "LogLevel")) {
      log_fn(LOG_WARN, "Two LogLevel options in a row without intervening LogFile or SysLog");
      opt = opt->next;
    } else {
      tor_assert(!strcasecmp(opt->key, "LogFile") ||
                 !strcasecmp(opt->key, "SysLog"));
      if (opt->next && !strcasecmp(opt->next->key, "LogLevel")) {
        /* LogFile/SysLog followed by LogLevel */
        if (add_single_log(opt->next, opt, options->RunAsDaemon) < 0)
          return -1;
        opt = opt->next->next;
      } else {
        /* LogFile/SysLog followed by LogFile/SysLog or end of list. */
        if (add_single_log(NULL, opt, options->RunAsDaemon) < 0)
          return -1;
        opt = opt->next;
      }
    }
  }

  if (options->DebugLogFile) {
    log_fn(LOG_WARN, "DebugLogFile is deprecated; use LogFile and LogLevel instead");
    if (add_file_log(LOG_DEBUG, LOG_ERR, options->DebugLogFile) < 0)
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
    smartlist_split_string(entries, cfg->value, ",", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH(entries, const char *, ent,
    {
      log_fn(LOG_DEBUG,"Adding new entry '%s'",ent);
      *nextp = router_parse_exit_policy_from_string(ent);
      if (*nextp) {
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

static int parse_redirect_line(or_options_t *options,
                               struct config_line_t *line)
{
  smartlist_t *elements = NULL;
  exit_redirect_t *r;

  tor_assert(options);
  tor_assert(options->RedirectExitList);
  tor_assert(line);

  r = tor_malloc_zero(sizeof(exit_redirect_t));
  elements = smartlist_create();
  smartlist_split_string(elements, line->value, " ",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(elements) != 2) {
    log_fn(LOG_WARN, "Wrong number of elements in RedirectExit line");
    goto err;
  }
  if (parse_addr_and_port_range(smartlist_get(elements,0),&r->addr,&r->mask,
                                &r->port_min,&r->port_max)) {
    log_fn(LOG_WARN, "Error parsing source address in RedirectExit line");
    goto err;
  }
  if (0==strcasecmp(smartlist_get(elements,1), "pass")) {
    r->is_redirect = 0;
  } else {
    if (parse_addr_port(smartlist_get(elements,1),NULL,&r->addr_dest,
                             &r->port_dest)) {
      log_fn(LOG_WARN, "Error parseing dest address in RedirectExit line");
      goto err;
    }
    r->is_redirect = 1;
  }

  goto done;
 err:
  tor_free(r);
 done:
  SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
  smartlist_free(elements);
  if (r) {
    smartlist_add(options->RedirectExitList, r);
    return 0;
  } else {
    return -1;
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
    log_fn(LOG_WARN, "Too few arguments to DirServer line.");
    goto err;
  }
  addrport = smartlist_get(items, 0);
  if (parse_addr_port(addrport, &address, NULL, &port)<0) {
    log_fn(LOG_WARN, "Error parsing DirServer address '%s'", addrport);
    goto err;
  }
  if (!port) {
    log_fn(LOG_WARN, "Missing port in DirServe address '%s'",addrport);
    goto err;
  }

  tor_strstrip(smartlist_get(items, 1), " ");
  if (strlen(smartlist_get(items, 1)) != HEX_DIGEST_LEN) {
    log_fn(LOG_WARN, "Key digest for DirServer is wrong length.");
    goto err;
  }
  if (base16_decode(digest, DIGEST_LEN,
                    smartlist_get(items,1), HEX_DIGEST_LEN)<0) {
    log_fn(LOG_WARN, "Unable to decode DirServer key digest.");
    goto err;
  }

  log_fn(LOG_DEBUG, "Trusted dirserver at %s:%d (%s)", address, (int)port,
         (char*)smartlist_get(items,1));
  add_trusted_dir_server(address, port, digest);

  r = 0;
  goto done;

  err:
  r = -1;

  done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);

  if (address)
    tor_free(address);

  return r;
}

const char *
get_data_directory(or_options_t *options)
{
  const char *d;

  if (options->DataDirectory) {
    d = options->DataDirectory;
  } else {
#ifdef MS_WINDOWS
    char *p;
    p = tor_malloc(MAX_PATH);
    strlcpy(p,get_windows_conf_root(),MAX_PATH);
    options->DataDirectory = p;
    return p;
#else
    d = "~/.tor";
#endif
  }

  if (d && strncmp(d,"~/",2) == 0) {
    char *fn = expand_filename(d);
    if (!fn) {
      log_fn(LOG_ERR,"Failed to expand filename '%s'. Exiting.", d);
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
