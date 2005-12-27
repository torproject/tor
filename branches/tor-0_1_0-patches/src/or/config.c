/* Copyright 2001 Matej Pfajfar.
 * Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char config_c_id[] = "$Id$";
/**
 * \file config.c
 *
 * \brief Code to parse and interpret configuration files.
 **/

#include "or.h"
#ifdef MS_WINDOWS
#include <shlobj.h>
#endif
#include "../common/aes.h"

/** Enumeration of types which option values can take */
typedef enum config_type_t {
  CONFIG_TYPE_STRING = 0,   /**< An arbitrary string. */
  CONFIG_TYPE_UINT,         /**< A non-negative integer less than MAX_INT */
  CONFIG_TYPE_INTERVAL,     /**< A number of seconds, with optional units*/
  CONFIG_TYPE_MEMUNIT,      /**< A number of bytes, with optional units*/
  CONFIG_TYPE_DOUBLE,       /**< A floating-point value */
  CONFIG_TYPE_BOOL,         /**< A boolean value, expressed as 0 or 1. */
  CONFIG_TYPE_CSV,          /**< A list of strings, separated by commas and optional
                              * whitespace. */
  CONFIG_TYPE_LINELIST,     /**< Uninterpreted config lines */
  CONFIG_TYPE_LINELIST_S,   /**< Uninterpreted, context-sensitive config lines,
                             * mixed with other keywords. */
  CONFIG_TYPE_LINELIST_V,   /**< Catch-all "virtual" option to summarize
                             * context-sensitive config lines when fetching.
                             */
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
  PLURAL(EntryNode),
  PLURAL(ExcludeNode),
  PLURAL(FirewallPort),
  PLURAL(LongLivedPort),
  PLURAL(HiddenServiceNode),
  PLURAL(HiddenServiceExcludeNode),
  PLURAL(NumCpu),
  PLURAL(RendNode),
  PLURAL(RendExcludeNode),
  PLURAL(StrictEntryNode),
  PLURAL(StrictExitNode),
  { "l", "Log", 1},
  { "BandwidthRateBytes", "BandwidthRate", 0},
  { "BandwidthBurstBytes", "BandwidthBurst", 0},
  { "DirFetchPostPeriod", "StatusFetchPeriod", 0},
  { "MaxConn", "ConnLimit", 0},
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
#define STRUCT_OFFSET(tp, member) ((off_t) (((char*)&((tp*)0)->member)-(char*)0))
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
  VAR("AccountingStart",     STRING,   AccountingStart,      NULL),
  VAR("AllowUnverifiedNodes",CSV,      AllowUnverifiedNodes, "middle,rendezvous"),
  VAR("AuthoritativeDirectory",BOOL,   AuthoritativeDir,     "0"),
  VAR("BandwidthRate",       MEMUNIT,  BandwidthRate,        "2 MB"),
  VAR("BandwidthBurst",      MEMUNIT,  BandwidthBurst,       "5 MB"),
  VAR("MaxAdvertisedBandwidth",MEMUNIT,MaxAdvertisedBandwidth,"128 TB"),
  VAR("ClientOnly",          BOOL,     ClientOnly,           "0"),
  VAR("ContactInfo",         STRING,   ContactInfo,          NULL),
  VAR("ControlPort",         UINT,     ControlPort,          "0"),
  VAR("CookieAuthentication",BOOL,     CookieAuthentication, "0"),
  VAR("DebugLogFile",        STRING,   DebugLogFile,         NULL),
  VAR("DataDirectory",       STRING,   DataDirectory,        NULL),
  VAR("DirAllowPrivateAddresses",BOOL, DirAllowPrivateAddresses, NULL),
  VAR("DirPort",             UINT,     DirPort,              "0"),
  VAR("DirBindAddress",      LINELIST, DirBindAddress,       NULL),
  /** DOCDOC **/
  VAR("DirFetchPeriod",      INTERVAL, DirFetchPeriod,       "0 seconds"),
  VAR("DirPostPeriod",       INTERVAL, DirPostPeriod,        "20 minutes"),
  VAR("RendPostPeriod",      INTERVAL, RendPostPeriod,       "20 minutes"),
  VAR("DirPolicy",           LINELIST, DirPolicy,            NULL),
  VAR("DirServer",           LINELIST, DirServers,           NULL),
  VAR("ExitNodes",           STRING,   ExitNodes,            NULL),
  VAR("EntryNodes",          STRING,   EntryNodes,           NULL),
  VAR("StrictExitNodes",     BOOL,     StrictExitNodes,      "0"),
  VAR("StrictEntryNodes",    BOOL,     StrictEntryNodes,     "0"),
  VAR("ExitPolicy",          LINELIST, ExitPolicy,           NULL),
  VAR("ExcludeNodes",        STRING,   ExcludeNodes,         NULL),
  VAR("TrackHostExits",      CSV,      TrackHostExits,       NULL),
  VAR("TrackHostExitsExpire",INTERVAL, TrackHostExitsExpire, "30 minutes"),
  VAR("MapAddress",          LINELIST, AddressMap,           NULL),
  VAR("FascistFirewall",     BOOL,     FascistFirewall,      "0"),
  VAR("FirewallPorts",       CSV,      FirewallPorts,        "80,443"),
  VAR("MyFamily",            STRING,   MyFamily,             NULL),
  VAR("NodeFamily",          LINELIST, NodeFamilies,         NULL),
  VAR("NoPublish",           BOOL,     NoPublish,            "0"),
  VAR("Group",               STRING,   Group,                NULL),
  VAR("HashedControlPassword",STRING,  HashedControlPassword, NULL),
  VAR("HttpProxy",           STRING,   HttpProxy,            NULL),
  VAR("HttpProxyAuthenticator",STRING, HttpProxyAuthenticator,NULL),
  VAR("HttpsProxy",          STRING,   HttpsProxy,           NULL),
  VAR("HttpsProxyAuthenticator",STRING,HttpsProxyAuthenticator,NULL),
  VAR("HiddenServiceOptions",LINELIST_V, RendConfigLines,    NULL),
  VAR("HiddenServiceDir",    LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServicePort",   LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceNodes",  LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceExcludeNodes", LINELIST_S, RendConfigLines, NULL),
  OBSOLETE("IgnoreVersion"),
  VAR("KeepalivePeriod",     INTERVAL, KeepalivePeriod,      "5 minutes"),
  VAR("Log",                 LINELIST, Logs,                 NULL),
  VAR("LogLevel",            LINELIST_S, OldLogOptions,      NULL),
  VAR("LogFile",             LINELIST_S, OldLogOptions,      NULL),
  OBSOLETE("LinkPadding"),
  VAR("ConnLimit",           UINT,     ConnLimit,            "1024"),
  VAR("MaxOnionsPending",    UINT,     MaxOnionsPending,     "100"),
  VAR("MonthlyAccountingStart",UINT,   _MonthlyAccountingStart,"0"),
  VAR("AccountingMaxKB",     UINT,     _AccountingMaxKB,     "0"),
  VAR("AccountingMax",       MEMUNIT,   AccountingMax,        "0 bytes"),
  VAR("Nickname",            STRING,   Nickname,             NULL),
  VAR("NewCircuitPeriod",    INTERVAL, NewCircuitPeriod,     "30 seconds"),
  VAR("MaxCircuitDirtiness", INTERVAL, MaxCircuitDirtiness,  "10 minutes"),
  VAR("NumCpus",             UINT,     NumCpus,              "1"),
  VAR("ORPort",              UINT,     ORPort,               "0"),
  VAR("ORBindAddress",       LINELIST, ORBindAddress,        NULL),
  VAR("OutboundBindAddress", STRING,   OutboundBindAddress,  NULL),
  VAR("PidFile",             STRING,   PidFile,              NULL),
  VAR("LongLivedPorts",      CSV,      LongLivedPorts,       "21,22,706,1863,5050,5190,5222,5223,6667,8300,8888"),
  VAR("PathlenCoinWeight",   DOUBLE,   PathlenCoinWeight,    "0.3"),
  VAR("RedirectExit",        LINELIST, RedirectExit,         NULL),
  OBSOLETE("RouterFile"),
  VAR("RunAsDaemon",         BOOL,     RunAsDaemon,          "0"),
  VAR("RunTesting",          BOOL,     RunTesting,           "0"),
  VAR("RecommendedVersions", LINELIST, RecommendedVersions,  NULL),
  VAR("RendNodes",           STRING,   RendNodes,            NULL),
  VAR("RendExcludeNodes",    STRING,   RendExcludeNodes,     NULL),
  VAR("SafeLogging",         BOOL,     SafeLogging,          "1"),
  VAR("ShutdownWaitLength",  INTERVAL, ShutdownWaitLength,   "30 seconds"),
  VAR("SocksPort",           UINT,     SocksPort,            "9050"),
  VAR("SocksBindAddress",    LINELIST, SocksBindAddress,     NULL),
  VAR("SocksPolicy",         LINELIST, SocksPolicy,          NULL),
  /** DOCDOC */
  VAR("StatusFetchPeriod",   INTERVAL, StatusFetchPeriod,    "0 seconds"),
  VAR("SysLog",              LINELIST_S, OldLogOptions,      NULL),
  OBSOLETE("TrafficShaping"),
  VAR("User",                STRING,   User,                 NULL),
  VAR("__LeaveStreamsUnattached", BOOL,LeaveStreamsUnattached, "0"),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};
#undef VAR
#undef OBSOLETE

/** Largest allowed config line */
#define CONFIG_LINE_T_MAXLEN 4096

static void config_line_append(struct config_line_t **lst,
                               const char *key, const char *val);
static void option_reset(or_options_t *options, config_var_t *var);
static void options_free(or_options_t *options);
static int option_is_same(or_options_t *o1, or_options_t *o2,const char *name);
static or_options_t *options_dup(or_options_t *old);
static int options_validate(or_options_t *options);
static int options_transition_allowed(or_options_t *old, or_options_t *new);
static int check_nickname_list(const char *lst, const char *name);
static void config_register_addressmaps(or_options_t *options);

static int parse_dir_server_line(const char *line, int validate_only);
static int parse_redirect_line(smartlist_t *result,
                               struct config_line_t *line);
static int parse_log_severity_range(const char *range, int *min_out,
                                    int *max_out);
static int convert_log_option(or_options_t *options,
                              struct config_line_t *level_opt,
                              struct config_line_t *file_opt, int isDaemon);
static int add_single_log_option(or_options_t *options, int minSeverity,
                                 int maxSeverity,
                                 const char *type, const char *fname);
static int normalize_log_options(or_options_t *options);
static int validate_data_directory(or_options_t *options);
static int write_configuration_file(const char *fname, or_options_t *options);

static uint64_t config_parse_memunit(const char *s, int *ok);
static int config_parse_interval(const char *s, int *ok);
static void print_cvs_version(void);
static int init_libevent(void);
#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
static void check_libevent_version(const char *m, const char *v, int server);
#endif

/*
 * Functions to read and write the global options pointer.
 */

/** Command-line and config-file options. */
static or_options_t *global_options=NULL;
/** Name of most recently read torrc file. */
static char *config_fname = NULL;

/** Return the currently configured options. */
or_options_t *
get_options(void) {
  tor_assert(global_options);
  return global_options;
}

/** Change the current global options to contain <b>new_val</b> instead
 * of their current value; free the old value as necessary.
 */
void
set_options(or_options_t *new_val) {
  if (global_options)
    options_free(global_options);
  global_options = new_val;
}

void
config_free_all(void)
{
  options_free(global_options);
  tor_free(config_fname);
}

/** If options->SafeLogging is on, return a not very useful string,
 * else return address.
 */
const char *
safe_str(const char *address) {
  if (get_options()->SafeLogging)
    return "[scrubbed]";
  else
    return address;
}

/** Fetch the active option list, and take actions based on it. All
 * of the things we do should survive being done repeatedly.
 * Return 0 if all goes well, return -1 if it's time to die.
 *
 * Note 1: <b>new_val</b> must have previously been validated with
 * options_validate(), or Tor may freak out and exit.
 *
 * Note 2: We haven't moved all the "act on new configuration" logic
 * here yet.  Some is still in do_hup() and other places.
 */
int
options_act(void) {
  struct config_line_t *cl;
  or_options_t *options = get_options();
  static int libevent_initialized = 0;

  /* XXXX009 We once had a reason to separate start_daemon and finish_daemon:
   *    It let us have the parent process stick around until we were sure Tor
   *    was started.  Should we make start_daemon get called earlier? -NM */
  if (options->RunAsDaemon) {
    start_daemon();
  }

  clear_trusted_dir_servers();
  for (cl = options->DirServers; cl; cl = cl->next) {
    if (parse_dir_server_line(cl->value, 0)<0) {
      log_fn(LOG_ERR,
             "Bug: Previously validated DirServer line could not be added!");
      return -1;
    }
  }

  if (rend_config_services(options, 0)<0) {
    log_fn(LOG_ERR,
           "Bug: Previously validated hidden services line could not be added!");
    return -1;
  }

  /* Setuid/setgid as appropriate */
  if (options->User || options->Group) {
    if (switch_id(options->User, options->Group) != 0) {
      return -1;
    }
  }

  /* Ensure data directory is private; create if possible. */
  if (check_private_dir(options->DataDirectory, CPD_CREATE) != 0) {
    log_fn(LOG_ERR, "Couldn't access/create private data directory %s",
           options->DataDirectory);
    return -1;
  }

  /* Bail out at this point if we're not going to be a server: we want
   * to not fork, and to log stuff to stderr. */
  if (options->command != CMD_RUN_TOR)
    return 0;

  mark_logs_temp(); /* Close current logs once new logs are open. */
  if (config_init_logs(options, 0)<0) /* Configure the log(s) */
    return -1;

  /* Close the temporary log we used while starting up, if it isn't already
   * gone. */
  close_temp_logs();
  add_callback_log(LOG_ERR, LOG_ERR, control_event_logmsg);
  adjust_event_log_severity();

  /* Set up libevent. */
  if (!libevent_initialized) {
    if (init_libevent())
      return -1;
    libevent_initialized = 1;
  }

  options->_ConnLimit =
    set_max_file_descriptors((unsigned)options->ConnLimit, MAXCONNECTIONS);
  if (options->_ConnLimit < 0)
    return -1;

  {
    smartlist_t *sl = smartlist_create();
    for (cl = options->RedirectExit; cl; cl = cl->next) {
      if (parse_redirect_line(sl, cl)<0)
        return -1;
    }
    set_exit_redirects(sl);
  }

  /* Finish backgrounding the process */
  if (options->RunAsDaemon) {
    /* We may be calling this for the n'th time (on SIGHUP), but it's safe. */
    finish_daemon(options->DataDirectory);
  }

  /* Write our pid to the pid file. If we do not have write permissions we
   * will log a warning */
  if (options->PidFile)
    write_pidfile(options->PidFile);

  /* Register addressmap directives */
  config_register_addressmaps(options);

  /* Update address policies. */
  parse_socks_policy();
  parse_dir_policy();

  init_cookie_authentication(options->CookieAuthentication);

  /* reload keys as needed for rendezvous services. */
  if (rend_service_load_keys()<0) {
    log_fn(LOG_ERR,"Error loading rendezvous service keys");
    return -1;
  }

  /* Set up accounting */
  if (accounting_parse_options(options, 0)<0) {
    log_fn(LOG_ERR,"Error in accounting options");
    return -1;
  }
  if (accounting_is_enabled(options))
    configure_accounting(time(NULL));

  if (!we_are_hibernating() && retry_all_listeners(1) < 0) {
    log_fn(LOG_ERR,"Failed to bind one of the listener ports.");
    return -1;
  }

#if 0
  {
    char *smin, *smax;
    smin = config_dump_options(options, 1);
    smax = config_dump_options(options, 0);
    log_fn(LOG_DEBUG, "These are our options:\n%s",smax);
    log_fn(LOG_DEBUG, "We changed these options:\n%s",smin);
    tor_free(smin);
    tor_free(smax);
  }
#endif

  /* Since our options changed, we might need to regenerate and upload our
   * server descriptor.  (We could probably be more clever about only calling
   * this when something significant changed.)
   */
  mark_my_descriptor_dirty();

  return 0;
}

/*
 * Functions to parse config options
 */

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
    if (!strcasecmp(option,config_abbrevs[i].abbreviated) &&
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
    } else if (!strcmp(argv[i],"--nt-service")) {
      i += 1;
      continue;
    }

    new = tor_malloc(sizeof(struct config_line_t));
    s = argv[i];

    while (*s == '-')
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
 * append it to *<b>lst</b>. */
static void
config_line_append(struct config_line_t **lst,
                   const char *key,
                   const char *val)
{
  struct config_line_t *newline;

  newline = tor_malloc(sizeof(struct config_line_t));
  newline->key = tor_strdup(key);
  newline->value = tor_strdup(val);
  newline->next = NULL;
  while (*lst)
    lst = &((*lst)->next);

  (*lst) = newline;
}

/** Helper: parse the config string and strdup into key/value
 * strings. Set *result to the list, or NULL if parsing the string
 * failed.  Return 0 on success, -1 on failure. Warn and ignore any
 * misformatted lines. */
int
config_get_lines(char *string, struct config_line_t **result)
{
  struct config_line_t *list = NULL, **next;
  char *k, *v;

  next = &list;
  do {
    string = parse_line_from_str(string, &k, &v);
    if (!string) {
      config_free_lines(list);
      return -1;
    }
    if (k && v) {
      /* This list can get long, so we keep a pointer to the end of it
       * rather than using config_line_append over and over and getting n^2
       * performance.  This is the only really long list. */
      *next = tor_malloc(sizeof(struct config_line_t));
      (*next)->key = tor_strdup(k);
      (*next)->value = tor_strdup(v);
      (*next)->next = NULL;
      next = &((*next)->next);
    }
  } while (*string);

  *result = list;
  return 0;
}

/**
 * Free all the configuration lines on the linked list <b>front</b>.
 */
void
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
  size_t keylen = strlen(key);
  if (!keylen)
    return NULL; /* if they say "--" on the commandline, it's not an option */
  /* First, check for an exact (case-insensitive) match */
  for (i=0; config_vars[i].name; ++i) {
    if (!strcasecmp(key, config_vars[i].name))
      return &config_vars[i];
  }
  /* If none, check for an abbreviated match */
  for (i=0; config_vars[i].name; ++i) {
    if (!strncasecmp(key, config_vars[i].name, keylen)) {
      log_fn(LOG_WARN, "The abbreviation '%s' is deprecated. "
          "Tell Nick and Roger to make it official, or just use '%s' instead",
             key, config_vars[i].name);
      return &config_vars[i];
    }
  }
  /* Okay, unrecognized options */
  return NULL;
}

/** If <b>c</b> is a syntactically valid configuration line, update
 * <b>options</b> with its value and return 0.  Otherwise return -1 for bad key,
 * -2 for bad value.
 *
 * If 'reset' is set, and we get a line containing no value, restore the
 * option to its default value.
 */
static int
config_assign_line(or_options_t *options, struct config_line_t *c, int reset)
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

  if (reset && !strlen(c->value)) {
    option_reset(options, var);
    return 0;
  }

  lvalue = ((char*)options) + var->var_offset;
  switch (var->type) {

  case CONFIG_TYPE_UINT:
    i = tor_parse_long(c->value, 10, 0, INT_MAX, &ok, NULL);
    if (!ok) {
      log(LOG_WARN, "Int keyword '%s %s' is malformed or out of bounds.",
          c->key,c->value);
      return -2;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_INTERVAL: {
    i = config_parse_interval(c->value, &ok);
    if (!ok) {
      return -2;
    }
    *(int *)lvalue = i;
    break;
  }

  case CONFIG_TYPE_MEMUNIT: {
    uint64_t u64 = config_parse_memunit(c->value, &ok);
    if (!ok) {
      return -2;
    }
    *(uint64_t *)lvalue = u64;
    break;
  }

  case CONFIG_TYPE_BOOL:
    i = tor_parse_long(c->value, 10, 0, 1, &ok, NULL);
    if (!ok) {
      log(LOG_WARN, "Boolean keyword '%s' expects 0 or 1.", c->key);
      return -2;
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
    if (*(smartlist_t**)lvalue) {
      SMARTLIST_FOREACH(*(smartlist_t**)lvalue, char *, cp, tor_free(cp));
      smartlist_clear(*(smartlist_t**)lvalue);
    } else {
      *(smartlist_t**)lvalue = smartlist_create();
    }

    smartlist_split_string(*(smartlist_t**)lvalue, c->value, ",",
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    break;

  case CONFIG_TYPE_LINELIST:
  case CONFIG_TYPE_LINELIST_S:
    config_line_append((struct config_line_t**)lvalue, c->key, c->value);
    break;

  case CONFIG_TYPE_OBSOLETE:
    log_fn(LOG_WARN, "Skipping obsolete configuration option '%s'", c->key);
    break;
  case CONFIG_TYPE_LINELIST_V:
    log_fn(LOG_WARN, "Can't provide value for virtual option '%s'", c->key);
    return -2;
  default:
    tor_assert(0);
    break;
  }
  return 0;
}

/** restore the option named <b>key</b> in options to its default value. */
static void
config_reset_line(or_options_t *options, const char *key)
{
  config_var_t *var;

  var = config_find_option(key);
  if (!var)
    return; /* give error on next pass. */

  option_reset(options, var);
}

/** Return true iff key is a valid configuration option. */
int
config_option_is_recognized(const char *key)
{
  config_var_t *var = config_find_option(key);
  return (var != NULL);
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
  tor_assert(options && key);

  var = config_find_option(key);
  if (!var) {
    log_fn(LOG_WARN, "Unknown option '%s'.  Failing.", key);
    return NULL;
  } else if (var->type == CONFIG_TYPE_LINELIST_S) {
    log_fn(LOG_WARN, "Can't return context-sensitive '%s' on its own", key);
    return NULL;
  }
  value = ((char*)options) + var->var_offset;

  if (var->type == CONFIG_TYPE_LINELIST ||
      var->type == CONFIG_TYPE_LINELIST_V) {
    /* Linelist requires special handling: we just copy and return it. */
    const struct config_line_t *next_in = *(const struct config_line_t**)value;
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
  switch (var->type)
    {
    case CONFIG_TYPE_STRING:
      if (*(char**)value) {
        result->value = tor_strdup(*(char**)value);
      } else {
        tor_free(result->key);
        tor_free(result);
        return NULL;
      }
      break;
    case CONFIG_TYPE_INTERVAL:
    case CONFIG_TYPE_UINT:
      /* This means every or_options_t uint or bool element
       * needs to be an int. Not, say, a uint16_t or char. */
      tor_snprintf(buf, sizeof(buf), "%d", *(int*)value);
      result->value = tor_strdup(buf);
      break;
    case CONFIG_TYPE_MEMUNIT:
      tor_snprintf(buf, sizeof(buf), U64_FORMAT,
                   U64_PRINTF_ARG(*(uint64_t*)value));
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
      if (*(smartlist_t**)value)
        result->value = smartlist_join_strings(*(smartlist_t**)value,",",0,NULL);
      else
        result->value = tor_strdup("");
      break;
    case CONFIG_TYPE_OBSOLETE:
      log_fn(LOG_WARN,"You asked me for the value of an obsolete config option %s.", key);
      tor_free(result->key);
      tor_free(result);
      return NULL;
    default:
      tor_free(result->key);
      tor_free(result);
      log_fn(LOG_WARN,"Bug: unknown type %d for known key %s", var->type, key);
      return NULL;
    }

  return result;
}

/** Iterate through the linked list of requested options <b>list</b>.
 * For each item, convert as appropriate and assign to <b>options</b>.
 * If an item is unrecognized, return -1 immediately,
 * else return 0 for success.
 *
 * If <b>reset</b>, then interpret empty lines as meaning "restore to
 * default value", and interpret LINELIST* options as replacing (not
 * extending) their previous values.  Return 0 on success, -1 on bad key,
 * -2 on bad value.
 */
static int
config_assign(or_options_t *options, struct config_line_t *list, int reset)
{
  struct config_line_t *p;
  tor_assert(options);

  /* pass 1: normalize keys */
  for (p = list; p; p = p->next) {
    const char *full = expand_abbrev(p->key, 0);
    if (strcmp(full,p->key)) {
      tor_free(p->key);
      p->key = tor_strdup(full);
    }
  }

  /* pass 2: if we're reading from a resetting source, clear all mentioned
   * linelists. */
  if (reset) {
    for (p = list; p; p = p->next)
      config_reset_line(options, p->key);
  }

  /* pass 3: assign. */
  while (list) {
    int r;
    if ((r=config_assign_line(options, list, reset)))
      return r;
    list = list->next;
  }
  return 0;
}

/** Try assigning <b>list</b> to the global options. You do this by duping
 * options, assigning list to the new one, then validating it. If it's
 * ok, then throw out the old one and stick with the new one. Else,
 * revert to old and return failure.  Return 0 on success, -1 on bad
 * keys, -2 on bad values, -3 on bad transition.
 */
int
config_trial_assign(struct config_line_t *list, int reset)
{
  int r;
  or_options_t *trial_options = options_dup(get_options());

  if ((r=config_assign(trial_options, list, reset)) < 0) {
    options_free(trial_options);
    return r;
  }

  if (options_validate(trial_options) < 0) {
    options_free(trial_options);
    return -2;
  }

  if (options_transition_allowed(get_options(), trial_options) < 0) {
    options_free(trial_options);
    return -3;
  }

  set_options(trial_options); /* we liked it. put it in place. */
  return 0;
}

/** Replace the option indexed by <b>var</b> in <b>options</b> with its
 * default value. */
static void
option_reset(or_options_t *options, config_var_t *var)
{
  struct config_line_t *c;
  void *lvalue;

  lvalue = ((char*)options) + var->var_offset;
  switch (var->type) {
    case CONFIG_TYPE_STRING:
      tor_free(*(char**)lvalue);
      break;
    case CONFIG_TYPE_DOUBLE:
      *(double*)lvalue = 0.0;
      break;
    case CONFIG_TYPE_INTERVAL:
    case CONFIG_TYPE_UINT:
    case CONFIG_TYPE_BOOL:
      *(int*)lvalue = 0;
      break;
    case CONFIG_TYPE_MEMUNIT:
      *(uint64_t*)lvalue = 0;
      break;
    case CONFIG_TYPE_CSV:
      if (*(smartlist_t**)lvalue) {
        SMARTLIST_FOREACH(*(smartlist_t **)lvalue, char *, cp, tor_free(cp));
        smartlist_free(*(smartlist_t **)lvalue);
        *(smartlist_t **)lvalue = NULL;
      }
      break;
    case CONFIG_TYPE_LINELIST:
    case CONFIG_TYPE_LINELIST_S:
      config_free_lines(*(struct config_line_t **)lvalue);
      *(struct config_line_t **)lvalue = NULL;
      break;
    case CONFIG_TYPE_LINELIST_V:
      /* handled by linelist_s. */
      break;
    case CONFIG_TYPE_OBSOLETE:
      break;
  }
  if (var->initvalue) {
    c = tor_malloc_zero(sizeof(struct config_line_t));
    c->key = tor_strdup(var->name);
    c->value = tor_strdup(var->initvalue);
    config_assign_line(options,c,0);
    config_free_lines(c);
  }
}

/** Set <b>options</b>-&gt;DirServers to contain the default directory
 * servers. */
static void
add_default_trusted_dirservers(or_options_t *options)
{
  /* moria1 */
  config_line_append(&options->DirServers, "DirServer",
       "18.244.0.188:9031 FFCB 46DB 1339 DA84 674C 70D7 CB58 6434 C437 0441");
  /* moria2 */
  config_line_append(&options->DirServers, "DirServer",
         "18.244.0.114:80 719B E45D E224 B607 C537 07D0 E214 3E2D 423E 74CF");
  /* tor26 */
  config_line_append(&options->DirServers, "DirServer",
     "86.59.21.38:80 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D");
//  "tor.noreply.org:9030 847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D");
}

/** Print a usage message for tor. */
static void
print_usage(void)
{
  printf(
"Copyright 2001-2005 Roger Dingledine, Nick Mathewson.\n\n"
"tor -f <torrc> [args]\n"
"See man page for options, or http://tor.eff.org/ for documentation.\n");
}

/**
 * Based on <b>options-\>Address</b>, guess our public IP address and put it
 * in *<b>addr</b>. Return 0 if all is well, or -1 if we can't find a
 * suitable public IP address.
 */
int
resolve_my_address(or_options_t *options, uint32_t *addr)
{
  struct in_addr in;
  struct hostent *rent;
  char hostname[256];
  int explicit_ip=1;
  char tmpbuf[INET_NTOA_BUF_LEN];
  static uint32_t old_addr=0;
  const char *address = options->Address;

  tor_assert(addr);

  /* workaround: some people were leaving "Address  " in their torrc,
   * and they had a buggy resolver that resolved " " to 0.0.0.0. Oops.
   */
  if (address)
    while (TOR_ISSPACE(*address))
      address++;

  if (address && *address) {
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

  tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
  if (is_internal_IP(htonl(in.s_addr)) && !options->NoPublish) {
    /* make sure we're ok with publishing an internal IP */
    if (!options->DirServers) {
      /* if they are using the default dirservers, disallow internal IPs always. */
      log_fn(LOG_WARN,"Address '%s' resolves to private IP '%s'. "
             "Tor servers that use the default DirServers must have public IP addresses.",
             hostname, tmpbuf);
      return -1;
    }
    if (!explicit_ip) {
      /* even if they've set their own dirservers, require an explicit IP if
       * they're using an internal address. */
      log_fn(LOG_WARN,"Address '%s' resolves to private IP '%s'. "
             "Please set the Address config option to be the IP you want to use.",
             hostname, tmpbuf);
      return -1;
    }
  }

  log_fn(LOG_DEBUG, "Resolved Address to %s.", tmpbuf);
  *addr = ntohl(in.s_addr);
  if (old_addr && old_addr != *addr) {
    log_fn(LOG_NOTICE,"Your IP seems to have changed. Updating.");
    server_has_changed_ip();
  }
  old_addr = *addr;
  return 0;
}

/** Called when we don't have a nickname set.  Try to guess a good
 * nickname based on the hostname, and return it in a newly allocated string. */
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
options_free(or_options_t *options)
{
  int i;
  void *lvalue;

  tor_assert(options);

  for (i=0; config_vars[i].name; ++i) {
    lvalue = ((char*)options) + config_vars[i].var_offset;
    switch (config_vars[i].type) {
      case CONFIG_TYPE_MEMUNIT:
      case CONFIG_TYPE_INTERVAL:
      case CONFIG_TYPE_UINT:
      case CONFIG_TYPE_BOOL:
      case CONFIG_TYPE_DOUBLE:
      case CONFIG_TYPE_OBSOLETE:
        break; /* nothing to free for these config types */
      case CONFIG_TYPE_STRING:
        tor_free(*(char **)lvalue);
        break;
      case CONFIG_TYPE_LINELIST:
      case CONFIG_TYPE_LINELIST_V:
        config_free_lines(*(struct config_line_t**)lvalue);
        *(struct config_line_t**)lvalue = NULL;
        break;
      case CONFIG_TYPE_CSV:
        if (*(smartlist_t**)lvalue) {
          SMARTLIST_FOREACH(*(smartlist_t**)lvalue, char *, cp, tor_free(cp));
          smartlist_free(*(smartlist_t**)lvalue);
          *(smartlist_t**)lvalue = NULL;
        }
        break;
      case CONFIG_TYPE_LINELIST_S:
        /* will be freed by corresponding LINELIST_V. */
        break;
    }
  }
  tor_free(options);
}

/** Return true iff the option <b>var</b> has the same value in <b>o1</b>
 * and <b>o2</b>.  Must not be called for LINELIST_S or OBSOLETE options.
 */
static int
option_is_same(or_options_t *o1, or_options_t *o2, const char *name)
{
  struct config_line_t *c1, *c2;
  int r = 1;
  c1 = config_get_assigned_option(o1, name);
  c2 = config_get_assigned_option(o2, name);
  while (c1 && c2) {
    if (strcasecmp(c1->key, c2->key) ||
        strcmp(c1->value, c2->value)) {
      r = 0;
      break;
    }
    c1 = c1->next;
    c2 = c2->next;
  }
  if (r && (c1 || c2)) {
    r = 0;
  }
  config_free_lines(c1);
  config_free_lines(c2);
  return r;
}

/** Copy storage held by <b>old</b> into a new or_options_t and return it. */
static or_options_t *
options_dup(or_options_t *old)
{
  or_options_t *newopts;
  int i;
  struct config_line_t *line;

  newopts = tor_malloc_zero(sizeof(or_options_t));
  for (i=0; config_vars[i].name; ++i) {
    if (config_vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    if (config_vars[i].type == CONFIG_TYPE_OBSOLETE)
      continue;
    line = config_get_assigned_option(old, config_vars[i].name);
    if (line) {
      if (config_assign(newopts, line, 0) < 0) {
        log_fn(LOG_WARN,"Bug: config_get_assigned_option() generated "
               "something we couldn't config_assign().");
        tor_assert(0);
      }
    }
    config_free_lines(line);
  }
  return newopts;
}

/** Set <b>options</b> to hold reasonable defaults for most options.
 * Each option defaults to zero. */
void
options_init(or_options_t *options)
{
  int i;
  config_var_t *var;

  for (i=0; config_vars[i].name; ++i) {
    var = &config_vars[i];
    if (!var->initvalue)
      continue; /* defaults to NULL or 0 */
    option_reset(options, var);
  }
}

/** Return a string containing a possible configuration file that would give
 * the configuration in <b>options</b>.  If <b>minimal</b> is true, do not
 * include options that are the same as Tor's defaults.
 */
char *
config_dump_options(or_options_t *options, int minimal)
{
  smartlist_t *elements;
  or_options_t *defaults;
  struct config_line_t *line;
  char *result;
  int i;

  defaults = tor_malloc_zero(sizeof(or_options_t));
  options_init(defaults);
  options_validate(defaults); /* ??? will this work? */

  elements = smartlist_create();
  for (i=0; config_vars[i].name; ++i) {
    if (config_vars[i].type == CONFIG_TYPE_OBSOLETE ||
        config_vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    /* Don't save 'hidden' control variables. */
    if (!strcmpstart(config_vars[i].name, "__"))
      continue;
    if (minimal && option_is_same(options, defaults, config_vars[i].name))
      continue;
    line = config_get_assigned_option(options, config_vars[i].name);
    for (; line; line = line->next) {
      size_t len = strlen(line->key) + strlen(line->value) + 3;
      char *tmp;
      tmp = tor_malloc(len);
      if (tor_snprintf(tmp, len, "%s %s\n", line->key, line->value)<0) {
        log_fn(LOG_ERR, "Internal error writing log option");
        tor_assert(0);
      }
      smartlist_add(elements, tmp);
    }
    config_free_lines(line);
  }

  result = smartlist_join_strings(elements, "", 0, NULL);
  SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
  smartlist_free(elements);
  return result;
}

static int
validate_ports_csv(smartlist_t *sl, const char *name) {
  int i;
  int result = 0;
  tor_assert(name);

  if (!sl)
    return 0;

  SMARTLIST_FOREACH(sl, const char *, cp,
  {
    i = atoi(cp);
    if (i < 1 || i > 65535) {
      log(LOG_WARN, "Port '%s' out of range in %s", cp, name);
      result=-1;
    }
  });
  return result;
}

/** Return 0 if every setting in <b>options</b> is reasonable.  Else
 * warn and return -1.  Should have no side effects, except for
 * normalizing the contents of <b>options</b>. */
static int
options_validate(or_options_t *options)
{
  int result = 0;
  struct config_line_t *cl;
  addr_policy_t *addr_policy=NULL;

  if (options->ORPort < 0 || options->ORPort > 65535) {
    log(LOG_WARN, "ORPort option out of bounds.");
    result = -1;
  }

  /* XXX might similarly want to check the other *BindAddress options */
  if (options->ORPort == 0 && options->ORBindAddress != NULL) {
    log(LOG_WARN, "ORPort must be defined if ORBindAddress is defined.");
    result = -1;
  }

  if (validate_data_directory(options)<0) {
    log(LOG_WARN, "Invalid DataDirectory");
    result = -1;
  }

  if (options->Nickname == NULL) {
    if (server_mode(options)) {
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

  if (server_mode(options) && !options->ContactInfo)
    log_fn(LOG_NOTICE,"Your ContactInfo config option is not set. Please consider setting it, so we can contact you if your server is misconfigured or something else goes wrong.");

  if (normalize_log_options(options))
    return -1;

  /* Special case if no options are given. */
  if (!options->Logs) {
    config_line_append(&options->Logs, "Log", "notice stdout");
  }

  if (config_init_logs(options, 1)<0) /* Validate the log(s) */
    return -1;

  if (server_mode(options)) {
    /* confirm that our address isn't broken, so we can complain now */
    uint32_t tmp;
    if (resolve_my_address(options, &tmp) < 0)
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

  if (options->ControlPort < 0 || options->ControlPort > 65535) {
    log(LOG_WARN, "ControlPort option out of bounds.");
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

  if (options->AuthoritativeDir && options->NoPublish) {
    log(LOG_WARN, "You cannot set both AuthoritativeDir and NoPublish.");
    result = -1;
  }

  if (options->ConnLimit <= 0) {
    log(LOG_WARN, "ConnLimit must be greater than 0, but was set to %d",
        options->ConnLimit);
    result = -1;
  }

  if (options->_AccountingMaxKB) {
    log(LOG_WARN, "AccountingMaxKB is deprecated.  Say 'AccountingMax %d KB' instead.", options->_AccountingMaxKB);
    options->AccountingMax = U64_LITERAL(1024)*options->_AccountingMaxKB;
    options->_AccountingMaxKB = 0;
  }

  if (validate_ports_csv(options->FirewallPorts,
                         "FirewallPorts") < 0)
    result = -1;

  if (validate_ports_csv(options->LongLivedPorts,
                         "LongLivedPorts") < 0)
    result = -1;

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
          result = -1;
        }
      });
  }

  if (options->SocksPort >= 1 &&
      (options->PathlenCoinWeight < 0.0 || options->PathlenCoinWeight >= 1.0)) {
    log(LOG_WARN, "PathlenCoinWeight option must be >=0.0 and <1.0.");
    result = -1;
  }

#define MIN_DIR_FETCH_PERIOD 600
#define MIN_DIR_POST_PERIOD 300
#define MIN_REND_POST_PERIOD 300
#define MIN_STATUS_FETCH_PERIOD 60

#define MAX_DIR_PERIOD (MIN_ONION_KEY_LIFETIME/2)
#define MAX_CACHE_DIR_FETCH_PERIOD 3600
#define MAX_CACHE_STATUS_FETCH_PERIOD 900

  if (options->DirFetchPeriod &&
      options->DirFetchPeriod < MIN_DIR_FETCH_PERIOD) {
    log(LOG_WARN, "DirFetchPeriod option must be at least %d seconds. Clipping.", MIN_DIR_FETCH_PERIOD);
    options->DirFetchPeriod = MIN_DIR_FETCH_PERIOD;
  }
  if (options->StatusFetchPeriod &&
      options->StatusFetchPeriod < MIN_STATUS_FETCH_PERIOD) {
    log(LOG_WARN, "StatusFetchPeriod option must be at least %d seconds. Clipping.", MIN_STATUS_FETCH_PERIOD);
    options->StatusFetchPeriod = MIN_STATUS_FETCH_PERIOD;
  }
  if (options->DirPostPeriod < MIN_DIR_POST_PERIOD) {
    log(LOG_WARN, "DirPostPeriod option must be at least %d seconds. Clipping.",
        MIN_DIR_POST_PERIOD);
    options->DirPostPeriod = MIN_DIR_POST_PERIOD;
  }
  if (options->RendPostPeriod < MIN_REND_POST_PERIOD) {
    log(LOG_WARN,"RendPostPeriod option must be at least %d seconds. Clipping.",
        MIN_REND_POST_PERIOD);
    options->RendPostPeriod = MIN_REND_POST_PERIOD;
  }

  if (options->DirPort && ! options->AuthoritativeDir) {
    if (options->DirFetchPeriod > MAX_CACHE_DIR_FETCH_PERIOD) {
      log(LOG_WARN, "Caching directory servers must have DirFetchPeriod less than %d seconds. Clipping.", MAX_CACHE_DIR_FETCH_PERIOD);
      options->DirFetchPeriod = MAX_CACHE_DIR_FETCH_PERIOD;
    }
    if (options->StatusFetchPeriod > MAX_CACHE_STATUS_FETCH_PERIOD) {
      log(LOG_WARN, "Caching directory servers must have StatusFetchPeriod less than %d seconds. Clipping.", MAX_CACHE_STATUS_FETCH_PERIOD);
      options->StatusFetchPeriod = MAX_CACHE_STATUS_FETCH_PERIOD;
    }
  }

  if (options->DirFetchPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, "DirFetchPeriod is too large; clipping.");
    options->DirFetchPeriod = MAX_DIR_PERIOD;
  }
  if (options->DirPostPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, "DirPostPeriod is too large; clipping.");
    options->DirPostPeriod = MAX_DIR_PERIOD;
  }
  if (options->StatusFetchPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, "StatusFetchPeriod is too large; clipping.");
    options->StatusFetchPeriod = MAX_DIR_PERIOD;
  }
  if (options->RendPostPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, "RendPostPeriod is too large; clipping.");
    options->RendPostPeriod = MAX_DIR_PERIOD;
  }

  if (options->KeepalivePeriod < 1) {
    log(LOG_WARN,"KeepalivePeriod option must be positive.");
    result = -1;
  }

  if (options->BandwidthRate > INT_MAX) {
    log(LOG_WARN,"BandwidthRate must be less than %d",INT_MAX);
    result = -1;
  }
  if (options->BandwidthBurst > INT_MAX) {
    log(LOG_WARN,"BandwidthBurst must be less than %d",INT_MAX);
    result = -1;
  }
  if (server_mode(options) &&
      options->BandwidthRate < ROUTER_REQUIRED_MIN_BANDWIDTH*2) {
    log(LOG_WARN,"BandwidthRate is set to %d bytes/second. For servers, it must be at least %d.", (int)options->BandwidthRate, ROUTER_REQUIRED_MIN_BANDWIDTH*2);
    result = -1;
  }
  if (options->BandwidthRate > options->BandwidthBurst) {
    log(LOG_WARN,"BandwidthBurst must be at least equal to BandwidthRate.");
    result = -1;
  }
#if 0
  if (2*options->BandwidthRate > options->BandwidthBurst) {
    log(LOG_NOTICE,"You have chosen a BandwidthBurst less than twice BandwidthRate. Please consider setting your BandwidthBurst higher (at least %d), to provide better service to the Tor network.", (int)(2*options->BandwidthRate));
  }
#endif

  if (options->_MonthlyAccountingStart) {
    if (options->AccountingStart) {
      log(LOG_WARN,"Can't specify AccountingStart and MonthlyAccountingStart");
      result = -1;
    } else {
      options->AccountingStart = tor_malloc(32);
      if (tor_snprintf(options->AccountingStart, 32, "month %d 0:00",
                       options->_MonthlyAccountingStart)<0) {
        log_fn(LOG_WARN,"Error translating MonthlyAccountingStart");
        result = -1;
      } else {
        log_fn(LOG_WARN,"MonthlyAccountingStart is deprecated.  Use 'AccountingStart %s' instead.", options->AccountingStart);
      }
    }
  }

  if (accounting_parse_options(options, 1)<0) {
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

  if (options->HttpProxyAuthenticator) {
    if (strlen(options->HttpProxyAuthenticator) >= 48) {
      log(LOG_WARN, "HttpProxyAuthenticator is too long (>= 48 chars).");
      result = -1;
    }
  }

  if (options->HttpsProxy) { /* parse it now */
    if (parse_addr_port(options->HttpsProxy, NULL,
                        &options->HttpsProxyAddr, &options->HttpsProxyPort) < 0) {
      log(LOG_WARN,"HttpsProxy failed to parse or resolve. Please fix.");
      result = -1;
    }
    if (options->HttpsProxyPort == 0) { /* give it a default */
      options->HttpsProxyPort = 443;
    }
  }

  if (options->HttpsProxyAuthenticator) {
    if (strlen(options->HttpsProxyAuthenticator) >= 48) {
      log(LOG_WARN, "HttpsProxyAuthenticator is too long (>= 48 chars).");
      result = -1;
    }
  }

  if (options->HashedControlPassword) {
    if (decode_hashed_password(NULL, options->HashedControlPassword)<0) {
      log_fn(LOG_WARN,"Bad HashedControlPassword: wrong length or bad encoding");
      result = -1;
    }
  }
  if (options->HashedControlPassword && options->CookieAuthentication) {
    log_fn(LOG_WARN,"Cannot enable both HashedControlPassword and CookieAuthentication");
    result = -1;
  }

  if (check_nickname_list(options->ExitNodes, "ExitNodes"))
    result = -1;
  if (check_nickname_list(options->EntryNodes, "EntryNodes"))
    result = -1;
  if (check_nickname_list(options->ExcludeNodes, "ExcludeNodes"))
    result = -1;
  if (check_nickname_list(options->RendNodes, "RendNodes"))
    result = -1;
  if (check_nickname_list(options->RendNodes, "RendExcludeNodes"))
    result = -1;
  if (check_nickname_list(options->MyFamily, "MyFamily"))
    result = -1;
  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (check_nickname_list(cl->value, "NodeFamily"))
      result = -1;
  }

  if (config_parse_addr_policy(options->ExitPolicy, &addr_policy)) {
    log_fn(LOG_WARN, "Error in Exit Policy entry.");
    result = -1;
  }
  config_append_default_exit_policy(&addr_policy);
  if (server_mode(options)) {
    exit_policy_implicitly_allows_local_networks(addr_policy, 1);
  }
  /* The rest of these calls *append* to addr_policy. So don't actually
   * use the results for anything other than checking if they parse! */
  if (config_parse_addr_policy(options->DirPolicy, &addr_policy)) {
    log_fn(LOG_WARN, "Error in DirPolicy entry.");
    result = -1;
  }
  if (config_parse_addr_policy(options->SocksPolicy, &addr_policy)) {
    log_fn(LOG_WARN, "Error in SocksPolicy entry.");
    result = -1;
  }
  addr_policy_free(addr_policy);

  for (cl = options->RedirectExit; cl; cl = cl->next) {
    if (parse_redirect_line(NULL, cl)<0)
      result = -1;
  }

  if (!options->DirServers) {
    add_default_trusted_dirservers(options);
  } else {
    for (cl = options->DirServers; cl; cl = cl->next) {
      if (parse_dir_server_line(cl->value, 1)<0)
        result = -1;
    }
  }

  if (rend_config_services(options, 1) < 0)
    result = -1;

  return result;
}

/** Helper: return true iff s1 and s2 are both NULL, or both non-NULL
 * equal strings. */
static int
opt_streq(const char *s1, const char *s2)
{
  if (!s1 && !s2)
    return 1;
  else if (s1 && s2 && !strcmp(s1,s2))
    return 1;
  else
    return 0;
}

/** Check if any of the previous options have changed but aren't allowed to. */
static int
options_transition_allowed(or_options_t *old, or_options_t *new_val) {

  if (!old)
    return 0;

  if (!opt_streq(old->PidFile, new_val->PidFile)) {
    log_fn(LOG_WARN,"PidFile is not allowed to change. Failing.");
    return -1;
  }

  if (old->RunAsDaemon != new_val->RunAsDaemon) {
    log_fn(LOG_WARN,"During reload, changing RunAsDaemon is not allowed. Failing.");
    return -1;
  }

  if (old->ORPort != new_val->ORPort) {
    log_fn(LOG_WARN,"During reload, changing ORPort is not allowed. Please upgrade to 0.1.1.6-alpha or later. Failing.");
    return -1;
  }

  if (strcmp(old->DataDirectory,new_val->DataDirectory)!=0) {
    log_fn(LOG_WARN,"During reload, changing DataDirectory (%s->%s) is not allowed. Failing.", old->DataDirectory, new_val->DataDirectory);
    return -1;
  }

  if (!opt_streq(old->User, new_val->User)) {
    log_fn(LOG_WARN,"During reload, changing User is not allowed. Failing.");
    return -1;
  }

  if (!opt_streq(old->Group, new_val->Group)) {
    log_fn(LOG_WARN,"During reload, changing Group is not allowed. Failing.");
    return -1;
  }

  return 0;
}

#ifdef MS_WINDOWS
/** Return the directory on windows where we expect to find our application
 * data. */
static char *get_windows_conf_root(void)
{
  static int is_set = 0;
  static char path[MAX_PATH+1];

  LPITEMIDLIST idl;
  IMalloc *m;
  HRESULT result;

  if (is_set)
    return path;

  /* Find X:\documents and settings\username\application data\ .
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

/** Return the default location for our torrc file. */
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
 * validate them for consistency, then take actions based on them.
 * Return 0 if success, -1 if failure. */
int
init_from_config(int argc, char **argv)
{
  or_options_t *oldoptions, *newoptions;
  struct config_line_t *cl;
  char *cf=NULL, *fname=NULL;
  int i, retval;
  int using_default_torrc;
  static char **backup_argv;
  static int backup_argc;

  if (argv) { /* first time we're called. save commandline args */
    backup_argv = argv;
    backup_argc = argc;
    oldoptions = NULL;
  } else { /* we're reloading. need to clean up old options first. */
    argv = backup_argv;
    argc = backup_argc;
    oldoptions = get_options();
  }
  if (argc > 1 && (!strcmp(argv[1], "-h") || !strcmp(argv[1],"--help"))) {
    print_usage();
    exit(0);
  }

  if (argc > 1 && (!strcmp(argv[1],"--version"))) {
    printf("Tor version %s.\n",VERSION);
    if (argc > 2 && (!strcmp(argv[2],"--version"))) {
      print_cvs_version();
    }
    exit(0);
  }

  newoptions = tor_malloc_zero(sizeof(or_options_t));
  options_init(newoptions);

  /* learn config file name, get config lines, assign them */
  fname = NULL;
  using_default_torrc = 1;
  newoptions->command = CMD_RUN_TOR;
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
      newoptions->command = CMD_LIST_FINGERPRINT;
    } else if (!strcmp(argv[i],"--hash-password")) {
      newoptions->command = CMD_HASH_PASSWORD;
      newoptions->command_arg = tor_strdup( (i < argc-1) ? argv[i+1] : "");
      ++i;
    } else if (!strcmp(argv[i],"--verify-config")) {
      newoptions->command = CMD_VERIFY_CONFIG;
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
#ifndef MS_WINDOWS
      fn = expand_filename("~/.torrc");
      if (fn && file_status(fn) == FN_FILE) {
        fname = fn;
      } else {
        tor_free(fn);
        fname = get_default_conf_file();
      }
#else
      fname = get_default_conf_file();
#endif
    }
  }
  tor_assert(fname);
  log(LOG_DEBUG, "Opening config file '%s'", fname);

  if (file_status(fname) != FN_FILE ||
      !(cf = read_file_to_str(fname,0))) {
    if (using_default_torrc == 1) {
      log(LOG_NOTICE, "Configuration file '%s' not present, "
          "using reasonable defaults.", fname);
      tor_free(fname); /* sets fname to NULL */
    } else {
      log(LOG_WARN, "Unable to open configuration file '%s'.", fname);
      tor_free(fname);
      goto err;
    }
  } else { /* it opened successfully. use it. */
    retval = config_get_lines(cf, &cl);
    tor_free(cf);
    if (retval < 0)
      goto err;
    retval = config_assign(newoptions, cl, 0);
    config_free_lines(cl);
    if (retval < 0)
      goto err;
  }

  /* Go through command-line variables too */
  cl = config_get_commandlines(argc,argv);
  retval = config_assign(newoptions,cl,0);
  config_free_lines(cl);
  if (retval < 0)
    goto err;

  /* Validate newoptions */
  if (options_validate(newoptions) < 0)
    goto err;

  if (options_transition_allowed(oldoptions, newoptions) < 0)
    goto err;

  set_options(newoptions); /* frees and replaces old options */
  if (options_act() < 0) { /* acting on them failed. die. */
    log_fn(LOG_ERR,"Acting on config options left us in a broken state. Dying.");
    exit(1);
  }
  tor_free(config_fname);
  config_fname = fname;
  return 0;
 err:
  tor_free(fname);
  options_free(newoptions);
  return -1;
}

static void
config_register_addressmaps(or_options_t *options) {
  smartlist_t *elts;
  struct config_line_t *opt;
  char *from, *to;

  addressmap_clear_configured();
  elts = smartlist_create();
  for (opt = options->AddressMap; opt; opt = opt->next) {
    smartlist_split_string(elts, opt->value, NULL,
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 2);
    if (smartlist_len(elts) >= 2) {
      from = smartlist_get(elts,0);
      to = smartlist_get(elts,1);
      if (!is_plausible_address(from)) {
        log_fn(LOG_WARN,"Skipping invalid argument '%s' to MapAddress",from);
      } else if (!is_plausible_address(to)) {
        log_fn(LOG_WARN,"Skipping invalid argument '%s' to MapAddress",to);
      } else {
        addressmap_register(from, tor_strdup(to), 0);
        if (smartlist_len(elts)>2) {
          log_fn(LOG_WARN,"Ignoring extra arguments to MapAddress.");
        }
      }
    } else {
      log_fn(LOG_WARN,"MapAddress '%s' has too few arguments. Ignoring.", opt->value);
    }
    SMARTLIST_FOREACH(elts, char*, cp, tor_free(cp));
    smartlist_clear(elts);
  }
  smartlist_free(elts);
}

/** If <b>range</b> is of the form MIN-MAX, for MIN and MAX both
 * recognized log severity levels, set *<b>min_out</b> to MIN and
 * *<b>max_out</b> to MAX and return 0.  Else, if <b>range</b> is of
 * the form MIN, act as if MIN-err had been specified.  Else, warn and
 * return -1.
 */
static int
parse_log_severity_range(const char *range, int *min_out, int *max_out)
{
  int levelMin, levelMax;
  const char *cp;
  cp = strchr(range, '-');
  if (cp) {
    if (cp == range) {
      levelMin = LOG_DEBUG;
    } else {
      char *tmp_sev = tor_strndup(range, cp - range);
      levelMin = parse_log_level(tmp_sev);
      if (levelMin < 0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
               "err|warn|notice|info|debug", tmp_sev);
        tor_free(tmp_sev);
        return -1;
      }
      tor_free(tmp_sev);
    }
    if (!*(cp+1)) {
      levelMax = LOG_ERR;
    } else {
      levelMax = parse_log_level(cp+1);
      if (levelMax < 0) {
        log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
               "err|warn|notice|info|debug", cp+1);
        return -1;
      }
    }
  } else {
    levelMin = parse_log_level(range);
    if (levelMin < 0) {
      log_fn(LOG_WARN, "Unrecognized log severity '%s': must be one of "
             "err|warn|notice|info|debug", range);
      return -1;
    }
    levelMax = LOG_ERR;
  }

  *min_out = levelMin;
  *max_out = levelMax;

  return 0;
}

/** Try to convert a pair of old-style logging options [LogLevel, and
 * (LogFile/Syslog)] to a new-style option, and add the new option to
 * options->Logs. */
static int
convert_log_option(or_options_t *options, struct config_line_t *level_opt,
                   struct config_line_t *file_opt, int isDaemon)
{
  int levelMin = -1, levelMax = -1;

  if (level_opt) {
    if (parse_log_severity_range(level_opt->value, &levelMin, &levelMax))
      return -1;
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
    if (add_single_log_option(options, levelMin, levelMax, "file", file_opt->value) < 0) {
      log_fn(LOG_WARN, "Cannot write to LogFile '%s': %s.", file_opt->value,
             strerror(errno));
      return -1;
    }
  } else if (file_opt && !strcasecmp(file_opt->key, "SysLog")) {
    if (add_single_log_option(options, levelMin, levelMax, "syslog", NULL) < 0)
      return -1;
  } else if (!isDaemon) {
    add_single_log_option(options, levelMin, levelMax, "stdout", NULL);
  }
  return 0;
}

/**
 * Initialize the logs based on the configuration file.
 */
int
config_init_logs(or_options_t *options, int validate_only)
{
  struct config_line_t *opt;
  int ok;
  smartlist_t *elts;

  ok = 1;
  elts = smartlist_create();
  for (opt = options->Logs; opt; opt = opt->next) {
    int levelMin=LOG_DEBUG, levelMax=LOG_ERR;
    smartlist_split_string(elts, opt->value, NULL,
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 3);
    if (smartlist_len(elts) == 0) {
      log_fn(LOG_WARN, "Bad syntax on Log option 'Log %s'", opt->value);
      ok = 0; goto cleanup;
    }
    if (parse_log_severity_range(smartlist_get(elts,0), &levelMin, &levelMax)) {
      ok = 0; goto cleanup;
    }
    if (smartlist_len(elts) < 2) { /* only loglevels were provided */
      if (!validate_only)
        add_stream_log(levelMin, levelMax, "<stdout>", stdout);
      goto cleanup;
    }
    if (!strcasecmp(smartlist_get(elts,1), "file")) {
      if (smartlist_len(elts) != 3) {
        log_fn(LOG_WARN, "Bad syntax on Log option 'Log %s'", opt->value);
        ok = 0; goto cleanup;
      }
      if (!validate_only)
        add_file_log(levelMin, levelMax, smartlist_get(elts, 2));
      goto cleanup;
    }
    if (smartlist_len(elts) != 2) {
      log_fn(LOG_WARN, "Bad syntax on Log option 'Log %s'", opt->value);
      ok = 0; goto cleanup;
    }
    if (!strcasecmp(smartlist_get(elts,1), "stdout")) {
      if (!validate_only) {
        add_stream_log(levelMin, levelMax, "<stdout>", stdout);
        close_temp_logs();
      }
    } else if (!strcasecmp(smartlist_get(elts,1), "stderr")) {
      if (!validate_only) {
        add_stream_log(levelMin, levelMax, "<stderr>", stderr);
        close_temp_logs();
      }
    } else if (!strcasecmp(smartlist_get(elts,1), "syslog")) {
#ifdef HAVE_SYSLOG_H
      if (!validate_only)
        add_syslog_log(levelMin, levelMax);
#else
      log_fn(LOG_WARN, "Syslog is not supported in this compilation.");
#endif
    } else {
      log_fn(LOG_WARN, "Unrecognized log type %s",
             (const char*)smartlist_get(elts,1));
      if (strchr(smartlist_get(elts,1), '/')) {
        log_fn(LOG_WARN, "Did you mean to say 'Log file %s' ?",
               (const char *)smartlist_get(elts,1));
      }
      ok = 0; goto cleanup;
    }
  cleanup:
    SMARTLIST_FOREACH(elts, char*, cp, tor_free(cp));
    smartlist_clear(elts);
  }
  smartlist_free(elts);
  if (!validate_only)
    close_temp_logs();

  return ok?0:-1;
}

/** Add a single option of the form Log min-max \<type\> [fname] to options. */
static int
add_single_log_option(or_options_t *options, int minSeverity, int maxSeverity,
                      const char *type, const char *fname)
{
  char buf[512];
  int n;

  n = tor_snprintf(buf, sizeof(buf), "%s%s%s %s%s%s",
                   log_level_to_string(minSeverity),
                   maxSeverity == LOG_ERR ? "" : "-",
                   maxSeverity == LOG_ERR ? "" : log_level_to_string(maxSeverity),
                   type, fname?" ":"", fname?fname:"");
  if (n<0) {
    log_fn(LOG_WARN, "Normalized log option too long.");
    return -1;
  }

  log(LOG_WARN, "The old LogLevel/LogFile/DebugLogFile/SysLog options are deprecated, and will go away soon.  Your new torrc line should be: 'Log %s'", buf);
  config_line_append(&options->Logs, "Log", buf);
  return 0;
}

/** Convert all old-style logging options to new-style Log options. Return 0
 * on success, -1 on failure. */
static int
normalize_log_options(or_options_t *options)
{
  /* The order of options is:  Level? (File Level?)+
   */
  struct config_line_t *opt = options->OldLogOptions;

  /* Special case for if first option is LogLevel. */
  if (opt && !strcasecmp(opt->key, "LogLevel")) {
    if (opt->next && (!strcasecmp(opt->next->key, "LogFile") ||
                      !strcasecmp(opt->next->key, "SysLog"))) {
      if (convert_log_option(options, opt, opt->next, options->RunAsDaemon) < 0)
        return -1;
      opt = opt->next->next;
    } else if (!opt->next) {
      if (convert_log_option(options, opt, NULL, options->RunAsDaemon) < 0)
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
        if (convert_log_option(options,opt->next,opt, options->RunAsDaemon) < 0)
          return -1;
        opt = opt->next->next;
      } else {
        /* LogFile/SysLog followed by LogFile/SysLog or end of list. */
        if (convert_log_option(options,NULL, opt, options->RunAsDaemon) < 0)
          return -1;
        opt = opt->next;
      }
    }
  }

  if (options->DebugLogFile) {
    if (add_single_log_option(options, LOG_DEBUG, LOG_ERR, "file", options->DebugLogFile) < 0)
      return -1;
  }

  tor_free(options->DebugLogFile);
  config_free_lines(options->OldLogOptions);
  options->OldLogOptions = NULL;

  return 0;
}

#define DEFAULT_EXIT_POLICY "reject 0.0.0.0/8,reject 169.254.0.0/16,reject 127.0.0.0/8,reject 192.168.0.0/16,reject 10.0.0.0/8,reject 172.16.0.0/12,reject *:25,reject *:119,reject *:135-139,reject *:445,,reject *:465,reject *:587,reject *:1214,reject *:4661-4666,reject *:6346-6429,reject *:6699,reject *:6881-6999,accept *:*"

void
config_append_default_exit_policy(addr_policy_t **policy)
{
  struct config_line_t tmp;
  addr_policy_t *ap;

  tmp.key = NULL;
  tmp.value = (char*)DEFAULT_EXIT_POLICY;
  tmp.next = NULL;
  config_parse_addr_policy(&tmp, policy);

  /* Remove redundant parts, if any. */
  for (ap=*policy; ap; ap=ap->next) {
    if (ap->msk == 0 && ap->prt_min <= 1 && ap->prt_max >= 65535) {
      if (ap->next) {
        addr_policy_free(ap->next);
        ap->next = NULL;
      }
      return;
    }
  }
}

/**
 * Given a linked list of config lines containing "allow" and "deny" tokens,
 * parse them and append the result to <b>dest</b>.  Return -1 if any tokens
 * are malformed, else return 0.
 */
int
config_parse_addr_policy(struct config_line_t *cfg,
                         addr_policy_t **dest)
{
  addr_policy_t **nextp;
  smartlist_t *entries;
  int r = 0;

  if (!cfg)
    return 0;

  nextp = dest;

  while (*nextp)
    nextp = &((*nextp)->next);

  entries = smartlist_create();
  for (; cfg; cfg = cfg->next) {
    smartlist_split_string(entries, cfg->value, ",", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
    SMARTLIST_FOREACH(entries, const char *, ent,
    {
      log_fn(LOG_DEBUG,"Adding new entry '%s'",ent);
      *nextp = router_parse_addr_policy_from_string(ent);
      if (*nextp) {
        nextp = &((*nextp)->next);
      } else {
        log_fn(LOG_WARN,"Malformed policy '%s'.", ent);
        r = -1;
      }
    });
    SMARTLIST_FOREACH(entries, char *, ent, tor_free(ent));
    smartlist_clear(entries);
  }
  smartlist_free(entries);
  return r;
}

/** Release all storage held by <b>p</b> */
void
addr_policy_free(addr_policy_t *p) {
  addr_policy_t *e;

  while (p) {
    e = p;
    p = p->next;
    tor_free(e->string);
    tor_free(e);
  }
}

/** Parse a single RedirectExit line's contents from <b>line</b>.  If
 *  they are valid, and <b>result</b> is not NULL, add an element to
 *  <b>result</b> and return 0. Else if they are valid, return 0.
 *  Else return -1. */
static int
parse_redirect_line(smartlist_t *result, struct config_line_t *line)
{
  smartlist_t *elements = NULL;
  exit_redirect_t *r;

  tor_assert(line);

  r = tor_malloc_zero(sizeof(exit_redirect_t));
  elements = smartlist_create();
  smartlist_split_string(elements, line->value, NULL,
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
      log_fn(LOG_WARN, "Error parsing dest address in RedirectExit line");
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
    if (result)
      smartlist_add(result, r);
    else
      tor_free(r);
    return 0;
  } else {
    return -1;
  }
}

/** Read the contents of a DirServer line from <b>line</b>.  Return 0
 * if the line is well-formed, and -1 if it isn't.  If
 * <b>validate_only</b> is 0, and the line is well-formed, then add
 * the dirserver described in the line as a valid server. */
static int
parse_dir_server_line(const char *line, int validate_only)
{
  smartlist_t *items = NULL;
  int r;
  char *addrport, *address=NULL;
  uint16_t port;
  char digest[DIGEST_LEN];

  items = smartlist_create();
  smartlist_split_string(items, line, NULL,
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
    log_fn(LOG_WARN, "Missing port in DirServer address '%s'",addrport);
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

  if (!validate_only) {
    log_fn(LOG_DEBUG, "Trusted dirserver at %s:%d (%s)", address, (int)port,
           (char*)smartlist_get(items,1));
    add_trusted_dir_server(address, port, digest);
  }

  r = 0;
  goto done;

  err:
  r = -1;

  done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  tor_free(address);
  return r;
}

/** Adjust the value of options->DataDirectory, or fill it in if it's
 * absent. Return 0 on success, -1 on failure. */
static int
normalize_data_directory(or_options_t *options) {
#ifdef MS_WINDOWS
  char *p;
  if (options->DataDirectory)
    return 0; /* all set */
  p = tor_malloc(MAX_PATH);
  strlcpy(p,get_windows_conf_root(),MAX_PATH);
  options->DataDirectory = p;
  return 0;
#else
  const char *d = options->DataDirectory;
  if (!d)
    d = "~/.tor";

 if (strncmp(d,"~/",2) == 0) {
   char *fn = expand_filename(d);
   if (!fn) {
     log_fn(LOG_ERR,"Failed to expand filename '%s'.", d);
     return -1;
   }
   if (!options->DataDirectory && !strcmp(fn,"/.tor")) {
     /* If our homedir is /, we probably don't want to use it. */
     /* XXXX Default to /var/lib/tor? */
     log_fn(LOG_WARN, "Default DataDirectory is ~/.tor, which works out to %s, which is probably not what you want.  Using %s/tor instead", fn, LOCALSTATEDIR);
     tor_free(fn);
     fn = tor_strdup(LOCALSTATEDIR"/tor");

   }
   tor_free(options->DataDirectory);
   options->DataDirectory = fn;
 }
 return 0;
#endif
}

/** Check and normalize the value of options->DataDirectory; return 0 if it
 * sane, -1 otherwise. */
static int
validate_data_directory(or_options_t *options) {
  if (normalize_data_directory(options) < 0)
    return -1;
  tor_assert(options->DataDirectory);
  if (strlen(options->DataDirectory) > (512-128)) {
    log_fn(LOG_ERR, "DataDirectory is too long.");
    return -1;
  }
#if 0
  if (check_private_dir(options->DataDirectory, CPD_CHECK != 0)) {
    log_fn(LOG_WARN, "Can't create directory %s", options->DataDirectory);
    return -1;
  }
#endif
  return 0;
}

#define GENERATED_FILE_PREFIX "# This file was generated by Tor; if you edit it, comments will not be preserved"

/** Save a configuration file for the configuration in <b>options</b>
 * into the file <b>fname</b>.  If the file already exists, and
 * doesn't begin with GENERATED_FILE_PREFIX, rename it.  Otherwise
 * replace it.  Return 0 on success, -1 on failure. */
static int
write_configuration_file(const char *fname, or_options_t *options)
{
  char *old_val=NULL, *new_val=NULL, *new_conf=NULL;
  int rename_old = 0, r;
  size_t len;

  if (fname) {
    switch (file_status(fname)) {
      case FN_FILE:
        old_val = read_file_to_str(fname, 0);
        if (strcmpstart(old_val, GENERATED_FILE_PREFIX)) {
          rename_old = 1;
        }
        tor_free(old_val);
        break;
      case FN_NOENT:
        break;
      default:
        log_fn(LOG_WARN,"Config file %s is not a file? Failing.", fname);
        return -1;
    }
  }

  if (!(new_conf = config_dump_options(options, 1))) {
    log_fn(LOG_WARN, "Couldn't get configuration string");
    goto err;
  }

  len = strlen(new_conf)+128;
  new_val = tor_malloc(len);
  tor_snprintf(new_val, len, "%s\n\n%s", GENERATED_FILE_PREFIX, new_conf);

  if (rename_old) {
    int i = 1;
    size_t fn_tmp_len = strlen(fname)+32;
    char *fn_tmp;
    tor_assert(fn_tmp_len > strlen(fname)); /*check for overflow*/
    fn_tmp = tor_malloc(fn_tmp_len);
    while (1) {
      if (tor_snprintf(fn_tmp, fn_tmp_len, "%s.orig.%d", fname, i)<0) {
        log_fn(LOG_WARN, "tor_snprintf failed inexplicably");
        tor_free(fn_tmp);
        goto err;
      }
      if (file_status(fn_tmp) == FN_NOENT)
        break;
      ++i;
    }
    log_fn(LOG_NOTICE, "Renaming old configuration file to %s", fn_tmp);
    rename(fname, fn_tmp);
    tor_free(fn_tmp);
  }

  write_str_to_file(fname, new_val, 0);

  r = 0;
  goto done;
 err:
  r = -1;
 done:
  tor_free(new_val);
  tor_free(new_conf);
  return r;
}

/**
 * Save the current configuration file value to disk.  Return 0 on
 * success, -1 on failure.
 **/
int
save_current_config(void)
{
  char *fn;
  if (config_fname) {
    /* XXX This fails if we can't write to our configuration file.
     *   Arguably, we should try falling back to datadirectory or something.
     *   But just as arguably, we shouldn't. */
    return write_configuration_file(config_fname, get_options());
  }
  fn = get_default_conf_file();
  return write_configuration_file(fn, get_options());
}

struct unit_table_t {
  const char *unit;
  uint64_t multiplier;
};

static struct unit_table_t memory_units[] = {
  { "",          1 },
  { "b",         1<< 0 },
  { "byte",      1<< 0 },
  { "bytes",     1<< 0 },
  { "kb",        1<<10 },
  { "kilobyte",  1<<10 },
  { "kilobytes", 1<<10 },
  { "m",         1<<20 },
  { "mb",        1<<20 },
  { "megabyte",  1<<20 },
  { "megabytes", 1<<20 },
  { "gb",        1<<30 },
  { "gigabyte",  1<<30 },
  { "gigabytes", 1<<30 },
  { "tb",        U64_LITERAL(1)<<40 },
  { "terabyte",  U64_LITERAL(1)<<40 },
  { "terabytes", U64_LITERAL(1)<<40 },
  { NULL, 0 },
};

static struct unit_table_t time_units[] = {
  { "",         1 },
  { "second",   1 },
  { "seconds",  1 },
  { "minute",   60 },
  { "minutes",  60 },
  { "hour",     60*60 },
  { "hours",    60*60 },
  { "day",      24*60*60 },
  { "days",     24*60*60 },
  { "week",     7*24*60*60 },
  { "weeks",    7*24*60*60 },
  { NULL, 0 },
};

/** Parse a string <b>val</b> containing a number, zero or more
 * spaces, and an optional unit string.  If the unit appears in the
 * table <b>u</b>, then multiply the number by the unit multiplier.
 * On success, set *<b>ok</b> to 1 and return this product.
 * Otherwise, set *<b>ok</b> to 0.
 */
static uint64_t
config_parse_units(const char *val, struct unit_table_t *u, int *ok)
{
  uint64_t v;
  char *cp;

  tor_assert(ok);

  v = tor_parse_uint64(val, 10, 0, UINT64_MAX, ok, &cp);
  if (!*ok)
    return 0;
  if (!cp) {
    *ok = 1;
    return v;
  }
  while (TOR_ISSPACE(*cp))
    ++cp;
  for ( ;u->unit;++u) {
    if (!strcasecmp(u->unit, cp)) {
      v *= u->multiplier;
      *ok = 1;
      return v;
    }
  }
  log_fn(LOG_WARN, "Unknown unit '%s'.", cp);
  *ok = 0;
  return 0;
}

/** Parse a string in the format "number unit", where unit is a unit of
 * information (byte, KB, M, etc).  On success, set *<b>ok</b> to true
 * and return the number of bytes specified.  Otherwise, set
 * *<b>ok</b> to false and return 0. */
static uint64_t
config_parse_memunit(const char *s, int *ok) {
  return config_parse_units(s, memory_units, ok);
}

/** Parse a string in the format "number unit", where unit is a unit of time.
 * On success, set *<b>ok</b> to true and return the number of seconds in
 * the provided interval.  Otherwise, set *<b>ok</b> to 0 and return -1.
 */
static int
config_parse_interval(const char *s, int *ok) {
  uint64_t r;
  r = config_parse_units(s, time_units, ok);
  if (!ok)
    return -1;
  if (r > INT_MAX) {
    log_fn(LOG_WARN, "Interval '%s' is too long", s);
    *ok = 0;
    return -1;
  }
  return (int)r;
}

/**
 * Initialize the libevent library.
 */
static int
init_libevent(void)
{
  configure_libevent_logging();
  /* If the kernel complains that some method (say, epoll) doesn't
   * exist, we don't care about it, since libevent will cope.
   */
  suppress_libevent_log_msg("Function not implemented");
#ifdef __APPLE__
  putenv("EVENT_NOKQUEUE=1");
#endif
  event_init();
  suppress_libevent_log_msg(NULL);
#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
  /* Making this a NOTICE for now so we can link bugs to a libevent versions
   * or methods better. */
  log(LOG_NOTICE, "Initialized libevent version %s using method %s",
      event_get_version(), event_get_method());
  check_libevent_version(event_get_method(), event_get_version(),
                         get_options()->ORPort != 0);
#else
  log(LOG_NOTICE, "Initialized old libevent (version 1.0b or earlier)");
  log(LOG_WARN, "You have a very old version of libevent.  It is likely to be buggy; please consider building Tor with a more recent version.");
#endif

  return 0;
}

#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
/**
 * Compare the given libevent method and version to a list of versions
 * which are known not to work.  Warn the user as appropriate.
 *
 */
static void
check_libevent_version(const char *m, const char *v, int server)
{
  int buggy = 0, iffy = 0, slow = 0;

  tor_assert(m && v);

  if (!strcmp(m, "kqueue")) {
    if (!strcmp(v, "1.0c") || !strcmp(v, "1.0d") || !strcmp(v, "1.0e") ||
        !strcmp(v, "1.1")) {
      buggy = 1;
    }
  } else if (!strcmp(m, "epoll")) {
    if (!strcmp(v, "1.0c") || !strcmp(v, "1.0d") || !strcmp(v, "1.0e"))
      iffy = 1;
  } else if (!strcmp(m, "poll")) {
    if (!strcmp(v, "1.0c") || !strcmp(v, "1.0d"))
      buggy = 1;
    else if (!strcmp(v, "1.0e"))
      slow = 1;
  } else if (!strcmp(m, "poll")) {
    if (!strcmp(v, "1.0c") || !strcmp(v, "1.0d") || !strcmp(v, "1.0e"))
      slow = 1;
  }

  if (buggy) {
    log(LOG_WARN,
        "There are known bugs in using %s with libevent %s. "
        "Please use the latest version of libevent.", m, v);
  } else if (iffy) {
    log(LOG_WARN,
        "There are minor bugs in using %s with libevent %s. "
        "You may want to use the latest version of libevent.", m, v);
  } else if (slow && server) {
    log(LOG_WARN,
        "libevent %s can be very slow with %s. "
      "When running a server, please use the latest version of libevent.",v,m);
  }

}
#endif

static void
print_cvs_version(void)
{
  extern const char aes_c_id[];
  extern const char compat_c_id[];
  extern const char container_c_id[];
  extern const char crypto_c_id[];
  extern const char log_c_id[];
  extern const char torgzip_c_id[];
  extern const char tortls_c_id[];
  extern const char util_c_id[];

  extern const char buffers_c_id[];
  extern const char circuitbuild_c_id[];
  extern const char circuitlist_c_id[];
  extern const char circuituse_c_id[];
  extern const char command_c_id[];
//  extern const char config_c_id[];
  extern const char connection_c_id[];
  extern const char connection_edge_c_id[];
  extern const char connection_or_c_id[];
  extern const char control_c_id[];
  extern const char cpuworker_c_id[];
  extern const char directory_c_id[];
  extern const char dirserv_c_id[];
  extern const char dns_c_id[];
  extern const char hibernate_c_id[];
  extern const char main_c_id[];
  extern const char onion_c_id[];
  extern const char relay_c_id[];
  extern const char rendclient_c_id[];
  extern const char rendcommon_c_id[];
  extern const char rendmid_c_id[];
  extern const char rendservice_c_id[];
  extern const char rephist_c_id[];
  extern const char router_c_id[];
  extern const char routerlist_c_id[];
  extern const char routerparse_c_id[];

  puts(AES_H_ID);
  puts(COMPAT_H_ID);
  puts(CONTAINER_H_ID);
  puts(CRYPTO_H_ID);
  puts(LOG_H_ID);
  puts(TORGZIP_H_ID);
  puts(TORINT_H_ID);
  puts(TORTLS_H_ID);
  puts(UTIL_H_ID);
  puts(aes_c_id);
  puts(compat_c_id);
  puts(container_c_id);
  puts(crypto_c_id);
  puts(log_c_id);
  puts(torgzip_c_id);
  puts(tortls_c_id);
  puts(util_c_id);

  puts(OR_H_ID);
  puts(buffers_c_id);
  puts(circuitbuild_c_id);
  puts(circuitlist_c_id);
  puts(circuituse_c_id);
  puts(command_c_id);
  puts(config_c_id);
  puts(connection_c_id);
  puts(connection_edge_c_id);
  puts(connection_or_c_id);
  puts(control_c_id);
  puts(cpuworker_c_id);
  puts(directory_c_id);
  puts(dirserv_c_id);
  puts(dns_c_id);
  puts(hibernate_c_id);
  puts(main_c_id);
  puts(onion_c_id);
  puts(relay_c_id);
  puts(rendclient_c_id);
  puts(rendcommon_c_id);
  puts(rendmid_c_id);
  puts(rendservice_c_id);
  puts(rephist_c_id);
  puts(router_c_id);
  puts(routerlist_c_id);
  puts(routerparse_c_id);
}
