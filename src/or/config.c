/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char config_c_id[] = \
  "$Id$";

/**
 * \file config.c
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
  CONFIG_TYPE_ISOTIME,      /**< An ISO-formated time relative to GMT. */
  CONFIG_TYPE_CSV,          /**< A list of strings, separated by commas and
                              * optional whitespace. */
  CONFIG_TYPE_LINELIST,     /**< Uninterpreted config lines */
  CONFIG_TYPE_LINELIST_S,   /**< Uninterpreted, context-sensitive config lines,
                             * mixed with other keywords. */
  CONFIG_TYPE_LINELIST_V,   /**< Catch-all "virtual" option to summarize
                             * context-sensitive config lines when fetching.
                             */
  CONFIG_TYPE_OBSOLETE,     /**< Obsolete (ignored) option. */
} config_type_t;

/** An abbreviation for a configuration option allowed on the command line. */
typedef struct config_abbrev_t {
  const char *abbreviated;
  const char *full;
  int commandline_only;
  int warn;
} config_abbrev_t;

/* Handy macro for declaring "In the config file or on the command line,
 * you can abbreviate <b>tok</b>s as <b>tok</b>". */
#define PLURAL(tok) { #tok, #tok "s", 0, 0 }

/* A list of command-line abbreviations. */
static config_abbrev_t _option_abbrevs[] = {
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
  { "l", "Log", 1, 0},
  { "AllowUnverifiedNodes", "AllowInvalidNodes", 0, 0},
  { "BandwidthRateBytes", "BandwidthRate", 0, 0},
  { "BandwidthBurstBytes", "BandwidthBurst", 0, 0},
  { "DirFetchPostPeriod", "StatusFetchPeriod", 0, 0},
  { "MaxConn", "ConnLimit", 0, 1},
  { "ORBindAddress", "ORListenAddress", 0, 0},
  { "DirBindAddress", "DirListenAddress", 0, 0},
  { "SocksBindAddress", "SocksListenAddress", 0, 0},
  { "UseHelperNodes", "UseEntryGuards", 0, 0},
  { "NumHelperNodes", "NumEntryGuards", 0, 0},
  { "UseEntryNodes", "UseEntryGuards", 0, 0},
  { "NumEntryNodes", "NumEntryGuards", 0, 0},
  { "ResolvConf", "ServerDNSResolvConfFile", 0, 1},
  { "SearchDomains", "ServerDNSSearchDomains", 0, 1},
  { NULL, NULL, 0, 0},
};
/* A list of state-file abbreviations, for compatibility. */
static config_abbrev_t _state_abbrevs[] = {
  { "AccountingBytesReadInterval", "AccountingBytesReadInInterval", 0, 0 },
  { "HelperNode", "EntryGuard", 0, 0 },
  { "HelperNodeDownSince", "EntryGuardDownSince", 0, 0 },
  { "HelperNodeUnlistedSince", "EntryGuardUnlistedSince", 0, 0 },
  { "EntryNode", "EntryGuard", 0, 0 },
  { "EntryNodeDownSince", "EntryGuardDownSince", 0, 0 },
  { "EntryNodeUnlistedSince", "EntryGuardUnlistedSince", 0, 0 },
  { NULL, NULL, 0, 0},
};
#undef PLURAL

/** A variable allowed in the configuration file or on the command line. */
typedef struct config_var_t {
  const char *name; /**< The full keyword (case insensitive). */
  config_type_t type; /**< How to interpret the type and turn it into a
                       * value. */
  off_t var_offset; /**< Offset of the corresponding member of or_options_t. */
  const char *initvalue; /**< String (or null) describing initial value. */
} config_var_t;

#define STRUCT_VAR_P(st, off) \
  ((void*) ( ((char*)st) + off ) )

/** An entry for config_vars: "The option <b>name</b> has type
 * CONFIG_TYPE_<b>conftype</b>, and corresponds to
 * or_options_t.<b>member</b>"
 */
#define VAR(name,conftype,member,initvalue)                             \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(or_options_t, member), \
      initvalue }
/** An entry for config_vars: "The option <b>name</b> is obsolete." */
#define OBSOLETE(name) { name, CONFIG_TYPE_OBSOLETE, 0, NULL }

/** Array of configuration options.  Until we disallow nonstandard
 * abbreviations, order is significant, since the first matching option will
 * be chosen first.
 */
static config_var_t _option_vars[] = {
  VAR("AccountingMax",       MEMUNIT,  AccountingMax,        "0 bytes"),
  VAR("AccountingMaxKB",     UINT,     _AccountingMaxKB,     "0"),
  VAR("AccountingStart",     STRING,   AccountingStart,      NULL),
  VAR("Address",             STRING,   Address,              NULL),
  VAR("__AllDirActionsPrivate",BOOL,   AllDirActionsPrivate, "0"),
  VAR("AllowInvalidNodes",   CSV,      AllowInvalidNodes,
                                                        "middle,rendezvous"),
  VAR("AssumeReachable",     BOOL,     AssumeReachable,      "0"),
  VAR("AuthDirInvalid",      LINELIST, AuthDirInvalid,       NULL),
  VAR("AuthDirReject",       LINELIST, AuthDirReject,        NULL),
  VAR("AuthDirRejectUnlisted",BOOL,    AuthDirRejectUnlisted,"0"),
  VAR("AuthoritativeDirectory",BOOL,   AuthoritativeDir,     "0"),
  VAR("AvoidDiskWrites",     BOOL,     AvoidDiskWrites,      "0"),
  VAR("BandwidthBurst",      MEMUNIT,  BandwidthBurst,       "6 MB"),
  VAR("BandwidthRate",       MEMUNIT,  BandwidthRate,        "3 MB"),
  VAR("CircuitBuildTimeout", INTERVAL, CircuitBuildTimeout,  "1 minute"),
  VAR("CircuitIdleTimeout",  INTERVAL, CircuitIdleTimeout,   "1 hour"),
  VAR("ClientOnly",          BOOL,     ClientOnly,           "0"),
  VAR("ConnLimit",           UINT,     ConnLimit,            "1000"),
  VAR("ContactInfo",         STRING,   ContactInfo,          NULL),
  VAR("ControlListenAddress",LINELIST, ControlListenAddress, NULL),
  VAR("ControlPort",         UINT,     ControlPort,          "0"),
  VAR("CookieAuthentication",BOOL,     CookieAuthentication, "0"),
  VAR("DataDirectory",       STRING,   DataDirectory,        NULL),
  VAR("DebugLogFile",        STRING,   DebugLogFile,         NULL),
  VAR("DirAllowPrivateAddresses",BOOL, DirAllowPrivateAddresses, NULL),
  VAR("DirListenAddress",    LINELIST, DirListenAddress,     NULL),
  OBSOLETE("DirFetchPeriod"),
  VAR("DirPolicy",           LINELIST, DirPolicy,            NULL),
  VAR("DirPort",             UINT,     DirPort,              "0"),
  OBSOLETE("DirPostPeriod"),
  VAR("DirServer",           LINELIST, DirServers,           NULL),
  VAR("EnforceDistinctSubnets", BOOL,  EnforceDistinctSubnets,"1"),
  VAR("EntryNodes",          STRING,   EntryNodes,           NULL),
  VAR("ExcludeNodes",        STRING,   ExcludeNodes,         NULL),
  VAR("ExitNodes",           STRING,   ExitNodes,            NULL),
  VAR("ExitPolicy",          LINELIST, ExitPolicy,           NULL),
  VAR("ExitPolicyRejectPrivate", BOOL, ExitPolicyRejectPrivate, "1"),
  VAR("FascistFirewall",     BOOL,     FascistFirewall,      "0"),
  VAR("FirewallPorts",       CSV,      FirewallPorts,        ""),
  VAR("FastFirstHopPK",      BOOL,     FastFirstHopPK,       "1"),
  VAR("FetchServerDescriptors",BOOL,   FetchServerDescriptors,"1"),
  VAR("FetchHidServDescriptors",BOOL,  FetchHidServDescriptors, "1"),
  VAR("FetchUselessDescriptors",BOOL,  FetchUselessDescriptors, "0"),
  VAR("Group",               STRING,   Group,                NULL),
  VAR("HardwareAccel",       BOOL,     HardwareAccel,        "0"),
  VAR("HashedControlPassword",STRING,  HashedControlPassword, NULL),
  VAR("HiddenServiceDir",    LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceExcludeNodes", LINELIST_S, RendConfigLines, NULL),
  VAR("HiddenServiceNodes",  LINELIST_S, RendConfigLines,    NULL),
  VAR("HiddenServiceOptions",LINELIST_V, RendConfigLines,    NULL),
  VAR("HiddenServicePort",   LINELIST_S, RendConfigLines,    NULL),
  VAR("HSAuthoritativeDir",  BOOL,     HSAuthoritativeDir,   "0"),
  VAR("HttpProxy",           STRING,   HttpProxy,            NULL),
  VAR("HttpProxyAuthenticator",STRING, HttpProxyAuthenticator,NULL),
  VAR("HttpsProxy",          STRING,   HttpsProxy,           NULL),
  VAR("HttpsProxyAuthenticator",STRING,HttpsProxyAuthenticator,NULL),
  OBSOLETE("IgnoreVersion"),
  VAR("KeepalivePeriod",     INTERVAL, KeepalivePeriod,      "5 minutes"),
  VAR("Log",                 LINELIST, Logs,                 NULL),
  OBSOLETE("LinkPadding"),
  VAR("LogFile",             LINELIST_S, OldLogOptions,      NULL),
  VAR("LogLevel",            LINELIST_S, OldLogOptions,      NULL),
  VAR("LongLivedPorts",      CSV,      LongLivedPorts,
                         "21,22,706,1863,5050,5190,5222,5223,6667,6697,8300"),
  VAR("MapAddress",          LINELIST, AddressMap,           NULL),
  VAR("MaxAdvertisedBandwidth",MEMUNIT,MaxAdvertisedBandwidth,"128 TB"),
  VAR("MaxCircuitDirtiness", INTERVAL, MaxCircuitDirtiness,  "10 minutes"),
  VAR("MaxOnionsPending",    UINT,     MaxOnionsPending,     "100"),
  OBSOLETE("MonthlyAccountingStart"),
  VAR("MyFamily",            STRING,   MyFamily,             NULL),
  VAR("NewCircuitPeriod",    INTERVAL, NewCircuitPeriod,     "30 seconds"),
  VAR("NamingAuthoritativeDirectory",BOOL, NamingAuthoritativeDir, "0"),
  VAR("Nickname",            STRING,   Nickname,             NULL),
  VAR("NoPublish",           BOOL,     NoPublish,            "0"),
  VAR("NodeFamily",          LINELIST, NodeFamilies,         NULL),
  VAR("NumCpus",             UINT,     NumCpus,              "1"),
  VAR("NumEntryGuards",      UINT,     NumEntryGuards,       "3"),
  VAR("ORListenAddress",     LINELIST, ORListenAddress,      NULL),
  VAR("ORPort",              UINT,     ORPort,               "0"),
  VAR("OutboundBindAddress", STRING,   OutboundBindAddress,  NULL),
  VAR("PathlenCoinWeight",   DOUBLE,   PathlenCoinWeight,    "0.3"),
  VAR("PidFile",             STRING,   PidFile,              NULL),
  VAR("ProtocolWarnings",    BOOL,     ProtocolWarnings,     "0"),
  VAR("PublishServerDescriptor",BOOL,  PublishServerDescriptor,"1"),
  VAR("PublishHidServDescriptors",BOOL,PublishHidServDescriptors, "1"),
  VAR("ReachableAddresses",  LINELIST, ReachableAddresses,   NULL),
  VAR("ReachableDirAddresses",LINELIST,ReachableDirAddresses,NULL),
  VAR("ReachableORAddresses",LINELIST, ReachableORAddresses, NULL),
  VAR("RecommendedVersions", LINELIST, RecommendedVersions,  NULL),
  VAR("RecommendedClientVersions", LINELIST, RecommendedClientVersions,  NULL),
  VAR("RecommendedServerVersions", LINELIST, RecommendedServerVersions,  NULL),
  VAR("RedirectExit",        LINELIST, RedirectExit,         NULL),
  VAR("RelayBandwidthBurst", MEMUNIT,  RelayBandwidthBurst,  "0"),
  VAR("RelayBandwidthRate",  MEMUNIT,  RelayBandwidthRate,   "0"),
  VAR("RendExcludeNodes",    STRING,   RendExcludeNodes,     NULL),
  VAR("RendNodes",           STRING,   RendNodes,            NULL),
  VAR("RendPostPeriod",      INTERVAL, RendPostPeriod,       "1 hour"),
  VAR("RephistTrackTime",    INTERVAL, RephistTrackTime,     "24 hours"),
  OBSOLETE("RouterFile"),
  VAR("RunAsDaemon",         BOOL,     RunAsDaemon,          "0"),
  VAR("RunTesting",          BOOL,     RunTesting,           "0"),
  VAR("SafeLogging",         BOOL,     SafeLogging,          "1"),
  VAR("SafeSocks",           BOOL,     SafeSocks,            "0"),
  VAR("ServerDNSDetectHijacking",BOOL,   ServerDNSDetectHijacking,"1"),
  VAR("ServerDNSResolvConfFile", STRING, ServerDNSResolvConfFile, NULL),
  VAR("ServerDNSSearchDomains",  BOOL,   ServerDNSSearchDomains,  "0"),
  VAR("ShutdownWaitLength",  INTERVAL, ShutdownWaitLength,   "30 seconds"),
  VAR("SocksListenAddress",  LINELIST, SocksListenAddress,   NULL),
  VAR("SocksPolicy",         LINELIST, SocksPolicy,          NULL),
  VAR("SocksPort",           UINT,     SocksPort,            "9050"),
  VAR("SocksTimeout",        INTERVAL, SocksTimeout,         "2 minutes"),
  OBSOLETE("StatusFetchPeriod"),
  VAR("StrictEntryNodes",    BOOL,     StrictEntryNodes,     "0"),
  VAR("StrictExitNodes",     BOOL,     StrictExitNodes,      "0"),
  VAR("SysLog",              LINELIST_S, OldLogOptions,      NULL),
  VAR("TestSocks",           BOOL,     TestSocks,            "0"),
  VAR("TestVia",             STRING,   TestVia,              NULL),
  VAR("TrackHostExits",      CSV,      TrackHostExits,       NULL),
  VAR("TrackHostExitsExpire",INTERVAL, TrackHostExitsExpire, "30 minutes"),
  OBSOLETE("TrafficShaping"),
  VAR("TransListenAddress",  LINELIST, TransListenAddress,   NULL),
  VAR("TransPort",           UINT,     TransPort,            "0"),
  VAR("UseEntryGuards",      BOOL,     UseEntryGuards,       "1"),
  VAR("User",                STRING,   User,                 NULL),
  VAR("V1AuthoritativeDirectory",BOOL, V1AuthoritativeDir,   "0"),
  VAR("VersioningAuthoritativeDirectory",BOOL,VersioningAuthoritativeDir, "0"),
  VAR("VirtualAddrNetwork",  STRING,   VirtualAddrNetwork,   "127.192.0.0/10"),
  VAR("__LeaveStreamsUnattached", BOOL,LeaveStreamsUnattached, "0"),
  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};
#undef VAR

#define VAR(name,conftype,member,initvalue)                             \
  { name, CONFIG_TYPE_ ## conftype, STRUCT_OFFSET(or_state_t, member),  \
      initvalue }
static config_var_t _state_vars[] = {
  VAR("AccountingBytesReadInInterval", MEMUNIT,
      AccountingBytesReadInInterval, NULL),
  VAR("AccountingBytesWrittenInInterval", MEMUNIT,
      AccountingBytesWrittenInInterval, NULL),
  VAR("AccountingExpectedUsage", MEMUNIT,     AccountingExpectedUsage, NULL),
  VAR("AccountingIntervalStart", ISOTIME,     AccountingIntervalStart, NULL),
  VAR("AccountingSecondsActive", INTERVAL,    AccountingSecondsActive, NULL),
  VAR("EntryGuard",              LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuardDownSince",     LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuardUnlistedSince", LINELIST_S,  EntryGuards,             NULL),
  VAR("EntryGuards",             LINELIST_V,  EntryGuards,             NULL),

  VAR("BWHistoryReadEnds",       ISOTIME,     BWHistoryReadEnds,      NULL),
  VAR("BWHistoryReadInterval",   UINT,        BWHistoryReadInterval,  NULL),
  VAR("BWHistoryReadValues",     CSV,         BWHistoryReadValues,    NULL),
  VAR("BWHistoryWriteEnds",      ISOTIME,     BWHistoryWriteEnds,     NULL),
  VAR("BWHistoryWriteInterval",  UINT,        BWHistoryWriteInterval, NULL),
  VAR("BWHistoryWriteValues",    CSV,         BWHistoryWriteValues,   NULL),

  VAR("TorVersion",              STRING,      TorVersion,             NULL),

  VAR("LastWritten",             ISOTIME,     LastWritten,            NULL),

  { NULL, CONFIG_TYPE_OBSOLETE, 0, NULL }
};

#undef VAR
#undef OBSOLETE

/** Represents an English description of a configuration variable; used when
 * generating configuration file comments. */
typedef struct config_var_description_t {
  const char *name;
  const char *description;
} config_var_description_t;

static config_var_description_t options_description[] = {
  { "Address", "The advertised (external) address we should use." },
  // { "AccountingStart", ""},
  { NULL, NULL },
};

static config_var_description_t state_description[] = {
  { "AccountingBytesReadInInterval",
    "How many bytes have we read in this accounting period?" },
  { "AccountingBytesWrittenInInterval",
    "How many bytes have we written in this accounting period?" },
  { "AccountingExpectedUsage",
    "How many bytes did we expect to use per minute? (0 for no estimate.)" },
  { "AccountingIntervalStart", "When did this accounting period begin?" },
  { "AccountingSecondsActive", "How long have we been awake in this period?" },

  { "BWHistoryReadEnds", "When does the last-recorded read-interval end?" },
  { "BWHistoryReadInterval", "How long is each read-interval (in seconds)?" },
  { "BWHistoryReadValues", "Number of bytes read in each interval." },
  { "BWHistoryWriteEnds", "When does the last-recorded write-interval end?" },
  { "BWHistoryWriteInterval", "How long is each write-interval (in seconds)?"},
  { "BWHistoryWriteValues", "Number of bytes written in each interval." },

  { "EntryGuard", "One of the nodes we have chosen as a fixed entry" },
  { "EntryGuardDownSince",
    "The last entry guard has been unreachable since this time." },
  { "EntryGuardUnlistedSince",
    "The last entry guard has been unusable since this time." },
  { "LastWritten", "When was this state file last regenerated?" },

  { "TorVersion", "Which version of Tor generated this state file?" },
  { NULL, NULL },
};

typedef int (*validate_fn_t)(void*,void*,int,char**);

/** Information on the keys, value types, key-to-struct-member mappings,
 * variable descriptions, validation functions, and abbreviations for a
 * configuration or storage format. */
typedef struct {
  size_t size;
  uint32_t magic;
  off_t magic_offset;
  config_abbrev_t *abbrevs;
  config_var_t *vars;
  validate_fn_t validate_fn;
  config_var_description_t *descriptions;
  /** If present, extra is a LINELIST variable for unrecognized
   * lines.  Otherwise, unrecognized lines are an error. */
  config_var_t *extra;
} config_format_t;

#define CHECK(fmt, cfg) do {                                            \
    tor_assert(fmt && cfg);                                             \
    tor_assert((fmt)->magic ==                                          \
               *(uint32_t*)STRUCT_VAR_P(cfg,fmt->magic_offset));        \
  } while (0)

static void config_line_append(config_line_t **lst,
                               const char *key, const char *val);
static void option_clear(config_format_t *fmt, or_options_t *options,
                         config_var_t *var);
static void option_reset(config_format_t *fmt, or_options_t *options,
                         config_var_t *var, int use_defaults);
static void config_free(config_format_t *fmt, void *options);
static int option_is_same(config_format_t *fmt,
                          or_options_t *o1, or_options_t *o2,
                          const char *name);
static or_options_t *options_dup(config_format_t *fmt, or_options_t *old);
static int options_validate(or_options_t *old_options, or_options_t *options,
                            int from_setconf, char **msg);
static int options_act_reversible(or_options_t *old_options, char **msg);
static int options_act(or_options_t *old_options);
static int options_transition_allowed(or_options_t *old, or_options_t *new,
                                      char **msg);
static int options_transition_affects_workers(or_options_t *old_options,
                                              or_options_t *new_options);
static int options_transition_affects_descriptor(or_options_t *old_options,
                                                 or_options_t *new_options);
static int check_nickname_list(const char *lst, const char *name, char **msg);
static void config_register_addressmaps(or_options_t *options);

static int parse_dir_server_line(const char *line, int validate_only);
static int parse_redirect_line(smartlist_t *result,
                               config_line_t *line, char **msg);
static int parse_log_severity_range(const char *range, int *min_out,
                                    int *max_out);
static int convert_log_option(or_options_t *options,
                              config_line_t *level_opt,
                              config_line_t *file_opt, int isDaemon);
static int add_single_log_option(or_options_t *options, int minSeverity,
                                 int maxSeverity,
                                 const char *type, const char *fname);
static int normalize_log_options(or_options_t *options);
static int validate_data_directory(or_options_t *options);
static int write_configuration_file(const char *fname, or_options_t *options);
static config_line_t *get_assigned_option(config_format_t *fmt,
                                     or_options_t *options, const char *key);
static void config_init(config_format_t *fmt, void *options);
static int or_state_validate(or_state_t *old_options, or_state_t *options,
                             int from_setconf, char **msg);

static uint64_t config_parse_memunit(const char *s, int *ok);
static int config_parse_interval(const char *s, int *ok);
static void print_svn_version(void);
static void init_libevent(void);
static int opt_streq(const char *s1, const char *s2);
typedef enum {
  LE_OLD=0, LE_10C, LE_10D, LE_10E, LE_11, LE_11A, LE_11B, LE_OTHER
} le_version_t;
static le_version_t decode_libevent_version(void);
#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
static void check_libevent_version(const char *m, int server);
#endif

/*static*/ or_options_t *options_new(void);

#define OR_OPTIONS_MAGIC 9090909

static config_format_t options_format = {
  sizeof(or_options_t),
  OR_OPTIONS_MAGIC,
  STRUCT_OFFSET(or_options_t, _magic),
  _option_abbrevs,
  _option_vars,
  (validate_fn_t)options_validate,
  options_description,
  NULL
};

#define OR_STATE_MAGIC 0x57A73f57

static config_var_t state_extra_var = {
  "__extra", CONFIG_TYPE_LINELIST, STRUCT_OFFSET(or_state_t, ExtraLines), NULL
};

static config_format_t state_format = {
  sizeof(or_state_t),
  OR_STATE_MAGIC,
  STRUCT_OFFSET(or_state_t, _magic),
  _state_abbrevs,
  _state_vars,
  (validate_fn_t)or_state_validate,
  state_description,
  &state_extra_var,
};

/*
 * Functions to read and write the global options pointer.
 */

/** Command-line and config-file options. */
static or_options_t *global_options = NULL;
/** Name of most recently read torrc file. */
static char *torrc_fname = NULL;
/** Persistent serialized state. */
static or_state_t *global_state = NULL;

/** Allocate an empty configuration object of a given format type. */
static void *
config_alloc(config_format_t *fmt)
{
  void *opts = tor_malloc_zero(fmt->size);
  *(uint32_t*)STRUCT_VAR_P(opts, fmt->magic_offset) = fmt->magic;
  CHECK(fmt, opts);
  return opts;
}

/** Return the currently configured options. */
or_options_t *
get_options(void)
{
  tor_assert(global_options);
  return global_options;
}

/** Change the current global options to contain <b>new_val</b> instead of
 * their current value; take action based on the new value; free the old value
 * as necessary.
 */
int
set_options(or_options_t *new_val, char **msg)
{
  or_options_t *old_options = global_options;
  global_options = new_val;
  /* Note that we pass the *old* options below, for comparison. It
   * pulls the new options directly out of global_options. */
  if (options_act_reversible(old_options, msg)<0) {
    tor_assert(*msg);
    global_options = old_options;
    return -1;
  }
  if (options_act(old_options) < 0) { /* acting on the options failed. die. */
    log_err(LD_BUG,
            "Acting on config options left us in a broken state. Dying.");
    exit(1);
  }
  if (old_options)
    config_free(&options_format, old_options);

  return 0;
}

/** Release all memory and resources held by global configuration structures.
 */
void
config_free_all(void)
{
  if (global_options) {
    config_free(&options_format, global_options);
    global_options = NULL;
  }
  if (global_state) {
    config_free(&state_format, global_state);
    global_state = NULL;
  }
  tor_free(torrc_fname);
}

/** If options->SafeLogging is on, return a not very useful string,
 * else return address.
 */
const char *
safe_str(const char *address)
{
  if (get_options()->SafeLogging)
    return "[scrubbed]";
  else
    return address;
}

/** Equivalent to escaped(safe_str(address)).  See reentrancy note on
 * escaped(): don't use this outside the main thread, or twice in the same
 * log statement. */
const char *
escaped_safe_str(const char *address)
{
  if (get_options()->SafeLogging)
    return "[scrubbed]";
  else
    return escaped(address);
}

/** Add the default directory servers directly into the trusted dir list. */
static void
add_default_trusted_dirservers(void)
{
  int i;
  const char *dirservers[] = {
    /* eventually we should mark moria1 as "v1only" */
    "moria1 v1 18.244.0.188:9031 "
      "FFCB 46DB 1339 DA84 674C 70D7 CB58 6434 C437 0441",
    "moria2 v1 18.244.0.114:80 "
      "719B E45D E224 B607 C537 07D0 E214 3E2D 423E 74CF",
    "tor26 v1 86.59.21.38:80 "
      "847B 1F85 0344 D787 6491 A548 92F9 0493 4E4E B85D",
    "lefkada 140.247.60.64:80 "
      "38D4 F5FC F7B1 0232 28B8 95EA 56ED E7D5 CCDC AF32",
    "dizum 194.109.206.212:80 "
      "7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
    NULL
  };
  for (i=0; dirservers[i]; i++)
    parse_dir_server_line(dirservers[i], 0);
}

/** Fetch the active option list, and take actions based on it. All of the
 * things we do should survive being done repeatedly.  If present,
 * <b>old_options</b> contains the previous value of the options.
 *
 * Return 0 if all goes well, return -1 if things went badly.
 */
static int
options_act_reversible(or_options_t *old_options, char **msg)
{
  smartlist_t *new_listeners = smartlist_create();
  smartlist_t *replaced_listeners = smartlist_create();
  static int libevent_initialized = 0;
  or_options_t *options = get_options();
  int running_tor = options->command == CMD_RUN_TOR;
  int set_conn_limit = 0;
  int r = -1;
  int logs_marked = 0;

  if (running_tor && options->RunAsDaemon) {
    /* No need to roll back, since you can't change the value. */
    start_daemon();
  }

  /* Setuid/setgid as appropriate */
  if (options->User || options->Group) {
    if (switch_id(options->User, options->Group) != 0) {
      /* No need to roll back, since you can't change the value. */
      *msg = tor_strdup("Problem with User or Group value. "
                        "See logs for details.");
      goto done;
    }
  }

  /* Set up libevent. */
  if (running_tor && !libevent_initialized) {
    init_libevent();
    libevent_initialized = 1;
  }

  /* Ensure data directory is private; create if possible. */
  if (check_private_dir(options->DataDirectory, CPD_CREATE)<0) {
    char buf[1024];
    int tmp = tor_snprintf(buf, sizeof(buf),
              "Couldn't access/create private data directory \"%s\"",
              options->DataDirectory);
    *msg = tor_strdup(tmp >= 0 ? buf : "internal error");
    goto done;
    /* No need to roll back, since you can't change the value. */
  }

  /* Bail out at this point if we're not going to be a client or server:
   * we don't run Tor itself. */
  if (options->command != CMD_RUN_TOR)
    goto commit;

  options->_ConnLimit =
    set_max_file_descriptors((unsigned)options->ConnLimit, MAXCONNECTIONS);
  if (options->_ConnLimit < 0) {
    *msg = tor_strdup("Problem with ConnLimit value. See logs for details.");
    goto rollback;
  }
  set_conn_limit = 1;

  if (retry_all_listeners(0, replaced_listeners, new_listeners) < 0) {
    *msg = tor_strdup("Failed to bind one of the listener ports.");
    goto rollback;
  }

  mark_logs_temp(); /* Close current logs once new logs are open. */
  logs_marked = 1;
  if (options_init_logs(options, 0)<0) { /* Configure the log(s) */
    *msg = tor_strdup("Failed to init Log options. See logs for details.");
    goto rollback;
  }

 commit:
  r = 0;
  if (logs_marked) {
    close_temp_logs();
    add_callback_log(LOG_ERR, LOG_ERR, control_event_logmsg);
    control_adjust_event_log_severity();
  }
  SMARTLIST_FOREACH(replaced_listeners, connection_t *, conn,
  {
    log_notice(LD_NET, "Closing old %s on %s:%d",
               conn_type_to_string(conn->type), conn->address, conn->port);
    connection_close_immediate(conn);
    connection_mark_for_close(conn);
  });
  goto done;

 rollback:
  r = -1;
  tor_assert(*msg);

  if (logs_marked) {
    rollback_log_changes();
    control_adjust_event_log_severity();
  }

  if (set_conn_limit && old_options)
    set_max_file_descriptors((unsigned)old_options->ConnLimit,MAXCONNECTIONS);

  SMARTLIST_FOREACH(new_listeners, connection_t *, conn,
  {
    log_notice(LD_NET, "Closing partially-constructed listener %s on %s:%d",
               conn_type_to_string(conn->type), conn->address, conn->port);
    connection_close_immediate(conn);
    connection_mark_for_close(conn);
  });

 done:
  smartlist_free(new_listeners);
  smartlist_free(replaced_listeners);
  return r;
}

/** Fetch the active option list, and take actions based on it. All of the
 * things we do should survive being done repeatedly.  If present,
 * <b>old_options</b> contains the previous value of the options.
 *
 * Return 0 if all goes well, return -1 if it's time to die.
 *
 * Note: We haven't moved all the "act on new configuration" logic
 * here yet.  Some is still in do_hup() and other places.
 */
static int
options_act(or_options_t *old_options)
{
  config_line_t *cl;
  char *fn;
  size_t len;
  or_options_t *options = get_options();
  int running_tor = options->command == CMD_RUN_TOR;
  char *msg;

  clear_trusted_dir_servers();
  if (options->DirServers) {
    for (cl = options->DirServers; cl; cl = cl->next) {
      if (parse_dir_server_line(cl->value, 0)<0) {
        log_err(LD_BUG,
            "Bug: Previously validated DirServer line could not be added!");
        return -1;
      }
    }
  } else {
    add_default_trusted_dirservers();
  }

  if (running_tor && rend_config_services(options, 0)<0) {
    log_err(LD_BUG,
       "Bug: Previously validated hidden services line could not be added!");
    return -1;
  }

  if (running_tor) {
    len = strlen(options->DataDirectory)+32;
    fn = tor_malloc(len);
    tor_snprintf(fn, len, "%s/cached-status", options->DataDirectory);
    if (check_private_dir(fn, CPD_CREATE) != 0) {
      log_err(LD_CONFIG,
              "Couldn't access/create private data directory \"%s\"", fn);
      tor_free(fn);
      return -1;
    }
    tor_free(fn);
  }

  /* Bail out at this point if we're not going to be a client or server:
   * we want to not fork, and to log stuff to stderr. */
  if (options->command != CMD_RUN_TOR)
    return 0;

  /* Load state */
  if (! global_state)
    if (or_state_load())
      return -1;

  {
    smartlist_t *sl = smartlist_create();
    char *errmsg = NULL;
    for (cl = options->RedirectExit; cl; cl = cl->next) {
      if (parse_redirect_line(sl, cl, &errmsg)<0) {
        log_warn(LD_CONFIG, "%s", errmsg);
        tor_free(errmsg);
        return -1;
      }
    }
    set_exit_redirects(sl);
  }

  /* Finish backgrounding the process */
  if (running_tor && options->RunAsDaemon) {
    /* We may be calling this for the n'th time (on SIGHUP), but it's safe. */
    finish_daemon(options->DataDirectory);
  }

  /* Write our pid to the pid file. If we do not have write permissions we
   * will log a warning */
  if (running_tor && options->PidFile)
    write_pidfile(options->PidFile);

  /* Register addressmap directives */
  config_register_addressmaps(options);
  parse_virtual_addr_network(options->VirtualAddrNetwork, 0, &msg);

  /* Update address policies. */
  policies_parse_from_options(options);

  init_cookie_authentication(options->CookieAuthentication);

  /* reload keys as needed for rendezvous services. */
  if (rend_service_load_keys()<0) {
    log_err(LD_GENERAL,"Error loading rendezvous service keys");
    return -1;
  }

  /* Set up accounting */
  if (accounting_parse_options(options, 0)<0) {
    log_err(LD_CONFIG,"Error in accounting options");
    return -1;
  }
  if (accounting_is_enabled(options))
    configure_accounting(time(NULL));

  if (!running_tor)
    return 0;

  /* Check for transitions that need action. */
  if (old_options) {
    if (options->UseEntryGuards && !old_options->UseEntryGuards) {
      log_info(LD_CIRC,
               "Switching to entry guards; abandoning previous circuits");
      circuit_mark_all_unused_circs();
      circuit_expire_all_dirty_circs();
    }

    if (options_transition_affects_workers(old_options, options)) {
      log_info(LD_GENERAL,
               "Worker-related options changed. Rotating workers.");
      if (server_mode(options) && !server_mode(old_options)) {
        if (init_keys() < 0) {
          log_err(LD_BUG,"Error initializing keys; exiting");
          return -1;
        }
        server_has_changed_ip();
        if (has_completed_circuit || !any_predicted_circuits(time(NULL)))
          inform_testing_reachability();
      }
      cpuworkers_rotate();
      dns_reset();
    }
#ifdef USE_EVENTDNS
    else {
      dns_reset();
    }
#endif
  }

  /* Check if we need to parse and add the EntryNodes config option. */
  if (options->EntryNodes &&
      (!old_options ||
       !opt_streq(old_options->EntryNodes, options->EntryNodes)))
    entry_nodes_should_be_added();

  /* If the user wants to avoid certain nodes, make sure none of them
   * are already entryguards */
  if (options->ExcludeNodes) {
    // XXX TODO
  }

  /* Since our options changed, we might need to regenerate and upload our
   * server descriptor.
   */
  if (!old_options ||
      options_transition_affects_descriptor(old_options, options))
    mark_my_descriptor_dirty();

  return 0;
}

/*
 * Functions to parse config options
 */

/** If <b>option</b> is an official abbreviation for a longer option,
 * return the longer option.  Otherwise return <b>option</b>.
 * If <b>command_line</b> is set, apply all abbreviations.  Otherwise, only
 * apply abbreviations that work for the config file and the command line.
 * If <b>warn_obsolete</b> is set, warn about deprecated names. */
static const char *
expand_abbrev(config_format_t *fmt, const char *option, int command_line,
              int warn_obsolete)
{
  int i;
  if (! fmt->abbrevs)
    return option;
  for (i=0; fmt->abbrevs[i].abbreviated; ++i) {
    /* Abbreviations are casei. */
    if (!strcasecmp(option,fmt->abbrevs[i].abbreviated) &&
        (command_line || !fmt->abbrevs[i].commandline_only)) {
      if (warn_obsolete && fmt->abbrevs[i].warn) {
        log_warn(LD_CONFIG,
                 "The configuration option '%s' is deprecated; "
                 "use '%s' instead.",
                 fmt->abbrevs[i].abbreviated,
                 fmt->abbrevs[i].full);
      }
      return fmt->abbrevs[i].full;
    }
  }
  return option;
}

/** Helper: Read a list of configuration options from the command line.
 * If successful, put them in *<b>result</b> and return 0, and return
 * -1 and leave *<b>result</b> alone. */
static int
config_get_commandlines(int argc, char **argv, config_line_t **result)
{
  config_line_t *front = NULL;
  config_line_t **new = &front;
  char *s;
  int i = 1;

  while (i < argc) {
    if (!strcmp(argv[i],"-f") ||
        !strcmp(argv[i],"--hash-password")) {
      i += 2; /* command-line option with argument. ignore them. */
      continue;
    } else if (!strcmp(argv[i],"--list-fingerprint") ||
               !strcmp(argv[i],"--verify-config")) {
      i += 1; /* command-line option. ignore it. */
      continue;
    } else if (!strcmp(argv[i],"--nt-service")) {
      i += 1;
      continue;
    }
    if (i == argc-1) {
      log_warn(LD_CONFIG,"Command-line option '%s' with no value. Failing.",
               argv[i]);
      config_free_lines(front);
      return -1;
    }

    *new = tor_malloc_zero(sizeof(config_line_t));
    s = argv[i];

    while (*s == '-')
      s++;

    (*new)->key = tor_strdup(expand_abbrev(&options_format, s, 1, 1));
    (*new)->value = tor_strdup(argv[i+1]);
    (*new)->next = NULL;
    log(LOG_DEBUG, LD_CONFIG, "Commandline: parsed keyword '%s', value '%s'",
        (*new)->key, (*new)->value);

    new = &((*new)->next);
    i += 2;
  }
  *result = front;
  return 0;
}

/** Helper: allocate a new configuration option mapping 'key' to 'val',
 * append it to *<b>lst</b>. */
static void
config_line_append(config_line_t **lst,
                   const char *key,
                   const char *val)
{
  config_line_t *newline;

  newline = tor_malloc(sizeof(config_line_t));
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
config_get_lines(char *string, config_line_t **result)
{
  config_line_t *list = NULL, **next;
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
      *next = tor_malloc(sizeof(config_line_t));
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
config_free_lines(config_line_t *front)
{
  config_line_t *tmp;

  while (front) {
    tmp = front;
    front = tmp->next;

    tor_free(tmp->key);
    tor_free(tmp->value);
    tor_free(tmp);
  }
}

/** Return the description for a given configuration variable, or NULL if no
 * description exists. */
static const char *
config_find_description(config_format_t *fmt, const char *name)
{
  int i;
  for (i=0; fmt->descriptions[i].name; ++i) {
    if (!strcasecmp(name, fmt->descriptions[i].name))
      return fmt->descriptions[i].description;
  }
  return NULL;
}

/** If <b>key</b> is a configuration option, return the corresponding
 * config_var_t.  Otherwise, if <b>key</b> is a non-standard abbreviation,
 * warn, and return the corresponding config_var_t.  Otherwise return NULL.
 */
static config_var_t *
config_find_option(config_format_t *fmt, const char *key)
{
  int i;
  size_t keylen = strlen(key);
  if (!keylen)
    return NULL; /* if they say "--" on the commandline, it's not an option */
  /* First, check for an exact (case-insensitive) match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strcasecmp(key, fmt->vars[i].name)) {
      return &fmt->vars[i];
    }
  }
  /* If none, check for an abbreviated match */
  for (i=0; fmt->vars[i].name; ++i) {
    if (!strncasecmp(key, fmt->vars[i].name, keylen)) {
      log_warn(LD_CONFIG, "The abbreviation '%s' is deprecated. "
               "Please use '%s' instead",
               key, fmt->vars[i].name);
      return &fmt->vars[i];
    }
  }
  /* Okay, unrecognized option */
  return NULL;
}

/*
 * Functions to assign config options.
 */

/** <b>c</b>-\>key is known to be a real key. Update <b>options</b>
 * with <b>c</b>-\>value and return 0, or return -1 if bad value.
 *
 * Called from config_assign_line() and option_reset().
 */
static int
config_assign_value(config_format_t *fmt, or_options_t *options,
                    config_line_t *c, char **msg)
{
  int i, r, ok;
  char buf[1024];
  config_var_t *var;
  void *lvalue;

  CHECK(fmt, options);

  var = config_find_option(fmt, c->key);
  tor_assert(var);

  lvalue = STRUCT_VAR_P(options, var->var_offset);

  switch (var->type) {

  case CONFIG_TYPE_UINT:
    i = tor_parse_long(c->value, 10, 0, INT_MAX, &ok, NULL);
    if (!ok) {
      r = tor_snprintf(buf, sizeof(buf),
          "Int keyword '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
    *(int *)lvalue = i;
    break;

  case CONFIG_TYPE_INTERVAL: {
    i = config_parse_interval(c->value, &ok);
    if (!ok) {
      r = tor_snprintf(buf, sizeof(buf),
          "Interval '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
    *(int *)lvalue = i;
    break;
  }

  case CONFIG_TYPE_MEMUNIT: {
    uint64_t u64 = config_parse_memunit(c->value, &ok);
    if (!ok) {
      r = tor_snprintf(buf, sizeof(buf),
          "Value '%s %s' is malformed or out of bounds.",
          c->key, c->value);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
    *(uint64_t *)lvalue = u64;
    break;
  }

  case CONFIG_TYPE_BOOL:
    i = tor_parse_long(c->value, 10, 0, 1, &ok, NULL);
    if (!ok) {
      r = tor_snprintf(buf, sizeof(buf),
          "Boolean '%s %s' expects 0 or 1.",
          c->key, c->value);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
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

  case CONFIG_TYPE_ISOTIME:
    if (parse_iso_time(c->value, (time_t *)lvalue)) {
      r = tor_snprintf(buf, sizeof(buf),
          "Invalid time '%s' for keyword '%s'", c->value, c->key);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
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
    config_line_append((config_line_t**)lvalue, c->key, c->value);
    break;

  case CONFIG_TYPE_OBSOLETE:
    log_warn(LD_CONFIG, "Skipping obsolete configuration option '%s'", c->key);
    break;
  case CONFIG_TYPE_LINELIST_V:
    r = tor_snprintf(buf, sizeof(buf),
        "You may not provide a value for virtual option '%s'", c->key);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  default:
    tor_assert(0);
    break;
  }
  return 0;
}

/** If <b>c</b> is a syntactically valid configuration line, update
 * <b>options</b> with its value and return 0.  Otherwise return -1 for bad
 * key, -2 for bad value.
 *
 * If <b>clear_first</b> is set, clear the value first. Then if
 * <b>use_defaults</b> is set, set the value to the default.
 *
 * Called from config_assign().
 */
static int
config_assign_line(config_format_t *fmt, or_options_t *options,
                   config_line_t *c, int use_defaults,
                   int clear_first, char **msg)
{
  config_var_t *var;

  CHECK(fmt, options);

  var = config_find_option(fmt, c->key);
  if (!var) {
    if (fmt->extra) {
      void *lvalue = STRUCT_VAR_P(options, fmt->extra->var_offset);
      log_info(LD_CONFIG,
               "Found unrecognized option '%s'; saving it.", c->key);
      config_line_append((config_line_t**)lvalue, c->key, c->value);
      return 0;
    } else {
      char buf[1024];
      int tmp = tor_snprintf(buf, sizeof(buf),
                "Unknown option '%s'.  Failing.", c->key);
      *msg = tor_strdup(tmp >= 0 ? buf : "internal error");
      return -1;
    }
  }
  /* Put keyword into canonical case. */
  if (strcmp(var->name, c->key)) {
    tor_free(c->key);
    c->key = tor_strdup(var->name);
  }

  if (!strlen(c->value)) {
    /* reset or clear it, then return */
    if (!clear_first) {
      if (var->type == CONFIG_TYPE_LINELIST ||
          var->type == CONFIG_TYPE_LINELIST_S) {
        /* We got an empty linelist from the torrc or commandline.
           As a special case, call this an error. Warn and ignore. */
        log_warn(LD_CONFIG,
                 "Linelist option '%s' has no value. Skipping.", c->key);
      } else { /* not already cleared */
        option_reset(fmt, options, var, use_defaults);
      }
    }
    return 0;
  }

  if (config_assign_value(fmt, options, c, msg) < 0)
    return -2;
  return 0;
}

/** Restore the option named <b>key</b> in options to its default value.
 * Called from config_assign(). */
static void
config_reset_line(config_format_t *fmt, or_options_t *options,
                  const char *key, int use_defaults)
{
  config_var_t *var;

  CHECK(fmt, options);

  var = config_find_option(fmt, key);
  if (!var)
    return; /* give error on next pass. */

  option_reset(fmt, options, var, use_defaults);
}

/** Return true iff key is a valid configuration option. */
int
option_is_recognized(const char *key)
{
  config_var_t *var = config_find_option(&options_format, key);
  return (var != NULL);
}

/** Return the canonical name of a configuration option. */
const char *
option_get_canonical_name(const char *key)
{
  config_var_t *var = config_find_option(&options_format, key);
  return var->name;
}

/** Return a canonicalized list of the options assigned for key.
 */
config_line_t *
option_get_assignment(or_options_t *options, const char *key)
{
  return get_assigned_option(&options_format, options, key);
}

static config_line_t *
config_lines_dup(const config_line_t *inp)
{
  config_line_t *result = NULL;
  config_line_t **next_out = &result;
  while (inp) {
    *next_out = tor_malloc(sizeof(config_line_t));
    (*next_out)->key = tor_strdup(inp->key);
    (*next_out)->value = tor_strdup(inp->value);
    inp = inp->next;
    next_out = &((*next_out)->next);
  }
  (*next_out) = NULL;
  return result;
}

static config_line_t *
get_assigned_option(config_format_t *fmt, or_options_t *options,
                    const char *key)
{
  config_var_t *var;
  const void *value;
  char buf[32];
  config_line_t *result;
  tor_assert(options && key);

  CHECK(fmt, options);

  var = config_find_option(fmt, key);
  if (!var) {
    log_warn(LD_CONFIG, "Unknown option '%s'.  Failing.", key);
    return NULL;
  }
  value = STRUCT_VAR_P(options, var->var_offset);

  result = tor_malloc_zero(sizeof(config_line_t));
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
    case CONFIG_TYPE_ISOTIME:
      if (*(time_t*)value) {
        result->value = tor_malloc(ISO_TIME_LEN+1);
        format_iso_time(result->value, *(time_t*)value);
      } else {
        tor_free(result->key);
        tor_free(result);
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
        result->value =
          smartlist_join_strings(*(smartlist_t**)value, ",", 0, NULL);
      else
        result->value = tor_strdup("");
      break;
    case CONFIG_TYPE_OBSOLETE:
      log_warn(LD_CONFIG,
               "You asked me for the value of an obsolete config option '%s'.",
               key);
      tor_free(result->key);
      tor_free(result);
      return NULL;
    case CONFIG_TYPE_LINELIST_S:
      log_warn(LD_CONFIG,
               "Can't return context-sensitive '%s' on its own", key);
      tor_free(result->key);
      tor_free(result);
      return NULL;
    case CONFIG_TYPE_LINELIST:
    case CONFIG_TYPE_LINELIST_V:
      tor_free(result->key);
      tor_free(result);
      return config_lines_dup(*(const config_line_t**)value);
    default:
      tor_free(result->key);
      tor_free(result);
      log_warn(LD_BUG,"Bug: unknown type %d for known key '%s'",
               var->type, key);
      return NULL;
    }

  return result;
}

/** Iterate through the linked list of requested options <b>list</b>.
 * For each item, convert as appropriate and assign to <b>options</b>.
 * If an item is unrecognized, set *msg and return -1 immediately,
 * else return 0 for success.
 *
 * If <b>clear_first</b>, interpret config options as replacing (not
 * extending) their previous values. If <b>clear_first</b> is set,
 * then <b>use_defaults</b> to decide if you set to defaults after
 * clearing, or make the value 0 or NULL.
 *
 * Here are the use cases:
 * 1. A non-empty AllowInvalid line in your torrc. Appends to current
 *    if linelist, replaces current if csv.
 * 2. An empty AllowInvalid line in your torrc. Should clear it.
 * 3. "RESETCONF AllowInvalid" sets it to default.
 * 4. "SETCONF AllowInvalid" makes it NULL.
 * 5. "SETCONF AllowInvalid=foo" clears it and sets it to "foo".
 *
 * Use_defaults   Clear_first
 *    0                0       "append"
 *    1                0       undefined, don't use
 *    0                1       "set to null first"
 *    1                1       "set to defaults first"
 * Return 0 on success, -1 on bad key, -2 on bad value.
 *
 * As an additional special case, if a LINELIST config option has
 * no value and clear_first is 0, then warn and ignore it.
 */

/*
There are three call cases for config_assign() currently.

Case one: Torrc entry
options_init_from_torrc() calls config_assign(0, 0)
  calls config_assign_line(0, 0).
    if value is empty, calls option_reset(0) and returns.
    calls config_assign_value(), appends.

Case two: setconf
options_trial_assign() calls config_assign(0, 1)
  calls config_reset_line(0)
    calls option_reset(0)
      calls option_clear().
  calls config_assign_line(0, 1).
    if value is empty, returns.
    calls config_assign_value(), appends.

Case three: resetconf
options_trial_assign() calls config_assign(1, 1)
  calls config_reset_line(1)
    calls option_reset(1)
      calls option_clear().
      calls config_assign_value(default)
  calls config_assign_line(1, 1).
    returns.
*/
static int
config_assign(config_format_t *fmt, void *options, config_line_t *list,
              int use_defaults, int clear_first, char **msg)
{
  config_line_t *p;

  CHECK(fmt, options);

  /* pass 1: normalize keys */
  for (p = list; p; p = p->next) {
    const char *full = expand_abbrev(fmt, p->key, 0, 1);
    if (strcmp(full,p->key)) {
      tor_free(p->key);
      p->key = tor_strdup(full);
    }
  }

  /* pass 2: if we're reading from a resetting source, clear all
   * mentioned config options, and maybe set to their defaults. */
  if (clear_first) {
    for (p = list; p; p = p->next)
      config_reset_line(fmt, options, p->key, use_defaults);
  }

  /* pass 3: assign. */
  while (list) {
    int r;
    if ((r=config_assign_line(fmt, options, list, use_defaults,
                              clear_first, msg)))
      return r;
    list = list->next;
  }
  return 0;
}

/** Try assigning <b>list</b> to the global options. You do this by duping
 * options, assigning list to the new one, then validating it. If it's
 * ok, then throw out the old one and stick with the new one. Else,
 * revert to old and return failure.  Return 0 on success, -1 on bad
 * keys, -2 on bad values, -3 on bad transition, and -4 on failed-to-set.
 *
 * If not success, point *<b>msg</b> to a newly allocated string describing
 * what went wrong.
 */
int
options_trial_assign(config_line_t *list, int use_defaults,
                     int clear_first, char **msg)
{
  int r;
  or_options_t *trial_options = options_dup(&options_format, get_options());

  if ((r=config_assign(&options_format, trial_options,
                       list, use_defaults, clear_first, msg)) < 0) {
    config_free(&options_format, trial_options);
    return r;
  }

  if (options_validate(get_options(), trial_options, 1, msg) < 0) {
    config_free(&options_format, trial_options);
    return -2;
  }

  if (options_transition_allowed(get_options(), trial_options, msg) < 0) {
    config_free(&options_format, trial_options);
    return -3;
  }

  if (set_options(trial_options, msg)<0) {
    config_free(&options_format, trial_options);
    return -4;
  }

  /* we liked it. put it in place. */
  return 0;
}

/** Reset config option <b>var</b> to 0, 0.0, NULL, or the equivalent.
 * Called from option_reset() and config_free(). */
static void
option_clear(config_format_t *fmt, or_options_t *options, config_var_t *var)
{
  void *lvalue = STRUCT_VAR_P(options, var->var_offset);
  (void)fmt; /* unused */
  switch (var->type) {
    case CONFIG_TYPE_STRING:
      tor_free(*(char**)lvalue);
      break;
    case CONFIG_TYPE_DOUBLE:
      *(double*)lvalue = 0.0;
      break;
    case CONFIG_TYPE_ISOTIME:
      *(time_t*)lvalue = 0;
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
      config_free_lines(*(config_line_t **)lvalue);
      *(config_line_t **)lvalue = NULL;
      break;
    case CONFIG_TYPE_LINELIST_V:
      /* handled by linelist_s. */
      break;
    case CONFIG_TYPE_OBSOLETE:
      break;
  }
}

/** Clear the option indexed by <b>var</b> in <b>options</b>. Then if
 * <b>use_defaults</b>, set it to its default value.
 * Called by config_init() and option_reset_line() and option_assign_line(). */
static void
option_reset(config_format_t *fmt, or_options_t *options,
             config_var_t *var, int use_defaults)
{
  config_line_t *c;
  void *lvalue;
  char *msg = NULL;
  CHECK(fmt, options);
  option_clear(fmt, options, var); /* clear it first */
  if (!use_defaults)
    return; /* all done */
  lvalue = STRUCT_VAR_P(options, var->var_offset);
  if (var->initvalue) {
    c = tor_malloc_zero(sizeof(config_line_t));
    c->key = tor_strdup(var->name);
    c->value = tor_strdup(var->initvalue);
    if (config_assign_value(fmt, options, c, &msg) < 0) {
      log_warn(LD_BUG, "Failed to assign default: %s", msg);
      tor_free(msg); /* if this happens it's a bug */
    }
    config_free_lines(c);
  }
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

/** Last value actually set by resolve_my_address. */
static uint32_t last_resolved_addr = 0;
/**
 * Based on <b>options-\>Address</b>, guess our public IP address and put it
 * (in host order) into *<b>addr_out</b>. If <b>hostname_out</b> is provided,
 * set *<b>hostname_out</b> to a new string holding the hostname we used to
 * get the address. Return 0 if all is well, or -1 if we can't find a suitable
 * public IP address.
 */
int
resolve_my_address(int warn_severity, or_options_t *options,
                   uint32_t *addr_out, char **hostname_out)
{
  struct in_addr in;
  struct hostent *rent;
  char hostname[256];
  int explicit_ip=1;
  int explicit_hostname=1;
  char tmpbuf[INET_NTOA_BUF_LEN];
  const char *address = options->Address;
  int notice_severity = warn_severity <= LOG_NOTICE ?
                          LOG_NOTICE : warn_severity;

  tor_assert(addr_out);

  if (address && *address) {
    strlcpy(hostname, address, sizeof(hostname));
  } else { /* then we need to guess our address */
    explicit_ip = 0; /* it's implicit */
    explicit_hostname = 0; /* it's implicit */

    if (gethostname(hostname, sizeof(hostname)) < 0) {
      log_fn(warn_severity, LD_NET,"Error obtaining local hostname");
      return -1;
    }
    log_debug(LD_CONFIG,"Guessed local host name as '%s'",hostname);
  }

  /* now we know hostname. resolve it and keep only the IP address */

  if (tor_inet_aton(hostname, &in) == 0) {
    /* then we have to resolve it */
    explicit_ip = 0;
    rent = (struct hostent *)gethostbyname(hostname);
    if (!rent) {
      uint32_t interface_ip;

      if (explicit_hostname) {
        log_fn(warn_severity, LD_CONFIG,
               "Could not resolve local Address '%s'. Failing.", hostname);
        return -1;
      }
      log_fn(notice_severity, LD_CONFIG,
             "Could not resolve guessed local hostname '%s'. "
             "Trying something else.", hostname);
      if (get_interface_address(warn_severity, &interface_ip)) {
        log_fn(warn_severity, LD_CONFIG,
               "Could not get local interface IP address. Failing.");
        return -1;
      }
      in.s_addr = htonl(interface_ip);
      tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
      log_fn(notice_severity, LD_CONFIG, "Learned IP address '%s' for "
             "local interface. Using that.", tmpbuf);
      strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
    } else {
      tor_assert(rent->h_length == 4);
      memcpy(&in.s_addr, rent->h_addr, rent->h_length);

      if (!explicit_hostname &&
          is_internal_IP(ntohl(in.s_addr), 0)) {
        uint32_t interface_ip;

        tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
        log_fn(notice_severity, LD_CONFIG, "Guessed local hostname '%s' "
               "resolves to a private IP address (%s).  Trying something "
               "else.", hostname, tmpbuf);

        if (get_interface_address(warn_severity, &interface_ip)) {
          log_fn(warn_severity, LD_CONFIG,
                 "Could not get local interface IP address. Too bad.");
        } else if (is_internal_IP(interface_ip, 0)) {
          struct in_addr in2;
          in2.s_addr = htonl(interface_ip);
          tor_inet_ntoa(&in2,tmpbuf,sizeof(tmpbuf));
          log_fn(notice_severity, LD_CONFIG,
                 "Interface IP address '%s' is a private address too. "
                 "Ignoring.", tmpbuf);
        } else {
          in.s_addr = htonl(interface_ip);
          tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
          log_fn(notice_severity, LD_CONFIG,
                 "Learned IP address '%s' for local interface."
                 " Using that.", tmpbuf);
          strlcpy(hostname, "<guessed from interfaces>", sizeof(hostname));
        }
      }
    }
  }

  tor_inet_ntoa(&in,tmpbuf,sizeof(tmpbuf));
  if (is_internal_IP(ntohl(in.s_addr), 0) &&
      options->PublishServerDescriptor) {
    /* make sure we're ok with publishing an internal IP */
    if (!options->DirServers) {
      /* if they are using the default dirservers, disallow internal IPs
       * always. */
      log_fn(warn_severity, LD_CONFIG,
             "Address '%s' resolves to private IP address '%s'. "
             "Tor servers that use the default DirServers must have public "
             "IP addresses.", hostname, tmpbuf);
      return -1;
    }
    if (!explicit_ip) {
      /* even if they've set their own dirservers, require an explicit IP if
       * they're using an internal address. */
      log_fn(warn_severity, LD_CONFIG, "Address '%s' resolves to private "
             "IP address '%s'. Please set the Address config option to be "
             "the IP address you want to use.", hostname, tmpbuf);
      return -1;
    }
  }

  log_debug(LD_CONFIG, "Resolved Address to '%s'.", tmpbuf);
  *addr_out = ntohl(in.s_addr);
  if (last_resolved_addr && last_resolved_addr != *addr_out) {
    /* Leave this as a notice, regardless of the requested severity,
     * at least until dynamic IP address support becomes bulletproof. */
    log_notice(LD_NET, "Your IP address seems to have changed. Updating.");
    server_has_changed_ip();
  }
  last_resolved_addr = *addr_out;
  if (hostname_out)
    *hostname_out = tor_strdup(hostname);
  return 0;
}

/** Return true iff <b>ip</b> (in host order) is judged to be on the
 * same network as us, or on a private network.
 */
int
is_local_IP(uint32_t ip)
{
  if (is_internal_IP(ip, 0))
    return 1;
  /* Check whether ip is on the same /24 as we are.
   *
   * It's possible that this next check will hit before the first time
   * resolve_my_address actually succeeds.  (For clients, it is likely that
   * resolve_my_address will never be called at all).  In those cases,
   * last_resolved_addr will be 0, and so checking to see whether ip is on the
   * same /24 as last_resolved_addr will be the same as checking whether it
   * was on net 0, which is already done by is_internal_IP.
   */
  if ((last_resolved_addr & 0xffffff00ul) == (ip & 0xffffff00ul))
    return 1;
  return 0;
}


/** Called when we don't have a nickname set.  Try to guess a good nickname
 * based on the hostname, and return it in a newly allocated string. If we
 * can't, return NULL and let the caller warn if it wants to. */
static char *
get_default_nickname(void)
{
  static const char * const bad_default_nicknames[] = {
    "localhost",
    NULL,
  };
  char localhostname[256];
  char *cp, *out, *outp;
  int i;

  if (gethostname(localhostname, sizeof(localhostname)) < 0)
    return NULL;

  /* Put it in lowercase; stop at the first dot. */
  if ((cp = strchr(localhostname, '.')))
    *cp = '\0';
  tor_strlower(localhostname);

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

  /* Check for dumb names. */
  for (i = 0; bad_default_nicknames[i]; ++i) {
    if (!strcmp(out, bad_default_nicknames[i])) {
      tor_free(out);
      return NULL;
    }
  }

  return out;
}

/** Release storage held by <b>options</b> */
static void
config_free(config_format_t *fmt, void *options)
{
  int i;

  tor_assert(options);

  for (i=0; fmt->vars[i].name; ++i)
    option_clear(fmt, options, &(fmt->vars[i]));
  if (fmt->extra) {
    config_line_t **linep = STRUCT_VAR_P(options, fmt->extra->var_offset);
    config_free_lines(*linep);
    *linep = NULL;
  }
  tor_free(options);
}

/** Return true iff a and b contain identical keys and values in identical
 * order. */
static int
config_lines_eq(config_line_t *a, config_line_t *b)
{
  while (a && b) {
    if (strcasecmp(a->key, b->key) || strcmp(a->value, b->value))
      return 0;
    a = a->next;
    b = b->next;
  }
  if (a || b)
    return 0;
  return 1;
}

/** Return true iff the option <b>var</b> has the same value in <b>o1</b>
 * and <b>o2</b>.  Must not be called for LINELIST_S or OBSOLETE options.
 */
static int
option_is_same(config_format_t *fmt,
               or_options_t *o1, or_options_t *o2, const char *name)
{
  config_line_t *c1, *c2;
  int r = 1;
  CHECK(fmt, o1);
  CHECK(fmt, o2);

  c1 = get_assigned_option(fmt, o1, name);
  c2 = get_assigned_option(fmt, o2, name);
  r = config_lines_eq(c1, c2);
  config_free_lines(c1);
  config_free_lines(c2);
  return r;
}

/** Copy storage held by <b>old</b> into a new or_options_t and return it. */
static or_options_t *
options_dup(config_format_t *fmt, or_options_t *old)
{
  or_options_t *newopts;
  int i;
  config_line_t *line;

  newopts = config_alloc(fmt);
  for (i=0; fmt->vars[i].name; ++i) {
    if (fmt->vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    if (fmt->vars[i].type == CONFIG_TYPE_OBSOLETE)
      continue;
    line = get_assigned_option(fmt, old, fmt->vars[i].name);
    if (line) {
      char *msg = NULL;
      if (config_assign(fmt, newopts, line, 0, 0, &msg) < 0) {
        log_err(LD_BUG, "Bug: config_get_assigned_option() generated "
                "something we couldn't config_assign(): %s", msg);
        tor_free(msg);
        tor_assert(0);
      }
    }
    config_free_lines(line);
  }
  return newopts;
}

/** Return a new empty or_options_t.  Used for testing. */
or_options_t *
options_new(void)
{
  return config_alloc(&options_format);
}

/** Set <b>options</b> to hold reasonable defaults for most options.
 * Each option defaults to zero. */
void
options_init(or_options_t *options)
{
  config_init(&options_format, options);
}

/* Set all vars in the configuration object 'options' to their default
 * values. */
static void
config_init(config_format_t *fmt, void *options)
{
  int i;
  config_var_t *var;
  CHECK(fmt, options);

  for (i=0; fmt->vars[i].name; ++i) {
    var = &fmt->vars[i];
    if (!var->initvalue)
      continue; /* defaults to NULL or 0 */
    option_reset(fmt, options, var, 1);
  }
}

/* Allocate and return a new string holding the written-out values of the vars
 * in 'options' If 'minimal', do not write out any default-valued vars. */
static char *
config_dump(config_format_t *fmt, void *options, int minimal)
{
  smartlist_t *elements;
  or_options_t *defaults;
  config_line_t *line, *assigned;
  char *result;
  int i;
  const char *desc;
  char *msg = NULL;

  defaults = config_alloc(fmt);
  config_init(fmt, defaults);

  /* XXX use a 1 here so we don't add a new log line while dumping */
  if (fmt->validate_fn(NULL,defaults, 1, &msg) < 0) {
    log_err(LD_BUG, "Failed to validate default config.");
    tor_free(msg);
    tor_assert(0);
  }

  elements = smartlist_create();
  for (i=0; fmt->vars[i].name; ++i) {
    if (fmt->vars[i].type == CONFIG_TYPE_OBSOLETE ||
        fmt->vars[i].type == CONFIG_TYPE_LINELIST_S)
      continue;
    /* Don't save 'hidden' control variables. */
    if (!strcmpstart(fmt->vars[i].name, "__"))
      continue;
    if (minimal && option_is_same(fmt, options, defaults, fmt->vars[i].name))
      continue;

    desc = config_find_description(fmt, fmt->vars[i].name);
    line = assigned = get_assigned_option(fmt, options, fmt->vars[i].name);

    if (line && desc) {
      /* Only dump the description if there's something to describe. */
      size_t len = strlen(desc)+8;
      char *tmp = tor_malloc(len);
      tor_snprintf(tmp, len, "# %s\n",desc);
      smartlist_add(elements, tmp);
    }

    for (; line; line = line->next) {
      size_t len = strlen(line->key) + strlen(line->value) + 3;
      char *tmp;
      tmp = tor_malloc(len);
      if (tor_snprintf(tmp, len, "%s %s\n", line->key, line->value)<0) {
        log_err(LD_BUG,"Internal error writing option value");
        tor_assert(0);
      }
      smartlist_add(elements, tmp);
    }
    config_free_lines(assigned);
  }

  if (fmt->extra) {
    line = *(config_line_t**)STRUCT_VAR_P(options, fmt->extra->var_offset);
    for (; line; line = line->next) {
      size_t len = strlen(line->key) + strlen(line->value) + 3;
      char *tmp;
      tmp = tor_malloc(len);
      if (tor_snprintf(tmp, len, "%s %s\n", line->key, line->value)<0) {
        log_err(LD_BUG,"Internal error writing option value");
        tor_assert(0);
      }
      smartlist_add(elements, tmp);
    }
  }

  result = smartlist_join_strings(elements, "", 0, NULL);
  SMARTLIST_FOREACH(elements, char *, cp, tor_free(cp));
  smartlist_free(elements);
  config_free(fmt, defaults);
  return result;
}

/** Return a string containing a possible configuration file that would give
 * the configuration in <b>options</b>.  If <b>minimal</b> is true, do not
 * include options that are the same as Tor's defaults.
 */
char *
options_dump(or_options_t *options, int minimal)
{
  return config_dump(&options_format, options, minimal);
}

/* Return 0 if every element of sl is a string holding a decimal
 * representation of a port number, or if sl is NULL.
 * Otherwise set *msg and return -1. */
static int
validate_ports_csv(smartlist_t *sl, const char *name, char **msg)
{
  int i;
  char buf[1024];
  tor_assert(name);

  if (!sl)
    return 0;

  SMARTLIST_FOREACH(sl, const char *, cp,
  {
    i = atoi(cp);
    if (i < 1 || i > 65535) {
      int r = tor_snprintf(buf, sizeof(buf),
                           "Port '%s' out of range in %s", cp, name);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
  });
  return 0;
}

#if 0
/* XXXX Unused. */
/** Return 0 if every element of sl is a string holding an IP address, or if sl
 * is NULL.  Otherwise set *msg and return -1. */
static int
validate_ips_csv(smartlist_t *sl, const char *name, char **msg)
{
  char buf[1024];
  tor_assert(name);

  if (!sl)
    return 0;

  SMARTLIST_FOREACH(sl, const char *, cp,
  {
    struct in_addr in;
    if (0 == tor_inet_aton(cp, &in)) {
      int r = tor_snprintf(buf, sizeof(buf),
                        "Malformed address '%s' out of range in %s", cp, name);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
  });
  return 0;
}
#endif

/** Lowest allowable value for RendPostPeriod; if this is too low, hidden
 * services can overload the directory system. */
#define MIN_REND_POST_PERIOD (5*60)

/** Highest allowable value for DirFetchPeriod, StatusFetchPeriod, and
 * RendPostPeriod. */
#define MAX_DIR_PERIOD (MIN_ONION_KEY_LIFETIME/2)

/** Return 0 if every setting in <b>options</b> is reasonable, and a
 * permissible transition from <b>old_options</b>. Else return -1.
 * Should have no side effects, except for normalizing the contents of
 * <b>options</b>.
 *
 * On error, tor_strdup an error explanation into *<b>msg</b>.
 *
 * XXX
 * If <b>from_setconf</b>, we were called by the controller, and our
 * Log line should stay empty. If it's 0, then give us a default log
 * if there are no logs defined.
 */
static int
options_validate(or_options_t *old_options, or_options_t *options,
                 int from_setconf, char **msg)
{
  int i, r;
  config_line_t *cl;
  const char *uname;
  char buf[1024];
#define REJECT(arg) \
  do { *msg = tor_strdup(arg); return -1; } while (0)
#define COMPLAIN(arg) do { log(LOG_WARN, LD_CONFIG, arg); } while (0)

  tor_assert(msg);
  *msg = NULL;

  if (options->ORPort < 0 || options->ORPort > 65535)
    REJECT("ORPort option out of bounds.");

  uname = get_uname();
  if (server_mode(options) &&
      (!strcmpstart(uname, "Windows 95") ||
       !strcmpstart(uname, "Windows 98") ||
       !strcmpstart(uname, "Windows Me"))) {
    log(LOG_WARN, LD_CONFIG, "Tor is running as a server, but you are "
        "running %s; this probably won't work. See "
        "http://wiki.noreply.org/noreply/TheOnionRouter/TorFAQ#ServerOS "
        "for details.", get_uname());
  }

  if (options->ORPort == 0 && options->ORListenAddress != NULL)
    REJECT("ORPort must be defined if ORListenAddress is defined.");

  if (options->DirPort == 0 && options->DirListenAddress != NULL)
    REJECT("DirPort must be defined if DirListenAddress is defined.");

  if (options->ControlPort == 0 && options->ControlListenAddress != NULL)
    REJECT("ControlPort must be defined if ControlListenAddress is defined.");

  if (options->TransPort == 0 && options->TransListenAddress != NULL)
    REJECT("TransPort must be defined if TransListenAddress is defined.");

#if 0 /* don't complain, since a standard configuration does this! */
  if (options->SocksPort == 0 && options->SocksListenAddress != NULL)
    REJECT("SocksPort must be defined if SocksListenAddress is defined.");
#endif

  for (i = 0; i < 2; ++i) {
    int is_socks = i==0;
    config_line_t *line, *opt, *old;
    const char *tp = is_socks ? "SOCKS proxy" : "transparent proxy";
    if (is_socks) {
      opt = options->SocksListenAddress;
      old = old_options ? old_options->SocksListenAddress : NULL;
    } else {
      opt = options->TransListenAddress;
      old = old_options ? old_options->TransListenAddress : NULL;
    }

    for (line = opt; line; line = line->next) {
      char *address = NULL;
      uint16_t port;
      uint32_t addr;
      if (parse_addr_port(LOG_WARN, line->value, &address, &addr, &port)<0)
        continue; /* We'll warn about this later. */
      if (!is_internal_IP(addr, 1) &&
          (!old_options || !config_lines_eq(old, opt))) {
        log_warn(LD_CONFIG,
             "You specified a public address '%s' for a %s. Other "
             "people on the Internet might find your computer and use it as "
             "an open %s. Please don't allow this unless you have "
             "a good reason.", address, tp, tp);
      }
      tor_free(address);
    }
  }

  if (validate_data_directory(options)<0)
    REJECT("Invalid DataDirectory");

  if (options->Nickname == NULL) {
    if (server_mode(options)) {
      if (!(options->Nickname = get_default_nickname())) {
        log_notice(LD_CONFIG, "Couldn't pick a nickname based on "
                   "our hostname; using %s instead.", UNNAMED_ROUTER_NICKNAME);
        options->Nickname = tor_strdup(UNNAMED_ROUTER_NICKNAME);
      } else {
        log_notice(LD_CONFIG, "Choosing default nickname '%s'",
                   options->Nickname);
      }
    }
  } else {
    if (!is_legal_nickname(options->Nickname)) {
      r = tor_snprintf(buf, sizeof(buf),
          "Nickname '%s' is wrong length or contains illegal characters.",
          options->Nickname);
      *msg = tor_strdup(r >= 0 ? buf : "internal error");
      return -1;
    }
  }

  if (server_mode(options) && !options->ContactInfo)
    log(LOG_NOTICE, LD_CONFIG, "Your ContactInfo config option is not set. "
        "Please consider setting it, so we can contact you if your server is "
        "misconfigured or something else goes wrong.");

  if (normalize_log_options(options))
    REJECT("Failed to normalize old Log options. See logs for details.");

  /* Special case on first boot if no Log options are given. */
  if (!options->Logs && !options->RunAsDaemon && !from_setconf)
    config_line_append(&options->Logs, "Log", "notice stdout");

  if (options_init_logs(options, 1)<0) /* Validate the log(s) */
    REJECT("Failed to validate Log options. See logs for details.");

  if (options->NoPublish) {
    log(LOG_WARN, LD_CONFIG,
        "NoPublish is obsolete. Use PublishServerDescriptor instead.");
    options->PublishServerDescriptor = 0;
  }

  if (authdir_mode(options)) {
    /* confirm that our address isn't broken, so we can complain now */
    uint32_t tmp;
    if (resolve_my_address(LOG_WARN, options, &tmp, NULL) < 0)
      REJECT("Failed to resolve/guess local address. See logs for details.");
  }

#ifndef MS_WINDOWS
  if (options->RunAsDaemon && torrc_fname && path_is_relative(torrc_fname))
    REJECT("Can't use a relative path to torrc when RunAsDaemon is set.");
#endif

  if (options->SocksPort < 0 || options->SocksPort > 65535)
    REJECT("SocksPort option out of bounds.");

  if (options->TransPort < 0 || options->TransPort > 65535)
    REJECT("TransPort option out of bounds.");

  if (options->SocksPort == 0 && options->TransPort == 0 &&
      options->ORPort == 0)
    REJECT("SocksPort, TransPort, and ORPort are all undefined? Quitting.");

  if (options->ControlPort < 0 || options->ControlPort > 65535)
    REJECT("ControlPort option out of bounds.");

  if (options->DirPort < 0 || options->DirPort > 65535)
    REJECT("DirPort option out of bounds.");

#ifndef USE_TRANSPARENT
  if (options->TransPort || options->TransListenAddress)
    REJECT("TransPort and TransListenAddress are disabled in this build.");
#endif

  if (options->StrictExitNodes &&
      (!options->ExitNodes || !strlen(options->ExitNodes)) &&
      (!old_options ||
       (old_options->StrictExitNodes != options->StrictExitNodes) ||
       (!opt_streq(old_options->ExitNodes, options->ExitNodes))))
    COMPLAIN("StrictExitNodes set, but no ExitNodes listed.");

  if (options->StrictEntryNodes &&
      (!options->EntryNodes || !strlen(options->EntryNodes)) &&
      (!old_options ||
       (old_options->StrictEntryNodes != options->StrictEntryNodes) ||
       (!opt_streq(old_options->EntryNodes, options->EntryNodes))))
    COMPLAIN("StrictEntryNodes set, but no EntryNodes listed.");

  if (options->AuthoritativeDir) {
    if (!options->ContactInfo)
      REJECT("Authoritative directory servers must set ContactInfo");
    if (options->V1AuthoritativeDir && !options->RecommendedVersions)
      REJECT("V1 auth dir servers must set RecommendedVersions.");
    if (!options->RecommendedClientVersions)
      options->RecommendedClientVersions =
        config_lines_dup(options->RecommendedVersions);
    if (!options->RecommendedServerVersions)
      options->RecommendedServerVersions =
        config_lines_dup(options->RecommendedVersions);
    if (options->VersioningAuthoritativeDir &&
        (!options->RecommendedClientVersions ||
         !options->RecommendedServerVersions))
      REJECT("Versioning auth dir servers must set Recommended*Versions.");
    if (options->UseEntryGuards) {
      log_info(LD_CONFIG, "Authoritative directory servers can't set "
               "UseEntryGuards. Disabling.");
      options->UseEntryGuards = 0;
    }
  }

  if (options->AuthoritativeDir && !options->DirPort)
    REJECT("Running as authoritative directory, but no DirPort set.");

  if (options->AuthoritativeDir && !options->ORPort)
    REJECT("Running as authoritative directory, but no ORPort set.");

  if (options->AuthoritativeDir && options->ClientOnly)
    REJECT("Running as authoritative directory, but ClientOnly also set.");

  if (options->ConnLimit <= 0) {
    r = tor_snprintf(buf, sizeof(buf),
        "ConnLimit must be greater than 0, but was set to %d",
        options->ConnLimit);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  }

  if (options->_AccountingMaxKB) {
    log(LOG_WARN, LD_CONFIG, "AccountingMaxKB is deprecated.  "
        "Say 'AccountingMax %d KB' instead.", options->_AccountingMaxKB);
    options->AccountingMax = U64_LITERAL(1024)*options->_AccountingMaxKB;
    options->_AccountingMaxKB = 0;
  }

  if (validate_ports_csv(options->FirewallPorts, "FirewallPorts", msg) < 0)
    return -1;

  if (validate_ports_csv(options->LongLivedPorts, "LongLivedPorts", msg) < 0)
    return -1;

  if (options->FascistFirewall && !options->ReachableAddresses) {
    if (options->FirewallPorts && smartlist_len(options->FirewallPorts)) {
      /* We already have firewall ports set, so migrate them to
       * ReachableAddresses, which will set ReachableORAddresses and
       * ReachableDirAddresses if they aren't set explicitly. */
      smartlist_t *instead = smartlist_create();
      config_line_t *new_line = tor_malloc_zero(sizeof(config_line_t));
      new_line->key = tor_strdup("ReachableAddresses");
      /* If we're configured with the old format, we need to prepend some
       * open ports. */
      SMARTLIST_FOREACH(options->FirewallPorts, const char *, portno,
      {
        int p = atoi(portno);
        char *s;
        if (p<0) continue;
        s = tor_malloc(16);
        tor_snprintf(s, 16, "*:%d", p);
        smartlist_add(instead, s);
      });
      new_line->value = smartlist_join_strings(instead,",",0,NULL);
      /* These have been deprecated since 0.1.1.5-alpha-cvs */
      log(LOG_NOTICE, LD_CONFIG,
          "Converting FascistFirewall and FirewallPorts "
          "config options to new format: \"ReachableAddresses %s\"",
          new_line->value);
      options->ReachableAddresses = new_line;
      SMARTLIST_FOREACH(instead, char *, cp, tor_free(cp));
      smartlist_free(instead);
    } else {
      /* We do not have FirewallPorts set, so add 80 to
       * ReachableDirAddresses, and 443 to ReachableORAddresses. */
      if (!options->ReachableDirAddresses) {
        config_line_t *new_line = tor_malloc_zero(sizeof(config_line_t));
        new_line->key = tor_strdup("ReachableDirAddresses");
        new_line->value = tor_strdup("*:80");
        options->ReachableDirAddresses = new_line;
        log(LOG_NOTICE, LD_CONFIG, "Converting FascistFirewall config option "
            "to new format: \"ReachableDirAddresses *:80\"");
      }
      if (!options->ReachableORAddresses) {
        config_line_t *new_line = tor_malloc_zero(sizeof(config_line_t));
        new_line->key = tor_strdup("ReachableORAddresses");
        new_line->value = tor_strdup("*:443");
        options->ReachableORAddresses = new_line;
        log(LOG_NOTICE, LD_CONFIG, "Converting FascistFirewall config option "
            "to new format: \"ReachableORAddresses *:443\"");
      }
    }
  }

  for (i=0; i<3; i++) {
    config_line_t **linep =
      (i==0) ? &options->ReachableAddresses :
        (i==1) ? &options->ReachableORAddresses :
                 &options->ReachableDirAddresses;
    if (!*linep)
      continue;
    /* We need to end with a reject *:*, not an implicit accept *:* */
    for (;;) {
      if (!strcmp((*linep)->value, "reject *:*")) /* already there */
        break;
      linep = &((*linep)->next);
      if (!*linep) {
        *linep = tor_malloc_zero(sizeof(config_line_t));
        (*linep)->key = tor_strdup(
          (i==0) ?  "ReachableAddresses" :
            (i==1) ? "ReachableORAddresses" :
                     "ReachableDirAddresses");
        (*linep)->value = tor_strdup("reject *:*");
        break;
      }
    }
  }

  if ((options->ReachableAddresses ||
       options->ReachableORAddresses ||
       options->ReachableDirAddresses) &&
      server_mode(options))
    REJECT("Servers must be able to freely connect to the rest "
           "of the Internet, so they must not set Reachable*Addresses "
           "or FascistFirewall.");

  options->_AllowInvalid = 0;
  if (options->AllowInvalidNodes) {
    SMARTLIST_FOREACH(options->AllowInvalidNodes, const char *, cp, {
        if (!strcasecmp(cp, "entry"))
          options->_AllowInvalid |= ALLOW_INVALID_ENTRY;
        else if (!strcasecmp(cp, "exit"))
          options->_AllowInvalid |= ALLOW_INVALID_EXIT;
        else if (!strcasecmp(cp, "middle"))
          options->_AllowInvalid |= ALLOW_INVALID_MIDDLE;
        else if (!strcasecmp(cp, "introduction"))
          options->_AllowInvalid |= ALLOW_INVALID_INTRODUCTION;
        else if (!strcasecmp(cp, "rendezvous"))
          options->_AllowInvalid |= ALLOW_INVALID_RENDEZVOUS;
        else {
          r = tor_snprintf(buf, sizeof(buf),
              "Unrecognized value '%s' in AllowInvalidNodes", cp);
          *msg = tor_strdup(r >= 0 ? buf : "internal error");
          return -1;
        }
      });
  }

  if (options->SocksPort >= 1 &&
      (options->PathlenCoinWeight < 0.0 || options->PathlenCoinWeight >= 1.0))
    REJECT("PathlenCoinWeight option must be >=0.0 and <1.0.");

  if (options->RendPostPeriod < MIN_REND_POST_PERIOD) {
    log(LOG_WARN,LD_CONFIG,"RendPostPeriod option must be at least %d seconds."
        " Clipping.", MIN_REND_POST_PERIOD);
    options->RendPostPeriod = MIN_REND_POST_PERIOD;
  }

  if (options->RendPostPeriod > MAX_DIR_PERIOD) {
    log(LOG_WARN, LD_CONFIG, "RendPostPeriod is too large; clipping to %ds.",
        MAX_DIR_PERIOD);
    options->RendPostPeriod = MAX_DIR_PERIOD;
  }

  if (options->KeepalivePeriod < 1)
    REJECT("KeepalivePeriod option must be positive.");

  if (options->BandwidthRate > INT_MAX) {
    r = tor_snprintf(buf, sizeof(buf),
                     "BandwidthRate must be less than %d",INT_MAX);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  }
  if (options->BandwidthBurst > INT_MAX) {
    r = tor_snprintf(buf, sizeof(buf),
                     "BandwidthBurst must be less than %d",INT_MAX);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  }
  if (server_mode(options) &&
      options->BandwidthRate < ROUTER_REQUIRED_MIN_BANDWIDTH*2) {
    r = tor_snprintf(buf, sizeof(buf),
                     "BandwidthRate is set to %d bytes/second. "
                     "For servers, it must be at least %d.",
                     (int)options->BandwidthRate,
                     ROUTER_REQUIRED_MIN_BANDWIDTH*2);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  }
  if (options->BandwidthRate > options->BandwidthBurst)
    REJECT("BandwidthBurst must be at least equal to BandwidthRate.");

  if (accounting_parse_options(options, 1)<0)
    REJECT("Failed to parse accounting options. See logs for details.");

  if (options->HttpProxy) { /* parse it now */
    if (parse_addr_port(LOG_WARN, options->HttpProxy, NULL,
                        &options->HttpProxyAddr, &options->HttpProxyPort) < 0)
      REJECT("HttpProxy failed to parse or resolve. Please fix.");
    if (options->HttpProxyPort == 0) { /* give it a default */
      options->HttpProxyPort = 80;
    }
  }

  if (options->HttpProxyAuthenticator) {
    if (strlen(options->HttpProxyAuthenticator) >= 48)
      REJECT("HttpProxyAuthenticator is too long (>= 48 chars).");
  }

  if (options->HttpsProxy) { /* parse it now */
    if (parse_addr_port(LOG_WARN, options->HttpsProxy, NULL,
                        &options->HttpsProxyAddr, &options->HttpsProxyPort) <0)
      REJECT("HttpsProxy failed to parse or resolve. Please fix.");
    if (options->HttpsProxyPort == 0) { /* give it a default */
      options->HttpsProxyPort = 443;
    }
  }

  if (options->HttpsProxyAuthenticator) {
    if (strlen(options->HttpsProxyAuthenticator) >= 48)
      REJECT("HttpsProxyAuthenticator is too long (>= 48 chars).");
  }

  if (options->HashedControlPassword) {
    if (decode_hashed_password(NULL, options->HashedControlPassword)<0)
      REJECT("Bad HashedControlPassword: wrong length or bad encoding");
  }
  if (options->HashedControlPassword && options->CookieAuthentication)
    REJECT("Cannot set both HashedControlPassword and CookieAuthentication");

  if (options->UseEntryGuards && ! options->NumEntryGuards)
    REJECT("Cannot enable UseEntryGuards with NumEntryGuards set to 0");

#ifndef USE_EVENTDNS
  if (options->ServerDNSResolvConfFile)
    log(LOG_WARN, LD_CONFIG,
       "ServerDNSResolvConfFile only works when eventdns support is enabled.");
#endif

  if (check_nickname_list(options->ExitNodes, "ExitNodes", msg))
    return -1;
  if (check_nickname_list(options->EntryNodes, "EntryNodes", msg))
    return -1;
  if (check_nickname_list(options->ExcludeNodes, "ExcludeNodes", msg))
    return -1;
  if (check_nickname_list(options->RendNodes, "RendNodes", msg))
    return -1;
  if (check_nickname_list(options->RendNodes, "RendExcludeNodes", msg))
    return -1;
  if (check_nickname_list(options->TestVia, "TestVia", msg))
    return -1;
  if (check_nickname_list(options->MyFamily, "MyFamily", msg))
    return -1;
  for (cl = options->NodeFamilies; cl; cl = cl->next) {
    if (check_nickname_list(cl->value, "NodeFamily", msg))
      return -1;
  }

  if (validate_addr_policies(options, msg) < 0)
    return -1;

  for (cl = options->RedirectExit; cl; cl = cl->next) {
    if (parse_redirect_line(NULL, cl, msg)<0)
      return -1;
  }

  if (options->DirServers) {
    if (!old_options ||
        !config_lines_eq(options->DirServers, old_options->DirServers))
        COMPLAIN("You have used DirServer to specify directory authorities in "
                 "your configuration.  This is potentially dangerous: it can "
                 "make you look different from all other Tor users, and hurt "
                 "your anonymity.  Even if you've specified the same "
                 "authorities as Tor uses by default, the defaults could "
                 "change in the future.  Be sure you know what you're doing.");
    for (cl = options->DirServers; cl; cl = cl->next) {
      if (parse_dir_server_line(cl->value, 1)<0)
        REJECT("DirServer line did not parse. See logs for details.");
    }
  }

  if (rend_config_services(options, 1) < 0)
    REJECT("Failed to configure rendezvous options. See logs for details.");

  if (parse_virtual_addr_network(options->VirtualAddrNetwork, 1, NULL)<0)
    return -1;

  return 0;
#undef REJECT
#undef COMPLAIN
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
options_transition_allowed(or_options_t *old, or_options_t *new_val,
                           char **msg)
{
  if (!old)
    return 0;

  if (!opt_streq(old->PidFile, new_val->PidFile)) {
    *msg = tor_strdup("PidFile is not allowed to change.");
    return -1;
  }

  if (old->RunAsDaemon != new_val->RunAsDaemon) {
    *msg = tor_strdup("While Tor is running, changing RunAsDaemon "
                      "is not allowed.");
    return -1;
  }

  if (strcmp(old->DataDirectory,new_val->DataDirectory)!=0) {
    char buf[1024];
    int r = tor_snprintf(buf, sizeof(buf),
               "While Tor is running, changing DataDirectory "
               "(\"%s\"->\"%s\") is not allowed.",
               old->DataDirectory, new_val->DataDirectory);
    *msg = tor_strdup(r >= 0 ? buf : "internal error");
    return -1;
  }

  if (!opt_streq(old->User, new_val->User)) {
    *msg = tor_strdup("While Tor is running, changing User is not allowed.");
    return -1;
  }

  if (!opt_streq(old->Group, new_val->Group)) {
    *msg = tor_strdup("While Tor is running, changing Group is not allowed.");
    return -1;
  }

  if (old->HardwareAccel != new_val->HardwareAccel) {
    *msg = tor_strdup("While Tor is running, changing HardwareAccel is "
                      "not allowed.");
    return -1;
  }

  return 0;
}

/** Return 1 if any change from <b>old_options</b> to <b>new_options</b>
 * will require us to rotate the cpu and dns workers; else return 0. */
static int
options_transition_affects_workers(or_options_t *old_options,
                                   or_options_t *new_options)
{
  if (!opt_streq(old_options->DataDirectory, new_options->DataDirectory) ||
      old_options->NumCpus != new_options->NumCpus ||
      old_options->ORPort != new_options->ORPort ||
      old_options->ServerDNSSearchDomains !=
                                       new_options->ServerDNSSearchDomains ||
      old_options->SafeLogging != new_options->SafeLogging ||
      !config_lines_eq(old_options->Logs, new_options->Logs))
    return 1;

  /* Check whether log options match. */

  /* Nothing that changed matters. */
  return 0;
}

/** Return 1 if any change from <b>old_options</b> to <b>new_options</b>
 * will require us to generate a new descriptor; else return 0. */
static int
options_transition_affects_descriptor(or_options_t *old_options,
                                      or_options_t *new_options)
{
  if (!opt_streq(old_options->DataDirectory, new_options->DataDirectory) ||
      !opt_streq(old_options->Nickname,new_options->Nickname) ||
      !opt_streq(old_options->Address,new_options->Address) ||
      !config_lines_eq(old_options->ExitPolicy,new_options->ExitPolicy) ||
      old_options->ORPort != new_options->ORPort ||
      old_options->DirPort != new_options->DirPort ||
      old_options->ClientOnly != new_options->ClientOnly ||
      old_options->NoPublish != new_options->NoPublish ||
      old_options->PublishServerDescriptor !=
        new_options->PublishServerDescriptor ||
      old_options->BandwidthRate != new_options->BandwidthRate ||
      old_options->BandwidthBurst != new_options->BandwidthBurst ||
      !opt_streq(old_options->ContactInfo, new_options->ContactInfo) ||
      !opt_streq(old_options->MyFamily, new_options->MyFamily) ||
      !opt_streq(old_options->AccountingStart, new_options->AccountingStart) ||
      old_options->AccountingMax != new_options->AccountingMax)
    return 1;

  return 0;
}

#ifdef MS_WINDOWS
/** Return the directory on windows where we expect to find our application
 * data. */
static char *
get_windows_conf_root(void)
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
    log_warn(LD_CONFIG,
             "I couldn't find your application data folder: are you "
             "running an ancient version of Windows 95? Defaulting to \"%s\"",
             path);
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
static const char *
get_default_conf_file(void)
{
#ifdef MS_WINDOWS
  static char path[MAX_PATH+1];
  strlcpy(path, get_windows_conf_root(), MAX_PATH);
  strlcat(path,"\\torrc",MAX_PATH);
  return path;
#else
  return (CONFDIR "/torrc");
#endif
}

/** Verify whether lst is a string containing valid-looking space-separated
 * nicknames, or NULL. Return 0 on success. Warn and return -1 on failure.
 */
static int
check_nickname_list(const char *lst, const char *name, char **msg)
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
        char buf[1024];
        int tmp = tor_snprintf(buf, sizeof(buf),
                  "Invalid nickname '%s' in %s line", s, name);
        *msg = tor_strdup(tmp >= 0 ? buf : "internal error");
        r = -1;
        break;
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
options_init_from_torrc(int argc, char **argv)
{
  or_options_t *oldoptions, *newoptions;
  config_line_t *cl;
  char *cf=NULL, *fname=NULL, *errmsg=NULL;
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
      print_svn_version();
    }
    exit(0);
  }

  newoptions = tor_malloc_zero(sizeof(or_options_t));
  newoptions->_magic = OR_OPTIONS_MAGIC;
  options_init(newoptions);

  /* learn config file name */
  fname = NULL;
  using_default_torrc = 1;
  newoptions->command = CMD_RUN_TOR;
  for (i = 1; i < argc; ++i) {
    if (i < argc-1 && !strcmp(argv[i],"-f")) {
      if (fname) {
        log(LOG_WARN, LD_CONFIG, "Duplicate -f options on command line.");
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
    const char *dflt = get_default_conf_file();
    if (dflt && file_status(dflt) == FN_FILE) {
      fname = tor_strdup(dflt);
    } else {
#ifndef MS_WINDOWS
      char *fn;
      fn = expand_filename("~/.torrc");
      if (fn && file_status(fn) == FN_FILE) {
        fname = fn;
      } else {
        tor_free(fn);
        fname = tor_strdup(dflt);
      }
#else
      fname = tor_strdup(dflt);
#endif
    }
  }
  tor_assert(fname);
  log(LOG_DEBUG, LD_CONFIG, "Opening config file \"%s\"", fname);

  tor_free(torrc_fname);
  torrc_fname = fname;

  /* get config lines, assign them */
  if (file_status(fname) != FN_FILE ||
      !(cf = read_file_to_str(fname,0))) {
    if (using_default_torrc == 1) {
      log(LOG_NOTICE, LD_CONFIG, "Configuration file \"%s\" not present, "
          "using reasonable defaults.", fname);
      tor_free(fname); /* sets fname to NULL */
      torrc_fname = NULL;
    } else {
      log(LOG_WARN, LD_CONFIG,
          "Unable to open configuration file \"%s\".", fname);
      goto err;
    }
  } else { /* it opened successfully. use it. */
    retval = config_get_lines(cf, &cl);
    tor_free(cf);
    if (retval < 0)
      goto err;
    retval = config_assign(&options_format, newoptions, cl, 0, 0, &errmsg);
    config_free_lines(cl);
    if (retval < 0)
      goto err;
  }

  /* Go through command-line variables too */
  if (config_get_commandlines(argc, argv, &cl) < 0)
    goto err;
  retval = config_assign(&options_format, newoptions, cl, 0, 0, &errmsg);
  config_free_lines(cl);
  if (retval < 0)
    goto err;

  /* Validate newoptions */
  if (options_validate(oldoptions, newoptions, 0, &errmsg) < 0)
    goto err;

  if (options_transition_allowed(oldoptions, newoptions, &errmsg) < 0)
    goto err;

  if (set_options(newoptions, &errmsg))
    goto err; /* frees and replaces old options */

  return 0;
 err:
  tor_free(fname);
  torrc_fname = NULL;
  config_free(&options_format, newoptions);
  if (errmsg) {
    log(LOG_WARN,LD_CONFIG,"Failed to parse/validate config: %s", errmsg);
    tor_free(errmsg);
  }
  return -1;
}

/** Return the location for our configuration file.
 */
const char *
get_torrc_fname(void)
{
  if (torrc_fname)
    return torrc_fname;
  else
    return get_default_conf_file();
}

/** Adjust the address map mased on the MapAddress elements in the
 * configuration <b>options</b>
 */
static void
config_register_addressmaps(or_options_t *options)
{
  smartlist_t *elts;
  config_line_t *opt;
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
        log_warn(LD_CONFIG,
                 "Skipping invalid argument '%s' to MapAddress", from);
      } else if (!is_plausible_address(to)) {
        log_warn(LD_CONFIG,
                 "Skipping invalid argument '%s' to MapAddress", to);
      } else {
        addressmap_register(from, tor_strdup(to), 0);
        if (smartlist_len(elts)>2) {
          log_warn(LD_CONFIG,"Ignoring extra arguments to MapAddress.");
        }
      }
    } else {
      log_warn(LD_CONFIG,"MapAddress '%s' has too few arguments. Ignoring.",
               opt->value);
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
        log_warn(LD_CONFIG, "Unrecognized minimum log severity '%s': must be "
                 "one of err|warn|notice|info|debug", tmp_sev);
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
        log_warn(LD_CONFIG, "Unrecognized maximum log severity '%s': must be "
                 "one of err|warn|notice|info|debug", cp+1);
        return -1;
      }
    }
  } else {
    levelMin = parse_log_level(range);
    if (levelMin < 0) {
      log_warn(LD_CONFIG, "Unrecognized log severity '%s': must be one of "
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
convert_log_option(or_options_t *options, config_line_t *level_opt,
                   config_line_t *file_opt, int isDaemon)
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
    if (add_single_log_option(options, levelMin, levelMax, "file",
                              file_opt->value) < 0) {
      log_warn(LD_FS, "Cannot write to LogFile \"%s\": %s.", file_opt->value,
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
options_init_logs(or_options_t *options, int validate_only)
{
  config_line_t *opt;
  int ok;
  smartlist_t *elts;
  int daemon =
#ifdef MS_WINDOWS
               0;
#else
               options->RunAsDaemon;
#endif

  ok = 1;
  elts = smartlist_create();

  for (opt = options->Logs; opt; opt = opt->next) {
    int levelMin=LOG_DEBUG, levelMax=LOG_ERR;
    smartlist_split_string(elts, opt->value, NULL,
                           SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 3);
    if (smartlist_len(elts) == 0) {
      log_warn(LD_CONFIG, "No arguments to Log option 'Log %s'", opt->value);
      ok = 0; goto cleanup;
    }
    if (parse_log_severity_range(smartlist_get(elts,0), &levelMin,
                                 &levelMax)) {
      ok = 0; goto cleanup;
    }
    if (smartlist_len(elts) < 2) { /* only loglevels were provided */
      if (!validate_only) {
        if (daemon) {
          log_warn(LD_CONFIG,
              "Can't log to stdout with RunAsDaemon set; skipping stdout");
        } else {
          add_stream_log(levelMin, levelMax, "<stdout>", stdout);
        }
      }
      goto cleanup;
    }
    if (!strcasecmp(smartlist_get(elts,1), "file")) {
      if (smartlist_len(elts) != 3) {
        log_warn(LD_CONFIG, "Bad syntax on file Log option 'Log %s'",
                 opt->value);
        ok = 0; goto cleanup;
      }
      if (!validate_only) {
        if (add_file_log(levelMin, levelMax, smartlist_get(elts, 2)) < 0) {
          log_warn(LD_CONFIG, "Couldn't open file for 'Log %s'", opt->value);
          ok = 0;
        }
      }
      goto cleanup;
    }
    if (smartlist_len(elts) != 2) {
      log_warn(LD_CONFIG, "Wrong number of arguments on Log option 'Log %s'",
               opt->value);
      ok = 0; goto cleanup;
    }
    if (!strcasecmp(smartlist_get(elts,1), "stdout")) {
      if (daemon) {
        log_warn(LD_CONFIG, "Can't log to stdout with RunAsDaemon set.");
        ok = 0; goto cleanup;
      }
      if (!validate_only) {
        add_stream_log(levelMin, levelMax, "<stdout>", stdout);
      }
    } else if (!strcasecmp(smartlist_get(elts,1), "stderr")) {
      if (daemon) {
        log_warn(LD_CONFIG, "Can't log to stderr with RunAsDaemon set.");
        ok = 0; goto cleanup;
      }
      if (!validate_only) {
        add_stream_log(levelMin, levelMax, "<stderr>", stderr);
      }
    } else if (!strcasecmp(smartlist_get(elts,1), "syslog")) {
#ifdef HAVE_SYSLOG_H
      if (!validate_only)
        add_syslog_log(levelMin, levelMax);
#else
      log_warn(LD_CONFIG, "Syslog is not supported in this compilation.");
#endif
    } else {
      log_warn(LD_CONFIG, "Unrecognized log type %s",
               (const char*)smartlist_get(elts,1));
      if (strchr(smartlist_get(elts,1), '/') ||
          strchr(smartlist_get(elts,1), '\\')) {
        log_warn(LD_CONFIG, "Did you mean to say 'Log file %s' ?",
                 (const char *)smartlist_get(elts,1));
      }
      ok = 0; goto cleanup;
    }
  cleanup:
    SMARTLIST_FOREACH(elts, char*, cp, tor_free(cp));
    smartlist_clear(elts);
  }
  smartlist_free(elts);

  return ok?0:-1;
}

/** Add a single option of the form Log min-max \<type\> [fname] to options. */
static int
add_single_log_option(or_options_t *options, int minSeverity, int maxSeverity,
                      const char *type, const char *fname)
{
  char *buf;
  size_t len;

  len = 256 + fname?strlen(fname):0;
  buf = tor_malloc(len);

  if (tor_snprintf(buf, len, "%s%s%s %s%s%s",
                log_level_to_string(minSeverity),
                maxSeverity == LOG_ERR ? "" : "-",
                maxSeverity == LOG_ERR ? "" : log_level_to_string(maxSeverity),
                type, fname?" ":"", fname?fname:"")<0) {
    log_warn(LD_BUG, "Normalized log option too long.");
    tor_free(buf);
    return -1;
  }

  log(LOG_WARN, LD_CONFIG, "The old LogLevel/LogFile/DebugLogFile/SysLog "
      "options are deprecated, and will go away soon.  Your new torrc line "
      "should be: 'Log %s'", buf);
  config_line_append(&options->Logs, "Log", buf);
  tor_free(buf);
  return 0;
}

/** Convert all old-style logging options to new-style Log options. Return 0
 * on success, -1 on failure. */
static int
normalize_log_options(or_options_t *options)
{
  /* The order of options is:  Level? (File Level?)+
   */
  config_line_t *opt = options->OldLogOptions;

  /* Special case for if first option is LogLevel. */
  if (opt && !strcasecmp(opt->key, "LogLevel")) {
    if (opt->next && (!strcasecmp(opt->next->key, "LogFile") ||
                      !strcasecmp(opt->next->key, "SysLog"))) {
      if (convert_log_option(options, opt, opt->next, options->RunAsDaemon)< 0)
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
      log_warn(LD_CONFIG, "Two LogLevel options in a row without "
               "intervening LogFile or SysLog");
      opt = opt->next;
    } else {
      tor_assert(!strcasecmp(opt->key, "LogFile") ||
                 !strcasecmp(opt->key, "SysLog"));
      if (opt->next && !strcasecmp(opt->next->key, "LogLevel")) {
        /* LogFile/SysLog followed by LogLevel */
        if (convert_log_option(options,opt->next,opt, options->RunAsDaemon) <0)
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
    if (add_single_log_option(options, LOG_DEBUG, LOG_ERR, "file",
                              options->DebugLogFile) < 0)
      return -1;
  }

  tor_free(options->DebugLogFile);
  config_free_lines(options->OldLogOptions);
  options->OldLogOptions = NULL;

  return 0;
}

/** Parse a single RedirectExit line's contents from <b>line</b>.  If
 *  they are valid, and <b>result</b> is not NULL, add an element to
 *  <b>result</b> and return 0. Else if they are valid, return 0.
 *  Else set *msg and return -1. */
static int
parse_redirect_line(smartlist_t *result, config_line_t *line, char **msg)
{
  smartlist_t *elements = NULL;
  exit_redirect_t *r;

  tor_assert(line);

  r = tor_malloc_zero(sizeof(exit_redirect_t));
  elements = smartlist_create();
  smartlist_split_string(elements, line->value, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 0);
  if (smartlist_len(elements) != 2) {
    *msg = tor_strdup("Wrong number of elements in RedirectExit line");
    goto err;
  }
  if (parse_addr_and_port_range(smartlist_get(elements,0),&r->addr,&r->mask,
                                &r->port_min,&r->port_max)) {
    *msg = tor_strdup("Error parsing source address in RedirectExit line");
    goto err;
  }
  if (0==strcasecmp(smartlist_get(elements,1), "pass")) {
    r->is_redirect = 0;
  } else {
    if (parse_addr_port(LOG_WARN, smartlist_get(elements,1),NULL,
                        &r->addr_dest, &r->port_dest)) {
      *msg = tor_strdup("Error parsing dest address in RedirectExit line");
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
    tor_assert(*msg);
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
  int r, idx;
  char *addrport=NULL, *address=NULL, *nickname=NULL, *fingerprint=NULL;
  uint16_t port;
  char digest[DIGEST_LEN];
  int is_v1_authority = 0, is_hidserv_authority = 0,
    is_not_hidserv_authority = 0, is_v2_authority = 1;

  items = smartlist_create();
  smartlist_split_string(items, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (smartlist_len(items) < 1) {
    log_warn(LD_CONFIG, "No arguments on DirServer line.");
    goto err;
  }

  idx = 0;
  if (is_legal_nickname(smartlist_get(items, 0))) {
    nickname = smartlist_get(items, 0);
    smartlist_del_keeporder(items, 0);
  }

  while (smartlist_len(items)) {
    char *flag = smartlist_get(items, 0);
    if (TOR_ISDIGIT(flag[0]))
      break;
    if (!strcasecmp(flag, "v1")) {
      is_v1_authority = is_hidserv_authority = 1;
    } else if (!strcasecmp(flag, "hs")) {
      is_hidserv_authority = 1;
    } else if (!strcasecmp(flag, "no-hs")) {
      is_not_hidserv_authority = 1;
    } else if (!strcasecmp(flag, "no-v2")) {
      is_v2_authority = 0;
    } else {
      log_warn(LD_CONFIG, "Unrecognized flag '%s' on DirServer line",
               flag);
    }
    tor_free(flag);
    smartlist_del_keeporder(items, 0);
  }

  if (is_not_hidserv_authority)
    is_hidserv_authority = 0;

  if (smartlist_len(items) < 2) {
    log_warn(LD_CONFIG, "Too few arguments to DirServer line.");
    goto err;
  }
  addrport = smartlist_get(items, 0);
  if (parse_addr_port(LOG_WARN, addrport, &address, NULL, &port)<0) {
    log_warn(LD_CONFIG, "Error parsing DirServer address '%s'", addrport);
    goto err;
  }
  if (!port) {
    log_warn(LD_CONFIG, "Missing port in DirServer address '%s'",addrport);
    goto err;
  }
  smartlist_del_keeporder(items, 0);

  fingerprint = smartlist_join_strings(items, "", 0, NULL);
  if (strlen(fingerprint) != HEX_DIGEST_LEN) {
    log_warn(LD_CONFIG, "Key digest for DirServer is wrong length.");
    goto err;
  }
  if (base16_decode(digest, DIGEST_LEN, fingerprint, HEX_DIGEST_LEN)<0) {
    log_warn(LD_CONFIG, "Unable to decode DirServer key digest.");
    goto err;
  }

  if (!validate_only) {
    log_debug(LD_DIR, "Trusted dirserver at %s:%d (%s)", address, (int)port,
              (char*)smartlist_get(items,1));
    add_trusted_dir_server(nickname, address, port, digest, is_v1_authority,
                           is_v2_authority, is_hidserv_authority);

  }

  r = 0;
  goto done;

  err:
  r = -1;

  done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  tor_free(addrport);
  tor_free(address);
  tor_free(nickname);
  tor_free(fingerprint);
  return r;
}

/** Adjust the value of options->DataDirectory, or fill it in if it's
 * absent. Return 0 on success, -1 on failure. */
static int
normalize_data_directory(or_options_t *options)
{
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
     log_err(LD_CONFIG,"Failed to expand filename \"%s\".", d);
     return -1;
   }
   if (!options->DataDirectory && !strcmp(fn,"/.tor")) {
     /* If our homedir is /, we probably don't want to use it. */
     /* XXXX Default to /var/lib/tor? */
     log_warn(LD_CONFIG,
              "Default DataDirectory is \"~/.tor\".  This expands to "
              "\"%s\", which is probably not what you want.  Using \"%s/tor\" "
              "instead", fn, LOCALSTATEDIR);
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
validate_data_directory(or_options_t *options)
{
  if (normalize_data_directory(options) < 0)
    return -1;
  tor_assert(options->DataDirectory);
  if (strlen(options->DataDirectory) > (512-128)) {
    log_err(LD_CONFIG, "DataDirectory is too long.");
    return -1;
  }
  return 0;
}

/** This string must remain the same forevermore. It is how we
 * recognize that the torrc file doesn't need to be backed up. */
#define GENERATED_FILE_PREFIX "# This file was generated by Tor; " \
  "if you edit it, comments will not be preserved"
/** This string can change; it tries to give the reader an idea
 * that editing this file by hand is not a good plan. */
#define GENERATED_FILE_COMMENT "# The old torrc file was renamed " \
  "to torrc.orig.1 or similar, and Tor will ignore it"

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
      case FN_ERROR:
      case FN_DIR:
      default:
        log_warn(LD_CONFIG,
                 "Config file \"%s\" is not a file? Failing.", fname);
        return -1;
    }
  }

  if (!(new_conf = options_dump(options, 1))) {
    log_warn(LD_BUG, "Couldn't get configuration string");
    goto err;
  }

  len = strlen(new_conf)+256;
  new_val = tor_malloc(len);
  tor_snprintf(new_val, len, "%s\n%s\n\n%s",
               GENERATED_FILE_PREFIX, GENERATED_FILE_COMMENT, new_conf);

  if (rename_old) {
    int i = 1;
    size_t fn_tmp_len = strlen(fname)+32;
    char *fn_tmp;
    tor_assert(fn_tmp_len > strlen(fname)); /*check for overflow*/
    fn_tmp = tor_malloc(fn_tmp_len);
    while (1) {
      if (tor_snprintf(fn_tmp, fn_tmp_len, "%s.orig.%d", fname, i)<0) {
        log_warn(LD_BUG, "tor_snprintf failed inexplicably");
        tor_free(fn_tmp);
        goto err;
      }
      if (file_status(fn_tmp) == FN_NOENT)
        break;
      ++i;
    }
    log_notice(LD_CONFIG, "Renaming old configuration file to \"%s\"", fn_tmp);
    if (rename(fname, fn_tmp) < 0) {
      log_warn(LD_FS, "Couldn't rename configuration file \"%s\" to \"%s\": %s",
             fname, fn_tmp, strerror(errno));
      tor_free(fn_tmp);
      goto err;
    }
    tor_free(fn_tmp);
  }

  if (write_str_to_file(fname, new_val, 0) < 0)
    goto err;

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
options_save_current(void)
{
  if (torrc_fname) {
    /* XXX This fails if we can't write to our configuration file.
     *   Arguably, we should try falling back to datadirectory or something.
     *   But just as arguably, we shouldn't. */
    return write_configuration_file(torrc_fname, get_options());
  }
  return write_configuration_file(get_default_conf_file(), get_options());
}

/** Mapping from a unit name to a multiplier for converting that unit into a
 * base unit. */
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
  log_warn(LD_CONFIG, "Unknown unit '%s'.", cp);
  *ok = 0;
  return 0;
}

/** Parse a string in the format "number unit", where unit is a unit of
 * information (byte, KB, M, etc).  On success, set *<b>ok</b> to true
 * and return the number of bytes specified.  Otherwise, set
 * *<b>ok</b> to false and return 0. */
static uint64_t
config_parse_memunit(const char *s, int *ok)
{
  return config_parse_units(s, memory_units, ok);
}

/** Parse a string in the format "number unit", where unit is a unit of time.
 * On success, set *<b>ok</b> to true and return the number of seconds in
 * the provided interval.  Otherwise, set *<b>ok</b> to 0 and return -1.
 */
static int
config_parse_interval(const char *s, int *ok)
{
  uint64_t r;
  r = config_parse_units(s, time_units, ok);
  if (!ok)
    return -1;
  if (r > INT_MAX) {
    log_warn(LD_CONFIG, "Interval '%s' is too long", s);
    *ok = 0;
    return -1;
  }
  return (int)r;
}

/**
 * Initialize the libevent library.
 */
static void
init_libevent(void)
{
  configure_libevent_logging();
  /* If the kernel complains that some method (say, epoll) doesn't
   * exist, we don't care about it, since libevent will cope.
   */
  suppress_libevent_log_msg("Function not implemented");
#ifdef __APPLE__
  if (decode_libevent_version() < LE_11B) {
    setenv("EVENT_NOKQUEUE","1",1);
  } else if (!getenv("EVENT_NOKQUEUE")) {
    const char *ver = NULL;
#ifdef HAVE_EVENT_GET_VERSION
    ver = event_get_version();
#endif
    /* If we're 1.1b or later, we'd better have get_version() */
    tor_assert(ver);
    log(LOG_NOTICE, LD_GENERAL, "Enabling experimental OS X kqueue support "
        "with libevent %s.  If this turns out to not work, "
        "set the environment variable EVENT_NOKQUEUE, and tell the Tor "
        "developers.", ver);
  }
#endif
  event_init();
  suppress_libevent_log_msg(NULL);
#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
  /* Making this a NOTICE for now so we can link bugs to a libevent versions
   * or methods better. */
  log(LOG_NOTICE, LD_GENERAL,
      "Initialized libevent version %s using method %s. Good.",
      event_get_version(), event_get_method());
  check_libevent_version(event_get_method(), get_options()->ORPort != 0);
#else
  log(LOG_NOTICE, LD_GENERAL,
      "Initialized old libevent (version 1.0b or earlier).");
  log(LOG_WARN, LD_GENERAL,
      "You have a *VERY* old version of libevent.  It is likely to be buggy; "
      "please build Tor with a more recent version.");
#endif
}

#if defined(HAVE_EVENT_GET_VERSION) && defined(HAVE_EVENT_GET_METHOD)
static const struct {
  const char *name; le_version_t version;
} le_version_table[] = {
  /* earlier versions don't have get_version. */
  { "1.0c", LE_10C },
  { "1.0d", LE_10D },
  { "1.0e", LE_10E },
  { "1.1",  LE_11 },
  { "1.1a", LE_11A },
  { "1.1b", LE_11B },
  { NULL, 0 }
};

static le_version_t
decode_libevent_version(void)
{
  const char *v = event_get_version();
  int i;
  for (i=0; le_version_table[i].name; ++i) {
    if (!strcmp(le_version_table[i].name, v)) {
      return le_version_table[i].version;
    }
  }
  return LE_OTHER;
}

/**
 * Compare the given libevent method and version to a list of versions
 * which are known not to work.  Warn the user as appropriate.
 *
 */
static void
check_libevent_version(const char *m, int server)
{
  int buggy = 0, iffy = 0, slow = 0;
  le_version_t version;
  const char *v = event_get_version();

  version = decode_libevent_version();

  /* XXX Would it be worthwhile disabling the methods that we know
   * are buggy, rather than just warning about them and then proceeding
   * to use them? If so, we should probably not wrap this whole thing
   * in HAVE_EVENT_GET_VERSION and HAVE_EVENT_GET_METHOD. -RD */
  if (!strcmp(m, "kqueue")) {
    if (version < LE_11B)
      buggy = 1;
  } else if (!strcmp(m, "epoll")) {
    if (version < LE_11)
      iffy = 1;
  } else if (!strcmp(m, "poll")) {
    if (version < LE_10E)
      buggy = 1;
    else if (version < LE_11)
      slow = 1;
  } else if (!strcmp(m, "poll")) {
    if (version < LE_11)
      slow = 1;
  } else if (!strcmp(m, "win32")) {
    if (version < LE_11B)
      buggy = 1;
  }

  if (buggy) {
    log(LOG_WARN, LD_GENERAL,
        "There are known bugs in using %s with libevent %s. "
        "Please use the latest version of libevent.", m, v);
  } else if (iffy) {
    log(LOG_WARN, LD_GENERAL,
        "There are minor bugs in using %s with libevent %s. "
        "You may want to use the latest version of libevent.", m, v);
  } else if (slow && server) {
    log(LOG_WARN, LD_GENERAL,
        "libevent %s can be very slow with %s. "
        "When running a server, please use the latest version of libevent.",
        v,m);
  }

}
#else
static le_version_t
decode_libevent_version(void)
{
  return LE_OLD;
}
#endif

/** Return the persistent state struct for this Tor. */
or_state_t *
get_or_state(void)
{
  return global_state;
}

/** Return the filename used to write and read the persistent state. */
static char *
get_or_state_fname(void)
{
  char *fname = NULL;
  or_options_t *options = get_options();
  size_t len = strlen(options->DataDirectory) + 16;
  fname = tor_malloc(len);
  tor_snprintf(fname, len, "%s/state", options->DataDirectory);
  return fname;
}

/** Return 0 if every setting in <b>state</b> is reasonable, and a
 * permissible transition from <b>old_state</b>.  Else warn and return -1.
 * Should have no side effects, except for normalizing the contents of
 * <b>state</b>.
 */
/* XXX from_setconf is here because of bug 238 */
static int
or_state_validate(or_state_t *old_state, or_state_t *state,
                  int from_setconf, char **msg)
{
  /* We don't use these; only options do. Still, we need to match that
   * signature. */
  (void) from_setconf;
  (void) old_state;
  if (entry_guards_parse_state(state, 0, msg)<0) {
    return -1;
  }
  if (state->TorVersion) {
    tor_version_t v;
    if (tor_version_parse(state->TorVersion, &v)) {
      log_warn(LD_GENERAL, "Can't parse Tor version '%s' from your state "
               "file. Proceeding anyway.", state->TorVersion);
    } else { /* take action based on v */
      if (tor_version_as_new_as(state->TorVersion, "0.1.1.10-alpha") &&
          !tor_version_as_new_as(state->TorVersion, "0.1.1.16-rc-cvs")) {
        log_notice(LD_CONFIG, "Detected state file from buggy version '%s'. "
                   "Enabling workaround to choose working entry guards.",
                   state->TorVersion);
        config_free_lines(state->EntryGuards);
        state->EntryGuards = NULL;
      }
    }
  }
  return 0;
}

/** Replace the current persistent state with <b>new_state</b> */
static void
or_state_set(or_state_t *new_state)
{
  char *err = NULL;
  tor_assert(new_state);
  if (global_state)
    config_free(&state_format, global_state);
  global_state = new_state;
  if (entry_guards_parse_state(global_state, 1, &err)<0) {
    log_warn(LD_GENERAL,"%s",err);
    tor_free(err);
  }
  if (rep_hist_load_state(global_state, &err)<0) {
    log_warn(LD_GENERAL,"Unparseable bandwidth history state: %s",err);
    tor_free(err);
  }
}

/** Reload the persistent state from disk, generating a new state as needed.
 * Return 0 on success, less than 0 on failure.
 */
int
or_state_load(void)
{
  or_state_t *new_state = NULL;
  char *contents = NULL, *fname;
  char *errmsg = NULL;
  int r = -1, badstate = 0;

  fname = get_or_state_fname();
  switch (file_status(fname)) {
    case FN_FILE:
      if (!(contents = read_file_to_str(fname, 0))) {
        log_warn(LD_FS, "Unable to read state file \"%s\"", fname);
        goto done;
      }
      break;
    case FN_NOENT:
      break;
    case FN_ERROR:
    case FN_DIR:
    default:
      log_warn(LD_GENERAL,"State file \"%s\" is not a file? Failing.", fname);
      goto done;
  }
  new_state = tor_malloc_zero(sizeof(or_state_t));
  new_state->_magic = OR_STATE_MAGIC;
  config_init(&state_format, new_state);
  if (contents) {
    config_line_t *lines=NULL;
    int assign_retval;
    if (config_get_lines(contents, &lines)<0)
      goto done;
    assign_retval = config_assign(&state_format, new_state,
                                  lines, 0, 0, &errmsg);
    config_free_lines(lines);
    if (assign_retval<0)
      badstate = 1;
    if (errmsg) {
      log_warn(LD_GENERAL, "%s", errmsg);
      tor_free(errmsg);
    }
  }

  if (!badstate && or_state_validate(NULL, new_state, 1, &errmsg) < 0)
    badstate = 1;

  if (errmsg) {
    log_warn(LD_GENERAL, "%s", errmsg);
    tor_free(errmsg);
  }

  if (badstate && !contents) {
    log_warn(LD_BUG, "Uh oh.  We couldn't even validate our own default state."
             " This is a bug in Tor.");
    goto done;
  } else if (badstate && contents) {
    int i;
    file_status_t status;
    size_t len = strlen(fname)+16;
    char *fname2 = tor_malloc(len);
    for (i = 0; i < 100; ++i) {
      tor_snprintf(fname2, len, "%s.%d", fname, i);
      status = file_status(fname2);
      if (status == FN_NOENT)
        break;
    }
    if (i == 100) {
      log_warn(LD_BUG, "Unable to parse state in \"%s\"; too many saved bad "
               "state files to move aside. Discarding the old state file.",
               fname);
      unlink(fname);
    } else {
      log_warn(LD_BUG, "Unable to parse state in \"%s\". Moving it aside "
               "to \"%s\".  This could be a bug in Tor; please tell "
               "the developers.", fname, fname2);
      rename(fname, fname2);
    }
    tor_free(fname2);
    tor_free(contents);
    config_free(&state_format, new_state);

    new_state = tor_malloc_zero(sizeof(or_state_t));
    new_state->_magic = OR_STATE_MAGIC;
    config_init(&state_format, new_state);
  } else if (contents) {
    log_info(LD_GENERAL, "Loaded state from \"%s\"", fname);
  } else {
    log_info(LD_GENERAL, "Initialized state");
  }
  or_state_set(new_state);
  new_state = NULL;
  if (!contents) {
    global_state->dirty = 1;
    or_state_save();
  }
  r = 0;

 done:
  tor_free(fname);
  tor_free(contents);
  if (new_state)
    config_free(&state_format, new_state);

  return r;
}

/** Write the persistent state to disk. Return 0 for success, <0 on failure. */
int
or_state_save(void)
{
  char *state, *contents;
  char tbuf[ISO_TIME_LEN+1];
  size_t len;
  char *fname;

  tor_assert(global_state);

  entry_guards_update_state(global_state);
  rep_hist_update_state(global_state);

  if (!global_state->dirty)
    return 0;

  global_state->LastWritten = time(NULL);
  tor_free(global_state->TorVersion);
  global_state->TorVersion = tor_strdup("Tor " VERSION);
  state = config_dump(&state_format, global_state, 0);
  len = strlen(state)+128;
  contents = tor_malloc(len);
  format_local_iso_time(tbuf, time(NULL));
  tor_snprintf(contents, len,
               "# Tor state file last generated on %s\n"
               "# You *do not* need to edit this file.\n\n%s",
               tbuf, state);
  tor_free(state);
  fname = get_or_state_fname();
  if (write_str_to_file(fname, contents, 0)<0) {
    log_warn(LD_FS, "Unable to write state to file \"%s\"", fname);
    tor_free(fname);
    tor_free(contents);
    return -1;
  }
  log_info(LD_GENERAL, "Saved state to \"%s\"", fname);
  tor_free(fname);
  tor_free(contents);

  global_state->dirty = 0;
  return 0;
}

/** Helper to implement GETINFO functions about configuration variables (not
 * their values).  Given a "config/names" question, set *<b>answer</b> to a
 * new string describing the supported configuration variables and their
 * types. */
int
config_getinfo_helper(const char *question, char **answer)
{
  if (!strcmp(question, "config/names")) {
    smartlist_t *sl = smartlist_create();
    int i;
    for (i = 0; _option_vars[i].name; ++i) {
      config_var_t *var = &_option_vars[i];
      const char *type, *desc;
      char *line;
      size_t len;
      desc = config_find_description(&options_format, var->name);
      switch (var->type) {
        case CONFIG_TYPE_STRING: type = "String"; break;
        case CONFIG_TYPE_UINT: type = "Integer"; break;
        case CONFIG_TYPE_INTERVAL: type = "TimeInterval"; break;
        case CONFIG_TYPE_MEMUNIT: type = "DataSize"; break;
        case CONFIG_TYPE_DOUBLE: type = "Float"; break;
        case CONFIG_TYPE_BOOL: type = "Boolean"; break;
        case CONFIG_TYPE_ISOTIME: type = "Time"; break;
        case CONFIG_TYPE_CSV: type = "CommaList"; break;
        case CONFIG_TYPE_LINELIST: type = "LineList"; break;
        case CONFIG_TYPE_LINELIST_S: type = "Dependant"; break;
        case CONFIG_TYPE_LINELIST_V: type = "Virtual"; break;
        default:
        case CONFIG_TYPE_OBSOLETE:
          type = NULL; break;
      }
      if (!type)
        continue;
      len = strlen(var->name)+strlen(type)+16;
      if (desc)
        len += strlen(desc);
      line = tor_malloc(len);
      if (desc)
        tor_snprintf(line, len, "%s %s %s\n",var->name,type,desc);
      else
        tor_snprintf(line, len, "%s %s\n",var->name,type);
      smartlist_add(sl, line);
    }
    *answer = smartlist_join_strings(sl, "", 0, NULL);
    SMARTLIST_FOREACH(sl, char *, c, tor_free(c));
    smartlist_free(sl);
  }
  return 0;
}

#include "../common/ht.h"
#include "../common/test.h"

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
extern const char policies_c_id[];
extern const char relay_c_id[];
extern const char rendclient_c_id[];
extern const char rendcommon_c_id[];
extern const char rendmid_c_id[];
extern const char rendservice_c_id[];
extern const char rephist_c_id[];
extern const char router_c_id[];
extern const char routerlist_c_id[];
extern const char routerparse_c_id[];

/** Dump the version of every file to the log. */
static void
print_svn_version(void)
{
  puts(AES_H_ID);
  puts(COMPAT_H_ID);
  puts(CONTAINER_H_ID);
  puts(CRYPTO_H_ID);
  puts(HT_H_ID);
  puts(TEST_H_ID);
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
  puts(policies_c_id);
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

