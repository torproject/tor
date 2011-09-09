/* Copyright (c) 2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file transports.c
 * \brief Pluggable Transports related code.
 **/

#define PT_PRIVATE
#include "or.h"
#include "config.h"
#include "circuitbuild.h"
#include "transports.h"
#include "util.h"

/* ASN TIDY THESE UP*/
static void set_managed_proxy_environment(char ***envp, const managed_proxy_t *mp);
static INLINE int proxy_configuration_finished(const managed_proxy_t *mp);

static void managed_proxy_destroy_impl(managed_proxy_t *mp,
                                       int also_free_transports);
#define managed_proxy_destroy(mp) managed_proxy_destroy_impl(mp, 0)
#define managed_proxy_destroy_with_transports(mp) managed_proxy_destroy_impl(mp, 1)

static void handle_finished_proxy(managed_proxy_t *mp);
static void configure_proxy(managed_proxy_t *mp);

static void parse_method_error(const char *line, int is_server_method);
#define parse_server_method_error(l) parse_method_error(l, 1)
#define parse_client_method_error(l) parse_method_error(l, 0)

static INLINE void free_execve_args(char **arg);

/** Managed proxy protocol strings */
#define PROTO_ENV_ERROR "ENV-ERROR"
#define PROTO_NEG_SUCCESS "VERSION"
#define PROTO_NEG_FAIL "VERSION-ERROR no-version"
#define PROTO_CMETHOD "CMETHOD"
#define PROTO_SMETHOD "SMETHOD"
#define PROTO_CMETHOD_ERROR "CMETHOD-ERROR"
#define PROTO_SMETHOD_ERROR "SMETHOD-ERROR"
#define PROTO_CMETHODS_DONE "CMETHODS DONE"
#define PROTO_SMETHODS_DONE "SMETHODS DONE"

/* The smallest valid managed proxy protocol line that can
   appear. It's the size of "VERSION 1" */
#define SMALLEST_MANAGED_LINE_SIZE 9

/** Number of environment variables for managed proxy clients/servers. */
#define ENVIRON_SIZE_CLIENT 5
#define ENVIRON_SIZE_SERVER 8

/** The first and only supported - at the moment - configuration
    protocol version. */
#define PROTO_VERSION_ONE 1

/** List of unconfigured managed proxies. */
static smartlist_t *unconfigured_proxy_list = NULL;

/*  The main idea here is:

    A managed proxy is represented by a managed_proxy_t struct and can
    spawn multiple transports.

    unconfigured_proxy_list is a list of all the unconfigured managed
    proxies; everytime we find a managed proxy in torrc we add it in
    that list.
    In every run_scheduled_event() tick, we attempt to launch and then
    configure each managed proxy, using the configuration protocol
    defined in the 180_pluggable_transport.txt proposal. A managed
    proxy might need several ticks to get fully configured.

    When a managed proxy is fully configured, we register all its
    transports to the circuitbuild.c subsystem - like we do with
    external proxies - and then free the managed proxy struct
    since it's no longer needed. */

/** Return true if there are still unconfigured managed proxies. */
int
pt_proxies_configuration_pending(void)
{
  if (!unconfigured_proxy_list) return 0;
  return !!smartlist_len(unconfigured_proxy_list);
}

/** Return true if <b>mp</b> has the same argv as <b>proxy_argv</b> */
static int
managed_proxy_has_argv(managed_proxy_t *mp, char **proxy_argv)
{
  char **tmp1=proxy_argv;
  char **tmp2=mp->argv;

  tor_assert(tmp1);
  tor_assert(tmp2);

  while (*tmp1 && *tmp2) {
    if (strcmp(*tmp1++, *tmp2++))
      return 0;
  }

  if (!*tmp1 && !*tmp2)
    return 1;

  return 0;
}

/** Return a managed proxy with the same argv as <b>proxy_argv</b>.
 *  If no such managed proxy exists, return NULL. */
static managed_proxy_t *
get_managed_proxy_by_argv(char **proxy_argv)
{
  if (!unconfigured_proxy_list)
    return NULL;

  SMARTLIST_FOREACH_BEGIN(unconfigured_proxy_list,  managed_proxy_t *, mp) {
    if (managed_proxy_has_argv(mp, proxy_argv))
      return mp;
  } SMARTLIST_FOREACH_END(mp);

  return NULL;
}

/** Add <b>transport</b> to managed proxy <b>mp</b>. */
static void
add_transport_to_proxy(const char *transport, managed_proxy_t *mp)
{
  tor_assert(mp->transports_to_launch);
  if (!smartlist_string_isin(mp->transports_to_launch, transport))
    smartlist_add(mp->transports_to_launch, tor_strdup(transport));
}

/** Launch managed proxy <b>mp</b>. */
static int
launch_managed_proxy(managed_proxy_t *mp)
{
  char **envp=NULL;
  int retval;
  FILE *stdout_read = NULL;
  int stdout_pipe=-1, stderr_pipe=-1;

  /* prepare the environment variables for the managed proxy */
  set_managed_proxy_environment(&envp, mp);

  retval = tor_spawn_background(mp->argv[0], &stdout_pipe,
                                &stderr_pipe, (const char **)mp->argv,
                                (const char **)envp);
  if (retval < 0) {
    log_warn(LD_GENERAL, "Spawn failed");
    return -1;
  }

  /* free the memory allocated by set_managed_proxy_environment(). */
  free_execve_args(envp);

  /* Set stdout/stderr pipes to be non-blocking */
  fcntl(stdout_pipe, F_SETFL, O_NONBLOCK);
  /* Open the buffered IO streams */
  stdout_read = fdopen(stdout_pipe, "r");

  log_warn(LD_CONFIG, "The spawn is alive (%d)!", retval);

  mp->conf_state = PT_PROTO_LAUNCHED;
  mp->stdout = stdout_read;

  return 0;
}

/** Check if any of the managed proxies we are currently trying to
 *  configure have anything new to say. This is called from
 *  run_scheduled_events(). */
void
pt_configure_remaining_proxies(void)
{
  log_warn(LD_CONFIG, "We start configuring remaining managed proxies!");
  SMARTLIST_FOREACH_BEGIN(unconfigured_proxy_list,  managed_proxy_t *, mp) {
    /* configured proxies shouldn't be in unconfigured_proxy_list. */
    tor_assert(!proxy_configuration_finished(mp));

    configure_proxy(mp);

  } SMARTLIST_FOREACH_END(mp);
}

/** Attempt to continue configuring managed proxy <b>mp</b>. */
static void
configure_proxy(managed_proxy_t *mp)
{
  enum stream_status r;
  char stdout_buf[200];

  /* if we haven't launched the proxy yet, do it now */
  if (mp->conf_state == PT_PROTO_INFANT) {
    launch_managed_proxy(mp);
    return;
  }

  tor_assert(mp->conf_state != PT_PROTO_INFANT);

  while (1) {
    r = get_string_from_pipe(mp->stdout, stdout_buf,
                             sizeof(stdout_buf) - 1);

    if (r  == IO_STREAM_OKAY) { /* got a line; handle it! */
      handle_proxy_line((const char *)stdout_buf, mp);
    } else if (r == IO_STREAM_EAGAIN) { /* check back later */
      return;
    } else if (r == IO_STREAM_CLOSED || r == IO_STREAM_TERM) { /* snap! */
      log_warn(LD_GENERAL, "Managed proxy stream closed. "
               "Most probably application stopped running");
      mp->conf_state = PT_PROTO_BROKEN;
    } else { /* unknown stream status */
      log_warn(LD_GENERAL, "Unknown stream status while configuring proxy.");
    }

    /* if the proxy finished configuring, exit the loop. */
    if (proxy_configuration_finished(mp)) {
      handle_finished_proxy(mp);
      return;
    }
  }
}

/** Register server managed proxy <b>mp</b> transports to state */
static void
register_server_proxy(const managed_proxy_t *mp)
{
  if (mp->is_server) {
    SMARTLIST_FOREACH_BEGIN(mp->transports, transport_t *, t) {
      save_transport_to_state(t->name,&t->addr,t->port); /* pass tor_addr_t? */
    } SMARTLIST_FOREACH_END(t);
  }
}

/** Register all the transports supported by client managed proxy
 *  <b>mp</b> to the bridge subsystem. */
static void
register_client_proxy(const managed_proxy_t *mp)
{
  SMARTLIST_FOREACH_BEGIN(mp->transports, transport_t *, t) {
    if (transport_add(t)<0) {
      log_warn(LD_GENERAL, "Could not add transport %s. Skipping.", t->name);
      transport_free(t);
    } else {
      log_warn(LD_GENERAL, "Succesfully registered transport %s", t->name);
    }
  } SMARTLIST_FOREACH_END(t);
}

/** Register the transports of managed proxy <b>mp</b>. */
static INLINE void
register_proxy(const managed_proxy_t *mp)
{
  if (mp->is_server)
    register_server_proxy(mp);
  else
    register_client_proxy(mp);
}

/** Free memory allocated by managed proxy <b>mp</b>.
 * If <b>also_free_transports</b> is set, also free the transports
 * associated with this managed proxy. */
static void
managed_proxy_destroy_impl(managed_proxy_t *mp, int also_free_transports)
{
  /* transport_free() all its transports */
  if (also_free_transports)
    SMARTLIST_FOREACH(mp->transports, transport_t *, t, transport_free(t));

  /* free the transports smartlist */
  smartlist_clear(mp->transports);
  smartlist_free(mp->transports);

  SMARTLIST_FOREACH(mp->transports_to_launch, char *, t, tor_free(t));

  /* free the transports smartlist */
  smartlist_clear(mp->transports_to_launch);
  smartlist_free(mp->transports_to_launch);

  /* remove it from the list of managed proxies */
  smartlist_remove(unconfigured_proxy_list, mp);

  /* close its stdout stream */
  fclose(mp->stdout);

  /* free the argv */
  free_execve_args(mp->argv);

  tor_free(mp);
}


/** Handle a configured or broken managed proxy <b>mp</b>. */
static void
handle_finished_proxy(managed_proxy_t *mp)
{
  switch (mp->conf_state) {
  case PT_PROTO_BROKEN: /* if broken: */
    managed_proxy_destroy_with_transports(mp); /* destroy it and all its transports */
    break;
  case PT_PROTO_CONFIGURED: /* if configured correctly: */
    register_proxy(mp); /* register transports */
    mp->conf_state = PT_PROTO_COMPLETED; /* mark it as completed, */
    managed_proxy_destroy(mp); /* destroy the managed proxy struct,
                                     keeping the transports intact */
    break;
  default:
    log_warn(LD_CONFIG, "Unfinished managed proxy in "
             "handle_finished_proxy().");
    tor_assert(0);
  }

  tor_assert(smartlist_len(unconfigured_proxy_list) >= 0);
}

/** Return true if the configuration of the managed proxy <b>mp</b> is
    finished. */
static INLINE int
proxy_configuration_finished(const managed_proxy_t *mp)
{
  return (mp->conf_state == PT_PROTO_CONFIGURED ||
          mp->conf_state == PT_PROTO_BROKEN);
}


/** This function is called when a proxy sends an {S,C}METHODS DONE message,
 */
static void
handle_methods_done(const managed_proxy_t *mp)
{
  tor_assert(mp->transports);

  if (smartlist_len(mp->transports) == 0)
    log_warn(LD_GENERAL, "Proxy was spawned successfully, "
             "but it didn't laucn any pluggable transport listeners!");

  log_warn(LD_CONFIG, "%s managed proxy configuration completed!",
           mp->is_server ? "Server" : "Client");
}

/** Handle a configuration protocol <b>line</b> received from a
 *  managed proxy <b>mp</b>. */
void
handle_proxy_line(const char *line, managed_proxy_t *mp)
{
  printf("Judging line: %s\n", line);

  if (strlen(line) < SMALLEST_MANAGED_LINE_SIZE) {
    log_warn(LD_GENERAL, "Managed proxy configuration line is too small. "
             "Discarding");
    goto err;
  }

  if (!strcmpstart(line, PROTO_ENV_ERROR)) {
    if (mp->conf_state != PT_PROTO_LAUNCHED)
      goto err;

    parse_env_error(line);
    goto err;
  } else if (!strcmpstart(line, PROTO_NEG_FAIL)) {
    if (mp->conf_state != PT_PROTO_LAUNCHED)
      goto err;

    log_warn(LD_CONFIG, "Managed proxy could not pick a "
             "configuration protocol version.");
    goto err;
  } else if (!strcmpstart(line, PROTO_NEG_SUCCESS)) {
    if (mp->conf_state != PT_PROTO_LAUNCHED)
      goto err;

    if (parse_version(line,mp) < 0)
      goto err;

    tor_assert(mp->conf_protocol != 0);
    mp->conf_state = PT_PROTO_ACCEPTING_METHODS;
    return;
  } else if (!strcmpstart(line, PROTO_CMETHODS_DONE)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    handle_methods_done(mp);

    mp->conf_state = PT_PROTO_CONFIGURED;
    return;
  } else if (!strcmpstart(line, PROTO_SMETHODS_DONE)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    handle_methods_done(mp);

    mp->conf_state = PT_PROTO_CONFIGURED;
    return;
  } else if (!strcmpstart(line, PROTO_CMETHOD_ERROR)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    parse_client_method_error(line);
    goto err;
  } else if (!strcmpstart(line, PROTO_SMETHOD_ERROR)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    parse_server_method_error(line);
    goto err;
  } else if (!strcmpstart(line, PROTO_CMETHOD)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    if (parse_cmethod_line(line, mp) < 0)
      goto err;

    return;
  } else if (!strcmpstart(line, PROTO_SMETHOD)) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    if (parse_smethod_line(line, mp) < 0)
      goto err;

    return;
  } else if (!strcmpstart(line, SPAWN_ERROR_MESSAGE)) {
    log_warn(LD_GENERAL, "Could not launch managed proxy executable!");
    goto err;
  }

  log_warn(LD_CONFIG, "Unknown line received by managed proxy. (%s)", line);

 err:
  mp->conf_state = PT_PROTO_BROKEN;
  return;
}

/** Parses an ENV-ERROR <b>line</b> and warns the user accordingly. */
void
parse_env_error(const char *line)
{
  /* (Length of the protocol string) plus (a space) and (the first char of
     the error message) */
  if (strlen(line) < (strlen(PROTO_ENV_ERROR) + 2))
    log_warn(LD_CONFIG, "Managed proxy sent us an %s without an error "
             "message.", PROTO_ENV_ERROR);

  log_warn(LD_CONFIG, "Managed proxy couldn't understand the "
           "pluggable transport environment variables. (%s)",
           line+strlen(PROTO_ENV_ERROR)+1);
}

/** Handles a VERSION <b>line</b>. Updates the configuration protocol
 *  version in <b>mp</b>. */
int
parse_version(const char *line, managed_proxy_t *mp)
{
  if (strlen(line) < (strlen(PROTO_NEG_SUCCESS) + 2)) {
    log_warn(LD_CONFIG, "Managed proxy sent us malformed %s line.",
             PROTO_NEG_SUCCESS);
    return -1;
  }

  if (strcmp("1", line+strlen(PROTO_NEG_SUCCESS)+1)) {
    log_warn(LD_CONFIG, "We don't support version '%s'. "
             "We only support version '1'", line+strlen(PROTO_NEG_SUCCESS)+1);
    return -1;
  }

  mp->conf_protocol = PROTO_VERSION_ONE; /* temp. till more versions appear */
  return 0;
}

/** Parses {C,S}METHOD-ERROR <b>line</b> and warns the user
 *  accordingly.  If <b>is_server</b> it is an SMETHOD-ERROR,
 *  otherwise it is a CMETHOD-ERROR. */
static void
parse_method_error(const char *line, int is_server)
{
  const char* error = is_server ?
    PROTO_SMETHOD_ERROR : PROTO_CMETHOD_ERROR;

  /* (Length of the protocol string) plus (a space) and (the first char of
     the error message) */
  if (strlen(line) < (strlen(error) + 2))
    log_warn(LD_CONFIG, "Managed proxy sent us an %s without an error "
             "message.", error);

  log_warn(LD_CONFIG, "%s managed proxy encountered a method error. (%s)",
           is_server ? "Server" : "Client",
           line+strlen(error)+1);
}

/** Parses an SMETHOD <b>line</b> and if well-formed it registers the
 *  new transport in <b>mp</b>. */
int
parse_smethod_line(const char *line, managed_proxy_t *mp)
{
  int r;
  smartlist_t *items = NULL;

  char *method_name=NULL;

  char *addrport=NULL;
  tor_addr_t addr;
  uint16_t port = 0;

  transport_t *transport=NULL;

  items = smartlist_create();
  smartlist_split_string(items, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (smartlist_len(items) < 3) {
    log_warn(LD_CONFIG, "Server managed proxy sent us a SMETHOD line "
             "with too few arguments.");
    goto err;
  }

  tor_assert(!strcmp(smartlist_get(items,0),PROTO_SMETHOD));

  method_name = smartlist_get(items,1);

  addrport = smartlist_get(items, 2);
  if (tor_addr_port_parse(addrport, &addr, &port)<0) {
    log_warn(LD_CONFIG, "Error parsing transport "
             "address '%s'", addrport);
    goto err;
  }

  if (!port) {
    log_warn(LD_CONFIG,
             "Transport address '%s' has no port.", addrport);
    goto err;
  }

  transport = transport_create(&addr, port, method_name, PROXY_NONE);
  if (!transport)
    goto err;

  smartlist_add(mp->transports, transport);

  /* For now, notify the user so that he knows where the server
     transport is listening. */
  log_warn(LD_CONFIG, "Server transport %s at %s:%d.",
           method_name, fmt_addr(&addr), (int)port);

  r=0;
  goto done;

 err:
  r = -1;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  return r;
}

/** Parses a CMETHOD <b>line</b>, and if well-formed it registers
 *  the new transport in <b>mp</b>. */
int
parse_cmethod_line(const char *line, managed_proxy_t *mp)
{
  int r;
  smartlist_t *items = NULL;

  char *method_name=NULL;

  char *socks_ver_str=NULL;
  int socks_ver=PROXY_NONE;

  char *addrport=NULL;
  tor_addr_t addr;
  uint16_t port = 0;

  transport_t *transport=NULL;

  items = smartlist_create();
  smartlist_split_string(items, line, NULL,
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (smartlist_len(items) < 4) {
    log_warn(LD_CONFIG, "Client managed proxy sent us a CMETHOD line "
             "with too few arguments.");
    goto err;
  }

  tor_assert(!strcmp(smartlist_get(items,0),PROTO_CMETHOD));

  method_name = smartlist_get(items,1);

  socks_ver_str = smartlist_get(items,2);

  if (!strcmp(socks_ver_str,"socks4")) {
    socks_ver = PROXY_SOCKS4;
  } else if (!strcmp(socks_ver_str,"socks5")) {
    socks_ver = PROXY_SOCKS5;
  } else {
    log_warn(LD_CONFIG, "Client managed proxy sent us a proxy protocol "
             "we don't recognize. (%s)", socks_ver_str);
    goto err;
  }

  addrport = smartlist_get(items, 3);
  if (tor_addr_port_parse(addrport, &addr, &port)<0) {
    log_warn(LD_CONFIG, "Error parsing transport "
             "address '%s'", addrport);
    goto err;
  }

  if (!port) {
    log_warn(LD_CONFIG,
             "Transport address '%s' has no port.", addrport);
    goto err;
  }

  transport = transport_create(&addr, port, method_name, socks_ver);
  if (!transport)
    goto err;

  smartlist_add(mp->transports, transport);

  log_warn(LD_CONFIG, "Transport %s at %s:%d with SOCKS %d. "
           "Attached to managed proxy.",
           method_name, fmt_addr(&addr), (int)port, socks_ver);

  r=0;
  goto done;

 err:
  r = -1;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  return r;
}

/** Return a string containing the address:port that <b>transport</b>
 *  should use. It's the responsibility of the caller to free() the
 *  received string. */
static char *
get_bindaddr_for_proxy(const managed_proxy_t *mp)
{
  char *bindaddr = NULL;
  smartlist_t *string_tmp = smartlist_create();

  tor_assert(mp->is_server);

  SMARTLIST_FOREACH_BEGIN(mp->transports_to_launch, char *, t) {
    tor_asprintf(&bindaddr, "%s-%s", t, get_bindaddr_for_transport(t));
    smartlist_add(string_tmp, bindaddr);
  } SMARTLIST_FOREACH_END(t);

  bindaddr = smartlist_join_strings(string_tmp, ",", 0, NULL);

  SMARTLIST_FOREACH(string_tmp, char *, t, tor_free(t));
  smartlist_free(string_tmp);

  return bindaddr;
}

/** Prepare the <b>envp</b> of managed proxy <b>mp</b> */
static void
set_managed_proxy_environment(char ***envp, const managed_proxy_t *mp)
{
  or_options_t *options = get_options();
  char **tmp=NULL;
  char *state_loc=NULL;
  char *transports_to_launch=NULL;
  char *bindaddr=NULL;

  int n_envs = mp->is_server ? ENVIRON_SIZE_SERVER : ENVIRON_SIZE_CLIENT;

  /* allocate enough space for our env. vars and a NULL pointer */
  *envp = tor_malloc(sizeof(char*)*(n_envs+1));
  tmp = *envp;

  state_loc = get_datadir_fname("pt_state/"); /* XXX temp */
  transports_to_launch =
    smartlist_join_strings(mp->transports_to_launch, ",", 0, NULL);

  tor_asprintf(tmp++, "HOME=%s", getenv("HOME"));
  tor_asprintf(tmp++, "PATH=%s", getenv("PATH"));
  tor_asprintf(tmp++, "TOR_PT_STATE_LOCATION=%s", state_loc);
  tor_asprintf(tmp++, "TOR_PT_MANAGED_TRANSPORT_VER=1"); /* temp */
  if (mp->is_server) {
    bindaddr = get_bindaddr_for_proxy(mp);

    tor_asprintf(tmp++, "TOR_PT_ORPORT=127.0.0.1:%d", options->ORPort); /* XXX temp */
    tor_asprintf(tmp++, "TOR_PT_SERVER_BINDADDR=%s", bindaddr);
    tor_asprintf(tmp++, "TOR_PT_SERVER_TRANSPORTS=%s", transports_to_launch);
    tor_asprintf(tmp++, "TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:4200"); /* XXX temp*/
  } else {
    tor_asprintf(tmp++, "TOR_PT_CLIENT_TRANSPORTS=%s", transports_to_launch);
  }
  *tmp = NULL;

  tor_free(state_loc);
  tor_free(transports_to_launch);
  tor_free(bindaddr);
}

/** Register <b>transport</b> using proxy with <b>proxy_argv</b> to
 *  the managed proxy subsystem.
 *  If <b>is_server</b> is true, then the proxy is a server proxy. */
void
pt_kickstart_proxy(const char *transport, char **proxy_argv, int is_server)
{
  managed_proxy_t *mp=NULL;

  mp = get_managed_proxy_by_argv(proxy_argv);

  if (!mp) { /* we haven't seen this proxy before */
    /* create a managed proxy */
    managed_proxy_t *mp = tor_malloc_zero(sizeof(managed_proxy_t));
    mp->conf_state = PT_PROTO_INFANT;
    mp->is_server = is_server;
    mp->argv = proxy_argv;
    mp->transports = smartlist_create();

    mp->transports_to_launch = smartlist_create();
    add_transport_to_proxy(transport, mp);

    /* register the managed proxy */
    if (!unconfigured_proxy_list)
      unconfigured_proxy_list = smartlist_create();
    smartlist_add(unconfigured_proxy_list, mp);
  } else { /* known proxy. just add transport to its transport list */
    add_transport_to_proxy(transport, mp);
    free_execve_args(proxy_argv);
  }
}

/** Frees the array of pointers in <b>arg</b> used as arguments to
    execve. */
static INLINE void
free_execve_args(char **arg)
{
  char **tmp = arg;
  while (*tmp) /* use the fact that the last element of the array is a
                  NULL pointer to know when to stop freeing */
    _tor_free(*tmp++);

  tor_free(arg);
}

/** Release all storage held by the pluggable transports subsystem. */
void
pt_free_all(void)
{
  if (unconfigured_proxy_list) {
    /* If the proxy is in PT_PROTO_COMPLETED, it has registered its
       transports and it's the duty of the circuitbuild.c subsystem to
       free them. Otherwise, it hasn't registered its transports yet
       and we should free them here. */
    SMARTLIST_FOREACH_BEGIN(unconfigured_proxy_list, managed_proxy_t *, mp) {
      if (mp->conf_state == PT_PROTO_COMPLETED)
        managed_proxy_destroy(mp);
      else
        managed_proxy_destroy_with_transports(mp);
    } SMARTLIST_FOREACH_END(mp);

    smartlist_clear(unconfigured_proxy_list);
    smartlist_free(unconfigured_proxy_list);
    unconfigured_proxy_list=NULL;
  }
}

