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

static void set_managed_proxy_environment(char ***envp,
                                          const managed_proxy_t *mp);
static INLINE int proxy_configuration_finished(const managed_proxy_t *mp);

static void managed_proxy_destroy(managed_proxy_t *mp);

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
static smartlist_t *managed_proxy_list = NULL;
/** Number of still unconfigured proxies. */
static int unconfigured_proxies_n = 0;

/** "The main idea is:"

    Each managed proxy is represented by a 'managed_proxy_t'.
    Each managed proxy can support multiple transports.
    Each managed proxy gets configured through a multistep process.

    'managed_proxy_list' contains all the managed proxies this tor
    instance is supporting.
    In the 'managed_proxy_list' there are 'unconfigured_proxies_n'
    managed proxies that are still unconfigured.

    In every run_scheduled_event() tick, we attempt to launch and then
    configure the unconfiged managed proxies, using the configuration
    protocol defined in the 180_pluggable_transport.txt proposal. A
    managed proxy might need several ticks to get fully configured.

    When a managed proxy is fully configured, we register all its
    transports to the circuitbuild.c subsystem. At that point the
    transports are owned by the circuitbuild.c subsystem.

    When a managed proxy fails to follow the 180 configuration
    protocol, it gets marked as broken and gets destroyed.

    "In a little more technical detail:"

    While we are serially parsing torrc, we store all the transports
    that a proxy should spawn in its 'transports_to_launch' element.

    When we finish reading the torrc, we spawn the managed proxy and
    expect {S,C}METHOD lines from its output. We add transports
    described by METHOD lines to its 'transports' element, as
    'transport_t' structs.

    When the managed proxy stops spitting METHOD lines (signified by a
    '{S,C}METHODS DONE' message) we register all the transports
    collected to the circuitbuild.c subsystem. At this point, the
    'transport_t's can be transformed into dangling pointers at any
    point by the circuitbuild.c subsystem, and so we replace all
    'transport_t's with strings describing the transport names.  We
    can still go from a transport name to a 'transport_t' using the
    fact that transport names uniquely identify 'transport_t's.

    "In even more technical detail I shall describe what happens when
    the SIGHUP bell tolls:"

    We immediately destroy all unconfigured proxies (We shouldn't have
    unconfigured proxies in the first place, except when SIGHUP rings
    immediately after tor is launched.).

    We mark all managed proxies and transports to signify that they
    must be removed if they don't contribute by the new torrc
    (marked_for_removal).
    We also mark all managed proxies to signify that they might need
    to be restarted so that they end up supporting all the transports
    the new torrc wants them to support (got_hup).
    We also clear their 'transports_to_launch' list so that we can put
    there the transports we need to launch according to the new torrc.

    We then start parsing torrc again.

    Everytime we encounter a transport line using a known pre-SIGHUP
    managed proxy, we cleanse that proxy from the removal mark.

    We also mark it as unconfigured so that on the next scheduled
    events tick, we investigate whether we need to restart the proxy
    so that it also spawns the new transports.
    If the post-SIGHUP 'transports_to_launch' list is identical to the
    pre-SIGHUP one, it means that no changes were introduced to this
    proxy during the SIGHUP and no restart has to take place.

    During the post-SIGHUP torrc parsing, we unmark all transports
    spawned by managed proxies that we find in our torrc.
    We do that so that if we don't need to restart a managed proxy, we
    can continue using its old transports normally.
    If we end up restarting the proxy, we destroy and unregister all
    old transports from the circuitbuild.c subsystem.
*/

/** Return true if there are still unconfigured managed proxies. */
int
pt_proxies_configuration_pending(void)
{
  return !! unconfigured_proxies_n;
}

/** Return true if <b>mp</b> has the same argv as <b>proxy_argv</b> */
static int
managed_proxy_has_argv(const managed_proxy_t *mp, char **proxy_argv)
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
get_managed_proxy_by_argv_and_type(char **proxy_argv, int is_server)
{
  if (!managed_proxy_list)
    return NULL;

  SMARTLIST_FOREACH_BEGIN(managed_proxy_list,  managed_proxy_t *, mp) {
    if (managed_proxy_has_argv(mp, proxy_argv) &&
        mp->is_server == is_server)
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

/** Called when a SIGHUP occurs. Returns true if managed proxy
 *  <b>mp</b> needs to be restarted after the SIGHUP, based on the new
 *  torrc. */
static int
proxy_needs_restart(const managed_proxy_t *mp)
{
  /* mp->transport_to_launch is populated with the names of the
     transports that must be launched *after* the SIGHUP.
     mp->transports is populated with the names of the transports that
     were launched *before* the SIGHUP.

     If the two lists contain the same strings, we don't need to
     restart the proxy, since it already does what we want. */

  tor_assert(smartlist_len(mp->transports_to_launch) > 0);
  tor_assert(mp->conf_state == PT_PROTO_COMPLETED);

  if (smartlist_len(mp->transports_to_launch) != smartlist_len(mp->transports))
    goto needs_restart;

  SMARTLIST_FOREACH_BEGIN(mp->transports_to_launch, char *, t_t_l) {
    if (!smartlist_string_isin(mp->transports, t_t_l))
      goto needs_restart;

  } SMARTLIST_FOREACH_END(t_t_l);

  return 0;

 needs_restart:
  return 1;
}

/** Managed proxy <b>mp</b> must be restarted. Do all the necessary
 *  preparations and then flag its state so that it will be relaunched
 *  in the next tick. */
static void
proxy_prepare_for_restart(managed_proxy_t *mp)
{
  transport_t *t_tmp = NULL;

  tor_assert(mp->conf_state == PT_PROTO_COMPLETED);
  tor_assert(mp->pid);

  /* kill the old obfsproxy process */
  tor_terminate_process(mp->pid);
  mp->pid = 0;
  fclose(mp->stdout);

  /* destroy all its old transports. we no longer use them. */
  SMARTLIST_FOREACH_BEGIN(mp->transports, const char *, t_name) {
    t_tmp = transport_get_by_name(t_name);
    if (t_tmp)
      t_tmp->marked_for_removal = 1;
  } SMARTLIST_FOREACH_END(t_name);
  sweep_transport_list();

  /* free the transport names in mp->transports */
  SMARTLIST_FOREACH(mp->transports, char *, t_name, tor_free(t_name));
  smartlist_clear(mp->transports);

  /* flag it as an infant proxy so that it gets launched on next tick */
  mp->conf_state = PT_PROTO_INFANT;
}

/** Launch managed proxy <b>mp</b>. */
static int
launch_managed_proxy(managed_proxy_t *mp)
{
  char **envp=NULL;
  int pid;
  FILE *stdout_read = NULL;
  int stdout_pipe=-1, stderr_pipe=-1;

  /* prepare the environment variables for the managed proxy */
  set_managed_proxy_environment(&envp, mp);

  pid = tor_spawn_background(mp->argv[0], &stdout_pipe,
                             &stderr_pipe, (const char **)mp->argv,
                             (const char **)envp);
  if (pid < 0) {
    log_warn(LD_GENERAL, "Managed proxy at '%s' failed at launch.",
             mp->argv[0]);
    return -1;
  }

  /* free the memory allocated by set_managed_proxy_environment(). */
  free_execve_args(envp);

  /* Set stdout/stderr pipes to be non-blocking */
  fcntl(stdout_pipe, F_SETFL, O_NONBLOCK);
  /* Open the buffered IO streams */
  stdout_read = fdopen(stdout_pipe, "r");

  log_info(LD_CONFIG, "Managed proxy has spawned at PID %d.", pid);

  mp->conf_state = PT_PROTO_LAUNCHED;
  mp->stdout = stdout_read;
  mp->pid = pid;

  return 0;
}

/** Check if any of the managed proxies we are currently trying to
 *  configure have anything new to say. This is called from
 *  run_scheduled_events(). */
void
pt_configure_remaining_proxies(void)
{
  log_debug(LD_CONFIG, "Configuring remaining managed proxies (%d)!",
            unconfigured_proxies_n);
  SMARTLIST_FOREACH_BEGIN(managed_proxy_list,  managed_proxy_t *, mp) {
    tor_assert(mp->conf_state != PT_PROTO_BROKEN);

    if (mp->got_hup) {
      mp->got_hup = 0;

    /* This proxy is marked by a SIGHUP. Check whether we need to
       restart it. */
      if (proxy_needs_restart(mp)) {
        log_info(LD_GENERAL, "Preparing managed proxy for restart.");
        proxy_prepare_for_restart(mp);
        continue;
      } else { /* it doesn't need to be restarted. */
        log_info(LD_GENERAL, "Nothing changed for managed proxy after HUP: "
                 "not restarting.");
        unconfigured_proxies_n--;
        tor_assert(unconfigured_proxies_n >= 0);
      }

      continue;
    }

    /* If the proxy is not fully configured, try to configure it
       futher. */
    if (!proxy_configuration_finished(mp))
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
      log_notice(LD_GENERAL, "Managed proxy stream closed. "
                 "Most probably application stopped running");
      mp->conf_state = PT_PROTO_BROKEN;
    } else { /* unknown stream status */
      log_notice(LD_GENERAL, "Unknown stream status while configuring proxy.");
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
register_server_proxy(managed_proxy_t *mp)
{
  /* After we register this proxy's transports, we switch its
     mp->transports to a list containing strings of its transport
     names. (See transports.h) */
  smartlist_t *sm_tmp = smartlist_create();

  tor_assert(mp->conf_state != PT_PROTO_COMPLETED);
  SMARTLIST_FOREACH_BEGIN(mp->transports, transport_t *, t) {
    save_transport_to_state(t->name, &t->addr, t->port);
    smartlist_add(sm_tmp, tor_strdup(t->name));
  } SMARTLIST_FOREACH_END(t);

  /* Since server proxies don't register their transports in the
     circuitbuild.c subsystem, it's our duty to free them when we
     switch mp->transports to strings. */
  SMARTLIST_FOREACH(mp->transports, transport_t *, t, transport_free(t));
  smartlist_free(mp->transports);

  mp->transports = sm_tmp;
}

/** Register all the transports supported by client managed proxy
 *  <b>mp</b> to the bridge subsystem. */
static void
register_client_proxy(managed_proxy_t *mp)
{
  int r;
  /* After we register this proxy's transports, we switch its
     mp->transports to a list containing strings of its transport
     names. (See transports.h) */
  smartlist_t *sm_tmp = smartlist_create();

  tor_assert(mp->conf_state != PT_PROTO_COMPLETED);
  SMARTLIST_FOREACH_BEGIN(mp->transports, transport_t *, t) {
    r = transport_add(t);
    switch (r) {
    case -1:
      log_notice(LD_GENERAL, "Could not add transport %s. Skipping.", t->name);
      transport_free(t);
      break;
    case 0:
      log_info(LD_GENERAL, "Succesfully registered transport %s", t->name);
      smartlist_add(sm_tmp, tor_strdup(t->name));
      break;
    case 1:
      log_info(LD_GENERAL, "Succesfully registered transport %s", t->name);
      smartlist_add(sm_tmp, tor_strdup(t->name));
      transport_free(t);
      break;
    }
  } SMARTLIST_FOREACH_END(t);

  smartlist_free(mp->transports);
  mp->transports = sm_tmp;
}

/** Register the transports of managed proxy <b>mp</b>. */
static INLINE void
register_proxy(managed_proxy_t *mp)
{
  if (mp->is_server)
    register_server_proxy(mp);
  else
    register_client_proxy(mp);
}

/** Free memory allocated by managed proxy <b>mp</b>. */
static void
managed_proxy_destroy(managed_proxy_t *mp)
{
  if (mp->conf_state != PT_PROTO_COMPLETED)
    SMARTLIST_FOREACH(mp->transports, transport_t *, t, transport_free(t));
  else
    SMARTLIST_FOREACH(mp->transports, char *, t_name, tor_free(t_name));

  /* free the transports smartlist */
  smartlist_free(mp->transports);

  /* free the transports_to_launch smartlist */
  SMARTLIST_FOREACH(mp->transports_to_launch, char *, t, tor_free(t));
  smartlist_free(mp->transports_to_launch);

  /* remove it from the list of managed proxies */
  smartlist_remove(managed_proxy_list, mp);

  /* close its stdout stream */
  if (mp->stdout)
    fclose(mp->stdout);

  /* free the argv */
  free_execve_args(mp->argv);

  if (mp->pid)
    tor_terminate_process(mp->pid);

  tor_free(mp);
}

/** Handle a configured or broken managed proxy <b>mp</b>. */
static void
handle_finished_proxy(managed_proxy_t *mp)
{
  switch (mp->conf_state) {
  case PT_PROTO_BROKEN: /* if broken: */
    managed_proxy_destroy(mp); /* annihilate it. */
    break;
  case PT_PROTO_CONFIGURED: /* if configured correctly: */
    register_proxy(mp); /* register its transports */
    mp->conf_state = PT_PROTO_COMPLETED; /* and mark it as completed. */
    break;
  case PT_PROTO_INFANT:
  case PT_PROTO_LAUNCHED:
  case PT_PROTO_ACCEPTING_METHODS:
  case PT_PROTO_COMPLETED:
  default:
    log_warn(LD_CONFIG, "Unexpected managed proxy state in "
             "handle_finished_proxy().");
    tor_assert(0);
  }

  unconfigured_proxies_n--;
  tor_assert(unconfigured_proxies_n >= 0);
}

/** Return true if the configuration of the managed proxy <b>mp</b> is
    finished. */
static INLINE int
proxy_configuration_finished(const managed_proxy_t *mp)
{
  return (mp->conf_state == PT_PROTO_CONFIGURED ||
          mp->conf_state == PT_PROTO_BROKEN);
}

/** This function is called when a proxy sends an {S,C}METHODS DONE message. */
static void
handle_methods_done(const managed_proxy_t *mp)
{
  tor_assert(mp->transports);

  if (smartlist_len(mp->transports) == 0)
    log_notice(LD_GENERAL, "Proxy was spawned successfully, "
               "but it didn't laucn any pluggable transport listeners!");

  log_info(LD_CONFIG, "%s managed proxy configuration completed!",
           mp->is_server ? "Server" : "Client");
}

/** Handle a configuration protocol <b>line</b> received from a
 *  managed proxy <b>mp</b>. */
void
handle_proxy_line(const char *line, managed_proxy_t *mp)
{
  log_debug(LD_GENERAL, "Got a line from managed proxy: %s\n", line);

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
    log_notice(LD_CONFIG, "Managed proxy sent us an %s without an error "
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

  if (strcmp("1", line+strlen(PROTO_NEG_SUCCESS)+1)) { /* hardcoded temp */
    log_warn(LD_CONFIG, "Managed proxy tried to negotiate on version '%s'. "
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
  if (!string_is_C_identifier(method_name)) {
    log_warn(LD_CONFIG, "Transport name is not a C identifier (%s).",
             method_name);
    goto err;
  }

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
  log_info(LD_CONFIG, "Server transport %s at %s:%d.",
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
  if (!string_is_C_identifier(method_name)) {
    log_warn(LD_CONFIG, "Transport name is not a C identifier (%s).",
             method_name);
    goto err;
  }

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

  log_info(LD_CONFIG, "Transport %s at %s:%d with SOCKS %d. "
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

    /* XXX temp */
    tor_asprintf(tmp++, "TOR_PT_ORPORT=127.0.0.1:%d", options->ORPort);
    tor_asprintf(tmp++, "TOR_PT_SERVER_BINDADDR=%s", bindaddr);
    tor_asprintf(tmp++, "TOR_PT_SERVER_TRANSPORTS=%s", transports_to_launch);
    /* XXX temp*/
    tor_asprintf(tmp++, "TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:4200");
  } else {
    tor_asprintf(tmp++, "TOR_PT_CLIENT_TRANSPORTS=%s", transports_to_launch);
  }
  *tmp = NULL;

  tor_free(state_loc);
  tor_free(transports_to_launch);
  tor_free(bindaddr);
}

/** Create and return a new managed proxy for <b>transport</b> using
 *  <b>proxy_argv</b>. If <b>is_server</b> is true, it's a server
 *  managed proxy. */
static managed_proxy_t *
managed_proxy_create(const char *transport, char **proxy_argv, int is_server)
{
  managed_proxy_t *mp = tor_malloc_zero(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_INFANT;
  mp->is_server = is_server;
  mp->argv = proxy_argv;
  mp->transports = smartlist_create();

  mp->transports_to_launch = smartlist_create();
  add_transport_to_proxy(transport, mp);

  /* register the managed proxy */
  if (!managed_proxy_list)
    managed_proxy_list = smartlist_create();
  smartlist_add(managed_proxy_list, mp);
  unconfigured_proxies_n++;

  return mp;
}

/** Register <b>transport</b> using proxy with <b>proxy_argv</b> to
 *  the managed proxy subsystem.
 *  If <b>is_server</b> is true, then the proxy is a server proxy. */
void
pt_kickstart_proxy(const char *transport, char **proxy_argv, int is_server)
{
  managed_proxy_t *mp=NULL;
  transport_t *old_transport = NULL;

  mp = get_managed_proxy_by_argv_and_type(proxy_argv, is_server);

  if (!mp) { /* we haven't seen this proxy before */
    managed_proxy_create(transport, proxy_argv, is_server);

  } else { /* known proxy. add its transport to its transport list */
    if (mp->got_hup) {
      /* If the managed proxy we found is marked by a SIGHUP, it means
         that it's not useless and should be kept. If it's marked for
         removal, unmark it and increase the unconfigured proxies so
         that we try to restart it if we need to. Afterwards, check if
         a transport_t for 'transport' used to exist before the SIGHUP
         and make sure it doesn't get deleted because we might reuse
         it. */
      if (mp->marked_for_removal) {
        mp->marked_for_removal = 0;
        unconfigured_proxies_n++;
      }

      old_transport = transport_get_by_name(transport);
      if (old_transport)
        old_transport->marked_for_removal = 0;
    }

    add_transport_to_proxy(transport, mp);
    free_execve_args(proxy_argv);
  }
}

/** Frees the array of pointers in <b>arg</b> used as arguments to
    execve(2). */
static INLINE void
free_execve_args(char **arg)
{
  char **tmp = arg;
  while (*tmp) /* use the fact that the last element of the array is a
                  NULL pointer to know when to stop freeing */
    _tor_free(*tmp++);

  tor_free(arg);
}

/** Tor will read its config.
 *  Prepare the managed proxy list so that proxies not used in the new
 *  config will shutdown, and proxies that need to spawn different
 *  transports will do so. */
void
pt_prepare_proxy_list_for_config_read(void)
{
  if (!managed_proxy_list)
    return;

  SMARTLIST_FOREACH_BEGIN(managed_proxy_list, managed_proxy_t *, mp) {
    /* Destroy unconfigured proxies. */
    if (mp->conf_state != PT_PROTO_COMPLETED) {
        managed_proxy_destroy(mp);
        unconfigured_proxies_n--;
        continue;
    }

    tor_assert(mp->conf_state == PT_PROTO_COMPLETED);

    mp->marked_for_removal = 1;
    mp->got_hup = 1;
    SMARTLIST_FOREACH(mp->transports_to_launch, char *, t, tor_free(t));
    smartlist_clear(mp->transports_to_launch);
  } SMARTLIST_FOREACH_END(mp);

  tor_assert(unconfigured_proxies_n == 0);
}

/** The tor config was read.
 *  Destroy all managed proxies that were marked by a previous call to
 *  prepare_proxy_list_for_config_read() and are not used by the new
 *  config. */
void
sweep_proxy_list(void)
{
  if (!managed_proxy_list)
    return;

  SMARTLIST_FOREACH_BEGIN(managed_proxy_list, managed_proxy_t *, mp) {
    if (mp->marked_for_removal) {
      SMARTLIST_DEL_CURRENT(managed_proxy_list, mp);
      managed_proxy_destroy(mp);
    }
  } SMARTLIST_FOREACH_END(mp);
}

/** Release all storage held by the pluggable transports subsystem. */
void
pt_free_all(void)
{
  if (managed_proxy_list) {
    /* If the proxy is in PT_PROTO_COMPLETED, it has registered its
       transports and it's the duty of the circuitbuild.c subsystem to
       free them. Otherwise, it hasn't registered its transports yet
       and we should free them here. */
    SMARTLIST_FOREACH(managed_proxy_list, managed_proxy_t *, mp,
                      managed_proxy_destroy(mp));

    smartlist_free(managed_proxy_list);
    managed_proxy_list=NULL;
  }
}

