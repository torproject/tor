/* Copyright (c) 2011-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file transports.c
 * \brief Pluggable Transports related code.
 *
 * \details
 * Each managed proxy is represented by a <b>managed_proxy_t</b>.
 * Each managed proxy can support multiple transports.
 * Each managed proxy gets configured through a multistep process.
 *
 * ::managed_proxy_list contains all the managed proxies this tor
 * instance is supporting.
 * In the ::managed_proxy_list there are ::unconfigured_proxies_n
 * managed proxies that are still unconfigured.
 *
 * In every run_scheduled_event() tick, we attempt to launch and then
 * configure the unconfiged managed proxies, using the configuration
 * protocol defined in the 180_pluggable_transport.txt proposal. A
 * managed proxy might need several ticks to get fully configured.
 *
 * When a managed proxy is fully configured, we register all its
 * transports to the circuitbuild.c subsystem. At that point the
 * transports are owned by the circuitbuild.c subsystem.
 *
 * When a managed proxy fails to follow the 180 configuration
 * protocol, it gets marked as broken and gets destroyed.
 *
 * <b>In a little more detail:</b>
 *
 * While we are serially parsing torrc, we store all the transports
 * that a proxy should spawn in its <em>transports_to_launch</em>
 * element.
 *
 * When we finish reading the torrc, we spawn the managed proxy and
 * expect {S,C}METHOD lines from its output. We add transports
 * described by METHOD lines to its <em>transports</em> element, as
 * transport_t structs.
 *
 * When the managed proxy stops spitting METHOD lines (signified by a
 * '{S,C}METHODS DONE' message) we register all the transports
 * collected to the circuitbuild.c subsystem. At this point, the
 * pointers to transport_t can be transformed into dangling pointers
 * at any point by the circuitbuild.c subsystem, and so we replace all
 * transport_t pointers with strings describing the transport names.
 * We can still go from a transport name to a transport_t using the
 * fact that each transport name uniquely identifies a transport_t.
 *
 * <b>In even more detail, this is what happens when a SIGHUP
 * occurs:</b>
 *
 * We immediately destroy all unconfigured proxies (We shouldn't have
 * unconfigured proxies in the first place, except when SIGHUP rings
 * immediately after tor is launched.).
 *
 * We mark all managed proxies and transports to signify that they
 * must be removed if they don't contribute by the new torrc
 * (we mark using the <b>marked_for_removal</b> element).
 * We also mark all managed proxies to signify that they might need to
 * be restarted so that they end up supporting all the transports the
 * new torrc wants them to support (using the <b>got_hup</b> element).
 * We also clear their <b>transports_to_launch</b> list so that we can
 * put there the transports we need to launch according to the new
 * torrc.
 *
 * We then start parsing torrc again.
 *
 * Everytime we encounter a transport line using a known pre-SIGHUP
 * managed proxy, we cleanse that proxy from the removal mark.
 * We also mark it as unconfigured so that on the next scheduled
 * events tick, we investigate whether we need to restart the proxy
 * so that it also spawns the new transports.
 * If the post-SIGHUP <b>transports_to_launch</b> list is identical to
 * the pre-SIGHUP one, it means that no changes were introduced to
 * this proxy during the SIGHUP and no restart has to take place.
 *
 * During the post-SIGHUP torrc parsing, we unmark all transports
 * spawned by managed proxies that we find in our torrc.
 * We do that so that if we don't need to restart a managed proxy, we
 * can continue using its old transports normally.
 * If we end up restarting the proxy, we destroy and unregister all
 * old transports from the circuitbuild.c subsystem.
 **/

#define PT_PRIVATE
#include "or.h"
#include "config.h"
#include "circuitbuild.h"
#include "transports.h"
#include "util.h"
#include "router.h"

static process_environment_t *
create_managed_proxy_environment(const managed_proxy_t *mp);

static INLINE int proxy_configuration_finished(const managed_proxy_t *mp);

static void managed_proxy_destroy(managed_proxy_t *mp,
                                  int also_terminate_process);

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

/** Number of environment variables for managed proxy clients/servers. */
#define ENVIRON_SIZE_CLIENT 3
#define ENVIRON_SIZE_SERVER 7 /* XXX known to be too high, but that's ok */

/** The first and only supported - at the moment - configuration
    protocol version. */
#define PROTO_VERSION_ONE 1

/** List of unconfigured managed proxies. */
static smartlist_t *managed_proxy_list = NULL;
/** Number of still unconfigured proxies. */
static int unconfigured_proxies_n = 0;
/** Boolean: True iff we might need to restart some proxies. */
static int check_if_restarts_needed = 0;

/** Return true if there are still unconfigured managed proxies, or proxies
 * that need restarting. */
int
pt_proxies_configuration_pending(void)
{
  return unconfigured_proxies_n || check_if_restarts_needed;
}

/** Assert that the unconfigured_proxies_n value correctly matches the number
 * of proxies in a state other than PT_PROTO_COMPLETE. */
static void
assert_unconfigured_count_ok(void)
{
  int n_completed = 0;
  if (!managed_proxy_list) {
    tor_assert(unconfigured_proxies_n == 0);
    return;
  }

  SMARTLIST_FOREACH(managed_proxy_list, managed_proxy_t *, mp, {
      if (mp->conf_state == PT_PROTO_COMPLETED)
        ++n_completed;
  });

  tor_assert(n_completed + unconfigured_proxies_n ==
             smartlist_len(managed_proxy_list));
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

  /* destroy the process handle and terminate the process. */
  tor_process_handle_destroy(mp->process_handle, 1);
  mp->process_handle = NULL;

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
  unconfigured_proxies_n++;
}

/** Launch managed proxy <b>mp</b>. */
static int
launch_managed_proxy(managed_proxy_t *mp)
{
  int retval;

  process_environment_t *env = create_managed_proxy_environment(mp);

#ifdef _WIN32
  /* Passing NULL as lpApplicationName makes Windows search for the .exe */
  retval = tor_spawn_background(NULL,
                                (const char **)mp->argv,
                                env,
                                &mp->process_handle);
#else
  retval = tor_spawn_background(mp->argv[0],
                                (const char **)mp->argv,
                                env,
                                &mp->process_handle);
#endif

  process_environment_free(env);

  if (retval == PROCESS_STATUS_ERROR) {
    log_warn(LD_GENERAL, "Managed proxy at '%s' failed at launch.",
             mp->argv[0]);
    return -1;
  }

  log_info(LD_CONFIG, "Managed proxy at '%s' has spawned with PID '%d'.",
           mp->argv[0], tor_process_get_pid(mp->process_handle));

  mp->conf_state = PT_PROTO_LAUNCHED;

  return 0;
}

/** Check if any of the managed proxies we are currently trying to
 *  configure have anything new to say. This is called from
 *  run_scheduled_events(). */
void
pt_configure_remaining_proxies(void)
{
  smartlist_t *tmp = smartlist_new();

  log_debug(LD_CONFIG, "Configuring remaining managed proxies (%d)!",
            unconfigured_proxies_n);

  /* Iterate over tmp, not managed_proxy_list, since configure_proxy can
   * remove elements from managed_proxy_list. */
  smartlist_add_all(tmp, managed_proxy_list);

  assert_unconfigured_count_ok();

  SMARTLIST_FOREACH_BEGIN(tmp,  managed_proxy_t *, mp) {
    tor_assert(mp->conf_state != PT_PROTO_BROKEN ||
               mp->conf_state != PT_PROTO_FAILED_LAUNCH);

    if (mp->got_hup) {
      mp->got_hup = 0;

      /* This proxy is marked by a SIGHUP. Check whether we need to
         restart it. */
      if (proxy_needs_restart(mp)) {
        log_info(LD_GENERAL, "Preparing managed proxy '%s' for restart.",
                 mp->argv[0]);
        proxy_prepare_for_restart(mp);
      } else { /* it doesn't need to be restarted. */
        log_info(LD_GENERAL, "Nothing changed for managed proxy '%s' after "
                 "HUP: not restarting.", mp->argv[0]);
      }

      continue;
    }

    /* If the proxy is not fully configured, try to configure it
       futher. */
    if (!proxy_configuration_finished(mp))
      configure_proxy(mp);

  } SMARTLIST_FOREACH_END(mp);

  smartlist_free(tmp);
  check_if_restarts_needed = 0;
  assert_unconfigured_count_ok();
}

#ifdef _WIN32

/** Attempt to continue configuring managed proxy <b>mp</b>. */
static void
configure_proxy(managed_proxy_t *mp)
{
  int pos;
  char stdout_buf[200];
  smartlist_t *lines = NULL;

  /* if we haven't launched the proxy yet, do it now */
  if (mp->conf_state == PT_PROTO_INFANT) {
    if (launch_managed_proxy(mp) < 0) { /* launch fail */
      mp->conf_state = PT_PROTO_FAILED_LAUNCH;
      handle_finished_proxy(mp);
    }
    return;
  }

  tor_assert(mp->conf_state != PT_PROTO_INFANT);
  tor_assert(mp->process_handle);

  pos = tor_read_all_handle(tor_process_get_stdout_pipe(mp->process_handle),
                            stdout_buf, sizeof(stdout_buf) - 1, NULL);
  if (pos < 0) {
    log_notice(LD_GENERAL, "Failed to read data from managed proxy '%s'.",
               mp->argv[0]);
    mp->conf_state = PT_PROTO_BROKEN;
    goto done;
  }

  if (pos == 0) /* proxy has nothing interesting to say. */
    return;

  /* End with a null even if there isn't a \r\n at the end */
  /* TODO: What if this is a partial line? */
  stdout_buf[pos] = '\0';

  /* Split up the buffer */
  lines = smartlist_new();
  tor_split_lines(lines, stdout_buf, pos);

  /* Handle lines. */
  SMARTLIST_FOREACH_BEGIN(lines, const char *, line) {
    handle_proxy_line(line, mp);
    if (proxy_configuration_finished(mp))
      goto done;
  } SMARTLIST_FOREACH_END(line);

 done:
  /* if the proxy finished configuring, exit the loop. */
  if (proxy_configuration_finished(mp))
    handle_finished_proxy(mp);

  if (lines)
    smartlist_free(lines);
}

#else /* _WIN32 */

/** Attempt to continue configuring managed proxy <b>mp</b>. */
static void
configure_proxy(managed_proxy_t *mp)
{
  enum stream_status r;
  char stdout_buf[200];

  /* if we haven't launched the proxy yet, do it now */
  if (mp->conf_state == PT_PROTO_INFANT) {
    if (launch_managed_proxy(mp) < 0) { /* launch fail */
      mp->conf_state = PT_PROTO_FAILED_LAUNCH;
      handle_finished_proxy(mp);
    }
    return;
  }

  tor_assert(mp->conf_state != PT_PROTO_INFANT);
  tor_assert(mp->process_handle);

  while (1) {
    r = get_string_from_pipe(tor_process_get_stdout_pipe(mp->process_handle),
                             stdout_buf, sizeof(stdout_buf) - 1);

    if (r  == IO_STREAM_OKAY) { /* got a line; handle it! */
      handle_proxy_line((const char *)stdout_buf, mp);
    } else if (r == IO_STREAM_EAGAIN) { /* check back later */
      return;
    } else if (r == IO_STREAM_CLOSED || r == IO_STREAM_TERM) { /* snap! */
      log_warn(LD_GENERAL, "Our communication channel with the managed proxy "
               "'%s' closed. Most probably application stopped running.",
               mp->argv[0]);
      mp->conf_state = PT_PROTO_BROKEN;
    } else { /* unknown stream status */
      log_warn(LD_BUG, "Unknown stream status '%d' while configuring managed "
               "proxy '%s'.", (int)r, mp->argv[0]);
    }

    /* if the proxy finished configuring, exit the loop. */
    if (proxy_configuration_finished(mp)) {
      handle_finished_proxy(mp);
      return;
    }
  }
}

#endif /* _WIN32 */

/** Register server managed proxy <b>mp</b> transports to state */
static void
register_server_proxy(managed_proxy_t *mp)
{
  /* After we register this proxy's transports, we switch its
     mp->transports to a list containing strings of its transport
     names. (See transports.h) */
  smartlist_t *sm_tmp = smartlist_new();

  tor_assert(mp->conf_state != PT_PROTO_COMPLETED);
  SMARTLIST_FOREACH_BEGIN(mp->transports, transport_t *, t) {
    save_transport_to_state(t->name, &t->addr, t->port);
    log_notice(LD_GENERAL, "Registered server transport '%s' at '%s:%d'",
               t->name, fmt_addr(&t->addr), (int)t->port);
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
  smartlist_t *sm_tmp = smartlist_new();

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
managed_proxy_destroy(managed_proxy_t *mp,
                      int also_terminate_process)
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

  /* free the argv */
  free_execve_args(mp->argv);

  tor_process_handle_destroy(mp->process_handle, also_terminate_process);
  mp->process_handle = NULL;

  tor_free(mp);
}

/** Handle a configured or broken managed proxy <b>mp</b>. */
static void
handle_finished_proxy(managed_proxy_t *mp)
{
  switch (mp->conf_state) {
  case PT_PROTO_BROKEN: /* if broken: */
    managed_proxy_destroy(mp, 1); /* annihilate it. */
    break;
  case PT_PROTO_FAILED_LAUNCH: /* if it failed before launching: */
    managed_proxy_destroy(mp, 0); /* destroy it but don't terminate */
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
    log_warn(LD_CONFIG, "Unexpected state '%d' of managed proxy '%s'.",
             (int)mp->conf_state, mp->argv[0]);
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
          mp->conf_state == PT_PROTO_BROKEN ||
          mp->conf_state == PT_PROTO_FAILED_LAUNCH);
}

/** This function is called when a proxy sends an {S,C}METHODS DONE message. */
static void
handle_methods_done(const managed_proxy_t *mp)
{
  tor_assert(mp->transports);

  if (smartlist_len(mp->transports) == 0)
    log_notice(LD_GENERAL, "Managed proxy '%s' was spawned successfully, "
               "but it didn't launch any pluggable transport listeners!",
               mp->argv[0]);

  log_info(LD_CONFIG, "%s managed proxy '%s' configuration completed!",
           mp->is_server ? "Server" : "Client",
           mp->argv[0]);
}

/** Handle a configuration protocol <b>line</b> received from a
 *  managed proxy <b>mp</b>. */
void
handle_proxy_line(const char *line, managed_proxy_t *mp)
{
  log_info(LD_GENERAL, "Got a line from managed proxy '%s': (%s)",
           mp->argv[0], line);

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
    /* managed proxy launch failed: parse error message to learn why. */
    int retval, child_state, saved_errno;
    retval = tor_sscanf(line, SPAWN_ERROR_MESSAGE "%x/%x",
                        &child_state, &saved_errno);
    if (retval == 2) {
      log_warn(LD_GENERAL,
               "Could not launch managed proxy executable at '%s' ('%s').",
               mp->argv[0], strerror(saved_errno));
    } else { /* failed to parse error message */
      log_warn(LD_GENERAL,"Could not launch managed proxy executable at '%s'.",
               mp->argv[0]);
    }

    mp->conf_state = PT_PROTO_FAILED_LAUNCH;
    return;
  }

  log_notice(LD_GENERAL, "Unknown line received by managed proxy (%s).", line);
  return;

 err:
  mp->conf_state = PT_PROTO_BROKEN;
  log_warn(LD_CONFIG, "Managed proxy at '%s' failed the configuration protocol"
           " and will be destroyed.", mp->argv[0]);
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
  tor_addr_t tor_addr;
  char *address=NULL;
  uint16_t port = 0;

  transport_t *transport=NULL;

  items = smartlist_new();
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
  if (tor_addr_port_split(LOG_PROTOCOL_WARN, addrport, &address, &port)<0) {
    log_warn(LD_CONFIG, "Error parsing transport "
             "address '%s'", addrport);
    goto err;
  }

  if (!port) {
    log_warn(LD_CONFIG,
             "Transport address '%s' has no port.", addrport);
    goto err;
  }

  if (tor_addr_parse(&tor_addr, address) < 0) {
    log_warn(LD_CONFIG, "Error parsing transport address '%s'", address);
    goto err;
  }

  transport = transport_new(&tor_addr, port, method_name, PROXY_NONE);
  if (!transport)
    goto err;

  smartlist_add(mp->transports, transport);

  /* For now, notify the user so that he knows where the server
     transport is listening. */
  log_info(LD_CONFIG, "Server transport %s at %s:%d.",
           method_name, address, (int)port);

  r=0;
  goto done;

 err:
  r = -1;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  tor_free(address);
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
  tor_addr_t tor_addr;
  char *address=NULL;
  uint16_t port = 0;

  transport_t *transport=NULL;

  items = smartlist_new();
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
  if (tor_addr_port_split(LOG_PROTOCOL_WARN, addrport, &address, &port)<0) {
    log_warn(LD_CONFIG, "Error parsing transport "
             "address '%s'", addrport);
    goto err;
  }

  if (!port) {
    log_warn(LD_CONFIG,
             "Transport address '%s' has no port.", addrport);
    goto err;
  }

  if (tor_addr_parse(&tor_addr, address) < 0) {
    log_warn(LD_CONFIG, "Error parsing transport address '%s'", address);
    goto err;
  }

  transport = transport_new(&tor_addr, port, method_name, socks_ver);
  if (!transport)
    goto err;

  smartlist_add(mp->transports, transport);

  log_info(LD_CONFIG, "Transport %s at %s:%d with SOCKS %d. "
           "Attached to managed proxy.",
           method_name, address, (int)port, socks_ver);

  r=0;
  goto done;

 err:
  r = -1;

 done:
  SMARTLIST_FOREACH(items, char*, s, tor_free(s));
  smartlist_free(items);
  tor_free(address);
  return r;
}

/** Return the string that tor should place in TOR_PT_SERVER_BINDADDR
 *  while configuring the server managed proxy in <b>mp</b>. The
 *  string is stored in the heap, and it's the the responsibility of
 *  the caller to deallocate it after its use. */
static char *
get_bindaddr_for_server_proxy(const managed_proxy_t *mp)
{
  char *bindaddr_result = NULL;
  char *bindaddr_tmp = NULL;
  smartlist_t *string_tmp = smartlist_new();

  tor_assert(mp->is_server);

  SMARTLIST_FOREACH_BEGIN(mp->transports_to_launch, char *, t) {
    bindaddr_tmp = get_stored_bindaddr_for_server_transport(t);

    smartlist_add_asprintf(string_tmp, "%s-%s", t, bindaddr_tmp);

    tor_free(bindaddr_tmp);
  } SMARTLIST_FOREACH_END(t);

  bindaddr_result = smartlist_join_strings(string_tmp, ",", 0, NULL);

  SMARTLIST_FOREACH(string_tmp, char *, t, tor_free(t));
  smartlist_free(string_tmp);

  return bindaddr_result;
}

/** Return a newly allocated process_environment_t * for <b>mp</b>'s
 * process. */
static process_environment_t *
create_managed_proxy_environment(const managed_proxy_t *mp)
{
  /* Environment variables to be added to or set in mp's environment. */
  smartlist_t *envs = smartlist_new();
  /* XXXX The next time someone touches this code, shorten the name of
   * set_environment_variable_in_smartlist, add a
   * set_env_var_in_smartlist_asprintf function, and get rid of the
   * silly extra envs smartlist. */

  /* The final environment to be passed to mp. */
  smartlist_t *merged_env_vars = get_current_process_environment_variables();

  process_environment_t *env;

  {
    char *state_tmp = get_datadir_fname("pt_state/"); /* XXX temp */
    smartlist_add_asprintf(envs, "TOR_PT_STATE_LOCATION=%s", state_tmp);
    tor_free(state_tmp);
  }

  smartlist_add(envs, tor_strdup("TOR_PT_MANAGED_TRANSPORT_VER=1"));

  {
    char *transports_to_launch =
      smartlist_join_strings(mp->transports_to_launch, ",", 0, NULL);

    smartlist_add_asprintf(envs,
                           mp->is_server ?
                           "TOR_PT_SERVER_TRANSPORTS=%s" :
                           "TOR_PT_CLIENT_TRANSPORTS=%s",
                           transports_to_launch);

    tor_free(transports_to_launch);
  }

  if (mp->is_server) {
    {
      char *orport_tmp =
        get_first_listener_addrport_string(CONN_TYPE_OR_LISTENER);
      smartlist_add_asprintf(envs, "TOR_PT_ORPORT=%s", orport_tmp);
      tor_free(orport_tmp);
    }

    {
      char *bindaddr_tmp = get_bindaddr_for_server_proxy(mp);
      smartlist_add_asprintf(envs, "TOR_PT_SERVER_BINDADDR=%s", bindaddr_tmp);
      tor_free(bindaddr_tmp);
    }

    /* XXX024 Remove the '=' here once versions of obfsproxy which
     * assert that this env var exists are sufficiently dead.
     *
     * (If we remove this line entirely, some joker will stick this
     * variable in Tor's environment and crash PTs that try to parse
     * it even when not run in server mode.) */
    smartlist_add(envs, tor_strdup("TOR_PT_EXTENDED_SERVER_PORT="));
  }

  SMARTLIST_FOREACH_BEGIN(envs, const char *, env_var) {
    set_environment_variable_in_smartlist(merged_env_vars, env_var,
                                          _tor_free, 1);
  } SMARTLIST_FOREACH_END(env_var);

  env = process_environment_make(merged_env_vars);

  smartlist_free(envs);

  SMARTLIST_FOREACH(merged_env_vars, void *, x, tor_free(x));
  smartlist_free(merged_env_vars);

  return env;
}

/** Create and return a new managed proxy for <b>transport</b> using
 *  <b>proxy_argv</b>.  Also, add it to the global managed proxy list. If
 *  <b>is_server</b> is true, it's a server managed proxy.  Takes ownership of
 *  <b>proxy_argv</b>.
 *
 * Requires that proxy_argv have at least one element. */
static managed_proxy_t *
managed_proxy_create(const smartlist_t *transport_list,
                     char **proxy_argv, int is_server)
{
  managed_proxy_t *mp = tor_malloc_zero(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_INFANT;
  mp->is_server = is_server;
  mp->argv = proxy_argv;
  mp->transports = smartlist_new();

  mp->transports_to_launch = smartlist_new();
  SMARTLIST_FOREACH(transport_list, const char *, transport,
                    add_transport_to_proxy(transport, mp));

  /* register the managed proxy */
  if (!managed_proxy_list)
    managed_proxy_list = smartlist_new();
  smartlist_add(managed_proxy_list, mp);
  unconfigured_proxies_n++;

  assert_unconfigured_count_ok();

  return mp;
}

/** Register proxy with <b>proxy_argv</b>, supporting transports in
 *  <b>transport_list</b>, to the managed proxy subsystem.
 *  If <b>is_server</b> is true, then the proxy is a server proxy.
 *
 * Takes ownership of proxy_argv.
 *
 * Requires that proxy_argv be a NULL-terminated array of command-line
 * elements, containing at least one element.
 **/
void
pt_kickstart_proxy(const smartlist_t *transport_list,
                   char **proxy_argv, int is_server)
{
  managed_proxy_t *mp=NULL;
  transport_t *old_transport = NULL;

  if (!proxy_argv || !proxy_argv[0]) {
    return;
  }

  mp = get_managed_proxy_by_argv_and_type(proxy_argv, is_server);

  if (!mp) { /* we haven't seen this proxy before */
    managed_proxy_create(transport_list, proxy_argv, is_server);

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
        check_if_restarts_needed = 1;
      }

      SMARTLIST_FOREACH_BEGIN(transport_list, const char *, transport) {
        old_transport = transport_get_by_name(transport);
        if (old_transport)
          old_transport->marked_for_removal = 0;
      } SMARTLIST_FOREACH_END(transport);
    }

    SMARTLIST_FOREACH(transport_list, const char *, transport,
                      add_transport_to_proxy(transport, mp));
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

  assert_unconfigured_count_ok();
  SMARTLIST_FOREACH_BEGIN(managed_proxy_list, managed_proxy_t *, mp) {
    /* Destroy unconfigured proxies. */
    if (mp->conf_state != PT_PROTO_COMPLETED) {
      SMARTLIST_DEL_CURRENT(managed_proxy_list, mp);
      managed_proxy_destroy(mp, 1);
      unconfigured_proxies_n--;
      continue;
    }

    tor_assert(mp->conf_state == PT_PROTO_COMPLETED);

    mp->marked_for_removal = 1;
    mp->got_hup = 1;
    SMARTLIST_FOREACH(mp->transports_to_launch, char *, t, tor_free(t));
    smartlist_clear(mp->transports_to_launch);
  } SMARTLIST_FOREACH_END(mp);

  assert_unconfigured_count_ok();

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
  assert_unconfigured_count_ok();
  SMARTLIST_FOREACH_BEGIN(managed_proxy_list, managed_proxy_t *, mp) {
    if (mp->marked_for_removal) {
      SMARTLIST_DEL_CURRENT(managed_proxy_list, mp);
      managed_proxy_destroy(mp, 1);
    }
  } SMARTLIST_FOREACH_END(mp);
  assert_unconfigured_count_ok();
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
    SMARTLIST_FOREACH(managed_proxy_list, managed_proxy_t *, mp, {
        SMARTLIST_DEL_CURRENT(managed_proxy_list, mp);
        managed_proxy_destroy(mp, 1);
    });

    smartlist_free(managed_proxy_list);
    managed_proxy_list=NULL;
  }
}

