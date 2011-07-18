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

/* ASN TIDY THESE UP*/
static void set_environ(char ***envp, const char *method,
                        int is_server);
static INLINE int proxy_configuration_finished(managed_proxy_t *mp);

static void managed_proxy_destroy(managed_proxy_t *mp,
                                  int also_free_transports);
static void register_proxy_transports(managed_proxy_t *mp);
static void handle_finished_proxy(managed_proxy_t *mp);
static void configure_proxy(managed_proxy_t *mp);

static void parse_method_error(char *line, int is_server_method);
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
/** Number of unconfigured managed proxies. */
static int n_unconfigured_proxies = 0;

/*  The main idea is:

    A managed proxy is represented by a managed_proxy_t struct and can
    spawn multiple transports.

    unconfigured_proxy_list is a list of all the unconfigured managed
    proxies; everytime we spawn a managed proxy we add it in that
    list.
    In every run_scheduled_event() tick, we attempt to configure each
    managed proxy further, using the configuration protocol defined in
    the 180_pluggable_transport.txt proposal.

    When a managed proxy is fully configured, we register all its
    transports to the circuitbuild.c subsystem - like we do with
    external proxies - and then free the managed proxy struct
    since it's no longer needed. */

/** Return true if there are still unconfigured managed proxies. */
int
pt_proxies_configuration_pending(void)
{
  return !!n_unconfigured_proxies;
}

/** Launch a proxy for <b>method</b> using <b>proxy_argv</b> as its
 *  arguments. If <b>is_server</b>, launch a server proxy. */
int
pt_managed_launch_proxy(const char *method,
                        char **proxy_argv, int is_server)
{
  char **envp=NULL;
  int retval;
  FILE *stdout_read = NULL;
  int stdout_pipe=-1, stderr_pipe=-1;

  /* prepare the environment variables for the managed proxy */
  set_environ(&envp, method, is_server);

  /* ASN we should probably check if proxy_argv[0] is executable by our user */
  retval = tor_spawn_background(proxy_argv[0], &stdout_pipe,
                                &stderr_pipe, (const char **)proxy_argv,
                                (const char **)envp);
  if (retval < 0) {
    log_warn(LD_GENERAL, "Spawn failed");
    return -1;
  }

  /* free the memory allocated for the execve() */
  free_execve_args(envp);

  /* Set stdout/stderr pipes to be non-blocking */
  fcntl(stdout_pipe, F_SETFL, O_NONBLOCK);
  /* Open the buffered IO streams */
  stdout_read = fdopen(stdout_pipe, "r");

  log_warn(LD_CONFIG, "The spawn is alive (%d)!", retval);

  /* create a managed proxy */
  managed_proxy_t *mp = tor_malloc(sizeof(managed_proxy_t));
  mp->conf_state = PT_PROTO_INFANT;
  mp->stdout = stdout_read;
  mp->transports = smartlist_create();

  /* register the managed proxy */
  if (!unconfigured_proxy_list)
    unconfigured_proxy_list = smartlist_create();
  smartlist_add(unconfigured_proxy_list, mp);

  n_unconfigured_proxies++; /* ASN should we care about overflows here?
                               I say no. */

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
    if (proxy_configuration_finished(mp)) /* finished managed proxies
                                             shouldn't be here */
      assert(0);

    configure_proxy(mp);

  } SMARTLIST_FOREACH_END(mp);
}

/** Receive input from the managed proxy <b>mp</b> to get closer to
 *  finally configuring it. */
static void
configure_proxy(managed_proxy_t *mp)
{
  enum stream_status r;
  char stdout_buf[200];

  while (1) {
    r = get_string_from_pipe(mp->stdout, stdout_buf,
                             sizeof(stdout_buf) - 1);

    if (r == IO_STREAM_CLOSED || r == IO_STREAM_TERM) {
      log_warn(LD_GENERAL, "Managed proxy stream closed. "
               "Most probably application stopped running");
      mp->conf_state = PT_PROTO_BROKEN;
    } else if (r == IO_STREAM_EAGAIN) {
      return;
    } else {
      tor_assert(r == IO_STREAM_OKAY);
      handle_proxy_line(stdout_buf, mp);
    }

    /* if the proxy finished configuring, exit the loop. */
    if (proxy_configuration_finished(mp)) {
      handle_finished_proxy(mp);
      return;
    }
  }
}

/** Handle a configured or broken managed proxy <b>mp</b>. */
static void
handle_finished_proxy(managed_proxy_t *mp)
{
  switch (mp->conf_state) {
  case PT_PROTO_BROKEN: /* if broken: */
    managed_proxy_destroy(mp, 1); /* destroy it and all its transports */
    break;
  case PT_PROTO_CONFIGURED: /* if configured correctly: */
    register_proxy_transports(mp); /* register all its transports, */
    mp->conf_state = PT_PROTO_COMPLETED; /* mark it as completed, */
    managed_proxy_destroy(mp, 0); /* destroy the managed proxy struct,
                                     keeping the transports intact */
    break;
  default:
    log_warn(LD_CONFIG, "Unfinished managed proxy in "
             "handle_finished_proxy().");
    assert(0);
  }

  n_unconfigured_proxies--;
  tor_assert(n_unconfigured_proxies >= 0);
}

/** Register all the transports supported by managed proxy <b>mp</b>. */
static void
register_proxy_transports(managed_proxy_t *mp)
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

/** Free memory allocated by managed proxy <b>mp</b>.
 * If <b>also_free_transports</b> is set, also free the transports
 * associated with this managed proxy. */
static void
managed_proxy_destroy(managed_proxy_t *mp, int also_free_transports)
{
  /* transport_free() all its transports */
  if (also_free_transports)
    SMARTLIST_FOREACH(mp->transports, transport_t *, t, transport_free(t));

  /* free the transports smartlist */
  smartlist_clear(mp->transports);
  smartlist_free(mp->transports);

  /* remove it from the list of managed proxies */
  smartlist_remove(unconfigured_proxy_list, mp);

  /* close its stdout stream */
  fclose(mp->stdout);

  tor_free(mp);
}

/** Return true if the configuration of the managed proxy <b>mp</b> is
    finished. */
static INLINE int
proxy_configuration_finished(managed_proxy_t *mp)
{
  return (mp->conf_state == PT_PROTO_CONFIGURED ||
          mp->conf_state == PT_PROTO_BROKEN);
}

/** Handle a configuration protocol <b>line</b> received from a
 *  managed proxy <b>mp</b>. */
void
handle_proxy_line(char *line, managed_proxy_t *mp)
{
  printf("Judging line: %s\n", line);

  if (strlen(line) < SMALLEST_MANAGED_LINE_SIZE) {
    log_warn(LD_GENERAL, "Managed proxy configuration line is too small. "
             "Discarding");
    goto err;
  }

  if (!strncmp(line, PROTO_ENV_ERROR, strlen(PROTO_ENV_ERROR))) {
    if (mp->conf_state != PT_PROTO_INFANT)
      goto err;

    parse_env_error(line);
    goto err;
  } else if (!strncmp(line, PROTO_NEG_FAIL, strlen(PROTO_NEG_FAIL))) {
    if (mp->conf_state != PT_PROTO_INFANT)
      goto err;

    log_warn(LD_CONFIG, "Managed proxy could not pick a "
             "configuration protocol version.");
    goto err;
  } else if (!strncmp(line, PROTO_NEG_SUCCESS,
                      strlen(PROTO_NEG_SUCCESS))) {
    if (mp->conf_state != PT_PROTO_INFANT)
      goto err;

    if (parse_version(line,mp) < 0)
      goto err;

    tor_assert(mp->conf_protocol != 0);
    mp->conf_state = PT_PROTO_ACCEPTING_METHODS;
    return;
  } else if (!strncmp(line, PROTO_CMETHODS_DONE,
                      strlen(PROTO_CMETHODS_DONE))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    log_warn(LD_CONFIG, "Client managed proxy configuration completed!");
    mp->conf_state = PT_PROTO_CONFIGURED;
    return;
  } else if (!strncmp(line, PROTO_SMETHODS_DONE,
                      strlen(PROTO_SMETHODS_DONE))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    log_warn(LD_CONFIG, "Server managed proxy configuration completed!");
    mp->conf_state = PT_PROTO_CONFIGURED;
    return;
  } else if (!strncmp(line, PROTO_CMETHOD_ERROR,
                      strlen(PROTO_CMETHOD_ERROR))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    parse_client_method_error(line);
    goto err;
  } else if (!strncmp(line, PROTO_SMETHOD_ERROR,
                      strlen(PROTO_SMETHOD_ERROR))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    parse_server_method_error(line);
    goto err;
  } else if (!strncmp(line, PROTO_CMETHOD, strlen(PROTO_CMETHOD))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    if (parse_cmethod_line(line, mp) < 0)
      goto err;

    return;
  } else if (!strncmp(line, PROTO_SMETHOD, strlen(PROTO_SMETHOD))) {
    if (mp->conf_state != PT_PROTO_ACCEPTING_METHODS)
      goto err;

    if (parse_smethod_line(line, mp) < 0)
      goto err;

    return;
  }

  log_warn(LD_CONFIG, "Unknown line received by managed proxy. (%s)", line);

 err:
  mp->conf_state = PT_PROTO_BROKEN;
  return;
}

/** Parses an ENV-ERROR <b>line</b> and warns the user accordingly. */
void
parse_env_error(char *line)
{
  tor_assert(!strncmp(line, PROTO_ENV_ERROR, strlen(PROTO_ENV_ERROR)));

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
parse_version(char *line, managed_proxy_t *mp)
{
 tor_assert(!strncmp(line, PROTO_NEG_SUCCESS, strlen(PROTO_NEG_SUCCESS)));

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
parse_method_error(char *line, int is_server)
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

/** Parses an SMETHOD <b>line</b>. */
int
parse_smethod_line(char *line, managed_proxy_t *mp)
{
  int r;
  smartlist_t *items = NULL;

  char *method_name=NULL;

  char *addrport=NULL;
  tor_addr_t addr;
  uint16_t port = 0;

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
parse_cmethod_line(char *line, managed_proxy_t *mp)
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

/** Prepares the <b>envp</b> of a pluggable transport managed proxy
 *
 *  <b>method</b> is a line with transport methods to be launched.
 *  If <b>is_server</b> is set, prepare a server proxy <b>envp</b>. */
static void
set_environ(char ***envp, const char *method, int is_server)
{
  or_options_t *options = get_options();
  char **tmp=NULL;
  char *state_loc=NULL;

  int n_envs = is_server ? ENVIRON_SIZE_SERVER : ENVIRON_SIZE_CLIENT;

  /* allocate enough space for our env. vars and a NULL pointer */
  *envp = tor_malloc(sizeof(char*)*(n_envs+1));
  tmp = *envp;

  /* these should all be customizable */
  tor_asprintf(tmp++, "HOME=%s", getenv("HOME"));
  tor_asprintf(tmp++, "PATH=%s", getenv("PATH"));
  state_loc = get_datadir_fname("pt_state/");
  tor_asprintf(tmp++, "TOR_PT_STATE_LOCATION=%s", state_loc);
  tor_free(state_loc);
  tor_asprintf(tmp++, "TOR_PT_MANAGED_TRANSPORT_VER=1"); /* temp */
  if (is_server) {
    /* ASN check for ORPort values, should we be here if it's 0? */
    tor_asprintf(tmp++, "TOR_PT_ORPORT=127.0.0.1:%d", options->ORPort); /* temp */
    tor_asprintf(tmp++, "TOR_PT_SERVER_BINDADDR=127.0.0.1:0");
    tor_asprintf(tmp++, "TOR_PT_SERVER_TRANSPORTS=%s", method);
    tor_asprintf(tmp++, "TOR_PT_EXTENDED_SERVER_PORT=127.0.0.1:4200"); /* temp*/
  } else {
    tor_asprintf(tmp++, "TOR_PT_CLIENT_TRANSPORTS=%s", method);
  }
  *tmp = NULL;
}

/* ASN is this too ugly/stupid? */
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
        managed_proxy_destroy(mp,0);
      else
        managed_proxy_destroy(mp,1);
    } SMARTLIST_FOREACH_END(mp);

    smartlist_clear(unconfigured_proxy_list);
    smartlist_free(unconfigured_proxy_list);
    unconfigured_proxy_list=NULL;
  }
}

