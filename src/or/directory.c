/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2005 Roger Dingledine, Nick Mathewson. */
/* See LICENSE for licensing information */
/* $Id$ */
const char directory_c_id[] =
  "$Id$";

#include "or.h"

/**
 * \file directory.c
 * \brief Code to send and fetch directories and router
 * descriptors via HTTP.  Directories use dirserv.c to generate the
 * results; clients use routers.c to parse them.
 **/

/* In-points to directory.c:
 *
 * - directory_post_to_dirservers(), called from
 *   router_upload_dir_desc_to_dirservers() in router.c
 *   upload_service_descriptor() in rendservice.c
 * - directory_get_from_dirserver(), called from
 *   rend_client_refetch_renddesc() in rendclient.c
 *   run_scheduled_events() in main.c
 *   do_hup() in main.c
 * - connection_dir_process_inbuf(), called from
 *   connection_process_inbuf() in connection.c
 * - connection_dir_finished_flushing(), called from
 *   connection_finished_flushing() in connection.c
 * - connection_dir_finished_connecting(), called from
 *   connection_finished_connecting() in connection.c
 */
static void
directory_initiate_command_trusted_dir(trusted_dir_server_t *dirserv,
                                      uint8_t purpose, int private_connection,
                                      const char *resource,
                                      const char *payload, size_t payload_len);
static void
directory_initiate_command(const char *address, uint32_t addr, uint16_t port,
                           const char *platform,
                           const char *digest, uint8_t purpose,
                           int private_connection, const char *resource,
                           const char *payload, size_t payload_len);

static void
directory_send_command(connection_t *conn, const char *platform,
                       int purpose, const char *resource,
                       const char *payload, size_t payload_len);
static int directory_handle_command(connection_t *conn);
static int body_is_plausible(const char *body, size_t body_len, int purpose);
static int purpose_is_private(uint8_t purpose);
static char *http_get_header(const char *headers, const char *which);
static char *http_get_origin(const char *headers, connection_t *conn);
static void connection_dir_download_networkstatus_failed(connection_t *conn);
static void connection_dir_download_routerdesc_failed(connection_t *conn);
static void dir_networkstatus_download_failed(smartlist_t *failed);
static void dir_routerdesc_download_failed(smartlist_t *failed);

/********* START VARIABLES **********/

static addr_policy_t *dir_policy = NULL;

#define ALLOW_DIRECTORY_TIME_SKEW 30*60 /* 30 minutes */

/********* END VARIABLES ************/

/** Parse get_options()-&gt;DirPolicy, and put the processed version in
 * &dir_policy.  Ignore port specifiers.
 */
void
parse_dir_policy(void)
{
  addr_policy_t *n;
  if (dir_policy) {
    addr_policy_free(dir_policy);
    dir_policy = NULL;
  }
  config_parse_addr_policy(get_options()->DirPolicy, &dir_policy, -1);
  /* ports aren't used. */
  for (n=dir_policy; n; n = n->next) {
    n->prt_min = 1;
    n->prt_max = 65535;
  }
}

/** Free storage used to hold parsed directory policy */
void
free_dir_policy(void)
{
  addr_policy_free(dir_policy);
  dir_policy = NULL;
}

/** Return 1 if <b>addr</b> is permitted to connect to our dir port,
 * based on <b>dir_policy</b>. Else return 0.
 */
int
dir_policy_permits_address(uint32_t addr)
{
  int a;

  if (!dir_policy) /* 'no dir policy' means 'accept' */
    return 1;
  a = router_compare_addr_to_addr_policy(addr, 1, dir_policy);
  if (a==ADDR_POLICY_REJECTED)
    return 0;
  else if (a==ADDR_POLICY_ACCEPTED)
    return 1;
  warn(LD_BUG, "Bug: got unexpected 'maybe' answer from dir policy");
  return 0;
}

/** Return true iff the directory purpose 'purpose' must use an
 * anonymous connection to a directory. */
static int
purpose_is_private(uint8_t purpose)
{
  if (purpose == DIR_PURPOSE_FETCH_DIR ||
      purpose == DIR_PURPOSE_UPLOAD_DIR ||
      purpose == DIR_PURPOSE_FETCH_RUNNING_LIST ||
      purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS ||
      purpose == DIR_PURPOSE_FETCH_SERVERDESC)
    return 0;
  return 1;
}

/** Start a connection to every known directory server, using
 * connection purpose 'purpose' and uploading the payload 'payload'
 * (length 'payload_len').  The purpose should be one of
 * 'DIR_PURPOSE_UPLOAD_DIR' or 'DIR_PURPOSE_UPLOAD_RENDDESC'.
 */
void
directory_post_to_dirservers(uint8_t purpose, const char *payload,
                             size_t payload_len)
{
  smartlist_t *dirservers;
  int post_via_tor;

  router_get_trusted_dir_servers(&dirservers);
  tor_assert(dirservers);
  /* This tries dirservers which we believe to be down, but ultimately, that's
   * harmless, and we may as well err on the side of getting things uploaded.
   */
  SMARTLIST_FOREACH(dirservers, trusted_dir_server_t *, ds,
    {
      post_via_tor = purpose_is_private(purpose) ||
                     !fascist_firewall_allows_address(ds->addr,ds->dir_port);
      directory_initiate_command_trusted_dir(ds, purpose, post_via_tor,
                                             NULL, payload, payload_len);
    });
}

/** Start a connection to a random running directory server, using
 * connection purpose 'purpose' and requesting 'resource'.
 * If <b>retry_if_no_servers</b>, then if all the possible servers seem
 * down, mark them up and try again.
 */
void
directory_get_from_dirserver(uint8_t purpose, const char *resource,
                             int retry_if_no_servers)
{
  routerinfo_t *r = NULL;
  trusted_dir_server_t *ds = NULL;
  or_options_t *options = get_options();
  int fetch_fresh_first = server_mode(options) && options->DirPort != 0;
  int directconn = !purpose_is_private(purpose);

  int need_v1_support = purpose == DIR_PURPOSE_FETCH_DIR ||
                        purpose == DIR_PURPOSE_FETCH_RUNNING_LIST;
  int need_v2_support = purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS ||
                        purpose == DIR_PURPOSE_FETCH_SERVERDESC;

  if (directconn) {
    if (fetch_fresh_first && purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS &&
        !strcmpstart(resource,"fp/") && strlen(resource) == HEX_DIGEST_LEN+3) {
      /* Try to ask the actual dirserver its opinion. */
      char digest[DIGEST_LEN];
      base16_decode(digest, DIGEST_LEN, resource+3, HEX_DIGEST_LEN);
      ds = router_get_trusteddirserver_by_digest(digest);
    }
    if (!ds && fetch_fresh_first) {
      /* only ask authdirservers, and don't ask myself */
      ds = router_pick_trusteddirserver(need_v1_support, 1, 1,
                                        retry_if_no_servers);
    }
    if (!ds) {
      /* anybody with a non-zero dirport will do */
      r = router_pick_directory_server(1, 1, need_v2_support,
                                       retry_if_no_servers);
      if (!r) {
        const char *which;
        if (purpose == DIR_PURPOSE_FETCH_DIR)
          which = "directory";
        else if (purpose == DIR_PURPOSE_FETCH_RUNNING_LIST)
          which = "status list";
        else if (purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS)
          which = "network status";
        else // if (purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS)
          which = "server descriptors";
        info(LD_DIR,
             "No router found for %s; falling back to dirserver list", which);
        ds = router_pick_trusteddirserver(1, 1, 1,
                                          retry_if_no_servers);
        if (!ds)
          directconn = 0; /* last resort: try routing it via Tor */
      }
    }
  }
  if (!directconn) {
    /* Never use fascistfirewall; we're going via Tor. */
    if (purpose == DIR_PURPOSE_FETCH_RENDDESC) {
      /* only ask authdirservers, any of them will do */
      ds = router_pick_trusteddirserver(0, 0, 0, retry_if_no_servers);
    } else {
      /* anybody with a non-zero dirport will do. Disregard firewalls. */
      r = router_pick_directory_server(1, 0, need_v2_support,
                                       retry_if_no_servers);
    }
  }

  if (r)
    directory_initiate_command_router(r, purpose, !directconn,
                                      resource, NULL, 0);
  else if (ds)
    directory_initiate_command_trusted_dir(ds, purpose, !directconn,
                                           resource, NULL, 0);
  else {
    notice(LD_DIR,
           "No running dirservers known. Will try again later. (purpose %d)",
           purpose);
    if (!purpose_is_private(purpose)) {
      /* remember we tried them all and failed. */
      directory_all_unreachable(time(NULL));
    }
  }
}

/** Launch a new connection to the directory server <b>router</b> to upload or
 * download a service or rendezvous descriptor. <b>purpose</b> determines what
 * kind of directory connection we're launching, and must be one of
 * DIR_PURPOSE_{FETCH|UPLOAD}_{DIR|RENDDESC}.
 *
 * When uploading, <b>payload</b> and <b>payload_len</b> determine the content
 * of the HTTP post.  Otherwise, <b>payload</b> should be NULL.
 *
 * When fetching a rendezvous descriptor, <b>resource</b> is the service ID we
 * want to fetch.
 */
void
directory_initiate_command_router(routerinfo_t *router, uint8_t purpose,
                                  int private_connection, const char *resource,
                                  const char *payload, size_t payload_len)
{
  directory_initiate_command(router->address, router->addr, router->dir_port,
                         router->platform, router->cache_info.identity_digest,
                         purpose, private_connection, resource,
                         payload, payload_len);
}

/** As directory_initiate_command_router, but send the command to a trusted
 * directory server <b>dirserv</b>. **/
static void
directory_initiate_command_trusted_dir(trusted_dir_server_t *dirserv,
                                       uint8_t purpose, int private_connection,
                                       const char *resource,
                                       const char *payload, size_t payload_len)
{
  directory_initiate_command(dirserv->address, dirserv->addr,
               dirserv->dir_port, NULL, dirserv->digest, purpose,
               private_connection, resource,
               payload, payload_len);
}

/** Called when we are unable to complete the client's request to a
 * directory server: Mark the router as down and try again if possible.
 */
void
connection_dir_request_failed(connection_t *conn)
{
  if (router_digest_is_me(conn->identity_digest))
    return; /* this was a test fetch. don't retry. */
  router_mark_as_down(conn->identity_digest); /* don't try him again */
  if (conn->purpose == DIR_PURPOSE_FETCH_DIR ||
      conn->purpose == DIR_PURPOSE_FETCH_RUNNING_LIST) {
    info(LD_DIR, "Giving up on directory server at '%s:%d'; retrying",
         conn->address, conn->port);
    directory_get_from_dirserver(conn->purpose, NULL,
                                 0 /* don't retry_if_no_servers */);
  } else if (conn->purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS) {
    info(LD_DIR, "Giving up on directory server at '%s'; retrying",
         conn->address);
    connection_dir_download_networkstatus_failed(conn);
  } else if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC) {
    info(LD_DIR, "Giving up on directory server at '%s'; retrying",
         conn->address);
    connection_dir_download_routerdesc_failed(conn);
  }
}

/** Called when an attempt to download one or more network status
 * documents on connection <b>conn</b> failed. Decide whether to
 * retry the fetch now, later, or never.
 */
static void
connection_dir_download_networkstatus_failed(connection_t *conn)
{
  if (!conn->requested_resource) {
    /* We never reached directory_send_command, which means that we never
     * opened a network connection.  Either we're out of sockets, or the
     * network is down.  Either way, retrying would be pointless. */
    return;
  }
  if (!strcmpstart(conn->requested_resource, "all")) {
    /* We're a non-authoritative directory cache; try again. */
    directory_get_from_dirserver(conn->purpose, "all.z",
                                 0 /* don't retry_if_no_servers */);
  } else if (!strcmpstart(conn->requested_resource, "fp/")) {
    /* We were trying to download by fingerprint; mark them all has having
     * failed, and possibly retry them later.*/
    smartlist_t *failed = smartlist_create();
    dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                         failed, NULL, 0);
    if (smartlist_len(failed)) {
      dir_networkstatus_download_failed(failed);
      SMARTLIST_FOREACH(failed, char *, cp, tor_free(cp));
    }
    smartlist_free(failed);
  }
}

/** Called when an attempt to download one or more router descriptors
 * on connection <b>conn</b> failed.
 */
static void
connection_dir_download_routerdesc_failed(connection_t *conn)
{
  /* Try again. No need to increment the failure count for routerdescs, since
   * it's not their fault.*/
  /* update_router_descriptor_downloads(time(NULL)); */
}

/** Helper for directory_initiate_command_(router|trusted_dir): send the
 * command to a server whose address is <b>address</b>, whose IP is
 * <b>addr</b>, whose directory port is <b>dir_port</b>, whose tor version is
 * <b>platform</b>, and whose identity key digest is <b>digest</b>. The
 * <b>platform</b> argument is optional; the others are required. */
static void
directory_initiate_command(const char *address, uint32_t addr,
                           uint16_t dir_port, const char *platform,
                           const char *digest, uint8_t purpose,
                           int private_connection, const char *resource,
                           const char *payload, size_t payload_len)
{
  connection_t *conn;

  tor_assert(address);
  tor_assert(addr);
  tor_assert(dir_port);
  tor_assert(digest);

  switch (purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      debug(LD_DIR,"initiating directory fetch");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      debug(LD_DIR,"initiating hidden-service descriptor fetch");
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      debug(LD_OR,"initiating server descriptor upload");
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      debug(LD_REND,"initiating hidden-service descriptor upload");
      break;
    case DIR_PURPOSE_FETCH_RUNNING_LIST:
      debug(LD_DIR,"initiating running-routers fetch");
      break;
    case DIR_PURPOSE_FETCH_NETWORKSTATUS:
      debug(LD_DIR,"initiating network-status fetch");
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      debug(LD_DIR,"initiating server descriptor fetch");
      break;
    default:
      err(LD_BUG, "Unrecognized directory connection purpose.");
      tor_assert(0);
  }

  conn = connection_new(CONN_TYPE_DIR);

  /* set up conn so it's got all the data we need to remember */
  conn->addr = addr;
  conn->port = dir_port;
  conn->address = tor_strdup(address);
  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  conn->purpose = purpose;

  /* give it an initial state */
  conn->state = DIR_CONN_STATE_CONNECTING;

  if (!private_connection) {
    /* then we want to connect directly */

    if (get_options()->HttpProxy) {
      addr = get_options()->HttpProxyAddr;
      dir_port = get_options()->HttpProxyPort;
    }

    switch (connection_connect(conn, conn->address, addr, dir_port)) {
      case -1:
        connection_dir_request_failed(conn); /* retry if we want */
        connection_free(conn);
        return;
      case 1:
        conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
        /* fall through */
      case 0:
        /* queue the command on the outbuf */
        directory_send_command(conn, platform, purpose, resource,
                               payload, payload_len);
        connection_watch_events(conn, EV_READ | EV_WRITE);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via tor */
    /* make an AP connection
     * populate it and add it at the right state
     * socketpair and hook up both sides
     */
    conn->s = connection_ap_make_bridge(conn->address, conn->port);
    if (conn->s < 0) {
      warn(LD_NET,"Making AP bridge to dirserver failed.");
      connection_mark_for_close(conn);
      return;
    }

    conn->state = DIR_CONN_STATE_CLIENT_SENDING;
    connection_add(conn);
    /* queue the command on the outbuf */
    directory_send_command(conn, platform, purpose, resource,
                           payload, payload_len);
    connection_watch_events(conn, EV_READ | EV_WRITE);
  }
}

/** Queue an appropriate HTTP command on conn-\>outbuf.  The other args
 * are as in directory_initiate_command.
 */
static void
directory_send_command(connection_t *conn, const char *platform,
                       int purpose, const char *resource,
                       const char *payload, size_t payload_len)
{
  char proxystring[256];
  char proxyauthstring[256];
  char hoststring[128];
  char *url;
  char request[8192];
  const char *httpcommand = NULL;
  size_t len;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DIR);

  tor_free(conn->requested_resource);
  if (resource)
    conn->requested_resource = tor_strdup(resource);

  /* come up with a string for which Host: we want */
  if (conn->port == 80) {
    strlcpy(hoststring, conn->address, sizeof(hoststring));
  } else {
    tor_snprintf(hoststring, sizeof(hoststring),"%s:%d",
                 conn->address, conn->port);
  }

  /* come up with some proxy lines, if we're using one. */
  if (get_options()->HttpProxy) {
    char *base64_authenticator=NULL;
    const char *authenticator = get_options()->HttpProxyAuthenticator;

    tor_snprintf(proxystring, sizeof(proxystring),"http://%s", hoststring);
    if (authenticator) {
      base64_authenticator = alloc_http_authenticator(authenticator);
      if (!base64_authenticator)
        warn(LD_BUG, "Encoding http authenticator failed");
    }
    if (base64_authenticator) {
      tor_snprintf(proxyauthstring, sizeof(proxyauthstring),
                   "\r\nProxy-Authorization: Basic %s",
                   base64_authenticator);
      tor_free(base64_authenticator);
    } else {
      proxyauthstring[0] = 0;
    }
  } else {
    proxystring[0] = 0;
    proxyauthstring[0] = 0;
  }

  switch (purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      tor_assert(!resource);
      tor_assert(!payload);
      debug(LD_DIR, "Asking for compressed directory from server running %s",
            platform?platform:"<unknown version>");
      httpcommand = "GET";
      url = tor_strdup("/tor/dir.z");
      break;
    case DIR_PURPOSE_FETCH_RUNNING_LIST:
      tor_assert(!resource);
      tor_assert(!payload);
      httpcommand = "GET";
      url = tor_strdup("/tor/running-routers");
      break;
    case DIR_PURPOSE_FETCH_NETWORKSTATUS:
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/status/%s", resource);
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      httpcommand = "GET";
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/server/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      tor_assert(resource);
      tor_assert(!payload);

      /* this must be true or we wouldn't be doing the lookup */
      tor_assert(strlen(resource) <= REND_SERVICE_ID_LEN);
      /* This breaks the function abstraction. */
      strlcpy(conn->rend_query, resource, sizeof(conn->rend_query));

      httpcommand = "GET";
      /* Request the most recent versioned descriptor. */
      // XXXX011
      //tor_snprintf(url, sizeof(url), "/tor/rendezvous1/%s", resource);
      len = strlen(resource)+32;
      url = tor_malloc(len);
      tor_snprintf(url, len, "/tor/rendezvous/%s", resource);
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      tor_assert(!resource);
      tor_assert(payload);
      httpcommand = "POST";
      url = tor_strdup("/tor/rendezvous/publish");
      break;
    default:
      tor_assert(0);
      return;
  }
  tor_snprintf(request, sizeof(request), "%s %s", httpcommand, proxystring);
  connection_write_to_buf(request, strlen(request), conn);
  connection_write_to_buf(url, strlen(url), conn);
  tor_free(url);

  tor_snprintf(request, sizeof(request),
               " HTTP/1.0\r\nContent-Length: %lu\r\nHost: %s%s\r\n\r\n",
           payload ? (unsigned long)payload_len : 0,
           hoststring,
           proxyauthstring);
  connection_write_to_buf(request, strlen(request), conn);

  if (payload) {
    /* then send the payload afterwards too */
    connection_write_to_buf(payload, payload_len, conn);
  }
}

/** Parse an HTTP request string <b>headers</b> of the form
 * \verbatim
 * "\%s [http[s]://]\%s HTTP/1..."
 * \endverbatim
 * If it's well-formed, strdup the second \%s into *<b>url</b>, and
 * null-terminate it. If the url doesn't start with "/tor/", rewrite it
 * so it does. Return 0.
 * Otherwise, return -1.
 */
static int
parse_http_url(char *headers, char **url)
{
  char *s, *start, *tmp;

  s = (char *)eat_whitespace_no_nl(headers);
  if (!*s) return -1;
  s = (char *)find_whitespace(s); /* get past GET/POST */
  if (!*s) return -1;
  s = (char *)eat_whitespace_no_nl(s);
  if (!*s) return -1;
  start = s; /* this is it, assuming it's valid */
  s = (char *)find_whitespace(start);
  if (!*s) return -1;

  /* tolerate the http[s] proxy style of putting the hostname in the url */
  if (s-start >= 4 && !strcmpstart(start,"http")) {
    tmp = start + 4;
    if (*tmp == 's')
      tmp++;
    if (s-tmp >= 3 && !strcmpstart(tmp,"://")) {
      tmp = strchr(tmp+3, '/');
      if (tmp && tmp < s) {
        debug(LD_DIR,"Skipping over 'http[s]://hostname' string");
        start = tmp;
      }
    }
  }

  if (s-start < 5 || strcmpstart(start,"/tor/")) { /* need to rewrite it */
    *url = tor_malloc(s - start + 5);
    strlcpy(*url,"/tor", s-start+5);
    strlcat((*url)+4, start, s-start+1);
  } else {
    *url = tor_strndup(start, s-start);
  }
  return 0;
}

/** Return a copy of the first HTTP header in <b>headers</b> whose key is
 * <b>which</b>.  The key should be given with a terminating colon and space;
 * this function copies everything after, up to but not including the
 * following \\r\\n. */
static char *
http_get_header(const char *headers, const char *which)
{
  const char *cp = headers;
  while (cp) {
    if (!strcmpstart(cp, which)) {
      char *eos;
      cp += strlen(which);
      if ((eos = strchr(cp,'\r')))
        return tor_strndup(cp, eos-cp);
      else
        return tor_strdup(cp);
    }
    cp = strchr(cp, '\n');
    if (cp)
      ++cp;
  }
  return NULL;
}

/** Allocate and return a string describing the source of an HTTP request with
 * headers <b>headers</b> received on <b>conn</b>.  The format is either
 * "'1.2.3.4'", or "'1.2.3.4' (forwarded for '5.6.7.8')".
 */
static char *
http_get_origin(const char *headers, connection_t *conn)
{
  char *fwd;

  fwd = http_get_header(headers, "Forwarded-For: ");
  if (!fwd)
    fwd = http_get_header(headers, "X-Forwarded-For: ");
  if (fwd) {
    size_t len = strlen(fwd)+strlen(conn->address)+32;
    char *result = tor_malloc(len);
    tor_snprintf(result, len, "'%s' (forwarded for '%s')", conn->address, fwd);
    tor_free(fwd);
    return result;
  } else {
    size_t len = strlen(conn->address)+3;
    char *result = tor_malloc(len);
    tor_snprintf(result, len, "'%s'", conn->address);
    return result;
  }
}

/** Parse an HTTP response string <b>headers</b> of the form
 * \verbatim
 * "HTTP/1.\%d \%d\%s\r\n...".
 * \endverbatim
 *
 * If it's well-formed, assign the status code to *<b>code</b> and
 * return 0.  Otherwise, return -1.
 *
 * On success: If <b>date</b> is provided, set *date to the Date
 * header in the http headers, or 0 if no such header is found.  If
 * <b>compression</b> is provided, set *<b>compression</b> to the
 * compression method given in the Content-Encoding header, or 0 if no
 * such header is found, or -1 if the value of the header is not
 * recognized.  If <b>reason</b> is provided, strdup the reason string
 * into it.
 */
int
parse_http_response(const char *headers, int *code, time_t *date,
                    int *compression, char **reason)
{
  int n1, n2;
  char datestr[RFC1123_TIME_LEN+1];
  smartlist_t *parsed_headers;
  tor_assert(headers);
  tor_assert(code);

  while (TOR_ISSPACE(*headers)) headers++; /* tolerate leading whitespace */

  if (sscanf(headers, "HTTP/1.%d %d", &n1, &n2) < 2 ||
      (n1 != 0 && n1 != 1) ||
      (n2 < 100 || n2 >= 600)) {
    warn(LD_HTTP,"Failed to parse header '%s'",headers);
    return -1;
  }
  *code = n2;

  parsed_headers = smartlist_create();
  smartlist_split_string(parsed_headers, headers, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
  if (reason) {
    smartlist_t *status_line_elements = smartlist_create();
    tor_assert(smartlist_len(parsed_headers));
    smartlist_split_string(status_line_elements,
                           smartlist_get(parsed_headers, 0),
                           " ", SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, 3);
    tor_assert(smartlist_len(status_line_elements) <= 3);
    if (smartlist_len(status_line_elements) == 3) {
      *reason = smartlist_get(status_line_elements, 2);
      smartlist_set(status_line_elements, 2, NULL); /* Prevent free */
    }
    SMARTLIST_FOREACH(status_line_elements, char *, cp, tor_free(cp));
    smartlist_free(status_line_elements);
  }
  if (date) {
    *date = 0;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Date: ")) {
        strlcpy(datestr, s+6, sizeof(datestr));
        /* This will do nothing on failure, so we don't need to check
           the result.   We shouldn't warn, since there are many other valid
           date formats besides the one we use. */
        parse_rfc1123_time(datestr, date);
        break;
      });
  }
  if (compression) {
    const char *enc = NULL;
    SMARTLIST_FOREACH(parsed_headers, const char *, s,
      if (!strcmpstart(s, "Content-Encoding: ")) {
        enc = s+18; break;
      });
    if (!enc || !strcmp(enc, "identity")) {
      *compression = 0;
    } else if (!strcmp(enc, "deflate") || !strcmp(enc, "x-deflate")) {
      *compression = ZLIB_METHOD;
    } else if (!strcmp(enc, "gzip") || !strcmp(enc, "x-gzip")) {
      *compression = GZIP_METHOD;
    } else {
      info(LD_HTTP, "Unrecognized content encoding: '%s'. Trying to deal.",
           enc);
      *compression = -1;
    }
  }
  SMARTLIST_FOREACH(parsed_headers, char *, s, tor_free(s));
  smartlist_free(parsed_headers);

  return 0;
}

/** Return true iff <b>body</b> doesn't start with a plausible router or
 * running-list or directory opening.  This is a sign of possible compression.
 **/
static int
body_is_plausible(const char *body, size_t len, int purpose)
{
  int i;
  if (len == 0)
    return 1; /* empty bodies don't need decompression */
  if (len < 32)
    return 0;
  if (purpose != DIR_PURPOSE_FETCH_RENDDESC) {
    if (!strcmpstart(body,"router") ||
        !strcmpstart(body,"signed-directory") ||
        !strcmpstart(body,"network-status") ||
        !strcmpstart(body,"running-routers"))
    return 1;
    for (i=0;i<32;++i) {
      if (!TOR_ISPRINT(body[i]) && !TOR_ISSPACE(body[i]))
        return 0;
    }
    return 1;
  } else {
    return 1;
  }
}

/** We are a client, and we've finished reading the server's
 * response. Parse and it and act appropriately.
 *
 * If we're happy with the result (we get it and it's useful),
 * return 0. Otherwise return -1, and the caller should consider
 * trying the request again.
 *
 * The caller will take care of marking the connection for close.
 */
static int
connection_dir_client_reached_eof(connection_t *conn)
{
  char *body;
  char *headers;
  char *reason = NULL;
  size_t body_len=0;
  int status_code;
  time_t now, date_header=0;
  int delta;
  int compression;
  int plausible;
  int skewed=0;
  int allow_partial = conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC;

  switch (fetch_from_buf_http(conn->inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_DIR_SIZE,
                              allow_partial)) {
    case -1: /* overflow */
      warn(LD_PROTOCOL,"'fetch' response too large (server '%s:%d'). Closing.",
           conn->address, conn->port);
      return -1;
    case 0:
      info(LD_HTTP,
           "'fetch' response not all here, but we're at eof. Closing.");
      return -1;
    /* case 1, fall through */
  }

  if (parse_http_response(headers, &status_code, &date_header,
                          &compression, &reason) < 0) {
    warn(LD_HTTP,"Unparseable headers (server '%s:%d'). Closing.",
         conn->address, conn->port);
    tor_free(body); tor_free(headers);
    return -1;
  }
  if (!reason) reason = tor_strdup("[no reason given]");

  debug(LD_DIR,
        "Received response from directory server '%s:%d': %d \"%s\"",
        conn->address, conn->port, status_code, reason);

  if (date_header > 0) {
    now = time(NULL);
    delta = now-date_header;
    if (abs(delta)>ALLOW_DIRECTORY_TIME_SKEW) {
      log_fn(router_digest_is_trusted_dir(conn->identity_digest) ?
                                                        LOG_WARN : LOG_INFO,
             LD_HTTP,
             "Received directory with skewed time (server '%s:%d'): "
             "we are %d minutes %s, or the directory is %d minutes %s.",
             conn->address, conn->port,
             abs(delta)/60, delta>0 ? "ahead" : "behind",
             abs(delta)/60, delta>0 ? "behind" : "ahead");
      skewed = 1; /* don't check the recommended-versions line */
    } else {
      debug(LD_HTTP, "Time on received directory is within tolerance; "
            "we are %d seconds skewed.  (That's okay.)", delta);
    }
  }

  plausible = body_is_plausible(body, body_len, conn->purpose);
  if (compression || !plausible) {
    char *new_body = NULL;
    size_t new_len = 0;
    int guessed = detect_compression_method(body, body_len);
    if (compression <= 0 || guessed != compression) {
      /* Tell the user if we don't believe what we're told about compression.*/
      const char *description1, *description2;
      if (compression == ZLIB_METHOD)
        description1 = "as deflated";
      else if (compression == GZIP_METHOD)
        description1 = "as gzipped";
      else if (compression == 0)
        description1 = "as uncompressed";
      else
        description1 = "with an unknown Content-Encoding";
      if (guessed == ZLIB_METHOD)
        description2 = "deflated";
      else if (guessed == GZIP_METHOD)
        description2 = "gzipped";
      else if (!plausible)
        description2 = "confusing binary junk";
      else
        description2 = "uncompressed";

      info(LD_HTTP, "HTTP body from server '%s:%d' was labeled %s, "
           "but it seems to be %s.%s",
           conn->address, conn->port, description1, description2,
           (compression>0 && guessed>0)?"  Trying both.":"");
    }
    /* Try declared compression first if we can. */
    if (compression > 0)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, compression,
                          allow_partial);
    /* Okay, if that didn't work, and we think that it was compressed
     * differently, try that. */
    if (!new_body && guessed > 0 && compression != guessed)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, guessed,
                          allow_partial);
    /* If we're pretty sure that we have a compressed directory, and
     * we didn't manage to uncompress it, then warn and bail. */
    if (!plausible && !new_body) {
      warn(LD_HTTP, "Unable to decompress HTTP body (server '%s:%d').",
           conn->address, conn->port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (new_body) {
      tor_free(body);
      body = new_body;
      body_len = new_len;
    }
  }

  if (conn->purpose == DIR_PURPOSE_FETCH_DIR) {
    /* fetch/process the directory to learn about new routers. */
    info(LD_DIR,"Received directory (size %d) from server '%s:%d'",
         (int)body_len, conn->address, conn->port);
    if (status_code == 503 || body_len == 0) {
      info(LD_DIR,"Empty directory; status %d (\"%s\") Ignoring.",
           status_code, reason);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (status_code != 200) {
      warn(LD_DIR,"Received http status code %d (\"%s\") from server "
           "'%s:%d'. I'll try again soon.",
           status_code, reason, conn->address, conn->port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (router_parse_directory(body) < 0) {
      notice(LD_DIR,"I failed to parse the directory I fetched from "
             "'%s:%d'. Ignoring.", conn->address, conn->port);
    }
  }

  if (conn->purpose == DIR_PURPOSE_FETCH_RUNNING_LIST) {
    /* just update our list of running routers, if this list is new info */
    info(LD_DIR,"Received running-routers list (size %d)", (int)body_len);
    if (status_code != 200) {
      warn(LD_DIR,"Received http status code %d (\"%s\") from server "
           "'%s:%d'. I'll try again soon.",
           status_code, reason, conn->address, conn->port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (router_parse_runningrouters(body)<0) {
      warn(LD_DIR,"Bad running-routers from server '%s:%d'. I'll try again "
           "soon.",
           conn->address, conn->port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
  }

  if (conn->purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS) {
    smartlist_t *which = NULL;
    char *cp;
    info(LD_DIR,"Received networkstatus objects (size %d) from server "
         "'%s:%d'",(int) body_len, conn->address, conn->port);
    if (status_code != 200) {
      warn(LD_DIR,"Received http status code %d (\"%s\") from server "
           "'%s:%d' while fetching \"/tor/status/%s\". I'll try again soon.",
           status_code, reason, conn->address, conn->port,
           conn->requested_resource);
      tor_free(body); tor_free(headers); tor_free(reason);
      connection_dir_download_networkstatus_failed(conn);
      return -1;
    }
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"fp/")) {
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                           which, NULL, 0);
    }
    cp = body;
    while (*cp) {
      char *next = strstr(cp, "\nnetwork-status-version");
      if (next)
        next[1] = '\0';
      /* learn from it, and then remove it from 'which' */
      if (router_set_networkstatus(cp, time(NULL), NS_FROM_DIR, which)<0)
        break;
      if (next) {
        next[1] = 'n';
        cp = next+1;
      }
      else
        break;
    }
    routers_update_all_from_networkstatus(); /*launches router downloads*/
    directory_info_has_arrived(time(NULL), 0);
    if (which) {
      if (smartlist_len(which)) {
        dir_networkstatus_download_failed(which);
      }
      SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
      smartlist_free(which);
    }
  }

  if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC) {
    smartlist_t *which = NULL;
    int n_asked_for = 0;
    info(LD_DIR,"Received server info (size %d) from server '%s:%d'",
         (int)body_len, conn->address, conn->port);
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"fp/")) {
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                           which, NULL, 0);
      n_asked_for = smartlist_len(which);
    }
    if (status_code != 200) {
      int no_warn = status_code == 404 ||
        (status_code == 400 && !strcmp(reason, "Servers unavailable."));
      /* 404 means that it didn't have them; no big deal.
       * Older (pre-0.1.1.8) servers said 400 Servers unavailable instead. */
      log_fn(no_warn ? LOG_INFO : LOG_WARN, LD_DIR,
             "Received http status code %d (\"%s\") from server '%s:%d' "
             "while fetching \"/tor/server/%s\". I'll try again soon.",
             status_code, reason, conn->address, conn->port,
             conn->requested_resource);
      if (!which) {
        connection_dir_download_routerdesc_failed(conn);
      } else {
        dir_routerdesc_download_failed(which);
        SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
        smartlist_free(which);
      }
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    /* Learn the routers, assuming we requested by fingerprint or "all".
     * Right now, we only use "authority" to fetch ourself, so we don't want
     * to risk replacing ourself with a router running at the addr:port we
     * think we have.
     */
    if (which || (conn->requested_resource &&
                  !strcmpstart(conn->requested_resource, "all"))) {
      /* as we learn from them, we remove them from 'which' */
      router_load_routers_from_string(body, 0, which);
      directory_info_has_arrived(time(NULL), 0);
    }
    if (which) { /* mark remaining ones as failed */
      info(LD_DIR, "Received %d/%d routers requested from %s:%d",
           n_asked_for-smartlist_len(which), n_asked_for,
           conn->address, (int)conn->port);
      if (smartlist_len(which)) {
        dir_routerdesc_download_failed(which);
      }
      SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
      smartlist_free(which);
    }
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"authority")) {
      /* this might have been a dirport reachability test. see if it is. */
      routerinfo_t *me = router_get_my_routerinfo();
      if (me &&
          router_digest_is_me(conn->identity_digest) &&
          me->addr == conn->addr &&
          me->dir_port == conn->port)
        router_dirport_found_reachable();
    }
  }

  if (conn->purpose == DIR_PURPOSE_UPLOAD_DIR) {
    switch (status_code) {
      case 200:
        info(LD_GENERAL,"eof (status 200) after uploading server "
             "descriptor: finished.");
        break;
      case 400:
        warn(LD_GENERAL,"http status 400 (\"%s\") response from "
             "dirserver '%s:%d'. Please correct.",
             reason, conn->address, conn->port);
        break;
      case 403:
        warn(LD_GENERAL,"http status 403 (\"%s\") response from dirserver "
             "'%s:%d'. Is your clock skewed? Have you mailed us your key "
             "fingerprint? Are you using the right key? Are you using a "
             "private IP address? See http://tor.eff.org/doc/"
             "tor-doc-server.html", reason, conn->address, conn->port);
        break;
      default:
        warn(LD_GENERAL,"http status %d (\"%s\") reason unexpected (server "
             "'%s:%d').",
             status_code, reason, conn->address, conn->port);
        break;
    }
    /* return 0 in all cases, since we don't want to mark any
     * dirservers down just because they don't like us. */
  }

  if (conn->purpose == DIR_PURPOSE_FETCH_RENDDESC) {
    info(LD_REND,"Received rendezvous descriptor (size %d, status %d "
         "(\"%s\"))",
         (int)body_len, status_code, reason);
    switch (status_code) {
      case 200:
        if (rend_cache_store(body, body_len) < 0) {
          warn(LD_REND,"Failed to store rendezvous descriptor.");
          /* alice's ap_stream will notice when connection_mark_for_close
           * cleans it up */
        } else {
          /* success. notify pending connections about this. */
          conn->purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
          rend_client_desc_here(conn->rend_query);
        }
        break;
      case 404:
        /* not there. pending connections will be notified when
         * connection_mark_for_close cleans it up. */
        break;
      case 400:
        warn(LD_REND,"http status 400 (\"%s\"). Dirserver didn't like our "
             "rendezvous query?", reason);
        break;
      default:
        warn(LD_REND,"http status %d (\"%s\") response unexpected (server "
             "'%s:%d').",
             status_code, reason, conn->address, conn->port);
        break;
    }
  }

  if (conn->purpose == DIR_PURPOSE_UPLOAD_RENDDESC) {
    switch (status_code) {
      case 200:
        info(LD_REND,"Uploading rendezvous descriptor: finished with status "
             "200 (\"%s\")", reason);
        break;
      case 400:
        warn(LD_REND,"http status 400 (\"%s\") response from dirserver "
             "'%s:%d'. Malformed rendezvous descriptor?",
             reason, conn->address, conn->port);
        break;
      default:
        warn(LD_REND,"http status %d (\"%s\") response unexpected (server "
             "'%s:%d').",
             status_code, reason, conn->address, conn->port);
        break;
    }
  }
  tor_free(body); tor_free(headers); tor_free(reason);
  return 0;
}

/** Called when a directory connection reaches EOF */
int
connection_dir_reached_eof(connection_t *conn)
{
  int retval;
  if (conn->state != DIR_CONN_STATE_CLIENT_READING) {
    info(LD_HTTP,"conn reached eof, not reading. Closing.");
    /* This check is temporary; it's to let us know whether we should consider
     * parsing partial serverdesc responses. */
    if (conn->purpose == DIR_PURPOSE_FETCH_SERVERDESC &&
        buf_datalen(conn->inbuf)>=(24*1024)) {
      notice(LD_DIR,
             "Directory connection closed early after downloading %d bytes of "
             "descriptors. If this happens often, please file a bug report.",
             (int)buf_datalen(conn->inbuf));
    }
    connection_close_immediate(conn); /* error: give up on flushing */
    connection_mark_for_close(conn);
    return -1;
  }

  retval = connection_dir_client_reached_eof(conn);
  if (retval == 0) /* success */
    conn->state = DIR_CONN_STATE_CLIENT_FINISHED;
  connection_mark_for_close(conn);
  return retval;
}

/** Read handler for directory connections.  (That's connections <em>to</em>
 * directory servers and connections <em>at</em> directory servers.)
 */
int
connection_dir_process_inbuf(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DIR);

  /* Directory clients write, then read data until they receive EOF;
   * directory servers read data until they get an HTTP command, then
   * write their response (when it's finished flushing, they mark for
   * close).
   */

  /* If we're on the dirserver side, look for a command. */
  if (conn->state == DIR_CONN_STATE_SERVER_COMMAND_WAIT) {
    if (directory_handle_command(conn) < 0) {
      connection_mark_for_close(conn);
      return -1;
    }
    return 0;
  }

  /* XXX for READ states, might want to make sure inbuf isn't too big */

  debug(LD_HTTP,"Got data, not eof. Leaving on inbuf.");
  return 0;
}

/** Create an http response for the client <b>conn</b> out of
 * <b>status</b> and <b>reason_phrase</b>. Write it to <b>conn</b>.
 */
static void
write_http_status_line(connection_t *conn, int status,
                       const char *reason_phrase)
{
  char buf[256];
  if (tor_snprintf(buf, sizeof(buf), "HTTP/1.0 %d %s\r\n\r\n",
      status, reason_phrase) < 0) {
    warn(LD_BUG,"Bug: status line too long.");
    return;
  }
  connection_write_to_buf(buf, strlen(buf), conn);
}

/** Helper function: return 1 if there are any dir conns of purpose
 * <b>purpose</b> that are going elsewhere than our own ORPort/Dirport.
 * Else return 0.
 */
static int
already_fetching_directory(int purpose)
{
  int i, n;
  connection_t *conn;
  connection_t **carray;

  get_connection_array(&carray,&n);
  for (i=0;i<n;i++) {
    conn = carray[i];
    if (conn->type == CONN_TYPE_DIR &&
        conn->purpose == purpose &&
        !conn->marked_for_close &&
        !router_digest_is_me(conn->identity_digest))
      return 1;
  }
  return 0;
}

/** Helper function: called when a dirserver gets a complete HTTP GET
 * request.  Look for a request for a directory or for a rendezvous
 * service descriptor.  On finding one, write a response into
 * conn-\>outbuf.  If the request is unrecognized, send a 400.
 * Always return 0. */
static int
directory_handle_command_get(connection_t *conn, char *headers,
                             char *body, size_t body_len)
{
  size_t dlen;
  const char *cp;
  char *url = NULL;
  char tmp[8192];
  char date[RFC1123_TIME_LEN+1];

  debug(LD_DIRSERV,"Received GET command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if (parse_http_url(headers, &url) < 0) {
    write_http_status_line(conn, 400, "Bad request");
    return 0;
  }
  debug(LD_DIRSERV,"rewritten url as '%s'.", url);

  if (!strcmp(url,"/tor/") || !strcmp(url,"/tor/dir.z")) { /* dir fetch */
    int deflated = !strcmp(url,"/tor/dir.z");
    dlen = dirserv_get_directory(&cp, deflated);

    tor_free(url);

    if (dlen == 0) {
      notice(LD_DIRSERV,"Client asked for the mirrored directory, but we "
             "don't have a good one yet. Sending 503 Dir not available.");
      write_http_status_line(conn, 503, "Directory unavailable");
      /* try to get a new one now */
      if (!already_fetching_directory(DIR_PURPOSE_FETCH_DIR))
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
      return 0;
    }

    debug(LD_DIRSERV,"Dumping %sdirectory to client.",
          deflated?"deflated ":"");
    format_rfc1123_time(date, time(NULL));
    tor_snprintf(tmp, sizeof(tmp),
                 "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                 "Content-Type: %s\r\nContent-Encoding: %s\r\n\r\n",
                 date,
                 (int)dlen,
                 deflated?"application/octet-stream":"text/plain",
                 deflated?"deflate":"identity");
    connection_write_to_buf(tmp, strlen(tmp), conn);
    connection_write_to_buf(cp, dlen, conn);
    return 0;
  }

  if (!strcmp(url,"/tor/running-routers") ||
      !strcmp(url,"/tor/running-routers.z")) { /* running-routers fetch */
    int deflated = !strcmp(url,"/tor/running-routers.z");
    tor_free(url);
    dlen = dirserv_get_runningrouters(&cp, deflated);
    if (!dlen) { /* we failed to create/cache cp */
      write_http_status_line(conn, 503, "Directory unavailable");
      /* try to get a new one now */
      if (!already_fetching_directory(DIR_PURPOSE_FETCH_RUNNING_LIST))
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_RUNNING_LIST, NULL, 1);
      return 0;
    }

    format_rfc1123_time(date, time(NULL));
    tor_snprintf(tmp, sizeof(tmp),
                 "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                 "Content-Type: %s\r\nContent-Encoding: %s\r\n\r\n",
                 date,
                 (int)dlen,
                 deflated?"application/octet-stream":"text/plain",
                 deflated?"deflate":"identity");
    connection_write_to_buf(tmp, strlen(tmp), conn);
    connection_write_to_buf(cp, strlen(cp), conn);
    return 0;
  }

  if (!strcmpstart(url,"/tor/status/")) {
    /* v2 network status fetch. */
    size_t url_len = strlen(url);
    int deflated = !strcmp(url+url_len-2, ".z");
    smartlist_t *dir_objs = smartlist_create();
    const char *key = url + strlen("/tor/status/");
    if (deflated)
      url[url_len-2] = '\0';
    if (dirserv_get_networkstatus_v2(dir_objs, key)) {
      smartlist_free(dir_objs);
      return 0;
    }
    tor_free(url);
    if (!smartlist_len(dir_objs)) { /* we failed to create/cache cp */
      write_http_status_line(conn, 503, "Network status object unavailable");
      smartlist_free(dir_objs);
      return 0;
    }
    dlen = 0;
    SMARTLIST_FOREACH(dir_objs, cached_dir_t *, d,
                      dlen += deflated?d->dir_z_len:d->dir_len);
    format_rfc1123_time(date, time(NULL));
    tor_snprintf(tmp, sizeof(tmp),
                 "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                 "Content-Type: %s\r\nContent-Encoding: %s\r\n\r\n",
                 date,
                 (int)dlen,
                 deflated?"application/octet-stream":"text/plain",
                 deflated?"deflate":"identity");
    connection_write_to_buf(tmp, strlen(tmp), conn);
    SMARTLIST_FOREACH(dir_objs, cached_dir_t *, d,
       {
         if (deflated)
           connection_write_to_buf(d->dir_z, d->dir_z_len, conn);
         else
           connection_write_to_buf(d->dir, d->dir_len, conn);
       });
    smartlist_free(dir_objs);
    return 0;
  }

  if (!strcmpstart(url,"/tor/server/")) {
    size_t url_len = strlen(url);
    int deflated = !strcmp(url+url_len-2, ".z");
    int res;
    const char *msg;
    smartlist_t *descs = smartlist_create();
    if (deflated)
      url[url_len-2] = '\0';
    res = dirserv_get_routerdescs(descs, url, &msg);
    tor_free(url);
    if (res < 0)
      write_http_status_line(conn, 404, msg);
    else {
      size_t len = 0;
      format_rfc1123_time(date, time(NULL));
      SMARTLIST_FOREACH(descs, signed_descriptor_t *, ri,
                        len += ri->signed_descriptor_len);
      if (deflated) {
        size_t compressed_len;
        char *compressed;
        char *inp = tor_malloc(len+smartlist_len(descs)+1);
        char *cp = inp;
        SMARTLIST_FOREACH(descs, signed_descriptor_t *, ri,
           {
             memcpy(cp, ri->signed_descriptor,
                    ri->signed_descriptor_len);
             cp += ri->signed_descriptor_len;
             *cp++ = '\n';
           });
        *cp = '\0';
        /* XXXX This could be way more efficiently handled; let's see if it
         * shows up under oprofile. */
        if (tor_gzip_compress(&compressed, &compressed_len,
                              inp, cp-inp, ZLIB_METHOD)<0) {
          tor_free(inp);
          smartlist_free(descs);
          return -1;
        }
        tor_free(inp);
        tor_snprintf(tmp, sizeof(tmp),
                     "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                     "Content-Type: application/octet-stream\r\n"
                     "Content-Encoding: deflate\r\n\r\n",
                     date,
                     (int)compressed_len);
        connection_write_to_buf(tmp, strlen(tmp), conn);
        connection_write_to_buf(compressed, compressed_len, conn);
        tor_free(compressed);
      } else {
        tor_snprintf(tmp, sizeof(tmp),
                     "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                     "Content-Type: text/plain\r\n\r\n",
                     date,
                     (int)len);
        connection_write_to_buf(tmp, strlen(tmp), conn);
        SMARTLIST_FOREACH(descs, signed_descriptor_t *, ri,
                          connection_write_to_buf(ri->signed_descriptor,
                                                  ri->signed_descriptor_len,
                                                  conn));
      }
    }
    smartlist_free(descs);
    return 0;
  }

  if (!strcmpstart(url,"/tor/rendezvous/") ||
      !strcmpstart(url,"/tor/rendezvous1/")) {
    /* rendezvous descriptor fetch */
    const char *descp;
    size_t desc_len;
    int versioned = !strcmpstart(url,"/tor/rendezvous1/");
    const char *query = url+strlen("/tor/rendezvous/")+(versioned?1:0);

    if (!authdir_mode(get_options())) {
      /* We don't hand out rend descs. In fact, it could be a security
       * risk, since rend_cache_lookup_desc() below would provide it
       * if we're gone to the site recently, and 404 if we haven't.
       *
       * Reject. */
      write_http_status_line(conn, 400, "Nonauthoritative directory does not "
                             "store rendezvous descriptors");
      tor_free(url);
      return 0;
    }
    switch (rend_cache_lookup_desc(query, versioned?-1:0, &descp, &desc_len)) {
      case 1: /* valid */
        format_rfc1123_time(date, time(NULL));
        tor_snprintf(tmp, sizeof(tmp),
                     "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\n"
                     "Content-Type: application/octet-stream\r\n\r\n",
                     date,
                     (int)desc_len);
        connection_write_to_buf(tmp, strlen(tmp), conn);
        /* need to send descp separately, because it may include nuls */
        connection_write_to_buf(descp, desc_len, conn);
        break;
      case 0: /* well-formed but not present */
        write_http_status_line(conn, 404, "Not found");
        break;
      case -1: /* not well-formed */
        write_http_status_line(conn, 400, "Bad request");
        break;
    }
    tor_free(url);
    return 0;
  }

  /* we didn't recognize the url */
  write_http_status_line(conn, 404, "Not found");
  tor_free(url);
  return 0;
}

/** Helper function: called when a dirserver gets a complete HTTP POST
 * request.  Look for an uploaded server descriptor or rendezvous
 * service descriptor.  On finding one, process it and write a
 * response into conn-\>outbuf.  If the request is unrecognized, send a
 * 400.  Always return 0. */
static int
directory_handle_command_post(connection_t *conn, char *headers,
                              char *body, size_t body_len)
{
  const char *cp;
  char *origin = NULL;
  char *url = NULL;

  debug(LD_DIRSERV,"Received POST command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if (!authdir_mode(get_options())) {
    /* we just provide cached directories; we don't want to
     * receive anything. */
    write_http_status_line(conn, 400, "Nonauthoritative directory does not "
                           "accept posted server descriptors");
    return 0;
  }

  if (parse_http_url(headers, &url) < 0) {
    write_http_status_line(conn, 400, "Bad request");
    return 0;
  }
  debug(LD_DIRSERV,"rewritten url as '%s'.", url);
  origin = http_get_origin(headers, conn);

  if (!strcmp(url,"/tor/")) { /* server descriptor post */
    const char *msg;
    int r = dirserv_add_descriptor(body, &msg);
    tor_assert(msg);
    if (r > 0)
      dirserv_get_directory(&cp, 0); /* rebuild and write to disk */
    switch (r) {
      case -2:
      case -1:
      case 1:
        notice(LD_DIRSERV,"Rejected descriptor from %s.", origin);
        /* malformed descriptor, or something wrong */
        write_http_status_line(conn, 400, msg);
        break;
      case 0: /* accepted but discarded */
      case 2: /* accepted */
        write_http_status_line(conn, 200, msg);
        break;
    }
    goto done;
  }

  if (!strcmpstart(url,"/tor/rendezvous/publish")) {
    /* rendezvous descriptor post */
    if (rend_cache_store(body, body_len) < 0)
      write_http_status_line(conn, 400, "Invalid service descriptor rejected");
    else
      write_http_status_line(conn, 200, "Service descriptor stored");
    goto done;
  }

  /* we didn't recognize the url */
  write_http_status_line(conn, 404, "Not found");

 done:
  tor_free(url);
  tor_free(origin);
  return 0;

}

/** Called when a dirserver receives data on a directory connection;
 * looks for an HTTP request.  If the request is complete, remove it
 * from the inbuf, try to process it; otherwise, leave it on the
 * buffer.  Return a 0 on success, or -1 on error.
 */
static int
directory_handle_command(connection_t *conn)
{
  char *headers=NULL, *body=NULL;
  size_t body_len=0;
  int r;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DIR);

  switch (fetch_from_buf_http(conn->inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_BODY_SIZE, 0)) {
    case -1: /* overflow */
      warn(LD_DIRSERV,
           "Invalid input from address '%s'. Closing.", conn->address);
      return -1;
    case 0:
      debug(LD_DIRSERV,"command not all here yet.");
      return 0;
    /* case 1, fall through */
  }

  debug(LD_DIRSERV,"headers '%s', body '%s'.", headers, body);

  if (!strncasecmp(headers,"GET",3))
    r = directory_handle_command_get(conn, headers, body, body_len);
  else if (!strncasecmp(headers,"POST",4))
    r = directory_handle_command_post(conn, headers, body, body_len);
  else {
    warn(LD_PROTOCOL,"Got headers '%s' with unknown command. Closing.",
         headers);
    r = -1;
  }

  tor_free(headers); tor_free(body);
  return r;
}

/** Write handler for directory connections; called when all data has
 * been flushed.  Close the connection or wait for a response as
 * appropriate.
 */
int
connection_dir_finished_flushing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DIR);

  switch (conn->state) {
    case DIR_CONN_STATE_CLIENT_SENDING:
      debug(LD_DIR,"client finished sending command.");
      conn->state = DIR_CONN_STATE_CLIENT_READING;
      connection_stop_writing(conn);
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      debug(LD_DIRSERV,"Finished writing server response. Closing.");
      connection_mark_for_close(conn);
      return 0;
    default:
      warn(LD_BUG,"Bug: called in unexpected state %d.", conn->state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for directory connections: begin sending data to the
 * server */
int
connection_dir_finished_connecting(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_DIR);
  tor_assert(conn->state == DIR_CONN_STATE_CONNECTING);

  debug(LD_HTTP,"Dir connection to router %s:%u established.",
        conn->address,conn->port);

  conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
  return 0;
}

/** Called when one or more networkstatus fetches have failed (with uppercase
 * fingerprints listed in <b>failed</>).  Mark those fingerprints has having
 * failed once. */
static void
dir_networkstatus_download_failed(smartlist_t *failed)
{
  SMARTLIST_FOREACH(failed, const char *, fp,
  {
    char digest[DIGEST_LEN];
    trusted_dir_server_t *dir;
    base16_decode(digest, DIGEST_LEN, fp, strlen(fp));
    dir = router_get_trusteddirserver_by_digest(digest);

    if (dir)
      ++dir->n_networkstatus_failures;
  });
}

/** Called when one or more networkstatus fetches have failed (with uppercase
 * fingerprints listed in <b>failed</>). */
static void
dir_routerdesc_download_failed(smartlist_t *failed)
{
  char digest[DIGEST_LEN];
  local_routerstatus_t *rs;
  time_t now = time(NULL);
  int server = server_mode(get_options()) && get_options()->DirPort;
  SMARTLIST_FOREACH(failed, const char *, cp,
  {
    base16_decode(digest, DIGEST_LEN, cp, strlen(cp));
    rs = router_get_combined_status_by_digest(digest);
    if (!rs || rs->n_download_failures >= MAX_ROUTERDESC_DOWNLOAD_FAILURES)
      continue;
    ++rs->n_download_failures;
    if (server) {
      switch (rs->n_download_failures) {
        case 1: rs->next_attempt_at = 0; break;
        case 2: rs->next_attempt_at = 0; break;
        case 3: rs->next_attempt_at = now+60; break;
        case 4: rs->next_attempt_at = now+60; break;
        case 5: rs->next_attempt_at = now+60*2; break;
        case 6: rs->next_attempt_at = now+60*5; break;
        case 7: rs->next_attempt_at = now+60*15; break;
        default: rs->next_attempt_at = TIME_MAX; break;
      }
    } else {
      switch (rs->n_download_failures) {
        case 1: rs->next_attempt_at = 0; break;
        case 2: rs->next_attempt_at = now+60; break;
        case 3: rs->next_attempt_at = now+60*5; break;
        case 4: rs->next_attempt_at = now+60*10; break;
        default: rs->next_attempt_at = TIME_MAX; break;
      }
    }
    if (rs->next_attempt_at == 0)
      debug(LD_DIR, "%s failed %d time(s); I'll try again immediately.",
            cp, (int)rs->n_download_failures);
    else if (rs->next_attempt_at < TIME_MAX)
      debug(LD_DIR, "%s failed %d time(s); I'll try again in %d seconds.",
            cp, (int)rs->n_download_failures, (int)(rs->next_attempt_at-now));
    else
      debug(LD_DIR, "%s failed %d time(s); Giving up for a while.",
            cp, (int)rs->n_download_failures);
  });

  /* update_router_descriptor_downloads(time(NULL)); */
}

/* Given a directory <b>resource</b> request generated by us, containing zero
 * or more strings separated by plus signs, followed optionally by ".z", store
 * the strings, in order, into <b>fp_out</b>.  If <b>compressed_out</b> is
 * non-NULL, set it to 1 if the resource ends in ".z", else set it to 0.  If
 * decode_hex is true, then delete all elements that aren't hex digests, and
 * decode the rest.
 */
int
dir_split_resource_into_fingerprints(const char *resource,
                                     smartlist_t *fp_out, int *compressed_out,
                                     int decode_hex)
{
  int old_len;
  tor_assert(fp_out);
  old_len = smartlist_len(fp_out);
  smartlist_split_string(fp_out, resource, "+", 0, 0);
  if (compressed_out)
    *compressed_out = 0;
  if (smartlist_len(fp_out) > old_len) {
    char *last = smartlist_get(fp_out,smartlist_len(fp_out)-1);
    size_t last_len = strlen(last);
    if (last_len > 2 && !strcmp(last+last_len-2, ".z")) {
      last[last_len-2] = '\0';
      if (compressed_out)
        *compressed_out = 1;
    }
  }
  if (decode_hex) {
    int i;
    char *cp, *d = NULL;
    for (i = old_len; i < smartlist_len(fp_out); ++i) {
      cp = smartlist_get(fp_out, i);
      if (strlen(cp) != HEX_DIGEST_LEN) {
        info(LD_DIR, "Skipping digest \"%s\" with non-standard length.", cp);
        smartlist_del(fp_out, i--);
        goto again;
      }
      d = tor_malloc_zero(DIGEST_LEN);
      if (base16_decode(d, DIGEST_LEN, cp, HEX_DIGEST_LEN)<0) {
        info(LD_DIR, "Skipping non-decodable digest \"%s\"", cp);
        smartlist_del(fp_out, i--);
        goto again;
      }
      smartlist_set(fp_out, i, d);
      d = NULL;
    again:
      tor_free(cp);
      tor_free(d);
    }
  }
  return 0;
}

