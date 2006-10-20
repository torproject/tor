/* Copyright 2001-2004 Roger Dingledine.
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson. */
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
directory_initiate_command(const char *address, uint32_t addr, uint16_t port,
                           const char *platform,
                           const char *digest, uint8_t purpose,
                           int private_connection, const char *resource,
                           const char *payload, size_t payload_len);

static void
directory_send_command(dir_connection_t *conn, const char *platform,
                       int purpose, const char *resource,
                       const char *payload, size_t payload_len);
static int directory_handle_command(dir_connection_t *conn);
static int body_is_plausible(const char *body, size_t body_len, int purpose);
static int purpose_is_private(uint8_t purpose);
static char *http_get_header(const char *headers, const char *which);
static void http_set_address_origin(const char *headers, connection_t *conn);
static void connection_dir_download_networkstatus_failed(
                                                      dir_connection_t *conn);
static void connection_dir_download_routerdesc_failed(dir_connection_t *conn);
static void dir_networkstatus_download_failed(smartlist_t *failed);
static void dir_routerdesc_download_failed(smartlist_t *failed);
static void note_request(const char *key, size_t bytes);

/********* START VARIABLES **********/

/** How far in the future do we allow a directory server to tell us it is
 * before deciding that one of us has the wrong time? */
#define ALLOW_DIRECTORY_TIME_SKEW (30*60)

#define X_ADDRESS_HEADER "X-Your-Address-Is: "

/* HTTP cache control: how long do we tell proxies they can cache things? */
#define FULL_DIR_CACHE_LIFETIME (60*60)
#define RUNNINGROUTERS_CACHE_LIFETIME (20*60)
#define NETWORKSTATUS_CACHE_LIFETIME (5*60)
#define ROUTERDESC_CACHE_LIFETIME (30*60)
#define ROUTERDESC_BY_DIGEST_CACHE_LIFETIME (48*60*60)
#define ROBOTS_CACHE_LIFETIME (24*60*60)

/********* END VARIABLES ************/

/** Return true iff the directory purpose 'purpose' must use an
 * anonymous connection to a directory. */
static int
purpose_is_private(uint8_t purpose)
{
  if (get_options()->AllDirActionsPrivate)
    return 1;
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
  int post_to_hidserv_only;

  dirservers = router_get_trusted_dir_servers();
  tor_assert(dirservers);
  /* Only old dirservers handle rendezvous descriptor publishing. */
  post_to_hidserv_only = (purpose == DIR_PURPOSE_UPLOAD_RENDDESC);
  /* This tries dirservers which we believe to be down, but ultimately, that's
   * harmless, and we may as well err on the side of getting things uploaded.
   */
  SMARTLIST_FOREACH(dirservers, trusted_dir_server_t *, ds,
    {
      routerstatus_t *rs = &(ds->fake_status);
      if (post_to_hidserv_only && !ds->is_hidserv_authority)
        continue;
      if (!post_to_hidserv_only &&
          !(ds->is_v1_authority || ds->is_v2_authority))
        continue;
      post_via_tor = purpose_is_private(purpose) ||
              !fascist_firewall_allows_address_dir(ds->addr, ds->dir_port);
      directory_initiate_command_routerstatus(rs, purpose, post_via_tor,
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
  routerstatus_t *rs = NULL;
  or_options_t *options = get_options();
  int prefer_authority = server_mode(options) && options->DirPort != 0;
  int directconn = !purpose_is_private(purpose);
  authority_type_t type;

  /* FFFF we could break this switch into its own function, and call
   * it elsewhere in directory.c. -RD */
  switch (purpose) {
    case DIR_PURPOSE_FETCH_NETWORKSTATUS:
    case DIR_PURPOSE_FETCH_SERVERDESC:
      type = V2_AUTHORITY;
      break;
    case DIR_PURPOSE_FETCH_DIR:
    case DIR_PURPOSE_FETCH_RUNNING_LIST:
      type = V1_AUTHORITY;
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      type = HIDSERV_AUTHORITY;
      break;
    default:
      log_warn(LD_BUG, "Unexpected purpose %d", (int)purpose);
      return;
  }

  if (!options->FetchServerDescriptors && type != HIDSERV_AUTHORITY)
    return;

  if (directconn) {
    if (prefer_authority) {
      /* only ask authdirservers, and don't ask myself */
      rs = router_pick_trusteddirserver(type, 1, 1,
                                        retry_if_no_servers);
    }
    if (!rs) {
      /* anybody with a non-zero dirport will do */
      rs = router_pick_directory_server(1, 1, type==V2_AUTHORITY,
                                        retry_if_no_servers);
      if (!rs) {
        const char *which;
        if (purpose == DIR_PURPOSE_FETCH_DIR)
          which = "directory";
        else if (purpose == DIR_PURPOSE_FETCH_RUNNING_LIST)
          which = "status list";
        else if (purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS)
          which = "network status";
        else // if (purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS)
          which = "server descriptors";
        log_info(LD_DIR,
                 "No router found for %s; falling back to dirserver list",
                 which);
        rs = router_pick_trusteddirserver(type, 1, 1,
                                          retry_if_no_servers);
        if (!rs)
          directconn = 0; /* last resort: try routing it via Tor */
      }
    }
  }
  if (!directconn) {
    /* Never use fascistfirewall; we're going via Tor. */
    if (purpose == DIR_PURPOSE_FETCH_RENDDESC) {
      /* only ask hidserv authorities, any of them will do */
      rs = router_pick_trusteddirserver(HIDSERV_AUTHORITY, 0, 0,
                                        retry_if_no_servers);
    } else {
      /* anybody with a non-zero dirport will do. Disregard firewalls. */
      rs = router_pick_directory_server(1, 0, type == V2_AUTHORITY,
                                        retry_if_no_servers);
      /* If we have any hope of building an indirect conn, we know some router
       * descriptors.  If (rs==NULL), we can't build circuits anyway, so
       * there's no point in falling back to the authorities in this case. */
    }
  }

  if (rs)
    directory_initiate_command_routerstatus(rs, purpose, !directconn,
                                            resource, NULL, 0);
  else {
    log_notice(LD_DIR,
               "While fetching directory info, "
               "no running dirservers known. Will try again later. "
               "(purpose %d)", purpose);
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
directory_initiate_command_router(routerinfo_t *router,
                                  uint8_t purpose,
                                  int private_connection,
                                  const char *resource,
                                  const char *payload,
                                  size_t payload_len)
{
  directory_initiate_command(router->address, router->addr, router->dir_port,
                             router->platform,
                             router->cache_info.identity_digest,
                             purpose, private_connection, resource,
                             payload, payload_len);
}

/** Launch a new connection to the directory server <b>status</b> to upload or
 * download a server or rendezvous descriptor. <b>purpose</b> determines what
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
directory_initiate_command_routerstatus(routerstatus_t *status,
                                        uint8_t purpose,
                                        int private_connection,
                                        const char *resource,
                                        const char *payload,
                                        size_t payload_len)
{
  const char *platform = NULL;
  routerinfo_t *router;
  char address_buf[INET_NTOA_BUF_LEN+1];
  struct in_addr in;
  const char *address;
  if ((router = router_get_by_digest(status->identity_digest))) {
    platform = router->platform;
    address = router->address;
  } else {
    in.s_addr = htonl(status->addr);
    tor_inet_ntoa(&in, address_buf, sizeof(address_buf));
    address = address_buf;
  }
  directory_initiate_command(address, status->addr, status->dir_port,
                             platform, status->identity_digest,
                             purpose, private_connection, resource,
                             payload, payload_len);
}

/** Called when we are unable to complete the client's request to a
 * directory server: Mark the router as down and try again if possible.
 */
void
connection_dir_request_failed(dir_connection_t *conn)
{
  if (router_digest_is_me(conn->identity_digest))
    return; /* this was a test fetch. don't retry. */
  router_set_status(conn->identity_digest, 0); /* don't try him again */
  if (conn->_base.purpose == DIR_PURPOSE_FETCH_DIR ||
      conn->_base.purpose == DIR_PURPOSE_FETCH_RUNNING_LIST) {
    log_info(LD_DIR, "Giving up on directory server at '%s:%d'; retrying",
             conn->_base.address, conn->_base.port);
    directory_get_from_dirserver(conn->_base.purpose, NULL,
                                 0 /* don't retry_if_no_servers */);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS) {
    log_info(LD_DIR, "Giving up on directory server at '%s'; retrying",
             conn->_base.address);
    connection_dir_download_networkstatus_failed(conn);
  } else if (conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC) {
    log_info(LD_DIR, "Giving up on directory server at '%s'; retrying",
             conn->_base.address);
    connection_dir_download_routerdesc_failed(conn);
  }
}

/** Called when an attempt to download one or more network status
 * documents on connection <b>conn</b> failed. Decide whether to
 * retry the fetch now, later, or never.
 */
static void
connection_dir_download_networkstatus_failed(dir_connection_t *conn)
{
  if (!conn->requested_resource) {
    /* We never reached directory_send_command, which means that we never
     * opened a network connection.  Either we're out of sockets, or the
     * network is down.  Either way, retrying would be pointless. */
    return;
  }
  if (!strcmpstart(conn->requested_resource, "all")) {
    /* We're a non-authoritative directory cache; try again. */
    smartlist_t *trusted_dirs = router_get_trusted_dir_servers();
    SMARTLIST_FOREACH(trusted_dirs, trusted_dir_server_t *, ds,
                      ++ds->n_networkstatus_failures);
    directory_get_from_dirserver(conn->_base.purpose, "all.z",
                                 0 /* don't retry_if_no_servers */);
  } else if (!strcmpstart(conn->requested_resource, "fp/")) {
    /* We were trying to download by fingerprint; mark them all as having
     * failed, and possibly retry them later.*/
    smartlist_t *failed = smartlist_create();
    dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                         failed, NULL, 0, 0);
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
connection_dir_download_routerdesc_failed(dir_connection_t *conn)
{
  /* Try again. No need to increment the failure count for routerdescs, since
   * it's not their fault.*/
  /* update_router_descriptor_downloads(time(NULL)); */
  (void) conn;
  /* XXXX Why did the above get commented out? -NM */
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
  dir_connection_t *conn;

  tor_assert(address);
  tor_assert(addr);
  tor_assert(dir_port);
  tor_assert(digest);

  switch (purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      log_debug(LD_DIR,"initiating directory fetch");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      log_debug(LD_DIR,"initiating hidden-service descriptor fetch");
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      log_debug(LD_OR,"initiating server descriptor upload");
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      log_debug(LD_REND,"initiating hidden-service descriptor upload");
      break;
    case DIR_PURPOSE_FETCH_RUNNING_LIST:
      log_debug(LD_DIR,"initiating running-routers fetch");
      break;
    case DIR_PURPOSE_FETCH_NETWORKSTATUS:
      log_debug(LD_DIR,"initiating network-status fetch");
      break;
    case DIR_PURPOSE_FETCH_SERVERDESC:
      log_debug(LD_DIR,"initiating server descriptor fetch");
      break;
    default:
      log_err(LD_BUG, "Unrecognized directory connection purpose.");
      tor_assert(0);
  }

  conn = TO_DIR_CONN(connection_new(CONN_TYPE_DIR));

  /* set up conn so it's got all the data we need to remember */
  conn->_base.addr = addr;
  conn->_base.port = dir_port;
  conn->_base.address = tor_strdup(address);
  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  conn->_base.purpose = purpose;

  /* give it an initial state */
  conn->_base.state = DIR_CONN_STATE_CONNECTING;
  conn->dirconn_direct = (private_connection == 0);

  if (!private_connection) {
    /* then we want to connect directly */

    if (get_options()->HttpProxy) {
      addr = get_options()->HttpProxyAddr;
      dir_port = get_options()->HttpProxyPort;
    }

    switch (connection_connect(TO_CONN(conn), conn->_base.address, addr,
                               dir_port)) {
      case -1:
        connection_dir_request_failed(conn); /* retry if we want */
        connection_free(TO_CONN(conn));
        return;
      case 1:
        /* start flushing conn */
        conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING;
        /* fall through */
      case 0:
        /* queue the command on the outbuf */
        directory_send_command(conn, platform, purpose, resource,
                               payload, payload_len);
        connection_watch_events(TO_CONN(conn), EV_READ | EV_WRITE);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via tor */
    /* make an AP connection
     * populate it and add it at the right state
     * socketpair and hook up both sides
     */
    conn->_base.s = connection_ap_make_bridge(conn->_base.address,
                                              conn->_base.port);
    if (conn->_base.s < 0) {
      log_warn(LD_NET,"Making AP bridge to dirserver failed.");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }

    if (connection_add(TO_CONN(conn)) < 0) {
      log_warn(LD_NET,"Unable to add AP bridge to dirserver.");
      connection_mark_for_close(TO_CONN(conn));
      return;
    }
    conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING;
    /* queue the command on the outbuf */
    directory_send_command(conn, platform, purpose, resource,
                           payload, payload_len);
    connection_watch_events(TO_CONN(conn), EV_READ | EV_WRITE);
  }
}

/** Queue an appropriate HTTP command on conn-\>outbuf.  The other args
 * are as in directory_initiate_command.
 */
static void
directory_send_command(dir_connection_t *conn, const char *platform,
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
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  tor_free(conn->requested_resource);
  if (resource)
    conn->requested_resource = tor_strdup(resource);

  /* come up with a string for which Host: we want */
  if (conn->_base.port == 80) {
    strlcpy(hoststring, conn->_base.address, sizeof(hoststring));
  } else {
    tor_snprintf(hoststring, sizeof(hoststring),"%s:%d",
                 conn->_base.address, conn->_base.port);
  }

  /* come up with some proxy lines, if we're using one. */
  if (get_options()->HttpProxy) {
    char *base64_authenticator=NULL;
    const char *authenticator = get_options()->HttpProxyAuthenticator;

    tor_snprintf(proxystring, sizeof(proxystring),"http://%s", hoststring);
    if (authenticator) {
      base64_authenticator = alloc_http_authenticator(authenticator);
      if (!base64_authenticator)
        log_warn(LD_BUG, "Encoding http authenticator failed");
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
      log_debug(LD_DIR,
                "Asking for compressed directory from server running %s",
                platform?escaped(platform):"<unknown version>");
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
      // (XXXX We were going to switch this to fetch rendezvous1 descriptors,
      // but that never got testing, and it wasn't a good design.)
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

  if (strlen(proxystring) + strlen(url) >= 4096) {
    log_warn(LD_BUG,
             "Bug: squid does not like URLs longer than 4095 bytes, this "
             "one is %d bytes long: %s%s",
             (int)(strlen(proxystring) + strlen(url)), proxystring, url);
  }

  tor_snprintf(request, sizeof(request), "%s %s", httpcommand, proxystring);
  connection_write_to_buf(request, strlen(request), TO_CONN(conn));
  connection_write_to_buf(url, strlen(url), TO_CONN(conn));
  tor_free(url);

  if (!strcmp(httpcommand, "GET") && !payload) {
    tor_snprintf(request, sizeof(request),
                 " HTTP/1.0\r\nHost: %s%s\r\n\r\n",
                 hoststring,
                 proxyauthstring);
  } else {
    tor_snprintf(request, sizeof(request),
                 " HTTP/1.0\r\nContent-Length: %lu\r\nHost: %s%s\r\n\r\n",
                 payload ? (unsigned long)payload_len : 0,
                 hoststring,
                 proxyauthstring);
  }
  connection_write_to_buf(request, strlen(request), TO_CONN(conn));

  if (payload) {
    /* then send the payload afterwards too */
    connection_write_to_buf(payload, payload_len, TO_CONN(conn));
  }
}

/** Parse an HTTP request string <b>headers</b> of the form
 * \verbatim
 * "\%s [http[s]://]\%s HTTP/1..."
 * \endverbatim
 * If it's well-formed, strdup the second \%s into *<b>url</b>, and
 * nul-terminate it. If the url doesn't start with "/tor/", rewrite it
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
        log_debug(LD_DIR,"Skipping over 'http[s]://hostname' string");
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

/** If <b>headers</b> indicates that a proxy was involved, then rewrite
 * <b>conn</b>-\>address to describe our best guess of the address that
 * originated this HTTP request. */
static void
http_set_address_origin(const char *headers, connection_t *conn)
{
  char *fwd;

  fwd = http_get_header(headers, "Forwarded-For: ");
  if (!fwd)
    fwd = http_get_header(headers, "X-Forwarded-For: ");
  if (fwd) {
    tor_free(conn->address);
    conn->address = tor_strdup(escaped(fwd));
    tor_free(fwd);
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
                    compress_method_t *compression, char **reason)
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
    log_warn(LD_HTTP,"Failed to parse header %s",escaped(headers));
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
      *compression = NO_METHOD;
    } else if (!strcmp(enc, "deflate") || !strcmp(enc, "x-deflate")) {
      *compression = ZLIB_METHOD;
    } else if (!strcmp(enc, "gzip") || !strcmp(enc, "x-gzip")) {
      *compression = GZIP_METHOD;
    } else {
      log_info(LD_HTTP, "Unrecognized content encoding: %s. Trying to deal.",
               escaped(enc));
      *compression = UNKNOWN_METHOD;
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
 * If we're still happy with using this directory server in the future, return
 * 0. Otherwise return -1; and the caller should consider trying the request
 * again.
 *
 * The caller will take care of marking the connection for close.
 */
static int
connection_dir_client_reached_eof(dir_connection_t *conn)
{
  char *body;
  char *headers;
  char *reason = NULL;
  size_t body_len=0, orig_len=0;
  int status_code;
  time_t now, date_header=0;
  int delta;
  compress_method_t compression;
  int plausible;
  int skewed=0;
  int allow_partial = conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC;
  int was_compressed=0;

  switch (fetch_from_buf_http(conn->_base.inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_DIR_SIZE,
                              allow_partial)) {
    case -1: /* overflow */
      log_warn(LD_PROTOCOL,
               "'fetch' response too large (server '%s:%d'). Closing.",
               conn->_base.address, conn->_base.port);
      return -1;
    case 0:
      log_info(LD_HTTP,
               "'fetch' response not all here, but we're at eof. Closing.");
      return -1;
    /* case 1, fall through */
  }
  orig_len = body_len;

  if (parse_http_response(headers, &status_code, &date_header,
                          &compression, &reason) < 0) {
    log_warn(LD_HTTP,"Unparseable headers (server '%s:%d'). Closing.",
             conn->_base.address, conn->_base.port);
    tor_free(body); tor_free(headers);
    return -1;
  }
  if (!reason) reason = tor_strdup("[no reason given]");

  log_debug(LD_DIR,
            "Received response from directory server '%s:%d': %d %s",
            conn->_base.address, conn->_base.port, status_code,
            escaped(reason));

  /* now check if it's got any hints for us about our IP address. */
  if (conn->dirconn_direct) {
    char *guess = http_get_header(headers, X_ADDRESS_HEADER);
    if (guess) {
      router_new_address_suggestion(guess);
      tor_free(guess);
    }
  }

  if (date_header > 0) {
    now = time(NULL);
    delta = now-date_header;
    if (abs(delta)>ALLOW_DIRECTORY_TIME_SKEW) {
      log_fn(router_digest_is_trusted_dir(conn->identity_digest) ?
                                                        LOG_WARN : LOG_INFO,
             LD_HTTP,
             "Received directory with skewed time (server '%s:%d'): "
             "we are %d minutes %s, or the directory is %d minutes %s.",
             conn->_base.address, conn->_base.port,
             abs(delta)/60, delta>0 ? "ahead" : "behind",
             abs(delta)/60, delta>0 ? "behind" : "ahead");
      skewed = 1; /* don't check the recommended-versions line */
    } else {
      log_debug(LD_HTTP, "Time on received directory is within tolerance; "
                "we are %d seconds skewed.  (That's okay.)", delta);
    }
  }

  if (status_code == 503) {
    log_info(LD_DIR,"Received http status code %d (%s) from server "
             "'%s:%d'. I'll try again soon.",
             status_code, escaped(reason), conn->_base.address,
             conn->_base.port);
    tor_free(body); tor_free(headers); tor_free(reason);
    return -1;
  }

  plausible = body_is_plausible(body, body_len, conn->_base.purpose);
  if (compression != NO_METHOD || !plausible) {
    char *new_body = NULL;
    size_t new_len = 0;
    compress_method_t guessed = detect_compression_method(body, body_len);
    if (compression == UNKNOWN_METHOD || guessed != compression) {
      /* Tell the user if we don't believe what we're told about compression.*/
      const char *description1, *description2;
      if (compression == ZLIB_METHOD)
        description1 = "as deflated";
      else if (compression == GZIP_METHOD)
        description1 = "as gzipped";
      else if (compression == NO_METHOD)
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

      log_info(LD_HTTP, "HTTP body from server '%s:%d' was labeled %s, "
               "but it seems to be %s.%s",
               conn->_base.address, conn->_base.port, description1,
               description2,
               (compression>0 && guessed>0)?"  Trying both.":"");
    }
    /* Try declared compression first if we can. */
    if (compression == GZIP_METHOD  || compression == ZLIB_METHOD)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, compression,
                          !allow_partial, LOG_PROTOCOL_WARN);
    /* Okay, if that didn't work, and we think that it was compressed
     * differently, try that. */
    if (!new_body &&
        (guessed == GZIP_METHOD || guessed == ZLIB_METHOD) &&
        compression != guessed)
      tor_gzip_uncompress(&new_body, &new_len, body, body_len, guessed,
                          !allow_partial, LOG_PROTOCOL_WARN);
    /* If we're pretty sure that we have a compressed directory, and
     * we didn't manage to uncompress it, then warn and bail. */
    if (!plausible && !new_body) {
      log_fn(LOG_PROTOCOL_WARN, LD_HTTP,
             "Unable to decompress HTTP body (server '%s:%d').",
             conn->_base.address, conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (new_body) {
      tor_free(body);
      body = new_body;
      body_len = new_len;
      was_compressed = 1;
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_DIR) {
    /* fetch/process the directory to cache it. */
    log_info(LD_DIR,"Received directory (size %d) from server '%s:%d'",
             (int)body_len, conn->_base.address, conn->_base.port);
    if (status_code != 200) {
      log_warn(LD_DIR,"Received http status code %d (%s) from server "
               "'%s:%d' while fetching directory. I'll try again soon.",
               status_code, escaped(reason), conn->_base.address,
               conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (router_parse_directory(body) < 0) {
      log_notice(LD_DIR,"I failed to parse the directory I fetched from "
                 "'%s:%d'. Ignoring.", conn->_base.address, conn->_base.port);
    }
    note_request(was_compressed?"dl/dir.z":"dl/dir", orig_len);
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_RUNNING_LIST) {
    /* just update our list of running routers, if this list is new info */
    log_info(LD_DIR,"Received running-routers list (size %d)", (int)body_len);
    if (status_code != 200) {
      log_warn(LD_DIR,"Received http status code %d (%s) from server "
               "'%s:%d' while fetching running-routers. I'll try again soon.",
               status_code, escaped(reason), conn->_base.address,
               conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    if (router_parse_runningrouters(body)<0) {
      log_warn(LD_DIR,
               "Bad running-routers from server '%s:%d'. I'll try again soon.",
               conn->_base.address, conn->_base.port);
      tor_free(body); tor_free(headers); tor_free(reason);
      return -1;
    }
    note_request(was_compressed?"dl/running-routers.z":
                 "dl/running-routers", orig_len);
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_NETWORKSTATUS) {
    smartlist_t *which = NULL;
    networkstatus_source_t source;
    char *cp;
    log_info(LD_DIR,"Received networkstatus objects (size %d) from server "
             "'%s:%d'",(int) body_len, conn->_base.address, conn->_base.port);
    if (status_code != 200) {
      log_warn(LD_DIR,
           "Received http status code %d (%s) from server "
           "'%s:%d' while fetching \"/tor/status/%s\". I'll try again soon.",
           status_code, escaped(reason), conn->_base.address,
           conn->_base.port, conn->requested_resource);
      tor_free(body); tor_free(headers); tor_free(reason);
      connection_dir_download_networkstatus_failed(conn);
      return -1;
    }
    note_request(was_compressed?"dl/status.z":"dl/status", orig_len);
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"fp/")) {
      source = NS_FROM_DIR_BY_FP;
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource+3,
                                           which, NULL, 0, 0);
    } else if (conn->requested_resource &&
               !strcmpstart(conn->requested_resource, "all")) {
      source = NS_FROM_DIR_ALL;
      which = smartlist_create();
      SMARTLIST_FOREACH(router_get_trusted_dir_servers(),
                        trusted_dir_server_t *, ds,
        {
          char *cp = tor_malloc(HEX_DIGEST_LEN+1);
          base16_encode(cp, HEX_DIGEST_LEN+1, ds->digest, DIGEST_LEN);
          smartlist_add(which, cp);
        });
    } else {
      /* Can we even end up here? -- weasel*/
      source = NS_FROM_DIR_BY_FP;
      log_warn(LD_BUG, "We received a networkstatus but we didn't ask "
                       "for it by fp, nor did we ask for all.");
    }
    cp = body;
    while (*cp) {
      char *next = strstr(cp, "\nnetwork-status-version");
      if (next)
        next[1] = '\0';
      /* learn from it, and then remove it from 'which' */
      if (router_set_networkstatus(cp, time(NULL), source, which)<0)
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

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_SERVERDESC) {
    smartlist_t *which = NULL;
    int n_asked_for = 0;
    log_info(LD_DIR,"Received server info (size %d) from server '%s:%d'",
             (int)body_len, conn->_base.address, conn->_base.port);
    note_request(was_compressed?"dl/server.z":"dl/server", orig_len);
    if (conn->requested_resource &&
        !strcmpstart(conn->requested_resource,"d/")) {
      which = smartlist_create();
      dir_split_resource_into_fingerprints(conn->requested_resource+2,
                                           which, NULL, 0, 0);
      n_asked_for = smartlist_len(which);
    }
    if (status_code != 200) {
      int dir_okay = status_code == 404 ||
        (status_code == 400 && !strcmp(reason, "Servers unavailable."));
      /* 404 means that it didn't have them; no big deal.
       * Older (pre-0.1.1.8) servers said 400 Servers unavailable instead. */
      log_fn(dir_okay ? LOG_INFO : LOG_WARN, LD_DIR,
             "Received http status code %d (%s) from server '%s:%d' "
             "while fetching \"/tor/server/%s\". I'll try again soon.",
             status_code, escaped(reason), conn->_base.address,
             conn->_base.port, conn->requested_resource);
      if (!which) {
        connection_dir_download_routerdesc_failed(conn);
      } else {
        dir_routerdesc_download_failed(which);
        SMARTLIST_FOREACH(which, char *, cp, tor_free(cp));
        smartlist_free(which);
      }
      tor_free(body); tor_free(headers); tor_free(reason);
      return dir_okay ? 0 : -1;
    }
    /* Learn the routers, assuming we requested by fingerprint or "all".
     * Right now, we only use "authority" to fetch ourself, so we don't want
     * to risk replacing ourself with a router running at the addr:port we
     * think we have.
     */
    if (which || (conn->requested_resource &&
                  !strcmpstart(conn->requested_resource, "all"))) {
      /* as we learn from them, we remove them from 'which' */
      router_load_routers_from_string(body, SAVED_NOWHERE, which);
      directory_info_has_arrived(time(NULL), 0);
    }
    if (which) { /* mark remaining ones as failed */
      log_info(LD_DIR, "Received %d/%d routers requested from %s:%d",
               n_asked_for-smartlist_len(which), n_asked_for,
               conn->_base.address, (int)conn->_base.port);
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
          me->addr == conn->_base.addr &&
          me->dir_port == conn->_base.port)
        router_dirport_found_reachable();
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_DIR) {
    switch (status_code) {
      case 200:
        log_info(LD_GENERAL,"eof (status 200) after uploading server "
                 "descriptor: finished.");
        break;
      case 400:
        log_warn(LD_GENERAL,"http status 400 (%s) response from "
                 "dirserver '%s:%d'. Please correct.",
                 escaped(reason), conn->_base.address, conn->_base.port);
        break;
      case 403:
        log_warn(LD_GENERAL,
             "http status 403 (%s) response from dirserver "
             "'%s:%d'. Is your clock skewed? Have you mailed us your key "
             "fingerprint? Are you using the right key? Are you using a "
             "private IP address? See http://tor.eff.org/doc/"
             "tor-doc-server.html",escaped(reason), conn->_base.address,
             conn->_base.port);
        break;
      default:
        log_warn(LD_GENERAL,
             "http status %d (%s) reason unexpected while uploading "
             "descriptor to server '%s:%d').",
             status_code, escaped(reason), conn->_base.address,
             conn->_base.port);
        break;
    }
    /* return 0 in all cases, since we don't want to mark any
     * dirservers down just because they don't like us. */
  }

  if (conn->_base.purpose == DIR_PURPOSE_FETCH_RENDDESC) {
    log_info(LD_REND,"Received rendezvous descriptor (size %d, status %d "
             "(%s))",
             (int)body_len, status_code, escaped(reason));
    switch (status_code) {
      case 200:
        if (rend_cache_store(body, body_len) < 0) {
          log_warn(LD_REND,"Failed to store rendezvous descriptor.");
          /* alice's ap_stream will notice when connection_mark_for_close
           * cleans it up */
        } else {
          /* success. notify pending connections about this. */
          conn->_base.purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
          rend_client_desc_here(conn->rend_query);
        }
        break;
      case 404:
        /* not there. pending connections will be notified when
         * connection_mark_for_close cleans it up. */
        break;
      case 400:
        log_warn(LD_REND,
                 "http status 400 (%s). Dirserver didn't like our "
                 "rendezvous query?", escaped(reason));
        break;
      default:
        log_warn(LD_REND,"http status %d (%s) response unexpected while "
                 "fetching hidden service descriptor (server '%s:%d').",
                 status_code, escaped(reason), conn->_base.address,
                 conn->_base.port);
        break;
    }
  }

  if (conn->_base.purpose == DIR_PURPOSE_UPLOAD_RENDDESC) {
    switch (status_code) {
      case 200:
        log_info(LD_REND,
                 "Uploading rendezvous descriptor: finished with status "
                 "200 (%s)", escaped(reason));
        break;
      case 400:
        log_warn(LD_REND,"http status 400 (%s) response from dirserver "
                 "'%s:%d'. Malformed rendezvous descriptor?",
                 escaped(reason), conn->_base.address, conn->_base.port);
        break;
      default:
        log_warn(LD_REND,"http status %d (%s) response unexpected (server "
                 "'%s:%d').",
                 status_code, escaped(reason), conn->_base.address,
                 conn->_base.port);
        break;
    }
  }
  tor_free(body); tor_free(headers); tor_free(reason);
  return 0;
}

/** Called when a directory connection reaches EOF */
int
connection_dir_reached_eof(dir_connection_t *conn)
{
  int retval;
  if (conn->_base.state != DIR_CONN_STATE_CLIENT_READING) {
    log_info(LD_HTTP,"conn reached eof, not reading. Closing.");
    connection_close_immediate(TO_CONN(conn)); /* error: give up on flushing */
    connection_mark_for_close(TO_CONN(conn));
    return -1;
  }

  retval = connection_dir_client_reached_eof(conn);
  if (retval == 0) /* success */
    conn->_base.state = DIR_CONN_STATE_CLIENT_FINISHED;
  connection_mark_for_close(TO_CONN(conn));
  return retval;
}

/** Read handler for directory connections.  (That's connections <em>to</em>
 * directory servers and connections <em>at</em> directory servers.)
 */
int
connection_dir_process_inbuf(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  /* Directory clients write, then read data until they receive EOF;
   * directory servers read data until they get an HTTP command, then
   * write their response (when it's finished flushing, they mark for
   * close).
   */

  /* If we're on the dirserver side, look for a command. */
  if (conn->_base.state == DIR_CONN_STATE_SERVER_COMMAND_WAIT) {
    if (directory_handle_command(conn) < 0) {
      connection_mark_for_close(TO_CONN(conn));
      return -1;
    }
    return 0;
  }

  /* XXX for READ states, might want to make sure inbuf isn't too big */

  if (!conn->_base.inbuf_reached_eof)
    log_debug(LD_HTTP,"Got data, not eof. Leaving on inbuf.");
  return 0;
}

/** Create an http response for the client <b>conn</b> out of
 * <b>status</b> and <b>reason_phrase</b>. Write it to <b>conn</b>.
 */
static void
write_http_status_line(dir_connection_t *conn, int status,
                       const char *reason_phrase)
{
  char buf[256];
  if (tor_snprintf(buf, sizeof(buf), "HTTP/1.0 %d %s\r\n\r\n",
      status, reason_phrase) < 0) {
    log_warn(LD_BUG,"Bug: status line too long.");
    return;
  }
  connection_write_to_buf(buf, strlen(buf), TO_CONN(conn));
}

/** Write the header for an HTTP/1.0 response onto <b>conn</b>-\>outbuf,
 * with <b>type</b> as the Content-Type.
 *
 * If <b>length</b> is nonnegative, it is the Content-Length.
 * If <b>encoding</b> is provided, it is the Content-Encoding.
 * If <b>cache_lifetime</b> is greater than 0, the content may be cached for
 * up to cache_lifetime seconds.  Otherwise, the content may not be cached. */
static void
write_http_response_header(dir_connection_t *conn, ssize_t length,
                           const char *type, const char *encoding,
                           int cache_lifetime)
{
  char date[RFC1123_TIME_LEN+1];
  char tmp[1024];
  char *cp;
  time_t now = time(NULL);

  tor_assert(conn);
  tor_assert(type);

  format_rfc1123_time(date, now);
  cp = tmp;
  tor_snprintf(cp, sizeof(tmp),
               "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Type: %s\r\n"
               X_ADDRESS_HEADER "%s\r\n",
               date, type, conn->_base.address);
  cp += strlen(tmp);
  if (encoding) {
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Content-Encoding: %s\r\n", encoding);
    cp += strlen(cp);
  }
  if (length >= 0) {
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Content-Length: %ld\r\n", (long)length);
    cp += strlen(cp);
  }
  if (cache_lifetime > 0) {
    char expbuf[RFC1123_TIME_LEN+1];
    format_rfc1123_time(expbuf, now + cache_lifetime);
    /* We could say 'Cache-control: max-age=%d' here if we start doing
     * http/1.1 */
    tor_snprintf(cp, sizeof(tmp)-(cp-tmp),
                 "Expires: %s\r\n", expbuf);
    cp += strlen(cp);
  } else {
    /* We could say 'Cache-control: no-cache' here if we start doing
     * http/1.1 */
    strlcpy(cp, "Pragma: no-cache\r\n", sizeof(tmp)-(cp-tmp));
    cp += strlen(cp);
  }
  if (sizeof(tmp)-(cp-tmp) > 3)
    memcpy(cp, "\r\n", 3);
  else
    tor_assert(0);
  connection_write_to_buf(tmp, strlen(tmp), TO_CONN(conn));
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
        !router_digest_is_me(TO_DIR_CONN(conn)->identity_digest))
      return 1;
  }
  return 0;
}

#undef INSTRUMENT_DOWNLOADS

#ifdef INSTRUMENT_DOWNLOADS
/** DOCDOC */
static strmap_t *request_bytes_map = NULL;

/** DOCDOC */
static void
note_request(const char *key, size_t bytes)
{
  uint64_t *n;
  if (!request_bytes_map)
    request_bytes_map = strmap_new();

  n = strmap_get(request_bytes_map, key);
  if (!n) {
    n = tor_malloc_zero(sizeof(uint64_t));
    strmap_set(request_bytes_map, key, n);
  }
  *n += bytes;
}

/** DOCDOC */
char *
directory_dump_request_log(void)
{
  smartlist_t *lines;
  char tmp[256];
  char *result;
  strmap_iter_t *iter;

  if (!request_bytes_map)
    request_bytes_map = strmap_new();

  lines = smartlist_create();

  for (iter = strmap_iter_init(request_bytes_map);
       !strmap_iter_done(iter);
       iter = strmap_iter_next(request_bytes_map, iter)) {
    const char *key;
    void *val;
    uint64_t *n;
    strmap_iter_get(iter, &key, &val);
    n = val;
    tor_snprintf(tmp, sizeof(tmp), "%s  "U64_FORMAT"\n",
                 key, U64_PRINTF_ARG(*n));
    smartlist_add(lines, tor_strdup(tmp));
  }
  smartlist_sort_strings(lines);
  result = smartlist_join_strings(lines, "", 0, NULL);
  SMARTLIST_FOREACH(lines, char *, cp, tor_free(cp));
  smartlist_free(lines);
  return result;
}
#else
static void
note_request(const char *key, size_t bytes)
{
  (void)key;
  (void)bytes;
}

char *
directory_dump_request_log(void)
{
  return tor_strdup("Not supported.");
}
#endif

/** Helper function: called when a dirserver gets a complete HTTP GET
 * request.  Look for a request for a directory or for a rendezvous
 * service descriptor.  On finding one, write a response into
 * conn-\>outbuf.  If the request is unrecognized, send a 400.
 * Always return 0. */
static int
directory_handle_command_get(dir_connection_t *conn, char *headers,
                             char *body, size_t body_len)
{
  size_t dlen;
  const char *cp;
  char *url = NULL;
  or_options_t *options = get_options();
  /* We ignore the body of a GET request. */
  (void)body;
  (void)body_len;

  log_debug(LD_DIRSERV,"Received GET command.");

  conn->_base.state = DIR_CONN_STATE_SERVER_WRITING;

  if (parse_http_url(headers, &url) < 0) {
    write_http_status_line(conn, 400, "Bad request");
    return 0;
  }
  log_debug(LD_DIRSERV,"rewritten url as '%s'.", url);

  if (!strcmp(url,"/tor/") || !strcmp(url,"/tor/dir.z")) { /* dir fetch */
    int deflated = !strcmp(url,"/tor/dir.z");
    cached_dir_t *d = dirserv_get_directory();

    if (!d) {
      log_notice(LD_DIRSERV,"Client asked for the mirrored directory, but we "
                 "don't have a good one yet. Sending 503 Dir not available.");
      write_http_status_line(conn, 503, "Directory unavailable");
      /* try to get a new one now */
      if (!already_fetching_directory(DIR_PURPOSE_FETCH_DIR))
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_DIR, NULL, 1);
      tor_free(url);
      return 0;
    }
    dlen = deflated ? d->dir_z_len : d->dir_len;

    if (global_write_bucket_empty()) {
      log_info(LD_DIRSERV,
               "Client asked for the mirrored directory, but we've been "
               "writing too many bytes lately. Sending 503 Dir busy.");
      write_http_status_line(conn, 503, "Directory busy, try again later");
      tor_free(url);
      return 0;
    }

    note_request(url, dlen);
    tor_free(url);

    log_debug(LD_DIRSERV,"Dumping %sdirectory to client.",
              deflated?"deflated ":"");
    write_http_response_header(conn, dlen,
                          deflated?"application/octet-stream":"text/plain",
                          deflated?"deflate":"identity",
                          FULL_DIR_CACHE_LIFETIME);
    conn->cached_dir = d;
    conn->cached_dir_offset = 0;
    if (! deflated)
      conn->zlib_state = tor_zlib_new(0, ZLIB_METHOD);
    ++d->refcnt;

    /* Prime the connection with some data. */
    conn->dir_spool_src = DIR_SPOOL_CACHED_DIR;
    connection_dirserv_flushed_some(conn);
    return 0;
  }

  if (!strcmp(url,"/tor/running-routers") ||
      !strcmp(url,"/tor/running-routers.z")) { /* running-routers fetch */
    int deflated = !strcmp(url,"/tor/running-routers.z");
    dlen = dirserv_get_runningrouters(&cp, deflated);
    note_request(url, dlen);
    tor_free(url);
    if (!dlen) { /* we failed to create/cache cp */
      write_http_status_line(conn, 503, "Directory unavailable");
      /* try to get a new one now */
      if (!already_fetching_directory(DIR_PURPOSE_FETCH_RUNNING_LIST))
        directory_get_from_dirserver(DIR_PURPOSE_FETCH_RUNNING_LIST, NULL, 1);
      return 0;
    }

    write_http_response_header(conn, dlen,
                 deflated?"application/octet-stream":"text/plain",
                 deflated?"deflate":"identity",
                 RUNNINGROUTERS_CACHE_LIFETIME);
    connection_write_to_buf(cp, strlen(cp), TO_CONN(conn));
    return 0;
  }

  if (!strcmpstart(url,"/tor/status/")) {
    /* v2 network status fetch. */
    size_t url_len = strlen(url);
    int deflated = !strcmp(url+url_len-2, ".z");
    smartlist_t *dir_fps = smartlist_create();
    const char *request_type = NULL;
    const char *key = url + strlen("/tor/status/");
    if (deflated)
      url[url_len-2] = '\0';
    dirserv_get_networkstatus_v2_fingerprints(dir_fps, key);
    if (!strcmpstart(key, "fp/"))
      request_type = deflated?"/tor/status/fp.z":"/tor/status/fp";
    else if (!strcmpstart(key, "authority"))
      request_type = deflated?"/tor/status/authority.z":
        "/tor/status/authority";
    else if (!strcmpstart(key, "all"))
      request_type = deflated?"/tor/status/all.z":"/tor/status/all";
    else
      request_type = "/tor/status/?";
    tor_free(url);
    if (!smartlist_len(dir_fps)) { /* we failed to create/cache cp */
      write_http_status_line(conn, 503, "Network status object unavailable");
      smartlist_free(dir_fps);
      return 0;
    }
    // note_request(request_type,dlen);
    write_http_response_header(conn, -1,
                 deflated?"application/octet_stream":"text/plain",
                 deflated?"deflate":NULL,
                 smartlist_len(dir_fps) == 1 ? NETWORKSTATUS_CACHE_LIFETIME:0);
    conn->fingerprint_stack = dir_fps;
    if (! deflated)
      conn->zlib_state = tor_zlib_new(0, ZLIB_METHOD);

    /* Prime the connection with some data. */
    conn->dir_spool_src = DIR_SPOOL_NETWORKSTATUS;
    connection_dirserv_flushed_some(conn);

    return 0;
  }

  if (!strcmpstart(url,"/tor/server/")) {
    size_t url_len = strlen(url);
    int deflated = !strcmp(url+url_len-2, ".z");
    int res;
    const char *msg;
    const char *request_type = NULL;
    int cache_lifetime = 0;
    if (deflated)
      url[url_len-2] = '\0';
    conn->fingerprint_stack = smartlist_create();
    res = dirserv_get_routerdesc_fingerprints(conn->fingerprint_stack, url,
                                              &msg);

    if (!strcmpstart(url, "/tor/server/fp/")) {
      request_type = deflated?"/tor/server/fp.z":"/tor/server/fp";
      if (smartlist_len(conn->fingerprint_stack) == 1)
        cache_lifetime = ROUTERDESC_CACHE_LIFETIME;
    } else if (!strcmpstart(url, "/tor/server/authority")) {
      request_type = deflated?"/tor/server/authority.z":
        "/tor/server/authority";
      cache_lifetime = ROUTERDESC_CACHE_LIFETIME;
    } else if (!strcmpstart(url, "/tor/server/all")) {
      request_type = deflated?"/tor/server/all.z":"/tor/server/all";
      cache_lifetime = FULL_DIR_CACHE_LIFETIME;
    } else if (!strcmpstart(url, "/tor/server/d/")) {
      request_type = deflated?"/tor/server/d.z":"/tor/server/d";
      if (smartlist_len(conn->fingerprint_stack) == 1)
        cache_lifetime = ROUTERDESC_BY_DIGEST_CACHE_LIFETIME;
    } else {
      request_type = "/tor/server/?";
    }
    if (!strcmpstart(url, "/tor/server/d/"))
      conn->dir_spool_src = DIR_SPOOL_SERVER_BY_DIGEST;
    else
      conn->dir_spool_src = DIR_SPOOL_SERVER_BY_FP;
    tor_free(url);
    if (res < 0)
      write_http_status_line(conn, 404, msg);
    else {
      write_http_response_header(conn, -1,
                     deflated?"application/octet_stream":"text/plain",
                     deflated?"deflate":NULL, cache_lifetime);
      if (deflated)
        conn->zlib_state = tor_zlib_new(1, ZLIB_METHOD);
      /* Prime the connection with some data. */
      connection_dirserv_flushed_some(conn);
    }
    return 0;
  }

  if (options->HSAuthoritativeDir &&
      (!strcmpstart(url,"/tor/rendezvous/") ||
       !strcmpstart(url,"/tor/rendezvous1/"))) {
    /* rendezvous descriptor fetch */
    const char *descp;
    size_t desc_len;
    int versioned = !strcmpstart(url,"/tor/rendezvous1/");
    const char *query = url+strlen("/tor/rendezvous/")+(versioned?1:0);

    switch (rend_cache_lookup_desc(query, versioned?-1:0, &descp, &desc_len)) {
      case 1: /* valid */
        write_http_response_header(conn, desc_len, "application/octet-stream",
                                   NULL, 0);
        note_request("/tor/rendezvous?/", desc_len);
        /* need to send descp separately, because it may include nuls */
        connection_write_to_buf(descp, desc_len, TO_CONN(conn));
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

  if (!strcmpstart(url,"/tor/bytes.txt")) {
    char *bytes = directory_dump_request_log();
    size_t len = strlen(bytes);
    write_http_response_header(conn, len, "text/plain", NULL, 0);
    connection_write_to_buf(bytes, len, TO_CONN(conn));
    tor_free(bytes);
    tor_free(url);
    return 0;
  }

  if (!strcmp(url,"/tor/robots.txt")) { /* /robots.txt will have been
                                           rewritten to /tor/robots.txt */
    char robots[] = "User-agent: *\r\nDisallow: /\r\n";
    size_t len = strlen(robots);
    write_http_response_header(conn, len, "text/plain", NULL,
                               ROBOTS_CACHE_LIFETIME);
    connection_write_to_buf(robots, len, TO_CONN(conn));
    tor_free(url);
    return 0;
  }

  if (!strcmp(url,"/tor/dir-all-weaselhack") &&
      (conn->_base.addr == 0x7f000001ul) &&
      authdir_mode(options)) {
    /* XXX until weasel rewrites his scripts  XXXX012 */
    char *new_directory=NULL;

    if (dirserv_dump_directory_to_string(&new_directory,
                                         get_identity_key(), 1)) {
      log_warn(LD_BUG, "Error creating full v1 directory.");
      tor_free(new_directory);
      write_http_status_line(conn, 503, "Directory unavailable");
      return 0;
    }

    dlen = strlen(new_directory);

    write_http_response_header(conn, dlen, "text/plain", "identity", 0);

    connection_write_to_buf(new_directory, dlen, TO_CONN(conn));
    tor_free(new_directory);
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
directory_handle_command_post(dir_connection_t *conn, char *headers,
                              char *body, size_t body_len)
{
  char *url = NULL;
  or_options_t *options = get_options();

  log_debug(LD_DIRSERV,"Received POST command.");

  conn->_base.state = DIR_CONN_STATE_SERVER_WRITING;

  if (!authdir_mode(options)) {
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
  log_debug(LD_DIRSERV,"rewritten url as '%s'.", url);

  if (!strcmp(url,"/tor/")) { /* server descriptor post */
    const char *msg;
    int r = dirserv_add_descriptor(body, &msg);
    tor_assert(msg);
    if (r > 0)
      dirserv_get_directory(); /* rebuild and write to disk */
    switch (r) {
      case -2:
      case -1:
      case 1:
        log_notice(LD_DIRSERV,"Rejected router descriptor from %s.",
                   conn->_base.address);
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

  if (options->HSAuthoritativeDir &&
      !strcmpstart(url,"/tor/rendezvous/publish")) {
    /* rendezvous descriptor post */
    if (rend_cache_store(body, body_len) < 0) {
//      char tmp[1024*2+1];
      log_fn(LOG_PROTOCOL_WARN, LD_DIRSERV,
             "Rejected rend descriptor (length %d) from %s.",
             (int)body_len, conn->_base.address);
#if 0
      if (body_len <= 1024) {
        base16_encode(tmp, sizeof(tmp), body, body_len);
        log_notice(LD_DIRSERV,"Body was: %s", escaped(tmp));
      }
#endif
      write_http_status_line(conn, 400, "Invalid service descriptor rejected");
    } else {
      write_http_status_line(conn, 200, "Service descriptor stored");
    }
    goto done;
  }

  /* we didn't recognize the url */
  write_http_status_line(conn, 404, "Not found");

 done:
  tor_free(url);
  return 0;
}

/** Called when a dirserver receives data on a directory connection;
 * looks for an HTTP request.  If the request is complete, remove it
 * from the inbuf, try to process it; otherwise, leave it on the
 * buffer.  Return a 0 on success, or -1 on error.
 */
static int
directory_handle_command(dir_connection_t *conn)
{
  char *headers=NULL, *body=NULL;
  size_t body_len=0;
  int r;

  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  switch (fetch_from_buf_http(conn->_base.inbuf,
                              &headers, MAX_HEADERS_SIZE,
                              &body, &body_len, MAX_BODY_SIZE, 0)) {
    case -1: /* overflow */
      log_warn(LD_DIRSERV,
               "Invalid input from address '%s'. Closing.",
               conn->_base.address);
      return -1;
    case 0:
      log_debug(LD_DIRSERV,"command not all here yet.");
      return 0;
    /* case 1, fall through */
  }

  http_set_address_origin(headers, TO_CONN(conn));
  //log_debug(LD_DIRSERV,"headers %s, body %s.", headers, body);

  if (!strncasecmp(headers,"GET",3))
    r = directory_handle_command_get(conn, headers, body, body_len);
  else if (!strncasecmp(headers,"POST",4))
    r = directory_handle_command_post(conn, headers, body, body_len);
  else {
    log_fn(LOG_PROTOCOL_WARN, LD_PROTOCOL,
           "Got headers %s with unknown command. Closing.",
           escaped(headers));
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
connection_dir_finished_flushing(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);

  switch (conn->_base.state) {
    case DIR_CONN_STATE_CLIENT_SENDING:
      log_debug(LD_DIR,"client finished sending command.");
      conn->_base.state = DIR_CONN_STATE_CLIENT_READING;
      connection_stop_writing(TO_CONN(conn));
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      log_debug(LD_DIRSERV,"Finished writing server response. Closing.");
      connection_mark_for_close(TO_CONN(conn));
      return 0;
    default:
      log_warn(LD_BUG,"Bug: called in unexpected state %d.",
               conn->_base.state);
      tor_fragile_assert();
      return -1;
  }
  return 0;
}

/** Connected handler for directory connections: begin sending data to the
 * server */
int
connection_dir_finished_connecting(dir_connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->_base.type == CONN_TYPE_DIR);
  tor_assert(conn->_base.state == DIR_CONN_STATE_CONNECTING);

  log_debug(LD_HTTP,"Dir connection to router %s:%u established.",
            conn->_base.address,conn->_base.port);

  conn->_base.state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
  return 0;
}

/** Called when one or more networkstatus fetches have failed (with uppercase
 * fingerprints listed in <b>failed</>).  Mark those fingerprints as having
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

/** Called when one or more routerdesc fetches have failed (with uppercase
 * fingerprints listed in <b>failed</b>). */
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
      log_debug(LD_DIR, "%s failed %d time(s); I'll try again immediately.",
                cp, (int)rs->n_download_failures);
    else if (rs->next_attempt_at < TIME_MAX)
      log_debug(LD_DIR, "%s failed %d time(s); I'll try again in %d seconds.",
                cp, (int)rs->n_download_failures,
                (int)(rs->next_attempt_at-now));
    else
      log_debug(LD_DIR, "%s failed %d time(s); Giving up for a while.",
                cp, (int)rs->n_download_failures);
  });

  /* update_router_descriptor_downloads(time(NULL)); */
}

/* Given a directory <b>resource</b> request, containing zero
 * or more strings separated by plus signs, followed optionally by ".z", store
 * the strings, in order, into <b>fp_out</b>.  If <b>compressed_out</b> is
 * non-NULL, set it to 1 if the resource ends in ".z", else set it to 0.  If
 * decode_hex is true, then delete all elements that aren't hex digests, and
 * decode the rest.  If sort_uniq is true, then sort the list and remove
 * all duplicates.
 */
int
dir_split_resource_into_fingerprints(const char *resource,
                                     smartlist_t *fp_out, int *compressed_out,
                                     int decode_hex, int sort_uniq)
{
  smartlist_t *fp_tmp = smartlist_create();
  tor_assert(fp_out);
  smartlist_split_string(fp_tmp, resource, "+", 0, 0);
  if (compressed_out)
    *compressed_out = 0;
  if (smartlist_len(fp_tmp)) {
    char *last = smartlist_get(fp_tmp,smartlist_len(fp_tmp)-1);
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
    for (i = 0; i < smartlist_len(fp_tmp); ++i) {
      cp = smartlist_get(fp_tmp, i);
      if (strlen(cp) != HEX_DIGEST_LEN) {
        log_info(LD_DIR,
                 "Skipping digest %s with non-standard length.", escaped(cp));
        smartlist_del_keeporder(fp_tmp, i--);
        goto again;
      }
      d = tor_malloc_zero(DIGEST_LEN);
      if (base16_decode(d, DIGEST_LEN, cp, HEX_DIGEST_LEN)<0) {
        log_info(LD_DIR, "Skipping non-decodable digest %s", escaped(cp));
        smartlist_del_keeporder(fp_tmp, i--);
        goto again;
      }
      smartlist_set(fp_tmp, i, d);
      d = NULL;
    again:
      tor_free(cp);
      tor_free(d);
    }
  }
  if (sort_uniq) {
    smartlist_t *fp_tmp2 = smartlist_create();
    int i;
    if (decode_hex)
      smartlist_sort_digests(fp_tmp);
    else
      smartlist_sort_strings(fp_tmp);
    if (smartlist_len(fp_tmp))
      smartlist_add(fp_tmp2, smartlist_get(fp_tmp, 0));
    for (i = 1; i < smartlist_len(fp_tmp); ++i) {
      char *cp = smartlist_get(fp_tmp, i);
      char *last = smartlist_get(fp_tmp2, smartlist_len(fp_tmp2)-1);

      if ((decode_hex && memcmp(cp, last, DIGEST_LEN))
          || (!decode_hex && strcasecmp(cp, last)))
        smartlist_add(fp_tmp2, cp);
      else
        tor_free(cp);
    }
    smartlist_free(fp_tmp);
    fp_tmp = fp_tmp2;
  }
  smartlist_add_all(fp_out, fp_tmp);
  smartlist_free(fp_tmp);
  return 0;
}

