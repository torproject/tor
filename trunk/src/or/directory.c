/* Copyright 2001,2002,2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

/**
 * \file directory.c
 * \brief Implement directory HTTP protocol.
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
directory_initiate_command_router(routerinfo_t *router, uint8_t purpose,
                                  const char *payload, size_t payload_len);
static void
directory_initiate_command_trusted_dir(trusted_dir_server_t *dirserv,
                      uint8_t purpose, const char *payload, size_t payload_len);

static void
directory_initiate_command(const char *address, uint32_t addr, uint16_t port,
                           const char *platform,
                           const char *digest, uint8_t purpose,
                           const char *payload, size_t payload_len);

static void
directory_send_command(connection_t *conn, const char *platform,
                       uint16_t dir_port, int purpose,
                       const char *payload, size_t payload_len);
static int directory_handle_command(connection_t *conn);

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

#if 0 /* commented out for now, since for now what clients send is
         different from what servers want to receive */
/** URL for publishing rendezvous descriptors. */
char rend_publish_string[] = "/tor/rendezvous/publish";
/** Prefix for downloading rendezvous descriptors. */
char rend_fetch_url[] = "/tor/rendezvous/";
#endif

#define MAX_HEADERS_SIZE 50000
#define MAX_BODY_SIZE 500000

#define ALLOW_DIRECTORY_TIME_SKEW 30*60

/********* END VARIABLES ************/

/** Start a connection to every known directory server, using
 * connection purpose 'purpose' and uploading the payload 'payload'
 * (length 'payload_len').  The purpose should be one of
 * 'DIR_PURPOSE_UPLOAD_DIR' or 'DIR_PURPOSE_UPLOAD_RENDDESC'.
 */
void
directory_post_to_dirservers(uint8_t purpose, const char *payload,
                             size_t payload_len)
{
  int i;
  routerinfo_t *router;
  routerlist_t *rl;

  router_get_routerlist(&rl);
  if(!rl)
    return;

  for(i=0; i < smartlist_len(rl->routers); i++) {
    router = smartlist_get(rl->routers, i);
    /* Note: this posts our descriptor to ourselves, if we're an
     * authdirserver. But I think that's ok. */
    if(router->is_trusted_dir)
      directory_initiate_command_router(router, purpose, payload, payload_len);
  }
}

/** Start a connection to a random running directory server, using
 * connection purpose 'purpose' requesting 'payload' (length
 * 'payload_len').  The purpose should be one of
 * 'DIR_PURPOSE_FETCH_DIR' or 'DIR_PURPOSE_FETCH_RENDDESC'.
 */
void
directory_get_from_dirserver(uint8_t purpose, const char *payload,
                             size_t payload_len)
{
  routerinfo_t *r = NULL;
  trusted_dir_server_t *ds = NULL;

  if (purpose == DIR_PURPOSE_FETCH_DIR) {
    if (advertised_server_mode()) {
      /* only ask authdirservers, and don't ask myself */
      ds = router_pick_trusteddirserver(1);
    } else {
      /* anybody with a non-zero dirport will do */
      r = router_pick_directory_server(1);
      if (!r) {
        log_fn(LOG_INFO, "No router found for directory; falling back to dirserver list");
        ds = router_pick_trusteddirserver(1);
      }
    }
  } else { // (purpose == DIR_PURPOSE_FETCH_RENDDESC)
    /* only ask authdirservers, any of them will do */
    ds = router_pick_trusteddirserver(0);
  }

  if (r)
    directory_initiate_command_router(r, purpose, payload, payload_len);
  else if (ds)
    directory_initiate_command_trusted_dir(ds, purpose, payload, payload_len);
  else
    log_fn(LOG_WARN,"No running dirservers known. Not trying. (purpose %d)", purpose);
}


/** Launch a new connection to the directory server <b>router</b> to upload or
 * download a service or rendezvous descriptor. <b>purpose</b> determines what
 * kind of directory connection we're launching, and must be one of
 * DIR_PURPOSE_{FETCH|UPLOAD}_{DIR|RENDDESC}.
 *
 * When uploading, <b>payload</b> and <b>payload_len</b> determine the content
 * of the HTTP post.  When fetching a rendezvous descriptor, <b>payload</b>
 * and <b>payload_len</b> are the service ID we want to fetch.
 */
static void
directory_initiate_command_router(routerinfo_t *router, uint8_t purpose,
                                  const char *payload, size_t payload_len)
{
  directory_initiate_command(router->address, router->addr, router->dir_port,
                             router->platform, router->identity_digest,
                             purpose, payload, payload_len);
}

static void
directory_initiate_command_trusted_dir(trusted_dir_server_t *dirserv,
                      uint8_t purpose, const char *payload, size_t payload_len)
{
  directory_initiate_command(dirserv->address, dirserv->addr,dirserv->dir_port,
                        NULL, dirserv->digest, purpose, payload, payload_len);
}

static void
directory_initiate_command(const char *address, uint32_t addr,
                           uint16_t dir_port, const char *platform,
                           const char *digest, uint8_t purpose,
                           const char *payload, size_t payload_len)
{
  connection_t *conn;

  tor_assert(address && addr && dir_port && digest);

  switch (purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      log_fn(LOG_DEBUG,"initiating directory fetch");
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      log_fn(LOG_DEBUG,"initiating hidden-service descriptor fetch");
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      log_fn(LOG_DEBUG,"initiating server descriptor upload");
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      log_fn(LOG_DEBUG,"initiating hidden-service descriptor upload");
      break;
    default:
      log_fn(LOG_ERR, "Unrecognized directory connection purpose.");
      tor_assert(0);
  }

  conn = connection_new(CONN_TYPE_DIR);

  /* set up conn so it's got all the data we need to remember */
  if(options.HttpProxy) {
    conn->addr = options.HttpProxyAddr;
    conn->port = options.HttpProxyPort;
  } else {
    conn->addr = addr;
    conn->port = dir_port;
  }
  conn->address = tor_strdup(address);
  /* conn->nickname = tor_strdup(router->nickname); */
  /* tor_assert(router->identity_pkey); */
  /* conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey); */
  /* crypto_pk_get_digest(conn->identity_pkey, conn->identity_digest); */
  memcpy(conn->identity_digest, digest, DIGEST_LEN);

  conn->purpose = purpose;

  /* give it an initial state */
  conn->state = DIR_CONN_STATE_CONNECTING;

  if(purpose == DIR_PURPOSE_FETCH_DIR ||
     purpose == DIR_PURPOSE_UPLOAD_DIR) {
    /* then we want to connect directly */
    switch(connection_connect(conn, conn->address, conn->addr, conn->port)) {
      case -1:
        router_mark_as_down(conn->identity_digest); /* don't try him again */
        if(purpose == DIR_PURPOSE_FETCH_DIR &&
           !all_trusted_directory_servers_down()) {
          log_fn(LOG_INFO,"Giving up on dirserver %s; trying another.", conn->nickname);
          directory_get_from_dirserver(purpose, payload, payload_len);
        }
        connection_free(conn);
        return;
      case 1:
        conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
        /* fall through */
      case 0:
        /* queue the command on the outbuf */
        directory_send_command(conn, platform, dir_port,
                               purpose, payload, payload_len);

        connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via tor */
    /* make an AP connection
     * populate it and add it at the right state
     * socketpair and hook up both sides
     */
    conn->s = connection_ap_make_bridge(conn->address, conn->port);
    if(conn->s < 0) {
      log_fn(LOG_WARN,"Making AP bridge to dirserver failed.");
      connection_mark_for_close(conn);
      return;
    }

    conn->state = DIR_CONN_STATE_CLIENT_SENDING;
    connection_add(conn);
    /* queue the command on the outbuf */
    directory_send_command(conn, platform, dir_port,
                           purpose, payload, payload_len);
    connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
  }
}

/** Queue an appropriate HTTP command on conn-\>outbuf.  The args
 * <b>purpose</b>, <b>payload</b>, and <b>payload_len</b> are as in
 * directory_initiate_command.
 */
static void
directory_send_command(connection_t *conn, const char *platform,
                       uint16_t dir_port, int purpose,
                       const char *payload, size_t payload_len) {
  char tmp[8192];
  char proxystring[128];
  char hoststring[128];
  char url[128];
  int use_newer = 0;
  char *httpcommand = NULL;

  tor_assert(conn && conn->type == CONN_TYPE_DIR);
  tor_assert(dir_port && conn);

  /* If we don't know the platform, assume it's up-to-date. */
  use_newer = platform ? tor_version_as_new_as(platform, "0.0.9pre1"):1;

  if(dir_port == 80) {
    strlcpy(hoststring, conn->address, sizeof(hoststring));
  } else {
    sprintf(hoststring, "%s:%d", conn->address, dir_port);
  }
  if(options.HttpProxy) {
    sprintf(proxystring, "http://%s", hoststring);
  } else {
    proxystring[0] = 0;
  }

  switch(purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      tor_assert(payload == NULL);
      log_fn(LOG_DEBUG, "Asking for %scompressed directory from server running %s",
             use_newer?"":"un", platform?platform:"<unknown version>");
      httpcommand = "GET";
      strlcpy(url, use_newer ? "/tor/dir.z" : "/", sizeof(url));
      break;
    case DIR_PURPOSE_FETCH_RUNNING_LIST:
      tor_assert(payload == NULL);
      httpcommand = "GET";
      strlcpy(url, use_newer ? "/tor/running-routers" : "/running-routers", sizeof(url));
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      tor_assert(payload);
      httpcommand = "POST";
      strlcpy(url, use_newer ? "/tor/" : "/", sizeof(url));
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      tor_assert(payload);

      /* this must be true or we wouldn't be doing the lookup */
      tor_assert(payload_len <= REND_SERVICE_ID_LEN);
      /* This breaks the function abstraction. */
      memcpy(conn->rend_query, payload, payload_len);
      conn->rend_query[payload_len] = 0;

      httpcommand = "GET";
      sprintf(url, "%s/rendezvous/%s", use_newer ? "/tor" : "", payload);

      /* XXX We're using payload here to mean something other than
       * payload of the http post. This is probably bad, and should
       * be fixed one day. Kludge for now to make sure we don't post more. */
      payload_len = 0;
      payload = NULL;

      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      tor_assert(payload);
      httpcommand = "POST";
      sprintf(url, "%s/rendezvous/publish", use_newer ? "/tor" : "");
      break;
  }

  snprintf(tmp, sizeof(tmp), "%s %s%s HTTP/1.0\r\nContent-Length: %d\r\nHost: %s\r\n\r\n",
           httpcommand,
           proxystring,
           url,
           payload_len,
           hoststring);
  connection_write_to_buf(tmp, strlen(tmp), conn);

  if(payload) {
    /* then send the payload afterwards too */
    connection_write_to_buf(payload, payload_len, conn);
  }
}

/** Parse an HTTP request string <b>headers</b> of the form
 * "\%s [http[s]://]\%s HTTP/1..."
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
  if(s-start >= 4 && !strcmpstart(start,"http")) {
    tmp = start + 4;
    if(*tmp == 's')
      tmp++;
    if(s-tmp >= 3 && !strcmpstart(tmp,"://")) {
      tmp = strchr(tmp+3, '/');
      if(tmp && tmp < s) {
        log_fn(LOG_DEBUG,"Skipping over 'http[s]://hostname' string");
        start = tmp;
      }
    }
  }

  if(s-start < 5 || strcmpstart(start,"/tor/")) { /* need to rewrite it */
    *url = tor_malloc(s - start + 5);
    strcpy(*url,"/tor");
    strlcpy((*url)+4, start, s-start+1);
    (*url)[s-start+4] = 0; /* null terminate it */
  } else {
    *url = tor_strndup(start, s-start);
  }
  return 0;
}

/** Parse an HTTP response string <b>headers</b> of the form
 * "HTTP/1.\%d \%d\%s\r\n...".
 * If it's well-formed, assign *<b>code</b>, point *<b>message</b> to the first
 * non-space character after code if there is one and message is non-NULL
 * (else leave it alone), and return 0.
 * If <b>date</b> is provided, set *date to the Date header in the
 * http headers, or 0 if no such header is found.
 * Otherwise, return -1.
 */
static int
parse_http_response(char *headers, int *code, char **message, time_t *date,
                    int *compression)
{
  int n1, n2;
  char datestr[RFC1123_TIME_LEN+1];
  smartlist_t *parsed_headers;
  tor_assert(headers && code);

  while(isspace((int)*headers)) headers++; /* tolerate leading whitespace */

  if(sscanf(headers, "HTTP/1.%d %d", &n1, &n2) < 2 ||
     (n1 != 0 && n1 != 1) ||
     (n2 < 100 || n2 >= 600)) {
    log_fn(LOG_WARN,"Failed to parse header '%s'",headers);
    return -1;
  }
  *code = n2;
  if(message) {
    /* XXX should set *message correctly */
  }
  parsed_headers = smartlist_create();
  smartlist_split_string(parsed_headers, headers, "\n",
                         SPLIT_SKIP_SPACE|SPLIT_IGNORE_BLANK, -1);
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
      log_fn(LOG_WARN, "Unrecognized content encoding: '%s'", enc);
      *compression = 0;
    }
  }
  SMARTLIST_FOREACH(parsed_headers, char *, s, tor_free(s));
  smartlist_free(parsed_headers);

  return 0;
}

/** We are a client, and we've finished reading the server's
 * response. Parse and it and act appropriately.
 *
 * Return -1 if an error has occurred, or 0 normally. The caller
 * will take care of marking the connection for close.
 */
static int
connection_dir_client_reached_eof(connection_t *conn)
{
  char *body;
  char *headers;
  size_t body_len=0;
  int status_code;
  time_t now, date_header=0;
  int delta;
  int compression;

  switch(fetch_from_buf_http(conn->inbuf,
                             &headers, MAX_HEADERS_SIZE,
                             &body, &body_len, MAX_DIR_SIZE)) {
    case -1: /* overflow */
      log_fn(LOG_WARN,"'fetch' response too large. Failing.");
      return -1;
    case 0:
      log_fn(LOG_INFO,"'fetch' response not all here, but we're at eof. Closing.");
      return -1;
    /* case 1, fall through */
  }

  if(parse_http_response(headers, &status_code, NULL, &date_header,
                         &compression) < 0) {
    log_fn(LOG_WARN,"Unparseable headers. Closing.");
    tor_free(body); tor_free(headers);
    return -1;
  }
  if (date_header > 0) {
    now = time(NULL);
    delta = now-date_header;
    if (abs(delta)>ALLOW_DIRECTORY_TIME_SKEW) {
      log_fn(LOG_WARN, "Received directory with skewed time: we are %d minutes %s, or the directory is %d minutes %s.",
             abs(delta)/60, delta>0 ? "ahead" : "behind",
             abs(delta)/60, delta>0 ? "behind" : "ahead");
    } else {
      log_fn(LOG_INFO, "Time on received directory is within tolerance; we are %d seconds skewed.  (That's okay.)", delta);
    }
  }

  if (compression != 0) {
    char *new_body;
    size_t new_len;
    if (tor_gzip_uncompress(&new_body, &new_len, body, body_len, compression)) {
      log_fn(LOG_WARN, "Unable to decompress HTTP body.");
      tor_free(body); tor_free(headers);
      return -1;
    }
    tor_free(body);
    body = new_body;
    body_len = new_len;
  }

  if(conn->purpose == DIR_PURPOSE_FETCH_DIR) {
    /* fetch/process the directory to learn about new routers. */
    log_fn(LOG_INFO,"Received directory (size %d):\n%s", body_len, body);
    if(status_code == 503 || body_len == 0) {
      log_fn(LOG_INFO,"Empty directory. Ignoring.");
      tor_free(body); tor_free(headers);
      return 0;
    }
    if(status_code != 200) {
      log_fn(LOG_WARN,"Received http status code %d from dirserver. Failing.",
             status_code);
      tor_free(body); tor_free(headers);
      return -1;
    }
    if(router_load_routerlist_from_directory(body, NULL, 1) < 0){
      log_fn(LOG_WARN,"I failed to parse the directory I fetched from %s:%d. Ignoring.", conn->address, conn->port);
    } else {
      log_fn(LOG_INFO,"updated routers.");
    }
    directory_has_arrived(); /* do things we've been waiting to do */
  }

  if(conn->purpose == DIR_PURPOSE_FETCH_RUNNING_LIST) {
    running_routers_t *rrs;
    routerlist_t *rl;
    /* just update our list of running routers, if this list is new info */
    log_fn(LOG_INFO,"Received running-routers list (size %d):\n%s", body_len, body);
    if(status_code != 200) {
      log_fn(LOG_WARN,"Received http status code %d from dirserver. Failing.",
             status_code);
      tor_free(body); tor_free(headers);
      return -1;
    }
    if (!(rrs = router_parse_runningrouters(body))) {
      log_fn(LOG_WARN, "Can't parse runningrouters list");
      tor_free(body); tor_free(headers);
      return -1;
    }
    router_get_routerlist(&rl);
    routerlist_update_from_runningrouters(rl,rrs);
    running_routers_free(rrs);
  }

  if(conn->purpose == DIR_PURPOSE_UPLOAD_DIR) {
    switch(status_code) {
      case 200:
        log_fn(LOG_INFO,"eof (status 200) after uploading server descriptor: finished.");
        break;
      case 400:
        log_fn(LOG_WARN,"http status 400 (bad request) response from dirserver. Malformed server descriptor?");
        break;
      case 403:
        log_fn(LOG_WARN,"http status 403 (unapproved server) response from dirserver. Is your clock skewed? Have you mailed us your identity fingerprint? Are you using the right key? See README.");
        break;
      default:
        log_fn(LOG_WARN,"http status %d response unrecognized.", status_code);
        break;
    }
  }

  if(conn->purpose == DIR_PURPOSE_FETCH_RENDDESC) {
    log_fn(LOG_INFO,"Received rendezvous descriptor (size %d, status code %d)",
           body_len, status_code);
    switch(status_code) {
      case 200:
        if(rend_cache_store(body, body_len) < 0) {
          log_fn(LOG_WARN,"Failed to store rendezvous descriptor.");
          /* alice's ap_stream will notice when connection_mark_for_close
           * cleans it up */
        } else {
          /* success. notify pending connections about this. */
          rend_client_desc_fetched(conn->rend_query, 1);
          conn->purpose = DIR_PURPOSE_HAS_FETCHED_RENDDESC;
        }
        break;
      case 404:
        /* not there. pending connections will be notified when
         * connection_mark_for_close cleans it up. */
        break;
      case 400:
        log_fn(LOG_WARN,"http status 400 (bad request). Dirserver didn't like our rendezvous query?");
        break;
    }
  }

  if(conn->purpose == DIR_PURPOSE_UPLOAD_RENDDESC) {
    switch(status_code) {
      case 200:
        log_fn(LOG_INFO,"eof (status 200) after uploading rendezvous descriptor: finished.");
        break;
      case 400:
        log_fn(LOG_WARN,"http status 400 (bad request) response from dirserver. Malformed rendezvous descriptor?");
        break;
      default:
        log_fn(LOG_WARN,"http status %d response unrecognized.", status_code);
        break;
    }
  }
  tor_free(body); tor_free(headers);
  return 0;
}

/** Read handler for directory connections.  (That's connections <em>to</em>
 * directory servers and connections <em>at</em> directory servers.)
 */
int connection_dir_process_inbuf(connection_t *conn) {
  int retval;

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  /* Directory clients write, then read data until they receive EOF;
   * directory servers read data until they get an HTTP command, then
   * write their response (when it's finished flushing, they mark for
   * close).
   */
  if(conn->inbuf_reached_eof) {
    if(conn->state != DIR_CONN_STATE_CLIENT_READING) {
      log_fn(LOG_INFO,"conn reached eof, not reading. Closing.");
      connection_close_immediate(conn); /* it was an error; give up on flushing */
      connection_mark_for_close(conn);
      return -1;
    }

    retval = connection_dir_client_reached_eof(conn);
    connection_mark_for_close(conn);
    return retval;
  } /* endif 'reached eof' */

  /* If we're on the dirserver side, look for a command. */
  if(conn->state == DIR_CONN_STATE_SERVER_COMMAND_WAIT) {
    if (directory_handle_command(conn) < 0) {
      connection_mark_for_close(conn);
      return -1;
    }
    return 0;
  }

  /* XXX for READ states, might want to make sure inbuf isn't too big */

  log_fn(LOG_DEBUG,"Got data, not eof. Leaving on inbuf.");
  return 0;
}

static char answer200[] = "HTTP/1.0 200 OK\r\n\r\n";
static char answer400[] = "HTTP/1.0 400 Bad request\r\n\r\n";
static char answer403[] = "HTTP/1.0 403 Unapproved server\r\n\r\n";
static char answer404[] = "HTTP/1.0 404 Not found\r\n\r\n";
static char answer503[] = "HTTP/1.0 503 Directory unavailable\r\n\r\n";

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
  char *url;
  char tmp[8192];
  char date[RFC1123_TIME_LEN+1];

  log_fn(LOG_DEBUG,"Received GET command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if (parse_http_url(headers, &url) < 0) {
    connection_write_to_buf(answer400, strlen(answer400), conn);
    return 0;
  }
  log_fn(LOG_INFO,"rewritten url as '%s'.", url);

  if(!strcmp(url,"/tor/") || !strcmp(url,"/tor/dir.z")) { /* directory fetch */
    int deflated = !strcmp(url,"/tor/dir.z");
    dlen = dirserv_get_directory(&cp, deflated);

    tor_free(url);

    if(dlen == 0) {
      log_fn(LOG_WARN,"My directory is empty. Closing.");
      connection_write_to_buf(answer503, strlen(answer503), conn);
      return 0;
    }

    log_fn(LOG_DEBUG,"Dumping %sdirectory to client.", 
           deflated?"deflated ":"");
    format_rfc1123_time(date, time(NULL));
    snprintf(tmp, sizeof(tmp), "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nContent-Encoding: %s\r\n\r\n",
             date,
             (int)dlen,
             deflated?"deflate":"identity");
    connection_write_to_buf(tmp, strlen(tmp), conn);
    connection_write_to_buf(cp, dlen, conn);
    return 0;
  }

  if(!strcmp(url,"/tor/running-routers")) { /* running-routers fetch */
    tor_free(url);
    if(!authdir_mode()) {
      /* XXX008 for now, we don't cache running-routers. Reject. */
      connection_write_to_buf(answer400, strlen(answer400), conn);
      return 0;
    }
    dlen = dirserv_get_runningrouters(&cp);
    if(!dlen) { /* we failed to create cp */
      connection_write_to_buf(answer503, strlen(answer503), conn);
      return 0;
    }

    format_rfc1123_time(date, time(NULL));
    snprintf(tmp, sizeof(tmp), "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\n\r\n",
             date,
             (int)dlen);
    connection_write_to_buf(tmp, strlen(tmp), conn);
    connection_write_to_buf(cp, strlen(cp), conn);
    return 0;
  }

  if(!strcmpstart(url,"/tor/rendezvous/")) {
    /* rendezvous descriptor fetch */
    const char *descp;
    size_t desc_len;

    if(!authdir_mode()) {
      /* We don't hand out rend descs. In fact, it could be a security
       * risk, since rend_cache_lookup_desc() below would provide it
       * if we're gone to the site recently, and 404 if we haven't.
       *
       * Reject. */
      connection_write_to_buf(answer400, strlen(answer400), conn);
      tor_free(url);
      return 0;
    }
    switch(rend_cache_lookup_desc(url+strlen("/tor/rendezvous/"), &descp, &desc_len)) {
      case 1: /* valid */
        format_rfc1123_time(date, time(NULL));
        snprintf(tmp, sizeof(tmp), "HTTP/1.0 200 OK\r\nDate: %s\r\nContent-Length: %d\r\nContent-Type: application/octet-stream\r\n\r\n",
                 date,
                 (int)desc_len); /* can't include descp here, because it's got nuls */
        connection_write_to_buf(tmp, strlen(tmp), conn);
        connection_write_to_buf(descp, desc_len, conn);
        break;
      case 0: /* well-formed but not present */
        connection_write_to_buf(answer404, strlen(answer404), conn);
        break;
      case -1: /* not well-formed */
        connection_write_to_buf(answer400, strlen(answer400), conn);
        break;
    }
    tor_free(url);
    return 0;
  }

  /* we didn't recognize the url */
  connection_write_to_buf(answer404, strlen(answer404), conn);
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
  char *url;

  log_fn(LOG_DEBUG,"Received POST command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if(!authdir_mode()) {
    /* we just provide cached directories; we don't want to
     * receive anything. */
    connection_write_to_buf(answer400, strlen(answer400), conn);
    return 0;
  }

  if (parse_http_url(headers, &url) < 0) {
    connection_write_to_buf(answer400, strlen(answer400), conn);
    return 0;
  }
  log_fn(LOG_INFO,"rewritten url as '%s'.", url);

  if(!strcmp(url,"/tor/")) { /* server descriptor post */
    cp = body;
    switch(dirserv_add_descriptor(&cp)) {
      case -1:
        /* malformed descriptor, or something wrong */
        connection_write_to_buf(answer400, strlen(answer400), conn);
        break;
      case 0:
        /* descriptor was well-formed but server has not been approved */
        connection_write_to_buf(answer403, strlen(answer403), conn);
        break;
      case 1:
        dirserv_get_directory(&cp, 0); /* rebuild and write to disk */
        connection_write_to_buf(answer200, strlen(answer200), conn);
        break;
    }
    tor_free(url);
    return 0;
  }

  if(!strcmpstart(url,"/tor/rendezvous/publish")) {
    /* rendezvous descriptor post */
    if(rend_cache_store(body, body_len) < 0)
      connection_write_to_buf(answer400, strlen(answer400), conn);
    else
      connection_write_to_buf(answer200, strlen(answer200), conn);
    tor_free(url);
    return 0;
  }

  /* we didn't recognize the url */
  connection_write_to_buf(answer404, strlen(answer404), conn);
  tor_free(url);
  return 0;
}

/** Called when a dirserver receives data on a directory connection;
 * looks for an HTTP request.  If the request is complete, remove it
 * from the inbuf, try to process it; otherwise, leave it on the
 * buffer.  Return a 0 on success, or -1 on error.
 */
static int directory_handle_command(connection_t *conn) {
  char *headers=NULL, *body=NULL;
  size_t body_len=0;
  int r;

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  switch(fetch_from_buf_http(conn->inbuf,
                             &headers, MAX_HEADERS_SIZE,
                             &body, &body_len, MAX_BODY_SIZE)) {
    case -1: /* overflow */
      log_fn(LOG_WARN,"input too large. Failing.");
/*XXX009 needs a better warn message */
      return -1;
    case 0:
      log_fn(LOG_DEBUG,"command not all here yet.");
      return 0;
    /* case 1, fall through */
  }

  log_fn(LOG_DEBUG,"headers '%s', body '%s'.", headers, body);

  if(!strncasecmp(headers,"GET",3))
    r = directory_handle_command_get(conn, headers, body, body_len);
  else if (!strncasecmp(headers,"POST",4))
    r = directory_handle_command_post(conn, headers, body, body_len);
  else {
    log_fn(LOG_WARN,"Got headers '%s' with unknown command. Closing.", headers);
    r = -1;
  }

  tor_free(headers); tor_free(body);
  return r;
}

/** Write handler for directory connections; called when all data has
 * been flushed.  Close the connection or wait for a response as
 * appropriate.
 */
int connection_dir_finished_flushing(connection_t *conn) {

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  switch(conn->state) {
    case DIR_CONN_STATE_CLIENT_SENDING:
      log_fn(LOG_DEBUG,"client finished sending command.");
      conn->state = DIR_CONN_STATE_CLIENT_READING;
      connection_stop_writing(conn);
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      log_fn(LOG_INFO,"Finished writing server response. Closing.");
      connection_mark_for_close(conn);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d.", conn->state);
      return -1;
  }
  return 0;
}

/** Connected handler for directory connections: begin sending data to the
 * server */
int connection_dir_finished_connecting(connection_t *conn)
{
  tor_assert(conn && conn->type == CONN_TYPE_DIR);
  tor_assert(conn->state == DIR_CONN_STATE_CONNECTING);

  log_fn(LOG_INFO,"Dir connection to router %s:%u established.",
         conn->address,conn->port);

  conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
