/* Copyright 2001,2002,2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

static void directory_send_command(connection_t *conn, int purpose,
                                   const char *payload, int payload_len);
static int directory_handle_command(connection_t *conn);

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

char rend_publish_string[] = "/rendezvous/publish";
char rend_fetch_url[] = "/rendezvous/";

#define MAX_HEADERS_SIZE 2048
#define MAX_BODY_SIZE 500000

/********* END VARIABLES ************/

void directory_initiate_command(routerinfo_t *router, int purpose,
                                const char *payload, int payload_len) {
  connection_t *conn;

  if(purpose == DIR_PURPOSE_FETCH_DIR)
    log_fn(LOG_DEBUG,"initiating directory fetch");
  if(purpose == DIR_PURPOSE_FETCH_RENDDESC)
    log_fn(LOG_DEBUG,"initiating hidden-service descriptor fetch");
  if(purpose == DIR_PURPOSE_UPLOAD_DIR)
    log_fn(LOG_DEBUG,"initiating server descriptor upload");
  if(purpose == DIR_PURPOSE_UPLOAD_RENDDESC)
    log_fn(LOG_DEBUG,"initiating hidden-service descriptor upload");

  if (!router) { /* i guess they didn't have one in mind for me to use */
    log_fn(LOG_WARN,"No running dirservers known. Not trying. (purpose %d)", purpose);
    return;
  }

  conn = connection_new(CONN_TYPE_DIR);

  /* set up conn so it's got all the data we need to remember */
  conn->addr = router->addr;
  conn->port = router->dir_port;
  conn->address = tor_strdup(router->address);
  conn->nickname = tor_strdup(router->nickname);
  tor_assert(router->identity_pkey);
  conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey);

  conn->purpose = purpose;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return;
  }

  /* queue the command on the outbuf */
  directory_send_command(conn, purpose, payload, payload_len);

  /* give it an initial state */
  conn->state = DIR_CONN_STATE_CONNECTING;

  if(purpose == DIR_PURPOSE_FETCH_DIR ||
     purpose == DIR_PURPOSE_UPLOAD_DIR) {
    /* then we want to connect directly */
    switch(connection_connect(conn, conn->address, conn->addr, conn->port)) {
      case -1:
        router_mark_as_down(conn->nickname); /* don't try him again */
        connection_mark_for_close(conn, 0);
        return;
      case 1:
        conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
        /* fall through */
      case 0:
        connection_set_poll_socket(conn);
        connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
        /* writable indicates finish, readable indicates broken link,
           error indicates broken link in windowsland. */
    }
  } else { /* we want to connect via tor */
    /* make an AP connection
     *   populate it and add it at the right state
     * socketpair and hook up both sides
     */
    conn->s = connection_ap_make_bridge(conn->address, conn->port);
    if(conn->s < 0) {
      log_fn(LOG_WARN,"Making AP bridge to dirserver failed.");
      connection_mark_for_close(conn, 0);
      return;
    }

    conn->state = DIR_CONN_STATE_CLIENT_SENDING;
    connection_set_poll_socket(conn);
    connection_start_reading(conn);
  }
}

static void directory_send_command(connection_t *conn, int purpose,
                                   const char *payload, int payload_len) {
  char fetchstring[] = "GET / HTTP/1.0\r\n\r\n";
  char tmp[8192];

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  switch(purpose) {
    case DIR_PURPOSE_FETCH_DIR:
      tor_assert(payload == NULL);
      connection_write_to_buf(fetchstring, strlen(fetchstring), conn);
      break;
    case DIR_PURPOSE_UPLOAD_DIR:
      tor_assert(payload);
      snprintf(tmp, sizeof(tmp), "POST / HTTP/1.0\r\nContent-Length: %d\r\n\r\n",
               payload_len);
      connection_write_to_buf(tmp, strlen(tmp), conn);
      connection_write_to_buf(payload, payload_len, conn);
      break;
    case DIR_PURPOSE_FETCH_RENDDESC:
      tor_assert(payload);

      /* this must be true or we wouldn't be doing the lookup */
      tor_assert(payload_len <= REND_SERVICE_ID_LEN);
      memcpy(conn->rend_query, payload, payload_len);
      conn->rend_query[payload_len] = 0;

      snprintf(tmp, sizeof(tmp), "GET %s%s HTTP/1.0\r\n\r\n", rend_fetch_url, payload);
      connection_write_to_buf(tmp, strlen(tmp), conn);
      break;
    case DIR_PURPOSE_UPLOAD_RENDDESC:
      tor_assert(payload);
      snprintf(tmp, sizeof(tmp),
        "POST %s HTTP/1.0\r\nContent-Length: %d\r\n\r\n", rend_publish_string, payload_len);
      connection_write_to_buf(tmp, strlen(tmp), conn);
      /* could include nuls, need to write it separately */
      connection_write_to_buf(payload, payload_len, conn);
      break;
  }
}

/* Parse "%s %s HTTP/1..."
 * If it's well-formed, point *url to the second %s,
 * null-terminate it (this modifies headers!) and return 0.
 * Otherwise, return -1.
 */
int parse_http_url(char *headers, char **url) {
  char *s, *tmp;

  s = (char *)eat_whitespace_no_nl(headers);
  if (!*s) return -1;
  s = (char *)find_whitespace(s); /* get past GET/POST */
  if (!*s) return -1;
  s = (char *)eat_whitespace_no_nl(s);
  if (!*s) return -1;
  tmp = s; /* this is it, assuming it's valid */
  s = (char *)find_whitespace(s);
  if (!*s) return -1;
  *s = 0;
  *url = tmp;
  return 0;
}

/* Parse "HTTP/1.%d %d%s\r\n".
 * If it's well-formed, assign *code, point *message to the first
 * non-space character after code if there is one and message is non-NULL
 * (else leave it alone), and return 0.
 * Otherwise, return -1.
 */
int parse_http_response(char *headers, int *code, char **message) {
  int n1, n2;
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
  return 0;
}

int connection_dir_process_inbuf(connection_t *conn) {
  char *body;
  char *headers;
  int body_len=0;
  int status_code;

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  if(conn->inbuf_reached_eof) {
    if(conn->state != DIR_CONN_STATE_CLIENT_READING) {
      log_fn(LOG_INFO,"conn reached eof, not reading. Closing.");
      connection_close_immediate(conn); /* it was an error; give up on flushing */
      connection_mark_for_close(conn,0);
      return -1;
    }

    switch(fetch_from_buf_http(conn->inbuf,
                               &headers, MAX_HEADERS_SIZE,
                               &body, &body_len, MAX_DIR_SIZE)) {
      case -1: /* overflow */
        log_fn(LOG_WARN,"'fetch' response too large. Failing.");
        connection_mark_for_close(conn,0);
        return -1;
      case 0:
        log_fn(LOG_INFO,"'fetch' response not all here, but we're at eof. Closing.");
        connection_mark_for_close(conn,0);
        return -1;
      /* case 1, fall through */
    }

    if(parse_http_response(headers, &status_code, NULL) < 0) {
      log_fn(LOG_WARN,"Unparseable headers. Closing.");
      free(body); free(headers);
      connection_mark_for_close(conn,0);
      return -1;
    }

    if(conn->purpose == DIR_PURPOSE_FETCH_DIR) {
      /* fetch/process the directory to learn about new routers. */
      log_fn(LOG_INFO,"Received directory (size %d):\n%s", body_len, body);
      if(status_code == 503 || body_len == 0) {
        log_fn(LOG_INFO,"Empty directory. Ignoring.");
        free(body); free(headers);
        connection_mark_for_close(conn,0);
        return 0;
      }
      if(status_code != 200) {
        log_fn(LOG_WARN,"Received http status code %d from dirserver. Failing.",
               status_code);
        free(body); free(headers);
        connection_mark_for_close(conn,0);
        return -1;
      }
      if(router_set_routerlist_from_directory(body, conn->identity_pkey) < 0){
        log_fn(LOG_INFO,"...but parsing failed. Ignoring.");
      } else {
        log_fn(LOG_INFO,"updated routers.");
      }
      directory_has_arrived(); /* do things we've been waiting to do */
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
          log_fn(LOG_WARN,"http status 403 (unapproved server) response from dirserver. Is your clock skewed? Have you mailed arma your identity fingerprint? Are you using the right key? See README.");

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
    free(body); free(headers);
    connection_mark_for_close(conn,0);
    return 0;
  }

  if(conn->state == DIR_CONN_STATE_SERVER_COMMAND_WAIT) {
    if (directory_handle_command(conn) < 0) {
      connection_mark_for_close(conn,0);
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

/* always returns 0 */
static int directory_handle_command_get(connection_t *conn,
                                        char *headers, char *body,
                                        int body_len) {
  size_t dlen;
  const char *cp;
  char *url;
  char tmp[8192];

  log_fn(LOG_DEBUG,"Received GET command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if (parse_http_url(headers, &url) < 0) {
    connection_write_to_buf(answer400, strlen(answer400), conn);
    return 0;
  }

  if(!strcmp(url,"/")) { /* directory fetch */
    dlen = dirserv_get_directory(&cp);

    if(dlen == 0) {
      log_fn(LOG_WARN,"My directory is empty. Closing.");
      connection_write_to_buf(answer503, strlen(answer503), conn);
      return 0;
    }

    log_fn(LOG_DEBUG,"Dumping directory to client.");
    snprintf(tmp, sizeof(tmp), "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n",
             (int)dlen);
    connection_write_to_buf(tmp, strlen(tmp), conn);
    connection_write_to_buf(cp, strlen(cp), conn);
    return 0;
  }

  if(!strncmp(url,rend_fetch_url,strlen(rend_fetch_url))) {
    /* rendezvous descriptor fetch */
    const char *descp;
    int desc_len;

    switch(rend_cache_lookup_desc(url+strlen(rend_fetch_url), &descp, &desc_len)) {
      case 1: /* valid */
        snprintf(tmp, sizeof(tmp), "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n",
                 desc_len); /* can't include descp here, because it's got nuls */
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
    return 0;
  }

  /* we didn't recognize the url */
  connection_write_to_buf(answer404, strlen(answer404), conn);
  return 0;
}

/* always returns 0 */
static int directory_handle_command_post(connection_t *conn,
                                         char *headers, char *body,
                                         int body_len) {
  const char *cp;
  char *url;

  log_fn(LOG_DEBUG,"Received POST command.");

  conn->state = DIR_CONN_STATE_SERVER_WRITING;

  if (parse_http_url(headers, &url) < 0) {
    connection_write_to_buf(answer400, strlen(answer400), conn);
    return 0;
  }
  log_fn(LOG_INFO,"url '%s' posted to us.", url);

  if(!strcmp(url,"/")) { /* server descriptor post */
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
        dirserv_get_directory(&cp); /* rebuild and write to disk */
        connection_write_to_buf(answer200, strlen(answer200), conn);
        break;
    }
    return 0;
  }

  if(!strncmp(url,rend_publish_string,strlen(rend_publish_string))) {
    /* rendezvous descriptor post */
    if(rend_cache_store(body, body_len) < 0)
      connection_write_to_buf(answer400, strlen(answer400), conn);
    else
      connection_write_to_buf(answer200, strlen(answer200), conn);
    return 0;
  }

  /* we didn't recognize the url */
  connection_write_to_buf(answer404, strlen(answer404), conn);
  return 0;
}

static int directory_handle_command(connection_t *conn) {
  char *headers=NULL, *body=NULL;
  int body_len=0;
  int r;

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  switch(fetch_from_buf_http(conn->inbuf,
                             &headers, MAX_HEADERS_SIZE,
                             &body, &body_len, MAX_BODY_SIZE)) {
    case -1: /* overflow */
      log_fn(LOG_WARN,"input too large. Failing.");
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

int connection_dir_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  tor_assert(conn && conn->type == CONN_TYPE_DIR);

  switch(conn->state) {
    case DIR_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)) {
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          router_mark_as_down(conn->nickname); /* don't try him again */
          connection_mark_for_close(conn,0);
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_INFO,"Dir connection to router %s:%u established.",
          conn->address,conn->port);

      conn->state = DIR_CONN_STATE_CLIENT_SENDING; /* start flushing conn */
      return 0;
    case DIR_CONN_STATE_CLIENT_SENDING:
      log_fn(LOG_DEBUG,"client finished sending command.");
      conn->state = DIR_CONN_STATE_CLIENT_READING;
      connection_stop_writing(conn);
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      log_fn(LOG_INFO,"Finished writing server response. Closing.");
      connection_mark_for_close(conn,0);
      return 0;
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state %d.", conn->state);
      return -1;
  }
  return 0;
}

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
