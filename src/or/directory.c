/* Copyright 2001,2002,2003 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

static int directory_send_command(connection_t *conn, int command);
static int directory_handle_command(connection_t *conn);

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

static char fetchstring[] = "GET / HTTP/1.0\r\n\r\n";
static char answerstring[] = "HTTP/1.0 200 OK\r\n\r\n";
static char the_directory[MAX_DIR_SIZE+1];
static int directorylen=0;

/********* END VARIABLES ************/

void directory_initiate_command(routerinfo_t *router, int command) {
  connection_t *conn;

  if (command == DIR_CONN_STATE_CONNECTING_FETCH)
    log_fn(LOG_DEBUG,"initiating directory fetch");
  else
    log_fn(LOG_DEBUG,"initiating directory upload");

  if (!router) { /* i guess they didn't have one in mind for me to use */
    log_fn(LOG_WARN,"No running dirservers known. Not trying.");
    return;
  }

  conn = connection_new(CONN_TYPE_DIR);

  /* set up conn so it's got all the data we need to remember */
  conn->addr = router->addr;
  conn->port = router->dir_port;
  conn->address = tor_strdup(router->address);
  conn->nickname = tor_strdup(router->nickname);
  assert(router->identity_pkey);
  conn->identity_pkey = crypto_pk_dup_key(router->identity_pkey);

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return;
  }

  switch(connection_connect(conn, router->address, router->addr, router->dir_port)) {
    case -1:
      router_mark_as_down(conn->nickname); /* don't try him again */
      connection_remove(conn);
      connection_free(conn);
      return;
    case 0:
      connection_set_poll_socket(conn);
      connection_watch_events(conn, POLLIN | POLLOUT | POLLERR);
      /* writable indicates finish, readable indicates broken link,
         error indicates broken link in windowsland. */
      conn->state = command;
      return;
    /* case 1: fall through */
  }

  connection_set_poll_socket(conn);
  if(directory_send_command(conn, command) < 0) {
    connection_remove(conn);
    connection_free(conn);
  }
}

static int directory_send_command(connection_t *conn, int command) {
  const char *s;
  char tmp[8192];

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(command) {
    case DIR_CONN_STATE_CONNECTING_FETCH:
      connection_write_to_buf(fetchstring, strlen(fetchstring), conn);
      conn->state = DIR_CONN_STATE_CLIENT_SENDING_FETCH;
      break;
    case DIR_CONN_STATE_CONNECTING_UPLOAD:
      s = router_get_my_descriptor();
      if(!s) {
        log_fn(LOG_WARN,"Failed to get my descriptor.");
        return -1;
      }
      snprintf(tmp, sizeof(tmp), "POST / HTTP/1.0\r\nContent-Length: %d\r\n\r\n%s",
               strlen(s), s);
      connection_write_to_buf(tmp, strlen(tmp), conn);
      conn->state = DIR_CONN_STATE_CLIENT_SENDING_UPLOAD;
      break;
  }
  return 0;
}

int connection_dir_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(conn->inbuf_reached_eof) {
    switch(conn->state) {
      case DIR_CONN_STATE_CLIENT_READING_FETCH:
        /* kill it, but first process the_directory and learn about new routers. */
        switch(fetch_from_buf_http(conn->inbuf,
                                   NULL, 0, the_directory, MAX_DIR_SIZE)) {
          case -1: /* overflow */
            log_fn(LOG_WARN,"'fetch' response too large. Failing.");
            return -1;
          case 0:
            log_fn(LOG_INFO,"'fetch' response not all here, but we're at eof. Closing.");
            return -1;
          /* case 1, fall through */
        }
        /* XXX check headers, at least make sure returned 2xx */
        directorylen = strlen(the_directory);
        log_fn(LOG_INFO,"Received directory (size %d):\n%s", directorylen, the_directory);
        if(directorylen == 0) {
          log_fn(LOG_INFO,"Empty directory. Ignoring.");
          return -1;
        }
        if(router_get_dir_from_string(the_directory, conn->identity_pkey) < 0){
          log_fn(LOG_INFO,"...but parsing failed. Ignoring.");
        } else {
          log_fn(LOG_INFO,"updated routers.");
        }
        if(options.OnionRouter) { /* connect to them all */
          router_retry_connections();
        }
        return -1;
      case DIR_CONN_STATE_CLIENT_READING_UPLOAD:
        /* XXX make sure there's a 200 OK on the buffer */
        log_fn(LOG_INFO,"eof while reading upload response. Finished.");
        return -1;
      default:
        log_fn(LOG_INFO,"conn reached eof, not reading. Closing.");
        return -1;
    }
  }

  if(conn->state == DIR_CONN_STATE_SERVER_COMMAND_WAIT)
    return directory_handle_command(conn);

  /* XXX for READ states, might want to make sure inbuf isn't too big */

  log_fn(LOG_DEBUG,"Got data, not eof. Leaving on inbuf.");
  return 0;
}

static int directory_handle_command(connection_t *conn) {
  char headers[1024];
  char body[50000]; /* XXX */
  size_t dlen;
  const char *cp;

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(fetch_from_buf_http(conn->inbuf,
                             headers, sizeof(headers), body, sizeof(body))) {
    case -1: /* overflow */
      log_fn(LOG_WARN,"input too large. Failing.");
      return -1;
    case 0:
      log_fn(LOG_DEBUG,"command not all here yet.");
      return 0;
    /* case 1, fall through */
  }

  log_fn(LOG_DEBUG,"headers '%s', body '%s'.",headers,body);
  if(!strncasecmp(headers,"GET",3)) {
    /* XXX should check url and http version */
    log_fn(LOG_DEBUG,"Received GET command.");

    dlen = dirserv_get_directory(&cp);

    if(dlen == 0) {
      log_fn(LOG_WARN,"My directory is empty. Closing.");
      return -1; /* XXX send some helpful http error code */
    }

    log_fn(LOG_DEBUG,"Dumping directory to client."); 
    connection_write_to_buf(answerstring, strlen(answerstring), conn);
    connection_write_to_buf(cp, dlen, conn);
    conn->state = DIR_CONN_STATE_SERVER_WRITING;
    return 0;
  }

  if(!strncasecmp(headers,"POST",4)) {
    /* XXX should check url and http version */
    log_fn(LOG_DEBUG,"Received POST command.");
    cp = body;
    if(dirserv_add_descriptor(&cp) < 0) {
      log_fn(LOG_WARN,"dirserv_add_descriptor() failed. Dropping.");
      return -1; /* XXX should write an http failed code */
    }
    dirserv_get_directory(&cp); /* rebuild and write to disk */
    connection_write_to_buf(answerstring, strlen(answerstring), conn);
    conn->state = DIR_CONN_STATE_SERVER_WRITING;
    return 0;
  }

  log_fn(LOG_WARN,"Got headers with unknown command. Closing.");
  return -1;
}

int connection_dir_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(conn->state) {
    case DIR_CONN_STATE_CONNECTING_FETCH:
    case DIR_CONN_STATE_CONNECTING_UPLOAD:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, (void*)&e, &len) < 0)  { /* not yet */
        if(!ERRNO_CONN_EINPROGRESS(errno)) {
          log_fn(LOG_DEBUG,"in-progress connect failed. Removing.");
          router_mark_as_down(conn->nickname); /* don't try him again */
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_INFO,"Dir connection to router %s:%u established.",
          conn->address,conn->port);

      return directory_send_command(conn, conn->state);
    case DIR_CONN_STATE_CLIENT_SENDING_FETCH:
      log_fn(LOG_DEBUG,"client finished sending fetch command.");
      conn->state = DIR_CONN_STATE_CLIENT_READING_FETCH;
      connection_watch_events(conn, POLLIN);
      return 0;
    case DIR_CONN_STATE_CLIENT_SENDING_UPLOAD:
      log_fn(LOG_DEBUG,"client finished sending upload command.");
      conn->state = DIR_CONN_STATE_CLIENT_READING_UPLOAD;
      connection_watch_events(conn, POLLIN);
      return 0;
    case DIR_CONN_STATE_SERVER_WRITING:
      log_fn(LOG_INFO,"Finished writing server response. Closing.");
      return -1; /* kill it */
    default:
      log_fn(LOG_WARN,"BUG: called in unexpected state.");
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
