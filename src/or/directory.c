/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

#define MAX_DIR_SIZE 50000 /* XXX, big enough? */

static int directory_send_command(connection_t *conn, int command);
static void directory_rebuild(void);
static int directory_handle_command(connection_t *conn);

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

static char the_directory[MAX_DIR_SIZE+1];
static int directorylen=0;
static int directory_dirty=1;

static char fetchstring[] = "GET / HTTP/1.0\r\n\r\n";
static char uploadstring[] = "POST / HTTP/1.0\r\n\r\n";
static char answerstring[] = "HTTP/1.0 200 OK\r\n\r\n";

/********* END VARIABLES ************/

void directory_initiate_command(routerinfo_t *router, int command) {
  connection_t *conn;

  if(!router) /* i guess they didn't have one in mind for me to use */
    return;

#if 0 /* there's no problem with parallel get/posts now. whichever 'get' ends
         last is the directory. */
  if(connection_get_by_type(CONN_TYPE_DIR)) { /* there's already a dir conn running */
    log_fn(LOG_DEBUG,"Canceling connect, dir conn already active.");
    return;
  }
#endif

  if(command == DIR_CONN_STATE_CONNECTING_FETCH)
    log_fn(LOG_DEBUG,"initiating directory fetch");
  else
    log_fn(LOG_DEBUG,"initiating directory upload");

  conn = connection_new(CONN_TYPE_DIR);
  if(!conn)
    return;

  /* set up conn so it's got all the data we need to remember */
  conn->addr = router->addr;
  conn->port = router->dir_port;
  conn->address = strdup(router->address);
  conn->receiver_bucket = -1; /* edge connections don't do receiver buckets */
  conn->bandwidth = -1;
  if (router->signing_pkey)
    conn->pkey = crypto_pk_dup_key(router->signing_pkey);
  else {
    log_fn(LOG_ERR, "No signing key known for dirserver %s; signature won't be checked", conn->address);
    conn->pkey = NULL;
  }

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return;
  }

  switch(connection_connect(conn, router->address, router->addr, router->dir_port)) {
    case -1:
      router_forget_router(conn->addr, conn->port); /* XXX don't try him again */
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
  char *s;

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(command) {
    case DIR_CONN_STATE_CONNECTING_FETCH:
      if(connection_write_to_buf(fetchstring, strlen(fetchstring), conn) < 0) {
        log_fn(LOG_DEBUG,"Couldn't write fetch to buffer.");
        return -1;
      }
      conn->state = DIR_CONN_STATE_CLIENT_SENDING_FETCH;
      break;
    case DIR_CONN_STATE_CONNECTING_UPLOAD:
      s = router_get_my_descriptor();
      if(!s) {
        log_fn(LOG_DEBUG,"Failed to get my descriptor.");
        return -1;
      }
      if(connection_write_to_buf(uploadstring, strlen(uploadstring), conn) < 0 ||
         connection_write_to_buf(s, strlen(s), conn) < 0) {
        log_fn(LOG_DEBUG,"Couldn't write post/descriptor to buffer.");
        return -1;
      }
      conn->state = DIR_CONN_STATE_CLIENT_SENDING_UPLOAD;
      break;
  }
  return 0;
}

void directory_set_dirty(void) {
  directory_dirty = 1;
}

static void directory_rebuild(void) {
  if(directory_dirty) {
    if (dump_signed_directory_to_string(the_directory, MAX_DIR_SIZE,
                                        get_signing_privatekey())) {
      log(LOG_ERR, "Error writing directory");
      return;
    }
    directorylen = strlen(the_directory);
    log(LOG_INFO,"New directory (size %d):\n%s",directorylen,the_directory);
    directory_dirty = 0;
  } else {
    log(LOG_INFO,"Directory still clean, reusing.");
  }
}

int connection_dir_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(conn->inbuf_reached_eof) {
    switch(conn->state) {
      case DIR_CONN_STATE_CLIENT_READING_FETCH:
        /* kill it, but first process the_directory and learn about new routers. */
        switch(fetch_from_buf_http(conn->inbuf,&conn->inbuf_datalen,
                                   NULL, 0, the_directory, MAX_DIR_SIZE)) {
          case -1: /* overflow */
            log_fn(LOG_DEBUG,"'fetch' response too large. Failing.");
            return -1;
          case 0:
            log_fn(LOG_DEBUG,"'fetch' response not all here, but we're at eof. Closing.");
            return -1;
          /* case 1, fall through */
        }
        /* XXX check headers, at least make sure returned 2xx */
        directorylen = strlen(the_directory);
        log_fn(LOG_DEBUG,"Received directory (size %d):\n%s", directorylen, the_directory);
        if(directorylen == 0) {
          log_fn(LOG_DEBUG,"Empty directory. Ignoring.");
          return -1;
        }
        if(router_get_dir_from_string(the_directory, conn->pkey) < 0) {
          log_fn(LOG_DEBUG,"...but parsing failed. Ignoring.");
        } else {
          log_fn(LOG_DEBUG,"and got an %s directory; updated routers.", 
              conn->pkey ? "authenticated" : "unauthenticated");
        }
        if(options.OnionRouter) { /* connect to them all */
          router_retry_connections();
        }
        return -1;
      case DIR_CONN_STATE_CLIENT_READING_UPLOAD:
        /* XXX make sure there's a 200 OK on the buffer */
        log_fn(LOG_DEBUG,"eof while reading upload response. Finished.");
        return -1;
      default:
        log_fn(LOG_DEBUG,"conn reached eof, not reading. Closing.");
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
  char body[1024];

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(fetch_from_buf_http(conn->inbuf,&conn->inbuf_datalen,
                             headers, sizeof(headers), body, sizeof(body))) {
    case -1: /* overflow */
      log_fn(LOG_DEBUG,"input too large. Failing.");
      return -1;
    case 0:
      log_fn(LOG_DEBUG,"command not all here yet.");
      return 0;
    /* case 1, fall through */
  }

  log_fn(LOG_DEBUG,"headers '%s', body '%s'.",headers,body);
  if(!strncasecmp(headers,"GET",3)) {
    /* XXX should check url and http version */

    directory_rebuild(); /* rebuild it now, iff it's dirty */

    if(directorylen == 0) {
      log_fn(LOG_DEBUG,"My directory is empty. Closing.");
      return -1;
    }

    log_fn(LOG_DEBUG,"Dumping directory to client."); 
    if((connection_write_to_buf(answerstring, strlen(answerstring), conn) < 0) ||
       (connection_write_to_buf(the_directory, directorylen, conn) < 0)) {
      log_fn(LOG_DEBUG,"Failed to write answerstring+directory to outbuf.");
      return -1;
    }
    conn->state = DIR_CONN_STATE_SERVER_WRITING;
    return 0;
  }

  if(!strncasecmp(headers,"POST",4)) {
    /* XXX should check url and http version */
    log_fn(LOG_DEBUG,"Received POST command, body '%s'", body);
    if(connection_write_to_buf(answerstring, strlen(answerstring), conn) < 0) {
      log_fn(LOG_DEBUG,"Failed to write answerstring to outbuf.");
      return -1;
    }
    conn->state = DIR_CONN_STATE_SERVER_WRITING;
    return 0;
  }

  log_fn(LOG_DEBUG,"Got headers with unknown command. Closing.");
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
          router_forget_router(conn->addr, conn->port); /* don't try him again */
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log_fn(LOG_DEBUG,"Dir connection to router %s:%u established.",
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
      log_fn(LOG_DEBUG,"Finished writing server response. Closing.");
      return -1; /* kill it */
    default:
      log_fn(LOG_DEBUG,"BUG: called in unexpected state.");
      return 0;
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
