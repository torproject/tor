/* Copyright 2001,2002 Roger Dingledine, Matej Pfajfar. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

#define MAX_DIR_SIZE 50000 /* XXX, big enough? */

/********* START VARIABLES **********/

extern or_options_t options; /* command-line and config-file options */

static char the_directory[MAX_DIR_SIZE+1];
static int directorylen=0;
static int reading_headers=0;
static int directory_dirty=1;

static char getstring[] = "GET / HTTP/1.0\r\n\r\n";
static char answerstring[] = "HTTP/1.0 200 OK\r\n\r\n";

/********* END VARIABLES ************/

void directory_initiate_fetch(routerinfo_t *router) {
  connection_t *conn;
  struct sockaddr_in router_addr;
  int s;

  if(!router) /* i guess they didn't have one in mind for me to use */
    return;

  if(connection_get_by_type(CONN_TYPE_DIR)) /* there's already a fetch running */
    return;

  log(LOG_DEBUG,"directory_initiate_fetch(): initiating directory fetch");

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
    log(LOG_ERR, "No signing key known for directory %s; signature won't be checked", conn->address);
    conn->pkey = NULL;
  }

  s=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
  if(s < 0) { 
    log(LOG_ERR,"directory_initiate_fetch(): Error creating network socket.");
    connection_free(conn);
    return;
  }
  fcntl(s, F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  memset((void *)&router_addr,0,sizeof(router_addr));
  router_addr.sin_family = AF_INET;
  router_addr.sin_port = htons(router->dir_port);
  router_addr.sin_addr.s_addr = htonl(router->addr);

  log(LOG_DEBUG,"directory_initiate_fetch(): Trying to connect to %s:%u.",router->address,router->dir_port);

  if(connect(s,(struct sockaddr *)&router_addr,sizeof(router_addr)) < 0){
    if(errno != EINPROGRESS){
      /* yuck. kill it. */
      router_forget_router(conn->addr, conn->port); /* don't try him again */
      connection_free(conn);
      return;
    } else {
      /* it's in progress. set state appropriately and return. */
      conn->s = s;

      if(connection_add(conn) < 0) { /* no space, forget it */
        connection_free(conn);
        return;
      }

      log(LOG_DEBUG,"directory_initiate_fetch(): connect in progress.");
      connection_watch_events(conn, POLLIN | POLLOUT); /* writable indicates finish, readable indicates broken link */
      conn->state = DIR_CONN_STATE_CONNECTING;
      return;
    }
  }

  /* it succeeded. we're connected. */
  conn->s = s;

  if(connection_add(conn) < 0) { /* no space, forget it */
    connection_free(conn);
    return;
  }

  log(LOG_DEBUG,"directory_initiate_fetch(): Connection to router %s:%u established.",router->address,router->dir_port);

  if(directory_send_command(conn) < 0) {
    connection_remove(conn);
    connection_free(conn);
  }
}

int directory_send_command(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(connection_write_to_buf(getstring, strlen(getstring), conn) < 0) {
    log(LOG_DEBUG,"directory_send_command(): Couldn't write command to buffer.");
    return -1;
  }

  conn->state = DIR_CONN_STATE_SENDING_COMMAND;
  return 0;
}

void directory_set_dirty(void) {
  directory_dirty = 1;
}

void directory_rebuild(void) {
  if(directory_dirty) {
    if (dump_signed_directory_to_string(the_directory, MAX_DIR_SIZE,
                                        get_signing_privatekey())) {
      log(LOG_ERR, "Error writing directory");
      return;
    }
    log(LOG_INFO,"New directory:\n%s",the_directory);
    directorylen = strlen(the_directory);
    directory_dirty = 0;
  } else {
    log(LOG_INFO,"Directory still clean, reusing.");
  }
}

int connection_dir_process_inbuf(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(conn->inbuf_reached_eof) {
    if(conn->state != DIR_CONN_STATE_READING) {
      log(LOG_DEBUG,"connection_dir_process_inbuf(): conn reached eof, not reading. Closing.");
      return -1;
    }
    /* eof reached, kill it, but first process the_directory and learn about new routers. */
//    log(LOG_DEBUG,"connection_dir_process_inbuf(): conn reached eof. Processing directory.");
    log(LOG_DEBUG,"connection_dir_process_inbuf(): Received directory (size %d)\n%s", directorylen, the_directory);
    if(directorylen == 0) {
      log(LOG_DEBUG,"connection_dir_process_inbuf(): Empty directory. Ignoring.");
      return -1;
    }
    if(router_get_dir_from_string(the_directory, conn->pkey) < 0) {
      log(LOG_DEBUG,"connection_dir_process_inbuf(): ...but parsing failed. Ignoring.");
    } else {
      log(LOG_DEBUG,"connection_dir_process_inbuf(): and got a %s directory; updated routers.", 
          conn->pkey ? "authenticated" : "unauthenticated");
    }

    if(options.ORPort) { /* connect to them all */
      router_retry_connections();
    }
    return -1;
  }

  switch(conn->state) {
    case DIR_CONN_STATE_COMMAND_WAIT:
      return directory_handle_command(conn);
    case DIR_CONN_STATE_READING:
      return directory_handle_reading(conn);
    default:
      log(LOG_DEBUG,"connection_dir_process_inbuf(): Got data while writing; Ignoring.");
      break;
  }

  return 0;
}

int directory_handle_command(connection_t *conn) {
  char buf[15];

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(conn->inbuf_datalen < strlen(getstring)) { /* entire response available? */
    log(LOG_DEBUG,"directory_handle_command(): Entire command not here yet. Waiting.");
    return 0; /* not yet */
  }

  if(connection_fetch_from_buf(buf,strlen(getstring),conn) < 0) {
    return -1;    
  }

  if(strncasecmp(buf,getstring,strlen("GET / HTTP/"))) {
    log(LOG_DEBUG,"directory_handle_command(): Command doesn't seem to be a get. Closing,");
    return -1;
  }

  directory_rebuild(); /* rebuild it now, iff it's dirty */

  if(directorylen == 0) {
    log(LOG_DEBUG,"directory_handle_command(): My directory is empty. Closing.");
    return -1;
  }

  log(LOG_DEBUG,"directory_handle_command(): Dumping directory to client."); 
  if((connection_write_to_buf(answerstring, strlen(answerstring), conn) < 0) ||
     (connection_write_to_buf(the_directory, directorylen, conn) < 0)) {
    log(LOG_DEBUG,"directory_handle_command(): my outbuf is full. Oops.");
    return -1;
  }

  conn->state = DIR_CONN_STATE_WRITING;
  return 0;
}

int directory_handle_reading(connection_t *conn) {
  int amt;
  char *headers;

  assert(conn && conn->type == CONN_TYPE_DIR);

  if(reading_headers) {
    amt = connection_find_on_inbuf("\r\n\r\n", 4, conn);
    if(amt < 0) /* not there yet */
      return 0;
    headers = malloc(amt+1);
    if(connection_fetch_from_buf(headers,amt,conn) < 0) {
      log(LOG_DEBUG,"directory_handle_reading(): fetch_from_buf failed (reading headers).");
      return -1;
    }
    headers[amt] = 0; /* null terminate it, */
    free(headers); /* and then throw it away */
    reading_headers = 0;
  }

  amt = conn->inbuf_datalen;

  if(amt + directorylen >= MAX_DIR_SIZE) {
    log(LOG_DEBUG,"directory_handle_reading(): Directory too large. Failing messily.");
    return -1;
  }

  log(LOG_DEBUG,"directory_handle_reading(): Pulling %d bytes in at offset %d.",
    amt, directorylen);

  if(connection_fetch_from_buf(the_directory+directorylen,amt,conn) < 0) {
    log(LOG_DEBUG,"directory_handle_reading(): fetch_from_buf failed (reading dir).");
    return -1;    
  }

  directorylen += amt;

  the_directory[directorylen] = 0;

  return 0;
}

int connection_dir_finished_flushing(connection_t *conn) {
  int e, len=sizeof(e);

  assert(conn && conn->type == CONN_TYPE_DIR);

  switch(conn->state) {
    case DIR_CONN_STATE_CONNECTING:
      if (getsockopt(conn->s, SOL_SOCKET, SO_ERROR, &e, &len) < 0)  { /* not yet */
        if(errno != EINPROGRESS){
          /* yuck. kill it. */
          log(LOG_DEBUG,"connection_dir_finished_flushing(): in-progress connect failed. Removing.");
          router_forget_router(conn->addr, conn->port); /* don't try him again */
          return -1;
        } else {
          return 0; /* no change, see if next time is better */
        }
      }
      /* the connect has finished. */

      log(LOG_DEBUG,"connection_dir_finished_flushing(): Dir connection to router %s:%u established.",
          conn->address,conn->port);

      return directory_send_command(conn);
    case DIR_CONN_STATE_SENDING_COMMAND:
      log(LOG_DEBUG,"connection_dir_finished_flushing(): client finished sending command.");
      directorylen = 0;
      reading_headers = 1;
      conn->state = DIR_CONN_STATE_READING;
      connection_watch_events(conn, POLLIN);
      return 0;
    case DIR_CONN_STATE_WRITING:
      log(LOG_DEBUG,"connection_dir_finished_flushing(): Finished writing directory. Closing.");
      return -1; /* kill it */
    default:
      log(LOG_DEBUG,"Bug: connection_dir_finished_flushing() called in unexpected state.");
      return 0;
  }

  return 0;
}

int connection_dir_create_listener(struct sockaddr_in *bindaddr) {
  log(LOG_DEBUG,"connection_create_dir_listener starting");
  return connection_create_listener(bindaddr, CONN_TYPE_DIR_LISTENER);
}

int connection_dir_handle_listener_read(connection_t *conn) {
  log(LOG_INFO,"Dir: Received a connection request. Waiting for command.");
  return connection_handle_listener_read(conn, CONN_TYPE_DIR, DIR_CONN_STATE_COMMAND_WAIT);
} 

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
