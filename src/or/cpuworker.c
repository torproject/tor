/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"
extern or_options_t options; /* command-line and config-file options */

#define MAX_QUESTIONLEN 256

#define MAX_CPUWORKERS 17
#define MIN_CPUWORKERS 2

#define LEN_ONION_RESPONSE (1+DH_KEY_LEN+32)
#define LEN_HANDSHAKE_RESPONSE (somethingelse)

int num_cpuworkers=0;
int num_cpuworkers_busy=0;

int cpuworker_main(void *data);
static int spawn_cpuworker(void);
static void spawn_enough_cpuworkers(void);
static int process_pending_task(connection_t *cpuworker);

void cpu_init(void) {
  spawn_enough_cpuworkers();
}

int connection_cpu_finished_flushing(connection_t *conn) {
  assert(conn && conn->type == CONN_TYPE_CPUWORKER);
  connection_stop_writing(conn);
  return 0;
}

int connection_cpu_process_inbuf(connection_t *conn) {
  unsigned char buf[MAX_QUESTIONLEN];

  assert(conn && conn->type == CONN_TYPE_CPUWORKER);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_ERR,"Read eof. Worker dying.");
    if(conn->state != CPUWORKER_STATE_IDLE) {
      onion_pending_remove(conn->circ);
      circuit_close(conn->circ);
      conn->circ = NULL;
      num_cpuworkers_busy--;
    }
    num_cpuworkers--;
    return -1;
  }

  if(conn->state == CPUWORKER_STATE_BUSY_ONION) {
    assert(conn->circ);
    if(conn->inbuf_datalen < LEN_ONION_RESPONSE) /* entire answer available? */
      return 0; /* not yet */
    assert(conn->inbuf_datalen == LEN_ONION_RESPONSE);

    connection_fetch_from_buf(buf,LEN_ONION_RESPONSE,conn);

    if(*buf == 0 || conn->circ->p_conn == NULL ||
       onionskin_process(conn->circ, buf+1, buf+1+DH_KEY_LEN) < 0) {
      log_fn(LOG_DEBUG,"decoding onion, onionskin_process, or p_conn failed. Closing.");
//      onion_pending_remove(conn->circ);
      circuit_close(conn->circ);
    } else {
      log_fn(LOG_DEBUG,"onionskin_process succeeded. Yay.");
//      onion_pending_remove(conn->circ);
    }
    conn->circ = NULL;
  } else {
    assert(conn->state == CPUWORKER_STATE_BUSY_HANDSHAKE);

    assert(0); /* don't ask me to do handshakes yet */
  }

  conn->state = CPUWORKER_STATE_IDLE;
  num_cpuworkers_busy--;
  process_pending_task(conn); /* discard return value */
  return 0;
}

int cpuworker_main(void *data) {
  unsigned char question[MAX_QUESTIONLEN];
  unsigned char question_type;
  int *fdarray = data;
  int fd;
  int len;

  /* variables for onion processing */
  unsigned char keys[32];
  unsigned char response[DH_KEY_LEN];
  unsigned char buf[MAX_QUESTIONLEN];

  close(fdarray[0]); /* this is the side of the socketpair the parent uses */
  fd = fdarray[1]; /* this side is ours */

  for(;;) {

    if(read(fd, &question_type, 1) != 1) {
      log_fn(LOG_INFO,"read type failed. Exiting.");
      spawn_exit();
    }
    assert(question_type == CPUWORKER_TASK_ONION ||
           question_type == CPUWORKER_TASK_HANDSHAKE); 

    if(question_type == CPUWORKER_TASK_ONION)
      len = DH_ONIONSKIN_LEN;
    else
      len = 0; /* XXX */

    if(read(fd, question, len) != len) {
      log(LOG_INFO,"cpuworker_main(): read question failed. Exiting.");
      spawn_exit();
    }

    if(question_type == CPUWORKER_TASK_ONION) {
      if(onion_skin_server_handshake(question, get_privatekey(),
        response, keys, 32) < 0) {
        /* failure */
        log_fn(LOG_ERR,"onion_skin_server_handshake failed.");
        memset(buf,0,LEN_ONION_RESPONSE); /* send all zeros for failure */
      } else {
        /* success */
        log_fn(LOG_DEBUG,"onion_skin_server_handshake succeeded.");
        buf[0] = 1; /* 1 means success */
        memcpy(buf+1,response,DH_KEY_LEN);
        memcpy(buf+1+DH_KEY_LEN,keys,32);
      }
      if(write_all(fd, buf, LEN_ONION_RESPONSE) != LEN_ONION_RESPONSE) {
        log_fn(LOG_INFO,"writing response buf failed. Exiting.");
        spawn_exit();
      }
      log_fn(LOG_DEBUG,"finished writing response/keys.");
    } else { /* we've been asked to do a handshake. not implemented yet. */
      spawn_exit();
    }
  }
  return 0; /* windows wants this function to return an int */
}

static int spawn_cpuworker(void) {
  int fd[2];
  connection_t *conn;

  if(tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    perror("socketpair");
    exit(1);
  }

  spawn_func(cpuworker_main, (void*)fd);
  log_fn(LOG_DEBUG,"just spawned a worker.");
  close(fd[1]); /* we don't need the worker's side of the pipe */

  conn = connection_new(CONN_TYPE_CPUWORKER);
  if(!conn) {
    close(fd[0]);
    return -1;
  }

  set_socket_nonblocking(fd[0]);

  /* set up conn so it's got all the data we need to remember */
  conn->receiver_bucket = -1; /* non-cell connections don't do receiver buckets */
  conn->bandwidth = -1;
  conn->s = fd[0];

  if(connection_add(conn) < 0) { /* no space, forget it */
    log_fn(LOG_INFO,"connection_add failed. Giving up.");
    connection_free(conn); /* this closes fd[0] */
    return -1;
  }

  conn->state = CPUWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

static void spawn_enough_cpuworkers(void) {
  int num_cpuworkers_needed = options.NumCpus + 1;

  if(num_cpuworkers_needed < MIN_CPUWORKERS)
    num_cpuworkers_needed = MIN_CPUWORKERS;
  if(num_cpuworkers_needed > MAX_CPUWORKERS)
    num_cpuworkers_needed = MAX_CPUWORKERS;

  while(num_cpuworkers < num_cpuworkers_needed) {
    if(spawn_cpuworker() < 0) {
      log_fn(LOG_ERR,"spawn failed!");
      return;
    }
    num_cpuworkers++;
  }
}


static int process_pending_task(connection_t *cpuworker) {
  circuit_t *circ;

  assert(cpuworker);

  /* for now only process onion tasks */

  circ = onion_next_task();
  if(!circ)
    return 0;
  return assign_to_cpuworker(cpuworker, CPUWORKER_TASK_ONION, circ);
}

/* if cpuworker is defined, assert that he's idle, and use him. else,
 * look for an idle cpuworker and use him. if none idle, queue task onto
 * the pending onion list and return.
 * If question_type is CPUWORKER_TASK_ONION then task is a circ, else
 * (something else)
 */
int assign_to_cpuworker(connection_t *cpuworker, unsigned char question_type,
                        void *task) {
  circuit_t *circ;

  if(question_type == CPUWORKER_TASK_ONION) {
    circ = task;

    if(num_cpuworkers_busy == num_cpuworkers) {
      log_fn(LOG_DEBUG,"No idle cpuworkers. Queuing.");
      if(onion_pending_add(circ) < 0)
        return -1;
      return 0;
    }

    if(!cpuworker)
      cpuworker = connection_get_by_type_state(CONN_TYPE_CPUWORKER, CPUWORKER_STATE_IDLE);

    assert(cpuworker);

    cpuworker->circ = circ;
    cpuworker->state = CPUWORKER_STATE_BUSY_ONION;
    num_cpuworkers_busy++;

    if(connection_write_to_buf(&question_type, 1, cpuworker) < 0 ||
       connection_write_to_buf(circ->onionskin, DH_ONIONSKIN_LEN, cpuworker) < 0) {
      log_fn(LOG_NOTICE,"Write failed. Closing worker and failing circ.");
      cpuworker->marked_for_close = 1;
      return -1;
    }
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

