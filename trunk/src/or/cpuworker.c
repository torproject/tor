/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"
extern or_options_t options; /* command-line and config-file options */

#define MAX_CPUWORKERS 17
#define MIN_CPUWORKERS 1

#define TAG_LEN 8
#define LEN_ONION_QUESTION (1+TAG_LEN+DH_ONIONSKIN_LEN)
#define LEN_ONION_RESPONSE (1+TAG_LEN+DH_KEY_LEN+32)

int num_cpuworkers=0;
int num_cpuworkers_busy=0;

int cpuworker_main(void *data);
static int spawn_cpuworker(void);
static void spawn_enough_cpuworkers(void);
static void process_pending_task(connection_t *cpuworker);

void cpu_init(void) {
  spawn_enough_cpuworkers();
}

int connection_cpu_finished_flushing(connection_t *conn) {
  assert(conn && conn->type == CONN_TYPE_CPUWORKER);
  connection_stop_writing(conn);
  return 0;
}

static void tag_pack(char *tag, uint32_t addr, uint16_t port, aci_t aci) {
  *(uint32_t *)tag = addr;
  *(uint16_t *)(tag+4) = port;
  *(aci_t *)(tag+6) = aci;
}

static void tag_unpack(char *tag, uint32_t *addr, uint16_t *port, aci_t *aci) {
  struct in_addr in;

  *addr = *(uint32_t *)tag;
  *port = *(uint16_t *)(tag+4);
  *aci = *(aci_t *)(tag+6);

  in.s_addr = htonl(*addr);
  log_fn(LOG_DEBUG,"onion was from %s:%d, aci %d.", inet_ntoa(in), *port, *aci);
}

int connection_cpu_process_inbuf(connection_t *conn) {
  unsigned char buf[LEN_ONION_RESPONSE];
  uint32_t addr;
  uint16_t port;
  aci_t aci;
  connection_t *p_conn;
  circuit_t *circ;

  assert(conn && conn->type == CONN_TYPE_CPUWORKER);

  if(conn->inbuf_reached_eof) {
    log_fn(LOG_WARNING,"Read eof. Worker dying.");
    if(conn->state != CPUWORKER_STATE_IDLE) {
      /* XXX the circ associated with this cpuworker will wait forever. Oops. */
      num_cpuworkers_busy--;
    }
    num_cpuworkers--;
    return -1;
  }

  if(conn->state == CPUWORKER_STATE_BUSY_ONION) {
    if(buf_datalen(conn->inbuf) < LEN_ONION_RESPONSE) /* entire answer available? */
      return 0; /* not yet */
    assert(buf_datalen(conn->inbuf) == LEN_ONION_RESPONSE);

    connection_fetch_from_buf(buf,LEN_ONION_RESPONSE,conn);

    /* parse out the circ it was talking about */
    tag_unpack(buf+1, &addr, &port, &aci);
    circ = NULL;
    p_conn = connection_exact_get_by_addr_port(addr,port);
    if(p_conn)
      circ = circuit_get_by_aci_conn(aci, p_conn);

    if(!circ) {
      log_fn(LOG_INFO,"processed onion for a circ that's gone. Dropping.");
      goto done_processing;
    }
    assert(circ->p_conn);
    if(*buf == 0) {
      log_fn(LOG_WARNING,"decoding onionskin failed. Closing.");
      circuit_close(circ);
      goto done_processing;
    }
    if(onionskin_answer(circ, buf+1+TAG_LEN, buf+1+TAG_LEN+DH_KEY_LEN) < 0) {
      log_fn(LOG_WARNING,"onionskin_answer failed. Closing.");
      circuit_close(circ);
      goto done_processing;
    }
    log_fn(LOG_DEBUG,"onionskin_answer succeeded. Yay.");
  } else {
    assert(0); /* don't ask me to do handshakes yet */
  }

done_processing:
  conn->state = CPUWORKER_STATE_IDLE;
  num_cpuworkers_busy--;
  process_pending_task(conn);
  return 0;
}

int cpuworker_main(void *data) {
  unsigned char question[DH_ONIONSKIN_LEN];
  unsigned char question_type;
  int *fdarray = data;
  int fd;

  /* variables for onion processing */
  unsigned char keys[32];
  unsigned char reply_to_proxy[DH_KEY_LEN];
  unsigned char buf[LEN_ONION_RESPONSE];
  char tag[TAG_LEN];

  close(fdarray[0]); /* this is the side of the socketpair the parent uses */
  fd = fdarray[1]; /* this side is ours */

  for(;;) {

    if(read(fd, &question_type, 1) != 1) {
      log_fn(LOG_ERR,"read type failed. Exiting.");
      spawn_exit();
    }
    assert(question_type == CPUWORKER_TASK_ONION);

    if(read_all(fd, tag, TAG_LEN) != TAG_LEN) {
      log_fn(LOG_ERR,"read tag failed. Exiting.");
      spawn_exit();
    }

    if(read_all(fd, question, DH_ONIONSKIN_LEN) != DH_ONIONSKIN_LEN) {
      log_fn(LOG_ERR,"read question failed. Exiting.");
      spawn_exit();
    }

    if(question_type == CPUWORKER_TASK_ONION) {
      if(onion_skin_server_handshake(question, get_onion_key(),
        reply_to_proxy, keys, 32) < 0) {
        /* failure */
        log_fn(LOG_WARNING,"onion_skin_server_handshake failed.");
        memset(buf,0,LEN_ONION_RESPONSE); /* send all zeros for failure */
      } else {
        /* success */
        log_fn(LOG_INFO,"onion_skin_server_handshake succeeded.");
        buf[0] = 1; /* 1 means success */
        memcpy(buf+1,tag,TAG_LEN);
        memcpy(buf+1+TAG_LEN,reply_to_proxy,DH_KEY_LEN);
        memcpy(buf+1+TAG_LEN+DH_KEY_LEN,keys,32);
      }
      if(write_all(fd, buf, LEN_ONION_RESPONSE) != LEN_ONION_RESPONSE) {
        log_fn(LOG_ERR,"writing response buf failed. Exiting.");
        spawn_exit();
      }
      log_fn(LOG_DEBUG,"finished writing response.");
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

  set_socket_nonblocking(fd[0]);

  /* set up conn so it's got all the data we need to remember */
  conn->s = fd[0];
  conn->address = strdup("localhost");

  if(connection_add(conn) < 0) { /* no space, forget it */
    log_fn(LOG_WARNING,"connection_add failed. Giving up.");
    connection_free(conn); /* this closes fd[0] */
    return -1;
  }

  conn->state = CPUWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

static void spawn_enough_cpuworkers(void) {
  int num_cpuworkers_needed = options.NumCpus;

  if(num_cpuworkers_needed < MIN_CPUWORKERS)
    num_cpuworkers_needed = MIN_CPUWORKERS;
  if(num_cpuworkers_needed > MAX_CPUWORKERS)
    num_cpuworkers_needed = MAX_CPUWORKERS;

  while(num_cpuworkers < num_cpuworkers_needed) {
    if(spawn_cpuworker() < 0) {
      log_fn(LOG_WARNING,"spawn failed!");
      return;
    }
    num_cpuworkers++;
  }
}


static void process_pending_task(connection_t *cpuworker) {
  circuit_t *circ;

  assert(cpuworker);

  /* for now only process onion tasks */

  circ = onion_next_task();
  if(!circ)
    return;
  if(assign_to_cpuworker(cpuworker, CPUWORKER_TASK_ONION, circ) < 0)
    log_fn(LOG_WARNING,"assign_to_cpuworker failed. Ignoring.");
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
  char tag[TAG_LEN];

  assert(question_type == CPUWORKER_TASK_ONION);

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

    if(!circ->p_conn) {
      log_fn(LOG_INFO,"circ->p_conn gone. Failing circ.");
      return -1;
    }
    tag_pack(tag, circ->p_conn->addr, circ->p_conn->port, circ->p_aci);

    cpuworker->state = CPUWORKER_STATE_BUSY_ONION;
    num_cpuworkers_busy++;

    connection_write_to_buf(&question_type, 1, cpuworker);
    connection_write_to_buf(tag, sizeof(tag), cpuworker);
    connection_write_to_buf(circ->onionskin, DH_ONIONSKIN_LEN, cpuworker);
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

