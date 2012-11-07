/* Copyright (c) 2003-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file cpuworker.c
 * \brief Implements a farm of 'CPU worker' processes to perform
 * CPU-intensive tasks in another thread or process, to not
 * interrupt the main thread.
 *
 * Right now, we only use this for processing onionskins.
 **/

#include "or.h"
#include "buffers.h"
#include "channel.h"
#include "channeltls.h"
#include "circuitbuild.h"
#include "circuitlist.h"
#include "config.h"
#include "connection.h"
#include "cpuworker.h"
#include "main.h"
#include "onion.h"
#include "router.h"

/** The maximum number of cpuworker processes we will keep around. */
#define MAX_CPUWORKERS 16
/** The minimum number of cpuworker processes we will keep around. */
#define MIN_CPUWORKERS 1

/** The tag specifies which circuit this onionskin was from. */
#define TAG_LEN 12
/** How many bytes are sent from the cpuworker back to tor? */
#define LEN_ONION_RESPONSE \
  (1+TAG_LEN+ONIONSKIN_REPLY_LEN+CPATH_KEY_MATERIAL_LEN)

/** How many cpuworkers we have running right now. */
static int num_cpuworkers=0;
/** How many of the running cpuworkers have an assigned task right now. */
static int num_cpuworkers_busy=0;
/** We need to spawn new cpuworkers whenever we rotate the onion keys
 * on platforms where execution contexts==processes.  This variable stores
 * the last time we got a key rotation event. */
static time_t last_rotation_time=0;

static void cpuworker_main(void *data) ATTR_NORETURN;
static int spawn_cpuworker(void);
static void spawn_enough_cpuworkers(void);
static void process_pending_task(connection_t *cpuworker);

/** Initialize the cpuworker subsystem.
 */
void
cpu_init(void)
{
  cpuworkers_rotate();
}

/** Called when we're done sending a request to a cpuworker. */
int
connection_cpu_finished_flushing(connection_t *conn)
{
  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CPUWORKER);
  return 0;
}

/** Pack global_id and circ_id; set *tag to the result. (See note on
 * cpuworker_main for wire format.) */
static void
tag_pack(char *tag, uint64_t chan_id, circid_t circ_id)
{
  /*XXXX RETHINK THIS WHOLE MESS !!!! !NM NM NM NM*/
  /*XXXX DOUBLEPLUSTHIS!!!! AS AS AS AS*/
  set_uint64(tag, chan_id);
  set_uint32(tag+8, circ_id);
}

/** Unpack <b>tag</b> into addr, port, and circ_id.
 */
static void
tag_unpack(const char *tag, uint64_t *chan_id, circid_t *circ_id)
{
  *chan_id = get_uint64(tag);
  *circ_id = get_uint32(tag+8);
}

/** Called when the onion key has changed and we need to spawn new
 * cpuworkers.  Close all currently idle cpuworkers, and mark the last
 * rotation time as now.
 */
void
cpuworkers_rotate(void)
{
  connection_t *cpuworker;
  while ((cpuworker = connection_get_by_type_state(CONN_TYPE_CPUWORKER,
                                                   CPUWORKER_STATE_IDLE))) {
    connection_mark_for_close(cpuworker);
    --num_cpuworkers;
  }
  last_rotation_time = time(NULL);
  if (server_mode(get_options()))
    spawn_enough_cpuworkers();
}

/** If the cpuworker closes the connection,
 * mark it as closed and spawn a new one as needed. */
int
connection_cpu_reached_eof(connection_t *conn)
{
  log_warn(LD_GENERAL,"Read eof. CPU worker died unexpectedly.");
  if (conn->state != CPUWORKER_STATE_IDLE) {
    /* the circ associated with this cpuworker will have to wait until
     * it gets culled in run_connection_housekeeping(), since we have
     * no way to find out which circ it was. */
    log_warn(LD_GENERAL,"...and it left a circuit queued; abandoning circ.");
    num_cpuworkers_busy--;
  }
  num_cpuworkers--;
  spawn_enough_cpuworkers(); /* try to regrow. hope we don't end up
                                spinning. */
  connection_mark_for_close(conn);
  return 0;
}

/** Called when we get data from a cpuworker.  If the answer is not complete,
 * wait for a complete answer. If the answer is complete,
 * process it as appropriate.
 */
int
connection_cpu_process_inbuf(connection_t *conn)
{
  char success;
  char buf[LEN_ONION_RESPONSE];
  uint64_t chan_id;
  circid_t circ_id;
  channel_t *p_chan = NULL;
  circuit_t *circ;

  tor_assert(conn);
  tor_assert(conn->type == CONN_TYPE_CPUWORKER);

  if (!connection_get_inbuf_len(conn))
    return 0;

  if (conn->state == CPUWORKER_STATE_BUSY_ONION) {
    if (connection_get_inbuf_len(conn) < LEN_ONION_RESPONSE)
      return 0; /* not yet */
    tor_assert(connection_get_inbuf_len(conn) == LEN_ONION_RESPONSE);

    connection_fetch_from_buf(&success,1,conn);
    connection_fetch_from_buf(buf,LEN_ONION_RESPONSE-1,conn);

    /* parse out the circ it was talking about */
    tag_unpack(buf, &chan_id, &circ_id);
    circ = NULL;
    log_debug(LD_OR,
              "Unpacking cpuworker reply, chan_id is " U64_FORMAT
              ", circ_id is %d",
              U64_PRINTF_ARG(chan_id), circ_id);
    p_chan = channel_find_by_global_id(chan_id);

    if (p_chan)
      circ = circuit_get_by_circid_channel(circ_id, p_chan);

    if (success == 0) {
      log_debug(LD_OR,
                "decoding onionskin failed. "
                "(Old key or bad software.) Closing.");
      if (circ)
        circuit_mark_for_close(circ, END_CIRC_REASON_TORPROTOCOL);
      goto done_processing;
    }
    if (!circ) {
      /* This happens because somebody sends us a destroy cell and the
       * circuit goes away, while the cpuworker is working. This is also
       * why our tag doesn't include a pointer to the circ, because we'd
       * never know if it's still valid.
       */
      log_debug(LD_OR,"processed onion for a circ that's gone. Dropping.");
      goto done_processing;
    }
    tor_assert(! CIRCUIT_IS_ORIGIN(circ));
    if (onionskin_answer(TO_OR_CIRCUIT(circ), CELL_CREATED, buf+TAG_LEN,
                         buf+TAG_LEN+ONIONSKIN_REPLY_LEN) < 0) {
      log_warn(LD_OR,"onionskin_answer failed. Closing.");
      circuit_mark_for_close(circ, END_CIRC_REASON_INTERNAL);
      goto done_processing;
    }
    log_debug(LD_OR,"onionskin_answer succeeded. Yay.");
  } else {
    tor_assert(0); /* don't ask me to do handshakes yet */
  }

 done_processing:
  conn->state = CPUWORKER_STATE_IDLE;
  num_cpuworkers_busy--;
  if (conn->timestamp_created < last_rotation_time) {
    connection_mark_for_close(conn);
    num_cpuworkers--;
    spawn_enough_cpuworkers();
  } else {
    process_pending_task(conn);
  }
  return 0;
}

/** Implement a cpuworker.  'data' is an fdarray as returned by socketpair.
 * Read and writes from fdarray[1].  Reads requests, writes answers.
 *
 *   Request format:
 *          Task type           [1 byte, always CPUWORKER_TASK_ONION]
 *          Opaque tag          TAG_LEN
 *          Onionskin challenge ONIONSKIN_CHALLENGE_LEN
 *   Response format:
 *          Success/failure     [1 byte, boolean.]
 *          Opaque tag          TAG_LEN
 *          Onionskin challenge ONIONSKIN_REPLY_LEN
 *          Negotiated keys     KEY_LEN*2+DIGEST_LEN*2
 *
 *  (Note: this _should_ be by addr/port, since we're concerned with specific
 * connections, not with routers (where we'd use identity).)
 */
static void
cpuworker_main(void *data)
{
  char question[ONIONSKIN_CHALLENGE_LEN];
  uint8_t question_type;
  tor_socket_t *fdarray = data;
  tor_socket_t fd;

  /* variables for onion processing */
  char keys[CPATH_KEY_MATERIAL_LEN];
  char reply_to_proxy[ONIONSKIN_REPLY_LEN];
  char buf[LEN_ONION_RESPONSE];
  char tag[TAG_LEN];
  crypto_pk_t *onion_key = NULL, *last_onion_key = NULL;

  fd = fdarray[1]; /* this side is ours */
#ifndef TOR_IS_MULTITHREADED
  tor_close_socket(fdarray[0]); /* this is the side of the socketpair the
                                 * parent uses */
  tor_free_all(1); /* so the child doesn't hold the parent's fd's open */
  handle_signals(0); /* ignore interrupts from the keyboard, etc */
#endif
  tor_free(data);

  dup_onion_keys(&onion_key, &last_onion_key);

  for (;;) {
    ssize_t r;

    if ((r = recv(fd, (void *)&question_type, 1, 0)) != 1) {
//      log_fn(LOG_ERR,"read type failed. Exiting.");
      if (r == 0) {
        log_info(LD_OR,
                 "CPU worker exiting because Tor process closed connection "
                 "(either rotated keys or died).");
      } else {
        log_info(LD_OR,
                 "CPU worker exiting because of error on connection to Tor "
                 "process.");
        log_info(LD_OR,"(Error on %d was %s)",
                 fd, tor_socket_strerror(tor_socket_errno(fd)));
      }
      goto end;
    }
    tor_assert(question_type == CPUWORKER_TASK_ONION);

    if (read_all(fd, tag, TAG_LEN, 1) != TAG_LEN) {
      log_err(LD_BUG,"read tag failed. Exiting.");
      goto end;
    }

    if (read_all(fd, question, ONIONSKIN_CHALLENGE_LEN, 1) !=
        ONIONSKIN_CHALLENGE_LEN) {
      log_err(LD_BUG,"read question failed. Exiting.");
      goto end;
    }

    if (question_type == CPUWORKER_TASK_ONION) {
      if (onion_skin_server_handshake(question, onion_key, last_onion_key,
          reply_to_proxy, keys, CPATH_KEY_MATERIAL_LEN) < 0) {
        /* failure */
        log_debug(LD_OR,"onion_skin_server_handshake failed.");
        *buf = 0; /* indicate failure in first byte */
        memcpy(buf+1,tag,TAG_LEN);
        /* send all zeros as answer */
        memset(buf+1+TAG_LEN, 0, LEN_ONION_RESPONSE-(1+TAG_LEN));
      } else {
        /* success */
        log_debug(LD_OR,"onion_skin_server_handshake succeeded.");
        buf[0] = 1; /* 1 means success */
        memcpy(buf+1,tag,TAG_LEN);
        memcpy(buf+1+TAG_LEN,reply_to_proxy,ONIONSKIN_REPLY_LEN);
        memcpy(buf+1+TAG_LEN+ONIONSKIN_REPLY_LEN,keys,CPATH_KEY_MATERIAL_LEN);
      }
      if (write_all(fd, buf, LEN_ONION_RESPONSE, 1) != LEN_ONION_RESPONSE) {
        log_err(LD_BUG,"writing response buf failed. Exiting.");
        goto end;
      }
      log_debug(LD_OR,"finished writing response.");
    }
  }
 end:
  if (onion_key)
    crypto_pk_free(onion_key);
  if (last_onion_key)
    crypto_pk_free(last_onion_key);
  tor_close_socket(fd);
  crypto_thread_cleanup();
  spawn_exit();
}

/** Launch a new cpuworker. Return 0 if we're happy, -1 if we failed.
 */
static int
spawn_cpuworker(void)
{
  tor_socket_t *fdarray;
  tor_socket_t fd;
  connection_t *conn;
  int err;

  fdarray = tor_malloc(sizeof(tor_socket_t)*2);
  if ((err = tor_socketpair(AF_UNIX, SOCK_STREAM, 0, fdarray)) < 0) {
    log_warn(LD_NET, "Couldn't construct socketpair for cpuworker: %s",
             tor_socket_strerror(-err));
    tor_free(fdarray);
    return -1;
  }

  tor_assert(SOCKET_OK(fdarray[0]));
  tor_assert(SOCKET_OK(fdarray[1]));

  fd = fdarray[0];
  spawn_func(cpuworker_main, (void*)fdarray);
  log_debug(LD_OR,"just spawned a cpu worker.");
#ifndef TOR_IS_MULTITHREADED
  tor_close_socket(fdarray[1]); /* don't need the worker's side of the pipe */
  tor_free(fdarray);
#endif

  conn = connection_new(CONN_TYPE_CPUWORKER, AF_UNIX);

  set_socket_nonblocking(fd);

  /* set up conn so it's got all the data we need to remember */
  conn->s = fd;
  conn->address = tor_strdup("localhost");
  tor_addr_make_unspec(&conn->addr);

  if (connection_add(conn) < 0) { /* no space, forget it */
    log_warn(LD_NET,"connection_add for cpuworker failed. Giving up.");
    connection_free(conn); /* this closes fd */
    return -1;
  }

  conn->state = CPUWORKER_STATE_IDLE;
  connection_start_reading(conn);

  return 0; /* success */
}

/** If we have too few or too many active cpuworkers, try to spawn new ones
 * or kill idle ones.
 */
static void
spawn_enough_cpuworkers(void)
{
  int num_cpuworkers_needed = get_num_cpus(get_options());

  if (num_cpuworkers_needed < MIN_CPUWORKERS)
    num_cpuworkers_needed = MIN_CPUWORKERS;
  if (num_cpuworkers_needed > MAX_CPUWORKERS)
    num_cpuworkers_needed = MAX_CPUWORKERS;

  while (num_cpuworkers < num_cpuworkers_needed) {
    if (spawn_cpuworker() < 0) {
      log_warn(LD_GENERAL,"Cpuworker spawn failed. Will try again later.");
      return;
    }
    num_cpuworkers++;
  }
}

/** Take a pending task from the queue and assign it to 'cpuworker'. */
static void
process_pending_task(connection_t *cpuworker)
{
  or_circuit_t *circ;
  char *onionskin = NULL;

  tor_assert(cpuworker);

  /* for now only process onion tasks */

  circ = onion_next_task(&onionskin);
  if (!circ)
    return;
  if (assign_onionskin_to_cpuworker(cpuworker, circ, onionskin))
    log_warn(LD_OR,"assign_to_cpuworker failed. Ignoring.");
}

/** How long should we let a cpuworker stay busy before we give
 * up on it and decide that we have a bug or infinite loop?
 * This value is high because some servers with low memory/cpu
 * sometimes spend an hour or more swapping, and Tor starves. */
#define CPUWORKER_BUSY_TIMEOUT (60*60*12)

/** We have a bug that I can't find. Sometimes, very rarely, cpuworkers get
 * stuck in the 'busy' state, even though the cpuworker process thinks of
 * itself as idle. I don't know why. But here's a workaround to kill any
 * cpuworker that's been busy for more than CPUWORKER_BUSY_TIMEOUT.
 */
static void
cull_wedged_cpuworkers(void)
{
  time_t now = time(NULL);
  smartlist_t *conns = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(conns, connection_t *, conn) {
    if (!conn->marked_for_close &&
        conn->type == CONN_TYPE_CPUWORKER &&
        conn->state == CPUWORKER_STATE_BUSY_ONION &&
        conn->timestamp_lastwritten + CPUWORKER_BUSY_TIMEOUT < now) {
      log_notice(LD_BUG,
                 "closing wedged cpuworker. Can somebody find the bug?");
      num_cpuworkers_busy--;
      num_cpuworkers--;
      connection_mark_for_close(conn);
    }
  } SMARTLIST_FOREACH_END(conn);
}

/** Try to tell a cpuworker to perform the public key operations necessary to
 * respond to <b>onionskin</b> for the circuit <b>circ</b>.
 *
 * If <b>cpuworker</b> is defined, assert that he's idle, and use him. Else,
 * look for an idle cpuworker and use him. If none idle, queue task onto the
 * pending onion list and return.  Return 0 if we successfully assign the
 * task, or -1 on failure.
 */
int
assign_onionskin_to_cpuworker(connection_t *cpuworker,
                              or_circuit_t *circ, char *onionskin)
{
  char qbuf[1];
  char tag[TAG_LEN];
  time_t now = approx_time();
  static time_t last_culled_cpuworkers = 0;

  /* Checking for wedged cpuworkers requires a linear search over all
   * connections, so let's do it only once a minute.
   */
#define CULL_CPUWORKERS_INTERVAL 60

  if (last_culled_cpuworkers + CULL_CPUWORKERS_INTERVAL <= now) {
    cull_wedged_cpuworkers();
    spawn_enough_cpuworkers();
    last_culled_cpuworkers = now;
  }

  if (1) {
    if (num_cpuworkers_busy == num_cpuworkers) {
      log_debug(LD_OR,"No idle cpuworkers. Queuing.");
      if (onion_pending_add(circ, onionskin) < 0) {
        tor_free(onionskin);
        return -1;
      }
      return 0;
    }

    if (!cpuworker)
      cpuworker = connection_get_by_type_state(CONN_TYPE_CPUWORKER,
                                               CPUWORKER_STATE_IDLE);

    tor_assert(cpuworker);

    if (!circ->p_chan) {
      log_info(LD_OR,"circ->p_chan gone. Failing circ.");
      tor_free(onionskin);
      return -1;
    }
    tag_pack(tag, circ->p_chan->global_identifier,
             circ->p_circ_id);

    cpuworker->state = CPUWORKER_STATE_BUSY_ONION;
    /* touch the lastwritten timestamp, since that's how we check to
     * see how long it's been since we asked the question, and sometimes
     * we check before the first call to connection_handle_write(). */
    cpuworker->timestamp_lastwritten = time(NULL);
    num_cpuworkers_busy++;

    qbuf[0] = CPUWORKER_TASK_ONION;
    connection_write_to_buf(qbuf, 1, cpuworker);
    connection_write_to_buf(tag, sizeof(tag), cpuworker);
    connection_write_to_buf(onionskin, ONIONSKIN_CHALLENGE_LEN, cpuworker);
    tor_free(onionskin);
  }
  return 0;
}

