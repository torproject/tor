/* Copyright 2003 Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#include "or.h"

#define MAX_DNSSLAVES 50
#define MIN_DNSSLAVES 3 /* 1 for the tor process, 3 slaves */

struct slave_data_t {
  int fd; /* socket to talk on */
  int num_processed; /* number of times we've used this slave */
  char busy; /* whether this slave currently has a task */
  char question[256]; /* the hostname that we're resolving */
  unsigned char question_len; /* how many bytes in question */
  char answer[256]; /* the answer to the question */
  unsigned char answer_len; /* how many bytes in answer */
};

struct slave_data_t slave_data[MAX_DNSSLAVES+1];
struct pollfd poll_data[MAX_DNSSLAVES+1];

static int dns_spawn_slave(void);
static int dns_read_block(int fd, char *string, unsigned char *len);
static int dns_write_block(int fd, char *string, unsigned char len);
static int dns_read_tor_question(int index);
static int dns_read_slave_response(int index);
static int dns_find_idle_slave(int max);
static int dns_assign_to_slave(int from, int to);
static int dns_master_to_tor(int from, int to);
static void dns_master_main(int fd);

int connection_dns_finished_flushing(connection_t *conn) {

  assert(conn && conn->type == CONN_TYPE_DNSMASTER);

  connection_stop_writing(conn);

  return 0;
}

int connection_dns_process_inbuf(connection_t *conn) {
  unsigned char length;
  char buf[256];
  char *question;
  connection_t *exitconn;

  assert(conn && conn->type == CONN_TYPE_DNSMASTER);
  assert(conn->state == DNSMASTER_STATE_OPEN);

  if(conn->inbuf_reached_eof) {
    log(LOG_ERR,"connection_dns_process_inbuf(): Read eof. No more dnsmaster!");
    return -1;
  }

  assert(conn->inbuf);

  if(conn->inbuf_datalen <= 0)
    return 0;

  /* peek into the inbuf, so we can check if it's all here */
  length = *conn->inbuf; /* warning: abstraction violation :( */
  assert(length < 240);

  if(conn->inbuf_datalen < 1+length) { /* entire answer available? */
    log(LOG_INFO,"connection_dns_process_inbuf(): %d available, waiting for %d.", conn->inbuf_datalen, length+1);
    return 0; /* not yet */
  }

  if(connection_fetch_from_buf(buf,1+length,conn) < 0) {
    log(LOG_ERR,"connection_dns_process_inbuf(): Broken inbuf. No more dnsmaster!");
    return -1;
  }
 
  question = buf+1;
  log(LOG_DEBUG,"connection_dns_process_inbuf(): length %d, question '%s', strlen question %d", length, question, strlen(question));
  assert(length == 4 + strlen(question) + 1);
  
  /* find the conn that question refers to. */
  exitconn = connection_get_pendingresolve_by_address(question);

  if(!exitconn) {
    log(LOG_DEBUG,"connection_dns_process_inbuf(): No conn -- question no longer relevant? Dropping.");
    return connection_process_inbuf(conn); /* process the remainder of the buffer */
  }
  memcpy((char *)&exitconn->addr, buf+1+length-4,4);
  exitconn->addr = ntohl(exitconn->addr); /* get it back to host order */

  if(connection_exit_connect(exitconn) < 0) {
    exitconn->marked_for_close = 1;
  }

  return connection_process_inbuf(conn); /* process the remainder of the buffer */
}


/* return -1 if error, else the fd that can talk to the dns master */
int dns_master_start(void) {
  connection_t *conn;
  pid_t pid;
  int fd[2];

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    log(LOG_ERR,"dns_master_start(): socketpair failed.");
    return -1;
  }

  pid = fork();
  if(pid < 0) {
    log(LOG_ERR,"dns_master_start(): fork failed.");
    return -1;
  }
  if(pid == 0) { /* i'm the child */
    log(LOG_DEBUG,"dns_master_start(): child says fd0 %d, fd1 %d.", fd[0], fd[1]);
    close(fd[0]);
    dns_master_main(fd[1]);
    assert(0); /* never gets here */
  }

  /* i'm the parent */

  close(fd[1]);

  fcntl(fd[0], F_SETFL, O_NONBLOCK); /* set s to non-blocking */

  conn = connection_new(CONN_TYPE_DNSMASTER);
  if(!conn) {
    log(LOG_INFO,"dns_master_start(): connection_new failed. Giving up.");
    /* XXX tell the dnsmaster to die */
    return -1;
  }

  conn->s = fd[0];
  conn->address = strdup("localhost");
  conn->receiver_bucket = -1; /* edge connections don't do receiver buckets */
  conn->bandwidth = -1;

  if(connection_add(conn) < 0) { /* no space, forget it */
    log(LOG_INFO,"dns_master_start(): connection_add failed. Giving up.");
    connection_free(conn);
    /* XXX tell the dnsmaster to die */    
    return -1;
  }

  conn->state = DNSMASTER_STATE_OPEN;
  connection_start_reading(conn);
  log(LOG_INFO,"dns_master_start(): dns handler is spawned.");
  return fd[0];
}

static void dns_slave_main(int fd) {
  char question[256];
  unsigned char question_len;
  struct hostent *rent;

  for(;;) {
    if(dns_read_block(fd, question, &question_len) < 0) { /* the master wants us to die */
      log(LOG_INFO,"dns_slave_main(): eof on read from master. Exiting.");
      exit(0);
    }

    rent = gethostbyname(question);
    if (!rent) { 
      log(LOG_INFO,"dns_slave_main(): Could not resolve dest addr %s. Returning nulls.",question);
      if(dns_write_block(fd, "\0\0\0\0", 4) < 0) {
        log(LOG_INFO,"dns_slave_main(): writing to master failed. Exiting.");
        exit(0);
      }     
    } else {
      if(dns_write_block(fd, rent->h_addr, rent->h_length) < 0) {
        log(LOG_INFO,"dns_slave_main(): writing to master failed. Exiting.");
        exit(0);
      }
      log(LOG_INFO,"dns_slave_main(): Answered question '%s'.",question);
    }
  }
}

static int dns_spawn_slave(void) {
  pid_t pid;
  int fd[2];

  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
    perror("socketpair");
    exit(1);
  }

  pid = fork();
  if(pid < 0) {
    perror("fork");
    exit(1);
  }
  if(pid == 0) { /* i'm the child */
    close(fd[0]);
    dns_slave_main(fd[1]);
    assert(0); /* never gets here */  
  }

  /* i'm the parent */
  log(LOG_INFO,"dns_spawn_slave(): just spawned a slave."); // XXX change to debug
  close(fd[1]);
  return fd[0];
}

/* read a first byte from fd, put it into *len. Then read *len
 * bytes from fd and put it into string.
 * Return -1 if eof or read error or bad len, else return 0.
 */
int dns_read_block(int fd, char *string, unsigned char *len) {
  int read_result;

  log(LOG_DEBUG,"dns_read_block(): Calling read to learn length (fd %d).", fd);
  read_result = read(fd, len, 1);
  log(LOG_DEBUG,"dns_read_block(): read finished, returned %d", read_result);
  if (read_result < 0) {
    log(LOG_INFO,"dns_read_block(): read len returned error");
    return -1;
  } else if (read_result == 0) {
    log(LOG_INFO,"dns_read_block(): Encountered eof reading len");
    return -1;
  } else if (*len <= 0) {
    log(LOG_INFO,"dns_read_block(): len not >0");
    return -1;
  }

  log(LOG_DEBUG,"dns_read_block(): Calling read to get string, length %u.", *len);
  read_result = read(fd, string, *len);
  if (read_result < 0) {
    log(LOG_INFO,"dns_read_block(): read string returned error");
    return -1;
  } else if (read_result == 0) {
    log(LOG_INFO,"dns_read_block(): Encountered eof reading string");
    return -1;
  }

  string[*len] = 0; /* null terminate it, just in case */
//  log(LOG_INFO,"dns_read_block(): Read '%s', len %u.",string,*len);
  return 0;
}

/* write ("%c%s", string, len) onto fd */
static int dns_write_block(int fd, char *string, unsigned char len) {
  int write_result;
  int written=0;
  char tmp[257];

  assert(len <= 250);
  tmp[0] = len;
  memcpy(tmp+1, string, len);
  log(LOG_DEBUG,"dns_write_block(): writing length %u, fd %d.", len, fd);

  while(written < len+1) {
    write_result = write(fd, tmp, len+1-written);
    if (write_result < 0) {
      return -1;
    }
    written += write_result;
  }

  return 0;
}

/* pull in question. block until we've read everything. 
 * return -1 if eof. */
static int dns_read_tor_question(int index) {

  log(LOG_DEBUG,"dns_read_tor_question(): Pulling question from tor");
  if(dns_read_block(slave_data[index].fd,
                    slave_data[index].question,
                    &slave_data[index].question_len) < 0)
    return -1;

//  log(LOG_INFO,"dns_read_tor_question(): Read question '%s'",slave_data[index].question);
  return 0;
}

/* pull in answer. block until we've read it. return -1 if eof. */
static int dns_read_slave_response(int index) {

  if(dns_read_block(slave_data[index].fd,
                    slave_data[index].answer,
                    &slave_data[index].answer_len) < 0)
    return -1;

  return 0;
}

static int dns_find_idle_slave(int max) {
  int i;

  for(i=1;i<max;i++)
    if(slave_data[i].busy == 0) {
      log(LOG_DEBUG,"dns_find_idle_slave(): slave %d is chosen.",i);
      return i;
    }

  assert(0); /* should never get here */
}

static int dns_assign_to_slave(int from, int to) {

  slave_data[to].question_len = slave_data[from].question_len;
  memcpy(slave_data[to].question, slave_data[from].question, slave_data[from].question_len);

//  slave_data[from].question_len = 0;

  log(LOG_DEBUG,"dns_assign_to_slave(): from index %d to %d (writing fd %d)",from,to,slave_data[to].fd);
  if(dns_write_block(slave_data[to].fd,
                     slave_data[to].question,
                     slave_data[to].question_len) < 0) {
    log(LOG_INFO,"dns_assign_to_slave(): writing to slave failed.");
    return -1;
  }

  return 0;
}

static int dns_master_to_tor(int from, int to) {
  char tmp[256];
  unsigned char len;

  len = slave_data[from].question_len+1+slave_data[from].answer_len;
  memcpy(tmp, slave_data[from].question, slave_data[from].question_len);
  tmp[slave_data[from].question_len] = 0; /* null terminate it */
  memcpy(tmp+1+slave_data[from].question_len, slave_data[from].answer, slave_data[from].answer_len);

  log(LOG_DEBUG,"dns_master_to_tor(): question is '%s', length %d",slave_data[from].question,slave_data[from].question_len);
  log(LOG_DEBUG,"dns_master_to_tor(): answer is %d %d %d %d",
    slave_data[from].answer[0],
    slave_data[from].answer[1],
    slave_data[from].answer[2],
    slave_data[from].answer[3]);
  assert(slave_data[from].answer_len == 4);
  if(dns_write_block(slave_data[to].fd, tmp, len) < 0) {
    log(LOG_INFO,"dns_master_to_tor(): writing to tor failed.");
    return -1;
  }

  return 0;
}

int dns_tor_to_master(char *address) {
  connection_t *conn;
  unsigned char len;

  conn = connection_get_by_type(CONN_TYPE_DNSMASTER);
  if(!conn) {
    log(LOG_ERR,"dns_tor_to_master(): dns master nowhere to be found!");
    /* XXX should do gethostbyname right here */
    return -1;
  }

  len = strlen(address);
  if(connection_write_to_buf(&len, 1, conn) < 0) {
    log(LOG_DEBUG,"dns_tor_to_master(): Couldn't write length.");
    return -1;
  }

  if(connection_write_to_buf(address, len, conn) < 0) {
    log(LOG_DEBUG,"dns_tor_to_master(): Couldn't write address.");
    return -1;
  }

//  log(LOG_DEBUG,"dns_tor_to_master(): submitted '%s'", address);
  return 0;
}

static void dns_master_main(int fd) {
  int nfds=1; /* the 0th index is the tor process, the rest are slaves */
  int num_slaves_busy=0;
  int num_slaves_needed = MIN_DNSSLAVES;
  int poll_result, idle, i;

  poll_data[0].fd = slave_data[0].fd = fd;
  poll_data[0].events = POLLIN;

  for(;;) { /* loop forever */

    assert(num_slaves_needed < MAX_DNSSLAVES);
    while(nfds-1 < num_slaves_needed) {
      /* add another slave. */

      i = nfds;
      memset(&slave_data[i], 0, sizeof(struct slave_data_t));
      memset(&poll_data[i], 0, sizeof(struct pollfd));
      slave_data[i].fd = poll_data[i].fd = dns_spawn_slave();
      poll_data[i].events = POLLIN; /* listen always, to prevent accidental deadlock */      
      nfds++;
    }

    /* XXX later, decide on a timeout value, to catch wedged slaves */

    poll_result = poll(poll_data, nfds, -1);
    log(LOG_DEBUG,"dns_master_main(): Poll returned -- activity!");
    for(i=0;i<nfds;i++) {
      if(poll_data[i].revents & POLLIN) {
        if(i==0) { /* note that we read only one question per poll loop */
          if(dns_read_tor_question(i) >= 0) {
            while(1) {
              idle = dns_find_idle_slave(nfds);
              if(dns_assign_to_slave(i, idle) >= 0)
                break; /* successfully assigned to one */
              /* XXX slave must die, recalc num slaves and num busy */
            }
            num_slaves_busy++; 
          } else { /* error */
            log(LOG_INFO,"dns_master_main(): dns_read_tor_question failed. Master dying.");
            exit(1);
          }
        } else {
          if(dns_read_slave_response(i) >= 0) {
            if(dns_master_to_tor(i, 0) < 0) {
              log(LOG_INFO,"dns_master_main(): dns_master_to_tor failed. Master dying.");
              exit(1);
            }
            slave_data[i].busy = 0;
            num_slaves_busy--;
            poll_data[0].events = POLLIN; /* resume reading from tor if we'd stopped */
          } else { /* error */
            log(LOG_INFO,"dns_master_main(): dns_read_slave_response failed. Leaving slave stranded (FIXME)");
          }
        }
      }
    }
    log(LOG_DEBUG,"dns_master_main(): Finished looping over fd's.");

    if(num_slaves_busy >= num_slaves_needed) {
      if(num_slaves_needed == MAX_DNSSLAVES-1)
        poll_data[0].events = 0; /* stop reading from tor */
      else
        num_slaves_needed++;
    }

  }
  assert(0); /* should never get here */
}

