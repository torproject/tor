/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#define _GNU_SOURCE
#include <stdlib.h>
#include "compat.h"
#include "compat_threads.h"

#include "util.h"
#include "torlog.h"

#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

/** Return a newly allocated, ready-for-use mutex. */
tor_mutex_t *
tor_mutex_new(void)
{
  tor_mutex_t *m = tor_malloc_zero(sizeof(tor_mutex_t));
  tor_mutex_init(m);
  return m;
}
/** Release all storage and system resources held by <b>m</b>. */
void
tor_mutex_free(tor_mutex_t *m)
{
  if (!m)
    return;
  tor_mutex_uninit(m);
  tor_free(m);
}

tor_cond_t *
tor_cond_new(void)
{
  tor_cond_t *cond = tor_malloc(sizeof(tor_cond_t));
  if (tor_cond_init(cond)<0)
    tor_free(cond);
  return cond;
}
void
tor_cond_free(tor_cond_t *c)
{
  if (!c)
    return;
  tor_cond_uninit(c);
  tor_free(c);
}

/** Identity of the "main" thread */
static unsigned long main_thread_id = -1;

/** Start considering the current thread to be the 'main thread'.  This has
 * no effect on anything besides in_main_thread(). */
void
set_main_thread(void)
{
  main_thread_id = tor_get_thread_id();
}
/** Return true iff called from the main thread. */
int
in_main_thread(void)
{
  return main_thread_id == tor_get_thread_id();
}

#ifdef HAVE_EVENTFD
static int
eventfd_alert(int fd)
{
  uint64_t u = 1;
  int r = write(fd, (void*)&u, sizeof(u));
  if (r < 0 && errno != EAGAIN)
    return -1;
  return 0;
}

static int
eventfd_drain(int fd)
{
  uint64_t u = 0;
  int r = read(fd, (void*)&u, sizeof(u));
  if (r < 0 && errno != EAGAIN)
    return -1;
  return 0;
}
#endif

#ifdef HAVE_PIPE
static int
pipe_alert(int fd)
{
  ssize_t r = write(fd, "x", 1);
  if (r < 0 && errno != EAGAIN)
    return -1;
  return 0;
}

static int
pipe_drain(int fd)
{
  char buf[32];
  ssize_t r;
  while ((r = read(fd, buf, sizeof(buf))) >= 0)
    ;
  if (r == 0 || errno != EAGAIN)
    return -1;
  return 0;
}
#endif

static int
sock_alert(tor_socket_t fd)
{
  ssize_t r = send(fd, "x", 1, 0);
  if (r < 0 && !ERRNO_IS_EAGAIN(tor_socket_errno(fd)))
    return -1;
  return 0;
}

static int
sock_drain(tor_socket_t fd)
{
  char buf[32];
  ssize_t r;
  while ((r = recv(fd, buf, sizeof(buf), 0)) >= 0)
    ;
  if (r == 0 || !ERRNO_IS_EAGAIN(tor_socket_errno(fd)))
    return -1;
  return 0;
}

/** Allocate a new set of alert sockets. DOCDOC */
int
alert_sockets_create(alert_sockets_t *socks_out)
{
  tor_socket_t socks[2];

#ifdef HAVE_EVENTFD
#if defined(EFD_CLOEXEC) && defined(EFD_NONBLOCK)
  socks[0] = eventfd(0, EFD_CLOEXEC|EFD_NONBLOCK);
#else
  socks[0] = -1;
#endif
  if (socks[0] < 0) {
    socks[0] = eventfd(0,0);
    if (socks[0] >= 0) {
      if (fcntl(socks[0], F_SETFD, FD_CLOEXEC) < 0 ||
          set_socket_nonblocking(socks[0]) < 0) {
        close(socks[0]);
        return -1;
      }
    }
  }
  if (socks[0] >= 0) {
    socks_out->read_fd = socks_out->write_fd = socks[0];
    socks_out->alert_fn = eventfd_alert;
    socks_out->drain_fn = eventfd_drain;
    return 0;
  }
#endif

#ifdef HAVE_PIPE2
  if (pipe2(socks, O_NONBLOCK|O_CLOEXEC) == 0) {
    socks_out->read_fd = socks[0];
    socks_out->write_fd = socks[1];
    socks_out->alert_fn = pipe_alert;
    socks_out->drain_fn = pipe_drain;
    return 0;
  }
#endif

#ifdef HAVE_PIPE
  if (pipe(socks) == 0) {
    if (fcntl(socks[0], F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(socks[1], F_SETFD, FD_CLOEXEC) < 0 ||
        set_socket_nonblocking(socks[0]) < 0 ||
        set_socket_nonblocking(socks[1]) < 0) {
      close(socks[0]);
      close(socks[1]);
      return -1;
    }
    socks_out->read_fd = socks[0];
    socks_out->write_fd = socks[1];
    socks_out->alert_fn = pipe_alert;
    socks_out->drain_fn = pipe_drain;
    return 0;
  }
#endif

  if (tor_socketpair(AF_UNIX, SOCK_STREAM, 0, socks) == 0) {
    set_socket_nonblocking(socks[0]);
    set_socket_nonblocking(socks[1]);
    socks_out->alert_fn = sock_alert;
    socks_out->drain_fn = sock_drain;
    return 0;
  }
  return -1;
}
