/* Copyright 2002,2003 Nick Mathewson, Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __FAKEPOLL_H
#define __FAKEPOLL_H
#define FAKEPOLL_H_ID "$Id$"

/**
 * \file fakepoll.h
 * \brief Headers for fakepoll.c
 */

#include "orconfig.h"

#define POLL_NO_WARN

#if defined(HAVE_POLL_H)
#include <poll.h>
#elif defined(HAVE_SYS_POLL_H)
#include <sys/poll.h>
#endif

/* If _POLL_EMUL_H_ is defined, then poll is just a just a thin wrapper around
 * select.  On Mac OS 10.3, this wrapper is kinda flaky, and we should
 * use our own.
 */
#if !(defined(HAVE_POLL_H)||defined(HAVE_SYS_POLL_H))&&!defined(_POLL_EMUL_H_)
#define USE_FAKE_POLL
#endif

#if defined USE_FAKE_POLL && !defined(_POLL_EMUL_H_)
struct pollfd {
  int fd;
  short events;
  short revents;
};

#define POLLIN   0x0001
#define POLLPRI  0x0002
#define POLLOUT  0x0004
#define POLLERR  0x0008
#define POLLHUP  0x0010
#define POLLNVAL 0x0020
#endif

#ifdef MS_WINDOWS
#define MAXCONNECTIONS 10000 /* XXXX copied from or.h */
/* This trick makes winsock resize fd_set, which defaults to the insanely low
 * 64. */
#define FD_SETSIZE MAXCONNECTIONS
/* XXXX But Windows FD_SET and FD_CLR are tremendously ugly, and linear in
 *   the total number of sockets set! Perhaps we should eventually use
 *   WSAEventSelect and WSAWaitForMultipleEvents instead of select? */
#endif

#if defined(MS_WINDOWS) || ! defined(USE_FAKE_POLL)
/* If we're using poll, we can poll as many sockets as we want.
 * If we're on Windows, having too many sockets is harmless, since
 * select stupidly uses an array of sockets rather than a bitfield. */
#define SOCKET_IS_POLLABLE(fd) ((fd) >= 0)
#else
/* If we're using a real Posix select, then in order to be pollable, a socket
 * must
 *   a) be valid (>= 0)
 *   b) be < FD_SETSIZE.
 */
#define SOCKET_IS_POLLABLE(fd) ((fd) >= 0 && (fd) < FD_SETSIZE)
#endif

int tor_poll(struct pollfd *ufds, unsigned int nfds, int timeout);

#endif
