/* Copyright 2002,2003 Nick Mathewson, Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __FAKEPOLL_H
#define __FAKEPOLL_H

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

int tor_poll(struct pollfd *ufds, unsigned int nfds, int timeout);

#endif

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
