/* Copyright 2002,2003 Nick Mathewson, Roger Dingledine. */
/* See LICENSE for licensing information */
/* $Id$ */

#ifndef __FAKEPOLL_H
#define __FAKEPOLL_H

#include "orconfig.h"

#ifndef HAVE_POLL_H
#ifndef HAVE_SYS_POLL_H
#define USE_FAKE_POLL

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

int poll(struct pollfd *ufds, unsigned int nfds, int timeout);

#endif
#endif
#endif
