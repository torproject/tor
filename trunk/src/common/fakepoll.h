/*
 * fakepoll.h
 *
 * On systems where 'poll' doesn't exist, fake it with 'select'.
 *
 * Nick Mathewson <nickm@freehaven.net>
 */

/*
 * Changes :
 * $Log$
 * Revision 1.2  2003/05/09 02:25:37  nickm
 * work on versioning; new log_fn function
 *
 * Revision 1.1  2002/09/03 18:43:50  nickm
 * Add function to fake a poll call using select
 *
 */
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
