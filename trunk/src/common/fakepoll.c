/*
 * fakepoll.c
 *
 * On systems where 'poll' doesn't exist, fake it with 'select'.
 *
 * Nick Mathewson <nickm@freehaven.net>
 */

#include "orconfig.h"
#ifdef USE_FAKE_POLL
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#if _MSC_VER > 1300
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(_MSC_VER)
#include <winsock.h>
#endif

#include "fakepoll.h"
#include "util.h"

int
poll(struct pollfd *ufds, unsigned int nfds, int timeout)
{
	int idx, maxfd, fd, r;
	fd_set readfds, writefds, exceptfds;
	struct timeval _timeout;
	_timeout.tv_sec = timeout/1000;
	_timeout.tv_usec = (timeout%1000)*1000;
	
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	maxfd = -1;
	for (idx = 0; idx < nfds; ++idx) {
		fd = ufds[idx].fd;
		if (fd > maxfd && ufds[idx].events)
			maxfd = fd;
		if (ufds[idx].events & (POLLIN))
			FD_SET(fd, &readfds);
		if (ufds[idx].events & POLLOUT)
			FD_SET(fd, &writefds);
		if (ufds[idx].events & (POLLERR))
			FD_SET(fd, &exceptfds);
	}
	r = select(maxfd+1, &readfds, &writefds, &exceptfds, 
		   timeout == -1 ? NULL : &_timeout);
	if (r <= 0)
		return r;
	r = 0;
	for (idx = 0; idx < nfds; ++idx) {
		fd = ufds[idx].fd;
		ufds[idx].revents = 0;
		if (FD_ISSET(fd, &readfds))
			ufds[idx].revents |= POLLIN;
		if (FD_ISSET(fd, &writefds))
			ufds[idx].revents |= POLLOUT;
		if (FD_ISSET(fd, &exceptfds))
			ufds[idx].revents |= POLLERR;
		if (ufds[idx].revents)
			++r;
	}
	return r;
}
#endif
