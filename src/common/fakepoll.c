/*
 * fakepoll.c
 *
 * On systems where 'poll' doesn't exist, fake it with 'select'.
 *
 * Nick Mathewson <nickm@freehaven.net>
 */


/*
 * Changes :
 * $Log$
 * Revision 1.1  2002/09/03 18:43:50  nickm
 * Add function to fake a poll call using select
 *
 */
#include "fakepoll.h"

#ifdef USE_FAKE_POLL
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

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
