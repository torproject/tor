/* Copyright 2002,2003 Nick Mathewson, Roger Dingledine */
/* See LICENSE for licensing information */
/* $Id$ */

/*****
 * fakepoll.c: On systems where 'poll' doesn't exist, fake it with 'select'.
 *****/

#include "orconfig.h"
#include "fakepoll.h"

#ifdef USE_FAKE_POLL
#include <sys/types.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if _MSC_VER > 1300
#include <winsock2.h>
#include <ws2tcpip.h>
#elif defined(_MSC_VER)
#include <winsock.h>
#endif

/* by default, windows handles only 64 fd's */
#if defined(MS_WINDOWS) && !defined(FD_SETSIZE)
#define FD_SETSIZE MAXCONNECTIONS
#endif

#include <assert.h>
#include <stdlib.h>
#include "util.h"
#include "log.h"

int
tor_poll(struct pollfd *ufds, unsigned int nfds, int timeout)
{
        unsigned int idx;
        int maxfd, fd;
        int r;
#ifdef MS_WINDOWS
        int any_fds_set = 0;
#endif
        fd_set readfds, writefds, exceptfds;
#ifdef USING_FAKE_TIMEVAL
#undef timeval
#undef tv_sec
#undef tv_usec
#endif
        struct timeval _timeout;
        _timeout.tv_sec = timeout/1000;
        _timeout.tv_usec = (timeout%1000)*1000;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);

        maxfd = -1;
        for (idx = 0; idx < nfds; ++idx) {
                ufds[idx].revents = 0;
                fd = ufds[idx].fd;
                tor_assert(fd >= 0);
                if (fd > maxfd) {
                  maxfd = fd;
#ifdef MS_WINDOWS
                  any_fds_set = 1;
#endif
                }
                if (ufds[idx].events & POLLIN)
                        FD_SET(fd, &readfds);
                if (ufds[idx].events & POLLOUT)
                        FD_SET(fd, &writefds);
                FD_SET(fd, &exceptfds);
        }
#ifdef MS_WINDOWS
        if (!any_fds_set) {
                Sleep(timeout);
                return 0;
        }
#endif
        r = select(maxfd+1, &readfds, &writefds, &exceptfds,
                   timeout == -1 ? NULL : &_timeout);
        if (r <= 0)
                return r;
        r = 0;
        for (idx = 0; idx < nfds; ++idx) {
                fd = ufds[idx].fd;
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

/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
