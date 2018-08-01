/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */

#include "lib/net/socketpair.h"
#include "lib/net/socket.h"
#include "lib/net/address.h"

#include <errno.h>
#include <string.h>

#ifdef NEED_ERSATZ_SOCKETPAIR

static inline socklen_t
SIZEOF_SOCKADDR(int domain)
{
  switch (domain) {
    case AF_INET:
      return sizeof(struct sockaddr_in);
    case AF_INET6:
      return sizeof(struct sockaddr_in6);
    default:
      return 0;
  }
}

/**
 * Helper used to implement socketpair on systems that lack it, by
 * making a direct connection to localhost.
 */
STATIC int
tor_ersatz_socketpair(int family, int type, int protocol, tor_socket_t fd[2])
{
    /* This socketpair does not work when localhost is down. So
     * it's really not the same thing at all. But it's close enough
     * for now, and really, when localhost is down sometimes, we
     * have other problems too.
     */
    tor_socket_t listener = TOR_INVALID_SOCKET;
    tor_socket_t connector = TOR_INVALID_SOCKET;
    tor_socket_t acceptor = TOR_INVALID_SOCKET;
    tor_addr_t listen_tor_addr;
    struct sockaddr_storage connect_addr_ss, listen_addr_ss;
    struct sockaddr *listen_addr = (struct sockaddr *) &listen_addr_ss;
    uint16_t listen_port = 0;
    tor_addr_t connect_tor_addr;
    uint16_t connect_port = 0;
    struct sockaddr *connect_addr = (struct sockaddr *) &connect_addr_ss;
    socklen_t size;
    int saved_errno = -1;
    int ersatz_domain = AF_INET;

    memset(&connect_tor_addr, 0, sizeof(connect_tor_addr));
    memset(&connect_addr_ss, 0, sizeof(connect_addr_ss));
    memset(&listen_tor_addr, 0, sizeof(listen_tor_addr));
    memset(&listen_addr_ss, 0, sizeof(listen_addr_ss));

    if (protocol
#ifdef AF_UNIX
        || family != AF_UNIX
#endif
        ) {
#ifdef _WIN32
      return -WSAEAFNOSUPPORT;
#else
      return -EAFNOSUPPORT;
#endif
    }
    if (!fd) {
      return -EINVAL;
    }

    listener = tor_open_socket(ersatz_domain, type, 0);
    if (!SOCKET_OK(listener)) {
      int first_errno = tor_socket_errno(-1);
      if (first_errno == SOCK_ERRNO(EPROTONOSUPPORT)
          && ersatz_domain == AF_INET) {
        /* Assume we're on an IPv6-only system */
        ersatz_domain = AF_INET6;
        listener = tor_open_socket(ersatz_domain, type, 0);
        if (!SOCKET_OK(listener)) {
          /* Keep the previous behaviour, which was to return the IPv4 error.
           * (This may be less informative on IPv6-only systems.)
           * XX/teor - is there a better way to decide which errno to return?
           * (I doubt we care much either way, once there is an error.)
           */
          return -first_errno;
        }
      }
    }
    /* If there is no 127.0.0.1 or ::1, this will and must fail. Otherwise, we
     * risk exposing a socketpair on a routable IP address. (Some BSD jails
     * use a routable address for localhost. Fortunately, they have the real
     * AF_UNIX socketpair.) */
    if (ersatz_domain == AF_INET) {
      tor_addr_from_ipv4h(&listen_tor_addr, INADDR_LOOPBACK);
    } else {
      tor_addr_parse(&listen_tor_addr, "[::1]");
    }
    tor_assert(tor_addr_is_loopback(&listen_tor_addr));
    size = tor_addr_to_sockaddr(&listen_tor_addr,
                         0 /* kernel chooses port.  */,
                         listen_addr,
                         sizeof(listen_addr_ss));
    if (bind(listener, listen_addr, size) == -1)
      goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
      goto tidy_up_and_fail;

    connector = tor_open_socket(ersatz_domain, type, 0);
    if (!SOCKET_OK(connector))
      goto tidy_up_and_fail;
    /* We want to find out the port number to connect to.  */
    size = sizeof(connect_addr_ss);
    if (getsockname(listener, connect_addr, &size) == -1)
      goto tidy_up_and_fail;
    if (size != SIZEOF_SOCKADDR (connect_addr->sa_family))
      goto abort_tidy_up_and_fail;
    if (connect(connector, connect_addr, size) == -1)
      goto tidy_up_and_fail;

    size = sizeof(listen_addr_ss);
    acceptor = tor_accept_socket(listener, listen_addr, &size);
    if (!SOCKET_OK(acceptor))
      goto tidy_up_and_fail;
    if (size != SIZEOF_SOCKADDR(listen_addr->sa_family))
      goto abort_tidy_up_and_fail;
    /* Now check we are talking to ourself by matching port and host on the
       two sockets.  */
    if (getsockname(connector, connect_addr, &size) == -1)
      goto tidy_up_and_fail;
    /* Set *_tor_addr and *_port to the address and port that was used */
    tor_addr_from_sockaddr(&listen_tor_addr, listen_addr, &listen_port);
    tor_addr_from_sockaddr(&connect_tor_addr, connect_addr, &connect_port);
    if (size != SIZEOF_SOCKADDR (connect_addr->sa_family)
        || tor_addr_compare(&listen_tor_addr, &connect_tor_addr, CMP_SEMANTIC)
        || listen_port != connect_port) {
      goto abort_tidy_up_and_fail;
    }
    tor_close_socket(listener);
    fd[0] = connector;
    fd[1] = acceptor;

    return 0;

  abort_tidy_up_and_fail:
#ifdef _WIN32
    saved_errno = WSAECONNABORTED;
#else
    saved_errno = ECONNABORTED; /* I hope this is portable and appropriate.  */
#endif
  tidy_up_and_fail:
    if (saved_errno < 0)
      saved_errno = errno;
    if (SOCKET_OK(listener))
      tor_close_socket(listener);
    if (SOCKET_OK(connector))
      tor_close_socket(connector);
    if (SOCKET_OK(acceptor))
      tor_close_socket(acceptor);
    return -saved_errno;
}

#endif /* defined(NEED_ERSATZ_SOCKETPAIR) */
