/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define SOCKET_PRIVATE
#include "lib/net/socket.h"
#include "lib/net/address.h"
#include "lib/cc/compat_compiler.h"
#include "lib/lock/compat_mutex.h"
#include "lib/log/torlog.h"
#include "lib/log/util_bug.h"

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <stddef.h>
#include <string.h>

/* When set_max_file_sockets() is called, update this with the max file
 * descriptor value so we can use it to check the limit when opening a new
 * socket. Default value is what Debian sets as the default hard limit. */
static int max_sockets = 1024;

/** Return the maximum number of allowed sockets. */
int
get_max_sockets(void)
{
  return max_sockets;
}

/** Set the maximum number of allowed sockets to <b>n</b> */
void
set_max_sockets(int n)
{
  max_sockets = n;
}

#undef DEBUG_SOCKET_COUNTING
#ifdef DEBUG_SOCKET_COUNTING
#include "lib/container/bitarray.h"

/** A bitarray of all fds that should be passed to tor_socket_close(). Only
 * used if DEBUG_SOCKET_COUNTING is defined. */
static bitarray_t *open_sockets = NULL;
/** The size of <b>open_sockets</b>, in bits. */
static int max_socket = -1;
#endif /* defined(DEBUG_SOCKET_COUNTING) */

/** Count of number of sockets currently open.  (Undercounts sockets opened by
 * eventdns and libevent.) */
static int n_sockets_open = 0;

/** Mutex to protect open_sockets, max_socket, and n_sockets_open. */
static tor_mutex_t *socket_accounting_mutex = NULL;

/** Helper: acquire the socket accounting lock. */
static inline void
socket_accounting_lock(void)
{
  if (PREDICT_UNLIKELY(!socket_accounting_mutex))
    socket_accounting_mutex = tor_mutex_new();
  tor_mutex_acquire(socket_accounting_mutex);
}

/** Helper: release the socket accounting lock. */
static inline void
socket_accounting_unlock(void)
{
  tor_mutex_release(socket_accounting_mutex);
}

/** As close(), but guaranteed to work for sockets across platforms (including
 * Windows, where close()ing a socket doesn't work.  Returns 0 on success and
 * the socket error code on failure. */
int
tor_close_socket_simple(tor_socket_t s)
{
  int r = 0;

  /* On Windows, you have to call close() on fds returned by open(),
  * and closesocket() on fds returned by socket().  On Unix, everything
  * gets close()'d.  We abstract this difference by always using
  * tor_close_socket to close sockets, and always using close() on
  * files.
  */
  #if defined(_WIN32)
    r = closesocket(s);
  #else
    r = close(s);
  #endif

  if (r != 0) {
    int err = tor_socket_errno(-1);
    log_info(LD_NET, "Close returned an error: %s", tor_socket_strerror(err));
    return err;
  }

  return r;
}

/** As tor_close_socket_simple(), but keeps track of the number
 * of open sockets. Returns 0 on success, -1 on failure. */
MOCK_IMPL(int,
tor_close_socket,(tor_socket_t s))
{
  int r = tor_close_socket_simple(s);

  socket_accounting_lock();
#ifdef DEBUG_SOCKET_COUNTING
  if (s > max_socket || ! bitarray_is_set(open_sockets, s)) {
    log_warn(LD_BUG, "Closing a socket (%d) that wasn't returned by tor_open_"
             "socket(), or that was already closed or something.", s);
  } else {
    tor_assert(open_sockets && s <= max_socket);
    bitarray_clear(open_sockets, s);
  }
#endif /* defined(DEBUG_SOCKET_COUNTING) */
  if (r == 0) {
    --n_sockets_open;
  } else {
#ifdef _WIN32
    if (r != WSAENOTSOCK)
      --n_sockets_open;
#else
    if (r != EBADF)
      --n_sockets_open; // LCOV_EXCL_LINE -- EIO and EINTR too hard to force.
#endif /* defined(_WIN32) */
    r = -1;
  }

  tor_assert_nonfatal(n_sockets_open >= 0);
  socket_accounting_unlock();
  return r;
}

/** @{ */
#ifdef DEBUG_SOCKET_COUNTING
/** Helper: if DEBUG_SOCKET_COUNTING is enabled, remember that <b>s</b> is
 * now an open socket. */
static inline void
mark_socket_open(tor_socket_t s)
{
  /* XXXX This bitarray business will NOT work on windows: sockets aren't
     small ints there. */
  if (s > max_socket) {
    if (max_socket == -1) {
      open_sockets = bitarray_init_zero(s+128);
      max_socket = s+128;
    } else {
      open_sockets = bitarray_expand(open_sockets, max_socket, s+128);
      max_socket = s+128;
    }
  }
  if (bitarray_is_set(open_sockets, s)) {
    log_warn(LD_BUG, "I thought that %d was already open, but socket() just "
             "gave it to me!", s);
  }
  bitarray_set(open_sockets, s);
}
#else /* !(defined(DEBUG_SOCKET_COUNTING)) */
#define mark_socket_open(s) ((void) (s))
#endif /* defined(DEBUG_SOCKET_COUNTING) */
/** @} */

/** As socket(), but counts the number of open sockets. */
MOCK_IMPL(tor_socket_t,
tor_open_socket,(int domain, int type, int protocol))
{
  return tor_open_socket_with_extensions(domain, type, protocol, 1, 0);
}

/** Mockable wrapper for connect(). */
MOCK_IMPL(tor_socket_t,
tor_connect_socket,(tor_socket_t sock, const struct sockaddr *address,
                     socklen_t address_len))
{
  return connect(sock,address,address_len);
}

/** As socket(), but creates a nonblocking socket and
 * counts the number of open sockets. */
tor_socket_t
tor_open_socket_nonblocking(int domain, int type, int protocol)
{
  return tor_open_socket_with_extensions(domain, type, protocol, 1, 1);
}

/** As socket(), but counts the number of open sockets and handles
 * socket creation with either of SOCK_CLOEXEC and SOCK_NONBLOCK specified.
 * <b>cloexec</b> and <b>nonblock</b> should be either 0 or 1 to indicate
 * if the corresponding extension should be used.*/
tor_socket_t
tor_open_socket_with_extensions(int domain, int type, int protocol,
                                int cloexec, int nonblock)
{
  tor_socket_t s;

  /* We are about to create a new file descriptor so make sure we have
   * enough of them. */
  if (get_n_open_sockets() >= max_sockets - 1) {
#ifdef _WIN32
    WSASetLastError(WSAEMFILE);
#else
    errno = EMFILE;
#endif
    return TOR_INVALID_SOCKET;
  }

#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
  int ext_flags = (cloexec ? SOCK_CLOEXEC : 0) |
                  (nonblock ? SOCK_NONBLOCK : 0);
  s = socket(domain, type|ext_flags, protocol);
  if (SOCKET_OK(s))
    goto socket_ok;
  /* If we got an error, see if it is EINVAL. EINVAL might indicate that,
   * even though we were built on a system with SOCK_CLOEXEC and SOCK_NONBLOCK
   * support, we are running on one without. */
  if (errno != EINVAL)
    return s;
#endif /* defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK) */

  s = socket(domain, type, protocol);
  if (! SOCKET_OK(s))
    return s;

#if defined(FD_CLOEXEC)
  if (cloexec) {
    if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
      log_warn(LD_FS,"Couldn't set FD_CLOEXEC: %s", strerror(errno));
      tor_close_socket_simple(s);
      return TOR_INVALID_SOCKET;
    }
  }
#else /* !(defined(FD_CLOEXEC)) */
  (void)cloexec;
#endif /* defined(FD_CLOEXEC) */

  if (nonblock) {
    if (set_socket_nonblocking(s) == -1) {
      tor_close_socket_simple(s);
      return TOR_INVALID_SOCKET;
    }
  }

  goto socket_ok; /* So that socket_ok will not be unused. */

 socket_ok:
  tor_take_socket_ownership(s);
  return s;
}

/**
 * For socket accounting: remember that we are the owner of the socket
 * <b>s</b>. This will prevent us from overallocating sockets, and prevent us
 * from asserting later when we close the socket <b>s</b>.
 */
void
tor_take_socket_ownership(tor_socket_t s)
{
  socket_accounting_lock();
  ++n_sockets_open;
  mark_socket_open(s);
  socket_accounting_unlock();
}

/** As accept(), but counts the number of open sockets. */
tor_socket_t
tor_accept_socket(tor_socket_t sockfd, struct sockaddr *addr, socklen_t *len)
{
  return tor_accept_socket_with_extensions(sockfd, addr, len, 1, 0);
}

/** As accept(), but returns a nonblocking socket and
 * counts the number of open sockets. */
tor_socket_t
tor_accept_socket_nonblocking(tor_socket_t sockfd, struct sockaddr *addr,
                              socklen_t *len)
{
  return tor_accept_socket_with_extensions(sockfd, addr, len, 1, 1);
}

/** As accept(), but counts the number of open sockets and handles
 * socket creation with either of SOCK_CLOEXEC and SOCK_NONBLOCK specified.
 * <b>cloexec</b> and <b>nonblock</b> should be either 0 or 1 to indicate
 * if the corresponding extension should be used.*/
tor_socket_t
tor_accept_socket_with_extensions(tor_socket_t sockfd, struct sockaddr *addr,
                                 socklen_t *len, int cloexec, int nonblock)
{
  tor_socket_t s;

  /* We are about to create a new file descriptor so make sure we have
   * enough of them. */
  if (get_n_open_sockets() >= max_sockets - 1) {
#ifdef _WIN32
    WSASetLastError(WSAEMFILE);
#else
    errno = EMFILE;
#endif
    return TOR_INVALID_SOCKET;
  }

#if defined(HAVE_ACCEPT4) && defined(SOCK_CLOEXEC) \
  && defined(SOCK_NONBLOCK)
  int ext_flags = (cloexec ? SOCK_CLOEXEC : 0) |
                  (nonblock ? SOCK_NONBLOCK : 0);
  s = accept4(sockfd, addr, len, ext_flags);
  if (SOCKET_OK(s))
    goto socket_ok;
  /* If we got an error, see if it is ENOSYS. ENOSYS indicates that,
   * even though we were built on a system with accept4 support, we
   * are running on one without. Also, check for EINVAL, which indicates that
   * we are missing SOCK_CLOEXEC/SOCK_NONBLOCK support. */
  if (errno != EINVAL && errno != ENOSYS)
    return s;
#endif /* defined(HAVE_ACCEPT4) && defined(SOCK_CLOEXEC) ... */

  s = accept(sockfd, addr, len);
  if (!SOCKET_OK(s))
    return s;

#if defined(FD_CLOEXEC)
  if (cloexec) {
    if (fcntl(s, F_SETFD, FD_CLOEXEC) == -1) {
      log_warn(LD_NET, "Couldn't set FD_CLOEXEC: %s", strerror(errno));
      tor_close_socket_simple(s);
      return TOR_INVALID_SOCKET;
    }
  }
#else /* !(defined(FD_CLOEXEC)) */
  (void)cloexec;
#endif /* defined(FD_CLOEXEC) */

  if (nonblock) {
    if (set_socket_nonblocking(s) == -1) {
      tor_close_socket_simple(s);
      return TOR_INVALID_SOCKET;
    }
  }

  goto socket_ok; /* So that socket_ok will not be unused. */

 socket_ok:
  tor_take_socket_ownership(s);
  return s;
}

/** Return the number of sockets we currently have opened. */
int
get_n_open_sockets(void)
{
  int n;
  socket_accounting_lock();
  n = n_sockets_open;
  socket_accounting_unlock();
  return n;
}

/**
 * Allocate a pair of connected sockets.  (Like socketpair(family,
 * type,protocol,fd), but works on systems that don't have
 * socketpair.)
 *
 * Currently, only (AF_UNIX, SOCK_STREAM, 0) sockets are supported.
 *
 * Note that on systems without socketpair, this call will fail if
 * localhost is inaccessible (for example, if the networking
 * stack is down). And even if it succeeds, the socket pair will not
 * be able to read while localhost is down later (the socket pair may
 * even close, depending on OS-specific timeouts).
 *
 * Returns 0 on success and -errno on failure; do not rely on the value
 * of errno or WSAGetLastError().
 **/
/* It would be nicer just to set errno, but that won't work for windows. */
int
tor_socketpair(int family, int type, int protocol, tor_socket_t fd[2])
{
//don't use win32 socketpairs (they are always bad)
#if defined(HAVE_SOCKETPAIR) && !defined(_WIN32)
  int r;

#ifdef SOCK_CLOEXEC
  r = socketpair(family, type|SOCK_CLOEXEC, protocol, fd);
  if (r == 0)
    goto sockets_ok;
  /* If we got an error, see if it is EINVAL. EINVAL might indicate that,
   * even though we were built on a system with SOCK_CLOEXEC support, we
   * are running on one without. */
  if (errno != EINVAL)
    return -errno;
#endif /* defined(SOCK_CLOEXEC) */

  r = socketpair(family, type, protocol, fd);
  if (r < 0)
    return -errno;

#if defined(FD_CLOEXEC)
  if (SOCKET_OK(fd[0])) {
    r = fcntl(fd[0], F_SETFD, FD_CLOEXEC);
    if (r == -1) {
      close(fd[0]);
      close(fd[1]);
      return -errno;
    }
  }
  if (SOCKET_OK(fd[1])) {
    r = fcntl(fd[1], F_SETFD, FD_CLOEXEC);
    if (r == -1) {
      close(fd[0]);
      close(fd[1]);
      return -errno;
    }
  }
#endif /* defined(FD_CLOEXEC) */
  goto sockets_ok; /* So that sockets_ok will not be unused. */

 sockets_ok:
  socket_accounting_lock();
  if (SOCKET_OK(fd[0])) {
    ++n_sockets_open;
    mark_socket_open(fd[0]);
  }
  if (SOCKET_OK(fd[1])) {
    ++n_sockets_open;
    mark_socket_open(fd[1]);
  }
  socket_accounting_unlock();

  return 0;
#else /* !(defined(HAVE_SOCKETPAIR) && !defined(_WIN32)) */
  return tor_ersatz_socketpair(family, type, protocol, fd);
#endif /* defined(HAVE_SOCKETPAIR) && !defined(_WIN32) */
}

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

/** Mockable wrapper for getsockname(). */
MOCK_IMPL(int,
tor_getsockname,(tor_socket_t sock, struct sockaddr *address,
                 socklen_t *address_len))
{
   return getsockname(sock, address, address_len);
}

/**
 * Find the local address associated with the socket <b>sock</b>, and
 * place it in *<b>addr_out</b>.  Return 0 on success, -1 on failure.
 *
 * (As tor_getsockname, but instead places the result in a tor_addr_t.) */
int
tor_addr_from_getsockname(struct tor_addr_t *addr_out, tor_socket_t sock)
{
  struct sockaddr_storage ss;
  socklen_t ss_len = sizeof(ss);
  memset(&ss, 0, sizeof(ss));

  if (tor_getsockname(sock, (struct sockaddr *) &ss, &ss_len) < 0)
    return -1;

  return tor_addr_from_sockaddr(addr_out, (struct sockaddr *)&ss, NULL);
}

/** Turn <b>socket</b> into a nonblocking socket. Return 0 on success, -1
 * on failure.
 */
int
set_socket_nonblocking(tor_socket_t sock)
{
#if defined(_WIN32)
  unsigned long nonblocking = 1;
  ioctlsocket(sock, FIONBIO, (unsigned long*) &nonblocking);
#else
  int flags;

  flags = fcntl(sock, F_GETFL, 0);
  if (flags == -1) {
    log_warn(LD_NET, "Couldn't get file status flags: %s", strerror(errno));
    return -1;
  }
  flags |= O_NONBLOCK;
  if (fcntl(sock, F_SETFL, flags) == -1) {
    log_warn(LD_NET, "Couldn't set file status flags: %s", strerror(errno));
    return -1;
  }
#endif /* defined(_WIN32) */

  return 0;
}
