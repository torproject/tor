/* Copyright 2003-2004 Roger Dingledine; Copyright 2004 Nick Mathewson */
/* See LICENSE for licensing information */
/* $Id$ */


/* This is required on rh7 to make strptime not complain.
 */
#define _GNU_SOURCE

#include "orconfig.h"

#ifdef MS_WINDOWS
#include <io.h>
#include <process.h>
#include <direct.h>
#include <windows.h>
#endif
#ifdef HAVE_UNAME
#include <sys/utsname.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifndef HAVE_GETTIMEOFDAY
#ifdef HAVE_FTIME
#include <sys/timeb.h>
#endif
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "compat.h"
#include "log.h"
#include "util.h"

/* Inline the strl functions if the plaform doesn't have them. */
#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif
#ifndef HAVE_STRLCAT
#include "strlcat.c"
#endif

/** Replacement for snprintf.  Differs from platform snprintf in two
 * ways: First, always NUL-terminates its output.  Second, always
 * returns -1 if the result is truncated.  (Note that this return
 * behavior does <i>not</i> conform to C99; it just happens to be the
 * easiest to emulate "return -1" with conformant implementations than
 * it is to emulate "return number that would be written" with
 * non-conformant implementations.) */
int tor_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list ap;
  int r;
  va_start(ap,format);
  r = tor_vsnprintf(str,size,format,ap);
  va_end(ap);
  return r;
}

/** Replacement for vsnpritnf; behavior differs as tor_snprintf differs from
 * snprintf.
 */
int tor_vsnprintf(char *str, size_t size, const char *format, va_list args)
{
  int r;
#ifdef MS_WINDOWS
  r = _vsnprintf(str, size, format, args);
#else
  r = vsnprintf(str, size, format, args);
#endif
  str[size-1] = '\0';
  if (r < 0 || ((size_t)r) >= size)
    return -1;
  return r;
}

#ifndef UNALIGNED_INT_ACCESS_OK
/**
 * Read a 16-bit value beginning at <b>cp</b>.  Equaivalent to
 * *(uint16_t*)(cp), but will not cause segfaults on platforms that forbid
 * unaligned memory access.
 */
uint16_t get_uint16(const char *cp)
{
  uint16_t v;
  memcpy(&v,cp,2);
  return v;
}
/**
 * Read a 32-bit value beginning at <b>cp</b>.  Equaivalent to
 * *(uint32_t*)(cp), but will not cause segfaults on platforms that forbid
 * unaligned memory access.
 */
uint32_t get_uint32(const char *cp)
{
  uint32_t v;
  memcpy(&v,cp,4);
  return v;
}
/**
 * Set a 16-bit value beginning at <b>cp</b> to <b>v</b>. Equivalent to
 * *(uint16_t)(cp) = v, but will not cause segfaults on platforms that forbid
 * unaligned memory access. */
void set_uint16(char *cp, uint16_t v)
{
  memcpy(cp,&v,2);
}
/**
 * Set a 32-bit value beginning at <b>cp</b> to <b>v</b>. Equivalent to
 * *(uint32_t)(cp) = v, but will not cause segfaults on platforms that forbid
 * unaligned memory access. */
void set_uint32(char *cp, uint32_t v)
{
  memcpy(cp,&v,4);
}
#endif

/**
 * Rename the file 'from' to the file 'to'.  On unix, this is the same as
 * rename(2).  On windows, this removes 'to' first if it already exists.
 * Returns 0 on success.  Returns -1 and sets errno on failure.
 */
int replace_file(const char *from, const char *to)
{
#ifndef MS_WINDOWS
  return rename(from,to);
#else
  switch(file_status(to))
    {
    case FN_NOENT:
      break;
    case FN_FILE:
      if (unlink(to)) return -1;
      break;
    case FN_ERROR:
      return -1;
    case FN_DIR:
      errno = EISDIR;
      return -1;
    }
  return rename(from,to);
#endif
}

/** Turn <b>socket</b> into a nonblocking socket.
 */
void set_socket_nonblocking(int socket)
{
#ifdef MS_WINDOWS
  /* Yes means no and no means yes.  Do you not want to be nonblocking? */
  int nonblocking = 0;
  ioctlsocket(socket, FIONBIO, (unsigned long*) &nonblocking);
#else
  fcntl(socket, F_SETFL, O_NONBLOCK);
#endif
}

/**
 * Allocate a pair of connected sockets.  (Like socketpair(family,
 * type,protocol,fd), but works on systems that don't have
 * socketpair.)
 *
 * Currently, only (AF_UNIX, SOCK_STREAM, 0 ) sockets are supported.
 *
 * Note that on systems without socketpair, this call will fail if
 * localhost is inaccessible (for example, if the networking
 * stack is down). And even if it succeeds, the socket pair will not
 * be able to read while localhost is down later (the socket pair may
 * even close, depending on OS-specific timeouts).
 **/
int
tor_socketpair(int family, int type, int protocol, int fd[2])
{
#ifdef HAVE_SOCKETPAIR
    return socketpair(family, type, protocol, fd);
#else
    /* This socketpair does not work when localhost is down. So
     * it's really not the same thing at all. But it's close enough
     * for now, and really, when localhost is down sometimes, we
     * have other problems too.
     */
    int listener = -1;
    int connector = -1;
    int acceptor = -1;
    struct sockaddr_in listen_addr;
    struct sockaddr_in connect_addr;
    int size;

    if (protocol
#ifdef AF_UNIX
        || family != AF_UNIX
#endif
        ) {
#ifdef MS_WINDOWS
        errno = WSAEAFNOSUPPORT;
#else
        errno = EAFNOSUPPORT;
#endif
        return -1;
    }
    if (!fd) {
        errno = EINVAL;
        return -1;
    }

    listener = socket(AF_INET, type, 0);
    if (listener == -1)
      return -1;
    memset (&listen_addr, 0, sizeof (listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
    listen_addr.sin_port = 0;   /* kernel choses port.  */
    if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
        == -1)
        goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
        goto tidy_up_and_fail;

    connector = socket(AF_INET, type, 0);
    if (connector == -1)
        goto tidy_up_and_fail;
    /* We want to find out the port number to connect to.  */
    size = sizeof (connect_addr);
    if (getsockname(listener, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr))
        goto abort_tidy_up_and_fail;
    if (connect(connector, (struct sockaddr *) &connect_addr,
                sizeof (connect_addr)) == -1)
        goto tidy_up_and_fail;

    size = sizeof (listen_addr);
    acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
    if (acceptor == -1)
        goto tidy_up_and_fail;
    if (size != sizeof(listen_addr))
        goto abort_tidy_up_and_fail;
    tor_close_socket(listener);
    /* Now check we are talking to ourself by matching port and host on the
       two sockets.  */
    if (getsockname(connector, (struct sockaddr *) &connect_addr, &size) == -1)
        goto tidy_up_and_fail;
    if (size != sizeof (connect_addr)
        || listen_addr.sin_family != connect_addr.sin_family
        || listen_addr.sin_addr.s_addr != connect_addr.sin_addr.s_addr
        || listen_addr.sin_port != connect_addr.sin_port) {
        goto abort_tidy_up_and_fail;
    }
    fd[0] = connector;
    fd[1] = acceptor;
    return 0;

  abort_tidy_up_and_fail:
#ifdef MS_WINDOWS
  errno = WSAECONNABORTED;
#else
  errno = ECONNABORTED; /* I hope this is portable and appropriate.  */
#endif
  tidy_up_and_fail:
    {
        int save_errno = errno;
        if (listener != -1)
            tor_close_socket(listener);
        if (connector != -1)
            tor_close_socket(connector);
        if (acceptor != -1)
            tor_close_socket(acceptor);
        errno = save_errno;
        return -1;
    }
#endif
}

/** Get the maximum allowed number of file descriptors. (Some systems
 * have a low soft limit.) Make sure we set it to at least
 * <b>required_min</b>. Return 0 if we can, or -1 if we fail. */
int set_max_file_descriptors(unsigned int required_min) {
#ifndef HAVE_GETRLIMIT
  log_fn(LOG_INFO,"This platform is missing getrlimit(). Proceeding.");
  return 0; /* hope we'll be ok */
#else
  struct rlimit rlim;

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    log_fn(LOG_WARN, "Could not get maximum number of file descriptors: %s",
           strerror(errno));
    return -1;
  }
  if(required_min > rlim.rlim_max) {
    log_fn(LOG_WARN,"We need %d file descriptors available, and we're limited to %d. Please change your ulimit.", required_min, (int)rlim.rlim_max);
    return -1;
  }
  if(required_min > rlim.rlim_cur) {
    log_fn(LOG_INFO,"Raising max file descriptors from %d to %d.",
           (int)rlim.rlim_cur, (int)rlim.rlim_max);
  }
  rlim.rlim_cur = rlim.rlim_max;
  if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    log_fn(LOG_WARN, "Could not set maximum number of file descriptors: %s",
           strerror(errno));
    return -1;
  }
  return 0;
#endif
}

/** Call setuid and setgid to run as <b>user</b>:<b>group</b>.  Return 0 on
 * success.  On failure, log and return -1.
 */
int switch_id(char *user, char *group) {
#ifndef MS_WINDOWS
  struct passwd *pw = NULL;
  struct group *gr = NULL;

  if (user) {
    pw = getpwnam(user);
    if (pw == NULL) {
      log_fn(LOG_ERR,"User '%s' not found.", user);
      return -1;
    }
  }

  /* switch the group first, while we still have the privileges to do so */
  if (group) {
    gr = getgrnam(group);
    if (gr == NULL) {
      log_fn(LOG_ERR,"Group '%s' not found.", group);
      return -1;
    }

    if (setgid(gr->gr_gid) != 0) {
      log_fn(LOG_ERR,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  } else if (user) {
    if (setgid(pw->pw_gid) != 0) {
      log_fn(LOG_ERR,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  }

  /* now that the group is switched, we can switch users and lose
     privileges */
  if (user) {
    if (setuid(pw->pw_uid) != 0) {
      log_fn(LOG_ERR,"Error setting UID: %s", strerror(errno));
      return -1;
    }
  }

  return 0;
#endif

  log_fn(LOG_ERR,
         "User or group specified, but switching users is not supported.");

  return -1;
}

/** Set *addr to the IP address (in dotted-quad notation) stored in c.
 * Return 1 on success, 0 if c is badly formatted.  (Like inet_aton(c,addr),
 * but works on Windows and Solaris.)
 */
int tor_inet_aton(const char *c, struct in_addr* addr)
{
#ifdef HAVE_INET_ATON
  return inet_aton(c, addr);
#else
  uint32_t r;
  tor_assert(c);
  tor_assert(addr);
  if (strcmp(c, "255.255.255.255") == 0) {
    addr->s_addr = 0xFFFFFFFFu;
    return 1;
  }
  r = inet_addr(c);
  if (r == INADDR_NONE)
    return 0;
  addr->s_addr = r;
  return 1;
#endif
}

/* Hold the result of our call to <b>uname</b>. */
static char uname_result[256];
/* True iff uname_result is set. */
static int uname_result_is_set = 0;

/* Return a pointer to a description of our platform.
 */
const char *
get_uname(void)
{
#ifdef HAVE_UNAME
  struct utsname u;
#endif
  if (!uname_result_is_set) {
#ifdef HAVE_UNAME
    if (uname(&u) != -1) {
      /* (linux says 0 is success, solaris says 1 is success) */
      tor_snprintf(uname_result, sizeof(uname_result), "%s %s %s",
               u.sysname, u.nodename, u.machine);
    } else
#endif
      {
        strlcpy(uname_result, "Unknown platform", sizeof(uname_result));
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}

/*
 *   Process control
 */

/** Minimalist interface to run a void function in the background.  On
 * unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
 * func should not return, but rather should call spawn_exit.
 */
int spawn_func(int (*func)(void *), void *data)
{
#ifdef MS_WINDOWS
  int rv;
  rv = _beginthread(func, 0, data);
  if (rv == (unsigned long) -1)
    return -1;
  return 0;
#else
  pid_t pid;
  pid = fork();
  if (pid<0)
    return -1;
  if (pid==0) {
    /* Child */
    func(data);
    tor_assert(0); /* Should never reach here. */
    return 0; /* suppress "control-reaches-end-of-non-void" warning. */
  } else {
    /* Parent */
    return 0;
  }
#endif
}

/** End the current thread/process.
 */
void spawn_exit()
{
#ifdef MS_WINDOWS
  _endthread();
#else
  exit(0);
#endif
}


/** Set *timeval to the current time of day.  On error, log and terminate.
 * (Same as gettimeofday(timeval,NULL), but never returns -1.)
 */
void tor_gettimeofday(struct timeval *timeval) {
#ifdef HAVE_GETTIMEOFDAY
  if (gettimeofday(timeval, NULL)) {
    log_fn(LOG_ERR, "gettimeofday failed.");
    /* If gettimeofday dies, we have either given a bad timezone (we didn't),
       or segfaulted.*/
    exit(1);
  }
#elif defined(HAVE_FTIME)
  struct timeb tb;
  ftime(&tb);
  timeval->tv_sec = tb.time;
  timeval->tv_usec = tb.millitm * 1000;
#else
#error "No way to get time."
#endif
  return;
}

#ifndef MS_WINDOWS
struct tor_mutex_t {
};
tor_mutex_t *tor_mutex_new(void) { return NULL; }
void tor_mutex_acquire(tor_mutex_t *m) { }
void tor_mutex_release(tor_mutex_t *m) { }
void tor_mutex_free(tor_mutex_t *m) { }
#else
struct tor_mutex_t {
  HANDLE handle;
};
tor_mutex_t *tor_mutex_new(void)
{
  tor_mutex_t *m;
  m = tor_malloc_zero(sizeof(tor_mutex_t));
  m->handle = CreateMutex(NULL, FALSE, NULL);
  tor_assert(m->handle != NULL);
  return m;
}
void tor_mutex_free(tor_mutex_t *m)
{
  CloseHandle(m->handle);
  tor_free(m);
}
void tor_mutex_acquire(tor_mutex_t *m)
{
  DWORD r;
  r = WaitForSingleObject(m->handle, INFINITE);
  switch (r) {
    case WAIT_ABANDONED: /* holding thread exited. */
        case WAIT_OBJECT_0: /* we got the mutex normally. */
      break;
    case WAIT_TIMEOUT: /* Should never happen. */
          tor_assert(0);
      break;
        case WAIT_FAILED:
      log_fn(LOG_WARN, "Failed to acquire mutex: %d", GetLastError());
  }
}
void tor_mutex_release(tor_mutex_t *m)
{
  BOOL r;
  r = ReleaseMutex(m->handle);
  if (!r) {
    log_fn(LOG_WARN, "Failed to release mutex: %d", GetLastError());
  }
}
#endif


/**
 * On Windows, WSAEWOULDBLOCK is not always correct: when you see it,
 * you need to ask the socket for its actual errno.  Also, you need to
 * get your errors from WSAGetLastError, not errno.  (If you supply a
 * socket of -1, we check WSAGetLastError, but don't correct
 * WSAEWOULDBLOCKs.)
 */
#ifdef MS_WINDOWS
int tor_socket_errno(int sock)
{
  int optval, optvallen=sizeof(optval);
  int err = WSAGetLastError();
  if (err == WSAEWOULDBLOCK && sock >= 0) {
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)&optval, &optvallen))
      return err;
    if (optval)
      return optval;
  }
  return err;
}
#endif

#ifdef MS_WINDOWS
#define E(code, s) { code, (s " [" #code " ]") }
struct { int code; const char *msg; } windows_socket_errors[] = {
  E(WSAEINTR, "Interrupted function call"),
  E(WSAEACCES, "Permission denied"),
  E(WSAEFAULT, "Bad address"),
  E(WSAEINVAL, "Invalid argument"),
  E(WSAEMFILE, "Too many open files"),
  E(WSAEWOULDBLOCK,  "Resource temporarily unavailable"),
  E(WSAEINPROGRESS, "Operation now in progress"),
  E(WSAEALREADY, "Operation already in progress"),
  E(WSAENOTSOCK, "Socket operation on nonsocket"),
  E(WSAEDESTADDRREQ, "Destination address required"),
  E(WSAEMSGSIZE, "Message too long"),
  E(WSAEPROTOTYPE, "Protocol wrong for socket"),
  E(WSAENOPROTOOPT, "Bad protocol option"),
  E(WSAEPROTONOSUPPORT, "Protocol not supported"),
  E(WSAESOCKTNOSUPPORT, "Socket type not supported"),
  /* What's the difference between NOTSUPP and NOSUPPORT? :) */
  E(WSAEOPNOTSUPP, "Operation not supported"),
  E(WSAEPFNOSUPPORT,  "Protocol family not supported"),
  E(WSAEAFNOSUPPORT, "Address family not supported by protocol family"),
  E(WSAEADDRINUSE, "Address already in use"),
  E(WSAEADDRNOTAVAIL, "Cannot assign requested address"),
  E(WSAENETDOWN, "Network is down"),
  E(WSAENETUNREACH, "Network is unreachable"),
  E(WSAENETRESET, "Network dropped connection on reset"),
  E(WSAECONNABORTED, "Software caused connection abort"),
  E(WSAECONNRESET, "Connection reset by peer"),
  E(WSAENOBUFS, "No buffer space avaialable"),
  E(WSAEISCONN, "Socket is already connected"),
  E(WSAENOTCONN, "Socket is not connected"),
  E(WSAESHUTDOWN, "Cannot send after socket shutdown"),
  E(WSAETIMEDOUT, "Connection timed out"),
  E(WSAECONNREFUSED, "Connection refused"),
  E(WSAEHOSTDOWN, "Host is down"),
  E(WSAEHOSTUNREACH, "No route to host"),
  E(WSAEPROCLIM, "Too many processes"),
  /* Yes, some of these start with WSA, not WSAE. No, I don't know why. */
  E(WSASYSNOTREADY, "Network subsystem is unavailable"),
  E(WSAVERNOTSUPPORTED, "Winsock.dll out of range"),
  E(WSANOTINITIALISED, "Successful WSAStartup not yet performed"),
  E(WSAEDISCON, "Graceful shutdown now in progress"),
#ifdef WSATYPE_NOT_FOUND
  E(WSATYPE_NOT_FOUND, "Class type not found"),
#endif
  E(WSAHOST_NOT_FOUND, "Host not found"),
  E(WSATRY_AGAIN, "Nonauthoritative host not found"),
  E(WSANO_RECOVERY, "This is a nonrecoverable error"),
  E(WSANO_DATA, "Valid name, no data record of requested type)"),

  /* There are some more error codes whose numeric values are marked
   * <b>OS dependent</b>. They start with WSA_, apparently for the same
   * reason that practitioners of some craft traditions deliberately
   * introduce imperfections into their baskets and rugs "to allow the
   * evil spirits to escape."  If we catch them, then our binaries
   * might not report consistent results across versions of Windows.
   * Thus, I'm going to let them all fall through.
   */
  { -1, NULL },
};
/** There does not seem to be a strerror equivalent for winsock errors.
 * Naturally, we have to roll our own.
 */
const char *tor_socket_strerror(int e)
{
  int i;
  for (i=0; windows_socket_errors[i].code >= 0; ++i) {
    if (e == windows_socket_errors[i].code)
      return windows_socket_errors[i].msg;
  }
  return strerror(e);
}
#endif
/*
  Local Variables:
  mode:c
  indent-tabs-mode:nil
  c-basic-offset:2
  End:
*/
