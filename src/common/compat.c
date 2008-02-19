/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id$ */
const char compat_c_id[] =
  "$Id$";

/**
 * \file compat.c
 * \brief Wrappers to make calls more portable.  This code defines
 * functions such as tor_malloc, tor_snprintf, get/set various data types,
 * renaming, setting socket options, switching user IDs.  It is basically
 * where the non-portable items are conditionally included depending on
 * the platform.
 **/

/* This is required on rh7 to make strptime not complain.
 * We also need it to make memmem get defined (where available)
 */
#define _GNU_SOURCE

#include "orconfig.h"
#include "compat.h"

#ifdef MS_WINDOWS
#include <process.h>
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
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h> /* FreeBSD needs this to know what version it is */
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif
#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

#ifdef USE_BSOCKETS
#include <bsocket.h>
#endif

#include "log.h"
#include "util.h"
#include "container.h"

/* Inline the strl functions if the platform doesn't have them. */
#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif
#ifndef HAVE_STRLCAT
#include "strlcat.c"
#endif

#ifndef INADDR_NONE
/* This is used by inet_addr, but apparently Solaris doesn't define it
 * anyplace. */
#define INADDR_NONE ((unsigned long) -1)
#endif

#ifdef HAVE_SYS_MMAN_H
/** Implementation for tor_mmap_t: holds the regular tor_mmap_t, along
 * with extra fields needed for mmap()-based memory mapping. */
typedef struct tor_mmap_impl_t {
  tor_mmap_t base;
  size_t mapping_size; /**< Size of the actual mapping. (This is this file
                        * size, rounded up to the nearest page.) */
} tor_mmap_impl_t;

/** Try to create a memory mapping for <b>filename</b> and return it.  On
 * failure, return NULL.  Sets errno properly, using ERANGE to mean
 * "empty file". */
tor_mmap_t *
tor_mmap_file(const char *filename)
{
  int fd; /* router file */
  char *string;
  int page_size;
  tor_mmap_impl_t *res;
  size_t size, filesize;

  tor_assert(filename);

  fd = open(filename, O_RDONLY, 0);
  if (fd<0) {
    int save_errno = errno;
    int severity = (errno == ENOENT) ? LOG_INFO : LOG_WARN;
    log_fn(severity, LD_FS,"Could not open \"%s\" for mmap(): %s",filename,
           strerror(errno));
    errno = save_errno;
    return NULL;
  }

  size = filesize = (size_t) lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  /* ensure page alignment */
  page_size = getpagesize();
  size += (size%page_size) ? page_size-(size%page_size) : 0;

  if (!size) {
    /* Zero-length file. If we call mmap on it, it will succeed but
     * return NULL, and bad things will happen. So just fail. */
    log_info(LD_FS,"File \"%s\" is empty. Ignoring.",filename);
    errno = ERANGE;
    close(fd);
    return NULL;
  }

  string = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);
  if (string == MAP_FAILED) {
    int save_errno = errno;
    log_warn(LD_FS,"Could not mmap file \"%s\": %s", filename,
             strerror(errno));
    errno = save_errno;
    return NULL;
  }

  res = tor_malloc_zero(sizeof(tor_mmap_impl_t));
  res->base.data = string;
  res->base.size = filesize;
  res->mapping_size = size;

  return &(res->base);
}
/** Release storage held for a memory mapping. */
void
tor_munmap_file(tor_mmap_t *handle)
{
  tor_mmap_impl_t *h = SUBTYPE_P(handle, tor_mmap_impl_t, base);
  munmap((char*)h->base.data, h->mapping_size);
  tor_free(h);
}
#elif defined(MS_WINDOWS)
/** Implementation for tor_mmap_t: holds the regular tor_mmap_t, along
 * with extra fields needed for WIN32 memory mapping. */
typedef struct win_mmap_t {
  tor_mmap_t base;
  HANDLE file_handle;
  HANDLE mmap_handle;
} win_mmap_t;
tor_mmap_t *
tor_mmap_file(const char *filename)
{
  win_mmap_t *res = tor_malloc_zero(sizeof(win_mmap_t));
  int empty = 0;
  res->file_handle = INVALID_HANDLE_VALUE;
  res->mmap_handle = NULL;

  res->file_handle = CreateFile(filename,
                                GENERIC_READ, FILE_SHARE_READ,
                                NULL,
                                OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL,
                                0);

  if (res->file_handle == INVALID_HANDLE_VALUE)
    goto win_err;

  res->base.size = GetFileSize(res->file_handle, NULL);

  if (res->base.size == 0) {
    log_info(LD_FS,"File \"%s\" is empty. Ignoring.",filename);
    empty = 1;
    goto err;
  }

  res->mmap_handle = CreateFileMapping(res->file_handle,
                                       NULL,
                                       PAGE_READONLY,
#if SIZEOF_SIZE_T > 4
                                       (res->base.size >> 32),
#else
                                       0,
#endif
                                       (res->base.size & 0xfffffffful),
                                       NULL);
  if (res->mmap_handle == NULL)
    goto win_err;
  res->base.data = (char*) MapViewOfFile(res->mmap_handle,
                                         FILE_MAP_READ,
                                         0, 0, 0);
  if (!res->base.data)
    goto win_err;

  return &(res->base);
 win_err: {
    DWORD e = GetLastError();
    int severity = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) ?
      LOG_INFO : LOG_WARN;
    char *msg = format_win32_error(e);
    log_fn(severity, LD_FS, "Couldn't mmap file \"%s\": %s", filename, msg);
    tor_free(msg);
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
      errno = ENOENT;
    else
      errno = EINVAL;
  }
 err:
  if (empty)
    errno = ERANGE;
  tor_munmap_file(&res->base);
  return NULL;
}
void
tor_munmap_file(tor_mmap_t *handle)
{
  win_mmap_t *h = SUBTYPE_P(handle, win_mmap_t, base);
  if (handle->data)
    /* This is an ugly cast, but without it, "data" in struct tor_mmap_t would
       have to be redefined as non-const. */
    UnmapViewOfFile( (LPVOID) handle->data);

  if (h->mmap_handle != NULL)
    CloseHandle(h->mmap_handle);
  if (h->file_handle != INVALID_HANDLE_VALUE)
    CloseHandle(h->file_handle);
  tor_free(h);
}
#else
tor_mmap_t *
tor_mmap_file(const char *filename)
{
  struct stat st;
  char *res = read_file_to_str(filename, RFTS_BIN|RFTS_IGNORE_MISSING, &st);
  tor_mmap_t *handle;
  if (! res)
    return NULL;
  handle = tor_malloc_zero(sizeof(tor_mmap_t));
  handle->data = res;
  handle->size = st.st_size;
  return handle;
}
void
tor_munmap_file(tor_mmap_t *handle)
{
  char *d = (char*)handle->data;
  tor_free(d);
  memset(handle, 0, sizeof(tor_mmap_t));
  tor_free(handle);
}
#endif

/** Replacement for snprintf.  Differs from platform snprintf in two
 * ways: First, always NUL-terminates its output.  Second, always
 * returns -1 if the result is truncated.  (Note that this return
 * behavior does <i>not</i> conform to C99; it just happens to be
 * easier to emulate "return -1" with conformant implementations than
 * it is to emulate "return number that would be written" with
 * non-conformant implementations.) */
int
tor_snprintf(char *str, size_t size, const char *format, ...)
{
  va_list ap;
  int r;
  va_start(ap,format);
  r = tor_vsnprintf(str,size,format,ap);
  va_end(ap);
  return r;
}

/** Replacement for vsnprintf; behavior differs as tor_snprintf differs from
 * snprintf.
 */
int
tor_vsnprintf(char *str, size_t size, const char *format, va_list args)
{
  int r;
  if (size == 0)
    return -1; /* no place for the NUL */
  if (size > SIZE_T_CEILING)
    return -1;
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

/** Given <b>hlen</b> bytes at <b>haystack</b> and <b>nlen</b> bytes at
 * <b>needle</b>, return a pointer to the first occurrence of the needle
 * within the haystack, or NULL if there is no such occurrence.
 *
 * Requires that nlen be greater than zero.
 */
const void *
tor_memmem(const void *_haystack, size_t hlen,
           const void *_needle, size_t nlen)
{
#if defined(HAVE_MEMMEM) && (!defined(__GNUC__) || __GNUC__ >= 2)
  tor_assert(nlen);
  return memmem(_haystack, hlen, _needle, nlen);
#else
  /* This isn't as fast as the GLIBC implementation, but it doesn't need to
   * be. */
  const char *p, *end;
  const char *haystack = (const char*)_haystack;
  const char *needle = (const char*)_needle;
  char first;
  tor_assert(nlen);

  p = haystack;
  end = haystack + hlen;
  first = *(const char*)needle;
  while ((p = memchr(p, first, end-p))) {
    if (p+nlen > end)
      return NULL;
    if (!memcmp(p, needle, nlen))
      return p;
    ++p;
  }
  return NULL;
#endif
}

#ifdef MS_WINDOWS
/** Take a filename and return a pointer to its final element.  This
 * function is called on __FILE__ to fix a MSVC nit where __FILE__
 * contains the full path to the file.  This is bad, because it
 * confuses users to find the home directory of the person who
 * compiled the binary in their warrning messages.
 */
const char *
tor_fix_source_file(const char *fname)
{
  const char *cp1, *cp2, *r;
  cp1 = strrchr(fname, '/');
  cp2 = strrchr(fname, '\\');
  if (cp1 && cp2) {
    r = (cp1<cp2)?(cp2+1):(cp1+1);
  } else if (cp1) {
    r = cp1+1;
  } else if (cp2) {
    r = cp2+1;
  } else {
    r = fname;
  }
  return r;
}
#endif

/**
 * Read a 16-bit value beginning at <b>cp</b>.  Equivalent to
 * *(uint16_t*)(cp), but will not cause segfaults on platforms that forbid
 * unaligned memory access.
 */
uint16_t
get_uint16(const char *cp)
{
  uint16_t v;
  memcpy(&v,cp,2);
  return v;
}
/**
 * Read a 32-bit value beginning at <b>cp</b>.  Equivalent to
 * *(uint32_t*)(cp), but will not cause segfaults on platforms that forbid
 * unaligned memory access.
 */
uint32_t
get_uint32(const char *cp)
{
  uint32_t v;
  memcpy(&v,cp,4);
  return v;
}
/**
 * Set a 16-bit value beginning at <b>cp</b> to <b>v</b>. Equivalent to
 * *(uint16_t)(cp) = v, but will not cause segfaults on platforms that forbid
 * unaligned memory access. */
void
set_uint16(char *cp, uint16_t v)
{
  memcpy(cp,&v,2);
}
/**
 * Set a 32-bit value beginning at <b>cp</b> to <b>v</b>. Equivalent to
 * *(uint32_t)(cp) = v, but will not cause segfaults on platforms that forbid
 * unaligned memory access. */
void
set_uint32(char *cp, uint32_t v)
{
  memcpy(cp,&v,4);
}

/**
 * Rename the file <b>from</b> to the file <b>to</b>.  On unix, this is
 * the same as rename(2).  On windows, this removes <b>to</b> first if
 * it already exists.
 * Returns 0 on success.  Returns -1 and sets errno on failure.
 */
int
replace_file(const char *from, const char *to)
{
#ifndef MS_WINDOWS
  return rename(from,to);
#else
  switch (file_status(to))
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

/** Change <b>fname</b>'s modification time to now. */
int
touch_file(const char *fname)
{
  if (utime(fname, NULL)!=0)
    return -1;
  return 0;
}

/** Count of number of sockets currently open.  (Undercounts sockets opened by
 * eventdns and libevent.) */
static int n_sockets_open = 0;

/** As close(), but guaranteed to work for sockets across platforms (including
 * Windows, where close()ing a socket doesn't work.  Returns 0 on success, -1
 * on failure. */
int
tor_close_socket(int s)
{
  int r = 0;
  /* On Windows, you have to call close() on fds returned by open(),
   * and closesocket() on fds returned by socket().  On Unix, everything
   * gets close()'d.  We abstract this difference by always using
   * tor_close_socket to close sockets, and always using close() on
   * files.
   */
#ifdef USE_BSOCKETS
  r = bclose(s);
#elif defined(MS_WINDOWS)
  r = closesocket(s);
#else
  r = close(s);
#endif
  if (r == 0) {
    --n_sockets_open;
  } else {
    int err = tor_socket_errno(-1);
    log_info(LD_NET, "Close returned an error: %s", tor_socket_strerror(err));
#ifdef WIN32
    if (err != WSAENOTSOCK)
      --n_sockets_open;
#else
    if (err != EBADF)
      --n_sockets_open;
#endif
    r = -1;
  }
  if (n_sockets_open < 0)
    log_warn(LD_BUG, "Our socket count is below zero: %d. Please submit a "
             "bug report.", n_sockets_open);
  return r;
}

/** As socket(), but counts the number of open sockets. */
int
tor_open_socket(int domain, int type, int protocol)
{
  int s = socket(domain, type, protocol);
  if (s >= 0)
    ++n_sockets_open;
  return s;
}

/** Return the number of sockets we currently have opened. */
int
get_n_open_sockets(void)
{
  return n_sockets_open;
}

/** Turn <b>socket</b> into a nonblocking socket.
 */
void
set_socket_nonblocking(int socket)
{
#if defined(MS_WINDOWS) && !defined(USE_BSOCKETS)
  unsigned long nonblocking = 1;
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
tor_socketpair(int family, int type, int protocol, int fd[2])
{
//don't use win32 socketpairs (they are always bad)
#if defined(HAVE_SOCKETPAIR) && !defined(MS_WINDOWS)
  int r;
  r = socketpair(family, type, protocol, fd);
  return r < 0 ? -errno : r;
#elif defined(USE_BSOCKETS)
  return bsocketpair(family, type, protocol, fd);
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
    int saved_errno = -1;

    if (protocol
#ifdef AF_UNIX
        || family != AF_UNIX
#endif
        ) {
#ifdef MS_WINDOWS
      return -WSAEAFNOSUPPORT;
#else
      return -EAFNOSUPPORT;
#endif
    }
    if (!fd) {
      return -EINVAL;
    }

    listener = tor_open_socket(AF_INET, type, 0);
    if (listener < 0)
      return -tor_socket_errno(-1);
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listen_addr.sin_port = 0;   /* kernel chooses port.  */
    if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
        == -1)
      goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
      goto tidy_up_and_fail;

    connector = tor_open_socket(AF_INET, type, 0);
    if (connector < 0)
      goto tidy_up_and_fail;
    /* We want to find out the port number to connect to.  */
    size = sizeof(connect_addr);
    if (getsockname(listener, (struct sockaddr *) &connect_addr, &size) == -1)
      goto tidy_up_and_fail;
    if (size != sizeof (connect_addr))
      goto abort_tidy_up_and_fail;
    if (connect(connector, (struct sockaddr *) &connect_addr,
                sizeof(connect_addr)) == -1)
      goto tidy_up_and_fail;

    size = sizeof(listen_addr);
    acceptor = accept(listener, (struct sockaddr *) &listen_addr, &size);
    if (acceptor < 0)
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
    saved_errno = WSAECONNABORTED;
#else
    saved_errno = ECONNABORTED; /* I hope this is portable and appropriate.  */
#endif
  tidy_up_and_fail:
    if (saved_errno < 0)
      saved_errno = errno;
    if (listener != -1)
      tor_close_socket(listener);
    if (connector != -1)
      tor_close_socket(connector);
    if (acceptor != -1)
      tor_close_socket(acceptor);
    return -saved_errno;
#endif
}

#define ULIMIT_BUFFER 32 /* keep 32 extra fd's beyond _ConnLimit */

#if defined(HAVE_GETRLIMIT) && !defined(HAVE_RLIM_T)
typedef unsigned long rlim_t;
#endif

/** Learn the maximum allowed number of file descriptors. (Some systems
 * have a low soft limit.
 *
 * We compute this by finding the largest number between <b>limit</b>
 * and <b>cap</b> that we can use. If we can't find a number greater
 * than or equal to <b>limit</b>, then we fail: return -1.
 *
 * Otherwise, return the number minus some buffer to allow for other
 * file descriptors we'll want available for ordinary use. */
int
set_max_file_descriptors(unsigned long limit, unsigned long cap)
{
#ifndef HAVE_GETRLIMIT
  log_fn(LOG_INFO, LD_NET,
         "This platform is missing getrlimit(). Proceeding.");
  if (limit < cap) {
    log_info(LD_CONFIG, "ConnLimit must be at most %d. Using that.", (int)cap);
    limit = cap;
  }
#else
  struct rlimit rlim;
  rlim_t most;
  tor_assert(limit > 0);
  tor_assert(cap > 0);

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    log_warn(LD_NET, "Could not get maximum number of file descriptors: %s",
             strerror(errno));
    return -1;
  }
  //log_notice(LD_CONFIG, "%llu %llu", rlim.rlim_cur, rlim.rlim_max);
  if ((unsigned long)rlim.rlim_max < limit) {
    log_warn(LD_CONFIG,"We need %lu file descriptors available, and we're "
             "limited to %lu. Please change your ulimit -n.",
             limit, (unsigned long)rlim.rlim_max);
    return -1;
  }
  most = rlim.rlim_max > (rlim_t)cap ? (rlim_t)cap : rlim.rlim_max;
  if ((rlim_t)most > rlim.rlim_cur) {
    log_info(LD_NET,"Raising max file descriptors from %lu to %lu.",
             (unsigned long)rlim.rlim_cur, (unsigned long)most);
  }
  rlim.rlim_cur = most;

  if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    int bad = 1;
#ifdef OPEN_MAX
    if (errno == EINVAL && OPEN_MAX < rlim.rlim_cur) {
      /* On some platforms, OPEN_MAX is the real limit, and getrlimit() is
       * full of nasty lies.  I'm looking at you, OSX 10.5.... */
      rlim.rlim_cur = OPEN_MAX;
      if (setrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        if (rlim.rlim_cur < (rlim_t)limit) {
          log_warn(LD_CONFIG, "We are limited to %lu file descriptors by "
                 "OPEN_MAX, and ConnLimit is %lu.  Changing ConnLimit; sorry.",
                   (unsigned long)OPEN_MAX, limit);
        } else {
          log_info(LD_CONFIG, "Dropped connection limit to OPEN_MAX (%lu); "
                   "Apparently, %lu was too high and rlimit lied to us.",
                   (unsigned long)OPEN_MAX, (unsigned long)most);
        }
        most = rlim.rlim_cur;
        bad = 0;
      }
    }
#endif
    if (bad) {
      log_warn(LD_CONFIG,"Couldn't set maximum number of file descriptors: %s",
               strerror(errno));
      return -1;
    }
  }
  /* leave some overhead for logs, etc, */
  limit = most;
#endif

  if (limit < ULIMIT_BUFFER) {
    log_warn(LD_CONFIG,
             "ConnLimit must be at least %d. Failing.", ULIMIT_BUFFER);
    return -1;
  }
  return limit - ULIMIT_BUFFER;
}

/** Call setuid and setgid to run as <b>user</b>:<b>group</b>.  Return 0 on
 * success.  On failure, log and return -1.
 */
int
switch_id(const char *user, const char *group)
{
#ifndef MS_WINDOWS
  struct passwd *pw = NULL;
  struct group *gr = NULL;

  if (user) {
    pw = getpwnam(user);
    if (pw == NULL) {
      log_warn(LD_CONFIG,"User '%s' not found.", user);
      return -1;
    }
  }

  /* switch the group first, while we still have the privileges to do so */
  if (group) {
    gr = getgrnam(group);
    if (gr == NULL) {
      log_warn(LD_CONFIG,"Group '%s' not found.", group);
      return -1;
    }

    if (setgid(gr->gr_gid) != 0) {
      log_warn(LD_GENERAL,"Error setting to configured GID: %s",
               strerror(errno));
      return -1;
    }
  } else if (user) {
    if (setgid(pw->pw_gid) != 0) {
      log_warn(LD_GENERAL,"Error setting to user GID: %s", strerror(errno));
      return -1;
    }
  }

  /* now that the group is switched, we can switch users and lose
     privileges */
  if (user) {
    if (setuid(pw->pw_uid) != 0) {
      log_warn(LD_GENERAL,"Error setting UID: %s", strerror(errno));
      return -1;
    }
  }

  return 0;
#else
  (void)user;
  (void)group;
#endif

  log_warn(LD_CONFIG,
           "User or group specified, but switching users is not supported.");
  return -1;
}

#ifdef HAVE_PWD_H
/** Allocate and return a string containing the home directory for the
 * user <b>username</b>. Only works on posix-like systems. */
char *
get_user_homedir(const char *username)
{
  struct passwd *pw;
  tor_assert(username);

  if (!(pw = getpwnam(username))) {
    log_err(LD_CONFIG,"User \"%s\" not found.", username);
    return NULL;
  }
  return tor_strdup(pw->pw_dir);
}
#endif

/** Set *addr to the IP address (in dotted-quad notation) stored in c.
 * Return 1 on success, 0 if c is badly formatted.  (Like inet_aton(c,addr),
 * but works on Windows and Solaris.)
 */
int
tor_inet_aton(const char *c, struct in_addr* addr)
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

/** Given <b>af</b>==AF_INET and <b>src</b> a struct in_addr, or
 * <b>af</b>==AF_INET6 and <b>src</b> a struct in6_addr, try to format the
 * address and store it in the <b>len</b>-byte buffer <b>dst</b>.  Returns
 * <b>dst</b> on success, NULL on failure.
 *
 * (Like inet_ntop(af,src,dst,len), but works on platforms that don't have it:
 * Tor sometimes needs to format ipv6 addresses even on platforms without ipv6
 * support.) */
const char *
tor_inet_ntop(int af, const void *src, char *dst, size_t len)
{
  if (af == AF_INET) {
    if (tor_inet_ntoa(src, dst, len) < 0)
      return NULL;
    else
      return dst;
  } else if (af == AF_INET6) {
    const struct in6_addr *addr = src;
    char buf[64], *cp;
    int longestGapLen = 0, longestGapPos = -1, i,
      curGapPos = -1, curGapLen = 0;
    uint16_t words[8];
    for (i = 0; i < 8; ++i) {
      words[i] = (((uint16_t)addr->s6_addr[2*i])<<8) + addr->s6_addr[2*i+1];
    }
    if (words[0] == 0 && words[1] == 0 && words[2] == 0 && words[3] == 0 &&
        words[4] == 0 && ((words[5] == 0 && words[6] && words[7]) ||
                          (words[5] == 0xffff))) {
      /* This is an IPv4 address. */
      if (words[5] == 0) {
        tor_snprintf(buf, sizeof(buf), "::%d.%d.%d.%d",
                     addr->s6_addr[12], addr->s6_addr[13],
                     addr->s6_addr[14], addr->s6_addr[15]);
      } else {
        tor_snprintf(buf, sizeof(buf), "::%x:%d.%d.%d.%d", words[5],
                     addr->s6_addr[12], addr->s6_addr[13],
                     addr->s6_addr[14], addr->s6_addr[15]);
      }
      if (strlen(buf) > len)
        return NULL;
      strlcpy(dst, buf, len);
      return dst;
    }
    i = 0;
    while (i < 8) {
      if (words[i] == 0) {
        curGapPos = i++;
        curGapLen = 1;
        while (i<8 && words[i] == 0) {
          ++i; ++curGapLen;
        }
        if (curGapLen > longestGapLen) {
          longestGapPos = curGapPos;
          longestGapLen = curGapLen;
        }
      } else {
        ++i;
      }
    }
    if (longestGapLen<=1)
      longestGapPos = -1;

    cp = buf;
    for (i = 0; i < 8; ++i) {
      if (words[i] == 0 && longestGapPos == i) {
        if (i == 0)
          *cp++ = ':';
        *cp++ = ':';
        while (i < 8 && words[i] == 0)
          ++i;
        --i; /* to compensate for loop increment. */
      } else {
        tor_snprintf(cp, sizeof(buf)-(cp-buf), "%x", (unsigned)words[i]);
        cp += strlen(cp);
        if (i != 7)
          *cp++ = ':';
      }
    }
    *cp = '\0';
    if (strlen(buf) > len)
      return NULL;
    strlcpy(dst, buf, len);
    return dst;
  } else {
    return NULL;
  }
}

/** Given <b>af</b>==AF_INET or <b>af</b>==AF_INET6, and a string <b>src</b>
 * encoding an IPv4 address or IPv6 address correspondingly, try to parse the
 * address and store the result in <b>dst</b> (which must have space for a
 * struct in_addr or a struct in6_addr, as appropriate).  Return 1 on success,
 * 0 on a bad parse, and -1 on a bad <b>af</b>.
 *
 * (Like inet_pton(af,src,dst) but works on platforms that don't have it: Tor
 * sometimes needs to format ipv6 addresses even on platforms without ipv6
 * support.) */
int
tor_inet_pton(int af, const char *src, void *dst)
{
  if (af == AF_INET) {
    return tor_inet_aton(src, dst);
  } else if (af == AF_INET6) {
    struct in6_addr *out = dst;
    uint16_t words[8];
    int gapPos = -1, i, setWords=0;
    const char *dot = strchr(src, '.');
    const char *eow; /* end of words. */
    if (dot == src)
      return 0;
    else if (!dot)
      eow = src+strlen(src);
    else {
      int byte1,byte2,byte3,byte4;
      char more;
      for (eow = dot-1; eow >= src && TOR_ISDIGIT(*eow); --eow)
        ;
      ++eow;

      /* We use "scanf" because some platform inet_aton()s are too lax
       * about IPv4 addresses of the form "1.2.3" */
      if (sscanf(eow, "%d.%d.%d.%d%c", &byte1,&byte2,&byte3,&byte4,&more) != 4)
        return 0;

      if (byte1 > 255 || byte1 < 0 ||
          byte2 > 255 || byte2 < 0 ||
          byte3 > 255 || byte3 < 0 ||
          byte4 > 255 || byte4 < 0)
        return 0;

      words[6] = (byte1<<8) | byte2;
      words[7] = (byte3<<8) | byte4;
      setWords += 2;
    }

    i = 0;
    while (src < eow) {
      if (i > 7)
        return 0;
      if (TOR_ISXDIGIT(*src)) {
        char *next;
        int r = strtol(src, &next, 16);
        if (next > 4+src)
          return 0;
        if (next == src)
          return 0;
        if (r<0 || r>65536)
          return 0;

        words[i++] = (uint16_t)r;
        setWords++;
        src = next;
        if (*src != ':' && src != eow)
          return 0;
        ++src;
      } else if (*src == ':' && i > 0 && gapPos==-1) {
        gapPos = i;
        ++src;
      } else if (*src == ':' && i == 0 && src[1] == ':' && gapPos==-1) {
        gapPos = i;
        src += 2;
      } else {
        return 0;
      }
    }

    if (setWords > 8 ||
        (setWords == 8 && gapPos != -1) ||
        (setWords < 8 && gapPos == -1))
      return 0;

    if (gapPos >= 0) {
      int nToMove = setWords - (dot ? 2 : 0) - gapPos;
      int gapLen = 8 - setWords;
      tor_assert(nToMove >= 0);
      memmove(&words[gapPos+gapLen], &words[gapPos],
              sizeof(uint16_t)*nToMove);
      memset(&words[gapPos], 0, sizeof(uint16_t)*gapLen);
    }
    for (i = 0; i < 8; ++i) {
      out->s6_addr[2*i  ] = words[i] >> 8;
      out->s6_addr[2*i+1] = words[i] & 0xff;
    }

    return 1;
  } else {
    return -1;
  }
}

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address, in host byte order.  Returns 0
 * on success, -1 on failure; 1 on transient failure.
 *
 * (This function exists because standard windows gethostbyname
 * doesn't treat raw IP addresses properly.)
 */
int
tor_lookup_hostname(const char *name, uint32_t *addr)
{
  tor_addr_t myaddr;
  int ret;

  if ((ret = tor_addr_lookup(name, AF_INET, &myaddr)))
    return ret;

  if (IN_FAMILY(&myaddr) == AF_INET) {
    *addr = IPV4IPh(&myaddr);
    return ret;
  }

  return -1;
}

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *<b>addr</b> to the proper IP address and family. The <b>family</b>
 * argument (which must be AF_INET, AF_INET6, or AF_UNSPEC) declares a
 * <i>preferred</i> family, though another one may be returned if only one
 * family is implemented for this address.
 *
 * Return 0 on success, -1 on failure; 1 on transient failure.
 */
int
tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr)
{
  /* Perhaps eventually this should be replaced by a tor_getaddrinfo or
   * something.
   */
  struct in_addr iaddr;
  struct in6_addr iaddr6;
  tor_assert(name);
  tor_assert(addr);
  tor_assert(family == AF_INET || family == AF_UNSPEC);
  memset(addr, 0, sizeof(addr)); /* Clear the extraneous fields. */
  if (!*name) {
    /* Empty address is an error. */
    return -1;
  } else if (tor_inet_pton(AF_INET, name, &iaddr)) {
    /* It's an IPv4 IP. */
    addr->family = AF_INET;
    memcpy(&addr->addr.in_addr, &iaddr, sizeof(struct in_addr));
    return 0;
  } else if (tor_inet_pton(AF_INET6, name, &iaddr6)) {
    addr->family = AF_INET6;
    memcpy(&addr->addr.in6_addr, &iaddr6, sizeof(struct in6_addr));
    return 0;
  } else {
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo *res=NULL, *res_p;
    struct addrinfo *best=NULL;
    struct addrinfo hints;
    int result = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(name, NULL, &hints, &res);
    if (!err) {
      best = NULL;
      for (res_p = res; res_p; res_p = res_p->ai_next) {
        if (family == AF_UNSPEC) {
          if (res_p->ai_family == AF_INET) {
            best = res_p;
            break;
          } else if (res_p->ai_family == AF_INET6 && !best) {
            best = res_p;
          }
        } else if (family == res_p->ai_family) {
          best = res_p;
          break;
        }
      }
      if (!best)
        best = res;
      if (best->ai_family == AF_INET) {
        addr->family = AF_INET;
        memcpy(&addr->addr.in_addr,
               &((struct sockaddr_in*)best->ai_addr)->sin_addr,
               sizeof(struct in_addr));
        result = 0;
      } else if (best->ai_family == AF_INET6) {
        addr->family = AF_INET6;
        memcpy(&addr->addr.in6_addr,
               &((struct sockaddr_in6*)best->ai_addr)->sin6_addr,
               sizeof(struct in6_addr));
        result = 0;
      }
      freeaddrinfo(res);
      return result;
    }
    return (err == EAI_AGAIN) ? 1 : -1;
#else
    struct hostent *ent;
    int err;
#ifdef HAVE_GETHOSTBYNAME_R_6_ARG
    char buf[2048];
    struct hostent hostent;
    int r;
    r = gethostbyname_r(name, &hostent, buf, sizeof(buf), &ent, &err);
#elif defined(HAVE_GETHOSTBYNAME_R_5_ARG)
    char buf[2048];
    struct hostent hostent;
    ent = gethostbyname_r(name, &hostent, buf, sizeof(buf), &err);
#elif defined(HAVE_GETHOSTBYNAME_R_3_ARG)
    struct hostent_data data;
    struct hostent hent;
    memset(&data, 0, sizeof(data));
    err = gethostbyname_r(name, &hent, &data);
    ent = err ? NULL : &hent;
#else
    ent = gethostbyname(name);
#ifdef MS_WINDOWS
    err = WSAGetLastError();
#else
    err = h_errno;
#endif
#endif /* endif HAVE_GETHOSTBYNAME_R_6_ARG. */
    if (ent) {
      addr->family = ent->h_addrtype;
      if (ent->h_addrtype == AF_INET) {
        memcpy(&addr->addr.in_addr, ent->h_addr, sizeof(struct in_addr));
      } else if (ent->h_addrtype == AF_INET6) {
        memcpy(&addr->addr.in6_addr, ent->h_addr, sizeof(struct in6_addr));
      } else {
        tor_assert(0); /* gethostbyname() returned a bizarre addrtype */
      }
      return 0;
    }
#ifdef MS_WINDOWS
    return (err == WSATRY_AGAIN) ? 1 : -1;
#else
    return (err == TRY_AGAIN) ? 1 : -1;
#endif
#endif
  }
}

/** Hold the result of our call to <b>uname</b>. */
static char uname_result[256];
/** True iff uname_result is set. */
static int uname_result_is_set = 0;

/** Return a pointer to a description of our platform.
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
      tor_snprintf(uname_result, sizeof(uname_result), "%s %s",
               u.sysname, u.machine);
    } else
#endif
      {
#ifdef MS_WINDOWS
        OSVERSIONINFOEX info;
        int i;
        unsigned int leftover_mask;
        const char *plat = NULL;
        const char *extra = NULL;
        static struct {
          unsigned major; unsigned minor; const char *version;
        } win_version_table[] = {
          { 6, 0, "Windows \"Longhorn\"" },
          { 5, 2, "Windows Server 2003" },
          { 5, 1, "Windows XP" },
          { 5, 0, "Windows 2000" },
          /* { 4, 0, "Windows NT 4.0" }, */
          { 4, 90, "Windows Me" },
          { 4, 10, "Windows 98" },
          /* { 4, 0, "Windows 95" } */
          { 3, 51, "Windows NT 3.51" },
          { 0, 0, NULL }
        };
#ifdef VER_SUITE_BACKOFFICE
        static struct {
          unsigned int mask; const char *str;
        } win_mask_table[] = {
          { VER_SUITE_BACKOFFICE,         " {backoffice}" },
          { VER_SUITE_BLADE,              " {\"blade\" (2003, web edition)}" },
          { VER_SUITE_DATACENTER,         " {datacenter}" },
          { VER_SUITE_ENTERPRISE,         " {enterprise}" },
          { VER_SUITE_EMBEDDEDNT,         " {embedded}" },
          { VER_SUITE_PERSONAL,           " {personal}" },
          { VER_SUITE_SINGLEUSERTS,
            " {terminal services, single user}" },
          { VER_SUITE_SMALLBUSINESS,      " {small business}" },
          { VER_SUITE_SMALLBUSINESS_RESTRICTED,
            " {small business, restricted}" },
          { VER_SUITE_TERMINAL,           " {terminal services}" },
          { 0, NULL },
        };
#endif
        memset(&info, 0, sizeof(info));
        info.dwOSVersionInfoSize = sizeof(info);
        if (! GetVersionEx((LPOSVERSIONINFO)&info)) {
          strlcpy(uname_result, "Bizarre version of Windows where GetVersionEx"
                  " doesn't work.", sizeof(uname_result));
          uname_result_is_set = 1;
          return uname_result;
        }
        if (info.dwMajorVersion == 4 && info.dwMinorVersion == 0) {
          if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
            plat = "Windows NT 4.0";
          else
            plat = "Windows 95";
          if (info.szCSDVersion[1] == 'B')
            extra = "OSR2 (B)";
          else if (info.szCSDVersion[1] == 'C')
            extra = "OSR2 (C)";
        } else {
          for (i=0; win_version_table[i].major>0; ++i) {
            if (win_version_table[i].major == info.dwMajorVersion &&
                win_version_table[i].minor == info.dwMinorVersion) {
              plat = win_version_table[i].version;
              break;
            }
          }
        }
        if (plat && !strcmp(plat, "Windows 98")) {
          if (info.szCSDVersion[1] == 'A')
            extra = "SE (A)";
          else if (info.szCSDVersion[1] == 'B')
            extra = "SE (B)";
        }
        if (plat) {
          if (!extra)
            extra = info.szCSDVersion;
          tor_snprintf(uname_result, sizeof(uname_result), "%s %s",
                       plat, extra);
        } else {
          if (info.dwMajorVersion > 6 ||
              (info.dwMajorVersion==6 && info.dwMinorVersion>0))
            tor_snprintf(uname_result, sizeof(uname_result),
                      "Very recent version of Windows [major=%d,minor=%d] %s",
                      (int)info.dwMajorVersion,(int)info.dwMinorVersion,
                      info.szCSDVersion);
          else
            tor_snprintf(uname_result, sizeof(uname_result),
                      "Unrecognized version of Windows [major=%d,minor=%d] %s",
                      (int)info.dwMajorVersion,(int)info.dwMinorVersion,
                      info.szCSDVersion);
        }
#ifdef VER_SUITE_BACKOFFICE
        if (info.wProductType == VER_NT_DOMAIN_CONTROLLER) {
          strlcat(uname_result, " [domain controller]", sizeof(uname_result));
        } else if (info.wProductType == VER_NT_SERVER) {
          strlcat(uname_result, " [server]", sizeof(uname_result));
        } else if (info.wProductType == VER_NT_WORKSTATION) {
          strlcat(uname_result, " [workstation]", sizeof(uname_result));
        }
        leftover_mask = info.wSuiteMask;
        for (i = 0; win_mask_table[i].mask; ++i) {
          if (info.wSuiteMask & win_mask_table[i].mask) {
            strlcat(uname_result, win_mask_table[i].str, sizeof(uname_result));
            leftover_mask &= ~win_mask_table[i].mask;
          }
        }
        if (leftover_mask) {
          size_t len = strlen(uname_result);
          tor_snprintf(uname_result+len, sizeof(uname_result)-len,
                       " {0x%x}", info.wSuiteMask);
        }
#endif
#else
        strlcpy(uname_result, "Unknown platform", sizeof(uname_result));
#endif
      }
    uname_result_is_set = 1;
  }
  return uname_result;
}

/*
 *   Process control
 */

#if defined(USE_PTHREADS)
/** Wraps a void (*)(void*) function and its argument so we can
 * invoke them in a way pthreads would expect.
 */
typedef struct tor_pthread_data_t {
  void (*func)(void *);
  void *data;
} tor_pthread_data_t;
/** Given a tor_pthread_data_t <b>_data</b>, call _data-&gt;func(d-&gt;data)
 * and free _data.  Used to make sure we can call functions the way pthread
 * expects. */
static void *
tor_pthread_helper_fn(void *_data)
{
  tor_pthread_data_t *data = _data;
  void (*func)(void*);
  void *arg;
  /* mask signals to worker threads to avoid SIGPIPE, etc */
  sigset_t sigs;
  /* We're in a subthread; don't handle any signals here. */
  sigfillset(&sigs);
  pthread_sigmask(SIG_SETMASK, &sigs, NULL);

  func = data->func;
  arg = data->data;
  tor_free(_data);
  func(arg);
  return NULL;
}
#endif

/** Minimalist interface to run a void function in the background.  On
 * unix calls fork, on win32 calls beginthread.  Returns -1 on failure.
 * func should not return, but rather should call spawn_exit.
 *
 * NOTE: if <b>data</b> is used, it should not be allocated on the stack,
 * since in a multithreaded environment, there is no way to be sure that
 * the caller's stack will still be around when the called function is
 * running.
 */
int
spawn_func(void (*func)(void *), void *data)
{
#if defined(USE_WIN32_THREADS)
  int rv;
  rv = (int)_beginthread(func, 0, data);
  if (rv == (int)-1)
    return -1;
  return 0;
#elif defined(USE_PTHREADS)
  pthread_t thread;
  tor_pthread_data_t *d;
  d = tor_malloc(sizeof(tor_pthread_data_t));
  d->data = data;
  d->func = func;
  if (pthread_create(&thread,NULL,tor_pthread_helper_fn,d))
    return -1;
  if (pthread_detach(thread))
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
void
spawn_exit(void)
{
#if defined(USE_WIN32_THREADS)
  _endthread();
  //we should never get here. my compiler thinks that _endthread returns, this
  //is an attempt to fool it.
  tor_assert(0);
  _exit(0);
#elif defined(USE_PTHREADS)
  pthread_exit(NULL);
#else
  /* http://www.erlenstar.demon.co.uk/unix/faq_2.html says we should
   * call _exit, not exit, from child processes. */
  _exit(0);
#endif

}

/** Set *timeval to the current time of day.  On error, log and terminate.
 * (Same as gettimeofday(timeval,NULL), but never returns -1.)
 */
void
tor_gettimeofday(struct timeval *timeval)
{
#ifdef MS_WINDOWS
  /* Epoch bias copied from perl: number of units between windows epoch and
   * unix epoch. */
#define EPOCH_BIAS U64_LITERAL(116444736000000000)
#define UNITS_PER_SEC U64_LITERAL(10000000)
#define USEC_PER_SEC U64_LITERAL(1000000)
#define UNITS_PER_USEC U64_LITERAL(10)
  union {
    uint64_t ft_64;
    FILETIME ft_ft;
  } ft;
  /* number of 100-nsec units since Jan 1, 1601 */
  GetSystemTimeAsFileTime(&ft.ft_ft);
  if (ft.ft_64 < EPOCH_BIAS) {
    log_err(LD_GENERAL,"System time is before 1970; failing.");
    exit(1);
  }
  ft.ft_64 -= EPOCH_BIAS;
  timeval->tv_sec = (unsigned) (ft.ft_64 / UNITS_PER_SEC);
  timeval->tv_usec = (unsigned) ((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(timeval, NULL)) {
    log_err(LD_GENERAL,"gettimeofday failed.");
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

#if defined(TOR_IS_MULTITHREADED) && !defined(MS_WINDOWS)
/** Defined iff we need to add locks when defining fake versions of reentrant
 * versions of time-related functions. */
#define TIME_FNS_NEED_LOCKS
#endif

#ifndef HAVE_LOCALTIME_R
#ifdef TIME_FNS_NEED_LOCKS
struct tm *
tor_localtime_r(const time_t *timep, struct tm *result)
{
  struct tm *r;
  static tor_mutex_t *m=NULL;
  if (!m) { m=tor_mutex_new(); }
  tor_assert(result);
  tor_mutex_acquire(m);
  r = localtime(timep);
  memcpy(result, r, sizeof(struct tm));
  tor_mutex_release(m);
  return result;
}
#else
struct tm *
tor_localtime_r(const time_t *timep, struct tm *result)
{
  struct tm *r;
  tor_assert(result);
  r = localtime(timep);
  memcpy(result, r, sizeof(struct tm));
  return result;
}
#endif
#endif

#ifndef HAVE_GMTIME_R
#ifdef TIME_FNS_NEED_LOCKS
struct tm *
tor_gmtime_r(const time_t *timep, struct tm *result)
{
  struct tm *r;
  static tor_mutex_t *m=NULL;
  if (!m) { m=tor_mutex_new(); }
  tor_assert(result);
  tor_mutex_acquire(m);
  r = gmtime(timep);
  memcpy(result, r, sizeof(struct tm));
  tor_mutex_release(m);
  return result;
}
#else
struct tm *
tor_gmtime_r(const time_t *timep, struct tm *result)
{
  struct tm *r;
  tor_assert(result);
  r = gmtime(timep);
  memcpy(result, r, sizeof(struct tm));
  return result;
}
#endif
#endif

#if defined(USE_WIN32_THREADS) && 0
/** A generic lock structure for multithreaded builds. */
struct tor_mutex_t {
  HANDLE handle;
};
tor_mutex_t *
tor_mutex_new(void)
{
  tor_mutex_t *m;
  m = tor_malloc_zero(sizeof(tor_mutex_t));
  m->handle = CreateMutex(NULL, FALSE, NULL);
  tor_assert(m->handle != NULL);
  return m;
}
void
tor_mutex_free(tor_mutex_t *m)
{
  CloseHandle(m->handle);
  tor_free(m);
}
void
tor_mutex_acquire(tor_mutex_t *m)
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
      log_warn(LD_GENERAL, "Failed to acquire mutex: %d",(int) GetLastError());
  }
}
void
tor_mutex_release(tor_mutex_t *m)
{
  BOOL r;
  r = ReleaseMutex(m->handle);
  if (!r) {
    log_warn(LD_GENERAL, "Failed to release mutex: %d", (int) GetLastError());
  }
}
unsigned long
tor_get_thread_id(void)
{
  return (unsigned long)GetCurrentThreadId();
}
#elif defined(USE_WIN32_THREADS)
/** A generic lock structure for multithreaded builds. */
struct tor_mutex_t {
  CRITICAL_SECTION mutex;
};
tor_mutex_t *
tor_mutex_new(void)
{
  tor_mutex_t *m = tor_malloc_zero(sizeof(tor_mutex_t));
  InitializeCriticalSection(&m->mutex);
  return m;
}
void
tor_mutex_free(tor_mutex_t *m)
{
  DeleteCriticalSection(&m->mutex);
  tor_free(m);
}
void
tor_mutex_acquire(tor_mutex_t *m)
{
  tor_assert(m);
  EnterCriticalSection(&m->mutex);
}
void
tor_mutex_release(tor_mutex_t *m)
{
  LeaveCriticalSection(&m->mutex);
}
unsigned long
tor_get_thread_id(void)
{
  return (unsigned long)GetCurrentThreadId();
}
#elif defined(USE_PTHREADS)
/** A generic lock structure for multithreaded builds. */
struct tor_mutex_t {
  pthread_mutex_t mutex;
};
/** Allocate and return new lock. */
tor_mutex_t *
tor_mutex_new(void)
{
  int err;
  tor_mutex_t *mutex = tor_malloc_zero(sizeof(tor_mutex_t));
  err = pthread_mutex_init(&mutex->mutex, NULL);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d creating a mutex.", err);
    tor_fragile_assert();
  }
  return mutex;
}
/** Wait until <b>m</b> is free, then acquire it. */
void
tor_mutex_acquire(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_lock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d locking a mutex.", err);
    tor_fragile_assert();
  }
}
/** Release the lock <b>m</b> so another thread can have it. */
void
tor_mutex_release(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_unlock(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d unlocking a mutex.", err);
    tor_fragile_assert();
  }
}
/** Free all storage held by the lock <b>m</b>. */
void
tor_mutex_free(tor_mutex_t *m)
{
  int err;
  tor_assert(m);
  err = pthread_mutex_destroy(&m->mutex);
  if (PREDICT_UNLIKELY(err)) {
    log_err(LD_GENERAL, "Error %d destroying a mutex.", err);
    tor_fragile_assert();
  }
  tor_free(m);
}
/** Return an integer representing this thread. */
unsigned long
tor_get_thread_id(void)
{
  union {
    pthread_t thr;
    unsigned long id;
  } r;
  r.thr = pthread_self();
  return r.id;
}
#else
/** A generic lock structure for multithreaded builds. */
struct tor_mutex_t {
  int _unused;
};
#endif

/* Conditions. */
#ifdef USE_PTHREADS
#if 0
/** Cross-platform condition implementation. */
struct tor_cond_t {
  pthread_cond_t cond;
};
/** Return a newly allocated condition, with nobody waiting on it. */
tor_cond_t *
tor_cond_new(void)
{
  tor_cond_t *cond = tor_malloc_zero(sizeof(tor_cond_t));
  if (pthread_cond_init(&cond->cond, NULL)) {
    tor_free(cond);
    return NULL;
  }
  return cond;
}
/** Release all resources held by <b>cond</b>. */
void
tor_cond_free(tor_cond_t *cond)
{
  tor_assert(cond);
  if (pthread_cond_destroy(&cond->cond)) {
    log_warn(LD_GENERAL,"Error freeing condition: %s", strerror(errno));
    return;
  }
  tor_free(cond);
}
/** Wait until one of the tor_cond_signal functions is called on <b>cond</b>.
 * All waiters on the condition must wait holding the same <b>mutex</b>.
 * Returns 0 on success, negative on failure. */
int
tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex)
{
  return pthread_cond_wait(&cond->cond, &mutex->mutex) ? -1 : 0;
}
/** Wake up one of the waiters on <b>cond</b>. */
void
tor_cond_signal_one(tor_cond_t *cond)
{
  pthread_cond_signal(&cond->cond);
}
/** Wake up all of the waiters on <b>cond</b>. */
void
tor_cond_signal_all(tor_cond_t *cond)
{
  pthread_cond_broadcast(&cond->cond);
}
#endif
/** Set up common structures for use by threading. */
void
tor_threads_init(void)
{
}
#elif defined(USE_WIN32_THREADS)
#if 0
static DWORD cond_event_tls_index;
struct tor_cond_t {
  CRITICAL_SECTION mutex;
  smartlist_t *events;
};
tor_cond_t *
tor_cond_new(void)
{
  tor_cond_t *cond = tor_malloc_zero(sizeof(tor_cond_t));
  InitializeCriticalSection(&cond->mutex);
  cond->events = smartlist_create();
  return cond;
}
void
tor_cond_free(tor_cond_t *cond)
{
  tor_assert(cond);
  DeleteCriticalSection(&cond->mutex);
  /* XXXX notify? */
  smartlist_free(cond->events);
  tor_free(cond);
}
int
tor_cond_wait(tor_cond_t *cond, tor_mutex_t *mutex)
{
  HANDLE event;
  int r;
  tor_assert(cond);
  tor_assert(mutex);
  event = TlsGetValue(cond_event_tls_index);
  if (!event) {
    event = CreateEvent(0, FALSE, FALSE, NULL);
    TlsSetValue(cond_event_tls_index, event);
  }
  EnterCriticalSection(&cond->mutex);

  tor_assert(WaitForSingleObject(event, 0) == WAIT_TIMEOUT);
  tor_assert(!smartlist_isin(cond->events, event));
  smartlist_add(cond->events, event);

  LeaveCriticalSection(&cond->mutex);

  tor_mutex_release(mutex);
  r = WaitForSingleObject(event, INFINITE);
  tor_mutex_acquire(mutex);

  switch (r) {
    case WAIT_OBJECT_0: /* we got the mutex normally. */
      break;
    case WAIT_ABANDONED: /* holding thread exited. */
    case WAIT_TIMEOUT: /* Should never happen. */
      tor_assert(0);
      break;
    case WAIT_FAILED:
      log_warn(LD_GENERAL, "Failed to acquire mutex: %d",(int) GetLastError());
  }
  return 0;
}
void
tor_cond_signal_one(tor_cond_t *cond)
{
  HANDLE event;
  tor_assert(cond);

  EnterCriticalSection(&cond->mutex);

  if ((event = smartlist_pop_last(cond->events)))
    SetEvent(event);

  LeaveCriticalSection(&cond->mutex);
}
void
tor_cond_signal_all(tor_cond_t *cond)
{
  tor_assert(cond);

  EnterCriticalSection(&cond->mutex);
  SMARTLIST_FOREACH(cond->events, HANDLE, event, SetEvent(event));
  smartlist_clear(cond->events);
  LeaveCriticalSection(&cond->mutex);
}
#endif
void
tor_threads_init(void)
{
#if 0
  cond_event_tls_index = TlsAlloc();
#endif
}
#endif

/**
 * On Windows, WSAEWOULDBLOCK is not always correct: when you see it,
 * you need to ask the socket for its actual errno.  Also, you need to
 * get your errors from WSAGetLastError, not errno.  (If you supply a
 * socket of -1, we check WSAGetLastError, but don't correct
 * WSAEWOULDBLOCKs.)
 *
 * The upshot of all of this is that when a socket call fails, you
 * should call tor_socket_errno <em>at most once</em> on the failing
 * socket to get the error.
 */
#if defined(MS_WINDOWS) && !defined(USE_BSOCKETS)
int
tor_socket_errno(int sock)
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

#if defined(MS_WINDOWS) && !defined(USE_BSOCKETS)
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
  E(WSAENOBUFS, "No buffer space available"),
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
const char *
tor_socket_strerror(int e)
{
  int i;
  for (i=0; windows_socket_errors[i].code >= 0; ++i) {
    if (e == windows_socket_errors[i].code)
      return windows_socket_errors[i].msg;
  }
  return strerror(e);
}
#endif

/** Called before we make any calls to network-related functions.
 * (Some operating systems require their network libraries to be
 * initialized.) */
int
network_init(void)
{
#ifdef MS_WINDOWS
  /* This silly exercise is necessary before windows will allow
   * gethostbyname to work. */
  WSADATA WSAData;
  int r;
  r = WSAStartup(0x101,&WSAData);
  if (r) {
    log_warn(LD_NET,"Error initializing windows network layer: code was %d",r);
    return -1;
  }
  /* WSAData.iMaxSockets might show the max sockets we're allowed to use.
   * We might use it to complain if we're trying to be a server but have
   * too few sockets available. */
#endif
  return 0;
}

#ifdef MS_WINDOWS
/** Return a newly allocated string describing the windows system error code
 * <b>err</b>.  Note that error codes are different from errno.  Error codes
 * come from GetLastError() when a winapi call fails.  errno is set only when
 * ansi functions fail.  Whee. */
char *
format_win32_error(DWORD err)
{
  LPVOID str = NULL;
  char *result;

  /* Somebody once decided that this interface was better than strerror(). */
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                 FORMAT_MESSAGE_FROM_SYSTEM |
                 FORMAT_MESSAGE_IGNORE_INSERTS,
                 NULL, err,
                 MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                 (LPTSTR) &str,
                 0, NULL);

  if (str) {
    result = tor_strdup((char*)str);
    LocalFree(str); /* LocalFree != free() */
  } else {
    result = tor_strdup("<unformattable error>");
  }
  return result;
}
#endif

