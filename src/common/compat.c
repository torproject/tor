/* Copyright 2003-2004 Roger Dingledine
 * Copyright 2004-2006 Roger Dingledine, Nick Mathewson */
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
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_SYS_UTIME_H
#include <sys/utime.h>
#endif

#include "log.h"
#include "util.h"

/* Inline the strl functions if the platform doesn't have them. */
#ifndef HAVE_STRLCPY
#include "strlcpy.c"
#endif
#ifndef HAVE_STRLCAT
#include "strlcat.c"
#endif

/* used by inet_addr, not defined on solaris anywhere!? */
#ifndef INADDR_NONE
#define INADDR_NONE ((unsigned long) -1)
#endif

/** Replacement for snprintf.  Differs from platform snprintf in two
 * ways: First, always NUL-terminates its output.  Second, always
 * returns -1 if the result is truncated.  (Note that this return
 * behavior does <i>not</i> conform to C99; it just happens to be the
 * easiest to emulate "return -1" with conformant implementations than
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

#ifndef UNALIGNED_INT_ACCESS_OK
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
#endif

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

/** Turn <b>socket</b> into a nonblocking socket.
 */
void
set_socket_nonblocking(int socket)
{
#ifdef MS_WINDOWS
  int nonblocking = 1;
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
 *
 * Returns 0 on success and -errno on failure; do not rely on the value
 * of errno or WSAGetLastSocketError().
 **/
/* It would be nicer just to set errno, but that won't work for windows. */
int
tor_socketpair(int family, int type, int protocol, int fd[2])
{
#ifdef HAVE_SOCKETPAIR
  int r;
  r = socketpair(family, type, protocol, fd);
  return r < 0 ? -errno : r;
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

    listener = socket(AF_INET, type, 0);
    if (listener == -1)
      return -tor_socket_errno(-1);
    if (!SOCKET_IS_POLLABLE(listener)) {
      warn(LD_NET, "Too many connections; can't open socketpair");
      tor_close_socket(listener);
#ifdef MS_WINDOWS
      return -ENFILE;
#else
      return -ENCONN;
#endif
    }
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    listen_addr.sin_port = 0;   /* kernel chooses port.  */
    if (bind(listener, (struct sockaddr *) &listen_addr, sizeof (listen_addr))
        == -1)
      goto tidy_up_and_fail;
    if (listen(listener, 1) == -1)
      goto tidy_up_and_fail;

    connector = socket(AF_INET, type, 0);
    if (connector == -1)
      goto tidy_up_and_fail;
    if (!SOCKET_IS_POLLABLE(connector)) {
      warn(LD_NET, "Too many connections; can't open socketpair");
      goto tidy_up_and_fail;
    }
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
    if (acceptor == -1)
      goto tidy_up_and_fail;
    if (!SOCKET_IS_POLLABLE(acceptor)) {
      warn(LD_NET, "Too many connections; can't open socketpair");
      goto tidy_up_and_fail;
    }
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
    log(LOG_INFO, LD_CONFIG, "ConnLimit must be at most %d. Using that.", cap);
    limit = cap;
  }
#else
  struct rlimit rlim;
  unsigned long most;
  tor_assert(limit > 0);
  tor_assert(cap > 0);

  if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    warn(LD_NET, "Could not get maximum number of file descriptors: %s",
           strerror(errno));
    return -1;
  }
  if (rlim.rlim_max < limit) {
    warn(LD_CONFIG,"We need %lu file descriptors available, and we're "
         "limited to %lu. Please change your ulimit -n.",
         limit, (unsigned long)rlim.rlim_max);
    return -1;
  }
  most = (rlim.rlim_max > cap) ? cap : (unsigned) rlim.rlim_max;
  if (most > rlim.rlim_cur) {
    info(LD_NET,"Raising max file descriptors from %lu to %lu.",
           (unsigned long)rlim.rlim_cur, most);
  }
  rlim.rlim_cur = most;
  if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
    warn(LD_CONFIG, "Could not set maximum number of file descriptors: %s",
           strerror(errno));
    return -1;
  }
  /* leave some overhead for logs, etc, */
  limit = most;
#endif

  if (limit < ULIMIT_BUFFER) {
    warn(LD_CONFIG,"ConnLimit must be at least %d. Failing.", ULIMIT_BUFFER);
    return -1;
  }
  return limit - ULIMIT_BUFFER;
}

/** Call setuid and setgid to run as <b>user</b>:<b>group</b>.  Return 0 on
 * success.  On failure, log and return -1.
 */
int
switch_id(char *user, char *group)
{
#ifndef MS_WINDOWS
  struct passwd *pw = NULL;
  struct group *gr = NULL;

  if (user) {
    pw = getpwnam(user);
    if (pw == NULL) {
      err(LD_CONFIG,"User '%s' not found.", user);
      return -1;
    }
  }

  /* switch the group first, while we still have the privileges to do so */
  if (group) {
    gr = getgrnam(group);
    if (gr == NULL) {
      err(LD_CONFIG,"Group '%s' not found.", group);
      return -1;
    }

    if (setgid(gr->gr_gid) != 0) {
      err(LD_GENERAL,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  } else if (user) {
    if (setgid(pw->pw_gid) != 0) {
      err(LD_GENERAL,"Error setting GID: %s", strerror(errno));
      return -1;
    }
  }

  /* now that the group is switched, we can switch users and lose
     privileges */
  if (user) {
    if (setuid(pw->pw_uid) != 0) {
      err(LD_GENERAL,"Error setting UID: %s", strerror(errno));
      return -1;
    }
  }

  return 0;
#endif

  err(LD_CONFIG,
      "User or group specified, but switching users is not supported.");
  return -1;
}

#ifdef HAVE_PWD_H
/** Allocate and return a string containing the home directory for the
 * user <b>username</b>. Only works on posix-like systems */
char *
get_user_homedir(const char *username)
{
  struct passwd *pw;
  tor_assert(username);

  if (!(pw = getpwnam(username))) {
    err(LD_CONFIG,"User \"%s\" not found.", username);
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

/** Similar behavior to Unix gethostbyname: resolve <b>name</b>, and set
 * *addr to the proper IP address, in network byte order.  Returns 0
 * on success, -1 on failure; 1 on transient failure.
 *
 * (This function exists because standard windows gethostbyname
 * doesn't treat raw IP addresses properly.)
 */
int
tor_lookup_hostname(const char *name, uint32_t *addr)
{
  /* Perhaps eventually this should be replaced by a tor_getaddrinfo or
   * something.
   */
  struct in_addr iaddr;
  tor_assert(name);
  tor_assert(addr);
  if (!*name) {
    /* Empty address is an error. */
    return -1;
  } else if (tor_inet_aton(name, &iaddr)) {
    /* It's an IP. */
    memcpy(addr, &iaddr.s_addr, 4);
    return 0;
  } else {
#ifdef HAVE_GETADDRINFO
    int err;
    struct addrinfo *res=NULL, *res_p;
    struct addrinfo hints;
    int result = -1;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_STREAM;
    err = getaddrinfo(name, NULL, NULL, &res);
    if (!err) {
      for (res_p = res; res_p; res_p = res_p->ai_next) {
        if (res_p->ai_family == AF_INET) {
          struct sockaddr_in *sin = (struct sockaddr_in *)res_p->ai_addr;
          memcpy(addr, &sin->sin_addr, 4);
          result = 0;
          break;
        }
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
#endif
    if (ent) {
      /* break to remind us if we move away from IPv4 */
      tor_assert(ent->h_length == 4);
      memcpy(addr, ent->h_addr, 4);
      return 0;
    }
    memset(addr, 0, 4);
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
        static struct {
          int major; int minor; const char *version;
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
          { -1, -1, NULL }
        };
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
        info.dwOSVersionInfoSize = sizeof(info);
        GetVersionEx((LPOSVERSIONINFO)&info);
        if (info.dwMajorVersion == 4 && info.dwMinorVersion == 0) {
          if (info.dwPlatformId == VER_PLATFORM_WIN32_NT)
            plat = "Windows NT 4.0";
          else
            plat = "Windows 95";
        } else {
          for (i=0; win_version_table[i].major>=0; ++i) {
            if (win_version_table[i].major == info.dwMajorVersion &&
                win_version_table[i].minor == info.dwMinorVersion) {
              plat = win_version_table[i].version;
              break;
            }
          }
        }
        if (plat) {
          tor_snprintf(uname_result, sizeof(uname_result), "%s %s",
                       plat, info.szCSDVersion);
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
/** Wraps a an int (*)(void*) function and its argument so we can
 * invoke them in a way pthreads would expect.
 */
typedef struct tor_pthread_data_t {
  int (*func)(void *);
  void *data;
} tor_pthread_data_t;
static void *
tor_pthread_helper_fn(void *_data)
{
  tor_pthread_data_t *data = _data;
  int (*func)(void*);
  void *arg;
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
spawn_func(int (*func)(void *), void *data)
{
#if defined(USE_WIN32_THREADS)
  int rv;
  rv = _beginthread(func, 0, data);
  if (rv == (unsigned long) -1)
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
    err(LD_GENERAL,"System time is before 1970; failing.");
    exit(1);
  }
  ft.ft_64 -= EPOCH_BIAS;
  timeval->tv_sec = (unsigned) (ft.ft_64 / UNITS_PER_SEC);
  timeval->tv_usec = (unsigned) ((ft.ft_64 / UNITS_PER_USEC) % USEC_PER_SEC);
#elif defined(HAVE_GETTIMEOFDAY)
  if (gettimeofday(timeval, NULL)) {
    err(LD_GENERAL,"gettimeofday failed.");
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

#ifdef USE_WIN32_THREADS
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
      warn(LD_GENERAL, "Failed to acquire mutex: %d", GetLastError());
  }
}
void
tor_mutex_release(tor_mutex_t *m)
{
  BOOL r;
  r = ReleaseMutex(m->handle);
  if (!r) {
    warn(LD_GENERAL, "Failed to release mutex: %d", GetLastError());
  }
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
tor_mutex_t *
tor_mutex_new(void)
{
  tor_mutex_t *mutex = tor_malloc_zero(sizeof(tor_mutex_t));
  pthread_mutex_init(&mutex->mutex, NULL);
  return mutex;
}
void
tor_mutex_acquire(tor_mutex_t *m)
{
  tor_assert(m);
  pthread_mutex_lock(&m->mutex);
}
void
tor_mutex_release(tor_mutex_t *m)
{
  tor_assert(m);
  pthread_mutex_unlock(&m->mutex);
}
void
tor_mutex_free(tor_mutex_t *m)
{
  tor_assert(m);
  pthread_mutex_destroy(&m->mutex);
  tor_free(m);
}
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
#ifdef MS_WINDOWS
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
    warn(LD_NET,"Error initializing windows network layer: code was %d",r);
    return -1;
  }
  /* WSAData.iMaxSockets might show the max sockets we're allowed to use.
   * We might use it to complain if we're trying to be a server but have
   * too few sockets available. */
#endif
  return 0;
}

