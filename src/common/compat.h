/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_COMPAT_H
#define TOR_COMPAT_H

#include "orconfig.h"
#include "lib/cc/torint.h"
#include "lib/testsupport/testsupport.h"
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdarg.h>
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif

#include "lib/cc/compat_compiler.h"
#include "lib/arch/bytes.h"
#include "lib/time/compat_time.h"
#include "lib/string/compat_ctype.h"
#include "lib/string/compat_string.h"
#include "lib/string/printf.h"
#include "lib/net/socket.h"
#include "lib/net/ipv4.h"
#include "lib/net/ipv6.h"
#include "lib/net/resolve.h"
#include "lib/fs/files.h"
#include "lib/fs/mmap.h"
#include "lib/fs/userdb.h"
#include "lib/wallclock/timeval.h"
#include "lib/intmath/cmp.h"

#include <stdio.h>
#include <errno.h>

/* ===== Time compatibility */

/* ===== File compatibility */

/* ===== Net compatibility */

/* ===== OS compatibility */

/* This needs some of the declarations above so we include it here. */
#include "lib/thread/threads.h"

#endif /* !defined(TOR_COMPAT_H) */
