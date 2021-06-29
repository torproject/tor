#include "lib/net/address.h"
#include "lib/net/socket.h"
#include "lib/cc/ctassert.h"
#include "lib/container/smartlist.h"
#include "lib/ctime/di_ops.h"
#include "lib/log/log.h"
#include "lib/log/escape.h"
#include "lib/malloc/malloc.h"
#include "lib/net/inaddr.h"
#include "lib/string/compat_ctype.h"
#include "lib/string/compat_string.h"
#include "lib/string/parse_int.h"
#include "lib/string/printf.h"
#include "lib/string/util_string.h"

#include "ext/siphash.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
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
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_IFADDRS_H
#include <ifaddrs.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int fuzz_init(void){
 return 0;
}

int fuzz_cleanup(void){
 return 0;
}

int fuzz_main(const uint8_t *data, size_t sz){

 tor_addr_t addr;
 char *fuzzing_data = tor_memdup_nulterm(data, sz);
 tor_addr_parse(&addr, fuzzing_data);
 tor_free(fuzzing_data);
 return 0;
}
