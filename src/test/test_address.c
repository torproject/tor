/* Copyright (c) 2014-2015, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define ADDRESS_PRIVATE

#ifdef _WIN32
#include <winsock2.h>
/* For access to structs needed by GetAdaptersAddresses */
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#include <iphlpapi.h>
#endif

#ifdef HAVE_IFADDRS_TO_SMARTLIST
#include <net/if.h>
#include <ifaddrs.h>
#endif

#ifdef HAVE_IFCONF_TO_SMARTLIST
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <net/if.h>
#endif

#include "or.h"
#include "address.h"
#include "test.h"

/** Return 1 iff <b>sockaddr1</b> and <b>sockaddr2</b> represent
 * the same IP address and port combination. Otherwise, return 0.
 */
static uint8_t
sockaddr_in_are_equal(struct sockaddr_in *sockaddr1,
                      struct sockaddr_in *sockaddr2)
{
   return ((sockaddr1->sin_family == sockaddr2->sin_family) &&
           (sockaddr1->sin_port == sockaddr2->sin_port) &&
           (sockaddr1->sin_addr.s_addr == sockaddr2->sin_addr.s_addr));
}

/** Return 1 iff <b>sockaddr1</b> and <b>sockaddr2</b> represent
 * the same IP address and port combination. Otherwise, return 0.
 */
static uint8_t
sockaddr_in6_are_equal(struct sockaddr_in6 *sockaddr1,
                       struct sockaddr_in6 *sockaddr2)
{
   return ((sockaddr1->sin6_family == sockaddr2->sin6_family) &&
           (sockaddr1->sin6_port == sockaddr2->sin6_port) &&
           (tor_memeq(sockaddr1->sin6_addr.s6_addr,
                      sockaddr2->sin6_addr.s6_addr,16)));
}

/** Create a sockaddr_in structure from IP address string <b>ip_str</b>.
 *
 * If <b>out</b> is not NULL, write the result
 * to the memory address in <b>out</b>. Otherwise, allocate the memory
 * for result. On success, return pointer to result. Otherwise, return
 * NULL.
 */
static struct sockaddr_in *
sockaddr_in_from_string(const char *ip_str, struct sockaddr_in *out)
{
  // [FIXME: add some error checking?]
  if (!out)
    out = tor_malloc_zero(sizeof(struct sockaddr_in));

  out->sin_family = AF_INET;
  out->sin_port = 0;
  tor_inet_pton(AF_INET,ip_str,&(out->sin_addr));

  return out;
}

/** Return 1 iff <b>smartlist</b> contains a tor_addr_t structure
 * that points to 127.0.0.1. Otherwise, return 0.
 */
static int
smartlist_contains_localhost_tor_addr(smartlist_t *smartlist)
{
  int found_localhost = 0;

  struct sockaddr_in *sockaddr_localhost;
  struct sockaddr_storage *sockaddr_to_check;

  sockaddr_localhost = sockaddr_in_from_string("127.0.0.1",NULL);

  sockaddr_to_check = tor_malloc(sizeof(struct sockaddr_in));

  SMARTLIST_FOREACH_BEGIN(smartlist, tor_addr_t *, tor_addr) {
    tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                         sizeof(struct sockaddr_in));

    if (sockaddr_in_are_equal((struct sockaddr_in *)sockaddr_to_check,
                              sockaddr_localhost)) {
      found_localhost = 1;
      break;
    }
  } SMARTLIST_FOREACH_END(tor_addr);

  tor_free(sockaddr_localhost);
  tor_free(sockaddr_to_check);

  return found_localhost;
}

#ifdef HAVE_IFADDRS_TO_SMARTLIST
static void
test_address_ifaddrs_to_smartlist(void *arg)
{
   struct ifaddrs *ifa = NULL;
   struct ifaddrs *ifa_ipv4 = NULL;
   struct ifaddrs *ifa_ipv6 = NULL;
   struct sockaddr_in *ipv4_sockaddr_local = NULL;
   struct sockaddr_in *netmask_slash8 = NULL;
   struct sockaddr_in *ipv4_sockaddr_remote = NULL;
   struct sockaddr_in6 *ipv6_sockaddr = NULL;
   smartlist_t *smartlist = NULL;
   tor_addr_t *tor_addr = NULL;
   struct sockaddr *sockaddr_to_check = NULL;
   socklen_t addr_len;

   (void)arg;

   netmask_slash8 = sockaddr_in_from_string("255.0.0.0",NULL);
   ipv4_sockaddr_local = sockaddr_in_from_string("127.0.0.1",NULL);
   ipv4_sockaddr_remote = sockaddr_in_from_string("128.52.160.20",NULL);

   ipv6_sockaddr = tor_malloc(sizeof(struct sockaddr_in6));
   ipv6_sockaddr->sin6_family = AF_INET6;
   ipv6_sockaddr->sin6_port = 0;
   inet_pton(AF_INET6, "2001:db8:8714:3a90::12",
             &(ipv6_sockaddr->sin6_addr));

   ifa = tor_malloc(sizeof(struct ifaddrs));
   ifa_ipv4 = tor_malloc(sizeof(struct ifaddrs));
   ifa_ipv6 = tor_malloc(sizeof(struct ifaddrs));

   ifa->ifa_next = ifa_ipv4;
   ifa->ifa_name = tor_strdup("eth0");
   ifa->ifa_flags = IFF_UP | IFF_RUNNING;
   ifa->ifa_addr = (struct sockaddr *)ipv4_sockaddr_local;
   ifa->ifa_netmask = (struct sockaddr *)netmask_slash8;
   ifa->ifa_dstaddr = NULL;
   ifa->ifa_data = NULL;

   ifa_ipv4->ifa_next = ifa_ipv6;
   ifa_ipv4->ifa_name = tor_strdup("eth1");
   ifa_ipv4->ifa_flags = IFF_UP | IFF_RUNNING;
   ifa_ipv4->ifa_addr = (struct sockaddr *)ipv4_sockaddr_remote;
   ifa_ipv4->ifa_netmask = (struct sockaddr *)netmask_slash8;
   ifa_ipv4->ifa_dstaddr = NULL;
   ifa_ipv4->ifa_data = NULL;

   ifa_ipv6->ifa_next = NULL;
   ifa_ipv6->ifa_name = tor_strdup("eth2");
   ifa_ipv6->ifa_flags = IFF_UP | IFF_RUNNING;
   ifa_ipv6->ifa_addr = (struct sockaddr *)ipv6_sockaddr;
   ifa_ipv6->ifa_netmask = NULL;
   ifa_ipv6->ifa_dstaddr = NULL;
   ifa_ipv6->ifa_data = NULL;

   smartlist = ifaddrs_to_smartlist(ifa);

   tt_assert(smartlist);
   tt_assert(smartlist_len(smartlist) == 3);

   sockaddr_to_check = tor_malloc(sizeof(struct sockaddr_in6));

   tor_addr = smartlist_get(smartlist,0);
   addr_len =
   tor_addr_to_sockaddr(tor_addr,0,sockaddr_to_check,
                        sizeof(struct sockaddr_in));

   tt_int_op(addr_len,==,sizeof(struct sockaddr_in));
   tt_assert(sockaddr_in_are_equal((struct sockaddr_in *)sockaddr_to_check,
                                   ipv4_sockaddr_local));

   tor_addr = smartlist_get(smartlist,1);
   addr_len =
   tor_addr_to_sockaddr(tor_addr,0,sockaddr_to_check,
                        sizeof(struct sockaddr_in));

   tt_int_op(addr_len,==,sizeof(struct sockaddr_in));
   tt_assert(sockaddr_in_are_equal((struct sockaddr_in *)sockaddr_to_check,
                                   ipv4_sockaddr_remote));

   tor_addr = smartlist_get(smartlist,2);
   addr_len =
   tor_addr_to_sockaddr(tor_addr,0,sockaddr_to_check,
                        sizeof(struct sockaddr_in6));

   tt_int_op(addr_len,==,sizeof(struct sockaddr_in6));
   tt_assert(sockaddr_in6_are_equal((struct sockaddr_in6*)sockaddr_to_check,
                                    ipv6_sockaddr));

   done:
   tor_free(netmask_slash8);
   tor_free(ipv4_sockaddr_local);
   tor_free(ipv4_sockaddr_remote);
   tor_free(ipv6_sockaddr);
   tor_free(ifa->ifa_name);
   tor_free(ifa_ipv4->ifa_name);
   tor_free(ifa_ipv6->ifa_name);
   tor_free(ifa);
   tor_free(ifa_ipv4);
   tor_free(ifa_ipv6);
   tor_free(sockaddr_to_check);
   SMARTLIST_FOREACH(smartlist, tor_addr_t *, t, tor_free(t));
   smartlist_free(smartlist);

   return;
}

static void
test_address_get_if_addrs_ifaddrs(void *arg)
{

  smartlist_t *results = NULL;

  (void)arg;

  results = get_interface_addresses_ifaddrs(0);

  tt_int_op(smartlist_len(results),>=,1);
  tt_assert(smartlist_contains_localhost_tor_addr(results));

  done:
  SMARTLIST_FOREACH(results, tor_addr_t *, t, tor_free(t));
  smartlist_free(results);
  return;
}

#endif

#ifdef HAVE_IP_ADAPTER_TO_SMARTLIST

static void
test_address_get_if_addrs_win32(void *arg)
{

  smartlist_t *results = NULL;

  (void)arg;

  results = get_interface_addresses_win32(0);

  tt_int_op(smartlist_len(results),>=,1);
  tt_assert(smartlist_contains_localhost_tor_addr(results));

  done:
  SMARTLIST_FOREACH(results, tor_addr_t *, t, tor_free(t));
  tor_free(results);
  return;
}

static void
test_address_ip_adapter_addresses_to_smartlist(void *arg)
{

  IP_ADAPTER_ADDRESSES *addrs1;
  IP_ADAPTER_ADDRESSES *addrs2;

  IP_ADAPTER_UNICAST_ADDRESS *unicast11;
  IP_ADAPTER_UNICAST_ADDRESS *unicast12;
  IP_ADAPTER_UNICAST_ADDRESS *unicast21;

  smartlist_t *result = NULL;

  struct sockaddr_in *sockaddr_test1;
  struct sockaddr_in *sockaddr_test2;
  struct sockaddr_in *sockaddr_localhost;
  struct sockaddr_in *sockaddr_to_check;

  tor_addr_t *tor_addr;

  (void)arg;
  (void)sockaddr_in6_are_equal;

  sockaddr_to_check = tor_malloc_zero(sizeof(struct sockaddr_in));

  addrs1 =
  tor_malloc_zero(sizeof(IP_ADAPTER_ADDRESSES));

  addrs1->FirstUnicastAddress =
  unicast11 = tor_malloc_zero(sizeof(IP_ADAPTER_UNICAST_ADDRESS));
  sockaddr_test1 = sockaddr_in_from_string("86.59.30.40",NULL);
  unicast11->Address.lpSockaddr = (LPSOCKADDR)sockaddr_test1;

  unicast11->Next = unicast12 =
  tor_malloc_zero(sizeof(IP_ADAPTER_UNICAST_ADDRESS));
  sockaddr_test2 = sockaddr_in_from_string("93.95.227.222", NULL);
  unicast12->Address.lpSockaddr = (LPSOCKADDR)sockaddr_test2;

  addrs1->Next = addrs2 =
  tor_malloc_zero(sizeof(IP_ADAPTER_ADDRESSES));

  addrs2->FirstUnicastAddress =
  unicast21 = tor_malloc_zero(sizeof(IP_ADAPTER_UNICAST_ADDRESS));
  sockaddr_localhost = sockaddr_in_from_string("127.0.0.1", NULL);
  unicast21->Address.lpSockaddr = (LPSOCKADDR)sockaddr_localhost;

  result = ip_adapter_addresses_to_smartlist(addrs1);

  tt_assert(result);
  tt_assert(smartlist_len(result) == 3);

  tor_addr = smartlist_get(result,0);

  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_assert(sockaddr_in_are_equal(sockaddr_test1,sockaddr_to_check));

  tor_addr = smartlist_get(result,1);

  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_assert(sockaddr_in_are_equal(sockaddr_test2,sockaddr_to_check));

  tor_addr = smartlist_get(result,2);

  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_assert(sockaddr_in_are_equal(sockaddr_localhost,sockaddr_to_check));

  done:
  SMARTLIST_FOREACH(result, tor_addr_t *, t, tor_free(t));
  smartlist_free(result);
  tor_free(addrs1);
  tor_free(addrs2);
  tor_free(unicast11->Address.lpSockaddr);
  tor_free(unicast11);
  tor_free(unicast12->Address.lpSockaddr);
  tor_free(unicast12);
  tor_free(unicast21->Address.lpSockaddr);
  tor_free(unicast21);
  tor_free(sockaddr_to_check);
  return;
}
#endif

#ifdef HAVE_IFCONF_TO_SMARTLIST

static void
test_address_ifreq_to_smartlist(void *arg)
{
  smartlist_t *results = NULL;
  const tor_addr_t *tor_addr = NULL;
  struct sockaddr_in *sockaddr = NULL;
  struct sockaddr_in *sockaddr_eth1 = NULL;
  struct sockaddr_in *sockaddr_to_check = NULL;

  struct ifconf *ifc;
  struct ifreq *ifr;
  struct ifreq *ifr_next;

  socklen_t addr_len;

  (void)arg;

  sockaddr_to_check = tor_malloc(sizeof(struct sockaddr_in));

  ifr = tor_malloc(sizeof(struct ifreq));
  memset(ifr,0,sizeof(struct ifreq));
  strlcpy(ifr->ifr_name,"lo",3);
  sockaddr = (struct sockaddr_in *) &(ifr->ifr_ifru.ifru_addr);
  sockaddr_in_from_string("127.0.0.1",sockaddr);

  ifc = tor_malloc(sizeof(struct ifconf));
  memset(ifc,0,sizeof(struct ifconf));
  ifc->ifc_len = sizeof(struct ifreq);
  ifc->ifc_ifcu.ifcu_req = ifr;

  results = ifreq_to_smartlist((struct ifreq *)ifc->ifc_buf,ifc->ifc_len);
  tt_int_op(smartlist_len(results),==,1);

  tor_addr = smartlist_get(results, 0);
  addr_len =
  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_int_op(addr_len,==,sizeof(struct sockaddr_in));
  tt_assert(sockaddr_in_are_equal(sockaddr,sockaddr_to_check));

  ifr = tor_realloc(ifr,2*sizeof(struct ifreq));
  ifr_next = ifr+1;
  strlcpy(ifr_next->ifr_name,"eth1",5);
  ifc->ifc_len = 2*sizeof(struct ifreq);
  ifc->ifc_ifcu.ifcu_req = ifr;
  sockaddr = (struct sockaddr_in *) &(ifr->ifr_ifru.ifru_addr);

  sockaddr_eth1 = (struct sockaddr_in *) &(ifr_next->ifr_ifru.ifru_addr);
  sockaddr_in_from_string("192.168.10.55",sockaddr_eth1);
  SMARTLIST_FOREACH(results, tor_addr_t *, t, tor_free(t));
  smartlist_free(results);

  results = ifreq_to_smartlist((struct ifreq *)ifc->ifc_buf,ifc->ifc_len);
  tt_int_op(smartlist_len(results),==,2);

  tor_addr = smartlist_get(results, 0);
  addr_len =
  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_int_op(addr_len,==,sizeof(struct sockaddr_in));
  tt_assert(sockaddr_in_are_equal(sockaddr,sockaddr_to_check));

  tor_addr = smartlist_get(results, 1);
  addr_len =
  tor_addr_to_sockaddr(tor_addr,0,(struct sockaddr *)sockaddr_to_check,
                       sizeof(struct sockaddr_in));

  tt_int_op(addr_len,==,sizeof(struct sockaddr_in));
  tt_assert(sockaddr_in_are_equal(sockaddr_eth1,sockaddr_to_check));

  done:
  tor_free(sockaddr_to_check);
  SMARTLIST_FOREACH(results, tor_addr_t *, t, tor_free(t));
  smartlist_free(results);
  tor_free(ifc);
  tor_free(ifr);
  return;
}

static void
test_address_get_if_addrs_ioctl(void *arg)
{

  smartlist_t *result = NULL;

  (void)arg;

  result = get_interface_addresses_ioctl(LOG_ERR);

  tt_assert(result);
  tt_int_op(smartlist_len(result),>=,1);

  tt_assert(smartlist_contains_localhost_tor_addr(result));

  done:
  SMARTLIST_FOREACH(result, tor_addr_t *, t, tor_free(t));
  smartlist_free(result);
  return;
}

#endif

#define ADDRESS_TEST(name, flags) \
  { #name, test_address_ ## name, flags, NULL, NULL }

struct testcase_t address_tests[] = {
#ifdef HAVE_IFADDRS_TO_SMARTLIST
  ADDRESS_TEST(get_if_addrs_ifaddrs, TT_FORK),
  ADDRESS_TEST(ifaddrs_to_smartlist, 0),
#endif
#ifdef HAVE_IP_ADAPTER_TO_SMARTLIST
  ADDRESS_TEST(get_if_addrs_win32, TT_FORK),
  ADDRESS_TEST(ip_adapter_addresses_to_smartlist, 0),
#endif
#ifdef HAVE_IFCONF_TO_SMARTLIST
  ADDRESS_TEST(get_if_addrs_ioctl, TT_FORK),
  ADDRESS_TEST(ifreq_to_smartlist, 0),
#endif
  END_OF_TESTCASES
};

