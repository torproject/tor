/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file netlink.c
 * \brief Functions to query interface and routing table information.
 */

#include "orconfig.h"
#include "compat.h"
#include "util.h"
#include "address.h"
#include "torlog.h"

#include "netlink.h"

#if defined(__linux__)

#ifdef HAVE_LINUX_NETLINK_H
#include <linux/netlink.h>
#endif
#ifdef HAVE_LINUX_RTNETLINK_H
#include <linux/rtnetlink.h>
#endif

typedef int (*netlink_msg_fn)(void *, struct nlmsghdr *);

struct getaddr_ctx {
  tor_addr_t *addr;
  int found;

  sa_family_t family;
  int ifindex;
};

static int
netlink_query(tor_socket_t fd, int severity, void *req, size_t reqlen,
              netlink_msg_fn msgfn, void *ctx)
{
  static const size_t max_resp_len = 16384;
  void *resp = NULL;
  struct sockaddr_nl nladdr;
  struct msghdr msg;
  struct iovec vec;
  ssize_t len;
  int cbret = 0, ret = -1;

  if (!msgfn)
    goto out;

  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  nladdr.nl_groups = 0;

  /* Build the request datagram. */
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &nladdr;
  msg.msg_namelen = sizeof(nladdr);
  vec.iov_base = req;
  vec.iov_len = reqlen;
  msg.msg_iov = &vec;
  msg.msg_iovlen = 1;

  len = sendmsg(fd, &msg, 0);
  if (len < 0) {
    tor_log(severity, LD_NET, "Unable to send netlink request: %s",
            strerror(errno));
    goto out;
  }

  /* Allocate space for the response, and fixup the iovec. */
  resp = tor_malloc_zero(max_resp_len);
  vec.iov_base = resp;
  vec.iov_len = max_resp_len;

  /* Responses are not guaranteed to be passed back to userland as a single
   * message, and in fact will not be in a lot of cases.  Loop consuming
   * responses till either a NLMSG_DONE or NLMSG_ERROR is encountered.
   *
   * Note: If the socket is ever used for multiple simultanious queries, or as
   * an async event notification system, all of this will break unless
   * requests contain sequence numbers, and the response processor is updated
   * to care about said sequence numbers. */
  do {
    struct nlmsghdr *resp_hdr;

    /* Read the response. */
    len = recvmsg(fd, &msg, 0);
    if (len < 0) {
      tor_log(severity, LD_NET, "Unable to recv netlink response: %s",
              strerror(errno));
      goto out;
    }
    if (msg.msg_flags & MSG_TRUNC) {
      /* If this happens, there's basically no good solution, because the
       * truncated data will still sit in the queue.  It's worth noting that a
       * lot of other userland tools will break if this condition occurs. */
      tor_log(severity, LD_NET, "NETLINK response was truncated");
      goto out;
    }
    msg.msg_flags = 0;

    /* Parse the response payload into individual netlink messages. */
    resp_hdr = resp;
    for (; NLMSG_OK(resp_hdr, len); resp_hdr = NLMSG_NEXT(resp_hdr, len)) {
      /* Call user parsing callback, unless the callback returns something
       * that's non-0, indicating that it no longer cares about the rest of
       * the messages. */
      if (cbret == 0)
        cbret = msgfn(ctx, resp_hdr);

      if (resp_hdr->nlmsg_type == NLMSG_DONE) {
        ret = 0;
        goto out;
      }
      if (resp_hdr->nlmsg_type == NLMSG_ERROR) {
        goto out;
      }
    }
  } while (1);

 out:
  tor_free(resp);
  return ret;
}

static int
netlink_parse_getroute_msg(void *ctx, struct nlmsghdr *msg)
{
  struct rtmsg *rtm;
  struct rtattr *attr;
  ssize_t attrlen;
  int *result;
  int has_gateway = 0;
  int has_destination = 0;
  int ifindex = -1;

  result = ctx;

  /* This routine is also invoked on NLMSG_DONE/NLMSG_ERROR, but there's no
   * additional processing to be done for those cases. */
  if (msg->nlmsg_type == NLMSG_DONE || msg->nlmsg_type == NLMSG_ERROR)
    return 0;

  /* Each message corresponds to a single routing table entry.  We are only
   * interested in the main table, so skip processing attributes for the other
   * tables. */
  rtm = NLMSG_DATA(msg);
  if (rtm->rtm_table != RT_TABLE_MAIN)
    return 0;

  /* Determine if this routing table is the one corresponding to the default
   * route, as it will have a gateway set, and no destination network. */
  attr = RTM_RTA(rtm);
  attrlen = RTM_PAYLOAD(msg);
  for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {
    switch (attr->rta_type) {
    case RTA_GATEWAY:
      /* The gateway of the route.  Future versions of the code could stash
       * this if it is ever neccecary information. */
      has_gateway = 1;
      break;
    case RTA_DST:
      /* The destination network.  This information is omitted for the default
       * route. */
      has_destination = 1;
      break;
    case RTA_OIF:
      /* The output interface index. */
      ifindex = *(int*)RTA_DATA(attr);
      break;
    default:
      /* Ignore, as not interesting. */
      break;
    }
  }

  /* If after processing the routing table entry, we have found a gateway, no
   * destination, and a valid output interface index, we are done. */
  if (has_gateway && !has_destination && ifindex != -1) {
    *result = ifindex;
    return 1; /* Skip further processing. */
  }

  return 0;
}

static int
netlink_parse_getaddr_msg(void *ctx, struct nlmsghdr *msg)
{
  struct getaddr_ctx *result;
  struct ifaddrmsg *ifa;
  struct rtattr *attr;
  ssize_t attrlen;
  int is_prefered = 1;
  int found = 0;

  result = ctx;

  /* This routine is also invoked on NLMSG_DONE/NLMSG_ERROR, but there's no
   * additional processing to be done for those cases. */
  if (msg->nlmsg_type == NLMSG_DONE || msg->nlmsg_type == NLMSG_ERROR)
    return 0;

  ifa = NLMSG_DATA(msg);

  /* Filter out any addresses that:
   *  * Don't have the correct family.
   *  * Don't have the correct index.
   *  * Aren't globally scoped.
   *  * Is secondary/temporary. */
  if (ifa->ifa_family != result->family ||
      (int)ifa->ifa_index != result->ifindex ||
      ifa->ifa_scope != RT_SCOPE_UNIVERSE ||
      ifa->ifa_flags & IFA_F_SECONDARY)
    return 0;

  attr = IFA_RTA(ifa);
  attrlen = RTM_PAYLOAD(msg);
  for (; RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {
    if (attr->rta_type == IFA_ADDRESS) {
      switch (ifa->ifa_family) {
      case AF_INET:
      {
        struct in_addr *src = RTA_DATA(attr);
        if ((size_t)attrlen >= sizeof(*src)) {
          tor_addr_from_in(result->addr, src);
          found = 1;
        }
        break;
      }
      case AF_INET6:
      {
        struct in6_addr *src = RTA_DATA(attr);
        if ((size_t)attrlen >= sizeof(*src)) {
          tor_addr_from_in6(result->addr, src);
          found = 1;
        }
        break;
      }
      default:
        /* Huh? This should never happen ever. */
        tor_assert_nonfatal_unreached();
        return 0;
      }
    } else if (attr->rta_type == IFA_CACHEINFO) {
      /* Only return the prefered source address for IPv6 interfaces. */
      struct ifa_cacheinfo *ci = RTA_DATA(attr);
      is_prefered = ci->ifa_prefered != 0;
    }
  }

  /* If after processing the address entry, we have found an address, and it
   * is prefered, we are done. */
  if (found && is_prefered) {
    result->found = 1;
    return 1; /* Skip further processing. */
  }

  return 0;
}

static int
netlink_get_external_ifindex(tor_socket_t fd, int severity, sa_family_t family)
{
  void *req = NULL;
  struct nlmsghdr *req_hdr;
  struct rtmsg *rtm;
  size_t reqlen;
  int ret = -1;
  int ifindex = -1;

  reqlen = NLMSG_SPACE(sizeof(*rtm));
  req = tor_malloc_zero(reqlen);

  /* Build the RTM_GETROUTE request. */
  req_hdr = req;
  req_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*rtm));
  req_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req_hdr->nlmsg_type = RTM_GETROUTE;
  rtm = NLMSG_DATA(req_hdr);
  rtm->rtm_family = family;
  rtm->rtm_table = RT_TABLE_MAIN;

  ret = netlink_query(fd, severity, req, reqlen, &netlink_parse_getroute_msg,
                      &ifindex);
  if (ret >= 0) {
    ret = ifindex;
  }

  tor_free(req);
  return ret;
}

static int
netlink_get_address_ifindex(tor_socket_t fd, int severity, sa_family_t family,
                            int ifindex, tor_addr_t *addr)
{
  struct getaddr_ctx result;
  void *req = NULL;
  struct nlmsghdr *req_hdr;
  struct ifaddrmsg *ifa;
  size_t reqlen;
  int ret = -1;

  reqlen = NLMSG_SPACE(sizeof(*ifa));
  req = tor_malloc_zero(reqlen);

  /* Build the RTM_GETADDR request.
   *
   * Querying by specific index is not implemented/broken on most systems,
   * so dump the entire interface table. */
  req_hdr = req;
  req_hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*ifa));
  req_hdr->nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
  req_hdr->nlmsg_type = RTM_GETADDR;
  ifa = NLMSG_DATA(req_hdr);
  ifa->ifa_family = family;

  result.found = 0;
  result.addr = addr;
  result.ifindex = ifindex;
  result.family = family;

  ret = netlink_query(fd, severity, req, reqlen, &netlink_parse_getaddr_msg,
                      &result);
  if (ret == 0 && result.found)
    ret = 0;

  tor_free(req);
  return ret;
}

/* Set <b>addr<b> to the IP Address (if any) of whatever interface connects to
 * the Internet. This address should only be used in checking whether our
 * address has changed. Return 0 on success, -1 on failure. */
MOCK_IMPL(int,
get_interface_address_netlink, (int severity, sa_family_t family,
                                tor_addr_t *addr))
{
  struct sockaddr_nl nladdr;
  tor_socket_t fd = -1;
  int r = -1;

  if (!addr)
    goto err;

  if (family != AF_INET && family != AF_INET6) {
    tor_log(severity, LD_NET, "Unsupported family: %d", family);
    goto err;
  }

  /* Create and bind the AF_NETLINK socket. */
  fd = tor_open_socket_with_extensions(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE,
                                       1, 0);
  if (fd < 0) {
    int e = tor_socket_errno(-1);
    tor_log(severity, LD_NET, "Unable to create NETLINK socket: %s",
            tor_socket_strerror(e));
    goto err;
  }
  memset(&nladdr, 0, sizeof(nladdr));
  nladdr.nl_family = AF_NETLINK;
  if (bind(fd, (struct sockaddr *) &nladdr, sizeof(nladdr)) != 0) {
    tor_log(severity, LD_NET, "Unable to bind socket: %s", strerror(errno));
    goto err;
  }

  /* Query the kernel for the routing table, to get the interface index for
   * the interface associated with the default route. */
  r = netlink_get_external_ifindex(fd, severity, family);
  if (r < 0)
    goto err;

  /* Query the kernel for the primary IP address associated with the interface
   * index. */
  r = netlink_get_address_ifindex(fd, severity, family, r, addr);
  if (r < 0)
    goto err;

 err:
  if (fd >= 0)
    tor_close_socket(fd);
  return r;
}

#else /* __linux__ */

/* One day, someone should write support for other platforms to query this
 * information. Till then, stub out the routine to always return an error. */
int
get_interface_address_netlink(int severity, sa_family_t family,
                              tor_addr_t *addr)
{
  (void)severity;
  (void)family;
  (void)addr;

  /* Don't bother logging on systems that do not support this. */

  return -1;
}

#endif /* __linux__ */

