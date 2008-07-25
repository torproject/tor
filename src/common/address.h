/* Copyright (c) 2003-2004, Roger Dingledine
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2008, The Tor Project, Inc. */
/* See LICENSE for licensing information */
/* $Id$ */

/**
 * \file address.h
 * \brief Headers for address.h
 **/

#ifndef __ADDRESS_H
#define __ADDRESS_H
#define ADDRESS_H_ID "$Id$"

#include "orconfig.h"
#include "torint.h"
#include "compat.h"

typedef uint8_t maskbits_t;
struct in_addr;
/** Holds an IPv4 or IPv6 address.  (Uses less memory than struct
 * sockaddr_storage.) */
typedef struct tor_addr_t
{
  sa_family_t family;
  union {
    struct in_addr in_addr;
    struct in6_addr in6_addr;
  } addr;
} tor_addr_t;

/* DOCDOC*/
static INLINE uint32_t tor_addr_to_ipv4n(const tor_addr_t *a);
static INLINE uint32_t tor_addr_to_ipv4h(const tor_addr_t *a);
static INLINE uint32_t tor_addr_to_mapped_ipv4h(const tor_addr_t *a);
static INLINE sa_family_t tor_addr_family(const tor_addr_t *a);
static INLINE const struct in_addr *tor_addr_to_in(const tor_addr_t *a);
static INLINE const struct in6_addr *tor_addr_to_in6(const tor_addr_t *a);
socklen_t tor_addr_to_sockaddr(const tor_addr_t *a, uint16_t port,
                               struct sockaddr *sa_out);
void tor_addr_from_sockaddr(tor_addr_t *a, const struct sockaddr *sa);

static INLINE const struct in6_addr *
tor_addr_to_in6(const tor_addr_t *a)
{
  return a->family == AF_INET6 ? &a->addr.in6_addr : NULL;
}

#define tor_addr_to_in6_addr16(x) S6_ADDR16(*tor_addr_to_in6(x))
#define tor_addr_to_in6_addr32(x) S6_ADDR32(*tor_addr_to_in6(x))

static INLINE uint32_t
tor_addr_to_ipv4n(const tor_addr_t *a)
{
  return a->family == AF_INET ? a->addr.in_addr.s_addr : 0;
}
static INLINE uint32_t
tor_addr_to_ipv4h(const tor_addr_t *a)
{
  return ntohl(tor_addr_to_ipv4n(a));
}
static INLINE uint32_t
tor_addr_to_mapped_ipv4h(const tor_addr_t *a)
{
  return ntohl(tor_addr_to_in6_addr32(a)[3]);
}
static INLINE sa_family_t
tor_addr_family(const tor_addr_t *a)
{
  return a->family;
}
static INLINE const struct in_addr *
tor_addr_to_in(const tor_addr_t *a)
{
  return a->family == AF_INET ? &a->addr.in_addr : NULL;
}

#define TOR_ADDR_BUF_LEN 48 /* [ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]
                             */

int tor_addr_lookup(const char *name, uint16_t family, tor_addr_t *addr_out);
char *tor_dup_addr(const tor_addr_t *addr) ATTR_MALLOC;

int get_interface_address6(int severity, sa_family_t family, tor_addr_t *addr);
int tor_addr_compare(const tor_addr_t *addr1, const tor_addr_t *addr2);
int tor_addr_compare_masked(const tor_addr_t *addr1, const tor_addr_t *addr2,
                            maskbits_t mask);
unsigned int tor_addr_hash(const tor_addr_t *addr);
int tor_addr_is_v4(const tor_addr_t *addr);
int tor_addr_is_internal(const tor_addr_t *ip, int for_listening) ATTR_PURE;
int tor_addr_parse_mask_ports(const char *s,
                              tor_addr_t *addr_out, maskbits_t *mask_out,
                              uint16_t *port_min_out, uint16_t *port_max_out);
const char * tor_addr_to_str(char *dest, const tor_addr_t *addr, int len,
                             int decorate);
int tor_addr_from_str(tor_addr_t *addr, const char *src);
void tor_addr_copy(tor_addr_t *dest, const tor_addr_t *src);
void tor_addr_from_ipv4h(tor_addr_t *dest, uint32_t v4addr);
int tor_addr_is_null(const tor_addr_t *addr);
int tor_addr_is_loopback(const tor_addr_t *addr);

/* IPv4 helpers */
int is_internal_IP(uint32_t ip, int for_listening) ATTR_PURE;
int parse_addr_port(int severity, const char *addrport, char **address,
                    uint32_t *addr, uint16_t *port_out);
int parse_port_range(const char *port, uint16_t *port_min_out,
                     uint16_t *port_max_out);
int parse_addr_and_port_range(const char *s, uint32_t *addr_out,
                              maskbits_t *maskbits_out, uint16_t *port_min_out,
                              uint16_t *port_max_out);
int addr_mask_get_bits(uint32_t mask);
int addr_mask_cmp_bits(uint32_t a1, uint32_t a2, maskbits_t bits);
#define INET_NTOA_BUF_LEN 16 /* 255.255.255.255 */
int tor_inet_ntoa(const struct in_addr *in, char *buf, size_t buf_len);
char *tor_dup_ip(uint32_t addr) ATTR_MALLOC;
int get_interface_address(int severity, uint32_t *addr);

#endif

