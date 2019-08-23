/* Copyright (c) 2019, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_PROTO_HAPROXY_H
#define TOR_PROTO_HAPROXY_H

struct tor_addr_port_t;

/**
 * Maximum length of haproxy header. According to the haproxy v1 spec,
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 * a 108-byte buffer is always enough to store all the line and a
 * trailing zero for string processing.
 */
#define MAX_HAPROXY_HEADER_LEN 108

char *format_proxy_header_line(const struct tor_addr_port_t *addr_port);

#endif /* !defined(TOR_PROTO_HAPROXY_H) */
