/* Copyright (c) 2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <stdio.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * Print a string representation of <b>address</b> to stderr
 * and return 0.
 *
 * This function is meant for replacing connect() syscall.
 */
int
connect(int socket, const struct sockaddr *address, socklen_t address_len)
{
  char ipstr[INET6_ADDRSTRLEN];
  (void)socket;
  (void)address_len;
  memset(ipstr, 0, sizeof(ipstr));

  if (address->sa_family == AF_INET) {
    const struct sockaddr_in *ipv4_sockaddr =
      (const struct sockaddr_in *)address;
    inet_ntop(address->sa_family, &ipv4_sockaddr->sin_addr,
              ipstr, INET6_ADDRSTRLEN);
  } else if (address->sa_family == AF_INET6) {
    const struct sockaddr_in6 *ipv6_sockaddr =
      (const struct sockaddr_in6 *)address;
    inet_ntop(address->sa_family, &ipv6_sockaddr->sin6_addr,
              ipstr, INET6_ADDRSTRLEN);
  }

  fprintf(stderr, "connect() %s\n", ipstr);

  return 0;
}

/**
 * Print a space-separated hex representation of data in
 * <b>buffer</b> of size <b>length</b> to stderr.
 * Return <b>length</b>.
 *
 * This function is meant for replacing send() syscall.
 */
ssize_t
send(int socket, const void *buffer, size_t length, int flags)
{
  const uint8_t *buf = (const uint8_t *)buffer;
  (void)socket;
  (void)flags;

  for (size_t i = 0; i < length; i++) {
    uint8_t b = *(buf + i);
    fprintf(stderr, "%02x ", b);
  }

  fprintf(stderr, "\n");

  return length;
}

/**
 * Read <b>length</b> of octets from stdin and put them
 * into <b>buffer</b>.
 *
 * This function is meant for replacing recv() syscall.
 */
ssize_t
recv(int socket, void *buffer, size_t length, int flags)
{
  char *buf = (char *)buffer;
  (void)socket;
  (void)flags;

  for (size_t i = 0; i < length; i++) {
    unsigned int in = 0;
    scanf("%02x", &in);
    if (in < 0xff) {
      uint8_t in8 = (uint8_t)in;
      *(buf + i) = in8;
    }
  }

  return length;
}

