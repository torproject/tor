/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2011, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"
#include "or.h"
#include "test.h"

static void
test_addr_basic(void)
{
  uint32_t u32;
  uint16_t u16;
  char *cp;

  /* Test parse_addr_port */
  cp = NULL; u32 = 3; u16 = 3;
  test_assert(!parse_addr_port(LOG_WARN, "1.2.3.4", &cp, &u32, &u16));
  test_streq(cp, "1.2.3.4");
  test_eq(u32, 0x01020304u);
  test_eq(u16, 0);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "4.3.2.1:99", &cp, &u32, &u16));
  test_streq(cp, "4.3.2.1");
  test_eq(u32, 0x04030201u);
  test_eq(u16, 99);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "nonexistent.address:4040",
                               &cp, NULL, &u16));
  test_streq(cp, "nonexistent.address");
  test_eq(u16, 4040);
  tor_free(cp);
  test_assert(!parse_addr_port(LOG_WARN, "localhost:9999", &cp, &u32, &u16));
  test_streq(cp, "localhost");
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 9999);
  tor_free(cp);
  u32 = 3;
  test_assert(!parse_addr_port(LOG_WARN, "localhost", NULL, &u32, &u16));
  test_eq(cp, NULL);
  test_eq(u32, 0x7f000001u);
  test_eq(u16, 0);
  tor_free(cp);
  test_eq(0, addr_mask_get_bits(0x0u));
  test_eq(32, addr_mask_get_bits(0xFFFFFFFFu));
  test_eq(16, addr_mask_get_bits(0xFFFF0000u));
  test_eq(31, addr_mask_get_bits(0xFFFFFFFEu));
  test_eq(1, addr_mask_get_bits(0x80000000u));

  /* Test inet_ntop */
  {
    char tmpbuf[TOR_ADDR_BUF_LEN];
    const char *ip = "176.192.208.224";
    struct in_addr in;
    tor_inet_pton(AF_INET, ip, &in);
    tor_inet_ntop(AF_INET, &in, tmpbuf, sizeof(tmpbuf));
    test_streq(tmpbuf, ip);
  }

 done:
  ;
}

#define _test_op_ip6(a,op,b,e1,e2)                               \
  STMT_BEGIN                                                     \
  tt_assert_test_fmt_type(a,b,e1" "#op" "e2,struct in6_addr*,    \
    (memcmp(_val1->s6_addr, _val2->s6_addr, 16) op 0),           \
    char *, "%s",                                                \
    { int i; char *cp;                                           \
      cp = _print = tor_malloc(64);                              \
      for (i=0;i<16;++i) {                                       \
        tor_snprintf(cp, 3,"%02x", (unsigned)_value->s6_addr[i]);\
        cp += 2;                                                 \
        if (i != 15) *cp++ = ':';                                \
      }                                                          \
    }, { tor_free(_print); }                                     \
  );                                                             \
  STMT_END

/** Helper: Assert that two strings both decode as IPv6 addresses with
 * tor_inet_pton(), and both decode to the same address. */
#define test_pton6_same(a,b) STMT_BEGIN                \
     test_eq(tor_inet_pton(AF_INET6, a, &a1), 1);      \
     test_eq(tor_inet_pton(AF_INET6, b, &a2), 1);      \
     _test_op_ip6(&a1,==,&a2,#a,#b);                   \
  STMT_END

/** Helper: Assert that <b>a</b> is recognized as a bad IPv6 address by
 * tor_inet_pton(). */
#define test_pton6_bad(a)                       \
  test_eq(0, tor_inet_pton(AF_INET6, a, &a1))

/** Helper: assert that <b>a</b>, when parsed by tor_inet_pton() and displayed
 * with tor_inet_ntop(), yields <b>b</b>. Also assert that <b>b</b> parses to
 * the same value as <b>a</b>. */
#define test_ntop6_reduces(a,b) STMT_BEGIN                              \
    test_eq(tor_inet_pton(AF_INET6, a, &a1), 1);                        \
    test_streq(tor_inet_ntop(AF_INET6, &a1, buf, sizeof(buf)), b);      \
    test_eq(tor_inet_pton(AF_INET6, b, &a2), 1);                        \
    _test_op_ip6(&a1, ==, &a2, a, b);                                   \
  STMT_END

/** Helper: assert that <b>a</b> parses by tor_inet_pton() into a address that
 * passes tor_addr_is_internal() with <b>for_listening</b>. */
#define test_internal_ip(a,for_listening) STMT_BEGIN           \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1); \
    t1.family = AF_INET6;                                      \
    if (!tor_addr_is_internal(&t1, for_listening))             \
      test_fail_msg( a "was not internal.");                   \
  STMT_END

/** Helper: assert that <b>a</b> parses by tor_inet_pton() into a address that
 * does not pass tor_addr_is_internal() with <b>for_listening</b>. */
#define test_external_ip(a,for_listening) STMT_BEGIN           \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1); \
    t1.family = AF_INET6;                                      \
    if (tor_addr_is_internal(&t1, for_listening))              \
      test_fail_msg(a  "was not external.");                   \
  STMT_END

/** Helper: Assert that <b>a</b> and <b>b</b>, when parsed by
 * tor_inet_pton(), give addresses that compare in the order defined by
 * <b>op</b> with tor_addr_compare(). */
#define test_addr_compare(a, op, b) STMT_BEGIN                    \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1);    \
    test_eq(tor_inet_pton(AF_INET6, b, &t2.addr.in6_addr), 1);    \
    t1.family = t2.family = AF_INET6;                             \
    r = tor_addr_compare(&t1,&t2,CMP_SEMANTIC);                   \
    if (!(r op 0))                                                \
      test_fail_msg("failed: tor_addr_compare("a","b") "#op" 0"); \
  STMT_END

/** Helper: Assert that <b>a</b> and <b>b</b>, when parsed by
 * tor_inet_pton(), give addresses that compare in the order defined by
 * <b>op</b> with tor_addr_compare_masked() with <b>m</b> masked. */
#define test_addr_compare_masked(a, op, b, m) STMT_BEGIN          \
    test_eq(tor_inet_pton(AF_INET6, a, &t1.addr.in6_addr), 1);    \
    test_eq(tor_inet_pton(AF_INET6, b, &t2.addr.in6_addr), 1);    \
    t1.family = t2.family = AF_INET6;                             \
    r = tor_addr_compare_masked(&t1,&t2,m,CMP_SEMANTIC);          \
    if (!(r op 0))                                                \
      test_fail_msg("failed: tor_addr_compare_masked("a","b","#m") "#op" 0"); \
  STMT_END

/** Helper: assert that <b>xx</b> is parseable as a masked IPv6 address with
 * ports by tor_parse_mask_addr_ports(), with family <b>f</b>, IP address
 * as 4 32-bit words <b>ip1...ip4</b>, mask bits as <b>mm</b>, and port range
 * as <b>pt1..pt2</b>. */
#define test_addr_mask_ports_parse(xx, f, ip1, ip2, ip3, ip4, mm, pt1, pt2) \
  STMT_BEGIN                                                                \
    test_eq(tor_addr_parse_mask_ports(xx, &t1, &mask, &port1, &port2), f);  \
    p1=tor_inet_ntop(AF_INET6, &t1.addr.in6_addr, bug, sizeof(bug));        \
    test_eq(htonl(ip1), tor_addr_to_in6_addr32(&t1)[0]);            \
    test_eq(htonl(ip2), tor_addr_to_in6_addr32(&t1)[1]);            \
    test_eq(htonl(ip3), tor_addr_to_in6_addr32(&t1)[2]);            \
    test_eq(htonl(ip4), tor_addr_to_in6_addr32(&t1)[3]);            \
    test_eq(mask, mm);                                     \
    test_eq(port1, pt1);                                   \
    test_eq(port2, pt2);                                   \
  STMT_END

/** Run unit tests for IPv6 encoding/decoding/manipulation functions. */
static void
test_addr_ip6_helpers(void)
{
  char buf[TOR_ADDR_BUF_LEN], bug[TOR_ADDR_BUF_LEN];
  struct in6_addr a1, a2;
  tor_addr_t t1, t2;
  int r, i;
  uint16_t port1, port2;
  maskbits_t mask;
  const char *p1;
  struct sockaddr_storage sa_storage;
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  //  struct in_addr b1, b2;
  /* Test tor_inet_ntop and tor_inet_pton: IPv6 */

  /* ==== Converting to and from sockaddr_t. */
  sin = (struct sockaddr_in *)&sa_storage;
  sin->sin_family = AF_INET;
  sin->sin_port = 9090;
  sin->sin_addr.s_addr = htonl(0x7f7f0102); /*127.127.1.2*/
  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin, NULL);
  test_eq(tor_addr_family(&t1), AF_INET);
  test_eq(tor_addr_to_ipv4h(&t1), 0x7f7f0102);

  memset(&sa_storage, 0, sizeof(sa_storage));
  test_eq(sizeof(struct sockaddr_in),
          tor_addr_to_sockaddr(&t1, 1234, (struct sockaddr *)&sa_storage,
                               sizeof(sa_storage)));
  test_eq(1234, ntohs(sin->sin_port));
  test_eq(0x7f7f0102, ntohl(sin->sin_addr.s_addr));

  memset(&sa_storage, 0, sizeof(sa_storage));
  sin6 = (struct sockaddr_in6 *)&sa_storage;
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = htons(7070);
  sin6->sin6_addr.s6_addr[0] = 128;
  tor_addr_from_sockaddr(&t1, (struct sockaddr *)sin6, NULL);
  test_eq(tor_addr_family(&t1), AF_INET6);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 0);
  test_streq(p1, "8000::");

  memset(&sa_storage, 0, sizeof(sa_storage));
  test_eq(sizeof(struct sockaddr_in6),
          tor_addr_to_sockaddr(&t1, 9999, (struct sockaddr *)&sa_storage,
                               sizeof(sa_storage)));
  test_eq(AF_INET6, sin6->sin6_family);
  test_eq(9999, ntohs(sin6->sin6_port));
  test_eq(0x80000000, ntohl(S6_ADDR32(sin6->sin6_addr)[0]));

  /* ==== tor_addr_lookup: static cases.  (Can't test dns without knowing we
   * have a good resolver. */
  test_eq(0, tor_addr_lookup("127.128.129.130", AF_UNSPEC, &t1));
  test_eq(AF_INET, tor_addr_family(&t1));
  test_eq(tor_addr_to_ipv4h(&t1), 0x7f808182);

  test_eq(0, tor_addr_lookup("9000::5", AF_UNSPEC, &t1));
  test_eq(AF_INET6, tor_addr_family(&t1));
  test_eq(0x90, tor_addr_to_in6_addr8(&t1)[0]);
  test_assert(tor_mem_is_zero((char*)tor_addr_to_in6_addr8(&t1)+1, 14));
  test_eq(0x05, tor_addr_to_in6_addr8(&t1)[15]);

  /* === Test pton: valid af_inet6 */
  /* Simple, valid parsing. */
  r = tor_inet_pton(AF_INET6,
                    "0102:0304:0506:0708:090A:0B0C:0D0E:0F10", &a1);
  test_assert(r==1);
  for (i=0;i<16;++i) { test_eq(i+1, (int)a1.s6_addr[i]); }
  /* ipv4 ending. */
  test_pton6_same("0102:0304:0506:0708:090A:0B0C:0D0E:0F10",
                  "0102:0304:0506:0708:090A:0B0C:13.14.15.16");
  /* shortened words. */
  test_pton6_same("0001:0099:BEEF:0000:0123:FFFF:0001:0001",
                  "1:99:BEEF:0:0123:FFFF:1:1");
  /* zeros at the beginning */
  test_pton6_same("0000:0000:0000:0000:0009:C0A8:0001:0001",
                  "::9:c0a8:1:1");
  test_pton6_same("0000:0000:0000:0000:0009:C0A8:0001:0001",
                  "::9:c0a8:0.1.0.1");
  /* zeros in the middle. */
  test_pton6_same("fe80:0000:0000:0000:0202:1111:0001:0001",
                  "fe80::202:1111:1:1");
  /* zeros at the end. */
  test_pton6_same("1000:0001:0000:0007:0000:0000:0000:0000",
                  "1000:1:0:7::");

  /* === Test ntop: af_inet6 */
  test_ntop6_reduces("0:0:0:0:0:0:0:0", "::");

  test_ntop6_reduces("0001:0099:BEEF:0006:0123:FFFF:0001:0001",
                     "1:99:beef:6:123:ffff:1:1");

  //test_ntop6_reduces("0:0:0:0:0:0:c0a8:0101", "::192.168.1.1");
  test_ntop6_reduces("0:0:0:0:0:ffff:c0a8:0101", "::ffff:192.168.1.1");
  test_ntop6_reduces("002:0:0000:0:3::4", "2::3:0:0:4");
  test_ntop6_reduces("0:0::1:0:3", "::1:0:3");
  test_ntop6_reduces("008:0::0", "8::");
  test_ntop6_reduces("0:0:0:0:0:ffff::1", "::ffff:0.0.0.1");
  test_ntop6_reduces("abcd:0:0:0:0:0:7f00::", "abcd::7f00:0");
  test_ntop6_reduces("0000:0000:0000:0000:0009:C0A8:0001:0001",
                     "::9:c0a8:1:1");
  test_ntop6_reduces("fe80:0000:0000:0000:0202:1111:0001:0001",
                     "fe80::202:1111:1:1");
  test_ntop6_reduces("1000:0001:0000:0007:0000:0000:0000:0000",
                     "1000:1:0:7::");

  /* === Test pton: invalid in6. */
  test_pton6_bad("foobar.");
  test_pton6_bad("55555::");
  test_pton6_bad("9:-60::");
  test_pton6_bad("1:2:33333:4:0002:3::");
  //test_pton6_bad("1:2:3333:4:00002:3::");// BAD, but glibc doesn't say so.
  test_pton6_bad("1:2:3333:4:fish:3::");
  test_pton6_bad("1:2:3:4:5:6:7:8:9");
  test_pton6_bad("1:2:3:4:5:6:7");
  test_pton6_bad("1:2:3:4:5:6:1.2.3.4.5");
  test_pton6_bad("1:2:3:4:5:6:1.2.3");
  test_pton6_bad("::1.2.3");
  test_pton6_bad("::1.2.3.4.5");
  test_pton6_bad("99");
  test_pton6_bad("");
  test_pton6_bad("1::2::3:4");
  test_pton6_bad("a:::b:c");
  test_pton6_bad(":::a:b:c");
  test_pton6_bad("a:b:c:::");

  /* test internal checking */
  test_external_ip("fbff:ffff::2:7", 0);
  test_internal_ip("fc01::2:7", 0);
  test_internal_ip("fdff:ffff::f:f", 0);
  test_external_ip("fe00::3:f", 0);

  test_external_ip("fe7f:ffff::2:7", 0);
  test_internal_ip("fe80::2:7", 0);
  test_internal_ip("febf:ffff::f:f", 0);

  test_internal_ip("fec0::2:7:7", 0);
  test_internal_ip("feff:ffff::e:7:7", 0);
  test_external_ip("ff00::e:7:7", 0);

  test_internal_ip("::", 0);
  test_internal_ip("::1", 0);
  test_internal_ip("::1", 1);
  test_internal_ip("::", 0);
  test_external_ip("::", 1);
  test_external_ip("::2", 0);
  test_external_ip("2001::", 0);
  test_external_ip("ffff::", 0);

  test_external_ip("::ffff:0.0.0.0", 1);
  test_internal_ip("::ffff:0.0.0.0", 0);
  test_internal_ip("::ffff:0.255.255.255", 0);
  test_external_ip("::ffff:1.0.0.0", 0);

  test_external_ip("::ffff:9.255.255.255", 0);
  test_internal_ip("::ffff:10.0.0.0", 0);
  test_internal_ip("::ffff:10.255.255.255", 0);
  test_external_ip("::ffff:11.0.0.0", 0);

  test_external_ip("::ffff:126.255.255.255", 0);
  test_internal_ip("::ffff:127.0.0.0", 0);
  test_internal_ip("::ffff:127.255.255.255", 0);
  test_external_ip("::ffff:128.0.0.0", 0);

  test_external_ip("::ffff:172.15.255.255", 0);
  test_internal_ip("::ffff:172.16.0.0", 0);
  test_internal_ip("::ffff:172.31.255.255", 0);
  test_external_ip("::ffff:172.32.0.0", 0);

  test_external_ip("::ffff:192.167.255.255", 0);
  test_internal_ip("::ffff:192.168.0.0", 0);
  test_internal_ip("::ffff:192.168.255.255", 0);
  test_external_ip("::ffff:192.169.0.0", 0);

  test_external_ip("::ffff:169.253.255.255", 0);
  test_internal_ip("::ffff:169.254.0.0", 0);
  test_internal_ip("::ffff:169.254.255.255", 0);
  test_external_ip("::ffff:169.255.0.0", 0);
  test_assert(is_internal_IP(0x7f000001, 0));

  /* tor_addr_compare(tor_addr_t x2) */
  test_addr_compare("ffff::", ==, "ffff::0");
  test_addr_compare("0::3:2:1", <, "0::ffff:0.3.2.1");
  test_addr_compare("0::2:2:1", <, "0::ffff:0.3.2.1");
  test_addr_compare("0::ffff:0.3.2.1", >, "0::0:0:0");
  test_addr_compare("0::ffff:5.2.2.1", <, "::ffff:6.0.0.0"); /* XXXX wrong. */
  tor_addr_parse_mask_ports("[::ffff:2.3.4.5]", &t1, NULL, NULL, NULL);
  tor_addr_parse_mask_ports("2.3.4.5", &t2, NULL, NULL, NULL);
  test_assert(tor_addr_compare(&t1, &t2, CMP_SEMANTIC) == 0);
  tor_addr_parse_mask_ports("[::ffff:2.3.4.4]", &t1, NULL, NULL, NULL);
  tor_addr_parse_mask_ports("2.3.4.5", &t2, NULL, NULL, NULL);
  test_assert(tor_addr_compare(&t1, &t2, CMP_SEMANTIC) < 0);

  /* test compare_masked */
  test_addr_compare_masked("ffff::", ==, "ffff::0", 128);
  test_addr_compare_masked("ffff::", ==, "ffff::0", 64);
  test_addr_compare_masked("0::2:2:1", <, "0::8000:2:1", 81);
  test_addr_compare_masked("0::2:2:1", ==, "0::8000:2:1", 80);

  /* Test decorated addr_to_string. */
  test_eq(AF_INET6, tor_addr_from_str(&t1, "[123:45:6789::5005:11]"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "[123:45:6789::5005:11]");
  test_eq(AF_INET, tor_addr_from_str(&t1, "18.0.0.1"));
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "18.0.0.1");

  /* Test tor_addr_parse_reverse_lookup_name */
  i = tor_addr_parse_reverse_lookup_name(&t1, "Foobar.baz", AF_UNSPEC, 0);
  test_eq(0, i);
  i = tor_addr_parse_reverse_lookup_name(&t1, "Foobar.baz", AF_UNSPEC, 1);
  test_eq(0, i);
  i = tor_addr_parse_reverse_lookup_name(&t1, "1.0.168.192.in-addr.arpa",
                                         AF_UNSPEC, 1);
  test_eq(1, i);
  test_eq(tor_addr_family(&t1), AF_INET);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "192.168.0.1");
  i = tor_addr_parse_reverse_lookup_name(&t1, "192.168.0.99", AF_UNSPEC, 0);
  test_eq(0, i);
  i = tor_addr_parse_reverse_lookup_name(&t1, "192.168.0.99", AF_UNSPEC, 1);
  test_eq(1, i);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "192.168.0.99");
  memset(&t1, 0, sizeof(t1));
  i = tor_addr_parse_reverse_lookup_name(&t1,
                                         "0.1.2.3.4.5.6.7.8.9.a.b.c.d.e.f."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(1, i);
  p1 = tor_addr_to_str(buf, &t1, sizeof(buf), 1);
  test_streq(p1, "[9dee:effe:ebe1:beef:fedc:ba98:7654:3210]");
  /* Failing cases. */
  i = tor_addr_parse_reverse_lookup_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.a.b.c.d.e.f.0."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.X.0.0.0.0.9."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1, "32.1.1.in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1, ".in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1, "1.2.3.4.5.in-addr.arpa",
                                         AF_UNSPEC, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1, "1.2.3.4.5.in-addr.arpa",
                                         AF_INET6, 0);
  test_eq(i, -1);
  i = tor_addr_parse_reverse_lookup_name(&t1,
                                         "6.7.8.9.a.b.c.d.e.f.a.b.c.d.e.0."
                                         "f.e.e.b.1.e.b.e.e.f.f.e.e.e.d.9."
                                         "ip6.ARPA",
                                         AF_INET, 0);
  test_eq(i, -1);

  /* test tor_addr_parse_mask_ports */
  test_addr_mask_ports_parse("[::f]/17:47-95", AF_INET6,
                             0, 0, 0, 0x0000000f, 17, 47, 95);
  //test_addr_parse("[::fefe:4.1.1.7/120]:999-1000");
  //test_addr_parse_check("::fefe:401:107", 120, 999, 1000);
  test_addr_mask_ports_parse("[::ffff:4.1.1.7]/120:443", AF_INET6,
                             0, 0, 0x0000ffff, 0x04010107, 120, 443, 443);
  test_addr_mask_ports_parse("[abcd:2::44a:0]:2-65000", AF_INET6,
                             0xabcd0002, 0, 0, 0x044a0000, 128, 2, 65000);

  r=tor_addr_parse_mask_ports("[fefef::]/112", &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("efef::/112", &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f:f:f:f::]", &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[::f:f:f:f:f:f:f:f]", &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("[f:f:f:f:f:f:f:f:f]", &t1, NULL, NULL, NULL);
  test_assert(r == -1);
  /* Test for V4-mapped address with mask < 96.  (arguably not valid) */
  r=tor_addr_parse_mask_ports("[::ffff:1.1.2.2/33]", &t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("1.1.2.2/33", &t1, &mask, NULL, NULL);
  test_assert(r == -1);
  r=tor_addr_parse_mask_ports("1.1.2.2/31", &t1, &mask, NULL, NULL);
  test_assert(r == AF_INET);
  r=tor_addr_parse_mask_ports("[efef::]/112", &t1, &mask, &port1, &port2);
  test_assert(r == AF_INET6);
  test_assert(port1 == 1);
  test_assert(port2 == 65535);

  /* make sure inet address lengths >= max */
  test_assert(INET_NTOA_BUF_LEN >= sizeof("255.255.255.255"));
  test_assert(TOR_ADDR_BUF_LEN >=
              sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"));

  test_assert(sizeof(tor_addr_t) >= sizeof(struct in6_addr));

  /* get interface addresses */
  r = get_interface_address6(LOG_DEBUG, AF_INET, &t1);
  i = get_interface_address6(LOG_DEBUG, AF_INET6, &t2);
#if 0
  tor_inet_ntop(AF_INET, &t1.sa.sin_addr, buf, sizeof(buf));
  printf("\nv4 address: %s  (family=%d)", buf, IN_FAMILY(&t1));
  tor_inet_ntop(AF_INET6, &t2.sa6.sin6_addr, buf, sizeof(buf));
  printf("\nv6 address: %s  (family=%d)", buf, IN_FAMILY(&t2));
#endif

 done:
  ;
}

#define ADDR_LEGACY(name)                                               \
  { #name, legacy_test_helper, 0, &legacy_setup, test_addr_ ## name }

struct testcase_t addr_tests[] = {
  ADDR_LEGACY(basic),
  ADDR_LEGACY(ip6_helpers),
  END_OF_TESTCASES
};

