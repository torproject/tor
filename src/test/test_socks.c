/* Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "or.h"
#include "buffers.h"
#include "config.h"
#include "proto_socks.h"
#include "test.h"

typedef struct socks_test_data_t {
  socks_request_t *req;
  buf_t *buf;
} socks_test_data_t;

static void *
socks_test_setup(const struct testcase_t *testcase)
{
  socks_test_data_t *data = tor_malloc(sizeof(socks_test_data_t));
  (void)testcase;
  data->buf = buf_new_with_capacity(256);
  data->req = socks_request_new();
  config_register_addressmaps(get_options());
  return data;
}
static int
socks_test_cleanup(const struct testcase_t *testcase, void *ptr)
{
  socks_test_data_t *data = ptr;
  (void)testcase;
  buf_free(data->buf);
  socks_request_free(data->req);
  tor_free(data);
  return 1;
}

static const struct testcase_setup_t socks_setup = {
  socks_test_setup, socks_test_cleanup
};

#define SOCKS_TEST_INIT()                       \
  socks_test_data_t *testdata = ptr;            \
  buf_t *buf = testdata->buf;                   \
  socks_request_t *socks = testdata->req;
#define ADD_DATA(buf, s)                                        \
  buf_add(buf, s, sizeof(s)-1)

static void
socks_request_clear(socks_request_t *socks)
{
  tor_free(socks->username);
  tor_free(socks->password);
  memset(socks, 0, sizeof(socks_request_t));
}

/** Perform unsupported SOCKS 4 commands */
static void
test_socks_4_unsupported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 4 Send BIND [02] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x04\x02\x11\x11\x02\x02\x02\x02\x00");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, -1);
  tt_int_op(4,OP_EQ, socks->socks_version);
  tt_int_op(0,OP_EQ, socks->replylen); /* XXX: shouldn't tor reply? */

 done:
  ;
}

/** Perform supported SOCKS 4 commands */
static void
test_socks_4_supported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  tt_int_op(0,OP_EQ, buf_datalen(buf));

  /* SOCKS 4 Send CONNECT [01] to IP address 2.2.2.2:4370 */
  ADD_DATA(buf, "\x04\x01\x11\x12\x02\x02\x02\x03\x00");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(4,OP_EQ, socks->socks_version);
  tt_int_op(0,OP_EQ, socks->replylen); /* XXX: shouldn't tor reply? */
  tt_int_op(SOCKS_COMMAND_CONNECT,OP_EQ, socks->command);
  tt_str_op("2.2.2.3",OP_EQ, socks->address);
  tt_int_op(4370,OP_EQ, socks->port);
  tt_assert(socks->got_auth == 0);
  tt_assert(! socks->username);

  tt_int_op(0,OP_EQ, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 4 Send CONNECT [01] to IP address 2.2.2.2:4369 with userid*/
  ADD_DATA(buf, "\x04\x01\x11\x12\x02\x02\x02\x04me\x00");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(4,OP_EQ, socks->socks_version);
  tt_int_op(0,OP_EQ, socks->replylen); /* XXX: shouldn't tor reply? */
  tt_int_op(SOCKS_COMMAND_CONNECT,OP_EQ, socks->command);
  tt_str_op("2.2.2.4",OP_EQ, socks->address);
  tt_int_op(4370,OP_EQ, socks->port);
  tt_assert(socks->got_auth == 1);
  tt_assert(socks->username);
  tt_int_op(2,OP_EQ, socks->usernamelen);
  tt_mem_op("me",OP_EQ, socks->username, 2);

  tt_int_op(0,OP_EQ, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 4a Send RESOLVE [F0] request for torproject.org */
  ADD_DATA(buf, "\x04\xF0\x01\x01\x00\x00\x00\x02me\x00torproject.org\x00");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(4,OP_EQ, socks->socks_version);
  tt_int_op(0,OP_EQ, socks->replylen); /* XXX: shouldn't tor reply? */
  tt_str_op("torproject.org",OP_EQ, socks->address);

  tt_int_op(0,OP_EQ, buf_datalen(buf));

 done:
  ;
}

/**  Perform unsupported SOCKS 5 commands */
static void
test_socks_5_unsupported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send unsupported BIND [02] command */
  ADD_DATA(buf, "\x05\x02\x00\x01");

  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks),OP_EQ, 0);
  tt_int_op(0,OP_EQ, buf_datalen(buf));
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);
  ADD_DATA(buf, "\x05\x02\x00\x01\x02\x02\x02\x01\x01\x01");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks),OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_COMMAND_NOT_SUPPORTED,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

  buf_clear(buf);
  socks_request_clear(socks);

  /* SOCKS 5 Send unsupported UDP_ASSOCIATE [03] command */
  ADD_DATA(buf, "\x05\x02\x00\x01");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks),OP_EQ, 0);
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);
  ADD_DATA(buf, "\x05\x03\x00\x01\x02\x02\x02\x01\x01\x01");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                               get_options()->SafeSocks),OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_COMMAND_NOT_SUPPORTED,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

 done:
  ;
}

/** Perform supported SOCKS 5 commands */
static void
test_socks_5_supported_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send CONNECT [01] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, 0);
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);

  ADD_DATA(buf, "\x05\x01\x00\x01\x02\x02\x02\x02\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, 1);
  tt_str_op("2.2.2.2",OP_EQ, socks->address);
  tt_int_op(4369,OP_EQ, socks->port);

  tt_int_op(0,OP_EQ, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Send CONNECT [01] to FQDN torproject.org:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\x01\x00\x03\x0Etorproject.org\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, 1);

  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);
  tt_str_op("torproject.org",OP_EQ, socks->address);
  tt_int_op(4369,OP_EQ, socks->port);

  tt_int_op(0,OP_EQ, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Send RESOLVE [F0] request for torproject.org:4369 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF0\x00\x03\x0Etorproject.org\x01\x02");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);
  tt_str_op("torproject.org",OP_EQ, socks->address);

  tt_int_op(0,OP_EQ, buf_datalen(buf));
  socks_request_clear(socks);

  /* SOCKS 5 Should NOT reject RESOLVE [F0] request for IPv4 address
   * string if SafeSocks is enabled. */

  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF0\x00\x03\x07");
  ADD_DATA(buf, "8.8.8.8");
  ADD_DATA(buf, "\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks, 1),
            OP_EQ, 1);

  tt_str_op("8.8.8.8", OP_EQ, socks->address);
  tt_int_op(4369, OP_EQ, socks->port);

  tt_int_op(0, OP_EQ, buf_datalen(buf));

  socks_request_clear(socks);

  /* SOCKS 5 should NOT reject RESOLVE [F0] reject for IPv6 address
   * string if SafeSocks is enabled. */

  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF0\x00\x03\x27");
  ADD_DATA(buf, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
  ADD_DATA(buf, "\x01\x02");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks, 1),
            OP_EQ, -1);

  tt_str_op("2001:0db8:85a3:0000:0000:8a2e:0370:7334", OP_EQ, socks->address);
  tt_int_op(258, OP_EQ, socks->port);

  tt_int_op(0, OP_EQ, buf_datalen(buf));

  socks_request_clear(socks);

  /* SOCKS 5 Send RESOLVE_PTR [F1] for IP address 2.2.2.5 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF1\x00\x01\x02\x02\x02\x05\x01\x03");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);
  tt_str_op("2.2.2.5",OP_EQ, socks->address);

  tt_int_op(0,OP_EQ, buf_datalen(buf));

 done:
  ;
}

/**  Perform SOCKS 5 authentication */
static void
test_socks_5_no_authenticate(void *ptr)
{
  SOCKS_TEST_INIT();

  /*SOCKS 5 No Authentication */
  ADD_DATA(buf,"\x05\x01\x00");
  tt_assert(!fetch_from_buf_socks(buf, socks,
                                    get_options()->TestSocks,
                                    get_options()->SafeSocks));
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(SOCKS_NO_AUTH,OP_EQ, socks->reply[1]);

  tt_int_op(0,OP_EQ, buf_datalen(buf));

  /*SOCKS 5 Send username/password anyway - pretend to be broken */
  ADD_DATA(buf,"\x01\x02\x01\x01\x02\x01\x01");
  tt_assert(!fetch_from_buf_socks(buf, socks,
                                    get_options()->TestSocks,
                                    get_options()->SafeSocks));
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(1,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);

  tt_int_op(2,OP_EQ, socks->usernamelen);
  tt_int_op(2,OP_EQ, socks->passwordlen);

  tt_mem_op("\x01\x01",OP_EQ, socks->username, 2);
  tt_mem_op("\x01\x01",OP_EQ, socks->password, 2);

 done:
  ;
}

/** Perform SOCKS 5 authentication */
static void
test_socks_5_authenticate(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Negotiate username/password authentication */
  ADD_DATA(buf, "\x05\x01\x02");

  tt_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(SOCKS_USER_PASS,OP_EQ, socks->reply[1]);
  tt_int_op(5,OP_EQ, socks->socks_version);

  tt_int_op(0,OP_EQ, buf_datalen(buf));

  /* SOCKS 5 Send username/password */
  ADD_DATA(buf, "\x01\x02me\x08mypasswd");
  tt_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(1,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);

  tt_int_op(2,OP_EQ, socks->usernamelen);
  tt_int_op(8,OP_EQ, socks->passwordlen);

  tt_mem_op("me",OP_EQ, socks->username, 2);
  tt_mem_op("mypasswd",OP_EQ, socks->password, 8);

 done:
  ;
}

/** Perform SOCKS 5 authentication and send data all in one go */
static void
test_socks_5_authenticate_with_data(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Negotiate username/password authentication */
  ADD_DATA(buf, "\x05\x01\x02");

  tt_assert(!fetch_from_buf_socks(buf, socks,
                                   get_options()->TestSocks,
                                   get_options()->SafeSocks));
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(SOCKS_USER_PASS,OP_EQ, socks->reply[1]);
  tt_int_op(5,OP_EQ, socks->socks_version);

  tt_int_op(0,OP_EQ, buf_datalen(buf));

  /* SOCKS 5 Send username/password */
  /* SOCKS 5 Send CONNECT [01] to IP address 2.2.2.2:4369 */
  ADD_DATA(buf, "\x01\x02me\x03you\x05\x01\x00\x01\x02\x02\x02\x02\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 1);
  tt_int_op(5,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(1,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);

  tt_str_op("2.2.2.2",OP_EQ, socks->address);
  tt_int_op(4369,OP_EQ, socks->port);

  tt_int_op(2,OP_EQ, socks->usernamelen);
  tt_int_op(3,OP_EQ, socks->passwordlen);
  tt_mem_op("me",OP_EQ, socks->username, 2);
  tt_mem_op("you",OP_EQ, socks->password, 3);

 done:
  ;
}

/** Try to negotiate an unsupported authentication type */
static void
test_socks_5_auth_unsupported_type(void *ptr)
{
  SOCKS_TEST_INIT();

  /* None of these authentication types are recognized. */
  ADD_DATA(buf, "\x05\x03\x99\x21\x10");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, -1);
  tt_int_op(0,OP_EQ, socks->socks_version);
  tt_int_op(2,OP_EQ, socks->replylen);
  tt_int_op(5,OP_EQ, socks->reply[0]);
  tt_int_op(0xff,OP_EQ, socks->reply[1]);

 done:
  ;
}

/** Try to negotiate an unsupported version of username/password auth. */
static void
test_socks_5_auth_unsupported_version(void *ptr)
{
  SOCKS_TEST_INIT();

  /* Negotiate username/password */
  ADD_DATA(buf, "\x05\x01\x02");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, 0);
  tt_int_op(0,OP_EQ, buf_datalen(buf)); /* buf should be drained */
  /* Now, suggest an unrecognized username/password version */
  ADD_DATA(buf, "\x02\x05" "hello" "\x05" "world");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, -1);

 done:
  ;
}

/** Perform SOCKS 5 authentication before method negotiated */
static void
test_socks_5_auth_before_negotiation(void *ptr)
{
  SOCKS_TEST_INIT();

  /* SOCKS 5 Send username/password */
  ADD_DATA(buf, "\x01\x02me\x02me");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                 get_options()->SafeSocks),
            OP_EQ, -1);
  tt_int_op(0,OP_EQ, socks->socks_version);
  tt_int_op(0,OP_EQ, socks->replylen);
  tt_int_op(0,OP_EQ, socks->reply[0]);
  tt_int_op(0,OP_EQ, socks->reply[1]);

 done:
  ;
}

/** Perform malformed SOCKS 5 commands */
static void
test_socks_5_malformed_commands(void *ptr)
{
  SOCKS_TEST_INIT();

  /* XXX: Stringified address length > MAX_SOCKS_ADDR_LEN will never happen */

  /** SOCKS 5 Send CONNECT [01] to IP address 2.2.2.2:4369, with SafeSocks set
   */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\x01\x00\x01\x02\x02\x02\x02\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks, 1),
            OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_NOT_ALLOWED,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

  buf_clear(buf);
  socks_request_clear(socks);

  /* SOCKS 5 Send RESOLVE_PTR [F1] for FQDN torproject.org */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\xF1\x00\x03\x0Etorproject.org\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

  buf_clear(buf);
  socks_request_clear(socks);

  /* XXX: len + 1 > MAX_SOCKS_ADDR_LEN (FQDN request) will never happen */

  /* SOCKS 5 Send CONNECT [01] to FQDN """"".com */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\x01\x00\x03\x09\"\"\"\"\".com\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_GENERAL_ERROR,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

  buf_clear(buf);
  socks_request_clear(socks);

  /* SOCKS 5 Send CONNECT [01] to address type 0x23 */
  ADD_DATA(buf, "\x05\x01\x00");
  ADD_DATA(buf, "\x05\x01\x00\x23\x02\x02\x02\x02\x11\x11");
  tt_int_op(fetch_from_buf_socks(buf, socks, get_options()->TestSocks,
                                   get_options()->SafeSocks),OP_EQ, -1);

  tt_int_op(5,OP_EQ,socks->socks_version);
  tt_int_op(10,OP_EQ,socks->replylen);
  tt_int_op(5,OP_EQ,socks->reply[0]);
  tt_int_op(SOCKS5_ADDRESS_TYPE_NOT_SUPPORTED,OP_EQ,socks->reply[1]);
  tt_int_op(1,OP_EQ,socks->reply[3]);

 done:
  ;
}

/** check for correct behavior when the socks command has not arrived. */
static void
test_socks_truncated(void *ptr)
{
  const struct {
    enum { NONE, AUTH, ALL } setup;
    const char *body;
    size_t len;
  } commands[] = {
    /* SOCKS4 */
    /* Connect, to an IP. */
    { NONE, "\x04\x01\x05\x05\x01\x02\x03\x04\x00", 9},
    /* Connect, to an IP, with authentication. */
    { NONE, "\x04\x01\x05\x05\x01\x02\x03\x04hello\x00", 14},
    /* SOCKS4A */
    /* Connect, to a hostname */
    { NONE, "\x04\x01\x09\x09\x00\x00\x00\x01\x00www.example.com\x00", 25},
    /* Connect, to a hostname, with authentication */
    { NONE, "\x04\x01\x09\x09\x00\x00\x00\x01hi\x00www.example.com\x00", 27},
    /* SOCKS5 */
    /* initial handshake */
    { NONE, "\x05\x00", 2 },
    /* no-auth handshake */
    { NONE, "\x05\x03\x99\x21\x10", 5 },
    /* SOCSK5, username-password, all empty. */
    { AUTH, "\x01\x00\x00", 3 },
    /* SOCSK5, username-password, 1 char each. */
    { AUTH, "\x01\x01x\x01y", 5 },
    /* SOCSK5, username-password, max length. */
    { AUTH, "\x01\xff"
      "Ogni tempo ha il suo fascismo: se ne notano i segni premonitori "
      "dovunque la concentrazione di potere nega al cittadino la "
      "possibilit\xc3\xa0 e la capacit\xc3\xa0 di esprimere ed attuare la "
      "sua volont\xc3\xa0. A questo si arriva in molti modi, non "
      "necessariamente col terror"
      "\xff"
      "e dell'intimidazione poliziesca, ma anche negando o distorcendo "
      "l'informazione, inquinando la giustizia, paralizzando la scuola, "
      "diffondendo in molti modi sottili la nostalgia per un mondo in cui "
      "regnava sovrano l'ordine, ed in cui la sicurezza dei pochi "
      /* privilegiati riposava sul lavoro forzato e sul silenzio forzato dei
         molti. -- Primo Levi */ , 513 },
    /* Socks5, IPv4 address */
    { ALL, "\x05\x01\x00\x01\x01\x02\x03\x04\x20\x20", 10 },
    /* Socks5, IPv6 address */
    { ALL, "\x05\x01\x00\x04"
      "\x49\x20\x48\x41\x5a\x20\x45\x41\x53\x54\x45\x52\x20\x45\x47\x47"
      "\x20\x20", 22 },
    /* Socks5, hostname, empty. */
    { ALL, "\x05\x01\x00\x03" "\x00" "\x00\x50", 7 },
    /* Socks5, hostname, moderate. */
    { ALL, "\x05\x01\x00\x03" "\x11" "onion.example.com" "\x00\x50", 24 },
    /* Socks5, hostname, maximum. */
    { ALL, "\x05\x01\x00\x03" "\xff"
      "whatsoever.I.shall.see.or.hear.in.the.course.of.my.profession.as.well."
      "as.outside.my.profession.in.my.intercourse.with.men.if.it.be.what."
      "should.not.be.published.abroad.I.will.never.divulge.holding.such."
      "things.to.be.holy.secrets.x.hippocratic.oath.wikipedia"
      "\x00\x50", 262 },
  };
  unsigned i, j;
  SOCKS_TEST_INIT();
  for (i = 0; i < ARRAY_LENGTH(commands); ++i) {
    for (j = 0; j < commands[i].len; ++j) {
      switch (commands[i].setup) {
        default: /* Falls through */
        case NONE:
          /* This test calls for no setup on the socks state. */
          break;
        case AUTH:
          /* This test calls for the socks state to be waiting for
           * username/password authentication */
          ADD_DATA(buf, "\x05\x01\x02");
          tt_int_op(0, OP_EQ, fetch_from_buf_socks(buf, socks, 0, 0));
          tt_int_op(0, OP_EQ, buf_datalen(buf));
          break;
        case ALL:
          /* This test calls for the socks state to be waiting for
           * the connection request */
          ADD_DATA(buf, "\x05\x01\x00");
          tt_int_op(0, OP_EQ, fetch_from_buf_socks(buf, socks, 0, 0));
          tt_int_op(0, OP_EQ, buf_datalen(buf));
      }

      TT_BLATHER(("Checking command %u, length %u, omitting char %u", i, j,
                  (unsigned)commands[i].body[j]));
      buf_add(buf, commands[i].body, j);
      /* This should return 0 meaning "not done yet" */
      tt_int_op(0, OP_EQ, fetch_from_buf_socks(buf, socks, 0, 0));
      tt_uint_op(j, OP_EQ, buf_datalen(buf)); /* Nothing was drained */
      buf_clear(buf);
      socks_request_free(testdata->req);
      socks = testdata->req = socks_request_new();
    }
  }
  done:
  ;
}

#define SOCKSENT(name)                                  \
  { #name, test_socks_##name, TT_FORK, &socks_setup, NULL }

struct testcase_t socks_tests[] = {
  SOCKSENT(4_unsupported_commands),
  SOCKSENT(4_supported_commands),

  SOCKSENT(5_unsupported_commands),
  SOCKSENT(5_supported_commands),
  SOCKSENT(5_no_authenticate),
  SOCKSENT(5_auth_unsupported_type),
  SOCKSENT(5_auth_unsupported_version),
  SOCKSENT(5_auth_before_negotiation),
  SOCKSENT(5_authenticate),
  SOCKSENT(5_authenticate_with_data),
  SOCKSENT(5_malformed_commands),

  SOCKSENT(truncated),

  END_OF_TESTCASES
};

