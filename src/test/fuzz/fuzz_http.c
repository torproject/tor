/* Copyright (c) 2016, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include "orconfig.h"

#define BUFFERS_PRIVATE
#define DIRECTORY_PRIVATE

#include "or.h"
#include "backtrace.h"
#include "buffers.h"
#include "config.h"
#include "connection.h"
#include "directory.h"
#include "torlog.h"

#include "fuzzing.h"

static int mock_get_options_calls = 0;
static or_options_t *mock_options = NULL;

static void
reset_options(or_options_t *options, int *get_options_calls)
{
  memset(options, 0, sizeof(or_options_t));
  options->TestingTorNetwork = 1;

  *get_options_calls = 0;
}

static const or_options_t*
mock_get_options(void)
{
  ++mock_get_options_calls;
  tor_assert(mock_options);
  return mock_options;
}

static void
mock_connection_write_to_buf_impl_(const char *string, size_t len,
                                   connection_t *conn, int zlib)
{
  log_debug(LD_GENERAL, "%sResponse:\n%zu\nConnection: %p\n%s\n",
            zlib ? "Compressed " : "", len, conn, string);
}

int
fuzz_init(void)
{
  mock_options = tor_malloc(sizeof(or_options_t));
  reset_options(mock_options, &mock_get_options_calls);
  MOCK(get_options, mock_get_options);
  /* Set up fake response handler */
  MOCK(connection_write_to_buf_impl_, mock_connection_write_to_buf_impl_);
  return 0;
}

int
fuzz_cleanup(void)
{
  tor_free(mock_options);
  UNMOCK(get_options);
  UNMOCK(connection_write_to_buf_impl_);
  return 0;
}

int
fuzz_main(const uint8_t *stdin_buf, size_t data_size)
{
  dir_connection_t dir_conn;

  /* Set up the fake connection */
  memset(&dir_conn, 0, sizeof(dir_connection_t));
  dir_conn.base_.type = CONN_TYPE_DIR;
  /* Apparently tor sets this before directory_handle_command() is called. */
  dir_conn.base_.address = tor_strdup("replace-this-address.example.com");

  dir_conn.base_.inbuf = buf_new_with_data((char*)stdin_buf, data_size);
  if (!dir_conn.base_.inbuf) {
    log_debug(LD_GENERAL, "Zero-Length-Input\n");
    return 0;
  }

  /* Parse the headers */
  int rv = directory_handle_command(&dir_conn);

  /* TODO: check the output is correctly parsed based on the input */

  /* Report the parsed origin address */
  if (dir_conn.base_.address) {
    log_debug(LD_GENERAL, "Address:\n%s\n", dir_conn.base_.address);
  }

  log_debug(LD_GENERAL, "Result:\n%d\n", rv);

  /* Reset. */
  tor_free(dir_conn.base_.address);
  buf_free(dir_conn.base_.inbuf);
  dir_conn.base_.inbuf = NULL;

  return 0;
}
