/* Copyright (c) 2017, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file test_proto_misc.c
 * \brief Test our smaller buffer-based protocol functions
 */

#include "or.h"
#include "test.h"
#include "buffers.h"
#include "connection_or.h"
#include "proto_cell.h"
#include "proto_control0.h"
#include "proto_http.h"
#include "proto_socks.h"

static void
test_proto_var_cell(void *arg)
{
  (void)arg;
  char *mem_op_hex_tmp = NULL;
  char tmp[1024];
  buf_t *buf = NULL;
  var_cell_t *cell = NULL;

  buf = buf_new();
  memset(tmp, 0xf0, sizeof(tmp));

  /* Short little commands will make us say "no cell yet." */
  tt_int_op(0, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  tt_ptr_op(cell, OP_EQ, NULL);
  buf_add(buf, "\x01\x02\x02\0x2", 4);
  tt_int_op(0, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  /* An incomplete fixed-length cell makes us say "no cell yet". */
  buf_add(buf, "\x03", 1);
  tt_int_op(0, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  /* A complete fixed length-cell makes us say "not a variable-length cell" */
  buf_add(buf, tmp, 509);
  tt_int_op(0, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  buf_clear(buf);

  /* An incomplete versions cell is a variable-length cell that isn't ready
   * yet. */
  buf_add(buf,
          "\x01\x02\x03\x04" /* circid */
          "\x07" /* VERSIONS */
          "\x00\x04" /* 4 bytes long */
          "\x00" /* incomplete */, 8);
  tt_int_op(1, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  tt_ptr_op(cell, OP_EQ, NULL);
  /* Complete it, and it's a variable-length cell. Leave a byte on the end for
   * fun. */
  buf_add(buf, "\x09\x00\x25\ff", 4);
  tt_int_op(1, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 4));
  tt_ptr_op(cell, OP_NE, NULL);
  tt_int_op(cell->command, OP_EQ, CELL_VERSIONS);
  tt_uint_op(cell->circ_id, OP_EQ, 0x01020304);
  tt_int_op(cell->payload_len, OP_EQ, 4);
  test_mem_op_hex(cell->payload, OP_EQ, "00090025");
  var_cell_free(cell);
  cell = NULL;
  tt_int_op(buf_datalen(buf), OP_EQ, 1);
  buf_clear(buf);

  /* In link protocol 3 and earlier, circid fields were two bytes long. Let's
   * ensure that gets handled correctly. */
  buf_add(buf,
          "\x23\x45\x81\x00\x06" /* command 81; 6 bytes long */
          "coraje", 11);
  tt_int_op(1, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 3));
  tt_ptr_op(cell, OP_NE, NULL);
  tt_int_op(cell->command, OP_EQ, 129);
  tt_uint_op(cell->circ_id, OP_EQ, 0x2345);
  tt_int_op(cell->payload_len, OP_EQ, 6);
  tt_mem_op(cell->payload, OP_EQ, "coraje", 6);
  var_cell_free(cell);
  cell = NULL;
  tt_int_op(buf_datalen(buf), OP_EQ, 0);

  /* In link protocol 2, only VERSIONS cells counted as variable-length */
  buf_add(buf,
          "\x23\x45\x81\x00\x06"
          "coraje", 11); /* As above */
  tt_int_op(0, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 2));
  buf_clear(buf);
  buf_add(buf,
          "\x23\x45\x07\x00\x06"
          "futuro", 11);
  tt_int_op(1, OP_EQ, fetch_var_cell_from_buf(buf, &cell, 2));
  tt_ptr_op(cell, OP_NE, NULL);
  tt_int_op(cell->command, OP_EQ, 7);
  tt_uint_op(cell->circ_id, OP_EQ, 0x2345);
  tt_int_op(cell->payload_len, OP_EQ, 6);
  tt_mem_op(cell->payload, OP_EQ, "futuro", 6);
  var_cell_free(cell);
  cell = NULL;

 done:
  buf_free(buf);
  var_cell_free(cell);
  tor_free(mem_op_hex_tmp);
}

static void
test_proto_control0(void *arg)
{
  (void)arg;
  buf_t *buf = buf_new();

  /* The only remaining function for the v0 control protocol is the function
     that detects whether the user has stumbled across an old controller
     that's using it.  The format was:
        u16 length;
        u16 command;
        u8 body[length];
  */

  /* Empty buffer -- nothing to do. */
  tt_int_op(0, OP_EQ, peek_buf_has_control0_command(buf));
  /* 3 chars in buf -- can't tell */
  buf_add(buf, "AUT", 3);
  tt_int_op(0, OP_EQ, peek_buf_has_control0_command(buf));
  /* command in buf -- easy to tell */
  buf_add(buf, "HENTICATE ", 10);
  tt_int_op(0, OP_EQ, peek_buf_has_control0_command(buf));

  /* Control0 command header in buf: make sure we detect it. */
  buf_clear(buf);
  buf_add(buf, "\x09\x05" "\x00\x05" "blah", 8);
  tt_int_op(1, OP_EQ, peek_buf_has_control0_command(buf));

 done:
  buf_free(buf);
}

struct testcase_t proto_misc_tests[] = {
  { "var_cell", test_proto_var_cell, 0, NULL, NULL },
  { "control0", test_proto_control0, 0, NULL, NULL },

  END_OF_TESTCASES
};

