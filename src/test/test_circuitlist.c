/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#define TOR_CHANNEL_INTERNAL_
#define CIRCUITLIST_PRIVATE
#include "or.h"
#include "channel.h"
#include "circuitlist.h"
#include "test.h"

static channel_t *
new_fake_channel(void)
{
  channel_t *chan = tor_malloc_zero(sizeof(channel_t));
  channel_init(chan);
  return chan;
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
  cell_direction_t dir;
} cam;

static void
circuitmux_attach_mock(circuitmux_t *cmux, circuit_t *circ,
                         cell_direction_t dir)
{
  ++cam.ncalls;
  cam.cmux = cmux;
  cam.circ = circ;
  cam.dir = dir;
}

static struct {
  int ncalls;
  void *cmux;
  void *circ;
} cdm;

static void
circuitmux_detach_mock(circuitmux_t *cmux, circuit_t *circ)
{
  ++cdm.ncalls;
  cdm.cmux = cmux;
  cdm.circ = circ;
}

#define GOT_CMUX_ATTACH(mux_, circ_, dir_) do {  \
    tt_int_op(cam.ncalls, ==, 1);                \
    tt_ptr_op(cam.cmux, ==, (mux_));             \
    tt_ptr_op(cam.circ, ==, (circ_));            \
    tt_ptr_op(cam.dir, ==, (dir_));              \
    memset(&cam, 0, sizeof(cam));                \
  } while (0)

#define GOT_CMUX_DETACH(mux_, circ_) do {        \
    tt_int_op(cdm.ncalls, ==, 1);                \
    tt_ptr_op(cdm.cmux, ==, (mux_));             \
    tt_ptr_op(cdm.circ, ==, (circ_));            \
    memset(&cdm, 0, sizeof(cdm));                \
  } while (0)


static void
test_clist_maps(void *arg)
{
  channel_t *ch1 = new_fake_channel();
  channel_t *ch2 = new_fake_channel();
  channel_t *ch3 = new_fake_channel();
  or_circuit_t *or_c1=NULL, *or_c2=NULL;

  MOCK(circuitmux_attach_circuit, circuitmux_attach_mock);
  MOCK(circuitmux_detach_circuit, circuitmux_detach_mock);
  memset(&cam, 0, sizeof(cam));
  memset(&cdm, 0, sizeof(cdm));

  ch1->cmux = (void*)0x1001;
  ch2->cmux = (void*)0x1002;
  ch3->cmux = (void*)0x1003;

  or_c1 = or_circuit_new(100, ch2);
  tt_assert(or_c1);
  GOT_CMUX_ATTACH(ch2->cmux, or_c1, CELL_DIRECTION_IN);
  tt_int_op(or_c1->p_circ_id, ==, 100);
  tt_ptr_op(or_c1->p_chan, ==, ch2);

  or_c2 = or_circuit_new(100, ch1);
  tt_assert(or_c2);
  GOT_CMUX_ATTACH(ch1->cmux, or_c2, CELL_DIRECTION_IN);
  tt_int_op(or_c2->p_circ_id, ==, 100);
  tt_ptr_op(or_c2->p_chan, ==, ch1);

  circuit_set_n_circid_chan(TO_CIRCUIT(or_c1), 200, ch1);
  GOT_CMUX_ATTACH(ch1->cmux, or_c1, CELL_DIRECTION_OUT);

  circuit_set_n_circid_chan(TO_CIRCUIT(or_c2), 200, ch2);
  GOT_CMUX_ATTACH(ch2->cmux, or_c2, CELL_DIRECTION_OUT);

  tt_ptr_op(circuit_get_by_circid_channel(200, ch1), ==, TO_CIRCUIT(or_c1));
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), ==, TO_CIRCUIT(or_c2));
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), ==, TO_CIRCUIT(or_c1));
  /* Try the same thing again, to test the "fast" path. */
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), ==, TO_CIRCUIT(or_c1));
  tt_assert(circuit_id_in_use_on_channel(100, ch2));
  tt_assert(! circuit_id_in_use_on_channel(101, ch2));

  /* Try changing the circuitid and channel of that circuit. */
  circuit_set_p_circid_chan(or_c1, 500, ch3);
  GOT_CMUX_DETACH(ch2->cmux, TO_CIRCUIT(or_c1));
  GOT_CMUX_ATTACH(ch3->cmux, TO_CIRCUIT(or_c1), CELL_DIRECTION_IN);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch2), ==, NULL);
  tt_assert(! circuit_id_in_use_on_channel(100, ch2));
  tt_ptr_op(circuit_get_by_circid_channel(500, ch3), ==, TO_CIRCUIT(or_c1));

  /* Now let's see about destroy handling. */
  tt_assert(! circuit_id_in_use_on_channel(205, ch2));
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  channel_note_destroy_pending(ch2, 200);
  channel_note_destroy_pending(ch2, 205);
  channel_note_destroy_pending(ch1, 100);
  tt_assert(circuit_id_in_use_on_channel(205, ch2))
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  tt_assert(circuit_id_in_use_on_channel(100, ch1));

  tt_assert(TO_CIRCUIT(or_c2)->n_delete_pending != 0);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), ==, TO_CIRCUIT(or_c2));
  tt_ptr_op(circuit_get_by_circid_channel(100, ch1), ==, TO_CIRCUIT(or_c2));

  /* Okay, now free ch2 and make sure that the circuit ID is STILL not
   * usable, because we haven't declared the destroy to be nonpending */
  tt_int_op(cdm.ncalls, ==, 0);
  circuit_free(TO_CIRCUIT(or_c2));
  or_c2 = NULL; /* prevent free */
  tt_int_op(cdm.ncalls, ==, 2);
  memset(&cdm, 0, sizeof(cdm));
  tt_assert(circuit_id_in_use_on_channel(200, ch2));
  tt_assert(circuit_id_in_use_on_channel(100, ch1));
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), ==, NULL);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch1), ==, NULL);

  /* Now say that the destroy is nonpending */
  channel_note_destroy_not_pending(ch2, 200);
  tt_ptr_op(circuit_get_by_circid_channel(200, ch2), ==, NULL);
  channel_note_destroy_not_pending(ch1, 100);
  tt_ptr_op(circuit_get_by_circid_channel(100, ch1), ==, NULL);
  tt_assert(! circuit_id_in_use_on_channel(200, ch2));
  tt_assert(! circuit_id_in_use_on_channel(100, ch1));


done:
  tor_free(ch1);
  tor_free(ch2);
  tor_free(ch3);
  if (or_c1)
    circuit_free(TO_CIRCUIT(or_c1));
  if (or_c2)
    circuit_free(TO_CIRCUIT(or_c2));
  UNMOCK(circuitmux_attach_circuit);
  UNMOCK(circuitmux_detach_circuit);
}


struct testcase_t circuitlist_tests[] = {
  { "maps", test_clist_maps, TT_FORK, NULL, NULL },
  END_OF_TESTCASES
};
