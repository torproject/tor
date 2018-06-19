/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitlist.h
 * \brief Header file for circuitlist.c.
 **/

#ifndef TOR_CIRCUITLIST_H
#define TOR_CIRCUITLIST_H

#include "testsupport.h"
#include "hs_ident.h"

/** Convert a circuit_t* to a pointer to the enclosing or_circuit_t.  Assert
 * if the cast is impossible. */
or_circuit_t *TO_OR_CIRCUIT(circuit_t *);
const or_circuit_t *CONST_TO_OR_CIRCUIT(const circuit_t *);
/** Convert a circuit_t* to a pointer to the enclosing origin_circuit_t.
 * Assert if the cast is impossible. */
origin_circuit_t *TO_ORIGIN_CIRCUIT(circuit_t *);
const origin_circuit_t *CONST_TO_ORIGIN_CIRCUIT(const circuit_t *);

MOCK_DECL(smartlist_t *, circuit_get_global_list, (void));
smartlist_t *circuit_get_global_origin_circuit_list(void);
int circuit_any_opened_circuits(void);
int circuit_any_opened_circuits_cached(void);
void circuit_cache_opened_circuit_state(int circuits_are_opened);

const char *circuit_state_to_string(int state);
const char *circuit_purpose_to_controller_string(uint8_t purpose);
const char *circuit_purpose_to_controller_hs_state_string(uint8_t purpose);
const char *circuit_purpose_to_string(uint8_t purpose);
void circuit_dump_by_conn(connection_t *conn, int severity);
void circuit_set_p_circid_chan(or_circuit_t *circ, circid_t id,
                               channel_t *chan);
void circuit_set_n_circid_chan(circuit_t *circ, circid_t id,
                               channel_t *chan);
void channel_mark_circid_unusable(channel_t *chan, circid_t id);
void channel_mark_circid_usable(channel_t *chan, circid_t id);
time_t circuit_id_when_marked_unusable_on_channel(circid_t circ_id,
                                                  channel_t *chan);
void circuit_set_state(circuit_t *circ, uint8_t state);
void circuit_close_all_marked(void);
int32_t circuit_initial_package_window(void);
origin_circuit_t *origin_circuit_new(void);
or_circuit_t *or_circuit_new(circid_t p_circ_id, channel_t *p_chan);
circuit_t *circuit_get_by_circid_channel(circid_t circ_id,
                                         channel_t *chan);
circuit_t *
circuit_get_by_circid_channel_even_if_marked(circid_t circ_id,
                                             channel_t *chan);
int circuit_id_in_use_on_channel(circid_t circ_id, channel_t *chan);
circuit_t *circuit_get_by_edge_conn(edge_connection_t *conn);
void circuit_unlink_all_from_channel(channel_t *chan, int reason);
origin_circuit_t *circuit_get_by_global_id(uint32_t id);
origin_circuit_t *circuit_get_ready_rend_circ_by_rend_data(
  const rend_data_t *rend_data);
origin_circuit_t *circuit_get_next_by_pk_and_purpose(origin_circuit_t *start,
                                     const uint8_t *digest, uint8_t purpose);
origin_circuit_t *circuit_get_next_service_intro_circ(origin_circuit_t *start);
origin_circuit_t *circuit_get_next_service_rp_circ(origin_circuit_t *start);
origin_circuit_t *circuit_get_next_service_hsdir_circ(origin_circuit_t *start);
origin_circuit_t *circuit_find_to_cannibalize(uint8_t purpose,
                                              extend_info_t *info, int flags);
void circuit_mark_all_unused_circs(void);
void circuit_mark_all_dirty_circs_as_unusable(void);
MOCK_DECL(void, circuit_mark_for_close_, (circuit_t *circ, int reason,
                                          int line, const char *file));
int circuit_get_cpath_len(origin_circuit_t *circ);
int circuit_get_cpath_opened_len(const origin_circuit_t *);
void circuit_clear_cpath(origin_circuit_t *circ);
crypt_path_t *circuit_get_cpath_hop(origin_circuit_t *circ, int hopnum);
void circuit_get_all_pending_on_channel(smartlist_t *out,
                                        channel_t *chan);
int circuit_count_pending_on_channel(channel_t *chan);

#define circuit_mark_for_close(c, reason)                               \
  circuit_mark_for_close_((c), (reason), __LINE__, SHORT_FILE__)

void assert_cpath_layer_ok(const crypt_path_t *cp);
MOCK_DECL(void, assert_circuit_ok,(const circuit_t *c));
void circuit_free_all(void);
void circuits_handle_oom(size_t current_allocation);

void circuit_clear_testing_cell_stats(circuit_t *circ);

void channel_note_destroy_pending(channel_t *chan, circid_t id);
MOCK_DECL(void, channel_note_destroy_not_pending,
          (channel_t *chan, circid_t id));

smartlist_t *circuit_find_circuits_to_upgrade_from_guard_wait(void);

#ifdef CIRCUITLIST_PRIVATE
STATIC void circuit_free_(circuit_t *circ);
#define circuit_free(circ) FREE_AND_NULL(circuit_t, circuit_free_, (circ))
STATIC size_t n_cells_in_circ_queues(const circuit_t *c);
STATIC uint32_t circuit_max_queued_data_age(const circuit_t *c, uint32_t now);
STATIC uint32_t circuit_max_queued_cell_age(const circuit_t *c, uint32_t now);
STATIC uint32_t circuit_max_queued_item_age(const circuit_t *c, uint32_t now);
#endif /* defined(CIRCUITLIST_PRIVATE) */

#endif /* !defined(TOR_CIRCUITLIST_H) */

