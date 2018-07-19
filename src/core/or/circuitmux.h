/* * Copyright (c) 2012-2018, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file circuitmux.h
 * \brief Header file for circuitmux.c
 **/

#ifndef TOR_CIRCUITMUX_H
#define TOR_CIRCUITMUX_H

#include "core/or/or.h"
#include "lib/testsupport/testsupport.h"

typedef struct circuitmux_policy_s circuitmux_policy_t;
typedef struct circuitmux_policy_data_s circuitmux_policy_data_t;
typedef struct circuitmux_policy_circ_data_s circuitmux_policy_circ_data_t;

/*
 * Hash table entry (yeah, calling it chanid_circid_muxinfo_s seems to
 * break the hash table code).
 */
typedef struct chanid_circid_muxinfo_t chanid_circid_muxinfo_t;

/*
 * Anything the mux wants to store per-circuit in the map; right now just
 * a count of queued cells.
 */
typedef struct circuit_muxinfo_s circuit_muxinfo_t;

struct circuitmux_policy_s {
  /* Allocate cmux-wide policy-specific data */
  circuitmux_policy_data_t * (*alloc_cmux_data)(circuitmux_t *cmux);
  /* Free cmux-wide policy-specific data */
  void (*free_cmux_data)(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data);
  /* Allocate circuit policy-specific data for a newly attached circuit */
  circuitmux_policy_circ_data_t *
    (*alloc_circ_data)(circuitmux_t *cmux,
                       circuitmux_policy_data_t *pol_data,
                       circuit_t *circ,
                       cell_direction_t direction,
                       unsigned int cell_count);
  /* Free circuit policy-specific data */
  void (*free_circ_data)(circuitmux_t *cmux,
                         circuitmux_policy_data_t *pol_data,
                         circuit_t *circ,
                         circuitmux_policy_circ_data_t *pol_circ_data);
  /* Notify that a circuit has become active/inactive */
  void (*notify_circ_active)(circuitmux_t *cmux,
                             circuitmux_policy_data_t *pol_data,
                             circuit_t *circ,
                             circuitmux_policy_circ_data_t *pol_circ_data);
  void (*notify_circ_inactive)(circuitmux_t *cmux,
                               circuitmux_policy_data_t *pol_data,
                               circuit_t *circ,
                               circuitmux_policy_circ_data_t *pol_circ_data);
  /* Notify of arriving/transmitted cells on a circuit */
  void (*notify_set_n_cells)(circuitmux_t *cmux,
                             circuitmux_policy_data_t *pol_data,
                             circuit_t *circ,
                             circuitmux_policy_circ_data_t *pol_circ_data,
                             unsigned int n_cells);
  void (*notify_xmit_cells)(circuitmux_t *cmux,
                            circuitmux_policy_data_t *pol_data,
                            circuit_t *circ,
                            circuitmux_policy_circ_data_t *pol_circ_data,
                            unsigned int n_cells);
  /* Choose a circuit */
  circuit_t * (*pick_active_circuit)(circuitmux_t *cmux,
                                     circuitmux_policy_data_t *pol_data);
  /* Optional: channel comparator for use by the scheduler */
  int (*cmp_cmux)(circuitmux_t *cmux_1, circuitmux_policy_data_t *pol_data_1,
                  circuitmux_t *cmux_2, circuitmux_policy_data_t *pol_data_2);
};

/*
 * Circuitmux policy implementations can subclass this to store circuitmux-
 * wide data; it just has the magic number in the base struct.
 */

struct circuitmux_policy_data_s {
  uint32_t magic;
};

/*
 * Circuitmux policy implementations can subclass this to store circuit-
 * specific data; it just has the magic number in the base struct.
 */

struct circuitmux_policy_circ_data_s {
  uint32_t magic;
};

/*
 * This struct holds whatever we want to store per attached circuit on a
 * circuitmux_t; right now, just the count of queued cells and the direction.
 */

struct circuit_muxinfo_s {
  /* Count of cells on this circuit at last update */
  unsigned int cell_count;
  /* Direction of flow */
  cell_direction_t direction;
  /* Policy-specific data */
  circuitmux_policy_circ_data_t *policy_data;
  /* Mark bit for consistency checker */
  unsigned int mark:1;
};

/*
 * A map from channel ID and circuit ID to a circuit_muxinfo_t for that
 * circuit.
 */

struct chanid_circid_muxinfo_t {
  HT_ENTRY(chanid_circid_muxinfo_t) node;
  uint64_t chan_id;
  circid_t circ_id;
  circuit_muxinfo_t muxinfo;
};

/*
 * Upcast #defines for the above types
 */

/**
 * Convert a circuitmux_policy_data_t subtype to a circuitmux_policy_data_t.
 */

#define TO_CMUX_POL_DATA(x)  (&((x)->base_))

/**
 * Convert a circuitmux_policy_circ_data_t subtype to a
 * circuitmux_policy_circ_data_t.
 */

#define TO_CMUX_POL_CIRC_DATA(x)  (&((x)->base_))

/* Consistency check */
void circuitmux_assert_okay(circuitmux_t *cmux);

/* Create/destroy */
circuitmux_t * circuitmux_alloc(void);
void circuitmux_detach_all_circuits(circuitmux_t *cmux,
                                    smartlist_t *detached_out);
void circuitmux_free_(circuitmux_t *cmux);
#define circuitmux_free(cmux) \
  FREE_AND_NULL(circuitmux_t, circuitmux_free_, (cmux))

/* Policy control */
void circuitmux_clear_policy(circuitmux_t *cmux);
MOCK_DECL(const circuitmux_policy_t *,
          circuitmux_get_policy, (circuitmux_t *cmux));
void circuitmux_set_policy(circuitmux_t *cmux,
                           const circuitmux_policy_t *pol);

/* Status inquiries */
cell_direction_t circuitmux_attached_circuit_direction(
    chanid_circid_muxinfo_t *hashent);
int circuitmux_is_circuit_attached(circuitmux_t *cmux, circuit_t *circ);
int circuitmux_is_circuit_active(circuitmux_t *cmux, circuit_t *circ);
unsigned int circuitmux_num_cells_for_circuit(circuitmux_t *cmux,
                                              circuit_t *circ);
MOCK_DECL(unsigned int, circuitmux_num_cells, (circuitmux_t *cmux));
unsigned int circuitmux_num_circuits(circuitmux_t *cmux);
unsigned int circuitmux_num_active_circuits(circuitmux_t *cmux);

/* Debuging interface - slow. */
int64_t circuitmux_count_queued_destroy_cells(const channel_t *chan,
                                              const circuitmux_t *cmux);

/* Channel interface */
circuit_t * circuitmux_get_first_active_circuit(circuitmux_t *cmux,
                                    destroy_cell_queue_t **destroy_queue_out);
void circuitmux_notify_xmit_cells(circuitmux_t *cmux, circuit_t *circ,
                                  unsigned int n_cells);
void circuitmux_notify_xmit_destroy(circuitmux_t *cmux);

/* Circuit interface */
MOCK_DECL(void, circuitmux_attach_circuit, (circuitmux_t *cmux,
                                            circuit_t *circ,
                                            cell_direction_t direction));
MOCK_DECL(void, circuitmux_detach_circuit,
          (circuitmux_t *cmux, circuit_t *circ));
void circuitmux_clear_num_cells(circuitmux_t *cmux, circuit_t *circ);
void circuitmux_set_num_cells(circuitmux_t *cmux, circuit_t *circ,
                              unsigned int n_cells);

void circuitmux_append_destroy_cell(channel_t *chan,
                                    circuitmux_t *cmux, circid_t circ_id,
                                    uint8_t reason);
void circuitmux_mark_destroyed_circids_usable(circuitmux_t *cmux,
                                              channel_t *chan);

/* Lookup interface */
chanid_circid_muxinfo_t * circuitmux_find_map_entry(circuitmux_t *cmux,
                                                    circuit_t *circ);

/* Optional interchannel comparisons for scheduling */
MOCK_DECL(int, circuitmux_compare_muxes,
          (circuitmux_t *cmux_1, circuitmux_t *cmux_2));

#endif /* !defined(TOR_CIRCUITMUX_H) */

