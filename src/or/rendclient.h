/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file rendclient.h
 * \brief Header file for rendclient.c.
 **/

#ifndef _TOR_RENDCLIENT_H
#define _TOR_RENDCLIENT_H

void rend_client_introcirc_has_opened(origin_circuit_t *circ);
void rend_client_rendcirc_has_opened(origin_circuit_t *circ);
int rend_client_introduction_acked(origin_circuit_t *circ,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_client_refetch_v2_renddesc(const rend_data_t *rend_query);
int rend_client_remove_intro_point(extend_info_t *failed_intro,
                                   const rend_data_t *rend_query);
int rend_client_rendezvous_acked(origin_circuit_t *circ,
                                 const uint8_t *request,
                                 size_t request_len);
int rend_client_receive_rendezvous(origin_circuit_t *circ,
                                   const uint8_t *request,
                                   size_t request_len);
void rend_client_desc_trynow(const char *query);

extend_info_t *rend_client_get_random_intro(const rend_data_t *rend_query);

int rend_client_send_introduction(origin_circuit_t *introcirc,
                                  origin_circuit_t *rendcirc);
int rend_parse_service_authorization(or_options_t *options,
                                     int validate_only);
rend_service_authorization_t *rend_client_lookup_service_authorization(
                                                const char *onion_address);
void rend_service_authorization_free_all(void);
rend_data_t *rend_data_dup(const rend_data_t *request);

#endif

