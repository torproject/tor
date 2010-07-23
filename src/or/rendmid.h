/* Copyright (c) 2001 Matej Pfajfar.
 * Copyright (c) 2001-2004, Roger Dingledine.
 * Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson.
 * Copyright (c) 2007-2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file geoip.h
 * \brief Header file for geoip functions
 **/

#ifndef _TOR_GEOIP_H
#define _TOR_GEOIP_H

int rend_mid_establish_intro(or_circuit_t *circ, const char *request,
                             size_t request_len);
int rend_mid_introduce(or_circuit_t *circ, const char *request,
                       size_t request_len);
int rend_mid_establish_rendezvous(or_circuit_t *circ, const char *request,
                                  size_t request_len);
int rend_mid_rendezvous(or_circuit_t *circ, const char *request,
                        size_t request_len);

#endif

