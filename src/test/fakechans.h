 /* Copyright (c) 2014, The Tor Project, Inc. */
 /* See LICENSE for licensing information */

#ifndef TOR_FAKECHANS_H
#define TOR_FAKECHANS_H

/**
 * \file fakechans.h
 * \brief Declarations for fake channels for test suite use
 */

void make_fake_cell(cell_t *c);
void make_fake_var_cell(var_cell_t *c);
channel_t * new_fake_channel(void);

#endif /* !defined(TOR_FAKECHANS_H) */
