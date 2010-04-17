/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef _TOR_FW_HELPER_H
#define _TOR_FW_HELPER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#define tor_fw_version "0.1"

typedef struct {
    int verbose;
    int help;
    int test_commandline;
    uint16_t private_dir_port;
    uint16_t private_or_port;
    uint16_t public_dir_port;
    uint16_t public_or_port;
    uint16_t internal_port;
    uint16_t external_port;
    int fetch_public_ip;
    int nat_pmp_status;
    int upnp_status;
    int public_ip_status;
} tor_fw_options_t;

#endif

