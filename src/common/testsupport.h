/* Copyright (c) 2013, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#ifndef TOR_TESTSUPPORT_H
#define TOR_TESTSUPPORT_H

#ifdef TOR_UNIT_TESTS
#define STATIC_UNLESS_TESTING
#else
#define STATIC_UNLESS_TESTING static
#endif

#endif

