/* Copyright (c) 2020, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file providers.c
 * \brief Defines LTTng probes.
 **/

/*
 * Create the traceprobes. Only done once in this C file.
 */
#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
