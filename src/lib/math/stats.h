/* Copyright (c) 2022, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file stats.h
 *
 * \brief Header for stats.c
 **/

#ifndef TOR_STATS_H
#define TOR_STATS_H

/** Update an average making it a "running average". The "avg" is the current
 * value that will be updated to the new one. The "value" is the new value to
 * add to the average and "n" is the new count as in including the "value". */
#define STATS_UPDATE_AVG(avg, value, n) \
  avg = ((avg) * ((n) - 1) + (value)) / (n)

#endif /* !defined(TOR_STATS_H) */
