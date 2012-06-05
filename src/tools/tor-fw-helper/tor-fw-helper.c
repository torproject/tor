/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010-2012, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/**
 * \file tor-fw-helper.c
 * \brief The main wrapper around our firewall helper logic.
 **/

/*
 * tor-fw-helper is a tool for opening firewalls with NAT-PMP and UPnP; this
 * tool is designed to be called by hand or by Tor by way of a exec() at a
 * later date.
 */

#include "orconfig.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#endif

#include "tor-fw-helper.h"
#ifdef NAT_PMP
#include "tor-fw-helper-natpmp.h"
#endif
#ifdef MINIUPNPC
#include "tor-fw-helper-upnp.h"
#endif

/** This is our meta storage type - it holds information about each helper
  including the total number of helper backends, function pointers, and helper
  state. */
typedef struct backends_t {
  /** The total number of backends */
  int n_backends;
  /** The backend functions as an array */
  tor_fw_backend_t backend_ops[MAX_BACKENDS];
  /** The internal backend state */
  void *backend_state[MAX_BACKENDS];
} backends_t;

/** Initalize each backend helper with the user input stored in <b>options</b>
 * and put the results in the <b>backends</b> struct. */
static int
init_backends(tor_fw_options_t *options, backends_t *backends)
{
  int n_available = 0;
  int i, r, n;
  tor_fw_backend_t *backend_ops_list[MAX_BACKENDS];
  void *data = NULL;
  /* First, build a list of the working backends. */
  n = 0;
#ifdef MINIUPNPC
  backend_ops_list[n++] = (tor_fw_backend_t *) tor_fw_get_miniupnp_backend();
#endif
#ifdef NAT_PMP
  backend_ops_list[n++] = (tor_fw_backend_t *) tor_fw_get_natpmp_backend();
#endif
  n_available = n;

  /* Now, for each backend that might work, try to initialize it.
   * That's how we roll, initialized.
   */
  n = 0;
  for (i=0; i<n_available; ++i) {
    data = calloc(1, backend_ops_list[i]->state_len);
    if (!data) {
      perror("calloc");
      exit(1);
    }
    r = backend_ops_list[i]->init(options, data);
    if (r == 0) {
      backends->backend_ops[n] = *backend_ops_list[i];
      backends->backend_state[n] = data;
      n++;
    } else {
      free(data);
    }
  }
  backends->n_backends = n;

  return n;
}

/** Return the proper commandline switches when the user needs information. */
static void
usage(void)
{
  fprintf(stderr, "tor-fw-helper usage:\n"
          " [-h|--help]\n"
          " [-T|--Test]\n"
          " [-v|--verbose]\n"
          " [-g|--fetch-public-ip]\n"
          " -i|--internal-or-port [TCP port]\n"
          " [-e|--external-or-port [TCP port]]\n"
          " [-d|--internal-dir-port [TCP port]\n"
          " [-p|--external-dir-port [TCP port]]]\n");
}

/** Log commandline options to a hardcoded file <b>tor-fw-helper.log</b> in the
 * current working directory. */
static int
log_commandline_options(int argc, char **argv)
{
  int i, retval;
  FILE *logfile;
  time_t now;

  /* Open the log file */
  logfile = fopen("tor-fw-helper.log", "a");
  if (NULL == logfile)
    return -1;

  /* Send all commandline arguments to the file */
  now = time(NULL);
  retval = fprintf(logfile, "START: %s\n", ctime(&now));
  for (i = 0; i < argc; i++) {
    retval = fprintf(logfile, "ARG: %d: %s\n", i, argv[i]);
    if (retval < 0)
      goto error;

    retval = fprintf(stdout, "ARG: %d: %s\n", i, argv[i]);
    if (retval < 0)
      goto error;
  }
  now = time(NULL);
  retval = fprintf(logfile, "END: %s\n", ctime(&now));

  /* Close and clean up */
  retval = fclose(logfile);
  return retval;

  /* If there was an error during writing */
 error:
  fclose(logfile);
  return -1;
}

/** Iterate over over each of the supported <b>backends</b> and attempt to
 * fetch the public ip. */
static void
tor_fw_fetch_public_ip(tor_fw_options_t *tor_fw_options,
                       backends_t *backends)
{
  int i;
  int r = 0;

  if (tor_fw_options->verbose)
    fprintf(stdout, "V: tor_fw_fetch_public_ip\n");

  for (i=0; i<backends->n_backends; ++i) {
    if (tor_fw_options->verbose) {
        fprintf(stdout, "V: running backend_state now: %i\n", i);
        fprintf(stdout, "V: size of backend state: %u\n",
                (int)(backends->backend_ops)[i].state_len);
        fprintf(stdout, "V: backend state name: %s\n",
                (char *)(backends->backend_ops)[i].name);
      }
    r = backends->backend_ops[i].fetch_public_ip(tor_fw_options,
                                                 backends->backend_state[i]);
    fprintf(stdout, "tor-fw-helper: tor_fw_fetch_public_ip backend %s "
            " returned: %i\n", (char *)(backends->backend_ops)[i].name, r);
  }
}

/** Iterate over each of the supported <b>backends</b> and attempt to add a
 * port forward for the OR port stored in <b>tor_fw_options</b>. */
static void
tor_fw_add_or_port(tor_fw_options_t *tor_fw_options,
                       backends_t *backends)
{
  int i;
  int r = 0;

  if (tor_fw_options->verbose)
    fprintf(stdout, "V: tor_fw_add_or_port\n");

  for (i=0; i<backends->n_backends; ++i) {
    if (tor_fw_options->verbose) {
      fprintf(stdout, "V: running backend_state now: %i\n", i);
      fprintf(stdout, "V: size of backend state: %u\n",
              (int)(backends->backend_ops)[i].state_len);
      fprintf(stdout, "V: backend state name: %s\n",
              (const char *) backends->backend_ops[i].name);
    }
    r = backends->backend_ops[i].add_tcp_mapping(tor_fw_options,
                                                 backends->backend_state[i]);
    fprintf(stdout, "tor-fw-helper: tor_fw_add_or_port backend %s "
            "returned: %i\n", (const char *) backends->backend_ops[i].name, r);
  }
}

/** Iterate over each of the supported <b>backends</b> and attempt to add a
 * port forward for the Dir port stored in <b>tor_fw_options</b>. */
static void
tor_fw_add_dir_port(tor_fw_options_t *tor_fw_options,
                       backends_t *backends)
{
  int i;
  int r = 0;

  if (tor_fw_options->verbose)
    fprintf(stdout, "V: tor_fw_add_dir_port\n");

  for (i=0; i<backends->n_backends; ++i) {
    if (tor_fw_options->verbose) {
      fprintf(stdout, "V: running backend_state now: %i\n", i);
      fprintf(stdout, "V: size of backend state: %u\n",
              (int)(backends->backend_ops)[i].state_len);
      fprintf(stdout, "V: backend state name: %s\n",
              (char *)(backends->backend_ops)[i].name);
    }
    r = backends->backend_ops[i].add_tcp_mapping(tor_fw_options,
                                                 backends->backend_state[i]);
    fprintf(stdout, "tor-fw-helper: tor_fw_add_dir_port backend %s "
            "returned: %i\n", (const char *)backends->backend_ops[i].name, r);
  }
}

/** Called before we make any calls to network-related functions.
 * (Some operating systems require their network libraries to be
 * initialized.) (from common/compat.c) */
static int
network_init(void)
{
#ifdef _WIN32
  /* This silly exercise is necessary before windows will allow
   * gethostbyname to work. */
  WSADATA WSAData;
  int r;
  r = WSAStartup(0x101, &WSAData);
  if (r) {
    fprintf(stderr, "E: Error initializing Windows network layer "
            "- code was %d", r);
    return -1;
  }
  /* WSAData.iMaxSockets might show the max sockets we're allowed to use.
   * We might use it to complain if we're trying to be a server but have
   * too few sockets available. */
#endif
  return 0;
}

int
main(int argc, char **argv)
{
  int r = 0;
  int c = 0;

  tor_fw_options_t tor_fw_options;
  backends_t backend_state;

  memset(&tor_fw_options, 0, sizeof(tor_fw_options));
  memset(&backend_state, 0, sizeof(backend_state));

  while (1) {
    int option_index = 0;
    static struct option long_options[] =
      {
        {"verbose", 0, 0, 'v'},
        {"help", 0, 0, 'h'},
        {"internal-or-port", 1, 0, 'i'},
        {"external-or-port", 1, 0, 'e'},
        {"internal-dir-port", 1, 0, 'd'},
        {"external-dir-port", 1, 0, 'p'},
        {"fetch-public-ip", 0, 0, 'g'},
        {"test-commandline", 0, 0, 'T'},
        {0, 0, 0, 0}
      };

    c = getopt_long(argc, argv, "vhi:e:d:p:gT",
                    long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'v': tor_fw_options.verbose = 1; break;
      case 'h': tor_fw_options.help = 1; usage(); exit(1); break;
      case 'i': sscanf(optarg, "%hu", &tor_fw_options.private_or_port);
        break;
      case 'e': sscanf(optarg, "%hu", &tor_fw_options.public_or_port);
        break;
      case 'd': sscanf(optarg, "%hu", &tor_fw_options.private_dir_port);
        break;
      case 'p': sscanf(optarg, "%hu", &tor_fw_options.public_dir_port);
        break;
      case 'g': tor_fw_options.fetch_public_ip = 1; break;
      case 'T': tor_fw_options.test_commandline = 1; break;
      case '?': break;
      default : fprintf(stderr, "Unknown option!\n"); usage(); exit(1);
    }
  }

  if (tor_fw_options.verbose) {
    fprintf(stderr, "V: tor-fw-helper version %s\n"
            "V: We were called with the following arguments:\n"
            "V: verbose = %d, help = %d, pub or port = %u, "
            "priv or port = %u\n"
            "V: pub dir port =  %u, priv dir port = %u\n"
            "V: fetch_public_ip = %u\n",
            tor_fw_version, tor_fw_options.verbose, tor_fw_options.help,
            tor_fw_options.private_or_port, tor_fw_options.public_or_port,
            tor_fw_options.private_dir_port, tor_fw_options.public_dir_port,
            tor_fw_options.fetch_public_ip);
  }

  if (tor_fw_options.test_commandline) {
    return log_commandline_options(argc, argv);
  }

  /* At the very least, we require an ORPort;
     Given a private ORPort, we can ask for a mapping that matches the port
     externally.
  */
  if (!tor_fw_options.private_or_port && !tor_fw_options.fetch_public_ip) {
    fprintf(stderr, "E: We require an ORPort or fetch_public_ip"
            " request!\n");
    usage();
    exit(1);
  } else {
    /* When we only have one ORPort, internal/external are
       set to be the same.*/
    if (!tor_fw_options.public_or_port && tor_fw_options.private_or_port) {
      if (tor_fw_options.verbose)
        fprintf(stdout, "V: We're setting public_or_port = "
                "private_or_port.\n");
      tor_fw_options.public_or_port = tor_fw_options.private_or_port;
    }
  }
  if (!tor_fw_options.private_dir_port) {
    if (tor_fw_options.verbose)
      fprintf(stdout, "V: We have no DirPort; no hole punching for "
              "DirPorts\n");

  } else {
    /* When we only have one DirPort, internal/external are
       set to be the same.*/
    if (!tor_fw_options.public_dir_port && tor_fw_options.private_dir_port) {
      if (tor_fw_options.verbose)
        fprintf(stdout, "V: We're setting public_or_port = "
                "private_or_port.\n");

      tor_fw_options.public_dir_port = tor_fw_options.private_dir_port;
    }
  }

  if (tor_fw_options.verbose) {
    fprintf(stdout, "V: pub or port = %u, priv or port = %u\n"
            "V: pub dir port =  %u, priv dir port = %u\n",
            tor_fw_options.private_or_port, tor_fw_options.public_or_port,
            tor_fw_options.private_dir_port,
            tor_fw_options.public_dir_port);
  }

  // Initialize networking
  if (network_init())
    exit(1);

  // Initalize the various fw-helper backend helpers
  r = init_backends(&tor_fw_options, &backend_state);
  if (r)
    printf("tor-fw-helper: %i NAT traversal helper(s) loaded\n", r);

  if (tor_fw_options.fetch_public_ip) {
    tor_fw_fetch_public_ip(&tor_fw_options, &backend_state);
  }

  if (tor_fw_options.private_or_port) {
    tor_fw_options.internal_port = tor_fw_options.private_or_port;
    tor_fw_options.external_port = tor_fw_options.private_or_port;
    tor_fw_add_or_port(&tor_fw_options, &backend_state);
  }

  if (tor_fw_options.private_dir_port) {
    tor_fw_options.internal_port = tor_fw_options.private_dir_port;
    tor_fw_options.external_port = tor_fw_options.private_dir_port;
    tor_fw_add_dir_port(&tor_fw_options, &backend_state);
  }

  r = (((tor_fw_options.nat_pmp_status | tor_fw_options.upnp_status)
        |tor_fw_options.public_ip_status));
  if (r > 0) {
    fprintf(stdout, "tor-fw-helper: SUCCESS\n");
  } else {
    fprintf(stderr, "tor-fw-helper: FAILURE\n");
  }

  exit(r);
}

