/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

/*
 * tor-fw-helper is a tool for opening firewalls with NAT-PMP and UPnP; this
 * tool is designed to be called by hand or by Tor by way of a exec() at a
 * later date.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include "orconfig.h"
#include "tor-fw-helper.h"
#include "tor-fw-helper-natpmp.h"
#include "tor-fw-helper-upnp.h"

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

/* Log commandline options */
static int
test_commandline_options(int argc, char **argv)
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

static void
tor_fw_fetch_public_ip(tor_fw_options_t *tor_fw_options,
                       miniupnpc_state_t *miniupnpc_state)
{
    int r = 0;
    r = tor_natpmp_fetch_public_ip(tor_fw_options);
    if (tor_fw_options->verbose)
        fprintf(stdout, "V: Attempts to fetch public ip (natpmp) resulted in: "
                "%d\n", r);

    if (r == 0)
        tor_fw_options->public_ip_status = 1;

    r = tor_upnp_fetch_public_ip(miniupnpc_state);
    if (tor_fw_options->verbose)
        fprintf(stdout, "V: Attempts to fetch public ip (upnp) resulted in: "
                "%d\n", r);

    if (r == 0)
        tor_fw_options->public_ip_status = 1;
}

static void
tor_fw_add_or_port(tor_fw_options_t *tor_fw_options, miniupnpc_state_t
                   *miniupnpc_state)
{
    int r = 0;
    tor_fw_options->internal_port = tor_fw_options->private_or_port;
    tor_fw_options->external_port = tor_fw_options->public_or_port;

    r = tor_natpmp_add_tcp_mapping(tor_fw_options);
    fprintf(stdout, "tor-fw-helper: Attempts to add ORPort mapping (natpmp)"
            "resulted in: %d\n", r);

    if (r == 0)
        tor_fw_options->nat_pmp_status = 1;

    r = tor_upnp_add_tcp_mapping(miniupnpc_state,
                                 tor_fw_options->private_or_port,
                                 tor_fw_options->public_or_port);
    fprintf(stdout, "tor-fw-helper: Attempts to add ORPort mapping (upnp)"
            "resulted in: %d\n", r);

    if (r == 0)
        tor_fw_options->upnp_status = 1;
}

static void
tor_fw_add_dir_port(tor_fw_options_t *tor_fw_options, miniupnpc_state_t
                    *miniupnpc_state)
{
    int r = 0;
    tor_fw_options->internal_port = tor_fw_options->private_dir_port;
    tor_fw_options->external_port = tor_fw_options->public_dir_port;

    r = tor_natpmp_add_tcp_mapping(tor_fw_options);
    fprintf(stdout, "V: Attempts to add DirPort mapping (natpmp) resulted in: "
            "%d\n", r);

    r = tor_upnp_add_tcp_mapping(miniupnpc_state,
                                 tor_fw_options->private_or_port,
                                 tor_fw_options->public_or_port);
    fprintf(stdout, "V: Attempts to add DirPort mapping (upnp) resulted in: "
            "%d\n",
           r);
}

int
main(int argc, char **argv)
{
   int r = 0;
   int c = 0;

   tor_fw_options_t tor_fw_options = {0,0,0,0,0,0,0,0,0,0,0,0,0};
   miniupnpc_state_t miniupnpc_state;

   miniupnpc_state.init = 0;

   while (1)
   {
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

       switch (c)
       {
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

   if (tor_fw_options.verbose)
   {
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
     return test_commandline_options(argc, argv);
   }

   /* At the very least, we require an ORPort;
      Given a private ORPort, we can ask for a mapping that matches the port
      externally.
   */
   if (!tor_fw_options.private_or_port && !tor_fw_options.fetch_public_ip)
   {
       fprintf(stderr, "E: We require an ORPort or fetch_public_ip"
               " request!\n");
       usage();
       exit(1);
   } else {
       /* When we only have one ORPort, internal/external are
          set to be the same.*/
       if (!tor_fw_options.public_or_port && tor_fw_options.private_or_port)
       {
           if (tor_fw_options.verbose)
               fprintf(stdout, "V: We're setting public_or_port = "
                       "private_or_port.\n");
           tor_fw_options.public_or_port = tor_fw_options.private_or_port;
       }
   }
   if (!tor_fw_options.private_dir_port)
   {
       if (tor_fw_options.verbose)
            fprintf(stdout, "V: We have no DirPort; no hole punching for "
                    "DirPorts\n");

   } else {
       /* When we only have one DirPort, internal/external are
          set to be the same.*/
       if (!tor_fw_options.public_dir_port && tor_fw_options.private_dir_port)
       {
           if (tor_fw_options.verbose)
                fprintf(stdout, "V: We're setting public_or_port = "
                        "private_or_port.\n");

           tor_fw_options.public_dir_port = tor_fw_options.private_dir_port;
       }
   }

   if (tor_fw_options.verbose)
   {
       fprintf(stdout, "V: pub or port = %u, priv or port = %u\n"
              "V: pub dir port =  %u, priv dir port = %u\n",
               tor_fw_options.private_or_port, tor_fw_options.public_or_port,
               tor_fw_options.private_dir_port,
               tor_fw_options.public_dir_port);
   }

   if (tor_fw_options.fetch_public_ip)
   {
       tor_fw_fetch_public_ip(&tor_fw_options, &miniupnpc_state);
   }

   if (tor_fw_options.private_or_port)
   {
       tor_fw_add_or_port(&tor_fw_options, &miniupnpc_state);
   }

   if (tor_fw_options.private_dir_port)
   {
       tor_fw_add_dir_port(&tor_fw_options, &miniupnpc_state);
   }

   r = (((tor_fw_options.nat_pmp_status | tor_fw_options.upnp_status)
        |tor_fw_options.public_ip_status));
   if (r > 0)
   {
       fprintf(stdout, "tor-fw-helper: SUCCESS\n");
   } else {
       fprintf(stderr, "tor-fw-helper: FAILURE\n");
   }

   exit(r);
}

