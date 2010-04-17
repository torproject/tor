/* Copyright (c) 2010, Jacob Appelbaum, Steven J. Murdoch.
 * Copyright (c) 2010, The Tor Project, Inc. */
/* See LICENSE for licensing information */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "tor-fw-helper.h"
#include "tor-fw-helper-natpmp.h"

int
tor_natpmp_add_tcp_mapping(tor_fw_options_t *tor_fw_options)
{
    int r = 0;
    int x = 0;
    int sav_errno;
    int protocol = NATPMP_PROTOCOL_TCP;
    int lease = NATPMP_DEFAULT_LEASE;
    natpmp_t natpmp;
    natpmpresp_t response;

    fd_set fds;
    struct timeval timeout;

    if (tor_fw_options->verbose)
        fprintf(stdout, "V: natpmp init...\n");
    initnatpmp(&natpmp);

    if (tor_fw_options->verbose)
        fprintf(stdout, "V: sending natpmp portmapping request...\n");
    r = sendnewportmappingrequest(&natpmp, protocol,
                                  tor_fw_options->internal_port,
                                  tor_fw_options->external_port,
                                  lease);
    fprintf(stdout, "tor-fw-helper: NAT-PMP sendnewportmappingrequest returned"
            " %d (%s)\n", r, r==12?"SUCCESS":"FAILED");

    do {
        FD_ZERO(&fds);
        FD_SET(natpmp.s, &fds);
        getnatpmprequesttimeout(&natpmp, &timeout);
        select(FD_SETSIZE, &fds, NULL, NULL, &timeout);

        if (tor_fw_options->verbose)
            fprintf(stdout, "V: attempting to readnatpmpreponseorretry...\n");
        r = readnatpmpresponseorretry(&natpmp, &response);
        sav_errno = errno;

        if (r<0 && r!=NATPMP_TRYAGAIN)
        {
            fprintf(stderr, "E: readnatpmpresponseorretry failed %d\n", r);
            fprintf(stderr, "E: errno=%d '%s'\n", sav_errno,
                    strerror(sav_errno));
        }

    } while ( r == NATPMP_TRYAGAIN );

    if (r == NATPMP_SUCCESS) {
        fprintf(stdout, "tor-fw-helper: NAT-PMP mapped public port %hu to"
                " localport %hu liftime %u\n",
                response.pnu.newportmapping.mappedpublicport,
                response.pnu.newportmapping.privateport,
                response.pnu.newportmapping.lifetime);
    }

    x = closenatpmp(&natpmp);
    if (tor_fw_options->verbose)
        fprintf(stdout, "V: closing natpmp socket: %d\n", x);
    return r;
}

int
tor_natpmp_fetch_public_ip(tor_fw_options_t *tor_fw_options)
{
    int r = 0;
    int x = 0;
    int sav_errno;
    natpmp_t natpmp;
    natpmpresp_t response;
    struct timeval timeout;
    fd_set fds;

    r = initnatpmp(&natpmp);
    if (tor_fw_options->verbose)
        fprintf(stdout, "V: NAT-PMP init: %d\n", r);

    r = sendpublicaddressrequest(&natpmp);
    fprintf(stdout, "tor-fw-helper: NAT-PMP sendpublicaddressrequest returned"
            " %d (%s)\n", r, r==2?"SUCCESS":"FAILED");

    do {
        FD_ZERO(&fds);
        FD_SET(natpmp.s, &fds);
        getnatpmprequesttimeout(&natpmp, &timeout);
        select(FD_SETSIZE, &fds, NULL, NULL, &timeout);

        if (tor_fw_options->verbose)
            fprintf(stdout, "V: NAT-PMP attempting to read reponse...\n");
        r = readnatpmpresponseorretry(&natpmp, &response);
        sav_errno = errno;

        if (tor_fw_options->verbose)
            fprintf(stdout, "V: NAT-PMP readnatpmpresponseorretry returned"
                    " %d\n", r);

        if ( r < 0 && r != NATPMP_TRYAGAIN)
        {
            fprintf(stderr, "E: NAT-PMP readnatpmpresponseorretry failed %d\n",
                    r);
            fprintf(stderr, "E: NAT-PMP errno=%d '%s'\n", sav_errno,
                    strerror(sav_errno));
        }

    } while ( r == NATPMP_TRYAGAIN );

    if (r != 0)
    {
        fprintf(stderr, "E: NAT-PMP It appears that something went wrong:"
                " %d\n", r);
        return r;
    }

    fprintf(stdout, "tor-fw-helper: ExternalIPAddress = %s\n",
           inet_ntoa(response.pnu.publicaddress.addr));

    x = closenatpmp(&natpmp);

    if (tor_fw_options->verbose)
    {
        fprintf(stdout, "V: result = %u\n", r);
        fprintf(stdout, "V: type = %u\n", response.type);
        fprintf(stdout, "V: resultcode = %u\n", response.resultcode);
        fprintf(stdout, "V: epoch = %u\n", response.epoch);
        fprintf(stdout, "V: closing natpmp result: %d\n", r);
    }

    return r;
}

