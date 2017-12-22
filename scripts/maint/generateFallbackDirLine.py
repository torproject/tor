#!/usr/bin/env python

# Generate a fallback directory whitelist/blacklist line for every fingerprint
# passed as an argument.
#
# Usage:
# generateFallbackDirLine.py fingerprint ...

import sys

import stem.descriptor.remote as remote

if len(sys.argv) <= 1:
  print "Usage: {} fingerprint ...".format(sys.argv[0])
  sys.exit(-1)

# we need the full consensus, because it has IPv6 ORPorts
# and we want a fingerprint to router mapping in routers
#
# stem returns document_handler='DOCUMENT' as a list of consensuses
# with one entry
consensus = remote.get_consensus(document_handler='DOCUMENT').run()[0]

for fingerprint in sys.argv[1:]:
  if fingerprint in consensus.routers:
    r = consensus.routers[fingerprint]
    # Tor clients don't use DirPorts, but old code requires one for fallbacks
    if r.dir_port is not None:
      # IPv4:DirPort orport=ORPort id=Fingerprint ipv6=[IPv6]:IPv6ORPort # nick
      ipv6_or_ap_list = [ apv for apv in r.or_addresses if apv[2] ]
      ipv6_str = ""
      if len(ipv6_or_ap_list) > 0:
        ipv6_or_ap = ipv6_or_ap_list[0]
        ipv6_str = " ipv6=[{}]:{}".format(ipv6_or_ap[0], ipv6_or_ap[1])
      print ("{}:{} orport={} id={}{} # {}"
             .format(r.address, r.dir_port, r.or_port, r.fingerprint,
                     ipv6_str, r.nickname))
    else:
      print "# {} needs a DirPort".format(fingerprint)    
  else:
    print "# {} not found in current consensus".format(fingerprint)
