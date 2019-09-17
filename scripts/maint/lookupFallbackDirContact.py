#!/usr/bin/env python

# Lookup fallback directory contact lines for every fingerprint passed as an
# argument.
#
# Usage:
# lookupFallbackDirContact.py fingerprint ...

import sys

import stem.descriptor.remote as remote

if len(sys.argv) <= 1:
  print "Usage: {} fingerprint ...".format(sys.argv[0])
  sys.exit(-1)

# we need descriptors, because the consensus does not have contact infos
descriptor_list = remote.get_server_descriptors(fingerprints=sys.argv[1:]).run()

descriptor_list_fingerprints = []
for d in descriptor_list:
  assert d.fingerprint in sys.argv[1:]
  descriptor_list_fingerprints.append(d.fingerprint)
  print "{} {}".format(d.fingerprint, d.contact)

for fingerprint in sys.argv[1:]:
  if fingerprint not in descriptor_list_fingerprints:
    print "{} not found in current descriptors".format(fingerprint)
