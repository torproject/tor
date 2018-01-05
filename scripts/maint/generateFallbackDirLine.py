#!/usr/bin/env python

# Generate a fallback directory whitelist/blacklist line for every fingerprint
# passed as an argument.
#
# Usage:
# generateFallbackDirLine.py fingerprint ...

import sys
import urllib2

import stem.descriptor.remote
import stem.util.tor_tools

if len(sys.argv) <= 1:
  print('Usage: %s fingerprint ...' % sys.argv[0])
  sys.exit(1)

for fingerprint in sys.argv[1:]:
  if not stem.util.tor_tools.is_valid_fingerprint(fingerprint):
    print("'%s' isn't a valid relay fingerprint" % fingerprint)
    sys.exit(1)

  try:
    desc = stem.descriptor.remote.get_server_descriptors(fingerprint).run()[0]
  except urllib2.HTTPError as exc:
    if exc.code == 404:
      print('# %s not found in recent descriptors' % fingerprint)
      continue
    else:
      raise

  if not desc.dir_port:
    print("# %s needs a DirPort" % fingerprint)
  else:
    ipv6_addresses = [(address, port) for address, port, is_ipv6 in desc.or_addresses if is_ipv6]
    ipv6_field = ' ipv6=[%s]:%s' % ipv6_addresses[0] if ipv6_addresses else ''
    print('%s:%s orport=%s id=%s%s # %s' % (desc.address, desc.dir_port, desc.or_port, fingerprint, ipv6_field, desc.nickname))
