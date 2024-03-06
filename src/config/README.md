# src/config files

This directory has configuration files that ship with Tor.  They include:

 - geoip
 - geoip6

## Geoip files for IPv4 and IPv6

### torrc.minimal, torrc.sample:

generated from torrc.minimal.in and torrc.sample.in by autoconf.

### torrc.minimal.in:

## A very small torrc, suitable for installation by default in
/etc/tor/torrc.

We try to change torrc.minimal.in as infrequently as possible,
since doing so makes the users of many packages have to re-build
their torrc files.


## torrc.minimal.in-staging

This is where we stage changes to torrc.minimal.in over time so
that when we have a change large enough to warrant a new
torrc.minimal.in, we can copy all the other changes over
wholesale.

## torrc.sample.in:

A verbose, discursive, batteries-included torrc.  Suitable for
letting people know how to set up various options, including those
most people shouldn't mess with.


==============================

## On the geoip format:

Our geoip files are line-oriented. Any empty line, or line starting
with a #, is ignored.

All other lines are composed of three comma-separated values:
START,END,CC. For the geoip file, START and END are IPv4 addresses
as expressed as 32-bit integers (such as 3325256709 to represent
198.51.100.5). For the geoip6 file, START and END are IPv6
addresses, with no brackets. In both cases CC is a two-character
country code.

The semantic meaning of a line START,END,CC is that all addresses
between START and END **_inclusive_** should be mapped to the country code
CC.

We guarantee that all entries within these files are disjoint --
that is, there is no address that is matched by more than one
line. We also guarantee that all entries within these files are
sorted in numerically ascending order by address.

Thus, one effective search algorithm here is to perform a binary
search on all the entries in the file.

Note that there **_are_** "gaps" in these databases: not every possible
address maps to a country code. In those cases, Tor reports the
country as ??.
