confdir = $(sysconfdir)/tor
tordatadir = $(datadir)/tor

EXTRA_DIST = fallback-consensus geoip

conf_DATA = torrc.sample

tordata_DATA = fallback-consensus geoip

# If we don't have it, fake it.
fallback-consensus:
	touch fallback-consensus

