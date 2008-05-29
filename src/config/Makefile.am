confdir = $(sysconfdir)/tor

tordatadir = $(datadir)/tor

EXTRA_DIST = geoip
# fallback-consensus

conf_DATA = torrc.sample

tordata_DATA = geoip
# fallback_consensus

# If we don't have it, fake it.
fallback-consensus:
	touch fallback-consensus

