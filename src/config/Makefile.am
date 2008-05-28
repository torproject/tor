confdir = $(sysconfdir)/tor

EXTRA_DIST = fallback-consensus geoip

conf_DATA = torrc.sample

data_DATA = fallback-consensus geoip

# If we don't have it, fake it.
fallback-consensus:
	touch fallback-consensus

