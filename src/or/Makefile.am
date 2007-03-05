TESTS = test

noinst_PROGRAMS = test

bin_PROGRAMS = tor

tor_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dns.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	tor_main.c

tor_LDADD = ../common/libor.a ../common/libor-crypto.a -lz -lssl -lcrypto

test_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dns.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	test.c

test_LDADD = ../common/libor.a ../common/libor-crypto.a -lz -lssl -lcrypto

noinst_HEADERS = or.h eventdns.h eventdns_tor.h

