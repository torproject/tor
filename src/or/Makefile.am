TESTS = test

noinst_PROGRAMS = test

bin_PROGRAMS = tor

tor_SOURCES = buffers.c circuit.c command.c config.c \
	connection.c connection_edge.c connection_or.c \
	cpuworker.c directory.c dirserv.c dns.c main.c \
	onion.c rendcommon.c rendmid.c rendservice.c rephist.c \
	router.c routerlist.c \
	tor_main.c

tor_LDADD = ../common/libor.a

test_SOURCES = buffers.c circuit.c command.c config.c \
	connection.c connection_edge.c connection_or.c \
	cpuworker.c directory.c dirserv.c dns.c main.c \
	onion.c rendcommon.c rendmid.c rendservice.c rephist.c \
	router.c routerlist.c \
	test.c

test_LDADD = ../common/libor.a

noinst_HEADERS = or.h tree.h


