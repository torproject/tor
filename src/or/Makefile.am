TESTS = test

noinst_PROGRAMS = test

sbin_PROGRAMS = tor

tor_SOURCES = buffers.c circuit.c command.c connection.c \
             connection_or.c config.c dirserv.c \
             onion.c router.c routerlist.c directory.c dns.c connection_edge.c \
             cpuworker.c main.c tor_main.c

tor_LDADD = ../common/libor.a

test_SOURCES = buffers.c circuit.c command.c connection.c \
             connection_or.c config.c dirserv.c \
             onion.c router.c routerlist.c directory.c dns.c connection_edge.c \
             cpuworker.c main.c test.c

test_LDADD = ../common/libor.a

noinst_HEADERS = or.h tree.h


