
TESTS = test_config

noinst_PROGRAMS = test_config

bin_PROGRAMS = or

or_LDADD = -L../common -lor -lz

or_SOURCES = buffers.c circuit.c command.c connection.c \
             connection_exit.c connection_ap.c connection_op.c connection_or.c config.c \
             main.c onion.c routers.c directory.c dns.c

test_config_SOURCES = test_config.c config.c

test_config_LDADD = -L../common -lor

noinst_HEADERS = or.h tree.h


