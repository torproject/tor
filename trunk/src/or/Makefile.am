
TESTS = test_config

noinst_PROGRAMS = test_config

bin_PROGRAMS = or

or_LDADD = -L../common -lor

or_SOURCES = buffers.c cell.c circuit.c command.c connection.c \
             connection_exit.c connection_ap.c connection_op.c connection_or.c config.c \
             main.c onion.c routers.c

test_config_SOURCES = test_config.c

test_config_LDADD = config.o -L../common -lor

noinst_HEADERS = or.h


