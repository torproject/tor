TESTS = test

noinst_PROGRAMS = test

AM_CPPFLAGS = -DSHARE_DATADIR="\"$(datadir)\"" \
        -DLOCALSTATEDIR="\"$(localstatedir)\"" \
        -DBINDIR="\"$(bindir)\""

AM_CFLAGS = -I../or

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

test_SOURCES = test_data.c test.c test_crypto.c test_containers.c tinytest.c

test_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
test_LDADD = ../or/libtor.a ../common/libor.a ../common/libor-crypto.a \
	../common/libor-event.a \
	-lz -lm -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@

noinst_HEADERS = tinytest.h tinytest_macros.h

EXTRA_DIST = tinytest_demo.c
