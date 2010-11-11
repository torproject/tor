TESTS = test

noinst_PROGRAMS = test test-child

AM_CPPFLAGS = -DSHARE_DATADIR="\"$(datadir)\"" \
        -DLOCALSTATEDIR="\"$(localstatedir)\"" \
        -DBINDIR="\"$(bindir)\""	       \
	-I"$(top_srcdir)/src/or"

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

test_SOURCES = \
	test.c \
	test_addr.c \
	test_containers.c \
	test_crypto.c \
	test_data.c \
	test_dir.c \
	test_microdesc.c \
	test_util.c \
	tinytest.c

if USE_BUFFEREVENTS
levent_openssl_lib = -levent_openssl
else
levent_openssl_lib =
endif

test_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
test_LDADD = ../or/libtor.a ../common/libor.a ../common/libor-crypto.a \
	../common/libor-event.a \
	@TOR_ZLIB_LIBS@ -lm @TOR_LIBEVENT_LIBS@ @TOR_OPENSSL_LIBS@ \
	@TOR_LIB_WS32@ @TOR_LIB_GDI@ $(levent_openssl_lib)

noinst_HEADERS = \
	tinytest.h \
	tinytest_macros.h \
	test.h


