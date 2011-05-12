
noinst_LIBRARIES = libor.a libor-crypto.a libor-event.a

EXTRA_DIST = common_sha1.i sha256.c

#CFLAGS  = -Wall -Wpointer-arith -O2

if USE_OPENBSD_MALLOC
libor_extra_source=OpenBSD_malloc_Linux.c
else
libor_extra_source=
endif

libor_a_SOURCES = address.c log.c util.c compat.c container.c mempool.c \
	memarea.c di_ops.c util_codedigest.c $(libor_extra_source)
libor_crypto_a_SOURCES = crypto.c aes.c tortls.c torgzip.c
libor_event_a_SOURCES = compat_libevent.c

noinst_HEADERS = address.h torlog.h crypto.h util.h compat.h aes.h torint.h tortls.h strlcpy.c strlcat.c torgzip.h container.h ht.h mempool.h memarea.h ciphers.inc compat_libevent.h tortls_states.h di_ops.h

common_sha1.i: $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS)
	if test "@SHA1SUM@" != none; then \
	  @SHA1SUM@ $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS) | @SED@ -n 's/^\(.*\)$$/"\1\\n"/p' > common_sha1.i; \
	elif test "@OPENSSL@" != none; then \
	  @OPENSSL@ sha1 $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS) | @SED@ -n 's/SHA1(\(.*\))= \(.*\)/"\2  \1\\n"/p' > common_sha1.i; \
	else \
	  rm common_sha1.i; \
	  touch common_sha1.i; \
	fi

util_codedigest.o: common_sha1.i
crypto.o: sha256.c
