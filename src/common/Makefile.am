
noinst_LIBRARIES = libor.a libor-crypto.a libor-event.a

EXTRA_DIST = common_sha1.i sha256.c Makefile.nmake

#CFLAGS  = -Wall -Wpointer-arith -O2

if USE_OPENBSD_MALLOC
libor_extra_source=OpenBSD_malloc_Linux.c
else
libor_extra_source=
endif

libor_a_SOURCES = \
  address.c					\
  compat.c					\
  container.c					\
  di_ops.c					\
  log.c						\
  memarea.c					\
  mempool.c					\
  procmon.c					\
  util.c					\
  util_codedigest.c				\
  $(libor_extra_source)

libor_crypto_a_SOURCES = \
  aes.c		\
  crypto.c	\
  torgzip.c	\
  tortls.c

libor_event_a_SOURCES = compat_libevent.c

noinst_HEADERS = 				\
  address.h					\
  aes.h						\
  ciphers.inc					\
  compat.h					\
  compat_libevent.h				\
  container.h					\
  crypto.h					\
  di_ops.h					\
  ht.h						\
  memarea.h					\
  mempool.h					\
  procmon.h					\
  strlcat.c					\
  strlcpy.c					\
  torgzip.h					\
  torint.h					\
  torlog.h					\
  tortls.h					\
  util.h

common_sha1.i: $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS)
	if test "@SHA1SUM@" != none; then \
	  (cd "$(srcdir)" && "@SHA1SUM@" $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS)) | "@SED@" -n 's/^\(.*\)$$/"\1\\n"/p' > common_sha1.i; \
	elif test "@OPENSSL@" != none; then \
	  (cd "$(srcdir)" && "@OPENSSL@" sha1 $(libor_SOURCES) $(libor_crypto_a_SOURCES) $(noinst_HEADERS)) | "@SED@" -n 's/SHA1(\(.*\))= \(.*\)/"\2  \1\\n"/p' > common_sha1.i; \
	else \
	  rm common_sha1.i; \
	  touch common_sha1.i; \
	fi

util_codedigest.o: common_sha1.i
crypto.o: sha256.c
