
noinst_LIBRARIES = libor.a libor-crypto.a

#CFLAGS  = -Wall -Wpointer-arith -O2

if USE_OPENBSD_MALLOC
libor_extra_source=OpenBSD_malloc_Linux.c
else
libor_extra_source=
endif

libor_a_SOURCES = address.c log.c util.c compat.c container.c mempool.c \
	memarea.c di_ops.c $(libor_extra_source)
libor_crypto_a_SOURCES = crypto.c aes.c tortls.c torgzip.c

noinst_HEADERS = address.h log.h crypto.h test.h util.h compat.h aes.h torint.h tortls.h strlcpy.c strlcat.c torgzip.h container.h ht.h mempool.h memarea.h di_ops.h ciphers.inc
