
noinst_LIBRARIES = libor.a libor-crypto.a

#CFLAGS  = -Wall -Wpointer-arith -O2

libor_a_SOURCES = log.c util.c compat.c container.c mempool.c
libor_crypto_a_SOURCES = crypto.c aes.c tortls.c torgzip.c

if USE_OPENBSD_MALLOC
libor_a_SOURCES += OpenBSD_malloc_Linux.c
endif

noinst_HEADERS = log.h crypto.h test.h util.h compat.h aes.h torint.h tortls.h strlcpy.c strlcat.c torgzip.h container.h ht.h mempool.h
