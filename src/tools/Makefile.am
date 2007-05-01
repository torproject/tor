bin_PROGRAMS = tor-resolve tor-gencert

tor_resolve_SOURCES = tor-resolve.c
tor_resolve_LDFLAGS = @TOR_LDFLAGS_libevent@
tor_resolve_LDADD = ../common/libor.a -levent @TOR_LIB_WS32@

tor_gencert_SOURCES = tor-gencert.c
tor_gencert_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
tor_gencert_LDADD = ../common/libor.a ../common/libor-crypto.a \
        -lz -lcrypto -levent @TOR_LIB_WS32@ @TOR_LIB_GDI@

