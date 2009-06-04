bin_PROGRAMS = tor-resolve tor-gencert
noinst_PROGRAMS =  tor-checkkey

tor_resolve_SOURCES = tor-resolve.c
tor_resolve_LDFLAGS = @TOR_LDFLAGS_libevent@
tor_resolve_LDADD = ../common/libor.a @TOR_LIB_WS32@

tor_gencert_SOURCES = tor-gencert.c
tor_gencert_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
tor_gencert_LDADD = ../common/libor.a ../common/libor-crypto.a \
        -lz -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@

tor_checkkey_SOURCES = tor-checkkey.c
tor_checkkey_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
tor_checkkey_LDADD = ../common/libor.a ../common/libor-crypto.a \
        -lz -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@
