if USE_FW_HELPER
bin_PROGRAMS = tor-fw-helper
else
bin_PROGRAMS =
endif

tor_fw_helper_SOURCES = tor-fw-helper.c \
	tor-fw-helper-natpmp.c tor-fw-helper-upnp.c
tor_fw_helper_INCLUDES = tor-fw-helper.h tor-fw-helper-natpmp.h tor-fw-helper-upnp.h
tor_fw_helper_LDFLAGS = @TOR_LDFLAGS_libnatpmp@ @TOR_LDFLAGS_libminiupnpc@
tor_fw_helper_LDADD = -lnatpmp -lminiupnpc ../../common/libor.a @TOR_LIB_WS32@
tor_fw_helper_CPPFLAGS = @TOR_CPPFLAGS_libnatpmp@ @TOR_CPPFLAGS_libminiupnpc@
