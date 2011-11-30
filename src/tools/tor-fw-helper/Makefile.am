if USE_FW_HELPER
bin_PROGRAMS = tor-fw-helper
else
bin_PROGRAMS =
endif

tor_fw_helper_SOURCES = \
	tor-fw-helper.c \
	tor-fw-helper-natpmp.c \
	tor-fw-helper-upnp.c
noinst_HEADERS = \
	tor-fw-helper.h \
	tor-fw-helper-natpmp.h \
	tor-fw-helper-upnp.h

if NAT_PMP
nat_pmp_ldflags = @TOR_LDFLAGS_libnatpmp@
nat_pmp_ldadd  = -lnatpmp @TOR_LIB_IPHLPAPI@
nat_pmp_cppflags = @TOR_CPPFLAGS_libnatpmp@
else
nat_pmp_ldflags =
nat_pmp_ldadd  =
nat_pmp_cppflags =
endif

if MINIUPNPC
miniupnpc_ldflags = @TOR_LDFLAGS_libminiupnpc@
miniupnpc_ldadd = -lminiupnpc -lm @TOR_LIB_IPHLPAPI@
miniupnpc_cppflags = @TOR_CPPFLAGS_libminiupnpc@
else
miniupnpc_ldflags =
miniupnpc_ldadd =
miniupnpc_cppflags =
endif

tor_fw_helper_LDFLAGS = $(nat_pmp_ldflags) $(miniupnpc_ldflags)
tor_fw_helper_LDADD = ../../common/libor.a $(nat_pmp_ldadd) $(miniupnpc_ldadd) @TOR_LIB_WS32@
tor_fw_helper_CPPFLAGS = $(nat_pmp_cppflags) $(miniupnpc_cppflags)
