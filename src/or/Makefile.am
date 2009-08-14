bin_PROGRAMS = tor
noinst_LIBRARIES = libtor.a

if BUILD_NT_SERVICES
tor_platform_source=ntmain.c
else
tor_platform_source=
endif

EXTRA_DIST=ntmain.c or_sha1.i

if USE_EXTERNAL_EVDNS
evdns_source=
else
evdns_source=eventdns.c
endif

libtor_a_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c geoip.c hibernate.c main.c $(tor_platform_source) \
	microdesc.c \
	networkstatus.c onion.c policies.c \
	reasons.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	$(evdns_source) config_codedigest.c

#libtor_a_LIBADD = ../common/libor.a ../common/libor-crypto.a \
#	../common/libor-event.a


tor_SOURCES = tor_main.c

AM_CPPFLAGS = -DSHARE_DATADIR="\"$(datadir)\"" \
        -DLOCALSTATEDIR="\"$(localstatedir)\"" \
        -DBINDIR="\"$(bindir)\""

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

tor_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@
tor_LDADD = ./libtor.a ../common/libor.a ../common/libor-crypto.a \
	../common/libor-event.a \
	@TOR_ZLIB_LIBS@ -lm @TOR_LIBEVENT_LIBS@ @TOR_OPENSSL_LIBS@ @TOR_LIB_WS32@ @TOR_LIB_GDI@

if USE_BUFFEREVENTS
tor_LDADD += -levent_openssl
endif

noinst_HEADERS = buffers.h circuitbuild.h circuitlist.h circuituse.h \
	command.h config.h connection_edge.h connection.h connection_or.h \
	control.h cpuworker.h directory.h dirserv.h dirvote.h dns.h \
	dnsserv.h geoip.h hibernate.h main.h microdesc.h networkstatus.h \
	ntmain.h onion.h policies.h reasons.h relay.h rendclient.h \
	rendcommon.h rendmid.h rendservice.h rephist.h router.h routerlist.h \
	routerparse.h or.h eventdns.h eventdns_tor.h micro-revision.i

config_codedigest.o: or_sha1.i

tor_main.o: micro-revision.i

micro-revision.i: FORCE
	@rm -f micro-revision.tmp;					\
	if test -d ../../.git && test -x "`which git 2>&1;true`"; then 	\
	  HASH="`git rev-parse --short=16 HEAD`"; 			\
	  echo \"$$HASH\" > micro-revision.tmp; 			\
        fi;								\
	if test ! -f micro-revision.tmp ; then				\
	  if test ! -f micro-revision.i ; then				\
	    echo '""' > micro-revision.i;				\
	  fi;								\
	elif test ! -f micro-revision.i ||				\
	  test x"`cat micro-revision.tmp`" != x"`cat micro-revision.i`"; then \
	  mv micro-revision.tmp micro-revision.i;			\
	fi; true

or_sha1.i: $(tor_SOURCES)
	if test "@SHA1SUM@" != none; then \
	  @SHA1SUM@ $(tor_SOURCES) | @SED@ -n 's/^\(.*\)$$/"\1\\n"/p' > or_sha1.i; \
	elif test "@OPENSSL@" != none; then \
	  @OPENSSL@ sha1 $(tor_SOURCES) | @SED@ -n 's/SHA1(\(.*\))= \(.*\)/"\2  \1\\n"/p' > or_sha1.i; \
	else \
	  rm or_sha1.i; \
	  touch or_sha1.i; \
	fi

CLEANFILES = micro-revision.i

#Dummy target to ensure that micro-revision.i _always_ gets built.
FORCE:
