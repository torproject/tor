TESTS = test

noinst_PROGRAMS = test

bin_PROGRAMS = tor

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

COMMON_SRC = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c geoip.c hibernate.c main.c $(tor_platform_source) \
	networkstatus.c onion.c policies.c \
	reasons.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	$(evdns_source) config_codedigest.c

tor_SOURCES = $(COMMON_SRC) tor_main.c

AM_CPPFLAGS = -DSHARE_DATADIR="\"$(datadir)\"" \
        -DLOCALSTATEDIR="\"$(localstatedir)\"" \
        -DBINDIR="\"$(bindir)\""

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

tor_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@
tor_LDADD = ../common/libor.a ../common/libor-crypto.a \
	../common/libor-event.a \
	-lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@
test_SOURCES = $(COMMON_SRC) test_data.c test.c

test_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
test_LDADD = ../common/libor.a ../common/libor-crypto.a \
	../common/libor-event.a \
	-lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@

noinst_HEADERS = or.h eventdns.h eventdns_tor.h micro-revision.i

config_codedigest.o: or_sha1.i

tor_main.o: micro-revision.i

micro-revision.i: FORCE
	@svkdir=$$SVKROOT; 					\
	if test "x$$svkdir" = x ; then 				\
	  svkdir=$$HOME/.svk; 					\
	fi; 							\
	if test -d ../../.git && test -x "`which git 2>&1;true`" ; then \
	  if test -d ../../.git/svn && test -x "`which git-svn 2>&1;true`" ; then \
	    git-svn info ../../README | 			\
	    sed -n 's/^Revision: \([0-9][0-9]*\).*/"\1"/p'      \
	                                   > micro-revision.tmp \
	        || true; 					\
	  fi; 							\
	elif test -d ../../.svn && test -x "`which svn 2>&1;true`" ; then \
	  svn info ../.. |					\
	  sed -n 's/^Revision: \([0-9][0-9]*\).*/"\1"/p' > micro-revision.tmp \
	     || true;						\
	elif test -x "`which svk 2>&1;true`" && test -d $$svkdir/local; then \
	  location=../..;					\
	  rev=x;						\
	  while test x$$rev = xx; do				\
	    x=`svk info $$location |				\
	      sed -n 's/^Mirrored From:.*, Rev\. \([0-9][0-9]*\)/\1/p'`; \
	    if test x$$x != x; then				\
	      rev=$$x;						\
	      break;						\
	    else						\
	      loc=`svk info $$location |			\
		sed -n 's/^Copied From: \(.*\), Rev\. [0-9][0-9]*/\1/p' | \
	        head -1`;					\
	      if test x$$loc = x; then				\
		break;						\
	      else						\
		location=/$$loc;				\
	      fi;						\
	    fi;							\
	  done;							\
	  if test x$$rev != xx; then				\
	    echo \"$$rev\" > micro-revision.tmp;		\
	  fi;							\
	fi;							\
	if test ! -f micro-revision.tmp ; then			\
	  if test ! -f micro-revision.i ; then			\
	    echo '""' > micro-revision.i;			\
	  fi;							\
	elif test ! -f micro-revision.i ||			\
	  test x"`cat micro-revision.tmp`" != x"`cat micro-revision.i`"; then \
	  mv micro-revision.tmp micro-revision.i;		\
	fi; true

or_sha1.i: $(tor_SOURCES) test_data.c test.c
	if test "@SHA1SUM@" != none; then \
	  @SHA1SUM@ $(tor_SOURCES) test_data.c test.c | @SED@ -n 's/^\(.*\)$$/"\1\\n"/p' > or_sha1.i; \
	elif test "@OPENSSL@" != none; then \
	  @OPENSSL@ sha1 $(tor_SOURCES) test_data.c test.c | @SED@ -n 's/SHA1(\(.*\))= \(.*\)/"\2  \1\\n"/p' > or_sha1.i; \
	else \
	  rm or_sha1.i; \
	  touch or_sha1.i; \
	fi



#Dummy target to ensure that micro-revision.i _always_ gets built.
FORCE:
