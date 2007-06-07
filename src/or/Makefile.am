TESTS = test

noinst_PROGRAMS = test

bin_PROGRAMS = tor

tor_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	tor_main.c

# -L flags need to go in LDFLAGS. -l flags need to go in LDADD.
# This seems to matter nowhere but on windows, but I assure you that it
# matters a lot there, and is quite hard to debug if you forget to do it.

tor_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ @TOR_LDFLAGS_libevent@
tor_LDADD = ../common/libor.a ../common/libor-crypto.a \
  -lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@
test_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dirvote.c \
	dns.c dnsserv.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	test.c

test_LDFLAGS = @TOR_LDFLAGS_zlib@ @TOR_LDFLAGS_openssl@ \
        @TOR_LDFLAGS_libevent@
test_LDADD = ../common/libor.a ../common/libor-crypto.a \
        -lz -levent -lssl -lcrypto @TOR_LIB_WS32@ @TOR_LIB_GDI@

noinst_HEADERS = or.h eventdns.h eventdns_tor.h micro-revision.i

tor_main.o: micro-revision.i

micro-revision.i: FORCE
	@svkdir=$$SVKROOT; \
	if test "x$$svkdir" = x ; then \
	  svkdir=$$HOME/.svk; \
	fi; \
	if test -d ../../.svn && test -x "`which svn 2>&1;true`" ; then \
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
		sed -n 's/^Copied From: \(.*\), Rev\. [0-9][0-9]*/\1/p'`; \
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

#Dummy target to ensure that micro-revision.i _always_ gets built.
FORCE:
