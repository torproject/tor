TESTS = test

noinst_PROGRAMS = test

bin_PROGRAMS = tor

tor_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dns.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	tor_main.c

tor_LDADD = ../common/libor.a ../common/libor-crypto.a

test_SOURCES = buffers.c circuitbuild.c circuitlist.c \
	circuituse.c command.c config.c \
	connection.c connection_edge.c connection_or.c control.c \
	cpuworker.c directory.c dirserv.c dns.c hibernate.c main.c \
	onion.c policies.c relay.c rendcommon.c rendclient.c rendmid.c \
	rendservice.c rephist.c router.c routerlist.c routerparse.c \
	eventdns.c \
	test.c

test_LDADD = ../common/libor.a ../common/libor-crypto.a

noinst_HEADERS = or.h eventdns.h eventdns_tor.h micro-revision.i

tor_main.o: micro-revision.i

micro-revision.i: FORCE
	if test -d ../../.svn ; then 				\
	  svn info ../.. |              			\
	  sed -n 's/^Revision: \([0-9][0-9]*\).*/"\1"/p' > micro-revision.i \
	     || true;                                           \
	fi;							\
	if test ! -f micro-revision.i -a x`which svk` != x; then\
          location=../..;                                       \
          rev=x;                                                \
          while test x$$rev = xx; do                            \
            x=`svk info $$location |                            \
              sed -n 's/^Mirrored From:.*, Rev\. \([0-9][0-9]*\)/\1/p'`; \
            if test x$$x != x; then                             \
              rev=$$x;                                          \
              break;                                            \
            else                                                \
              loc=`svk info $$location |                        \
                sed -n 's/^Copied From: \(.*\), Rev\. [0-9][0-9]*/\1/p'`; \
              if test x$$loc = x; then                          \
                break;                                          \
              else                                              \
                location=/$$loc;                                \
              fi;                                               \
            fi;                                                 \
          done;                                                 \
          if test x$$rev != x; then                             \
            echo \"$$rev\" > micro-revision.i;                  \
          fi;                                                   \
        fi;                                                     \
	if test ! -f micro-revision.i; then			\
	  echo '""' > micro-revision.i;				\
	fi

FORCE:
