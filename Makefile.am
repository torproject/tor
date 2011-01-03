# Copyright (c) 2001-2004, Roger Dingledine
# Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson
# Copyright (c) 2007-2011, The Tor Project, Inc.
# See LICENSE for licensing information

# "foreign" means we don't follow GNU package layout standards
# 1.6 means we require automake vesion 1.6
AUTOMAKE_OPTIONS = foreign 1.6

SUBDIRS = src doc contrib

DIST_SUBDIRS = src doc contrib

EXTRA_DIST = \
	ChangeLog					\
	INSTALL						\
	LICENSE						\
	README						\
	ReleaseNotes					\
	tor.spec					\
	tor.spec.in

#install-data-local:
#	$(INSTALL) -m 755 -d $(LOCALSTATEDIR)/lib/tor

# Assume a tarball is in .. for now.
dist-rpm:
	RPM_BUILD_DIR="/tmp/tor-rpm-build-$$$$";                \
	rm -rf $$RPM_BUILD_DIR;                                 \
	mkdir $$RPM_BUILD_DIR || exit 1;                        \
	for subdir in BUILD RPMS SOURCES SPECS SRPMS; do        \
	    mkdir $$RPM_BUILD_DIR/$$subdir;                     \
	done;                                                   \
	mkdir $$RPM_BUILD_DIR/SOURCES/tor-$(VERSION);           \
	cp -R ./ $$RPM_BUILD_DIR/SOURCES/tor-$(VERSION)/;       \
	pushd $$RPM_BUILD_DIR/SOURCES/;                         \
	tar zcf tor-$(VERSION).tar.gz ./;                       \
	popd;                                                   \
	LIBS=-lrt rpmbuild -ba --define "_topdir $$RPM_BUILD_DIR" tor.spec; \
	mv $$RPM_BUILD_DIR/SRPMS/* .;                           \
	mv $$RPM_BUILD_DIR/RPMS/* .;                            \
	rm -rf $$RPM_BUILD_DIR

dist: check

doxygen:
	doxygen && cd doc/doxygen/latex && make

test: all
	./src/test/test

# Avoid strlcpy.c, strlcat.c, aes.c, OpenBSD_malloc_Linux.c, sha256.c,
# eventdns.[hc], tinytest*.[ch]
check-spaces:
	./contrib/checkSpace.pl -C                    \
	        src/common/*.h                        \
		src/common/[^asO]*.c                  \
                src/common/address.c                  \
		src/or/[^e]*.[ch]                     \
                src/or/eventdns_tor.h                 \
		src/test/test*.[ch]                   \
                src/tools/*.[ch]                      \
		src/tools/tor-fw-helper/*.[ch]

check-docs:
	./contrib/checkOptionDocs.pl

check-logs:
	./contrib/checkLogs.pl                        \
		src/*/*.[ch] | sort -n

