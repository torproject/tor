# $Id$
# Copyright (c) 2001-2004, Roger Dingledine
# Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson
# See LICENSE for licensing information

AUTOMAKE_OPTIONS = foreign
 # else it keeps trying to put COPYING back in

SUBDIRS = src doc contrib

DIST_SUBDIRS = src doc contrib

EXTRA_DIST = INSTALL README AUTHORS LICENSE ChangeLog tor.spec tor.spec.in

#install-data-local:
#	$(INSTALL) -m 755 -d $(LOCALSTATEDIR)/lib/tor

dist-rpm: dist
	RPM_BUILD_DIR="/tmp/tor-rpm-build-$$$$";                \
	rm -rf $$RPM_BUILD_DIR;                                 \
	mkdir $$RPM_BUILD_DIR || exit 1;                        \
	for subdir in BUILD RPMS SOURCES SPECS SRPMS; do        \
	    mkdir $$RPM_BUILD_DIR/$$subdir;                     \
	done;                                                   \
	cp tor-$(VERSION).tar.gz $$RPM_BUILD_DIR/SOURCES;       \
	rpmbuild -ba --define "_topdir $$RPM_BUILD_DIR"	tor.spec;
#	   $$RPMBUILD_OPTIONS tor.spec; 			\
	mv $$RPM_BUILD_DIR/SRPMS/* .;                           \
	mv $$RPM_BUILD_DIR/RPMS/*/* .;                          \
	rm -rf $$RPM_BUILD_DIR

dist-osx:
	@if [ "x$(prefix)" != 'x/Library/Tor' ]; then \
	  echo "Configure with --prefix=/Library/Tor, please"; \
	  exit 1; \
	fi; \
	if [ "x$(bindir)" != 'x/Library/Tor' ]; then \
	  echo "Configure with --bindir=/Library/Tor, please"; \
	  exit 1; \
	fi; \
	if [ "x$(sysconfdir)" != 'x/Library' ]; then \
	  echo "Configure with --sysconfdir=/Library, please"; \
	  exit 1; \
	fi
	$(MAKE) all
	VERSION=$(VERSION) sh ./contrib/osx/package.sh

doxygen:
	doxygen && cd doc/doxygen/latex && make

# Avoid strlcpy.c, strlcat.c, tree.h
check-spaces:
	./contrib/checkSpace.pl -C             \
	        src/common/*.h                 \
		src/common/[^s]*.c             \
		src/or/[^t]*.[ch] src/or/t*.c

