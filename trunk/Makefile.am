AUTOMAKE_OPTIONS = foreign
 # else it keeps trying to put COPYING back in

SUBDIRS = src doc contrib

DIST_SUBDIRS = src doc contrib

EXTRA_DIST = INSTALL README AUTHORS LICENSE ChangeLog

#install-data-local:
#	$(INSTALL) -m 755 -d $(LOCALSTATEDIR)/lib/tor

dist-rpm: dist
	rm -rf /tmp/tor-rpm-build
	mkdir /tmp/tor-rpm-build
	for subdir in BUILD RPMS SOURCES SPECS SRPMS; do \
	    mkdir /tmp/tor-rpm-build/$$subdir;           \
	done
	cp tor-$(VERSION).tar.gz /tmp/tor-rpm-build/SOURCES
	rpmbuild -ba --define '_topdir /tmp/tor-rpm-build' contrib/tor.spec
	mv /tmp/tor-rpm-build/*RPMS/* .
