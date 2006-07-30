
EXTRA_DIST = tor-spec.txt HACKING rend-spec.txt control-spec.txt dir-spec.txt socks-extensions.txt website img tor-resolve.1 version-spec.txt tor-osx-dmg-creation.txt tor-rpm-creation.txt

man_MANS = tor.1 tor-resolve.1

SUBDIRS = design-paper

DIST_SUBDIRS = design-paper

website: ../../../cvs/website/docs/
	rm -rf website
	mkdir website
	if test -d $(srcdir)/../../../cvs/website ; then \
		cd $(srcdir)/../../../cvs/website && $(MAKE); \
	fi
	if test -d $(srcdir)/../../../cvs/website ; then \
		cp $(srcdir)/../../../cvs/website/docs/tor-*.html.* \
			$(srcdir)/../../../cvs/website/stylesheet.css website; \
	fi
img: ../../../cvs/website/img/
	rm -rf img
	mkdir img
#	if test -d $(srcdir)/../../website/img; then \
#		cp $(srcdir)/../../website/img/*.png \
#			$(srcdir)/../../website/img/*.jpg img; \
#	fi

.PHONY: website img
