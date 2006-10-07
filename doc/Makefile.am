
EXTRA_DIST = tor-spec.txt HACKING rend-spec.txt control-spec.txt dir-spec.txt socks-extensions.txt website img tor-resolve.1 version-spec.txt path-spec.txt tor-osx-dmg-creation.txt tor-rpm-creation.txt

man_MANS = tor.1 tor-resolve.1

SUBDIRS = design-paper

DIST_SUBDIRS = design-paper

website: ../../website/docs/
	rm -rf website
	mkdir website
	if test -d $(srcdir)/../../website ; then \
		cd $(srcdir)/../../website && $(MAKE); \
	fi
	if test -d $(srcdir)/../../website ; then \
		cp $(srcdir)/../../website/docs/tor-*.html.* \
			$(srcdir)/../../website/stylesheet.css website; \
	fi
img: ../../website/img/
	rm -rf img
	mkdir img
#	if test -d $(srcdir)/../../website/img; then \
#		cp $(srcdir)/../../website/img/*.png \
#			$(srcdir)/../../website/img/*.jpg img; \
#	fi

.PHONY: website img
