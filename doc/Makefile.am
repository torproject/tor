
EXTRA_DIST = website img HACKING                             \
             tor-resolve.1                                   \
             tor-osx-dmg-creation.txt tor-rpm-creation.txt   \
             tor-win32-mingw-creation.txt

man_MANS = tor.1 tor-resolve.1

SUBDIRS = design-paper spec

DIST_SUBDIRS = design-paper spec

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
