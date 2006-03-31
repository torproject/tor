
EXTRA_DIST = tor-spec.txt HACKING rend-spec.txt control-spec.txt dir-spec.txt socks-extensions.txt website img tor-resolve.1 version-spec.txt tor-osx-dmg-creation.txt tor-rpm-creation.txt

man_MANS = tor.1 tor-resolve.1

SUBDIRS = design-paper

DIST_SUBDIRS = design-paper

website: ../../website/docs/
	cd $(srcdir)/../../website && $(MAKE)
	rm -rf website
	mkdir website
	cp $(srcdir)/../../website/docs/tor-*.html.* \
		$(srcdir)/../../website/stylesheet.css website
img: ../../website/img/
	rm -rf img
	mkdir img
	cp $(srcdir)/../../website/img/*.png \
		$(srcdir)/../../website/img/*.jpg img

.PHONY: website img
