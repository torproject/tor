
EXTRA_DIST = tor-spec.txt HACKING rend-spec.txt control-spec.txt dir-spec.txt socks-extensions.txt website img tor-resolve.1 version-spec.txt tor-osx-dmg-creation.txt tor-rpm-creation.txt

man_MANS = tor.1 tor-resolve.1

SUBDIRS = design-paper

DIST_SUBDIRS = design-paper

website:
	cd $(srcdir)/../../website && $(MAKE)
	mkdir $(distdir)/website
	cp -p $(srcdir)/../../website/docs/tor-*.html.* \
	$(srcdir)/../../website/stylesheet.css $(distdir)/website
img:
	mkdir $(distdir)/img
	cp -p $(srcdir)/../../website/img/*.png \
	$(srcdir)/../../website/img/*.jpg $(distdir)/img

