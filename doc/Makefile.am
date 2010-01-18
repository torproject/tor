asciidoc_files = tor-gencert

html_in = $(asciidoc_files:=.html.in)

man_in = $(asciidoc_files:=.1.in)

EXTRA_DIST = HACKING                                         \
             tor-resolve.1 tor-gencert.1                     \
             $(html_in) $(man_in) $(asciidoc_files:=.1.txt)  \
             tor-osx-dmg-creation.txt tor-rpm-creation.txt   \
             tor-win32-mingw-creation.txt torify.1

nodist_man_MANS = tor.1 tor-resolve.1 tor-gencert.1 torify.1 $(asciidoc_files:=.1)

doc_DATA = $(asciidoc_files:=.html)

asciidoc_product = $(nodist_man_MANS) $(doc_DATA)

SUBDIRS = design-paper spec

DIST_SUBDIRS = design-paper spec

# Generate the html documentation from asciidoc, but don't do
# machine-specific replacements yet
$(html_in) :
	$(top_srcdir)/doc/asciidoc-helper.sh html @ASCIIDOC@ @SED@ $@

# Generate the manpage from asciidoc, but don't do
# machine-specific replacements yet
$(man_in) :
	$(top_srcdir)/doc/asciidoc-helper.sh man @A2X@ @SED@ $@

# use ../config.status to swap all machine-specific magic strings
# in the asciidoc with their replacements.
$(asciidoc_product) :
	../config.status --file=$@;
