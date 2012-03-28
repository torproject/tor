# We use a two-step process to generate documentation from asciidoc files.
#
# First, we use asciidoc/a2x to process the asciidoc files into .1.in and
# .html.in files (see the asciidoc-helper.sh script). These are the same as
# the regular .1 and .html files, except that they still have some autoconf
# variables set in them.
#
# Second, we use config.status to turn .1.in files into .1 files and
# .html.in files into .html files.
#
# We do the steps in this order so that we can ship the .*.in files as
# part of the source distribution, so that people without asciidoc can
# just use the .1 and .html files.

regular_mans = tor tor-gencert tor-resolve torify
all_mans = $(regular_mans) tor-fw-helper

if USE_ASCIIDOC
if USE_FW_HELPER
nodist_man_MANS = $(all_mans:=.1)
doc_DATA = $(all_mans:=.html)
else
nodist_man_MANS = $(regular_mans:=.1)
doc_DATA = $(regular_mans:=.html)
endif
html_in = $(all_mans:=.html.in)
man_in = $(all_mans:=.1.in)
txt_in = $(all_mans:=.1.txt)
else
html_in =
man_in =
txt_in =
nodist_man_MANS =
doc_DATA =
endif

EXTRA_DIST = HACKING asciidoc-helper.sh                      \
             $(html_in) $(man_in) $(txt_in)                  \
             tor-rpm-creation.txt                            \
             tor-win32-mingw-creation.txt spec/README        \
             state-contents.txt

docdir = @docdir@

asciidoc_product = $(nodist_man_MANS) $(doc_DATA)

# Generate the html documentation from asciidoc, but don't do
# machine-specific replacements yet
$(html_in) :
	$(top_srcdir)/doc/asciidoc-helper.sh html @ASCIIDOC@ $(top_srcdir)/doc/$@

tor.html.in : tor.1.txt
torify.html.in : torify.1.txt
tor-gencert.html.in : tor-gencert.1.txt
tor-resolve.html.in : tor-resolve.1.txt
tor-fw-helper.html.in : tor-fw-helper.1.txt

# Generate the manpage from asciidoc, but don't do
# machine-specific replacements yet
$(man_in) :
	$(top_srcdir)/doc/asciidoc-helper.sh man @A2X@ $(top_srcdir)/doc/$@

tor.1.in : tor.1.txt
torify.1.in : torify.1.txt
tor-gencert.1.in : tor-gencert.1.txt
tor-resolve.1.in : tor-resolve.1.txt
tor-fw-helper.1.in : tor-fw-helper.1.txt

# use ../config.status to swap all machine-specific magic strings
# in the asciidoc with their replacements.
$(asciidoc_product) :
	if test -e $(top_srcdir)/doc/$@.in && ! test -e ./$@.in ; then \
		cp $(top_srcdir)/doc/$@.in .; \
	fi
	../config.status --file=$@;

tor.1 : tor.1.in
torify.1 : torify.1.in
tor-gencert.1 : tor-gencert.1.in
tor-resolve.1 : tor-resolve.1.in
tor-fw-helper.1 : tor-fw-helper.1.in
tor.html : tor.html.in
torify.html : torify.html.in
tor-gencert.html : tor-gencert.html.in
tor-resolve.html : tor-resolve.html.in
tor-fw-helper.html : tor-fw-helper.html.in

CLEANFILES = $(asciidoc_product) config.log
DISTCLEANFILES = $(html_in) $(man_in)
