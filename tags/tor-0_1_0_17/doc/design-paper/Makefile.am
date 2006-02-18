
cell-struct.eps: cell-struct.fig
	fig2dev -L eps $< $@
interaction.eps: interaction.fig
	fig2dev -L eps $< $@
cell-struct.pdf: cell-struct.fig
	fig2dev -L pdf $< $@
interaction.pdf: interaction.fig
	fig2dev -L pdf $< $@

tor-design.ps: cell-struct.eps interaction.eps tor-design.bib tor-design.tex usenix.sty latex8.bst
	latex tor-design.tex
	bibtex tor-design
	latex tor-design.tex
	latex tor-design.tex
	dvips -o $@ tor-design.dvi

tor-design.pdf: cell-struct.pdf interaction.pdf tor-design.bib tor-design.tex usenix.sty latex8.bst
	pdflatex tor-design.tex
	bibtex tor-design
	pdflatex tor-design.tex
	pdflatex tor-design.tex

EXTRA_DIST = cell-struct.fig interaction.fig tor-design.bib usenix.sty latex8.bst tor-design.tex

DISTCLEANFILES = cell-struct.eps interaction.eps cell-struct.pdf interaction.pdf tor-design.aux tor-design.bbl tor-design.blg tor-design.log tor-design.dvi tor-design.ps tor-design.pdf
