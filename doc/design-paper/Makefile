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