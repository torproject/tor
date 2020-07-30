


HTML= \
	00-overview.html \
	01-common-utils.html \
	01a-memory.html \
	01b-collections.html \
	01c-time.html \
	01d-crypto.html \
	01e-os-compat.html \
	01f-threads.html \
	01g-strings.html \
	02-dataflow.html \
	03-modules.html \
	this-not-that.html

PNG = \
	diagrams/02/02-dataflow.png \
	diagrams/02/02-connection-types.png

all: generated

generated: $(HTML) $(PNG)

%.html: %.md
	maruku $< -o $@

%.png: %.dia
	dia $< --export=$@

clean:
	rm -f $(HTML)
	rm -f $(PNG)
