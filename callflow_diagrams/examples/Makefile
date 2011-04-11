XSLTPROC ?= xsltproc
FLAGS ?= --xinclude
TEMPLATE ?= ../cf.xsl
DPI ?= 72

SRCS := $(wildcard *.xml)
PNGS := $(patsubst %.xml,%.png,$(SRCS))
SVGS := $(patsubst %.xml,%.svg,$(SRCS))

all:	$(SVGS) $(PNGS)

%.svg:	%.xml Makefile $(TEMPLATE)
		$(XSLTPROC) $(FLAGS) -o $@ $(TEMPLATE) $<

%.png:	%.svg
		@echo "$< -> $@"
		@../svg2png "$<" "$@"

.PHONY:	clean

clean:	
		rm -f *.png *.svg
