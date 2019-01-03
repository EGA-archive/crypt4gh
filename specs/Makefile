SOURCES := main.tex $(wildcard sections/*.tex) abstract.tex settings.tex


#CURRDIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
#BUILD := $(CURRDIR)build
#CURRDIR := $(dir $(lastword $(MAKEFILE_LIST)))
BUILD := _build

LATEX := pdflatex --shell-escape
BIBTEX := bibtex -terse

ERROR ?= no 
ifeq ($(ERROR),yes)
FLAGS?=-interaction=errorstopmode -file-line-error -halt-on-error
REDIRECT?=
else
FLAGS?=-interaction=batchmode
REDIRECT?= > /dev/null
endif

VERSION=$(shell git rev-parse --short HEAD)

.SUFFIXES: .pdf .tex .bbl .txt .bb .map .enc .ttf .vf .tfm
.PHONY: all force web bib

## ==== PDF ==================================================
all: $(BUILD)/main.pdf

e:
	@make ERROR=yes

$(BUILD)/%.pdf: %.tex $(SOURCES)
	@echo "Compiling $*"
	@mkdir -p $(@D)
	@$(LATEX) $(FLAGS) -output-directory=$(BUILD) $< $(REDIRECT)
#	@while grep -q 'Rerun to get [a-z-]* right' $(<:%.tex=$(BUILD)/%.log); do $(LATEX) $(FLAGS) -output-directory=$(BUILD) $< $(REDIRECT) || exit; done

force: main.tex $(SOURCES)
	@echo "Compiling main.tex [forcing]"
	@mkdir -p $(@D)
	@$(LATEX) $(FLAGS) -output-directory=$(BUILD) $< $(REDIRECT)

final: main.tex $(BUILD)/main.bbl $(SOURCES)
	@mkdir -p $(BUILD)
	@echo "Second compilation"
	@$(LATEX) $(FLAGS) -output-directory=$(BUILD) $< $(REDIRECT)
	@echo "Final compilation"
	@$(LATEX) $(FLAGS) -output-directory=$(BUILD) $< $(REDIRECT)


## ==== Bibtex ==================================================
$(BUILD)/main.bbl: references.bib $(BUILD)/main.aux
	@echo "Compiling the bibliography for $*"
	@bibtex -terse $(BUILD)/main || true
$(BUILD)/main.aux: $(BUILD)/main.pdf
bib: $(BUILD)/main.bbl

## ==== Web ==================================================
#BIBHVA=bibhva
web: $(BUILD)/index.html

$(BUILD)/index.html: main.tex
	hevea -o $@ $<

## ==== Cleaning ==================================================
cleantilde:
	@find . -type f -iname '*~' -exec  rm {} \;

clean: cleantilde
	@rm -rf $(BUILD)/main.*

cleanall: cleantilde
	@rm -rf $(BUILD)



img: $(BUILD)/pic.pdf

$(BUILD)/pic.tex: pic.tex
	@echo "\documentclass[10pt]{article}\input{settings}\\\\begin{document}" > $@
	@cat $^ >> $@
	@echo "\\end{document}" >> $@

$(BUILD)/pic.pdf: $(BUILD)/pic.tex
	@pdflatex -interaction=errorstopmode -file-line-error -halt-on-error -output-directory=$(BUILD) $<
