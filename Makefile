# AnonymousSystem -- reproduction Makefile.
#
# Two reproduction modes (see README.md, section "Reproduction"):
#
#   make precomputed   regenerate every paper figure + table value from the
#                      shipped precomputed data (analysis/data/). No database,
#                      no network, no credentials, no Docker -- just Python and
#                      the two libraries in requirements.txt.
#
#   make full          run the real pipeline end to end at a small scale (one
#                      laptop + Docker). Set SCALE / PREFIXES / CRAWL_DURATION
#                      to change it, e.g.  make full SCALE=25
#
# Helpers:  make venv   (create .venv and install requirements.txt)
#           make clean  (remove generated figures/ and artifacts/)

PYTHON ?= python3
VENV    = .venv
VENV_PY = $(VENV)/bin/python

# Pass-through knobs for the full pipeline.
SCALE          ?= 10
PREFIXES       ?= a,b,c
CRAWL_DURATION ?= 5m

.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "AnonymousSystem reproduction targets:"
	@echo "  make precomputed   figures + table values from shipped data (no DB/network/Docker)"
	@echo "  make full          run the real pipeline end to end (Docker; SCALE=$(SCALE))"
	@echo "  make venv          create $(VENV) and install requirements.txt"
	@echo "  make clean         remove generated figures/ and artifacts/"

# Create a virtualenv with the pinned figure/table dependencies.
.PHONY: venv
venv: $(VENV_PY)
$(VENV_PY):
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r requirements.txt

# Precomputed reproduction. Uses .venv automatically if present (reproduce.sh
# picks it up), otherwise falls back to $(PYTHON); depends on venv so a bare
# `make precomputed` is self-contained.
.PHONY: precomputed
precomputed: venv
	PYTHON=$(VENV_PY) ./reproduce.sh precomputed

# Full pipeline end to end at the configured scale (Docker required).
.PHONY: full
full:
	./reproduce.sh full --scale $(SCALE) --prefixes $(PREFIXES) --crawl-duration $(CRAWL_DURATION)

.PHONY: clean
clean:
	rm -rf figures artifacts
