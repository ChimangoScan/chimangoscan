# Convenience wrappers around `uv run scanners ...`. Override CONFIG=... if your
# run config lives elsewhere (default: config/config.yaml if present).
SCAN := uv run scanners

.PHONY: help sync config test seed run status report analyze coordinator cluster-up cluster-down clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk -F':.*?## ' '{printf "  %-14s %s\n", $$1, $$2}'

sync: ## install the project + dev deps
	uv sync --extra dev

config: ## create config/config.yaml from the example (won't overwrite)
	@test -f config/config.yaml || cp config/config.example.yaml config/config.yaml; \
	 echo "config/config.yaml ready — edit source.path"

test: ## run the test suite
	uv run pytest

seed: ## load targets from the configured source into the queue
	$(SCAN) seed

run: ## drain the queue on this machine (WORKERS=4 K=4 ONLY=trivy,grype)
	$(SCAN) run $(if $(WORKERS),--workers $(WORKERS)) $(if $(K),--scan-parallelism $(K)) $(if $(ONLY),--only $(ONLY))

status: ## queue progress
	$(SCAN) status

report: ## rebuild aggregates + render report.html
	$(SCAN) report

analyze: ## cross-scanner stats -> out/_corpus/analysis.md
	$(SCAN) analyze

coordinator: ## serve the work queue over HTTP (for many workers)
	$(SCAN) coordinator

cluster-up: ## rsync + start workers on the configured remote hosts
	$(SCAN) cluster up

cluster-down: ## stop remote workers + tear down tunnels
	$(SCAN) cluster down

clean: ## remove runtime state (queue, output, caches) — keeps config and code
	rm -rf work out cache *.db *.db-* runs
