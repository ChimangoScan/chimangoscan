#!/usr/bin/env bash
# ChimangoScan -- end-to-end pipeline orchestrator.
#
# Runs the two stages of the Docker Hub security measurement in order:
#
#   Stage I+II + ranker  (stages/DITector)  -> exposure_ranked.jsonl
#   Stage III scan       (stages/scanners)  -> out/_corpus/{report.html,analysis.md}
#
# The single artefact that crosses the stage boundary is exposure_ranked.jsonl:
# DITector produces it, scanners consumes it via `scanners seed`.
#
# This is the FULL run. For a quick end-to-end sanity check that does not crawl
# the whole of Docker Hub, use orchestration/minimal_test.sh instead.
#
# Usage:
#   orchestration/run_pipeline.sh [--seed SEED] [--crawl-duration DUR]
#                                 [--threshold N] [--workers N] [--skip-crawl]
#
# Prerequisites (see README.md): Go 1.21+, Python 3.10+, Docker, MongoDB and
# Neo4j reachable, and Docker Hub accounts.json placed in stages/DITector/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DITECTOR="$ROOT/stages/DITector"
SCANNERS="$ROOT/stages/scanners"
ARTIFACTS="$ROOT/artifacts"
RANKED="$ARTIFACTS/exposure_ranked.jsonl"
# shellcheck source=orchestration/_runner.sh
source "$ROOT/orchestration/_runner.sh"

SEED=""
CRAWL_DURATION="6h"
THRESHOLD=1000
WORKERS=20
SKIP_CRAWL=0

while [ $# -gt 0 ]; do
  case "$1" in
    --seed)            SEED="$2"; shift 2 ;;
    --crawl-duration)  CRAWL_DURATION="$2"; shift 2 ;;
    --threshold)       THRESHOLD="$2"; shift 2 ;;
    --workers)         WORKERS="$2"; shift 2 ;;
    --skip-crawl)      SKIP_CRAWL=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log() { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }

mkdir -p "$ARTIFACTS"

if [ ! -e "$DITECTOR/main.go" ]; then
  echo "submodules not initialised -- run: git submodule update --init --recursive" >&2
  exit 1
fi

# Build the runner image once; every stage runs inside it so the host needs
# only Docker. MongoDB and Neo4j are reached over the host network.
ensure_runner

# ---------------------------------------------------------------------------
# Stage I -- crawl Docker Hub (discovery)
# ---------------------------------------------------------------------------
if [ "$SKIP_CRAWL" -eq 0 ]; then
  log "Stage I -- crawling Docker Hub (duration=$CRAWL_DURATION, workers=$WORKERS)"
  RUNNER_WORKDIR="$DITECTOR" in_runner sh -c \
    "timeout $CRAWL_DURATION go run main.go crawl --workers $WORKERS ${SEED:+--seed $SEED} --accounts accounts.json --config config.yaml" \
    || true   # timeout terminating the crawl is expected
else
  log "Stage I -- skipped (--skip-crawl); using repositories already in MongoDB"
fi

# ---------------------------------------------------------------------------
# Stage II -- build the IDEA layer graph
# ---------------------------------------------------------------------------
log "Stage II -- building the IDEA dependency graph (threshold=$THRESHOLD)"
RUNNER_WORKDIR="$DITECTOR" in_runner go run main.go build \
    --format mongo \
    --threshold "$THRESHOLD" \
    --tags 3 \
    --accounts accounts.json \
    --data_dir "$ARTIFACTS/build" \
    --config config.yaml

# ---------------------------------------------------------------------------
# Ranker -- compute exposure ranking -> exposure_ranked.jsonl
# ---------------------------------------------------------------------------
log "Ranker -- computing exposure ranking"
RUNNER_WORKDIR="$DITECTOR" in_runner sh -c \
  "OUT_PATH=$RANKED WORKDIR=$ARTIFACTS/exposure_work python3 scripts/compute_exposure_ranking.py"

if [ ! -s "$RANKED" ]; then
  echo "ranker produced no output: $RANKED" >&2
  exit 1
fi
log "exposure_ranked.jsonl ready -- $(wc -l < "$RANKED") repositories"

# ---------------------------------------------------------------------------
# Stage III -- multi-scanner sweep over the prioritised targets
# ---------------------------------------------------------------------------
# scanners reads its targets from the `source.path` of a run config. Generate a
# config that points at the exposure_ranked.jsonl this run just produced.
SCAN_CONFIG="$ARTIFACTS/scanners-run.yaml"
"$ROOT/orchestration/make_scanners_config.sh" "$RANKED" 0 > "$SCAN_CONFIG"

# Stage III runs the scanner orchestrator inside the runner; it starts the six
# scanner containers through the mounted host Docker socket (siblings on the
# host daemon). TMPDIR is pinned under the mounted artifacts directory so any
# image tar the orchestrator exports is on a host path the sibling containers
# can mount.
mkdir -p "$ARTIFACTS/tmp"
SCAN_ENV="TMPDIR=$ARTIFACTS/tmp"

log "Stage III -- seeding the scan queue from exposure_ranked.jsonl"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG seed"

log "Stage III -- running the six-scanner sweep"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG run --workers $WORKERS"

log "Stage III -- consolidating the corpus report"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG report -o $ARTIFACTS/report.html"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG analyze"

log "pipeline complete -- artefacts under $ARTIFACTS/"
