#!/usr/bin/env bash
# ChimangoScan -- minimal end-to-end test (the artifact's reproducibility claim).
#
# CLAIM: the ChimangoScan pipeline runs end to end -- discovery on Docker Hub,
# prioritisation, and a multi-scanner sweep -- producing a consolidated report.
#
# This script validates that claim quickly, without crawling the whole of
# Docker Hub. It:
#
#   1. crawls Docker Hub for a SHORT time, restricted to a few namespace
#      prefixes (default: a,b,c) -- Stage I, but tiny;
#   2. builds the IDEA layer graph for the repositories discovered  -- Stage II;
#   3. runs the exposure ranker, which sorts every repository by pull count and
#      supply-chain exposure                                        -- ranker;
#   4. seeds the scan queue with ONLY the top 10 most-pulled repositories and
#      runs the six default scanners over them                      -- Stage III;
#   5. asserts that the corpus report and analysis were produced.
#
# Expected wall time: roughly 20-45 min on a workstation (dominated by the
# image pulls and scans of the 10 targets). It exercises every component and
# every stage boundary of the full pipeline.
#
# Usage: orchestration/minimal_test.sh [--prefixes a,b,c] [--crawl-duration 5m]
#                                      [--top N]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DITECTOR="$ROOT/stages/DITector"
SCANNERS="$ROOT/stages/scanners"
ARTIFACTS="$ROOT/artifacts"
RANKED="$ARTIFACTS/exposure_ranked.jsonl"
TOPN="$ARTIFACTS/exposure_ranked.top.jsonl"
# shellcheck source=orchestration/_runner.sh
source "$ROOT/orchestration/_runner.sh"

PREFIXES="a,b,c"
CRAWL_DURATION="5m"
TOP=10

while [ $# -gt 0 ]; do
  case "$1" in
    --prefixes)        PREFIXES="$2"; shift 2 ;;
    --crawl-duration)  CRAWL_DURATION="$2"; shift 2 ;;
    --top)             TOP="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log()  { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }
fail() { echo "MINIMAL TEST FAILED: $*" >&2; exit 1; }

mkdir -p "$ARTIFACTS"

[ -e "$DITECTOR/main.go" ] || fail "submodules not initialised -- run: git submodule update --init --recursive"
[ -e "$DITECTOR/accounts.json" ] || fail "stages/DITector/accounts.json missing (Docker Hub accounts needed for the crawl)"

# Build the runner image once; every stage runs inside it so the host needs
# only Docker. MongoDB and Neo4j are reached over the host network.
ensure_runner

# ---------------------------------------------------------------------------
# 1. Stage I -- short crawl restricted to a few namespace prefixes
# ---------------------------------------------------------------------------
log "Stage I -- crawling Docker Hub prefixes [$PREFIXES] for $CRAWL_DURATION"
RUNNER_WORKDIR="$DITECTOR" in_runner sh -c \
  "timeout $CRAWL_DURATION go run main.go crawl --workers 8 --seed $PREFIXES --accounts accounts.json --config config.yaml" \
  || true   # the timeout ending the crawl is expected

# ---------------------------------------------------------------------------
# 2. Stage II -- build the IDEA graph for everything discovered (threshold 0)
# ---------------------------------------------------------------------------
log "Stage II -- building the IDEA dependency graph"
RUNNER_WORKDIR="$DITECTOR" in_runner go run main.go build \
    --format mongo \
    --threshold 0 \
    --tags 3 \
    --accounts accounts.json \
    --data_dir "$ARTIFACTS/build" \
    --config config.yaml

# ---------------------------------------------------------------------------
# 3. Ranker -- sort repositories by pull count + supply-chain exposure
# ---------------------------------------------------------------------------
log "Ranker -- computing exposure ranking"
RUNNER_WORKDIR="$DITECTOR" in_runner sh -c \
  "OUT_PATH=$RANKED WORKDIR=$ARTIFACTS/exposure_work python3 scripts/compute_exposure_ranking.py"

[ -s "$RANKED" ] || fail "ranker produced no exposure_ranked.jsonl"

# Keep only the TOP-N most-exposed repositories. The ranker already writes the
# file sorted by exposure descending, so the first N lines are the top N.
head -n "$TOP" "$RANKED" > "$TOPN"
N="$(wc -l < "$TOPN")"
[ "$N" -gt 0 ] || fail "top-$TOP selection is empty"
log "selected top $N repositories by exposure"

# ---------------------------------------------------------------------------
# 4. Stage III -- scan the top-N with the six default scanners
# ---------------------------------------------------------------------------
SCAN_CONFIG="$ARTIFACTS/scanners-minimal.yaml"
"$ROOT/orchestration/make_scanners_config.sh" "$TOPN" "$TOP" > "$SCAN_CONFIG"

# Stage III runs the scanner orchestrator inside the runner; it starts the six
# scanner containers through the mounted host Docker socket (siblings on the
# host daemon). TMPDIR is pinned under the mounted artifacts directory so any
# image tar the orchestrator exports is on a host path the sibling containers
# can mount.
mkdir -p "$ARTIFACTS/tmp"
SCAN_ENV="TMPDIR=$ARTIFACTS/tmp"

log "Stage III -- seeding the scan queue with the top $TOP targets"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG seed"

log "Stage III -- running the six-scanner sweep over the top $TOP"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG run --workers 4"

log "Stage III -- consolidating the corpus report"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG report -o $ARTIFACTS/report.html"
RUNNER_WORKDIR="$SCANNERS" in_runner sh -c "$SCAN_ENV uv run scanners -c $SCAN_CONFIG analyze"

# ---------------------------------------------------------------------------
# 5. Assertions -- the claim holds only if the corpus artefacts exist
# ---------------------------------------------------------------------------
[ -s "$ARTIFACTS/report.html" ]                  || fail "corpus report.html not produced"
[ -s "$ARTIFACTS/out/_corpus/summary.json" ]     || fail "corpus summary.json not produced"
[ -s "$ARTIFACTS/out/_corpus/analysis.md" ]      || fail "corpus analysis.md not produced"

log "MINIMAL TEST PASSED -- pipeline ran end to end over the top $TOP repositories"
echo "  ranking : $RANKED"
echo "  report  : $ARTIFACTS/report.html"
echo "  corpus  : $ARTIFACTS/out/_corpus/"
