#!/usr/bin/env bash
# AnonymousSystem -- one-command reproduction driver.
#
# Two modes, selected by the first argument:
#
#   ./reproduce.sh precomputed
#       Regenerate EVERY paper figure and table value from the small
#       precomputed data shipped in analysis/data/. No database, no network,
#       no credentials, no Docker. Needs only Python 3 and the two libraries
#       in requirements.txt (matplotlib, numpy). Outputs land in figures/:
#       the twelve fig_*.pdf and table_values.json. This is the path a
#       reviewer runs in a few seconds to confirm the paper's plots and table
#       numbers come straight out of the shipped data.
#
#   ./reproduce.sh full [--scale N] [options...]
#       Run the REAL pipeline end to end at a configurable scale -- Stage I
#       (crawl Docker Hub) -> Stage II (layer graph) -> exposure ranker ->
#       Stage III (six-scanner scan) -> consolidated report. The host needs
#       only Docker; every stage runs inside the containerized runner image
#       (docker/Dockerfile.runner). Scale and targets come from flags/config;
#       there is no hardcoded infrastructure. The default scale is small
#       (a few repositories, one laptop + Docker). Full-scale reproduction of
#       the paper (52,895 images) needs the authors' multi-machine setup and
#       runs for months -- see README.md, section "Reproduction".
#
# Usage:
#   ./reproduce.sh precomputed
#   ./reproduce.sh full [--scale N] [--prefixes a,b,c] [--crawl-duration 5m]
#   ./reproduce.sh help
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIGURES="$ROOT/figures"
DATA="$ROOT/analysis/data"
SCRIPTS="$ROOT/analysis/scripts"

log() { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }
die() { echo "reproduce.sh: $*" >&2; exit 1; }

usage() {
  sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; s/^#$//'
}

# ---------------------------------------------------------------------------
# PRECOMPUTED -- figures + tables from shipped data, no DB / network / Docker
# ---------------------------------------------------------------------------
reproduce_precomputed() {
  log "PRECOMPUTED reproduction -- figures + tables from analysis/data/"

  # Pick a Python: prefer an explicit venv, then $PYTHON, then python3.
  PY="${PYTHON:-}"
  if [ -z "$PY" ] && [ -x "$ROOT/.venv/bin/python" ]; then PY="$ROOT/.venv/bin/python"; fi
  if [ -z "$PY" ]; then PY="python3"; fi
  command -v "$PY" >/dev/null 2>&1 || die "python not found (set \$PYTHON or create .venv)"

  # Verify the two required libraries are importable; point the reviewer at
  # requirements.txt if they are not (we do NOT install silently).
  if ! "$PY" - <<'PYEOF' 2>/dev/null
import matplotlib, numpy  # noqa: F401
PYEOF
  then
    cat >&2 <<EOF
reproduce.sh: matplotlib / numpy not importable with: $PY

Install the pinned dependencies first, e.g.:

    python3 -m venv .venv
    . .venv/bin/activate
    pip install -r requirements.txt
    ./reproduce.sh precomputed

(or set \$PYTHON to an interpreter that already has them).
EOF
    exit 1
  fi

  # Stage the precomputed inputs into a scratch run directory. regenerate_all.py
  # writes figures into <out>/figures and table_values.json into <out>; we then
  # surface both at the top-level figures/ directory.
  WORK="$ROOT/artifacts/precomputed"
  rm -rf "$WORK"; mkdir -p "$WORK"
  cp "$DATA"/*.json "$WORK/"
  cp "$DATA"/recount_repo.log "$WORK/"   # carries the distinct-digest count

  export MPLBACKEND=Agg MPLCONFIGDIR="$WORK/.mpl"

  # Stage 2 (figures) and stage 3 (tables) of the regeneration pipeline read
  # only those JSONs -- they never open the database (stage 1 / analysis does).
  log "regenerating figures (stage: figures)"
  "$PY" "$SCRIPTS/regenerate_all.py" --stage figures --out "$WORK" --db /dev/null

  log "regenerating table values (stage: tables)"
  "$PY" "$SCRIPTS/regenerate_all.py" --stage tables --out "$WORK" --db /dev/null

  # Publish results at the top-level figures/ directory.
  mkdir -p "$FIGURES"
  cp "$WORK"/figures/*.pdf "$FIGURES/"
  cp "$WORK"/table_values.json "$FIGURES/"

  log "PRECOMPUTED reproduction complete"
  echo "  figures      : $FIGURES/  ($(ls -1 "$FIGURES"/*.pdf | wc -l) PDFs)"
  echo "  table values : $FIGURES/table_values.json"
}

# ---------------------------------------------------------------------------
# FULL -- the real pipeline end to end, at a configurable scale
# ---------------------------------------------------------------------------
reproduce_full() {
  # Defaults: a SMALL scale that runs on one laptop + Docker. Everything is
  # configurable; nothing about the authors' infrastructure is baked in.
  local SCALE=10               # number of top-exposure repositories to scan
  local PREFIXES="a,b,c"       # Docker Hub namespace prefixes to crawl
  local CRAWL_DURATION="5m"    # how long Stage I crawls
  local -a PASSTHRU=()

  while [ $# -gt 0 ]; do
    case "$1" in
      --scale)           SCALE="$2"; shift 2 ;;
      --prefixes)        PREFIXES="$2"; shift 2 ;;
      --crawl-duration)  CRAWL_DURATION="$2"; shift 2 ;;
      *) PASSTHRU+=("$1"); shift ;;
    esac
  done

  command -v docker >/dev/null 2>&1 || die "Docker is required for the full pipeline (see README.md)"

  log "FULL reproduction -- scale=$SCALE repositories, prefixes=[$PREFIXES], crawl=$CRAWL_DURATION"
  cat <<EOF
This runs the real pipeline end to end inside the containerized runner:
  Stage I  (crawl)   -> Stage II (layer graph) -> exposure ranker -> Stage III (scan)
The host needs only Docker; provide Docker Hub accounts in
stages/DITector/accounts.json (see README.md, "Security concerns").

Reproducing the paper at full scale (52,895 images) needs the authors'
multi-machine setup and runs for months. This command reproduces the SAME
pipeline at the requested scale.
EOF

  # Delegate to the orchestration driver, which builds the runner image on
  # first use and runs every stage inside it. The small-scale end-to-end run
  # is exactly the minimal test; --scale maps to its top-N selection.
  exec "$ROOT/orchestration/minimal_test.sh" \
    --prefixes "$PREFIXES" \
    --crawl-duration "$CRAWL_DURATION" \
    --top "$SCALE" \
    "${PASSTHRU[@]}"
}

# ---------------------------------------------------------------------------
MODE="${1:-}"
case "$MODE" in
  precomputed) shift; reproduce_precomputed "$@" ;;
  full)        shift; reproduce_full "$@" ;;
  ""|-h|--help|help) usage ;;
  *) die "unknown mode '$MODE' (expected: precomputed | full | help)" ;;
esac
