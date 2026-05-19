#!/usr/bin/env bash
# ChimangoScan -- regenerate every analysis JSON, figure and table value of the
# Docker Hub measurement paper from a scan-results SQLite database.
#
# This wraps analysis/scripts/regenerate_all.py: one read-only streaming pass
# over the database recomputes all per-repository aggregates, then the figure
# scripts and table-value emitter run. main.tex and the paper PDF are NOT in
# this repository (they live in a separate private paper repo); this stage
# produces only the data, figures/ and table_values.json.
#
# Usage: orchestration/run_analysis.sh --db PATH [--stage analysis|figures|tables|all]
#                                      [--sample N]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/analysis/scripts"
SEED="$ROOT/analysis/seed-inputs"
OUT="$ROOT/artifacts/analysis"

DB=""
STAGE="all"
SAMPLE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --db)      DB="$2"; shift 2 ;;
    --stage)   STAGE="$2"; shift 2 ;;
    --sample)  SAMPLE="$2"; shift 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$DB" ] || { echo "usage: run_analysis.sh --db PATH [--stage S] [--sample N]" >&2; exit 2; }
[ -s "$DB" ] || { echo "database not found: $DB" >&2; exit 1; }

mkdir -p "$OUT"

# regenerate_all.py reuses inputs that are NOT recomputed from the database
# (the OSV severity backfill, the crawl-wide CDF exported from MongoDB, and the
# per-scanner template). Seed them into the output directory before the run.
cp -n "$SEED/"*.json "$OUT/" 2>/dev/null || true

echo "=== regenerating analysis from $DB (stage=$STAGE) ==="
python3 "$SCRIPTS/regenerate_all.py" \
  --db "$DB" \
  --out "$OUT" \
  --stage "$STAGE" \
  ${SAMPLE:+--sample "$SAMPLE"}

echo "=== analysis artefacts written to $OUT/ ==="
