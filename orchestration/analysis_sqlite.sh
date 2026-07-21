#!/usr/bin/env bash
# AnonymousSystem -- SQLite analysis stage driver.
#
# Recomputes every analysis JSON, figure and table value of the Docker Hub
# measurement paper from a scan-results SQLite database (ditector-good.db), and
# runs the secret-detection ground-truth sampling/validation alongside it. Wraps
# analysis/scripts/regenerate_all.py and the two secret scripts, wiring the
# environment recount_repo.py reads (corpus filter, exposure-ranking override,
# temporal tags).
#
# Order: (a) analysis scan -> 11 JSONs, (b) secret_sample.py + validate_secrets.py,
#        (c) figures -> figures/*.pdf, (d) tables -> table_values.json.
#
# Usage:
#   orchestration/analysis_sqlite.sh --db PATH --out DIR
#       [--filter FILE] [--exposure FILE] [--tags FILE] [--sample N]
#
#   --db PATH        ditector-good.db, or a .zst that is decompressed first
#                    (~150 GB; a neighbouring PATH.sha256 is verified if present).
#   --out DIR        run/output directory for JSONs, figures/ and table_values.json.
#   --filter FILE    corpus filter (repo:tag per line) -> DITECTOR_FILTER_RT.
#                    Production used the top-60k list (52,895 kept).
#   --exposure FILE  exposure_ranked_v3.jsonl override -> DITECTOR_RANKING_V2
#                    (recount_repo.py's in-script default points at a stale v2).
#   --tags FILE      tags_full.jsonl for the temporal analysis -> DITECTOR_TAGS.
#   --sample N       cap the reports scan to N rows -- quick smoke pass only,
#                    NOT production numbers.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/analysis/scripts"
[ -x "$ROOT/.venv/bin/python3" ] && PATH="$ROOT/.venv/bin:$PATH"
SEED="$ROOT/analysis/seed-inputs"

# ~150 GB decompressed; require this much free space before expanding a .zst.
REQUIRED_BYTES=$((150 * 1024 * 1024 * 1024))

DB="" ; OUT="" ; FILTER="" ; EXPOSURE="" ; TAGS="" ; SAMPLE=""

usage() {
  echo "usage: analysis_sqlite.sh --db PATH --out DIR [--filter FILE]" \
       "[--exposure FILE] [--tags FILE] [--sample N]" >&2
  exit 2
}
die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --db)       DB="$2"; shift 2 ;;
    --out)      OUT="$2"; shift 2 ;;
    --filter)   FILTER="$2"; shift 2 ;;
    --exposure) EXPOSURE="$2"; shift 2 ;;
    --tags)     TAGS="$2"; shift 2 ;;
    --sample)   SAMPLE="$2"; shift 2 ;;
    -h|--help)  usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
[ -n "$DB" ] && [ -n "$OUT" ] || usage
[ -e "$DB" ] || die "database not found: $DB"

mkdir -p "$OUT"; OUT="$(realpath "$OUT")"

# --- database: accept a plain .db, or decompress a .zst into a scratch dir ---
if [ "${DB%.zst}" != "$DB" ]; then
  command -v zstd >/dev/null || die "zstd not installed (needed to decompress $DB)"
  DBDIR="$OUT/db"; mkdir -p "$DBDIR"
  TARGET="$DBDIR/$(basename "${DB%.zst}")"
  if [ -f "$DB.sha256" ]; then
    echo "=== verifying sha256 of $(basename "$DB") ==="
    want="$(awk '{print $1}' "$DB.sha256")"
    have="$(sha256sum "$DB" | awk '{print $1}')"
    [ "$want" = "$have" ] || die "sha256 mismatch on $DB (want $want, got $have)"
  fi
  if [ ! -s "$TARGET" ]; then
    avail="$(df -P -B1 "$DBDIR" | awk 'NR==2{print $4}')"
    [ "$avail" -ge "$REQUIRED_BYTES" ] || die \
      "insufficient space in $DBDIR: need ~150 GB, have $((avail/1024/1024/1024)) GB"
    echo "=== decompressing $(basename "$DB") -> $TARGET ==="
    zstd -d --long=31 -f -o "$TARGET" "$DB"
  fi
  DB="$TARGET"
fi
[ -s "$DB" ] || die "database not found or empty: $DB"
DB="$(realpath "$DB")"

# --- seed inputs regenerate_all.py reuses (NOT recomputed from the database) ---
# osv_severity_cache.json : OSV severity backfill (osv_step1..3 scripts)
# plan_crawl.json         : crawl-wide pull/dependency CDF exported from MongoDB (Stage I)
# step3_recompute.json    : per-scanner template (recount rewrites its .after only)
# Prefer a copy already in --out (e.g. plan_crawl.json freshly produced by the
# mongo stage); otherwise fall back to analysis/seed-inputs/.
for f in osv_severity_cache.json plan_crawl.json step3_recompute.json; do
  if [ ! -s "$OUT/$f" ]; then
    [ -s "$SEED/$f" ] || die "missing seed input $f -- expected in $OUT/ or $SEED/" \
      "(osv_severity_cache.json comes from the osv_step1..3 backfill;" \
      "plan_crawl.json is exported from MongoDB in Stage I;" \
      "step3_recompute.json ships in analysis/seed-inputs/)"
    cp "$SEED/$f" "$OUT/$f"
    echo "seeded $f from seed-inputs/"
  fi
done

# --- validate optional inputs and wire the environment recount_repo.py reads ---
export DITECTOR_DB="$DB"
if [ -n "$FILTER" ]; then
  [ -s "$FILTER" ] || die "corpus filter file not found: $FILTER"
  export DITECTOR_FILTER_RT="$(realpath "$FILTER")"
fi
if [ -n "$EXPOSURE" ]; then
  [ -s "$EXPOSURE" ] || die "exposure ranking file not found: $EXPOSURE"
  export DITECTOR_RANKING_V2="$(realpath "$EXPOSURE")"
fi
if [ -n "$TAGS" ]; then
  [ -s "$TAGS" ] || die "tags file not found: $TAGS"
  TAGS="$(realpath "$TAGS")"
  export DITECTOR_TAGS="$TAGS"
fi
[ -n "$SAMPLE" ] && export DITECTOR_SAMPLE="$SAMPLE" || true

regen() { python3 "$SCRIPTS/regenerate_all.py" --db "$DB" --out "$OUT" --stage "$1" \
            ${TAGS:+--tags "$TAGS"} ${SAMPLE:+--sample "$SAMPLE"}; }

echo "=== (a) analysis -- SQLite scan over $DB ==="
regen analysis

echo "=== (b) secret sampling + validation ==="
( cd "$OUT" && python3 "$SCRIPTS/secret_sample.py" \
             && python3 "$SCRIPTS/validate_secrets.py" )

echo "=== (c) figures ==="
regen figures

echo "=== (d) tables ==="
regen tables

echo "=== analysis stage complete -- outputs in $OUT/ ==="
