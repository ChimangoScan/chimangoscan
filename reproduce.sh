#!/usr/bin/env bash
# ChimangoScan -- one-command reproduction driver.
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
#   ./reproduce.sh analysis --dataset DIR [--stage mongo|neo4j|sqlite|verify|all]
#       Recompute EVERY paper number and figure from the released dataset
#       (the real databases: SQLite scan reports, MongoDB crawl, Neo4j layer
#       graph), one database at a time, then verify the recomputed values
#       against the paper's published numbers (exact match required). Each
#       stage runs standalone so the ~300 GB dataset can be validated
#       incrementally; results and the verification report land in
#       artifacts/analysis/ and docs/REPRODUCIBILITY_REPORT.md.
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

  # Stage the precomputed inputs into a scratch run directory. regenerate_all.py
  # writes figures into <out>/figures and table_values.json into <out>; both live
  # under the repo, so they land on the host whether we run natively or in Docker.
  WORK="$ROOT/artifacts/precomputed"
  # Clean the scratch dir; if a prior Docker-runner run left root-owned files,
  # remove them via a throwaway container (the reviewer has Docker).
  rm -rf "$WORK" 2>/dev/null || \
    docker run --rm -v "$ROOT/artifacts:/mnt" alpine rm -rf /mnt/precomputed 2>/dev/null || true
  mkdir -p "$WORK"
  cp "$DATA"/*.json "$WORK/"
  cp "$DATA"/recount_repo.log "$WORK/"   # carries the distinct-digest count

  # Choose an execution engine with matplotlib+numpy. Prefer a working host
  # interpreter (fast, no Docker); provision a local .venv if needed (never the
  # system Python -- PEP-668). If the host cannot provide them (e.g. a very new
  # host Python with no numpy wheel), fall back to the containerized runner,
  # which ships Python 3.12 + the libs -- so the reviewer needs only Docker.
  PY="${PYTHON:-}"
  [ -z "$PY" ] && [ -x "$ROOT/.venv/bin/python" ] && PY="$ROOT/.venv/bin/python"
  deps_ok() { [ -n "$PY" ] && "$PY" -c 'import matplotlib, numpy' 2>/dev/null; }
  if ! deps_ok; then
    log "provisioning a local .venv (one-time)"
    rm -rf "$ROOT/.venv"
    if python3 -m venv "$ROOT/.venv" >/dev/null 2>&1 \
       && "$ROOT/.venv/bin/pip" install -q -r "$ROOT/requirements.txt" >/dev/null 2>&1; then
      PY="$ROOT/.venv/bin/python"
    else
      rm -rf "$ROOT/.venv"; PY=""
    fi
  fi

  if deps_ok; then
    regen() { MPLBACKEND=Agg MPLCONFIGDIR="$WORK/.mpl" \
              "$PY" "$SCRIPTS/regenerate_all.py" --stage "$1" --out "$WORK" --db /dev/null; }
  else
    log "host Python lacks matplotlib/numpy -- running in the container runner (Docker)"
    # shellcheck source=orchestration/_runner.sh
    source "$ROOT/orchestration/_runner.sh"
    ensure_runner
    # Write outputs as the invoking user so re-runs can clean them without sudo.
    regen() { RUNNER_USER="$(id -u):$(id -g)" RUNNER_WORKDIR="$ROOT" in_runner sh -c \
              "MPLBACKEND=Agg MPLCONFIGDIR='$WORK/.mpl' python3 '$SCRIPTS/regenerate_all.py' --stage $1 --out '$WORK' --db /dev/null"; }
  fi

  # Stage figures + table values (they read only the shipped JSONs, never a DB).
  log "regenerating figures";      regen figures
  log "regenerating table values"; regen tables

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
# ANALYSIS -- recompute every paper number and figure from the released dataset
# ---------------------------------------------------------------------------
# ./reproduce.sh analysis --dataset DIR [--stage mongo|neo4j|sqlite|verify|all]
#                         [--out DIR] [-- extra args passed to the stage driver]
#
# DIR must hold the released dataset files (any subset; each stage names what
# it needs): chimangoscan-reports.db[.zst], dockerhub_data_*.archive.gz,
# neo4j_data_*.tar.gz, exposure_ranked_v3.jsonl, tags_full.jsonl. Stages are
# independent so the ~300 GB dataset can be validated one database at a time;
# verify checks whatever stage outputs exist in --out and skips the rest.
reproduce_analysis() {
  local DATASET="" STAGE="all" OUT="$ROOT/artifacts/analysis" FETCH=0
  local -a EXTRA=()
  while [ $# -gt 0 ]; do
    case "$1" in
      --dataset) DATASET="$2"; shift 2 ;;
      --stage)   STAGE="$2"; shift 2 ;;
      --out)     OUT="$2"; shift 2 ;;
      --fetch)   FETCH=1; shift ;;
      --)        shift; EXTRA=("$@"); break ;;
      *) die "analysis: unknown option '$1'" ;;
    esac
  done
  [ -n "$DATASET" ] || die "analysis: --dataset DIR is required"
  if [ "$FETCH" = 1 ]; then
    log "fetching dataset into $DATASET (GitHub release, split assets)"
    "$ROOT/scripts/fetch_dataset.sh" --out "$DATASET" || die "analysis: dataset fetch failed"
  fi
  [ -d "$DATASET" ] || die "analysis: dataset dir not found: $DATASET (use --fetch to download it)"
  mkdir -p "$OUT"

  if [ -f "$DATASET/SHA256SUMS" ]; then
    log "verifying dataset checksums (SHA256SUMS)"
    (cd "$DATASET" && sha256sum -c --ignore-missing --quiet SHA256SUMS) \
      || die "analysis: dataset checksum verification failed"
  fi

  find_one() { find "$DATASET" -maxdepth 1 -name "$1" | sort | head -1; }
  # The exposure ranking and tags export are DERIVED artefacts: in a full
  # (`all`) run the mongo/neo4j stages recompute them into $OUT, so prefer that
  # freshly-computed copy; fall back to a shipped copy in the dataset dir.
  find_computed() { [ -f "$OUT/$1" ] && echo "$OUT/$1" || find_one "$1"; }
  local DB ARCHIVE DUMP
  DB="$(find_one 'chimangoscan-reports.db')"; [ -n "$DB" ] || DB="$(find_one 'chimangoscan-reports.db.zst')"
  ARCHIVE="$(find_one 'dockerhub_data*.archive.gz')"
  DUMP="$(find_one 'neo4j_data*.tar.gz')"
  local DUMPS_TAR; DUMPS_TAR="$(find_one 'exposure_work*.tar')"

  # Stage-II analysis (exposure ranking + downstream propagation) reproduces from
  # the FROZEN 2026-05-18 layer-graph dumps, NOT from a live Neo4j/Mongo snapshot.
  # The layer graph keeps growing after the paper freeze -- images keep attaching
  # to layers over time -- so a restored post-freeze Neo4j inflates the downstream
  # propagation table by ~50% (image-bearing nodes 4.48M at freeze vs ~6.3M later).
  # Seeding the frozen edges/toplayers/repo_pull/tags dumps into $OUT/exposure_work
  # makes compute_exposure_ranking.py and propagation_compute.py use them (their
  # dump steps skip when the files are already present), so the ranking and the
  # propagation table reproduce the paper EXACTLY. (graph_stats' raw node/edge
  # counts are still read live from the shipped Neo4j and drift a few %: there is
  # no frozen Neo4j store to restore, only these analysis dumps.)
  if { [ "$STAGE" = neo4j ] || [ "$STAGE" = all ]; } && [ -n "$DUMPS_TAR" ] \
       && [ ! -s "$OUT/exposure_work/edges.tsv.gz" ]; then
    log "seeding frozen Stage-II dumps: $(basename "$DUMPS_TAR") -> $OUT/exposure_work"
    mkdir -p "$OUT/exposure_work"
    tar -xf "$DUMPS_TAR" -C "$OUT/exposure_work" \
      || die "analysis: failed to extract frozen dumps from $DUMPS_TAR"
  fi

  # In a full `all` run the mongo container is kept up so the neo4j stage can
  # recompute the exposure ranking against the live crawl (--with-mongo); these
  # are empty for a single-stage run, where each stage is self-contained.
  local KEEP_MONGO="" MONGO_URI_ALL="" MONGO_PORT_ALL="${MONGO_PORT:-27100}"

  run_stage() {
    case "$1" in
      mongo)
        [ -n "$ARCHIVE" ] || die "analysis: no dockerhub_data*.archive.gz in $DATASET"
        "$ROOT/orchestration/analysis_mongo.sh" --archive "$ARCHIVE" --out "$OUT" \
          ${KEEP_MONGO:+--keep} "${EXTRA[@]}" ;;
      neo4j)
        [ -n "$DUMP" ] || die "analysis: no neo4j_data*.tar.gz in $DATASET"
        # --with-mongo enables the exposure ranking + corpus filter (needs the
        # crawl MongoDB, kept up by the mongo stage in an `all` run).
        "$ROOT/orchestration/analysis_neo4j.sh" --dump "$DUMP" --out "$OUT" \
          ${DB:+--sqlite "$DB"} ${MONGO_URI_ALL:+--with-mongo "$MONGO_URI_ALL"} "${EXTRA[@]}" ;;
      sqlite)
        [ -n "$DB" ] || die "analysis: no chimangoscan-reports.db[.zst] in $DATASET"
        local EXPOSURE TAGS FILTER
        EXPOSURE="$(find_computed exposure_ranked_v3.jsonl)"
        TAGS="$(find_computed tags_full.jsonl)"
        FILTER="$OUT/corpus_filter.txt"
        if [ ! -f "$FILTER" ] && [ -n "$EXPOSURE" ]; then
          EXPOSURE_JSONL="$EXPOSURE" OUT="$FILTER" python3 "$SCRIPTS/make_corpus_filter.py" \
            || die "analysis: corpus filter generation failed"
        fi
        [ -f "$FILTER" ] || FILTER=""
        "$ROOT/orchestration/analysis_sqlite.sh" --db "$DB" --out "$OUT" \
          ${FILTER:+--filter "$FILTER"} \
          ${EXPOSURE:+--exposure "$EXPOSURE"} ${TAGS:+--tags "$TAGS"} "${EXTRA[@]}" ;;
      verify)
        "$ROOT/.venv/bin/python" "$SCRIPTS/verify_values.py" --results "$OUT" \
          --report "$ROOT/docs/REPRODUCIBILITY_REPORT.md" 2>/dev/null \
          || python3 "$SCRIPTS/verify_values.py" --results "$OUT" \
               --report "$ROOT/docs/REPRODUCIBILITY_REPORT.md" ;;
      *) die "analysis: unknown stage '$1' (mongo|neo4j|sqlite|verify|all)" ;;
    esac
  }

  log "ANALYSIS reproduction -- dataset=$DATASET stage=$STAGE out=$OUT"
  if [ "$STAGE" = all ]; then
    # Keep the ephemeral crawl MongoDB up across the mongo->neo4j boundary so the
    # exposure ranking can be recomputed; tear both analysis DBs down at the end
    # (also on failure). neo4j leaves its own container up only with --keep, so
    # only the mongo one needs an explicit sweep here.
    KEEP_MONGO=1
    MONGO_URI_ALL="mongodb://127.0.0.1:$MONGO_PORT_ALL"
    cleanup_mongo() {
      docker rm -f chimangoscan-mongo-analysis >/dev/null 2>&1 || true
      docker volume rm chimangoscan-mongo-analysis-data >/dev/null 2>&1 || true
    }
    trap cleanup_mongo EXIT   # on set -e exit a RETURN trap would not fire; EXIT does
    run_stage mongo             # --keep: crawl MongoDB stays up for exposure ranking
    # Decompress the scan DB ONCE, before neo4j: its per-CVE step
    # (extract_cve_digests) opens the SQLite file directly and cannot read a
    # .zst, and the sqlite stage then reuses the same decompressed .db (so it is
    # expanded once, not twice). Decompress to $OUT/db -- exactly where the
    # sqlite stage would expand it -- so passing this .db path skips re-expansion.
    if [ -n "$DB" ] && [ "${DB%.zst}" != "$DB" ]; then
      local DECOMP="$OUT/db/$(basename "${DB%.zst}")"
      if [ ! -s "$DECOMP" ]; then
        command -v zstd >/dev/null || die "analysis: zstd required to decompress $DB"
        mkdir -p "$OUT/db"
        log "decompressing scan DB once -> $DECOMP (~150 GB, a few minutes)"
        zstd -d --long=31 -f -o "$DECOMP" "$DB" || die "analysis: scan DB decompression failed"
      fi
      DB="$DECOMP"                # neo4j --sqlite and sqlite --db both get the .db
    fi
    run_stage neo4j             # --with-mongo: exposure ranking + corpus filter + per-CVE digests
    # Reclaim disk before the long sqlite pass: the crawl MongoDB and the
    # extracted Neo4j store are no longer needed (their artefacts are in $OUT).
    cleanup_mongo
    # Neo4j wrote its store as root inside the container, so this user cannot rm
    # it; reclaim the ~62 GB via a root helper container (fall back to a plain rm).
    docker run --rm -v "$OUT:$OUT" alpine rm -rf "$OUT/neo4j_data" 2>/dev/null \
      || rm -rf "$OUT/neo4j_data" || true
    run_stage sqlite            # $DB is already the decompressed .db; no second expansion
    run_stage verify
  else
    run_stage "$STAGE"
  fi
}

# ---------------------------------------------------------------------------
MODE="${1:-}"
case "$MODE" in
  precomputed) shift; reproduce_precomputed "$@" ;;
  analysis)    shift; reproduce_analysis "$@" ;;
  full)        shift; reproduce_full "$@" ;;
  ""|-h|--help|help) usage ;;
  *) die "unknown mode '$MODE' (expected: precomputed | analysis | full | help)" ;;
esac
