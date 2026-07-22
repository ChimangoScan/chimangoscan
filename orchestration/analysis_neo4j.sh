#!/usr/bin/env bash
# ChimangoScan -- Neo4j layer-graph analysis stage.
#
# Restores the released Neo4j data-directory archive into an EPHEMERAL Neo4j
# container, then recomputes the layer-graph results of the paper, in order:
#
#   graph_stats.json          node/edge/image-bearing counts   (always)
#   exposure_ranked_v3.jsonl  exposure ranking                 (needs --with-mongo)
#   corpus_filter.txt         top-N repo:tag corpus filter
#   cve_digests_v3.json       per-CVE affected digests         (needs --sqlite)
#   propagation_v3.json       per-CVE downstream propagation
#
# Steps whose inputs are missing are skipped with a message. Re-runs resume:
# the extracted data dir and the streamed graph dumps under --out are reused.
#
# Usage: orchestration/analysis_neo4j.sh --dump PATH --out DIR
#          [--with-mongo URI] [--sqlite PATH] [--keep]
#
#   --dump PATH       tar.gz or tar.zst of the Neo4j data/ directory
#   --out DIR         working/output directory (extraction, dumps, results)
#   --with-mongo URI  MongoDB with the crawl (dockerhub_data); enables the
#                     exposure ranking and everything derived from it
#   --sqlite PATH     scan-results SQLite (chimangoscan-reports.db); enables the
#                     CVE-digest extraction and propagation
#   --keep            leave the Neo4j container running on exit
#
# Env overrides: NEO4J_IMAGE (default neo4j:5 -- must match the major version
# that wrote the data dir), NEO4J_BOLT_ADDR (127.0.0.1:7688), NEO4J_WAIT_S
# (600), NEO4J_CONTAINER, NEO4J_HEAP, NEO4J_PAGECACHE (e.g. 8G),
# NEO4J_DATA_SUBDIR (path of the data dir inside the archive; auto-detected),
# TOP_N (60000).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/analysis/scripts"
[ -x "$ROOT/.venv/bin/python3" ] && PATH="$ROOT/.venv/bin:$PATH"
# shellcheck source=orchestration/_runner.sh
source "$ROOT/orchestration/_runner.sh"

NEO4J_IMAGE="${NEO4J_IMAGE:-neo4j:2026.03.1}"  # the released store was written by Neo4j 2026.03 (record format, but a CalVer kernel newer than 5.x can read)
NEO4J_BOLT_ADDR="${NEO4J_BOLT_ADDR:-127.0.0.1:7688}"
NEO4J_WAIT_S="${NEO4J_WAIT_S:-600}"
NEO4J_CONTAINER="${NEO4J_CONTAINER:-chimangoscan-neo4j}"
# Bound Neo4j's memory: unset, Neo4j 2026 grabs ~half of RAM as heap + a large
# page cache, starving the runner that parses the scan reports later in this
# stage (Python SIGSEGVs under the resulting memory pressure). The graph queries
# here are light (counts + a one-pass edge export), so a modest footprint is
# plenty and it leaves the host RAM the per-CVE step needs.
NEO4J_HEAP="${NEO4J_HEAP:-6G}"
NEO4J_PAGECACHE="${NEO4J_PAGECACHE:-8G}"
TOP_N="${TOP_N:-60000}"

DUMP=""
OUT=""
MONGO_URI=""
SQLITE=""
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dump)        DUMP="$2"; shift 2 ;;
    --out)         OUT="$2"; shift 2 ;;
    --with-mongo)  MONGO_URI="$2"; shift 2 ;;
    --sqlite)      SQLITE="$2"; shift 2 ;;
    --keep)        KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[ -n "$DUMP" ] && [ -n "$OUT" ] || \
  { echo "usage: analysis_neo4j.sh --dump PATH --out DIR [--with-mongo URI] [--sqlite PATH] [--keep]" >&2; exit 2; }
[ -s "$DUMP" ] || { echo "Neo4j dump not found: $DUMP (tar.gz of the data/ directory)" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker is required but not on PATH" >&2; exit 1; }
if [ -n "$SQLITE" ]; then
  [ -s "$SQLITE" ] || { echo "SQLite database not found: $SQLITE" >&2; exit 1; }
  SQLITE="$(realpath "$SQLITE")"
fi
DUMP="$(realpath "$DUMP")"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"

log() { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }

# ---------------------------------------------------------------------------
# Extract the data directory (idempotent) and locate the dir to mount at /data
# ---------------------------------------------------------------------------
DATA_ROOT="$OUT/neo4j_data"
if [ ! -d "$DATA_ROOT" ]; then
  log "extracting $DUMP -> $DATA_ROOT"
  rm -rf "$DATA_ROOT.tmp"
  mkdir -p "$DATA_ROOT.tmp"
  tar -xf "$DUMP" -C "$DATA_ROOT.tmp"
  mv "$DATA_ROOT.tmp" "$DATA_ROOT"
fi
if [ -n "${NEO4J_DATA_SUBDIR:-}" ]; then
  DATA_DIR="$DATA_ROOT/$NEO4J_DATA_SUBDIR"
else
  # Locate the neo4j data dir (the one holding databases/) wherever the archive
  # placed it: directly, under data/, or wrapped in an extra top-level folder
  # (the released tar wraps it in neo4j_data/). Mount the PARENT of databases/.
  DBDIR="$(find "$DATA_ROOT" -maxdepth 3 -type d -name databases 2>/dev/null | sort | head -1)"
  [ -n "$DBDIR" ] || {
    echo "no databases/ found under $DATA_ROOT -- set NEO4J_DATA_SUBDIR to the data dir inside the archive" >&2
    exit 1; }
  DATA_DIR="$(dirname "$DBDIR")"
fi

# ---------------------------------------------------------------------------
# Ephemeral Neo4j (auth disabled; the analysis scripts connect without auth)
# ---------------------------------------------------------------------------
cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo "--keep: Neo4j left running as $NEO4J_CONTAINER on bolt://$NEO4J_BOLT_ADDR"
  else
    docker rm -f "$NEO4J_CONTAINER" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker rm -f "$NEO4J_CONTAINER" >/dev/null 2>&1 || true
log "starting $NEO4J_IMAGE as $NEO4J_CONTAINER (bolt://$NEO4J_BOLT_ADDR)"
docker run -d --name "$NEO4J_CONTAINER" \
  -p "$NEO4J_BOLT_ADDR:7687" \
  -e NEO4J_AUTH=none \
  ${NEO4J_HEAP:+-e NEO4J_server_memory_heap_max__size="$NEO4J_HEAP"} \
  ${NEO4J_PAGECACHE:+-e NEO4J_server_memory_pagecache_size="$NEO4J_PAGECACHE"} \
  -v "$DATA_DIR:/data" \
  "$NEO4J_IMAGE" >/dev/null

wait_neo4j() {
  log "waiting for Neo4j (max ${NEO4J_WAIT_S}s)"
  local deadline=$(( $(date +%s) + NEO4J_WAIT_S ))
  until docker exec "$NEO4J_CONTAINER" cypher-shell -a bolt://127.0.0.1:7687 "RETURN 1;" >/dev/null 2>&1; do
    if ! docker ps -q --filter "name=^${NEO4J_CONTAINER}$" | grep -q .; then
      docker logs --tail 20 "$NEO4J_CONTAINER" >&2 || true
      echo "Neo4j container exited -- the data dir likely requires a different NEO4J_IMAGE major version" >&2
      exit 1
    fi
    [ "$(date +%s)" -lt "$deadline" ] || \
      { echo "Neo4j not ready after ${NEO4J_WAIT_S}s -- raise NEO4J_WAIT_S (large stores recover slowly)" >&2; exit 1; }
    sleep 3
  done
}
wait_neo4j

# The released store ships crash-consistent transaction logs; Neo4j replays them
# on the FIRST mount, but the heavy relationship traversal (exposure ranking) run
# before that recovery has fully settled hits transient store inconsistencies
# ("NOT PART OF CHAIN!"). The first mount persists the recovered store to disk, so
# one restart makes every query run against the already-recovered store.
log "restarting Neo4j once so log recovery settles before the traversal queries"
docker restart "$NEO4J_CONTAINER" >/dev/null
wait_neo4j

# ---------------------------------------------------------------------------
# Analysis chain (inside the runner image; Neo4j/Mongo reached via host net)
# ---------------------------------------------------------------------------
ensure_runner
RUNNER_EXTRA_MOUNT="-v $OUT:$OUT"
[ -n "$SQLITE" ] && RUNNER_EXTRA_MOUNT="$RUNNER_EXTRA_MOUNT -v $(dirname "$SQLITE"):$(dirname "$SQLITE")"

NEO4J_URI="bolt://$NEO4J_BOLT_ADDR"
WORK="$OUT/exposure_work"
RANKED="$OUT/exposure_ranked_v3.jsonl"
FILTER="$OUT/corpus_filter.txt"
CVES="$OUT/cve_digests_v3.json"

log "graph statistics"
in_runner sh -c "NEO4J_URI='$NEO4J_URI' OUT_PATH='$OUT/graph_stats.json' \
  python3 '$SCRIPTS/graph_stats.py'"

if [ -n "$MONGO_URI" ]; then
  log "exposure ranking"
  in_runner sh -c "NEO4J_URI='$NEO4J_URI' MONGO_URI='$MONGO_URI' WORKDIR='$WORK' OUT_PATH='$RANKED' \
    python3 '$SCRIPTS/compute_exposure_ranking.py'"
else
  echo "skipping exposure ranking: pass --with-mongo URI (needs the crawl MongoDB)"
fi

if [ -s "$RANKED" ]; then
  log "corpus filter (TOP_N=$TOP_N)"
  in_runner sh -c "EXPOSURE_JSONL='$RANKED' TOP_N='$TOP_N' OUT='$FILTER' \
    python3 '$SCRIPTS/make_corpus_filter.py'"
else
  echo "skipping corpus filter: $RANKED missing (rerun with --with-mongo)"
fi

if [ -n "$SQLITE" ] && [ -s "$FILTER" ]; then
  log "per-CVE affected digests"
  in_runner sh -c "CHIMANGOSCAN_DB='$SQLITE' CHIMANGOSCAN_FILTER_RT='$FILTER' OUT_PATH='$CVES' \
    python3 '$SCRIPTS/extract_cve_digests.py'"
elif [ -z "$SQLITE" ]; then
  echo "skipping CVE digests: pass --sqlite PATH (scan-results database)"
else
  echo "skipping CVE digests: corpus filter missing"
fi

if [ -s "$CVES" ] && [ -s "$WORK/edges.tsv.gz" ] && [ -s "$WORK/toplayers.jsonl.gz" ]; then
  log "downstream propagation"
  in_runner sh -c "WORKDIR='$WORK' CVE_JSON='$CVES' OUT_PATH='$OUT/propagation_v3.json' \
    python3 '$SCRIPTS/propagation_compute.py'"
else
  echo "skipping propagation: needs $CVES and the graph dumps under $WORK"
fi

log "Neo4j analysis stage done -- outputs in $OUT"
