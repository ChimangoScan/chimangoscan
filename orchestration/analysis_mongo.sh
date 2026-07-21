#!/usr/bin/env bash
# ChimangoScan -- MONGO (crawl) analysis stage.
#
# Restores the Stage I/II mongodump archive into an EPHEMERAL MongoDB container
# and computes every crawl-wide artefact of the paper:
#
#   crawl_stats.json  repository/tag/image/prefix-query totals, total pulls,
#                     pull-count distribution buckets, median/p99/max,
#                     last_updated coverage        (analysis/scripts/crawl_stats.py)
#   plan_crawl.json   crawl pull/dependency-weight CDF input of plan_figs.py
#                                                  (analysis/scripts/export_plan_crawl.py)
#   tags_full.jsonl   per-tag last_updated export for the temporal analysis
#                                                  (analysis/scripts/export_tags.py)
#
# The container publishes 127.0.0.1:$MONGO_PORT only (no clash with a resident
# mongod on 27017) and keeps its data on a named Docker volume. Without --keep,
# container and volume are removed on exit -- also on failure (trap). With
# --keep they stay up for the next stage; a re-run reuses them and skips the
# restore (a marker in the `_restore_meta` db records a completed restore).
#
# Usage: orchestration/analysis_mongo.sh --archive PATH [--out DIR] [--keep]
#
# Environment: MONGO_PORT (27100), MONGO_DB (dockerhub_data),
#              MONGO_IMAGE (mongo:7), MONGO_WAIT_S (120), RANKING (optional
#              exposure ranking jsonl for plan_crawl.json's depweight_base)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS="$ROOT/analysis/scripts"
[ -x "$ROOT/.venv/bin/python3" ] && PATH="$ROOT/.venv/bin:$PATH"

MONGO_PORT="${MONGO_PORT:-27100}"
MONGO_DB="${MONGO_DB:-dockerhub_data}"
MONGO_IMAGE="${MONGO_IMAGE:-mongo:7}"
MONGO_WAIT_S="${MONGO_WAIT_S:-120}"
CONTAINER="chimangoscan-mongo-analysis"
VOLUME="$CONTAINER-data"

ARCHIVE=""
OUT="$ROOT/artifacts/analysis"
KEEP=0

while [ $# -gt 0 ]; do
  case "$1" in
    --archive) ARCHIVE="$2"; shift 2 ;;
    --out)     OUT="$2"; shift 2 ;;
    --keep)    KEEP=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

log() { printf '\n=== [%s] %s ===\n' "$(date +%H:%M:%S)" "$*"; }

[ -n "$ARCHIVE" ] || { echo "usage: analysis_mongo.sh --archive PATH [--out DIR] [--keep]" >&2; exit 2; }
[ -s "$ARCHIVE" ] || { echo "archive not found: $ARCHIVE" >&2; exit 1; }
ARCHIVE="$(realpath "$ARCHIVE")"
mkdir -p "$OUT"
OUT="$(realpath "$OUT")"

python3 -c "import pymongo" 2>/dev/null \
  || { echo "pymongo missing: pip install pymongo (or run inside the runner image, docker/Dockerfile.runner)" >&2; exit 1; }

mongosh() { docker exec "$CONTAINER" mongosh --quiet --eval "$1"; }

cleanup() {
  if [ "$KEEP" = 1 ]; then
    echo "container $CONTAINER left running on 127.0.0.1:$MONGO_PORT (--keep)"
  else
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Start (or reuse) the ephemeral mongod.
if [ "$(docker ps -q -f "name=^$CONTAINER$")" ]; then
  log "reusing running container $CONTAINER"
else
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  if (exec 3<>"/dev/tcp/127.0.0.1/$MONGO_PORT") 2>/dev/null; then
    echo "port $MONGO_PORT already in use -- set MONGO_PORT to a free port" >&2
    exit 1
  fi
  log "starting $MONGO_IMAGE as $CONTAINER on 127.0.0.1:$MONGO_PORT"
  docker run -d --name "$CONTAINER" \
    -p "127.0.0.1:$MONGO_PORT:27017" \
    -v "$VOLUME:/data/db" \
    -v "$ARCHIVE:/restore.archive.gz:ro" \
    "$MONGO_IMAGE" >/dev/null
fi

log "waiting for mongod (up to ${MONGO_WAIT_S}s)"
deadline=$((SECONDS + MONGO_WAIT_S))
until [ "$(mongosh 'db.runCommand({ping:1}).ok' 2>/dev/null)" = "1" ]; do
  [ $SECONDS -lt $deadline ] || { echo "mongod not ready after ${MONGO_WAIT_S}s" >&2; exit 1; }
  sleep 2
done

if [ "$(mongosh "db.getSiblingDB('_restore_meta').flags.countDocuments({_id:'restored'})")" = "1" ]; then
  log "restore already done (marker present), skipping"
else
  log "restoring $ARCHIVE (namespace $MONGO_DB.*)"
  docker exec "$CONTAINER" mongorestore --quiet --drop --gzip \
    --archive=/restore.archive.gz --nsInclude "$MONGO_DB.*"
  mongosh "db.getSiblingDB('_restore_meta').flags.updateOne({_id:'restored'},{\$set:{at:new Date()}},{upsert:true})" >/dev/null
fi

export MONGO_URI="mongodb://127.0.0.1:$MONGO_PORT"
export MONGO_DB

log "crawl_stats.json"
OUT="$OUT/crawl_stats.json" python3 "$SCRIPTS/crawl_stats.py"
log "plan_crawl.json"
OUT="$OUT/plan_crawl.json" python3 "$SCRIPTS/export_plan_crawl.py"
log "tags_full.jsonl"
OUT="$OUT/tags_full.jsonl" python3 "$SCRIPTS/export_tags.py"

log "MONGO analysis artefacts written to $OUT/"
