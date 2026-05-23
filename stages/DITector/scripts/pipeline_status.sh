#!/usr/bin/env bash
# pipeline_status.sh — counts for the DITector pipeline stages.
#
# Reads:
#   - Mongo (<your-host>, container ditector_mongo)   → Stage I (crawl) + Stage II (build)
#   - build_metrics.log / build_checkpoint     → builder progress
#   - SQLite scanners/work/ditector.db (<your-host>)  → scan queue (Stage III)
#
# Runs from the workstation via SSH; if invoked on <your-host> itself, uses localhost.
# Variables: DIT_HOST=<ssh_target>  (default: <your-host>)
#            DIT_QUEUE_DB=<path>    (default: ${SCANNER_HOME}/scanners/work/ditector.db)
#            DIT_METRICS=<path>     (default: ${SCANNER_HOME}/DITector_research/build_metrics.log)
#            DIT_CHECKPOINT=<path>  (default: ${SCANNER_HOME}/DITector_research/build_checkpoint.jsonl)

set -u

HOST="${DIT_HOST:-localhost}"
QUEUE_DB="${DIT_QUEUE_DB:-/var/lib/ditector/ditector.db}"
METRICS="${DIT_METRICS:-/var/lib/ditector/build_metrics.log}"
CHECKPOINT="${DIT_CHECKPOINT:-/var/lib/ditector/build_checkpoint.jsonl}"

# Detect: if already on <your-host>, no SSH needed.
LOCAL=0
case "$(hostname)" in
  localhost|host1) LOCAL=1 ;;
esac

run() {
  if [ "$LOCAL" -eq 1 ]; then
    bash -c "$1"
  else
    ssh -o ConnectTimeout=10 "$HOST" "$1"
  fi
}

mongo_eval() {
  run "docker exec ditector_mongo mongosh --quiet --eval $(printf '%q' "$1")"
}

hr() { printf -- '── %s ──\n' "$1"; }

printf '============================================================\n'
printf '  DITector — pipeline status (host: %s)\n' "$HOST"
printf '  %s\n' "$(date -u +%FT%TZ)"
printf '============================================================\n\n'

hr 'STAGE I — CRAWL (Mongo dockerhub_data)'
mongo_eval '
db = db.getSiblingDB("dockerhub_data");
const fmt = (n) => n.toLocaleString("en-US");
print("crawler_keywords   (crawl seeds):        " + fmt(db.crawler_keywords.estimatedDocumentCount()));
print("repositories_data  (repos collected):    " + fmt(db.repositories_data.estimatedDocumentCount()));
print("tags_data          (tags collected):     " + fmt(db.tags_data.estimatedDocumentCount()));
print("images_data        (images collected):   " + fmt(db.images_data.estimatedDocumentCount()));
'

printf '\n'
hr 'STAGE II — BUILD (graph_built_at + build_metrics.log)'
mongo_eval '
db = db.getSiblingDB("dockerhub_data");
const fmt = (n) => n.toLocaleString("en-US");
// stage2_partial is a partial index with filter {graph_built_at: null} → counts UNBUILT in ms.
// BUILT = total - unbuilt (avoids a collection scan of 12.7M docs).
const total = db.repositories_data.estimatedDocumentCount();
const unbuilt = db.repositories_data.countDocuments({graph_built_at: null});
const built = total - unbuilt;
print("graph_built_at SET (Stage II done):   " + fmt(built) + "  (" + ((built/total)*100).toFixed(1) + "%)");
print("graph_built_at UNSET (pending):       " + fmt(unbuilt));
'
printf '\n[build_metrics.log last line]\n'
run "tail -1 $METRICS 2>/dev/null || echo '(not found: $METRICS)'"
printf '[build_checkpoint.jsonl total lines]\n'
run "wc -l $CHECKPOINT 2>/dev/null || echo '(not found: $CHECKPOINT)'"

printf '\n'
hr 'PULL_COUNT — distribution (repositories_data)'
mongo_eval '
db = db.getSiblingDB("dockerhub_data");
const fmt = (n) => n.toLocaleString("en-US").padStart(12);
const buckets = [
  ["pull_count >= 1B",   1000000000],
  ["pull_count >= 100M", 100000000],
  ["pull_count >= 10M",  10000000],
  ["pull_count >= 1M",   1000000],
  ["pull_count >= 100k", 100000],
  ["pull_count >= 10k",  10000],
  ["pull_count >= 1k",   1000],
];
buckets.forEach(([n, v]) => {
  const c = db.repositories_data.countDocuments({pull_count: {$gte: v}});
  print(n.padEnd(22) + " " + fmt(c));
});
print("");
print("Top 10 by pull_count:");
db.repositories_data.find({}, {namespace:1, name:1, pull_count:1, _id:0})
  .sort({pull_count:-1}).limit(10).forEach(d =>
    print("  " + fmt(d.pull_count||0) + "  " + d.namespace + "/" + d.name));
'

printf '\n'
hr 'STAGE III — SCAN (queue scanners/work/ditector.db)'
PY_QUEUE='
import sqlite3, sys
db = sys.argv[1]
c = sqlite3.connect(db)
print("  status          count")
rows = list(c.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status ORDER BY 2 DESC"))
for status, n in rows:
    print(f"  {status:<14} {n:>12,}")
total = c.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
done   = c.execute("SELECT COUNT(*) FROM jobs WHERE status=\"done\"").fetchone()[0]
print(f"  TOTAL          {total:>12,}")
if total:
    print(f"  done / total:   {done/total*100:.2f}%")
print()
nrep, sfind = c.execute("SELECT COUNT(*), COALESCE(SUM(n_findings),0) FROM reports").fetchone()
print(f"  consolidated reports:    {nrep:>12,}")
print(f"  findings (raw sum):      {sfind:>12,}")
last = c.execute("SELECT image, n_findings, finished_at FROM reports ORDER BY finished_at DESC LIMIT 5").fetchall()
if last:
    import datetime as _dt
    fmt = "%Y-%m-%d %H:%M:%SZ"
    print()
    print("  last 5 reports:")
    for img, nf, ts in last:
        when = _dt.datetime.fromtimestamp(ts, _dt.timezone.utc).strftime(fmt)
        print(f"    {when}  {nf:>6}  {img}")
'
run "python3 -c $(printf '%q' "$PY_QUEUE") $QUEUE_DB"

printf '\n============================================================\n'
