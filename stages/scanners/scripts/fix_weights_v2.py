#!/usr/bin/env python3
# fix_weights_v2.py — syncs jobs.weight in chimangoscan.db with the exposure
# computed by the ranker (read from chimangoscan_exposure_ranked_fixed.jsonl).
# Lookup by (ns,repo,tag,digest) with a fallback to base, in batches of 5000
# UPDATEs per commit so as not to inflate the WAL.
#
# Invocation (on host1):
#   python3 scripts/fix_weights_v2.py
import json, sqlite3, time, re
SRC = "/home/user/exposure-data/chimangoscan_exposure_ranked_fixed.jsonl"
DB  = "/home/user/scanners/work/chimangoscan.db"

def parse_jobs_image(img):
    """parse jobs.image -> (ns, repo, tag, digest) ou None se mal-formado.
       jobs.image: "[ns/]repo[:tag][@digest]"."""
    if not img or "@" not in img:
        return None
    left, dig = img.rsplit("@", 1)
    if ":" in left:
        path, tag = left.rsplit(":", 1)
    else:
        path, tag = left, "latest"
    path = path.lstrip("/")    # "/ayubalam/x" -> "ayubalam/x"
    if "/" in path:
        ns, repo = path.split("/", 1)
    else:
        ns, repo = "library", path
    return (ns, repo, tag, dig)

print("phase 1: build (ns,repo,tag,digest) -> exposure map from JSONL")
t0 = time.time()
key_exp = {}
n = 0
with open(SRC) as f:
    for line in f:
        d = json.loads(line)
        ns  = d.get("repository_namespace") or ""
        rp  = d.get("repository_name") or ""
        tg  = d.get("tag_name") or ""
        dig = d.get("image_digest") or ""
        exp = d.get("exposure")
        if not (ns and rp and dig) or exp is None:
            continue
        try:
            ex = float(exp)
        except Exception:
            continue
        k = (ns, rp, tg, dig)
        # caso raro: mesma key aparece 2x — mantém maior
        if ex > key_exp.get(k, -1):
            key_exp[k] = ex
        n += 1
print(f"  jsonl rows={n:,}  unique keys={len(key_exp):,}  in {time.time()-t0:.1f}s")

print("phase 2: scan jobs, lookup by full key")
c = sqlite3.connect(DB, timeout=60, isolation_level=None)
c.execute("PRAGMA journal_mode=WAL")
c.execute("PRAGMA busy_timeout=60000")
c.execute("PRAGMA synchronous=NORMAL")
t0 = time.time()
rows = c.execute("SELECT id, image, weight FROM jobs").fetchall()
print(f"  {len(rows):,} jobs in {time.time()-t0:.1f}s")

t0 = time.time()
fixes = []
n_match = 0; n_no_at = 0; n_no_match = 0
for jid, img, w in rows:
    p = parse_jobs_image(img)
    if p is None:
        n_no_at += 1; continue
    ex = key_exp.get(p)
    if ex is None:
        n_no_match += 1; continue
    n_match += 1
    if abs((w or 0) - ex) >= 1.0:
        fixes.append((ex, jid))
print(f"  match={n_match:,}  no_at={n_no_at:,}  no_match={n_no_match:,}  needing_update={len(fixes):,}  in {time.time()-t0:.1f}s")

print("phase 3: batched UPDATE (commit per 5000)")
t0 = time.time()
BATCH = 5000
total = 0
for i in range(0, len(fixes), BATCH):
    chunk = fixes[i:i+BATCH]
    c.execute("BEGIN IMMEDIATE")
    c.executemany("UPDATE jobs SET weight=? WHERE id=?", chunk)
    c.execute("COMMIT")
    total += len(chunk)
    if i % (BATCH*20) == 0:
        print(f"  {total:,}/{len(fixes):,}  ({100*total/max(1,len(fixes)):.1f}%) elapsed={time.time()-t0:.1f}s")
print(f"DONE: {total:,} updates in {time.time()-t0:.1f}s")

# advance the WAL readpoint to reduce work for the next cron; PASSIVE
# does not block other writers (e.g. coordinator) — TRUNCATE is left to
# a separate WAL-checkpoint cron that pauses the coordinator.
r = c.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
print(f"WAL checkpoint after batch UPDATE: busy={r[0]} total={r[1]} done={r[2]}")
c.close()
