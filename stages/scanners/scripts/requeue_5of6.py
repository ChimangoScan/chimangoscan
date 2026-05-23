#!/usr/bin/env python3
# requeue_5of6.py — re-enqueues reports with >=5 invocations in status=error
# (i.e. 5 of 6 scanners failed) by deleting them from reports and marking
# the corresponding jobs as pending. Makes a JSONL backup before the DELETE.
#
# One-shot operational script — invoke once per re-scan cycle:
#   python3 scripts/requeue_5of6.py
import sqlite3, json, time, os, sys
DB = "/home/anonymous/scanners/work/ditector.db"
BAK = "/home/anonymous/exposure-data/requeue_5of6_backup_" + time.strftime("%Y%m%d-%H%M%S") + ".jsonl"

c = sqlite3.connect(DB, timeout=60)
c.execute("PRAGMA busy_timeout=60000")
images = []
n_scanned = 0
for img, rj in c.execute("SELECT image, report_json FROM reports"):
    if not rj:
        continue
    n_scanned += 1
    try:
        d = json.loads(rj)
    except Exception:
        continue
    invs = d.get("invocations") or []
    err = sum(1 for i in invs if (i.get("status") or "") == "error")
    if err >= 5:
        images.append(img)
print("scanned", n_scanned, "reports; identified", len(images), "with >=5 errors", flush=True)
if not images:
    print("nothing to requeue")
    c.close()
    sys.exit(0)

n_bak = 0
with open(BAK, "w") as f:
    BATCH = 500
    for i in range(0, len(images), BATCH):
        chunk = images[i:i+BATCH]
        ph = ",".join("?" * len(chunk))
        rows = c.execute("SELECT image, report_json, n_findings, finished_at FROM reports WHERE image IN (" + ph + ")", chunk).fetchall()
        for img, rj, nf, fa in rows:
            f.write(json.dumps({"image": img, "report_json": rj, "n_findings": nf, "finished_at": fa}) + "\n")
            n_bak += 1
print("backed up", n_bak, "reports to", BAK, "(", os.path.getsize(BAK), "bytes)", flush=True)

c.isolation_level = None
c.execute("BEGIN IMMEDIATE")
del_total = 0
upd_total = 0
BATCH = 500
for i in range(0, len(images), BATCH):
    chunk = images[i:i+BATCH]
    ph = ",".join("?" * len(chunk))
    cur = c.execute("DELETE FROM reports WHERE image IN (" + ph + ")", chunk)
    del_total += cur.rowcount
    cur = c.execute("UPDATE jobs SET status='pending', worker_id=NULL, started_at=NULL, finished_at=NULL, heartbeat_at=NULL, attempts=0, error=NULL WHERE image IN (" + ph + ") AND status IN ('done','failed','skipped')", chunk)
    upd_total += cur.rowcount
c.execute("COMMIT")
print("DELETE reports:", del_total, " UPDATE jobs:", upd_total, flush=True)
c.close()
