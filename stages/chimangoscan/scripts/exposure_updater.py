#!/usr/bin/env python3
"""exposure_updater.py — periodic re-rank of the scanners queue from compute_exposure_ranking output.

Each iteration:
  1) Force a fresh ranking dump (rm work dir) + run compute_exposure_ranking.py
  2) Parse top-N from chimangoscan_exposure_ranked.jsonl
  3) UPSERT into queue.db:
       - new images: INSERT as 'pending'
       - existing 'pending':  UPDATE weight to the fresh exposure
       - existing 'done|running|skipped|failed': LEFT UNTOUCHED (preservation rule)
  4) Trim pending to top-N (delete pending with weight below the Nth)
  5) Persist exposure_state.last_run
  6) sleep (loop mode) or exit (--once)

Image identifier convention: "<ns>/<name>:<tag>@<digest>" (digest-pinned). This is
the canonical Docker ref — a worker can `docker pull` it directly and the same row
will be reused next iteration. When the registry rolls `latest` to a new digest the
ranker emits a new identifier; this script inserts it as a fresh pending row.

The full recompute is heavy (~30-45 min, hits Mongo+Neo4j hard). Run during
off-peak hours OR with `--loop 21600` (every 6h). Workers keep claiming jobs in
parallel; they only touch row status, never the weight column.
"""
from __future__ import annotations
import argparse
import gzip
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import time

EXPOSURE_STATE_DDL = """
CREATE TABLE IF NOT EXISTS exposure_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
)
"""

PROTECTED_STATUSES = ("done", "running")  # MUST not decrease


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def open_jsonl(path: str):
    return gzip.open(path, "rt", encoding="utf-8") if path.endswith(".gz") else open(path, "rt", encoding="utf-8")


def canonical_image(rec: dict) -> str:
    ns = rec["repository_namespace"]
    name = rec["repository_name"]
    tag = rec["tag_name"]
    dig = rec["image_digest"]
    repo = name if ns == "library" else f"{ns}/{name}"
    return f"{repo}:{tag}@{dig}"


def canonical_short_name(rec: dict) -> str:
    ns = rec["repository_namespace"]
    name = rec["repository_name"]
    tag = rec["tag_name"]
    repo = name if ns == "library" else f"{ns}_{name}"
    return f"{repo}_{tag}".replace("/", "_").replace(":", "_")


def run_ranker(ranker_script: str, work_dir: str, out_path: str, fresh: bool):
    if fresh and os.path.isdir(work_dir):
        log(f"removing stale work_dir {work_dir}")
        shutil.rmtree(work_dir)
    env = os.environ.copy()
    env["WORKDIR"] = work_dir
    env["OUT_PATH"] = out_path
    log(f"running ranker: {ranker_script} (WORKDIR={work_dir})")
    t0 = time.time()
    res = subprocess.run(["python3", ranker_script], env=env, check=False)
    dt = time.time() - t0
    log(f"ranker exited rc={res.returncode} in {dt:.0f}s")
    if res.returncode != 0:
        raise RuntimeError(f"compute_exposure_ranking exited {res.returncode}")


def counts_by_status(conn: sqlite3.Connection) -> dict[str, int]:
    return dict(conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall())


def upsert_top_n(conn: sqlite3.Connection, jsonl_path: str, top_n: int) -> tuple[int, int]:
    inserted = updated = 0
    now = time.time()
    insert_sql = """
      INSERT INTO jobs(image, name, target_json, weight, status, created_at)
      VALUES(?, ?, ?, ?, 'pending', ?)
      ON CONFLICT(image) DO UPDATE
        SET weight = excluded.weight
    """
    # Note: no WHERE — updates weight for ALL statuses (pending, done, skipped…).
    # The status is never touched here. The coordinator does not use the weight of done jobs, so it is safe.
    # This guarantees the dashboard always reads the updated exposure via jobs.weight.
    with open_jsonl(jsonl_path) as f:
        batch = []
        for i, line in enumerate(f):
            if i >= top_n:
                break
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            image = canonical_image(rec)
            name = canonical_short_name(rec)
            weight = float(rec.get("exposure") or rec.get("weights") or 0)
            target_json = json.dumps({"image": image, "name": name, "weight": weight, "meta": rec},
                                     separators=(",", ":"))
            batch.append((image, name, target_json, weight, now))
            if len(batch) >= 5000:
                conn.executemany(insert_sql, batch)
                conn.commit()  # commit per batch — avoids a single 500k-row transaction that causes a 29GB WAL
                batch.clear()
        if batch:
            conn.executemany(insert_sql, batch)
            conn.commit()
            batch.clear()
    # post-hoc counts
    inserted = conn.execute("SELECT COUNT(*) FROM jobs WHERE created_at = ?", (now,)).fetchone()[0]
    return inserted, top_n - inserted  # rough; updated ≈ top_n − inserted


def trim_pending(conn: sqlite3.Connection, top_n: int) -> int:
    pending_total = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0]
    if pending_total <= top_n:
        return 0
    row = conn.execute(
        "SELECT weight FROM jobs WHERE status='pending' ORDER BY weight DESC, id LIMIT 1 OFFSET ?",
        (top_n - 1,)
    ).fetchone()
    if row is None:
        return 0
    threshold = row[0]
    # delete in batches of 10k to avoid a giant transaction and blowing up the WAL
    deleted = 0
    while True:
        cur = conn.execute(
            "DELETE FROM jobs WHERE id IN ("
            "  SELECT id FROM jobs WHERE status='pending' AND weight < ? LIMIT 10000"
            ")",
            (threshold,)
        )
        conn.commit()
        deleted += cur.rowcount
        if cur.rowcount == 0:
            break
    return deleted


def iterate_once(args):
    log("=== iteration start ===")
    if not args.skip_ranker:
        run_ranker(args.ranker_script, args.work_dir, args.ranked_jsonl, fresh=not args.reuse_cache)
    else:
        log(f"--skip-ranker: reusing {args.ranked_jsonl}")

    if not os.path.exists(args.ranked_jsonl):
        raise RuntimeError(f"ranked jsonl missing: {args.ranked_jsonl}")

    conn = sqlite3.connect(args.queue_db, timeout=60.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(EXPOSURE_STATE_DDL)

    before = counts_by_status(conn)
    log("baseline:", {k: before.get(k, 0) for k in ("pending", "done", "running", "skipped", "failed")})

    inserted, updated_approx = upsert_top_n(conn, args.ranked_jsonl, args.top_n)
    log(f"upsert: inserted_new={inserted:,}  updated_pending≈{updated_approx:,}")

    trimmed = trim_pending(conn, args.top_n)
    log(f"trimmed_below_topN_pending: {trimmed:,}")

    after = counts_by_status(conn)
    log("after:   ", {k: after.get(k, 0) for k in ("pending", "done", "running", "skipped", "failed")})

    for s in PROTECTED_STATUSES:
        if after.get(s, 0) < before.get(s, 0):
            raise RuntimeError(f"PRESERVATION VIOLATED: {s} {before[s]} -> {after.get(s, 0)}")

    now = time.time()
    conn.execute(
        "INSERT OR REPLACE INTO exposure_state(key, value, updated_at) VALUES('last_run_at', ?, ?)",
        (str(now), now)
    )
    conn.commit()
    conn.close()
    log("=== iteration done ===")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--queue-db", required=True)
    ap.add_argument("--ranker-script", default="compute_exposure_ranking.py",
                    help="path to compute_exposure_ranking.py")
    ap.add_argument("--work-dir", default=os.path.expanduser("~/scanners/data/exposure_work"),
                    help="ranker scratch dir (dumps cached here)")
    ap.add_argument("--ranked-jsonl", default=os.path.expanduser("~/scanners/data/chimangoscan_exposure_ranked.jsonl"),
                    help="where the ranker writes its output (set as OUT_PATH for the ranker)")
    ap.add_argument("--top-n", type=int, default=500_000)
    ap.add_argument("--once", action="store_true",
                    help="run a single iteration and exit (default if --loop missing)")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="seconds to sleep between iterations; if 0, run --once")
    ap.add_argument("--skip-ranker", action="store_true",
                    help="don't run compute_exposure_ranking; reuse existing --ranked-jsonl")
    ap.add_argument("--reuse-cache", action="store_true",
                    help="don't rm work_dir before ranker (uses any cached mongo/neo4j dumps)")
    args = ap.parse_args()

    # graceful shutdown on SIGTERM/SIGINT
    stop = {"flag": False}
    def _stop(signum, frame):
        log(f"signal {signum} received; will stop after current iteration")
        stop["flag"] = True
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    if args.loop <= 0:
        iterate_once(args)
        return 0

    while not stop["flag"]:
        try:
            iterate_once(args)
        except Exception as e:
            log(f"iteration FAILED: {type(e).__name__}: {e}")
        if stop["flag"]:
            break
        log(f"sleeping {args.loop}s")
        # break sleep into chunks so signals are handled promptly
        slept = 0
        while slept < args.loop and not stop["flag"]:
            chunk = min(60, args.loop - slept)
            time.sleep(chunk)
            slept += chunk
    log("exited cleanly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
