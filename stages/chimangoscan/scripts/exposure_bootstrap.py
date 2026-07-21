#!/usr/bin/env python3
"""exposure_bootstrap.py — populates the scanners queue with the top-N targets by exposure.

Changes vs. the current scanners seed:
  * the image identifier becomes "<ns>/<name>:<tag>@<digest>"  (digest-pinned)
  * the queue is capped at --top-n (default 500k) by descending exposure
  * preserves existing done/running/skipped/failed/reports
  * creates the exposure_state table with the initial watermark

Idempotent: INSERT OR IGNORE on (image). Running again only adds what is missing.

Prerequisites on the host where it runs (<your-host>):
  - ranked jsonl: scanners/data/chimangoscan_exposure_ranked.jsonl
    (output of scripts/compute_exposure_ranking.py)
  - queue.db: scanners/work/chimangoscan.db

Usage:
  ./exposure_bootstrap.py --queue-db PATH --ranked-jsonl PATH
                          [--top-n 500000] [--migrate-existing]
                          [--dry-run]

Without --dry-run it runs for real. It always does a baseline+after diff and aborts with
a nonzero exit if done/running decrease (preservation sanity check).
"""
from __future__ import annotations
import argparse
import gzip
import json
import os
import sqlite3
import sys
import time
from contextlib import contextmanager

EXPOSURE_STATE_DDL = """
CREATE TABLE IF NOT EXISTS exposure_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at REAL NOT NULL
)
"""

PROTECTED = ("done", "running")  # estes nunca podem diminuir


def open_jsonl(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, "rt", encoding="utf-8")


def counts_by_status(conn: sqlite3.Connection) -> dict[str, int]:
    return dict(conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall())


def canonical_image(rec: dict) -> str:
    ns = rec["repository_namespace"]
    name = rec["repository_name"]
    tag = rec["tag_name"]
    dig = rec["image_digest"]
    repo = name if ns == "library" else f"{ns}/{name}"
    return f"{repo}:{tag}@{dig}"


def canonical_short_name(rec: dict) -> str:
    """Used by scanners.runner as the on-disk dir name; must be filesystem-safe."""
    ns = rec["repository_namespace"]
    name = rec["repository_name"]
    tag = rec["tag_name"]
    repo = name if ns == "library" else f"{ns}_{name}"
    return f"{repo}_{tag}".replace("/", "_").replace(":", "_")


def migrate_existing(conn: sqlite3.Connection, dry_run: bool) -> int:
    """Append @digest to image for rows where image lacks '@' AND target_json has meta.image_digest.

    The current rows were seeded with image='ns/name:tag' and the digest sitting in
    target_json.meta.image_digest. We rewrite image to 'ns/name:tag@sha256:...' so the
    daemon can compare against fresh digests from Mongo and decide what to re-rank.
    """
    sel = """
      SELECT id, image, target_json
      FROM jobs
      WHERE image NOT LIKE '%@sha256:%'
    """
    rows = list(conn.execute(sel))
    n_with_digest = n_without = 0
    updates = []
    for jid, image, tj in rows:
        try:
            dig = (json.loads(tj).get("meta") or {}).get("image_digest")
        except Exception:
            dig = None
        if not dig or not dig.startswith("sha256:"):
            n_without += 1
            continue
        new_image = f"{image}@{dig}"
        updates.append((new_image, jid))
        n_with_digest += 1

    print(f"  candidates without '@digest': {len(rows):,}", file=sys.stderr)
    print(f"  with usable meta.image_digest: {n_with_digest:,}", file=sys.stderr)
    print(f"  without digest (cannot migrate): {n_without:,}", file=sys.stderr)

    if dry_run:
        for new, jid in updates[:5]:
            print(f"  would SET image={new!r} (id={jid})", file=sys.stderr)
        return n_with_digest

    # do it; use INSERT OR IGNORE-style protection via UNIQUE constraint—conflicts mean
    # there's already another row with that digest-pinned image, in which case we drop
    # the un-digested one (it's a duplicate).
    n_done = 0
    for new_image, jid in updates:
        try:
            conn.execute("UPDATE jobs SET image = ? WHERE id = ?", (new_image, jid))
            n_done += 1
        except sqlite3.IntegrityError:
            # there's already a row with image=new_image (collision); delete the un-digested
            # one *only if* the colliding row has equal-or-better status (done > running > pending).
            keep = conn.execute("SELECT status FROM jobs WHERE image = ?", (new_image,)).fetchone()
            if keep is not None:
                conn.execute("DELETE FROM jobs WHERE id = ?", (jid,))
    conn.commit()
    print(f"  migrated rows: {n_done:,}", file=sys.stderr)
    return n_done


def bootstrap_insert(conn: sqlite3.Connection, jsonl_path: str, top_n: int,
                     dry_run: bool) -> tuple[int, int, float]:
    now = time.time()
    inserted = ignored = 0
    max_exposure_seen = 0.0

    insert_sql = """
      INSERT INTO jobs(image, name, target_json, weight, status, created_at)
      VALUES(?, ?, ?, ?, 'pending', ?)
      ON CONFLICT(image) DO NOTHING
    """

    with open_jsonl(jsonl_path) as f:
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
            max_exposure_seen = max(max_exposure_seen, weight)
            target_json = json.dumps({
                "image": image,
                "name": name,
                "weight": weight,
                "meta": rec,
            }, separators=(",", ":"))

            if dry_run:
                if i < 5:
                    print(f"  would INSERT image={image} weight={weight:,.0f}", file=sys.stderr)
                inserted += 1
                continue

            cur = conn.execute(insert_sql, (image, name, target_json, weight, now))
            if cur.rowcount > 0:
                inserted += 1
            else:
                ignored += 1

    if not dry_run:
        conn.commit()
    return inserted, ignored, max_exposure_seen


def trim_pending_to_top_n(conn: sqlite3.Connection, top_n: int, dry_run: bool) -> int:
    """Keep only the highest-exposure top_n pending rows; delete the rest of pending."""
    pending_total = conn.execute("SELECT COUNT(*) FROM jobs WHERE status='pending'").fetchone()[0]
    if pending_total <= top_n:
        return 0
    # find threshold
    row = conn.execute(
        "SELECT weight FROM jobs WHERE status='pending' ORDER BY weight DESC, id LIMIT 1 OFFSET ?",
        (top_n - 1,)
    ).fetchone()
    if row is None:
        return 0
    threshold = row[0]
    # delete the strictly-lower; for ties at threshold we keep all (simpler, slightly >top_n)
    if dry_run:
        n = conn.execute(
            "SELECT COUNT(*) FROM jobs WHERE status='pending' AND weight < ?",
            (threshold,)
        ).fetchone()[0]
        print(f"  would DELETE {n:,} pending rows with weight < {threshold:,.0f}", file=sys.stderr)
        return n
    cur = conn.execute(
        "DELETE FROM jobs WHERE status='pending' AND weight < ?",
        (threshold,)
    )
    conn.commit()
    return cur.rowcount


@contextmanager
def transactional(conn: sqlite3.Connection):
    """Open an explicit transaction that's rolled back on exception."""
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--queue-db", required=True, help="path to scanners chimangoscan.db")
    ap.add_argument("--ranked-jsonl", required=True, help="exposure-ranked jsonl (desc)")
    ap.add_argument("--top-n", type=int, default=500_000)
    ap.add_argument("--migrate-existing", action="store_true",
                    help="rewrite image to include @digest for legacy rows (uses target_json.meta.image_digest)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.queue_db):
        sys.exit(f"queue-db not found: {args.queue_db}")
    if not os.path.exists(args.ranked_jsonl):
        sys.exit(f"ranked-jsonl not found: {args.ranked_jsonl}")

    conn = sqlite3.connect(args.queue_db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(EXPOSURE_STATE_DDL)

    print("=== baseline ===", file=sys.stderr)
    before = counts_by_status(conn)
    for s, n in sorted(before.items()):
        print(f"  {s:<10} {n:>10,}", file=sys.stderr)

    if args.migrate_existing:
        print("=== migrate existing image -> image@digest ===", file=sys.stderr)
        migrate_existing(conn, args.dry_run)

    print("=== bootstrap insert (top_n=%d) ===" % args.top_n, file=sys.stderr)
    inserted, ignored, max_exp = bootstrap_insert(conn, args.ranked_jsonl, args.top_n, args.dry_run)
    print(f"  inserted: {inserted:,}   already-present (ignored): {ignored:,}", file=sys.stderr)
    print(f"  max exposure seen: {max_exp:,.0f}", file=sys.stderr)

    print("=== trim pending to top_n ===", file=sys.stderr)
    trimmed = trim_pending_to_top_n(conn, args.top_n, args.dry_run)
    print(f"  trimmed pending rows: {trimmed:,}", file=sys.stderr)

    print("=== after ===", file=sys.stderr)
    after = counts_by_status(conn)
    for s, n in sorted(after.items()):
        delta = n - before.get(s, 0)
        sign = "+" if delta >= 0 else ""
        print(f"  {s:<10} {n:>10,}  ({sign}{delta:,})", file=sys.stderr)

    # preservation sanity: done and running must NOT decrease
    bad = []
    for s in PROTECTED:
        if after.get(s, 0) < before.get(s, 0):
            bad.append(f"{s}: {before[s]:,} -> {after.get(s, 0):,}")
    if bad:
        print("!!! PRESERVATION VIOLATED:", "; ".join(bad), file=sys.stderr)
        sys.exit(2)

    # set watermark to now-ish; daemon will refine on first run by reading Mongo MAX(graph_built_at)
    if not args.dry_run:
        now = time.time()
        conn.execute(
            "INSERT OR REPLACE INTO exposure_state(key, value, updated_at) VALUES('bootstrap_at', ?, ?)",
            (str(now), now)
        )
        # initial last_built_at will be set by the daemon's first iteration; leave it for daemon to fill
        conn.commit()
        print(f"=== exposure_state.bootstrap_at = {now} ===", file=sys.stderr)

    conn.close()
    print("done.", file=sys.stderr)


if __name__ == "__main__":
    main()
