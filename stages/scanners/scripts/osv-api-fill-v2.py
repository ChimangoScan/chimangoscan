#!/usr/bin/env python3
"""Phase 3-ALT v2 — DB-friendly OSV severity backfill.

v1 (commit 081df0c) used a long-running UPDATE batch of 200 with explicit
con.commit() at the end. With autocommit OFF, sqlite3 started an implicit
write transaction on the first executemany and held the WAL writer slot for
several seconds at a time, which made the coordinator's INSERT/UPDATE jobs
queries error-loop and eventually crash it.

v2 changes:
  * isolation_level=None  -> autocommit, each UPDATE its own micro-txn.
  * PRAGMA busy_timeout=5000 — wait for writer slot instead of erroring.
  * time.sleep(0.1) after every UPDATE — yield writer slot to coord/workers.
  * WAL size guard: pause 30s above 10 GB, abort gracefully above 20 GB.
  * Single-threaded UPDATE loop. OSV API stage uses 2 workers max.
  * Resume from any pre-existing cache JSONL (CVE -> severity).
  * Backup (gz JSONL) every original report row touched, written BEFORE the
    UPDATE.

Run pinned to low priority:
    nohup nice -n 19 ionice -c 3 python3 -u osv-api-fill-v2.py \\
        > /tmp/osv-fill-v2.log 2>&1 &

Kill switch: if coord stops responding to /stats, kill this PID immediately.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# CVSS scoring — copied verbatim from scanners/src/scanners/adapters/osv.py
# so this script is self-contained on hosts that only have Python.
# ---------------------------------------------------------------------------
_V3_M = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": (0.85, 0.85), "L": (0.62, 0.68), "H": (0.27, 0.50)},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
_V4_IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    return -(-x * 10 // 1) / 10


def _cvss_v3_score(vec: str) -> float | None:
    parts = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
    try:
        scope_changed = parts.get("S") == "C"
        av = _V3_M["AV"][parts["AV"]]; ac = _V3_M["AC"][parts["AC"]]
        pr = _V3_M["PR"][parts["PR"]][1 if scope_changed else 0]
        ui = _V3_M["UI"][parts["UI"]]
        c = _V3_M["C"][parts["C"]]; i = _V3_M["I"][parts["I"]]; a = _V3_M["A"][parts["A"]]
    except KeyError:
        return None
    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (
        7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        if scope_changed
        else 6.42 * isc_base
    )
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * pr * ui
    raw = min((1.08 * (impact + expl)) if scope_changed else (impact + expl), 10.0)
    return _roundup(raw)


def _cvss_v4_score(vec: str) -> float | None:
    parts = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
    try:
        impact = max(_V4_IMPACT[parts["VC"]], _V4_IMPACT[parts["VI"]], _V4_IMPACT[parts["VA"]])
    except KeyError:
        return None
    if impact == 0:
        return 0.0
    av_bonus = {"N": 1.0, "A": 0.85, "L": 0.7, "P": 0.5}.get(parts.get("AV", "N"), 0.7)
    ac_bonus = {"L": 1.0, "H": 0.75}.get(parts.get("AC", "L"), 0.85)
    return round(min(10.0, impact * av_bonus * ac_bonus * 17.5), 1)


def _cvss_from_vuln(v: dict) -> float | None:
    best = None
    for s in v.get("severity") or []:
        score_str = str(s.get("score", ""))
        if not score_str:
            continue
        n = None
        if score_str.startswith("CVSS:3"):
            n = _cvss_v3_score(score_str)
        elif score_str.startswith("CVSS:4"):
            n = _cvss_v4_score(score_str)
        elif str(s.get("type", "")).upper().startswith("CVSS"):
            m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*", score_str)
            if m:
                n = float(m.group(1))
        if n is not None:
            best = max(best or 0.0, n)
    return best


_SEV_FROM_STR = {
    "critical": "critical", "crit": "critical",
    "high": "high", "important": "high", "error": "high",
    "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
    "low": "low", "minor": "low",
    "info": "info", "informational": "info", "negligible": "info",
    "none": "info", "log": "info", "note": "info", "unknown": "unknown",
}


def _qual_severity(v: dict) -> str:
    db = v.get("database_specific")
    if isinstance(db, dict) and db.get("severity"):
        return _SEV_FROM_STR.get(str(db["severity"]).strip().lower(), "unknown")
    for s in v.get("severity") or []:
        score_str = str(s.get("score", ""))
        if score_str and not score_str.upper().startswith("CVSS:"):
            sev = _SEV_FROM_STR.get(score_str.strip().lower(), "unknown")
            if sev != "unknown":
                return sev
    return "unknown"


def _bucket_from_cvss(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def severity_of_vuln(v: dict) -> tuple[str, float | None]:
    score = _cvss_from_vuln(v)
    if score is not None:
        return _bucket_from_cvss(score), score
    return _qual_severity(v), None


# ---------------------------------------------------------------------------
# OSV API client — gentle (2 workers, 5 req/s ceiling)
# ---------------------------------------------------------------------------
OSV_URL = "https://api.osv.dev/v1/vulns/{id}"

_rate_lock = threading.Lock()
_last_request_ts: list[float] = [0.0]
_min_interval = 1.0 / 5.0  # 5 req/s shared across all workers


def _throttle() -> None:
    with _rate_lock:
        now = time.monotonic()
        wait = _min_interval - (now - _last_request_ts[0])
        if wait > 0:
            time.sleep(wait)
        _last_request_ts[0] = time.monotonic()


def fetch_vuln(vid: str, timeout: float = 15.0) -> tuple[str, str | None, dict | None]:
    """Return (status, error_msg, vuln_dict). status in {ok, not_found, error}."""
    backoff = 1.0
    for attempt in range(5):
        _throttle()
        try:
            req = Request(OSV_URL.format(id=vid), headers={"User-Agent": "chimangoscan-osv-fill-v2/1"})
            with urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            try:
                return ("ok", None, json.loads(data))
            except json.JSONDecodeError as e:
                return ("error", f"json_decode:{e}", None)
        except HTTPError as e:
            if e.code == 404:
                return ("not_found", None, None)
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(backoff + random.random() * 0.5)
                backoff = min(backoff * 2, 30.0)
                continue
            return ("error", f"http_{e.code}", None)
        except (URLError, TimeoutError, OSError) as e:
            time.sleep(backoff + random.random() * 0.5)
            backoff = min(backoff * 2, 30.0)
            if attempt == 4:
                return ("error", f"net:{type(e).__name__}", None)
    return ("error", "exhausted_retries", None)


# ---------------------------------------------------------------------------
# DB helpers — read-only collection pass
# ---------------------------------------------------------------------------
LIKE_NEEDLE_A = '%"scanner":"osv"%"severity":"unknown"%'
LIKE_NEEDLE_B = '%"severity":"unknown"%"scanner":"osv"%'


def collect_targets(db_path: str, log) -> tuple[dict[str, int], set[str]]:
    """Read-only pass: find reports whose OSV findings still include unknowns.

    Returns:
      per_image: dict[image -> count_of_unknown_osv_findings]
      ids:       set of distinct vuln ids that need an OSV API lookup
    """
    log("== Stage 1: scan reports (read-only) ==")
    t0 = time.time()
    uri = f"file:{db_path}?mode=ro"
    con = sqlite3.connect(uri, uri=True, timeout=30)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(
        "SELECT image, report_json FROM reports WHERE report_json LIKE ? OR report_json LIKE ?",
        (LIKE_NEEDLE_A, LIKE_NEEDLE_B),
    )
    per_image: dict[str, int] = {}
    ids: set[str] = set()
    n_findings = 0
    scanned = 0
    while True:
        rows = cur.fetchmany(500)
        if not rows:
            break
        for r in rows:
            scanned += 1
            try:
                j = json.loads(r["report_json"] or "")
            except (TypeError, ValueError):
                continue
            unk_here = 0
            for fnd in j.get("findings") or []:
                if fnd.get("scanner") != "osv":
                    continue
                if fnd.get("severity") != "unknown":
                    continue
                vid = fnd.get("id")
                if vid:
                    ids.add(vid)
                    unk_here += 1
            if unk_here:
                per_image[r["image"]] = unk_here
                n_findings += unk_here
    con.close()
    log(f"  scanned {scanned} candidate rows -> "
        f"{len(per_image)} reports / {n_findings} findings / {len(ids)} distinct ids "
        f"(took {time.time() - t0:.1f}s)")
    return per_image, ids


# ---------------------------------------------------------------------------
# Stage 2: load cache + fetch missing CVEs (low concurrency, incremental cache)
# ---------------------------------------------------------------------------
def load_cache(cache_path: Path, log) -> tuple[dict[str, tuple[str, float | None]], set[str]]:
    """Load previously-resolved CVE severities. Returns (resolved, seen_ids)."""
    resolved: dict[str, tuple[str, float | None]] = {}
    seen: set[str] = set()
    if not cache_path.exists():
        log(f"  cache absent: {cache_path} (starting fresh)")
        return resolved, seen
    with cache_path.open() as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            vid = e.get("id")
            if not vid:
                continue
            seen.add(vid)
            if e.get("status") == "ok" and e.get("severity"):
                resolved[vid] = (e["severity"], e.get("cvss"))
    log(f"  cache loaded: {len(seen)} prior entries, {len(resolved)} usable severities "
        f"({cache_path})")
    return resolved, seen


def fetch_missing(ids_to_fetch: list[str], cache_path: Path, workers: int, log) -> dict[str, tuple[str, float | None]]:
    log(f"== Stage 2: OSV API lookup for {len(ids_to_fetch)} ids (workers={workers}) ==")
    if not ids_to_fetch:
        return {}
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_fh = cache_path.open("a", buffering=1)
    cache_lock = threading.Lock()
    resolved: dict[str, tuple[str, float | None]] = {}
    stats = {"ok": 0, "not_found": 0, "error": 0}
    t0 = time.time()
    done = 0
    total = len(ids_to_fetch)

    def worker(vid: str):
        status, err, v = fetch_vuln(vid)
        entry: dict[str, Any] = {"id": vid, "status": status, "ts": time.time()}
        sev: tuple[str, float | None] | None = None
        if status == "ok" and v is not None:
            sevname, score = severity_of_vuln(v)
            sev = (sevname, score)
            entry["severity"] = sevname
            entry["cvss"] = score
        elif err:
            entry["error"] = err
        return vid, status, sev, entry

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(worker, vid) for vid in ids_to_fetch]
        for fut in as_completed(futs):
            try:
                vid, status, sev, entry = fut.result()
            except Exception as e:  # noqa: BLE001
                log(f"  worker crash: {e}")
                continue
            stats[status if status in stats else "error"] += 1
            if sev is not None and sev[0] != "unknown":
                resolved[vid] = sev
            with cache_lock:
                cache_fh.write(json.dumps(entry) + "\n")
            done += 1
            if done % 200 == 0 or done == total:
                rate = done / max(time.time() - t0, 0.001)
                log(f"  {done}/{total} ok={stats['ok']} 404={stats['not_found']} err={stats['error']} ({rate:.1f}/s)")

    cache_fh.close()
    log(f"  done: ok={stats['ok']} not_found={stats['not_found']} error={stats['error']} "
        f"({time.time() - t0:.1f}s)")
    return resolved


# ---------------------------------------------------------------------------
# Stage 3: UPDATE loop — autocommit, sleep 100ms, WAL-aware
# ---------------------------------------------------------------------------
def wal_mb(db_path: str) -> int:
    try:
        return os.path.getsize(db_path + "-wal") // 1024 // 1024
    except OSError:
        return 0


def recompute_invocation_bys(report: dict) -> None:
    osv_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for fnd in report.get("findings") or []:
        if fnd.get("scanner") != "osv":
            continue
        sev = fnd.get("severity") or "unknown"
        osv_counts[sev] = osv_counts.get(sev, 0) + 1
    osv_counts = {k: v for k, v in osv_counts.items() if v > 0}
    for inv in report.get("invocations") or []:
        if inv.get("scanner") == "osv":
            inv["findings_by_severity"] = osv_counts
            return


def apply_updates(db_path: str,
                  per_image: dict[str, int],
                  resolved: dict[str, tuple[str, float | None]],
                  backup_path: Path,
                  args,
                  log) -> tuple[int, int, int, dict[str, Any]]:
    """Returns (n_reports_updated, n_findings_updated, max_wal_mb, sample_diff)."""
    log("== Stage 3: backup + apply updates (autocommit, 100ms yield per row) ==")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    rw = sqlite3.connect(db_path, timeout=60, isolation_level=None)  # autocommit
    rw.row_factory = sqlite3.Row
    rw.execute("PRAGMA busy_timeout=5000")
    cur = rw.cursor()

    images = list(per_image.keys())
    log(f"  candidate reports: {len(images)} | backup -> {backup_path}")

    n_reports = 0
    n_findings = 0
    n_skipped = 0
    max_wal = wal_mb(db_path)
    sample_diff: dict[str, Any] | None = None
    aborted = False
    t0 = time.time()

    with gzip.open(backup_path, "wt") as bk:
        for idx, image in enumerate(images, start=1):
            # WAL backpressure check every 500 rows
            if idx % 500 == 0 or idx == 1:
                w = wal_mb(db_path)
                max_wal = max(max_wal, w)
                if w > args.wal_abort_mb:
                    log(f"  WAL={w} MB > abort threshold {args.wal_abort_mb} MB -> stop")
                    aborted = True
                    break
                if w > args.wal_pause_mb:
                    log(f"  WAL={w} MB > pause threshold {args.wal_pause_mb} MB -> sleeping 30s")
                    time.sleep(30)

            try:
                row = cur.execute(
                    "SELECT report_json FROM reports WHERE image=?", (image,)
                ).fetchone()
            except sqlite3.OperationalError as e:
                log(f"  SELECT failed for {image}: {e} — sleeping 5s and continuing")
                time.sleep(5.0)
                n_skipped += 1
                continue
            if not row or not row["report_json"]:
                n_skipped += 1
                continue
            try:
                j = json.loads(row["report_json"])
            except ValueError:
                n_skipped += 1
                continue

            # Backup BEFORE any change.
            bk.write(json.dumps({"image": image, "report_json": j}, separators=(",", ":")) + "\n")

            pre_counts = None
            for inv in j.get("invocations") or []:
                if inv.get("scanner") == "osv":
                    pre_counts = dict(inv.get("findings_by_severity") or {})
                    break

            touched = 0
            for fnd in j.get("findings") or []:
                if fnd.get("scanner") != "osv":
                    continue
                if fnd.get("severity") != "unknown":
                    continue
                vid = fnd.get("id")
                sev = resolved.get(vid)
                if not sev:
                    continue
                sevname, score = sev
                if sevname == "unknown":
                    continue
                fnd["severity"] = sevname
                if score is not None:
                    fnd["cvss"] = score
                touched += 1

            if not touched:
                n_skipped += 1
                continue

            recompute_invocation_bys(j)
            new_rj = json.dumps(j, separators=(",", ":"))

            try:
                cur.execute("UPDATE reports SET report_json=? WHERE image=?", (new_rj, image))
            except sqlite3.OperationalError as e:
                # busy_timeout already absorbs short contention; treat anything
                # else as a soft failure and keep going.
                log(f"  UPDATE failed for {image}: {e} — sleeping 10s")
                time.sleep(10.0)
                n_skipped += 1
                continue

            n_reports += 1
            n_findings += touched

            if sample_diff is None:
                post_counts = None
                for inv in j.get("invocations") or []:
                    if inv.get("scanner") == "osv":
                        post_counts = dict(inv.get("findings_by_severity") or {})
                        break
                sample_diff = {
                    "image": image,
                    "pre_findings_by_severity": pre_counts,
                    "post_findings_by_severity": post_counts,
                    "findings_relabeled": touched,
                }

            if n_reports % 100 == 0:
                w = wal_mb(db_path)
                max_wal = max(max_wal, w)
                elapsed = time.time() - t0
                rate = n_reports / max(elapsed, 0.001)
                remaining = len(images) - idx
                log(f"  done={n_reports} skip={n_skipped} idx={idx}/{len(images)} "
                    f"wal={w}MB rate={rate:.1f}/s eta={remaining / max(rate, 0.001):.0f}s "
                    f"findings={n_findings}")

            # The yield: gives coord/workers a writer slot.
            time.sleep(args.row_sleep)

    rw.close()
    log(f"  final: reports_updated={n_reports} findings_updated={n_findings} "
        f"skipped={n_skipped} aborted={aborted} max_wal_mb={max_wal}")
    return n_reports, n_findings, max_wal, (sample_diff or {})


# ---------------------------------------------------------------------------
def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="/home/user/scanners/work/chimangoscan.db")
    p.add_argument("--cache", default="/home/user/exposure-data/osv-api-cache-20260515.jsonl",
                   help="JSONL cache of CVE -> severity (resumed if exists, appended to).")
    p.add_argument("--backup", default=None,
                   help="Path to gz backup (default: /home/user/exposure-data/osv-backfill-v2-backup-<ts>.jsonl.gz)")
    p.add_argument("--api-workers", type=int, default=2,
                   help="Concurrent OSV API requests. Keep low to not overload coord (default 2).")
    p.add_argument("--row-sleep", type=float, default=0.1,
                   help="Sleep between UPDATEs (seconds) — yields writer slot to coord. Default 0.1 = 100ms.")
    p.add_argument("--wal-pause-mb", type=int, default=10_000,
                   help="Pause 30s if WAL exceeds this size in MB (default 10 GB).")
    p.add_argument("--wal-abort-mb", type=int, default=20_000,
                   help="Abort gracefully if WAL exceeds this size in MB (default 20 GB).")
    p.add_argument("--dry-run", action="store_true",
                   help="Skip the UPDATE stage; do collect + lookup only.")
    p.add_argument("--log", default=None)
    args = p.parse_args()

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    cache_path = Path(args.cache)
    backup_path = Path(args.backup or f"/home/user/exposure-data/osv-backfill-v2-backup-{ts}.jsonl.gz")
    log_fh = open(args.log, "a") if args.log else None

    def log(msg: str) -> None:
        line = f"[{datetime.utcnow().isoformat(timespec='seconds')}Z] {msg}"
        print(line, flush=True)
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    log(f"db={args.db}")
    log(f"cache={cache_path}")
    log(f"backup={backup_path}")
    log(f"api_workers={args.api_workers} row_sleep={args.row_sleep}s "
        f"wal_pause_mb={args.wal_pause_mb} wal_abort_mb={args.wal_abort_mb}")

    # Pre-flight: WAL sanity check.
    pre_wal = wal_mb(args.db)
    log(f"pre-flight WAL = {pre_wal} MB")
    if pre_wal > args.wal_abort_mb:
        log(f"WAL already above abort threshold {args.wal_abort_mb} MB — refusing to start. "
            f"Pause coord and run a wal_checkpoint(TRUNCATE) first.")
        return 2

    # Stage 1: read-only scan.
    per_image, all_ids = collect_targets(args.db, log)
    if not per_image:
        log("nothing to do — no OSV findings still marked unknown")
        return 0

    # Stage 2: cache + API lookup.
    cached_resolved, cached_seen = load_cache(cache_path, log)
    n_reused = sum(1 for i in all_ids if i in cached_resolved)
    log(f"  cache will reuse {n_reused} resolved ids for the {len(all_ids)} ids in scope")

    to_fetch = sorted(i for i in all_ids if i not in cached_seen)
    log(f"  {len(to_fetch)} ids still need an OSV API call")
    fetched = fetch_missing(to_fetch, cache_path, args.api_workers, log)
    resolved = {**cached_resolved, **fetched}
    log(f"resolved-in-scope: {sum(1 for i in all_ids if i in resolved)} / {len(all_ids)}")

    if not resolved:
        log("no usable severities — aborting before UPDATE")
        return 1

    if args.dry_run:
        log("--dry-run set; skipping Stage 3")
        return 0

    # Stage 3: apply updates.
    n_rep, n_fnd, max_wal, sample = apply_updates(
        args.db, per_image, resolved, backup_path, args, log
    )

    # Stage 4: post-verification (read-only count of remaining unknowns).
    log("== Stage 4: post-verification ==")
    try:
        ro = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True, timeout=30)
        cur = ro.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM reports WHERE report_json LIKE ? OR report_json LIKE ?",
            (LIKE_NEEDLE_A, LIKE_NEEDLE_B),
        )
        remaining = cur.fetchone()[0]
        ro.close()
    except sqlite3.OperationalError as e:
        remaining = -1
        log(f"  post-verification SELECT failed: {e}")

    backup_size = backup_path.stat().st_size if backup_path.exists() else 0
    log("== Summary ==")
    log(f"  reports updated:   {n_rep}")
    log(f"  findings updated:  {n_fnd}")
    log(f"  max WAL observed:  {max_wal} MB")
    log(f"  reports still containing osv unknown: {remaining}")
    log(f"  cached CVEs reused: {n_reused}")
    log(f"  newly fetched:     {len(fetched)}")
    log(f"  backup:            {backup_path} ({backup_size:,} bytes)")
    if sample:
        log(f"  sample image:      {sample.get('image')}")
        log(f"    before: {sample.get('pre_findings_by_severity')}")
        log(f"    after : {sample.get('post_findings_by_severity')}")
        log(f"    relabeled: {sample.get('findings_relabeled')}")

    # Note: NO PRAGMA wal_checkpoint here — checkpointing on this DB stalls the
    # coord. Let the separate WAL-checkpoint cron drain the WAL during the
    # next coord pause window.
    return 0


if __name__ == "__main__":
    sys.exit(main())
