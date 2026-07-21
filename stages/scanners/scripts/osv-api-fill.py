#!/usr/bin/env python3
"""Phase 3-ALT: enrich OSV findings severity via api.osv.dev/v1/vulns/<id>.

Replaces the heavyweight docker pull + rescan approach. For each OSV finding in
reports.report_json with severity == "unknown", look the CVE/GHSA/etc. up on
the public OSV API, parse the CVSS vector with the same logic the local
adapter uses, and write the new severity/cvss back to the report. Then
recompute the OSV invocation's findings_by_severity aggregate.

Idempotent: safe to re-run; only touches findings still marked unknown.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import random
import re
import shutil
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
# (kept in-line so this script is self-contained and runs without the package
#  on hosts that only have Python).
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


# ---------------------------------------------------------------------------
# OSV API client
# ---------------------------------------------------------------------------
OSV_URL = "https://api.osv.dev/v1/vulns/{id}"

_rate_lock = threading.Lock()
_last_request_ts: list[float] = [0.0]
_min_interval = 1.0 / 50.0  # 50 req/s ceiling, shared across workers


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
            req = Request(OSV_URL.format(id=vid), headers={"User-Agent": "ditector-osv-fill/1"})
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


def severity_of_vuln(v: dict) -> tuple[str, float | None]:
    score = _cvss_from_vuln(v)
    if score is not None:
        return _bucket_from_cvss(score), score
    return _qual_severity(v), None


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
LIKE_NEEDLE = '%"scanner":"osv"%"severity":"unknown"%'


def iter_target_rows(db_path: str):
    """Yield (image, report_json) rows that contain at least one OSV finding
    still marked unknown. Uses a LIKE pre-filter to skip rows quickly without
    parsing JSON for the ~25k reports that have no OSV findings."""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(
        "SELECT image, report_json FROM reports "
        "WHERE report_json LIKE ? OR report_json LIKE ?",
        (LIKE_NEEDLE, '%"severity":"unknown"%"scanner":"osv"%'),
    )
    while True:
        rows = cur.fetchmany(500)
        if not rows:
            break
        for r in rows:
            yield r["image"], r["report_json"]
    con.close()


def collect_unknown_ids(db_path: str) -> tuple[set[str], dict[str, int], int]:
    """Single pass: collect distinct OSV finding ids that still have severity
    'unknown', return (ids, per-image-counts, n_findings)."""
    ids: set[str] = set()
    per_image: dict[str, int] = {}
    n_findings = 0
    for image, rj in iter_target_rows(db_path):
        try:
            j = json.loads(rj) if rj else None
        except (TypeError, ValueError):
            continue
        if not j:
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
            per_image[image] = unk_here
            n_findings += unk_here
    return ids, per_image, n_findings


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def stage_collect(args, log) -> tuple[set[str], dict[str, int]]:
    log("== Stage 1: scan reports for OSV findings still unknown ==")
    t0 = time.time()
    ids, per_image, n_findings = collect_unknown_ids(args.db)
    log(f"  {len(per_image)} reports / {n_findings} findings / {len(ids)} distinct CVE-ish ids "
        f"(scan took {time.time() - t0:.1f}s)")
    return ids, per_image


def stage_lookup(ids: set[str], cache_path: Path, args, log) -> dict[str, tuple[str, float | None]]:
    log(f"== Stage 2: query OSV API for {len(ids)} ids ({args.workers} workers) ==")
    cve_to_sev: dict[str, tuple[str, float | None]] = {}
    raw_cache: dict[str, dict | str] = {}

    # Resume from a previous cache file if requested.
    if args.resume and cache_path.exists():
        with cache_path.open() as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                vid = entry.get("id")
                if not vid:
                    continue
                if entry.get("status") == "ok":
                    cve_to_sev[vid] = (entry["severity"], entry.get("cvss"))
                raw_cache[vid] = entry
        log(f"  resumed {len(raw_cache)} prior lookups from {cache_path}")
        ids = {i for i in ids if i not in raw_cache}
        log(f"  {len(ids)} ids still to fetch")

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_fh = cache_path.open("a", buffering=1)
    cache_lock = threading.Lock()

    stats = {"ok": 0, "not_found": 0, "error": 0}
    t0 = time.time()
    done = 0
    total = len(ids)

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

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(worker, vid) for vid in ids]
        for fut in as_completed(futs):
            try:
                vid, status, sev, entry = fut.result()
            except Exception as e:  # noqa: BLE001
                log(f"  worker crash: {e}")
                continue
            stats[status if status in stats else "error"] += 1
            if sev is not None:
                cve_to_sev[vid] = sev
            with cache_lock:
                cache_fh.write(json.dumps(entry) + "\n")
            done += 1
            if done % 500 == 0 or done == total:
                rate = done / max(time.time() - t0, 0.001)
                log(f"  {done}/{total} ok={stats['ok']} 404={stats['not_found']} err={stats['error']} ({rate:.1f}/s)")

    cache_fh.close()
    log(f"  finished: ok={stats['ok']} not_found={stats['not_found']} error={stats['error']} "
        f"({time.time() - t0:.1f}s)")
    log(f"  cache: {cache_path}")
    return cve_to_sev


def recompute_invocation_bys(report: dict) -> None:
    """Recompute findings_by_severity for the OSV invocation in this report."""
    osv_counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "unknown": 0}
    for fnd in report.get("findings") or []:
        if fnd.get("scanner") != "osv":
            continue
        sev = fnd.get("severity") or "unknown"
        osv_counts[sev] = osv_counts.get(sev, 0) + 1
    # Drop zero buckets to match the existing schema (which only stores non-zero keys).
    osv_counts = {k: v for k, v in osv_counts.items() if v > 0}
    for inv in report.get("invocations") or []:
        if inv.get("scanner") == "osv":
            inv["findings_by_severity"] = osv_counts
            return


def stage_apply(cve_to_sev: dict[str, tuple[str, float | None]],
                target_images: dict[str, int],
                backup_path: Path,
                args,
                log) -> tuple[int, int, dict[str, Any]]:
    log("== Stage 3: backup + apply updates ==")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    images = list(target_images.keys())
    log(f"  will touch {len(images)} reports; backup -> {backup_path}")

    sample_diff = None
    n_reports_updated = 0
    n_findings_updated = 0
    batch: list[tuple[str, str]] = []
    written_backup = 0

    with gzip.open(backup_path, "wt") as bk:
        for image in images:
            cur.execute("SELECT report_json FROM reports WHERE image=?", (image,))
            row = cur.fetchone()
            if not row or not row["report_json"]:
                continue
            try:
                j = json.loads(row["report_json"])
            except ValueError:
                continue

            # Backup the original row before mutating anything.
            bk.write(json.dumps({"image": image, "report_json": j}, separators=(",", ":")) + "\n")
            written_backup += 1

            # Snapshot OSV invocation counts pre-mutation for sample diff.
            pre_counts = None
            for inv in j.get("invocations") or []:
                if inv.get("scanner") == "osv":
                    pre_counts = dict(inv.get("findings_by_severity") or {})
                    break

            touched_here = 0
            for fnd in j.get("findings") or []:
                if fnd.get("scanner") != "osv":
                    continue
                if fnd.get("severity") != "unknown":
                    continue
                vid = fnd.get("id")
                sev = cve_to_sev.get(vid)
                if not sev:
                    continue
                sevname, score = sev
                if sevname == "unknown":
                    continue
                fnd["severity"] = sevname
                if score is not None:
                    fnd["cvss"] = score
                touched_here += 1

            if not touched_here:
                continue

            recompute_invocation_bys(j)

            post_counts = None
            for inv in j.get("invocations") or []:
                if inv.get("scanner") == "osv":
                    post_counts = dict(inv.get("findings_by_severity") or {})
                    break

            if sample_diff is None and touched_here > 0:
                sample_diff = {
                    "image": image,
                    "pre_findings_by_severity": pre_counts,
                    "post_findings_by_severity": post_counts,
                    "findings_relabeled": touched_here,
                }

            batch.append((json.dumps(j, separators=(",", ":")), image))
            n_reports_updated += 1
            n_findings_updated += touched_here

            if len(batch) >= args.batch:
                cur.executemany("UPDATE reports SET report_json=? WHERE image=?", batch)
                con.commit()
                log(f"  batch commit: {n_reports_updated} reports / {n_findings_updated} findings")
                batch.clear()

        if batch:
            cur.executemany("UPDATE reports SET report_json=? WHERE image=?", batch)
            con.commit()
            log(f"  final batch: {n_reports_updated} reports / {n_findings_updated} findings")
            batch.clear()

    # advance the WAL readpoint to reduce work for the next cron;
    # PASSIVE does not block other writers (coord) — TRUNCATE is left to
    # a separate WAL-checkpoint cron that pauses the coordinator.
    try:
        r = cur.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        log(f"  WAL checkpoint after batch UPDATE: busy={r[0]} total={r[1]} done={r[2]}")
    except sqlite3.DatabaseError as e:
        log(f"  WAL checkpoint failed (non-fatal): {e}")

    con.close()
    log(f"  backup wrote {written_backup} reports to {backup_path}")
    return n_reports_updated, n_findings_updated, (sample_diff or {})


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--db", default="/home/user/scanners/work/ditector.db")
    p.add_argument("--workers", type=int, default=50)
    p.add_argument("--batch", type=int, default=200)
    p.add_argument("--cache", default=None,
                   help="Path to JSONL cache (default: /home/user/exposure-data/osv-api-cache-<ts>.jsonl)")
    p.add_argument("--backup", default=None,
                   help="Path to gz backup (default: /home/user/exposure-data/osv-api-fill-backup-<ts>.jsonl.gz)")
    p.add_argument("--resume", action="store_true",
                   help="If --cache exists, skip ids already fetched.")
    p.add_argument("--dry-run", action="store_true",
                   help="Skip the UPDATE step; still does collect + lookup + backup.")
    p.add_argument("--log", default=None, help="Optional log file (also prints to stdout)")
    args = p.parse_args()

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    cache_path = Path(args.cache or f"/home/user/exposure-data/osv-api-cache-{ts}.jsonl")
    backup_path = Path(args.backup or f"/home/user/exposure-data/osv-api-fill-backup-{ts}.jsonl.gz")

    log_fh = open(args.log, "a") if args.log else None

    def log(msg: str) -> None:
        line = f"[{datetime.utcnow().isoformat(timespec='seconds')}Z] {msg}"
        print(line, flush=True)
        if log_fh:
            log_fh.write(line + "\n")
            log_fh.flush()

    log(f"db={args.db} workers={args.workers} batch={args.batch}")

    ids, per_image = stage_collect(args, log)
    if not ids:
        log("nothing to do — no OSV findings still marked unknown")
        return 0

    cve_to_sev = stage_lookup(ids, cache_path, args, log)
    if not cve_to_sev:
        log("API returned no usable severities; aborting before UPDATE")
        return 1

    log(f"  resolved {len(cve_to_sev)}/{len(ids)} ids to a non-unknown severity")

    if args.dry_run:
        log("--dry-run set: skipping UPDATE stage")
        return 0

    n_rep, n_fnd, sample = stage_apply(cve_to_sev, per_image, backup_path, args, log)

    backup_size = backup_path.stat().st_size if backup_path.exists() else 0
    log("== Summary ==")
    log(f"  reports updated:  {n_rep}")
    log(f"  findings updated: {n_fnd}")
    log(f"  backup:           {backup_path} ({backup_size:,} bytes)")
    if sample:
        log(f"  sample image:     {sample.get('image')}")
        log(f"    before: {sample.get('pre_findings_by_severity')}")
        log(f"    after : {sample.get('post_findings_by_severity')}")
        log(f"    relabeled findings: {sample.get('findings_relabeled')}")

    # Post-verification count.
    log("== Post-verification ==")
    con = sqlite3.connect(args.db)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM reports WHERE report_json LIKE ?", (LIKE_NEEDLE,))
    remaining = cur.fetchone()[0]
    con.close()
    log(f"  reports still containing an OSV unknown finding: {remaining}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
