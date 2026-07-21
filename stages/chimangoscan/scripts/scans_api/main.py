"""localhost — read-only API over the ChimangoScan pipeline state.

Runs in a Docker container with `network: host` so it can hit the
local Mongo/Neo4j/coord without any extra tunnels:


  - coord HTTP          → http://127.0.0.1:8918/stats
  - Mongo dockerhub_data → mongodb://127.0.0.1:27017                 (Stage I + II counts)
  - Neo4j (later)       → bolt://127.0.0.1:7687                      (graph queries)

Endpoints are public read-only. CORS is open for the dashboard origin. Each handler is
cached in-process for SHORT_TTL/LONG_TTL seconds to avoid hammering the DB.

Environment:
  QUEUE_DB     default /data/chimangoscan.db
  MONGO_URI    default mongodb://127.0.0.1:27017
  COORD_URL    default http://127.0.0.1:8918
  CORS_ORIGINS default http://localhost,http://localhost:5173
  PORT         default 8920
"""
from __future__ import annotations
import json
import os
import sqlite3
import time
from contextlib import asynccontextmanager, closing
from functools import lru_cache
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

QUEUE_DB = os.environ.get("QUEUE_DB", "/data/chimangoscan.db")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
COORD_URL = os.environ.get("COORD_URL", "http://127.0.0.1:8918")
CORS_ORIGINS = [o.strip() for o in os.environ.get(
    "CORS_ORIGINS",
    "http://localhost,http://localhost:5173"
).split(",") if o.strip()]
PORT = int(os.environ.get("PORT", "8920"))

SHORT_TTL = 30.0   # /stats, /recent, /top, /dit-live — coord under load, don't hammer it
LONG_TTL = 60.0    # /pipeline (Mongo counts on 12M docs)

_cache: dict[str, tuple[float, object]] = {}
_cache_lock = __import__("threading").Lock()


def _cached(key: str, ttl: float, fn, stale_ok: bool = True):
    """Return cached value if fresh. On miss, call fn() and cache. Thread-safe.
    stale_ok=True: if fn() raises, return stale value rather than propagating.
    """
    now = time.time()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and (now - hit[0]) < ttl:
            return hit[1]
    try:
        val = fn()
        with _cache_lock:
            _cache[key] = (now, val)
        return val
    except Exception as exc:
        with _cache_lock:
            stale = _cache.get(key)
        if stale_ok and stale:
            return stale[1]
        raise


def _open_db() -> sqlite3.Connection:
    # uri=True + immutable=0 + read-only avoids holding write locks against the coord
    uri = f"file:{QUEUE_DB}?mode=ro"
    c = sqlite3.connect(uri, uri=True, timeout=10.0, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def _http_client() -> httpx.Client:
    return httpx.Client(timeout=20.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # warm caches so the first hits are fast (containers snapshot can take 5–10 s)
    import threading
    def _prewarm():
        try:
            _stats_from_coord()
        except Exception:
            pass
        try:
            _cached("containers:full", LONG_TTL, _build_containers_snapshot)
        except Exception as e:
            print(f"prewarm containers failed: {e}", flush=True)
    threading.Thread(target=_prewarm, daemon=True).start()
    # also refresh containers cache every minute in the background
    def _refresher():
        tick = 0
        while True:
            time.sleep(60)
            tick += 1
            try:
                if "containers:full" in _cache:
                    t, v = _cache["containers:full"]
                    if (time.time() - t) > 50:
                        _cache["containers:full"] = (0, v)
                _cached("containers:full", LONG_TTL, _build_containers_snapshot)
            except Exception as e:
                print(f"refresh containers failed: {e}", flush=True)
            # PASSIVE WAL checkpoint every 5 min to keep WAL size manageable
            if tick % 5 == 0:
                try:
                    c = sqlite3.connect(QUEUE_DB, timeout=5)
                    c.execute("PRAGMA wal_checkpoint(PASSIVE)")
                    c.close()
                except Exception:
                    pass
    threading.Thread(target=_refresher, daemon=True).start()
    yield


app = FastAPI(
    title="localhost",
    description="Read-only API over the ChimangoScan pipeline state.",
    version="0.1.5",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "OPTIONS"],
    allow_headers=["*"],
    max_age=600,
)


# ── handlers ─────────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
def health():
    # cheap check on every dep
    deps = {}
    try:
        c = _open_db()
        c.execute("SELECT 1").fetchone()
        c.close()
        deps["queue_db"] = "ok"
    except Exception as e:
        deps["queue_db"] = f"err: {type(e).__name__}: {e}"
    try:
        with _http_client() as h:
            r = h.get(f"{COORD_URL}/stats", timeout=5.0)
            deps["coord"] = "ok" if r.status_code == 200 else f"http {r.status_code}"
    except Exception as e:
        deps["coord"] = f"err: {type(e).__name__}: {e}"
    return {"status": "ok" if all(v == "ok" for v in deps.values()) else "degraded",
            "deps": deps,
            "ts": time.time()}


def _stats_from_coord() -> dict:
    """Authoritative queue counts come from the coord, not from SQLite directly
    (the coord may have rows in flight that SQLite WAL hasn't checkpointed yet).
    Short timeout so a busy coord doesn't block the whole endpoint; caller uses
    stale_ok=True to return cached data on timeout."""
    with _http_client() as h:
        r = h.get(f"{COORD_URL}/stats", timeout=3.0)
        r.raise_for_status()
        return r.json()


@app.get("/api/v1/queue/stats")
def queue_stats():
    """Counts by status + total findings, served from the coord."""
    return _cached("stats", SHORT_TTL, _stats_from_coord, stale_ok=True)


@app.get("/api/v1/queue/recent")
def queue_recent(limit: int = Query(30, ge=1, le=200)):
    """Most-recent N completed reports (image, findings count, finished_at)."""
    def fn():
        c = _open_db()
        rows = c.execute(
            """SELECT image, n_findings, finished_at
               FROM reports
               ORDER BY finished_at DESC
               LIMIT ?""", (limit,)
        ).fetchall()
        c.close()
        return [{"image": r["image"], "findings": r["n_findings"], "finished_at": r["finished_at"]}
                for r in rows]
    return _cached(f"recent:{limit}", SHORT_TTL, fn)


@app.get("/api/v1/queue/top")
def queue_top(
    limit: int = Query(100, ge=1, le=5000),
    status: Optional[str] = Query(None, description="filter: pending|done|running|skipped|failed"),
    q: Optional[str] = Query(None, description="substring match on image (case-insensitive)"),
):
    """Top N jobs ordered by weight desc. Optional status + substring filters."""
    def fn():
        c = _open_db()
        clauses = []
        params: list = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if q:
            clauses.append("LOWER(image) LIKE ?")
            params.append(f"%{q.lower()}%")
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (f"SELECT image, weight, status, attempts FROM jobs "
               f"{where} ORDER BY weight DESC, id LIMIT ?")
        params.append(limit)
        rows = c.execute(sql, params).fetchall()
        c.close()
        return [dict(r) for r in rows]
    key = f"top:{limit}:{status or 'all'}:{q or ''}"
    return _cached(key, SHORT_TTL, fn)


@app.get("/api/v1/queue/timeline")
def queue_timeline(
    bucket_minutes: int = Query(60, ge=5, le=1440, description="advisory; cron emits fixed 60min shape"),
    hours: int = Query(48, ge=1, le=168, description="advisory; cron emits fixed 48h shape"),
):
    """Per-hour count of reports finalized in the last 48h.

    Reads hourly_48h from /data/scanner-report/dit-live.json (refreshed by
    an offline cron on host1 every minute). Avoids slow GROUP BY
    on the 31GB WAL of reports.finished_at. The bucket_minutes/hours
    parameters are advisory: the cron emits a fixed shape (60-min buckets,
    48 of them, oldest -> newest). Returns empty buckets list if the file
    is unreadable.
    """
    def fn():
        try:
            with open("/data/scanner-report/dit-live.json", "rt") as f:
                d = json.load(f)
            raw = d.get("hourly_48h") or []
            buckets = [{"ts": h.get("hour"), "done": int(h.get("n_reports") or 0), "findings": 0}
                       for h in raw if h.get("hour")]
        except Exception:
            buckets = []
        return {"bucket_minutes": 60, "hours": 48, "buckets": buckets}
    return _cached("timeline:hourly_48h", SHORT_TTL, fn)


@app.get("/api/v1/scanner-stats")
def scanner_stats():
    """Aggregated findings + severity counts by scanner across ALL reports.

    Reads the pre-computed file built by an offline cron on host1
    (every 15 min) at
    /data/scanner-report/dit-scanner-stats.json. This sidesteps the
    per-container ``/api/v1/containers`` top-500 cap (which only filled
    ``by_scanner`` for the top 500 containers, summing to ~1.3M findings)
    and exposes the full ~49M-finding aggregate to the dashboard chart
    "findings por scanner empilhado por severidade".

    Shape::

        {
          "generated_at": "...Z",
          "n_reports": int,
          "scanners": {
            "syft":   {"c","h","m","l","i","u","n_findings","n_runs","n_ok","n_err"},
            "trivy":  {...}, "grype": {...}, "osv": {...},
            "dockle": {...}, "trufflehog": {...}
          },
          "build_seconds": float
        }

    Falls back to ``{generated_at: None, scanners: {}}`` (and an ``error``
    string) if the file is missing/unreadable — no slow DB scan.
    """
    def fn():
        try:
            with open("/data/scanner-report/dit-scanner-stats.json", "rt") as f:
                return json.load(f)
        except Exception as exc:
            return {"generated_at": None, "n_reports": 0,
                    "scanners": {}, "error": str(exc)}
    return _cached("scanner-stats", SHORT_TTL, fn)


@app.get("/api/v1/severity")
def severity():
    """Severity aggregates across ALL containers + vuln histogram by (c+h)."""
    def fn():
        snap = _cached("containers:full", LONG_TTL, _build_containers_snapshot)
        containers_list = snap.get("containers") or []
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                       "info": 0, "unknown": 0}
        short_to_long = {"c": "critical", "h": "high", "m": "medium",
                         "l": "low", "i": "info", "u": "unknown"}
        # histogram bins on (critical + high) per container
        bins = [
            {"label": "0",       "min": 0,   "max": 0,        "count": 0},
            {"label": "1-5",     "min": 1,   "max": 5,        "count": 0},
            {"label": "6-20",    "min": 6,   "max": 20,       "count": 0},
            {"label": "21-100",  "min": 21,  "max": 100,      "count": 0},
            {"label": "101-500", "min": 101, "max": 500,      "count": 0},
            {"label": ">500",    "min": 501, "max": 10**12,   "count": 0},
        ]
        total_findings = 0
        for ct in containers_list:
            ct_c = 0
            ct_h = 0
            for _sc, d in (ct.get("by_scanner") or {}).items():
                for short, longn in short_to_long.items():
                    v = int(d.get(short) or 0)
                    by_severity[longn] += v
                    total_findings += v
                ct_c += int(d.get("c") or 0)
                ct_h += int(d.get("h") or 0)
            ch = ct_c + ct_h
            for b in bins:
                if b["min"] <= ch <= b["max"]:
                    b["count"] += 1
                    break
        by_severity_short = {
            "c": by_severity["critical"],
            "h": by_severity["high"],
            "m": by_severity["medium"],
            "l": by_severity["low"],
            "i": by_severity["info"],
            "u": by_severity["unknown"],
        }
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "n_reports": len(containers_list),
            "total_findings": total_findings,
            "by_severity": by_severity,
            "by_severity_short": by_severity_short,
            "vuln_histogram": bins,
        }
    return _cached("severity", LONG_TTL, fn)


def _mongo_counts() -> dict:
    """Stage I (crawl) + Stage II (build) counts from Mongo. Fast — uses indexes."""
    from pymongo import MongoClient
    cli = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    db = cli["dockerhub_data"]
    total = db.repositories_data.estimated_document_count()
    unbuilt = db.repositories_data.count_documents({"graph_built_at": None})
    built = total - unbuilt
    keywords = db.crawler_keywords.estimated_document_count()
    tags = db.tags_data.estimated_document_count()
    images = db.images_data.estimated_document_count()
    cli.close()
    return {
        "crawl": {
            "keywords": keywords,
            "repos_total": total,
            "tags_total": tags,
            "images_total": images,
        },
        "build": {
            "repos_done": built,
            "repos_pending": unbuilt,
            "repos_pct": (built / total * 100) if total else 0,
        },
    }


@app.get("/api/v1/pipeline")
def pipeline():
    """End-to-end pipeline status: crawl + build + scan in one payload."""
    def fn():
        m = _mongo_counts()
        s = _stats_from_coord()
        return {
            "crawl": m["crawl"],
            "build": m["build"],
            "scan": {
                "total": s.get("total"),
                "pending": s.get("pending"),
                "running": s.get("running"),
                "done": s.get("done"),
                "skipped": s.get("skipped"),
                "failed": s.get("failed"),
                "reports": s.get("reports"),
                "findings": s.get("findings"),
            },
            "ts": time.time(),
        }
    return _cached("pipeline", LONG_TTL, fn)


SCANNER_LIST = ["syft", "trivy", "grype", "osv", "dockle", "trufflehog"]
SEV_KEYS = {"critical": "c", "high": "h", "medium": "m", "low": "l",
            "info": "i", "informational": "i", "negligible": "i", "unknown": "u"}


CONTAINERS_FULL_PATH = "/data/scanner-report/dit-containers-full.json"
CONTAINERS_FULL_MAX_AGE = 2 * 60 * 60  # 2h: depois disso, fallback p/ slow path


def _load_containers_from_static() -> dict | None:
    """Read the pre-parsed dit-containers.json the cron writes every minute.
    Way cheaper than re-parsing thousands of report JSONs in-process."""
    try:
        with open("/data/scanner-report/dit-containers.json", "rt") as f:
            return json.load(f)
    except Exception:
        return None


def _load_containers_full_from_file() -> dict | None:
    """Loads dit-containers-full.json built offline on host1 (every 10 min).
    It has by_scanner POPULATED for all ~21k rows — avoiding the on-demand
    reparsing of ~2GB that costs 5-10min.

    Returns None if the file does not exist, is corrupt, or is >2h old
    (cold-start grace: in those cases it falls back to the slow path).
    """
    try:
        st = os.stat(CONTAINERS_FULL_PATH)
    except FileNotFoundError:
        return None
    except Exception as exc:
        print(f"_load_containers_full_from_file: stat failed: {exc!r}", flush=True)
        return None
    age = time.time() - st.st_mtime
    if age > CONTAINERS_FULL_MAX_AGE:
        print(f"_load_containers_full_from_file: stale ({age:.0f}s > {CONTAINERS_FULL_MAX_AGE}s), falling back",
              flush=True)
        return None
    try:
        with open(CONTAINERS_FULL_PATH, "rt") as f:
            d = json.load(f)
    except Exception as exc:
        print(f"_load_containers_full_from_file: read failed: {exc!r}", flush=True)
        return None
    ct = d.get("containers")
    if not isinstance(ct, list) or not ct:
        return None
    d.setdefault("scanners", SCANNER_LIST)
    d.setdefault("n_total_scanned", len(ct))
    return d


# Full-scan of report_json parses ALL ~20k rows (~2 GB cumulative). The streaming
# sqlite3 cursor yields rows one-at-a-time, so peak memory stays ~one report_json
# (a few MB). The result is cached for LONG_TTL (60 s) and warmed by the
# background refresher thread, so cost is paid once per minute.


def _build_containers_snapshot() -> dict:
    """Prefer the offline cron-built dit-containers-full.json (cheap I/O).
    Falls back to slow DB reparsing only when the file is missing/stale —
    happens at cold start, before the first cron tick.
    """
    pre = _load_containers_full_from_file()
    if pre is not None:
        return pre
    print("_build_containers_snapshot: pre-built file missing/stale, "
          "rebuilding from DB (this will take minutes)", flush=True)
    return _build_containers_snapshot_slow()


def _build_containers_snapshot_slow() -> dict:
    """Build the per-container snapshot directly from SQLite. Slow (5-10min)
    fallback used only when the cron file isn't available — kept identical
    to the old behavior so the API stays correct during cold start.
    """
    import datetime as _dt
    t0 = time.time()
    try:
        c = _open_db()
    except Exception as exc:
        print(f"_build_containers_snapshot_slow: db open failed ({exc!r}), using static fallback", flush=True)
        cached = _load_containers_from_static()
        if cached and isinstance(cached.get("containers"), list):
            cached.setdefault("n_total_scanned", len(cached["containers"]))
            cached.setdefault("scanners", SCANNER_LIST)
            return cached
        raise

    with closing(c):
        n_total = c.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
        # Streaming cursor: sqlite3 yields rows on-demand, so peak memory is
        # ~one report_json (up to a few MB), not the entire 2 GB table.
        cur = c.execute(
            "SELECT image, report_json, n_findings, finished_at FROM reports"
        )
        containers: list[dict] = []
        for image, report_json_str, n_findings, finished_at in cur:
            try:
                r = json.loads(report_json_str) if report_json_str else {}
            except Exception:
                r = {}
            tgt = r.get("target") or {}
            meta = tgt.get("meta") or {}
            exposure = meta.get("exposure")
            if exposure is None:
                exposure = tgt.get("weight")
            try:
                exposure = float(exposure or 0)
            except Exception:
                exposure = 0.0
            fa = r.get("finished_at")
            if not fa and finished_at:
                try:
                    fa = _dt.datetime.fromtimestamp(float(finished_at), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                except Exception:
                    fa = None
            merged = len(r.get("findings") or []) if r else int(n_findings or 0)
            by_scanner: dict = {}
            for inv in (r.get("invocations") or []):
                sc = inv.get("scanner")
                if not sc:
                    continue
                d = {"n": int(inv.get("findings") or 0),
                     "c": 0, "h": 0, "m": 0, "l": 0, "i": 0, "u": 0,
                     "status": inv.get("status") or ""}
                for sev, cnt in (inv.get("findings_by_severity") or {}).items():
                    k = SEV_KEYS.get(str(sev).lower())
                    if k:
                        try:
                            d[k] += int(cnt or 0)
                        except Exception:
                            pass
                by_scanner[sc] = d
            if float(exposure).is_integer():
                exposure = int(exposure)
            containers.append({
                "image": image,
                "exposure": exposure,
                "finished_at": fa,
                "merged": merged,
                "by_scanner": by_scanner,
            })

    containers.sort(key=lambda x: x["exposure"], reverse=True)
    for i, ct in enumerate(containers):
        ct["rank"] = i + 1
    elapsed = time.time() - t0
    n_with_by = sum(1 for ct in containers if ct["by_scanner"])
    print(f"_build_containers_snapshot: {len(containers)} containers, "
          f"{n_with_by} with by_scanner, n_total={n_total}, elapsed={elapsed:.2f}s",
          flush=True)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_total_scanned": int(n_total),
        "scanners": SCANNER_LIST,
        "containers": containers,
    }


@app.get("/api/v1/containers")
def containers(
    limit: int = Query(3000, ge=1, le=100000),
    offset: int = Query(0, ge=0),
    q: Optional[str] = Query(None, description="substring filter on image"),
):
    """Every scanned container with per-scanner severity counts. No artificial cap."""
    def fn():
        return _cached("containers:full", LONG_TTL, _build_containers_snapshot)
    snap = fn()
    items = snap["containers"]
    if q:
        ql = q.lower()
        items = [c for c in items if ql in c["image"].lower()]
    n_shown = len(items)
    items = items[offset:offset + limit]
    return {
        "generated_at": snap["generated_at"],
        "n_total_scanned": snap["n_total_scanned"],
        "n_shown": n_shown,
        "offset": offset,
        "limit": limit,
        "scanners": snap["scanners"],
        "containers": items,
    }


def _machines_snapshot() -> dict:
    """Per-host state by parsing the cron-generated dit-live.json (it has
    workers_alive + load + ram via probe). Cheap to read; falls back to
    nulls if the file isn't there."""
    out = {"hosts": [], "ts": time.time()}
    try:
        with open("/data/scanner-report/dit-live.json", "rt") as f:
            d = json.load(f)
            for m in d.get("machines") or []:
                out["hosts"].append({
                    "host": m.get("host"),
                    "role": m.get("role"),
                    "workers_alive": m.get("workers_alive"),
                    "online": m.get("online"),
                    "load1": m.get("load"),
                    "ram_avail_mb": m.get("ram_avail_mb"),
                })
    except Exception:
        pass
    return out


@app.get("/api/v1/machines")
def machines():
    """List of worker hosts and their last-known state."""
    return _cached("machines", SHORT_TTL, _machines_snapshot)


@app.get("/api/v1/dit-live")
def dit_live():
    """Drop-in replacement for scanner-report/dit-live.json.

    Returns the same shape the static page consumes today: queue counts +
    machines + recent + history fields. History comes from the existing JSON
    file (which the cron is still updating until we replace it); everything
    else is fresh.
    """
    def fn():
        stats = _cached("stats", SHORT_TTL, _stats_from_coord, stale_ok=True)
        recent = queue_recent(limit=30) if callable(queue_recent) else []
        # piggyback on the cron-generated history while we transition; the file
        # is mounted via volume below.
        history = []
        try:
            with open("/data/scanner-report/dit-live.json", "rt") as f:
                prev = json.load(f)
                history = prev.get("history", [])[-30:]
        except Exception:
            history = []
        return {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "queue": stats,
            "recent": recent,
            "history": history,
            "rate_per_min": _estimate_rate(history),
        }
    return _cached("dit-live", SHORT_TTL, fn)


def _estimate_rate(history: list) -> Optional[float]:
    if len(history) < 2:
        return None
    h = history[-8:]
    first, last = h[0], h[-1]
    try:
        t0 = time.mktime(time.strptime(first["ts"], "%Y-%m-%dT%H:%M:%SZ"))
        t1 = time.mktime(time.strptime(last["ts"], "%Y-%m-%dT%H:%M:%SZ"))
        dt_min = (t1 - t0) / 60.0
        d_done = last["done"] - first["done"]
        if dt_min < 1 or d_done < 0:
            return None
        return round(d_done / dt_min, 2)
    except Exception:
        return None
