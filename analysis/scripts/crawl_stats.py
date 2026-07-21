#!/usr/bin/env python3
"""
Crawl-wide statistics from the Stage I MongoDB (`dockerhub_data`): every
number the paper reports about the crawl itself, none of which depends on the
scan database.

  - repository / tag / image / prefix-query totals (paper Sec. 3.1, Table
    "Dataset summary")
  - total cumulative pulls and the pull-count distribution buckets of Table
    "Repository pull-count distribution" (>=1B ... <1k, repos and % of pulls)
  - pull-count median / p99 / max over the FULL crawl (nearest-rank, over
    repositories with a recorded pull count). NOTE: the paper's Section 3.1
    median (198) / p99 (160,061) are over the exposure-ranked RESOLVED HEAD,
    not the full crawl (whose median is ~62, dragged down by the long tail of
    barely-pulled repositories); those are emitted by export_plan_crawl.py.
    The fields below are the full-crawl distribution behind Table 2's buckets.
  - `last_updated` coverage. NOTE: repositories_data.last_updated is empty in
    the released dump; the paper's 95.7% is over a different population and is
    not reproduced here.

Everything is computed server-side with aggregation pipelines (allowDiskUse);
the 12.7M-document repositories collection is never loaded into memory. The
percentile/median queries are index-order skips on the `pull_count` index.

ENVIRONMENT
  MONGO_URI  mongodb://127.0.0.1:27017
  MONGO_DB   dockerhub_data
  OUT        crawl_stats.json
"""
import json
import math
import os
import sys
import time

from pymongo import MongoClient
from pymongo.errors import AutoReconnect

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.environ.get("MONGO_DB", "dockerhub_data")
OUT = os.environ.get("OUT", "crawl_stats.json")

RECORDED = {"pull_count": {"$type": "number"}}
BOUNDS = [0, 1_000, 100_000, 1_000_000, 10_000_000, 100_000_000,
          1_000_000_000]
LABELS = ["<1k", "1k-100k", "100k-1M", "1M-10M", "10M-100M", "100M-1B",
          ">=1B"]


def pull_at_rank(repos, rank, _tries=4):
    """pull_count of the ascending rank-th repository (1-based), by index skip.

    The skip walks the pull_count index (created by the mongo stage before this
    runs), so it stays cheap and low-memory even at rank ~6M. A flaky mongod can
    still drop the socket mid-walk; retry a few times on AutoReconnect."""
    if rank < 1:
        return None
    for attempt in range(_tries):
        try:
            doc = next(repos.find(RECORDED, {"pull_count": 1, "_id": 0})
                       .sort("pull_count", 1).skip(rank - 1).limit(1), None)
            return int(doc["pull_count"]) if doc else None
        except AutoReconnect:
            if attempt == _tries - 1:
                raise
            time.sleep(3)


def main():
    # socketTimeoutMS=0: the median/p99 index-skips can run for minutes on a
    # 12.7M-doc crawl; do not let the client abort a slow-but-live query.
    # retryReads lets a dropped read reconnect once on its own.
    cli = MongoClient(MONGO_URI, serverSelectionTimeoutMS=120000,
                      socketTimeoutMS=0, retryReads=True)
    db = cli[MONGO_DB]
    repos = db.repositories_data

    total_repos = repos.count_documents({})
    n_recorded = repos.count_documents(RECORDED)
    n_last_updated = repos.count_documents(
        {"last_updated": {"$exists": True, "$nin": [None, ""]}})

    grand = list(repos.aggregate(
        [{"$match": RECORDED},
         {"$group": {"_id": None, "pulls": {"$sum": "$pull_count"}}}],
        allowDiskUse=True))
    total_pulls = int(grand[0]["pulls"]) if grand else 0

    raw = {b["_id"]: b for b in repos.aggregate(
        [{"$match": RECORDED},
         {"$bucket": {"groupBy": "$pull_count", "boundaries": BOUNDS,
                      "default": BOUNDS[-1],
                      "output": {"repos": {"$sum": 1},
                                 "pulls": {"$sum": "$pull_count"}}}}],
        allowDiskUse=True)}
    buckets = []
    for label, lo in zip(reversed(LABELS), reversed(BOUNDS)):
        b = raw.get(lo, {"repos": 0, "pulls": 0})
        buckets.append({
            "bucket": label,
            "repos": int(b["repos"]),
            "pulls": int(b["pulls"]),
            "pct_pulls": round(100.0 * b["pulls"] / total_pulls, 1)
            if total_pulls else 0.0})

    stats = {
        "repositories_total": total_repos,
        "repositories_with_pull_count": n_recorded,
        "total_pulls": total_pulls,
        "prefix_queries": db.crawler_keywords.count_documents({}),
        "tags_total": db.tags_data.count_documents({}),
        "images_total": db.images_data.count_documents({}),
        "last_updated_coverage_pct": round(
            100.0 * n_last_updated / total_repos, 1) if total_repos else 0.0,
        "pull_median_fullcrawl": pull_at_rank(repos, (n_recorded + 1) // 2),
        "pull_p99_fullcrawl": pull_at_rank(repos, math.ceil(0.99 * n_recorded)),
        "pull_max_fullcrawl": pull_at_rank(repos, n_recorded),
        "pull_buckets": buckets}
    cli.close()

    with open(OUT, "w") as fh:
        json.dump(stats, fh, indent=1)
    sys.stderr.write("wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
