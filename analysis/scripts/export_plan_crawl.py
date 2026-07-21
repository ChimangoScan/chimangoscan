#!/usr/bin/env python3
"""
Export `plan_crawl.json`, the crawl-wide CDF input of plan_figs.py
(fig_crawl_cdf):

  pull            repository pull counts, descending -- a systematic 1-in-K
                  sample of ALL crawled repositories sorted by pull count
                  (repositories without a recorded pull count sort last, as 0).
                  A systematic sample of the sorted list preserves the CDF and
                  always keeps the maximum.
  depweight_base  dependency weight (downstream image count) of every base
                  image, descending. This is a Stage II layer-graph quantity,
                  not stored in MongoDB: it is read from the exposure ranking
                  (rows with dependency_weight > 0). If the ranking file is
                  absent, the arrays are carried over from a previous
                  plan_crawl.json (the repo ships one in analysis/seed-inputs/).
  total_repos     total crawled repositories
  n_base          len(depweight_base)

ENVIRONMENT
  MONGO_URI      mongodb://127.0.0.1:27017
  MONGO_DB       dockerhub_data
  OUT            plan_crawl.json
  RANKING        exposure_ranked_v3.jsonl (dependency-weight source)
  SEED_PLAN      fallback plan_crawl.json for depweight_base
  SAMPLE_TARGET  approximate size of the pull sample (default 125000)
"""
import json
import os
import sys

from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.environ.get("MONGO_DB", "dockerhub_data")
OUT = os.environ.get("OUT", "plan_crawl.json")
RANKING = os.environ.get("RANKING", "exposure_ranked_v3.jsonl")
SEED_PLAN = os.environ.get("SEED_PLAN", os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "seed-inputs", "plan_crawl.json"))
SAMPLE_TARGET = int(os.environ.get("SAMPLE_TARGET", "125000"))


def sample_pulls(repos, total):
    stride = max(1, total // SAMPLE_TARGET)
    pulls = []
    cursor = repos.find({}, {"pull_count": 1, "_id": 0},
                        batch_size=20000).sort("pull_count", -1)
    for i, doc in enumerate(cursor):
        if i % stride == 0:
            pc = doc.get("pull_count")
            pulls.append(int(pc) if isinstance(pc, (int, float)) else 0)
    return pulls


def load_depweights():
    if os.path.exists(RANKING):
        dws = []
        with open(RANKING) as fh:
            for line in fh:
                try:
                    dw = json.loads(line).get("dependency_weight", 0) or 0
                except ValueError:
                    continue
                if dw > 0:
                    dws.append(int(dw))
        dws.sort(reverse=True)
        return dws
    if os.path.exists(SEED_PLAN):
        sys.stderr.write("warn: ranking %s missing, reusing depweight_base "
                         "from %s\n" % (RANKING, SEED_PLAN))
        return json.load(open(SEED_PLAN)).get("depweight_base", [])
    sys.stderr.write("warn: no dependency-weight source, depweight_base "
                     "empty\n")
    return []


def main():
    cli = MongoClient(MONGO_URI)
    repos = cli[MONGO_DB].repositories_data
    total = repos.count_documents({})
    pulls = sample_pulls(repos, total)
    cli.close()
    dws = load_depweights()

    with open(OUT, "w") as fh:
        json.dump({"pull": pulls, "depweight_base": dws,
                   "total_repos": total, "n_base": len(dws)}, fh)
    sys.stderr.write("wrote %s (%d pull samples of %d repos, %d bases)\n"
                     % (OUT, len(pulls), total, len(dws)))


if __name__ == "__main__":
    main()
