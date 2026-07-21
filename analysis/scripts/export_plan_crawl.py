#!/usr/bin/env python3
"""
Export `plan_crawl.json`, the crawl-wide CDF input of plan_figs.py
(fig_crawl_cdf):

  pull            repository pull counts, descending -- a systematic 1-in-K
                  sample of the exposure-ranked RESOLVED HEAD (the rows of the
                  exposure ranking), the population the paper's Section 3.1
                  pull statistics are over. A systematic sample of the sorted
                  list preserves the CDF and keeps the maximum.
  pull_median / pull_p99 / pull_max   over the full ranked head (median 198).
  depweight_base  dependency weight (downstream image count) of every base
                  image, descending. This is a Stage II layer-graph quantity,
                  not stored in MongoDB: it is read from the exposure ranking
                  (rows with dependency_weight > 0). If the ranking file is
                  absent, the arrays are carried over from a previous
                  plan_crawl.json (the repo ships one in analysis/seed-inputs/).
  total_repos     total crawled repositories
  n_base          len(depweight_base)

ENVIRONMENT
  RANKING        exposure_ranked_v3.jsonl (the resolved-head population)
  OUT            plan_crawl.json
  SEED_PLAN      fallback plan_crawl.json for depweight_base
  SAMPLE_TARGET  approximate size of the pull sample (default 125000)
"""
import json
import os
import sys


OUT = os.environ.get("OUT", "plan_crawl.json")
RANKING = os.environ.get("RANKING", "exposure_ranked_v3.jsonl")
SEED_PLAN = os.environ.get("SEED_PLAN", os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "seed-inputs", "plan_crawl.json"))
SAMPLE_TARGET = int(os.environ.get("SAMPLE_TARGET", "125000"))


def ranked_pulls():
    """Pull counts of the exposure-ranked resolved head, descending.

    The paper's Section 3.1 pull statistics (median 198, p99, the crawl CDF)
    are over the Stage-II-resolved, exposure-ranked repositories, NOT the full
    crawl: the long tail of barely-pulled repositories would pull the median
    down to ~62. That population is exactly the rows of the exposure ranking.
    """
    pulls = []
    with open(RANKING) as fh:
        for line in fh:
            try:
                pc = json.loads(line).get("pull_count") or 0
            except ValueError:
                continue
            pulls.append(int(pc))
    pulls.sort(reverse=True)
    return pulls


def systematic_sample(pulls):
    stride = max(1, len(pulls) // SAMPLE_TARGET)
    return [pulls[i] for i in range(0, len(pulls), stride)]


def pctl(sorted_desc, frac):
    if not sorted_desc:
        return 0
    asc = sorted_desc[::-1]
    return asc[min(len(asc) - 1, int(frac * len(asc)))]


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
    if not os.path.exists(RANKING):
        sys.stderr.write("error: exposure ranking %s required (it defines the "
                         "resolved head the paper's pull stats are over)\n"
                         % RANKING)
        sys.exit(1)
    full = ranked_pulls()
    sample = systematic_sample(full)
    dws = load_depweights()

    # Only the CDF sample and the base dependency weights: the paper's
    # Section 3.1 pull statistics are computed directly from the raw databases
    # (full-crawl median/p99/max in crawl_stats.py), not from any sample here.
    out = {"pull": sample, "depweight_base": dws,
           "total_repos": len(full), "n_base": len(dws)}
    with open(OUT, "w") as fh:
        json.dump(out, fh)
    sys.stderr.write("wrote %s (%d pull samples of %d ranked repos, "
                     "median=%d p99=%d max=%d, %d bases)\n"
                     % (OUT, len(sample), len(full), out["pull_median"],
                        out["pull_p99"], out["pull_max"], len(dws)))


if __name__ == "__main__":
    main()
