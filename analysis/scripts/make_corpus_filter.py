#!/usr/bin/env python3
"""Generate the corpus filter: the head-N repo:tag references of the exposure
ranking, in ranking order, one per line, with the `library/` prefix stripped.

This is the exact format extract_cve_digests.py and recount_repo.py
(CHIMANGOSCAN_FILTER_RT) match scanned report references against.

Env: EXPOSURE_JSONL (default ./exposure_ranked_v3.jsonl), TOP_N (default
60000), OUT (default ./corpus_filter.txt).
"""
import json
import os

EXPOSURE_JSONL = os.environ.get("EXPOSURE_JSONL", "./exposure_ranked_v3.jsonl")
TOP_N = int(os.environ.get("TOP_N", "60000"))
OUT = os.environ.get("OUT", "./corpus_filter.txt")


def main():
    n = 0
    tmp = OUT + ".tmp"
    with open(EXPOSURE_JSONL) as fin, open(tmp, "w") as fout:
        for line in fin:
            if n >= TOP_N:
                break
            r = json.loads(line)
            rt = "%s/%s:%s" % (r["repository_namespace"], r["repository_name"],
                               r["tag_name"])
            if rt.startswith("library/"):
                rt = rt[len("library/"):]
            fout.write(rt + "\n")
            n += 1
    os.replace(tmp, OUT)
    print("wrote %s (%d repo:tag)" % (OUT, n))


if __name__ == "__main__":
    main()
