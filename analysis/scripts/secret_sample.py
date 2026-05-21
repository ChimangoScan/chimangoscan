#!/usr/bin/env python3
"""Reservoir-sample a statistically representative set of TruffleHog secret
detections from the scanned corpus, plus full distribution by detector and
file location. Output: secret_dist.json (population stats) and
secret_sample.json (the random sample, for ground-truth classification)."""
import sqlite3, json, re, random
from collections import Counter

random.seed(42)
DB = "/mnt/win_ssd/ditector-good.db"
K = 1100                                  # 95% CI, +-3% on a proportion
con = sqlite3.connect(DB)

det = Counter(); locp = Counter()
total = 0; n_img = 0
reservoir = []                            # reservoir of K findings

def locpat(l):
    if l.endswith(".md5sums"): return "dpkg .md5sums (checksums)"
    if "/var/lib/dpkg/" in l or "/var/lib/apt/" in l or "/usr/share/doc/" in l: return "OS pkg metadata/doc"
    if re.search(r'(test|spec|fixture|mock|example|sample|demo)', l, re.I): return "test/example/sample path"
    if l.endswith((".pem", ".key", ".crt", ".pub", ".ppk")): return "key/cert file"
    if re.search(r'\.(md|txt|rst|html?)$', l, re.I): return "doc/text file"
    return "other"

for (img, rj) in con.execute("SELECT image, report_json FROM reports"):
    try: j = json.loads(rj)
    except Exception: continue
    secs = [f for f in (j.get("findings") or []) if f.get("category") == "secret"]
    if not secs: continue
    n_img += 1
    for f in secs:
        total += 1
        det[f.get("id", "?")] += 1
        locp[locpat(f.get("location", ""))] += 1
        rec = {"detector": f.get("id"), "value": (f.get("description") or "")[:80],
               "location": f.get("location", ""), "image": img.split("@")[0],
               "severity": f.get("severity")}
        if len(reservoir) < K:
            reservoir.append(rec)
        else:
            j2 = random.randint(0, total - 1)
            if j2 < K: reservoir[j2] = rec
con.close()

json.dump({"total_secret_findings": total, "images_with_secret": n_img,
           "by_detector": det.most_common(), "by_location": locp.most_common()},
          open("/mnt/win_ssd/chimangoscan-paper/secret_dist.json", "w"), indent=1)
json.dump(reservoir, open("/mnt/win_ssd/chimangoscan-paper/secret_sample.json", "w"), indent=1)
print(f"DONE total={total:,} images={n_img:,} sample={len(reservoir)}")
print("top detectors:", det.most_common(8))
print("locations:", locp.most_common())
