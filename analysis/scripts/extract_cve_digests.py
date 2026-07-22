#!/usr/bin/env python3
"""Extract, over the v3 corpus (top60k_rt_v3), for each CVE the set of distinct
image digests that carry it (pkg-vuln). Dedup by digest (each digest once).
Writes cve_digests_v3.json with the top-30 CVEs by distinct-digest count:
{cve: {package, severity, n_direct, digests:[...]}}. Used to recompute Table 10
(downstream propagation) by Neo4j union."""
import sqlite3, json, sys, os
from collections import Counter, defaultdict

DB = os.environ.get("CHIMANGOSCAN_DB", "/data/chimangoscan-reports.db")
FRT_PATH = os.environ.get("CHIMANGOSCAN_FILTER_RT", "/tmp/top60k_rt_v3.txt")
FRT = set(l.strip() for l in open(FRT_PATH) if l.strip())
OUT = os.environ.get("OUT_PATH", "./cve_digests_v3.json")
# A handful of report_json blobs are pathologically large (a scan of a giant
# image can be hundreds of MB); json.loads on those spikes memory and can crash
# the interpreter (SIGSEGV under memory pressure). Skip blobs above this size --
# they are a negligible fraction and do not affect the top-30-CVE aggregate.
MAX_RJ = int(os.environ.get("CVE_MAX_REPORT_BYTES", str(256 * 1024 * 1024)))

cve_digests = defaultdict(set)   # cve -> {digest}
cve_sev = {}
cve_pkg = {}
seen_digests = set()
con = sqlite3.connect(DB)
n = 0; kept = 0; skipped_big = 0
for image, rj in con.execute("SELECT image, report_json FROM reports"):
    n += 1
    if n % 5000 == 0:
        print(f"  read {n} reports, kept {kept}, cves {len(cve_digests)}, "
              f"skipped_big {skipped_big}", flush=True)
    rt = image.split("@", 1)[0].strip()
    if rt.startswith("library/"):
        rt = rt[8:]
    if rt not in FRT:
        continue
    if rj is None or len(rj) > MAX_RJ:
        if rj is not None:
            skipped_big += 1
        continue
    try:
        j = json.loads(rj)
    except Exception:
        continue
    digest = (((j.get("target") or {}).get("meta")) or {}).get("image_digest")
    if not digest or digest in seen_digests:
        j = None
        continue
    seen_digests.add(digest)
    kept += 1
    for f in (j.get("findings", []) or []):
        if f.get("category") != "pkg-vuln":
            continue
        pkg = f.get("package") or f.get("pkg") or ""
        sev = f.get("severity") or "unknown"
        for cve in (f.get("cves") or []):
            cve_digests[cve].add(digest)
            if cve not in cve_sev:
                cve_sev[cve] = sev; cve_pkg[cve] = pkg
    j = None   # free the parse tree before fetching the next (large) blob
con.close()
print(f"done: {kept} distinct-digest images, {len(cve_digests)} CVEs, "
      f"{skipped_big} oversize reports skipped", flush=True)

top = sorted(cve_digests.items(), key=lambda kv: -len(kv[1]))[:30]
out = {}
for cve, dg in top:
    out[cve] = {"package": cve_pkg.get(cve, ""), "severity": cve_sev.get(cve, ""),
                "n_direct": len(dg), "digests": sorted(dg)}
json.dump(out, open(OUT, "w"))
print(f"wrote {OUT} (top {len(out)} CVEs)")
for cve, d in list(out.items())[:12]:
    print(f"  {cve} {d['package']} {d['severity']} direct={d['n_direct']}")
