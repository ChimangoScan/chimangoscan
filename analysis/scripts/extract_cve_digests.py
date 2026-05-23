#!/usr/bin/env python3
"""Extract, over the v3 corpus (top60k_rt_v3), for each CVE the set of distinct
image digests that carry it (pkg-vuln). Dedup by digest (each digest once).
Writes cve_digests_v3.json with the top-30 CVEs by distinct-digest count:
{cve: {package, severity, n_direct, digests:[...]}}. Used to recompute Table 10
(downstream propagation) by Neo4j union."""
import sqlite3, json, sys
from collections import Counter, defaultdict

DB = "/data/ditector-good.db"
FRT = set(l.strip() for l in open("/tmp/top60k_rt_v3.txt") if l.strip())
OUT = "./cve_digests_v3.json"

cve_digests = defaultdict(set)   # cve -> {digest}
cve_sev = {}
cve_pkg = {}
seen_digests = set()
con = sqlite3.connect(DB)
n = 0; kept = 0
for image, rj in con.execute("SELECT image, report_json FROM reports"):
    n += 1
    if n % 5000 == 0:
        print(f"  read {n} reports, kept {kept}, cves {len(cve_digests)}", flush=True)
    rt = image.split("@", 1)[0].strip()
    if rt.startswith("library/"):
        rt = rt[8:]
    if rt not in FRT:
        continue
    try:
        j = json.loads(rj)
    except Exception:
        continue
    digest = (((j.get("target") or {}).get("meta")) or {}).get("image_digest")
    if not digest or digest in seen_digests:
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
con.close()
print(f"done: {kept} distinct-digest images, {len(cve_digests)} CVEs", flush=True)

top = sorted(cve_digests.items(), key=lambda kv: -len(kv[1]))[:30]
out = {}
for cve, dg in top:
    out[cve] = {"package": cve_pkg.get(cve, ""), "severity": cve_sev.get(cve, ""),
                "n_direct": len(dg), "digests": sorted(dg)}
json.dump(out, open(OUT, "w"))
print(f"wrote {OUT} (top {len(out)} CVEs)")
for cve, d in list(out.items())[:12]:
    print(f"  {cve} {d['package']} {d['severity']} direct={d['n_direct']}")
