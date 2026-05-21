#!/usr/bin/env python3
"""
Analise READ-ONLY do ditector-good.db para o paper. NAO modifica o banco.

Aplica a correcao de severidade OSV em memoria (osv_severity_cache.json) e,
num unico scan streaming, coleta tudo que o paper precisa:
  - most_severe          : imagens por pior severidade de vuln (Shu Fig.5)
  - n_with_critical/high : imagens com >=1 finding critical / high (pos-correcao)
  - sev_global_pkgvuln   : findings pkg-vuln por severidade (pos-correcao)
  - cve_distinct_by_year : CVEs distintos por ano de publicacao (Shu Fig.7)
  - pkg_top_by_images/vulns : pacotes causadores (Shu Tab.6)

Saida: /home/cristhian/dit_analysis/paper_analysis.json
Uso:   nohup python3 paper_analysis.py > paper_analysis.log 2>&1 &
"""
import sqlite3, json, sys, time, re
from collections import Counter, defaultdict

DB = "/mnt/win_ssd/ditector-good.db"
OUT = "/mnt/win_ssd/chimangoscan-paper/paper_analysis.json"
CACHE = "/mnt/win_ssd/chimangoscan-paper/osv_severity_cache.json"
UNKNOWN = {"unknown", "", "none", "null", "n/a", "na"}
SEV_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
CVE_RE = re.compile(r"CVE-(\d{4})-\d+", re.I)


def norm_pkg(p):
    p = str(p).split("@")[0]
    if "/" in p:
        p = p.split("/")[-1]
    return p.lower()


def main():
    with open(CACHE) as fh:
        cache = json.load(fh)
    resolved = {vid: r["severity"] for vid, r in cache["severity_by_id"].items()
                if r.get("severity")}
    sys.stderr.write("resolved osv ids: %d\n" % len(resolved))
    sys.stderr.flush()

    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=180)
    most_severe = Counter()
    sev_global = Counter()
    cve_year = defaultdict(set)
    pkg_images = Counter()
    pkg_vulns = Counter()
    n = n_vuln = n_crit = n_high = 0
    t0 = time.time()

    cur = con.cursor()
    cur.execute("SELECT report_json FROM reports")
    for (rj,) in cur:
        n += 1
        if n % 2000 == 0:
            sys.stderr.write("  ...%d reports (%.0fs)\n" % (n, time.time() - t0))
            sys.stderr.flush()
        try:
            j = json.loads(rj)
        except Exception:
            continue
        worst = -1
        has_crit = has_high = False
        pkgs = set()
        for f in j.get("findings", []) or []:
            if f.get("category") != "pkg-vuln":
                continue
            sc = str(f.get("scanner") or "")
            if sc == "clair":
                continue
            sev = str(f.get("severity") or "unknown").strip().lower()
            if sc == "osv" and sev in UNKNOWN:
                fid = f.get("id")
                if fid and fid in resolved:
                    sev = str(resolved[fid]).strip().lower()
            if sev not in SEV_RANK:
                sev = "unknown"
            sev_global[sev] += 1
            worst = max(worst, SEV_RANK[sev])
            if sev == "critical":
                has_crit = True
            if sev == "high":
                has_high = True
            for cve in (f.get("cves") or []):
                m = CVE_RE.match(str(cve))
                if m:
                    cve_year[m.group(1)].add(str(cve).upper())
            pk = f.get("package")
            if pk:
                npk = norm_pkg(pk)
                pkg_vulns[npk] += 1
                pkgs.add(npk)
        if worst < 0:
            most_severe["none"] += 1
        else:
            n_vuln += 1
            most_severe[RANK_SEV[worst]] += 1
        if has_crit:
            n_crit += 1
        if has_high:
            n_high += 1
        for npk in pkgs:
            pkg_images[npk] += 1
    con.close()

    out = {
        "n_reports": n,
        "n_with_vuln": n_vuln,
        "n_with_critical": n_crit,
        "n_with_high": n_high,
        "most_severe": dict(most_severe),
        "sev_global_pkgvuln": dict(sev_global),
        "cve_distinct_by_year": {y: len(s) for y, s in sorted(cve_year.items())},
        "n_distinct_cves": sum(len(s) for s in cve_year.values()),
        "pkg_top_by_images": pkg_images.most_common(40),
        "pkg_top_by_vulns": pkg_vulns.most_common(40),
        "elapsed_s": round(time.time() - t0),
    }
    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=1)
    sys.stderr.write("DONE %ds -> %s\n" % (out["elapsed_s"], OUT))
    print("n_reports=%d  n_with_critical=%d (%.1f%%)  n_with_high=%d (%.1f%%)"
          % (n, n_crit, 100*n_crit/n if n else 0, n_high, 100*n_high/n if n else 0))
    print("most_severe:", out["most_severe"])
    print("n_distinct_cves:", out["n_distinct_cves"])


if __name__ == "__main__":
    main()
