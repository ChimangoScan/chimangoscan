#!/usr/bin/env python3
"""
Single READ-ONLY streaming pass over ditector-good.db that recomputes EVERY
aggregate statistic the paper reports, COUNTED PER REPOSITORY.

The reports table holds one row per scanned repository reference. The paper
counts by repository: each scanned repository is a distinct publication of the
ecosystem, so every aggregate is over all 50,453 reports, NOT deduplicated by
image_digest. About 7,800 of those repositories share a byte-identical digest
with another (base-image clones).

EXCEPTION: the per-CVE downstream propagation factor (cve_depweight / cve_dps)
IS deduplicated by digest. Summing an image's dependency_weight once per clone
multiplies the downstream count by the number of clones, which is a genuine
calculation error independent of the repo-vs-content unit choice. So the
propagation accumulators add each distinct image_digest exactly once.

Produces, per-repository:
  dedup_analysis.json   master output, all numbers + old/new comparison
  paper_analysis.json   (overwritten) Shu panel: most_severe, cve_by_year, ...
  rich_analysis.json    (overwritten) severity tables, top packages, SBOM
  plan_analysis.json    (overwritten) plan A/B + N1..N7
  plan_scatter.json     (overwritten) per-image scatter arrays
  extra_analysis.json   (overwritten) venn + offcomm
  step3_recompute.json  (overwritten, .after blocks only) per-scanner severity
  fig_official_vs_community_stats.json (overwritten)
  analyze_db.stats.json (overwritten) accumulators for panels3.py

Old (with-duplicate) JSONs are backed up to *.bak.dup once.
"""
import sqlite3, json, sys, time, math, re, shutil, os, itertools
from collections import Counter, defaultdict
from datetime import datetime, timezone

DB = "/mnt/win_ssd/ditector-good.db"
OUT = "/mnt/win_ssd/chimangoscan-paper"
CACHE = os.path.join(OUT, "osv_severity_cache.json")
TAGS = "/mnt/cache/tags_full.jsonl"
NOW_TEMPORAL = datetime(2026, 5, 18, tzinfo=timezone.utc)
UNKNOWN = {"unknown", "", "none", "null", "n/a", "na"}
SEV_RANK = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
RANK_SEV = {v: k for k, v in SEV_RANK.items()}
SEVS = ["critical", "high", "medium", "low", "info", "unknown"]
SCANNERS = ["syft", "trivy", "grype", "osv", "clair", "dockle", "trufflehog"]
VULN_SCANNERS = ("trivy", "grype", "osv")
CVE_RE = re.compile(r"CVE-(\d{4})-\d+", re.I)

OS_ECO = {"deb", "debian", "ubuntu", "rpm", "centos", "redhat", "rhel",
          "apk", "alpine", "amazon", "oracle", "suse", "sles", "photon",
          "wolfi", "chainguard", "rocky", "alma", "mariner", "azurelinux",
          "distroless", "mageia", "openeuler", "alpm", "arch"}
LANG_ECO = {"go", "go-module", "gobinary", "golang", "npm", "node",
            "node-pkg", "pypi", "python", "python-pkg", "java-archive",
            "java", "maven", "gem", "rubygems", "ruby", "nuget", "dotnet",
            "composer", "php-composer", "php-pear", "packagist",
            "crates.io", "rust-crate", "cargo", "conan", "binary"}


def eco_norm(e):
    return str(e or "").strip().lower().split(":")[0].split("/")[0]


def eco_class(e):
    e = eco_norm(e)
    if e in OS_ECO:
        return "os"
    if e in LANG_ECO:
        return "lang"
    return "other"


def norm_pkg(p):
    p = str(p).split("@")[0]
    if "/" in p:
        p = p.split("/")[-1]
    return p.lower()


def pct(sv, q):
    n = len(sv)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sv[0])
    k = (n - 1) * (q / 100.0)
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return float(sv[int(k)])
    return sv[lo] * (hi - k) + sv[hi] * (k - lo)


def mean(v):
    return sum(v) / len(v) if v else 0.0


def spearman(xs, ys):
    n = len(xs)
    if n < 3:
        return 0.0

    def ranks(v):
        order = sorted(range(n), key=lambda i: v[i])
        r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j + 1 < n and v[order[j + 1]] == v[order[i]]:
                j += 1
            avg = (i + j) / 2.0 + 1.0
            for k in range(i, j + 1):
                r[order[k]] = avg
            i = j + 1
        return r

    rx, ry = ranks(xs), ranks(ys)
    mx, my = sum(rx) / n, sum(ry) / n
    sxy = sum((rx[i] - mx) * (ry[i] - my) for i in range(n))
    sxx = sum((rx[i] - mx) ** 2 for i in range(n))
    syy = sum((ry[i] - my) ** 2 for i in range(n))
    if sxx == 0 or syy == 0:
        return 0.0
    return sxy / math.sqrt(sxx * syy)


def parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def parse_image_key(img):
    """NAMESPACE/REPO:TAG[@sha256:...] or REPO:TAG -> (ns, repo, tag)."""
    if not img:
        return None
    img = str(img).split("@")[0]
    if ":" not in img:
        return None
    repo_part, tag = img.rsplit(":", 1)
    if "/" in repo_part:
        ns, repo = repo_part.split("/", 1)
    else:
        ns, repo = "library", repo_part
    return (ns.lower(), repo.lower(), tag)


def parse_dt(v):
    if v is None:
        return None
    if isinstance(v, dict):
        v = v.get("$date")
    if not v:
        return None
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def load_tagmap():
    """(ns,repo,tag) -> last_updated datetime, from the Mongo tags export."""
    tagmap = {}
    if not os.path.exists(TAGS):
        sys.stderr.write("warn: %s missing, temporal skipped\n" % TAGS)
        return tagmap
    with open(TAGS) as fh:
        for line in fh:
            try:
                j = json.loads(line)
            except Exception:
                continue
            ns = (j.get("repositories_namespace") or "").lower()
            repo = (j.get("repositories_name") or "").lower()
            name = j.get("name")
            if not repo or not name:
                continue
            lu = parse_dt(j.get("last_updated"))
            if lu:
                tagmap[(ns, repo, name)] = lu
    sys.stderr.write("tagmap: %d tags with last_updated\n" % len(tagmap))
    return tagmap


def main():
    cache = json.load(open(CACHE))
    resolved = {vid: r["severity"] for vid, r in cache["severity_by_id"].items()
                if r.get("severity")}
    sys.stderr.write("resolved osv ids: %d\n" % len(resolved))
    sys.stderr.flush()
    tagmap = load_tagmap()

    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True, timeout=300)

    seen_digests = set()
    n_rows = 0          # all reports table rows
    n_distinct = 0      # processed (deduplicated) images
    n_missing_digest = 0

    # ---- accumulators (all over DISTINCT images) ----
    most_severe = Counter()
    sev_global = Counter()              # merged findings by severity
    sev_by_scanner = {s: Counter() for s in SCANNERS}
    status_by_scanner = {s: Counter() for s in SCANNERS}
    wall_by_scanner = {s: [] for s in SCANNERS}
    scan_time_per_image = []
    cve_year = defaultdict(set)
    pkg_images = Counter()
    pkg_vulns = Counter()
    pkg_finds = Counter()
    pkg_cves = defaultdict(set)
    pkg_eco = defaultdict(Counter)
    pkg_crit = Counter()
    sev_images = Counter()              # images with >=1 of each severity
    sbom_imgs = Counter()
    sbom_eco = Counter()
    ecosystem_count = Counter()
    components_per_image = []
    vulns_per_image = []                # merged pkg-vuln per image
    n_vuln = n_crit = n_high = n_zero = 0
    img_with_secret = 0
    n_secrets_total = 0
    secret_type = Counter()
    img_with_misconfig = 0
    n_misconfig_total = 0
    misconfig_title = Counter()
    n_findings_array_sum = 0

    # plan: per-image distinct-group arrays
    img_pull, img_distinct, img_exposure, img_critical = [], [], [], []
    sev_all = Counter()
    sev_distinct = Counter()
    sec_off, sec_com = [], []
    setcount = Counter()
    total_groups = 0
    cve_images = Counter()
    cve_images_dedup = Counter()   # distinct-digest count, for propagation
    cve_exposure = Counter()
    cve_depweight = Counter()
    cve_dps = Counter()
    cve_sev = {}
    cve_pkg = {}
    n5_sev = defaultdict(Counter)
    n5_eco = defaultdict(Counter)
    n7 = Counter()
    n7_total_codet = 0
    n7_mismatch = 0
    # venn (group-image masks, summed over images)
    venn = Counter()
    # offcomm
    off_vpi, com_vpi = [], []
    off_secret = com_secret = 0
    n_off = n_com = 0
    # temporal: (age_days, n_pkgvuln) over distinct images
    temporal_pairs = []
    temporal_matched = 0
    # repro (Section 4.8): Liu high/critical prevalence, Wist severe-by-eco,
    # Dahlmanns private-key prevalence
    off_hc = com_hc = 0          # images with >=1 high|critical pkg-vuln
    sev_eco = Counter()          # eco_class -> high+critical findings
    sev_eco_lang = Counter()     # lang ecosystem -> high+critical findings
    sec_detector = Counter()     # secret detector counts
    img_with_pk = 0              # images with >=1 private-key secret

    t0 = time.time()
    cur = con.cursor()
    cur.execute("SELECT image, report_json, n_findings, finished_at FROM reports")
    for image, rj, _nf, _fa in cur:
        n_rows += 1
        if n_rows % 5000 == 0:
            sys.stderr.write("  ...%d rows, %d distinct (%.0fs)\n"
                             % (n_rows, n_distinct, time.time() - t0))
            sys.stderr.flush()
        try:
            j = json.loads(rj)
        except Exception:
            continue
        meta = ((j.get("target") or {}).get("meta")) or {}
        digest = meta.get("image_digest")
        # Count by repository: every row is its own unit, NO digest dedup.
        # digest_is_new flags the first row seen for a digest; only used to
        # deduplicate the per-CVE propagation accumulators (see below).
        if digest:
            digest_is_new = digest not in seen_digests
            if digest_is_new:
                seen_digests.add(digest)
        else:
            digest_is_new = True
            n_missing_digest += 1
        n_distinct += 1

        ns = (meta.get("repository_namespace") or "").strip().lower()
        official = ns in ("", "library")
        pull = meta.get("pull_count") or 0
        exposure = meta.get("exposure") or 0
        depw = meta.get("dependency_weight") or 0
        dps = meta.get("downstream_pull_sum") or 0

        # ---- invocations ----
        for inv in j.get("invocations", []) or []:
            sc = inv.get("scanner")
            if sc not in status_by_scanner:
                status_by_scanner[sc] = Counter()
                wall_by_scanner[sc] = []
            status_by_scanner[sc][inv.get("status", "unknown")] += 1
            ws = inv.get("wall_seconds")
            if isinstance(ws, (int, float)) and ws > 0:
                wall_by_scanner[sc].append(float(ws))

        st_t = parse_iso(j.get("started_at"))
        fi_t = parse_iso(j.get("finished_at"))
        if st_t is not None and fi_t is not None and fi_t >= st_t:
            scan_time_per_image.append(fi_t - st_t)

        findings = j.get("findings", []) or []
        n_findings_array_sum += len(findings)

        worst = -1
        has_crit = has_high = False
        has_pk = False
        n_pkgvuln = 0
        n_components = 0
        n_secret = 0
        n_misconfig = 0
        img_sev = set()
        img_pkgs = set()
        img_pkgcrit = set()
        img_comp = set()
        groups = defaultdict(dict)   # (cve,pkg) -> {scanner: sev, _eco: eco}

        for f in findings:
            cat = f.get("category")
            sc = str(f.get("scanner") or "")
            if sc == "clair":
                continue
            sev = str(f.get("severity") or "unknown").strip().lower()
            if sc == "osv" and cat == "pkg-vuln" and sev in UNKNOWN:
                fid = f.get("id")
                if fid and fid in resolved:
                    sev = str(resolved[fid]).strip().lower()
            # Dockle FATAL checkpoints surface as 'high' in the raw schema;
            # the paper treats FATAL as critical (step3_recompute high->crit).
            if sc == "dockle" and sev == "high":
                sev = "critical"
            if sev not in SEV_RANK:
                sev = "unknown"
            sev_global[sev] += 1
            if sc in sev_by_scanner:
                sev_by_scanner[sc][sev] += 1
            else:
                sev_by_scanner.setdefault(sc, Counter())[sev] += 1

            if cat == "pkg-vuln":
                n_pkgvuln += 1
                worst = max(worst, SEV_RANK[sev])
                if sev == "critical":
                    has_crit = True
                if sev == "high":
                    has_high = True
                if sev in ("high", "critical"):
                    cls = eco_class(f.get("ecosystem"))
                    sev_eco[cls] += 1
                    if cls == "lang":
                        sev_eco_lang[eco_norm(f.get("ecosystem"))] += 1
                img_sev.add(sev)
                pk = f.get("package")
                npk = norm_pkg(pk) if pk else None
                if npk:
                    pkg_finds[npk] += 1
                    pkg_vulns[npk] += 1
                    img_pkgs.add(npk)
                    if sev == "critical":
                        img_pkgcrit.add(npk)
                    eco = (f.get("ecosystem") or "").strip().lower()
                    if eco:
                        pkg_eco[npk][eco] += 1
                for cve in (f.get("cves") or []):
                    m = CVE_RE.match(str(cve))
                    if m:
                        cve_year[m.group(1)].add(str(cve).upper())
                        if npk:
                            pkg_cves[npk].add(str(cve).upper())
                # plan grouping (vuln scanners only)
                if sc in VULN_SCANNERS:
                    sev_all[sev] += 1
                    pkg = f.get("package") or ""
                    ecn = eco_norm(f.get("ecosystem"))
                    cves = f.get("cves") or []
                    if not cves:
                        cid = f.get("id")
                        cves = [cid] if cid else []
                    for cid in cves:
                        d = groups[(cid, pkg)]
                        if sc not in d or SEV_RANK.get(sev, 0) > \
                                SEV_RANK.get(d.get(sc, "unknown"), 0):
                            d[sc] = sev
                        d.setdefault("_eco", ecn)
            elif cat == "sbom-component":
                n_components += 1
                pk = f.get("package")
                if pk:
                    img_comp.add(norm_pkg(pk))
                ecosystem_count[f.get("ecosystem") or "unknown"] += 1
                sbom_eco[(f.get("ecosystem") or "unknown").strip().lower()] += 1
            elif cat == "secret":
                n_secret += 1
                secret_type[f.get("title") or "unknown"] += 1
                det = str(f.get("title") or f.get("id") or "?")
                sec_detector[det] += 1
                title = str(f.get("title") or "").lower()
                sid = str(f.get("id") or "").lower()
                if "privatekey" in title or "private" in title \
                        or "privatekey" in sid:
                    has_pk = True
            elif cat == "image-config":
                n_misconfig += 1
                misconfig_title[f.get("title") or "unknown"] += 1

        # ---- per-image rollups ----
        if worst < 0:
            most_severe["none"] += 1
            n_zero += 1
        else:
            n_vuln += 1
            most_severe[RANK_SEV[worst]] += 1
        if has_crit:
            n_crit += 1
        if has_high:
            n_high += 1
        vulns_per_image.append(n_pkgvuln)
        components_per_image.append(n_components)
        for s in img_sev:
            sev_images[s] += 1
        for npk in img_pkgs:
            pkg_images[npk] += 1
        for npk in img_pkgcrit:
            pkg_crit[npk] += 1
        for c in img_comp:
            sbom_imgs[c] += 1
        if n_secret > 0:
            img_with_secret += 1
        n_secrets_total += n_secret
        if n_misconfig > 0:
            img_with_misconfig += 1
        n_misconfig_total += n_misconfig

        # ---- temporal: image age vs n_pkgvuln (deduplicated) ----
        if tagmap:
            tkey = parse_image_key(image)
            lu = tagmap.get(tkey) if tkey else None
            if lu is not None:
                temporal_matched += 1
                age_days = (NOW_TEMPORAL - lu).total_seconds() / 86400.0
                temporal_pairs.append([round(age_days, 1), n_pkgvuln])

        # ---- plan group-level ----
        distinct = 0
        critical = 0
        img_cves_here = set()
        for key, d in groups.items():
            cid, pkg = key
            ecn = d.pop("_eco", "")
            scs = [s for s in d if s in VULN_SCANNERS]
            if not scs:
                continue
            distinct += 1
            total_groups += 1
            wsev = max((d[s] for s in scs),
                       key=lambda s: SEV_RANK.get(s, 0))
            if wsev == "critical":
                critical += 1
            sev_distinct[wsev] += 1
            mask = 0
            if "trivy" in d:
                mask |= 1
            if "grype" in d:
                mask |= 2
            if "osv" in d:
                mask |= 4
            setcount[mask] += 1
            ncan = len(scs)
            n5_sev[wsev][ncan] += 1
            n5_eco[eco_class(ecn)][ncan] += 1
            if ncan >= 2:
                for ix in range(len(VULN_SCANNERS)):
                    for jx in range(ix + 1, len(VULN_SCANNERS)):
                        sa, sb = VULN_SCANNERS[ix], VULN_SCANNERS[jx]
                        if sa in d and sb in d:
                            n7_total_codet += 1
                            n7[(d[sa], d[sb])] += 1
                            if d[sa] != d[sb]:
                                n7_mismatch += 1
            if cid and str(cid).upper().startswith("CVE-"):
                img_cves_here.add(cid)
                if cid not in cve_sev or SEV_RANK.get(wsev, 0) > \
                        SEV_RANK.get(cve_sev[cid], 0):
                    cve_sev[cid] = wsev
                    cve_pkg[cid] = pkg
                elif cid not in cve_pkg:
                    cve_pkg[cid] = pkg
        for cid in img_cves_here:
            cve_images[cid] += 1
            cve_exposure[cid] += exposure
            # Propagation factor: dependency_weight / downstream_pull_sum are
            # structural properties of the image CONTENT, so summing them once
            # per clone would multiply the downstream count by the clone count.
            # Add them once per distinct digest only (the corrected factor).
            if digest_is_new:
                cve_images_dedup[cid] += 1
                cve_depweight[cid] += depw
                cve_dps[cid] += dps

        img_pull.append(pull)
        img_distinct.append(distinct)
        img_exposure.append(exposure)
        img_critical.append(critical)

        # venn: per group-mask, accumulate region counts
        # (computed globally from setcount below)

        # offcomm
        if official:
            n_off += 1
            off_vpi.append(n_pkgvuln)
            sec_off.append(n_secret)
            if n_secret > 0:
                off_secret += 1
            if has_crit or has_high:
                off_hc += 1
        else:
            n_com += 1
            com_vpi.append(n_pkgvuln)
            sec_com.append(n_secret)
            if n_secret > 0:
                com_secret += 1
            if has_crit or has_high:
                com_hc += 1
        if has_pk:
            img_with_pk += 1

    con.close()
    elapsed = time.time() - t0
    sys.stderr.write("DONE %ds: %d rows, %d distinct images, %d missing digest\n"
                     % (elapsed, n_rows, n_distinct, n_missing_digest))

    N = n_distinct

    # ===== venn from setcount (group-image instances, in millions) =====
    venn = {
        "trivy_only": setcount.get(1, 0),
        "grype_only": setcount.get(2, 0),
        "osv_only": setcount.get(4, 0),
        "trivy_grype": setcount.get(3, 0),
        "trivy_osv": setcount.get(5, 0),
        "grype_osv": setcount.get(6, 0),
        "all3": setcount.get(7, 0),
    }

    # ===== plan derived =====
    pv = [(p, v) for p, v in zip(img_pull, img_distinct) if p and p > 0]
    rho_pull = spearman([x[0] for x in pv], [x[1] for x in pv]) if pv else 0.0
    ev = [(e, v) for e, v in zip(img_exposure, img_distinct) if e and e > 0]
    rho_exp = spearman([x[0] for x in ev], [x[1] for x in ev]) if ev else 0.0
    ec = [(e, c) for e, c in zip(img_exposure, img_critical) if e and e > 0]
    rho_exp_crit = spearman([x[0] for x in ec], [x[1] for x in ec]) if ec else 0.0

    order = sorted(range(len(img_exposure)), key=lambda i: img_exposure[i])
    nimg = len(order)
    deciles = []
    for d in range(10):
        lo = d * nimg // 10
        hi = (d + 1) * nimg // 10
        idx = order[lo:hi]
        vs = sorted(img_distinct[i] for i in idx)
        cs = [img_critical[i] for i in idx]
        m = len(vs)
        deciles.append({
            "decile": d + 1, "n": m,
            "median_vuln": vs[m // 2] if m else 0,
            "q1_vuln": vs[m // 4] if m else 0,
            "q3_vuln": vs[(3 * m) // 4] if m else 0,
            "median_critical": sorted(cs)[m // 2] if m else 0,
            "critical_prevalence_pct":
                100.0 * sum(1 for c in cs if c > 0) / m if m else 0.0,
        })

    def union_for(bits):
        return sum(c for m, c in setcount.items() if m & bits)
    single = {"trivy": union_for(1), "grype": union_for(2), "osv": union_for(4)}
    unique = {"trivy": setcount.get(1, 0), "grype": setcount.get(2, 0),
              "osv": setcount.get(4, 0)}
    BIT = {"trivy": 1, "grype": 2, "osv": 4}
    step_sum = [0.0, 0.0, 0.0]
    for perm in itertools.permutations(("trivy", "grype", "osv")):
        acc = prev = 0
        for k, s in enumerate(perm):
            acc |= BIT[s]
            cov = union_for(acc)
            step_sum[k] += (cov - prev)
            prev = cov
    marginal_avg = [s / 6.0 for s in step_sum]
    best1 = max(single.values())
    pairs = {("trivy", "grype"): union_for(3),
             ("trivy", "osv"): union_for(5),
             ("grype", "osv"): union_for(6)}
    best2 = max(pairs.values())
    all3 = union_for(7)

    total_exposure = sum(img_exposure)
    cve_n3 = []
    for cid, exp in cve_exposure.most_common(20):
        cve_n3.append({
            "cve": cid, "severity": cve_sev.get(cid, "unknown"),
            "package": cve_pkg.get(cid, ""),
            "affected_images": cve_images[cid],
            "pct_corpus": 100.0 * cve_images[cid] / nimg if nimg else 0,
            "summed_exposure": exp,
            "pct_total_exposure":
                100.0 * exp / total_exposure if total_exposure else 0.0,
        })
    # Propagation table: direct_images and the factor are over DISTINCT
    # images by content (cve_images_dedup), to match the deduplicated
    # downstream accumulators; this keeps the corrected propagation factor.
    cve_n2 = []
    for cid, nimgs in cve_images_dedup.most_common(25):
        depw = cve_depweight[cid]
        cve_n2.append({
            "cve": cid, "severity": cve_sev.get(cid, "unknown"),
            "package": cve_pkg.get(cid, ""),
            "direct_images": nimgs,
            "downstream_images": depw,
            "propagation_factor": (depw / nimgs) if nimgs else 0.0,
            "downstream_pull_sum": cve_dps[cid],
        })
    cve_n2.sort(key=lambda r: -r["downstream_images"])

    def cdf_stats(v):
        v = sorted(v)
        m = len(v)
        if m == 0:
            return {}
        return {"n": m, "zero_pct": 100.0 * sum(1 for x in v if x == 0) / m,
                "median": v[m // 2], "p90": v[min(m - 1, (9 * m) // 10)],
                "p99": v[min(m - 1, (99 * m) // 100)], "max": v[-1]}

    def n5_share(tbl):
        out = {}
        for k, cc in tbl.items():
            tot = sum(cc.values())
            if tot == 0:
                continue
            out[k] = {"total": tot,
                      "single_pct": 100.0 * cc.get(1, 0) / tot,
                      "two_pct": 100.0 * cc.get(2, 0) / tot,
                      "three_pct": 100.0 * cc.get(3, 0) / tot}
        return out

    # ===== top-package table =====
    top = [p for p, _ in pkg_images.most_common(25)]
    pkg_table = []
    for p in top:
        eco = pkg_eco[p].most_common(1)
        pkg_table.append({
            "package": p, "images": pkg_images[p], "findings": pkg_finds[p],
            "distinct_cves": len(pkg_cves[p]),
            "ecosystem": eco[0][0] if eco else "n/a",
            "critical_images": pkg_crit[p]})

    # ===== assemble outputs =====
    vpi_sorted = sorted(vulns_per_image)
    cpi_sorted = sorted(components_per_image)

    # ---- paper_analysis.json (Shu panel) ----
    paper_analysis = {
        "n_reports": N,
        "n_with_vuln": n_vuln, "n_with_critical": n_crit, "n_with_high": n_high,
        "most_severe": dict(most_severe),
        "sev_global_pkgvuln": {s: sev_all.get(s, 0) for s in SEVS},
        "cve_distinct_by_year": {y: len(s) for y, s in sorted(cve_year.items())},
        "n_distinct_cves": sum(len(s) for s in cve_year.values()),
        "pkg_top_by_images": pkg_images.most_common(40),
        "pkg_top_by_vulns": pkg_vulns.most_common(40),
        "elapsed_s": round(elapsed)}

    # ---- rich_analysis.json ----
    rich_analysis = {
        "n_reports": N,
        "sev_images": {s: sev_images.get(s, 0) for s in SEVS},
        "sev_findings": {s: sev_all.get(s, 0) for s in SEVS},
        "pkg_table": pkg_table,
        "n_distinct_packages": len(pkg_images),
        "sbom_top_by_images": sbom_imgs.most_common(30),
        "sbom_eco": dict(sbom_eco),
        "n_distinct_components": len(sbom_imgs),
        "elapsed_s": round(elapsed)}

    # ---- plan_analysis.json ----
    plan_analysis = {
        "n_reports": N, "elapsed_s": round(elapsed, 1),
        "total_distinct_groups": total_groups,
        "afig1_n4": {
            "scatter_n": len(pv),
            "rho_pull_vs_vuln": rho_pull,
            "rho_exposure_vs_vuln": rho_exp,
            "rho_exposure_vs_critical": rho_exp_crit,
            "exposure_deciles": deciles},
        "afig2_ctab4": {
            "sev_all_findings": dict(sev_all),
            "sev_distinct_groups": dict(sev_distinct)},
        "afig3": {"official": cdf_stats(sec_off),
                  "community": cdf_stats(sec_com)},
        "n1": {
            "total_distinct_groups": total_groups,
            "single_scanner_union": single,
            "unique_contribution": unique,
            "pair_union": {"+".join(k): v for k, v in pairs.items()},
            "best1": best1, "best2": best2, "all3": all3,
            "best1_pct": 100.0 * best1 / total_groups if total_groups else 0,
            "best2_pct": 100.0 * best2 / total_groups if total_groups else 0,
            "all3_pct": 100.0 * all3 / total_groups if total_groups else 0,
            "marginal_avg_over_orders": marginal_avg,
            "marginal_avg_pct": [100.0 * x / total_groups for x in marginal_avg]
            if total_groups else [0, 0, 0],
            "setcount_by_mask": {str(k): v for k, v in setcount.items()}},
        "n2": {"top_cve_propagation": cve_n2},
        "n3": {"total_corpus_exposure": total_exposure,
               "top_cve_by_exposure": cve_n3},
        "n5": {"by_severity": n5_share(n5_sev),
               "by_ecosystem_class": n5_share(n5_eco)},
        "n7": {"total_codetections": n7_total_codet, "mismatch": n7_mismatch,
               "mismatch_pct": 100.0 * n7_mismatch / n7_total_codet
               if n7_total_codet else 0.0,
               "confusion": {("%s|%s" % k): v for k, v in n7.items()},
               "sev_order": SEVS}}

    plan_scatter = {"pull": img_pull, "vuln": img_distinct,
                    "exposure": img_exposure, "critical": img_critical,
                    "sec_off": sec_off, "sec_com": sec_com}

    # ---- extra_analysis.json ----
    extra_analysis = {
        "n_reports": N,
        "venn": venn,
        "offcomm": {"official_vulns": off_vpi, "community_vulns": com_vpi,
                    "n_official": n_off, "n_community": n_com,
                    "official_secret": off_secret,
                    "community_secret": com_secret},
        "elapsed_s": round(elapsed)}

    # ---- fig_official_vs_community_stats.json ----
    def grp_stats(vpi, n_grp, sec):
        s = sorted(vpi)
        return {"n_images": n_grp, "median": pct(s, 50), "mean": mean(s),
                "p90": pct(s, 90),
                "secret_frac": sec / n_grp if n_grp else 0.0,
                "secret_with": sec, "secret_total": n_grp}
    offcomm_stats = {"OFFICIAL": grp_stats(off_vpi, n_off, off_secret),
                     "COMMUNITY": grp_stats(com_vpi, n_com, com_secret)}

    # ---- step3_recompute.json (.after blocks recomputed deduplicated) ----
    # sev_by_scanner already has OSV corrected. Build .after = current scanner
    # severity dicts for osv/dockle/global so panels3.py keeps working.
    osv_after = {s: sev_by_scanner.get("osv", Counter()).get(s, 0)
                 for s in SEVS}
    dockle_after = {s: sev_by_scanner.get("dockle", Counter()).get(s, 0)
                    for s in SEVS if sev_by_scanner.get("dockle",
                                                        Counter()).get(s, 0)}
    global_after = {s: sev_global.get(s, 0) for s in SEVS}
    step3 = json.load(open(os.path.join(OUT, "step3_recompute.json")))
    step3["osv"]["after"] = osv_after
    step3["dockle"]["after"] = dockle_after
    step3["global"]["after"] = global_after
    step3["_dedup_note"] = "after blocks recomputed per repository (50453 reports)"

    # ---- analyze_db.stats.json (for panels3.py) ----
    analyze_stats = {
        "n_reports": N,
        "n_findings_array_sum": n_findings_array_sum,
        "sev_global": dict(sev_global),
        "sev_by_scanner": {k: dict(v) for k, v in sev_by_scanner.items()},
        "status_by_scanner": {k: dict(v) for k, v in status_by_scanner.items()},
        "wall_by_scanner": {k: v for k, v in wall_by_scanner.items()},
        "scan_time_per_image": scan_time_per_image,
        "vulns_per_image": vulns_per_image,
        "img_has_critical": n_crit, "img_has_high": n_high,
        "img_zero_vuln": n_zero,
        "components_per_image": components_per_image,
        "ecosystem_count": dict(ecosystem_count),
        "img_with_secret": img_with_secret,
        "n_secrets_total": n_secrets_total,
        "secret_type": dict(secret_type),
        "img_with_misconfig": img_with_misconfig,
        "n_misconfig_total": n_misconfig_total,
        "misconfig_title": dict(misconfig_title)}

    # ---- temporal_analysis.json (deduplicated) ----
    t_ages = sorted(p[0] for p in temporal_pairs)
    temporal = {
        "n_reports": N,
        "matched": temporal_matched,
        "unmatched": N - temporal_matched,
        "coverage_pct": round(100.0 * temporal_matched / N, 2) if N else 0,
        "miss_examples": [],
        "age_days_min": t_ages[0] if t_ages else None,
        "age_days_max": t_ages[-1] if t_ages else None,
        "pairs": temporal_pairs}
    # temporal medians: <1yr vs >=1yr (paper Mills paragraph)
    young = sorted(nv for ad, nv in temporal_pairs if ad < 365)
    old = sorted(nv for ad, nv in temporal_pairs if ad >= 365)
    temporal_med_young = pct(young, 50)
    temporal_med_old = pct(old, 50)

    # ---- repro_analysis.json (Section 4.8, deduplicated) ----
    repro = {
        "n_reports": N,
        "liu": {
            "n_official": n_off, "n_community": n_com,
            "official_high_or_crit": off_hc,
            "community_high_or_crit": com_hc,
            "official_hc_pct": round(100.0 * off_hc / n_off, 1) if n_off else 0,
            "community_hc_pct": round(100.0 * com_hc / n_com, 1)
            if n_com else 0},
        "wist": {
            "sev_findings_by_eco_class": dict(sev_eco),
            "sev_findings_top_lang_eco": sev_eco_lang.most_common(12)},
        "dahl": {
            "img_with_secret": img_with_secret,
            "img_with_private_key": img_with_pk,
            "img_with_secret_pct": round(100.0 * img_with_secret / N, 1)
            if N else 0,
            "img_with_private_key_pct": round(100.0 * img_with_pk / N, 1)
            if N else 0,
            "secret_detector_top": sec_detector.most_common(20),
            "n_secret_findings": sum(sec_detector.values())},
        "elapsed_s": round(elapsed)}
    sev_eco_total = sum(sev_eco.values())
    wist_os_pct = 100.0 * sev_eco.get("os", 0) / sev_eco_total \
        if sev_eco_total else 0
    wist_lang_pct = 100.0 * sev_eco.get("lang", 0) / sev_eco_total \
        if sev_eco_total else 0

    # ---- master dedup_analysis.json ----
    pkgvuln_total = sum(sev_all.values())
    master = {
        "n_table_rows": n_rows,
        "n_distinct_images": N,
        "n_missing_digest": n_missing_digest,
        "n_duplicate_rows": n_rows - N,
        "elapsed_s": round(elapsed),
        "prevalence": {
            "with_vuln_pct": 100.0 * n_vuln / N,
            "with_critical_pct": 100.0 * n_crit / N,
            "with_high_pct": 100.0 * n_high / N,
            "with_secret_pct": 100.0 * img_with_secret / N,
            "with_misconfig_pct": 100.0 * img_with_misconfig / N,
            "n_with_vuln": n_vuln, "n_with_critical": n_crit,
            "n_with_high": n_high, "n_with_secret": img_with_secret,
            "n_with_misconfig": img_with_misconfig},
        "vulns_per_image": {
            "median": pct(vpi_sorted, 50), "mean": mean(vpi_sorted),
            "p90": pct(vpi_sorted, 90), "p99": pct(vpi_sorted, 99),
            "max": vpi_sorted[-1] if vpi_sorted else 0},
        "components_per_image": {
            "median": pct(cpi_sorted, 50), "mean": mean(cpi_sorted),
            "max": cpi_sorted[-1] if cpi_sorted else 0},
        "findings_total": {
            "pkg_vuln": pkgvuln_total,
            "sbom_component": sum(1 for _ in []) or sum(
                v for v in ecosystem_count.values()),
            "secret": n_secrets_total,
            "misconfig": n_misconfig_total,
            "all_merged": n_findings_array_sum},
        "sev_global_pkgvuln": {s: sev_all.get(s, 0) for s in SEVS},
        "sev_images": {s: sev_images.get(s, 0) for s in SEVS},
        "per_scanner_findings": {
            k: sum(v.values()) for k, v in sev_by_scanner.items()
            if sum(v.values()) > 0},
        "per_scanner_severity": {
            k: dict(v) for k, v in sev_by_scanner.items()
            if sum(v.values()) > 0},
        "status_by_scanner": {k: dict(v) for k, v in status_by_scanner.items()
                              if sum(v.values()) > 0},
        "distinct_groups_total": total_groups,
        "venn": venn,
        "marginal": plan_analysis["n1"],
        "offcomm": offcomm_stats,
        "rho_pull_vs_vuln": rho_pull,
        "rho_exposure_vs_vuln": rho_exp,
        "rho_exposure_vs_critical": rho_exp_crit,
        "n_distinct_cves": sum(len(s) for s in cve_year.values()),
        "cve_year": {y: len(s) for y, s in sorted(cve_year.items())},
        "most_severe": dict(most_severe),
        "top_packages": pkg_table[:12],
        "top_cve_exposure": cve_n3[:10],
        "top_cve_propagation": cve_n2[:10],
        "n5": plan_analysis["n5"],
        "n7": {"mismatch_pct": plan_analysis["n7"]["mismatch_pct"],
               "total_codetections": n7_total_codet},
        "temporal": {"coverage_pct": temporal["coverage_pct"],
                     "median_vuln_young_lt1yr": temporal_med_young,
                     "median_vuln_old_ge1yr": temporal_med_old,
                     "n_young": len(young), "n_old": len(old)},
        "repro": {
            "liu_official_hc_pct": repro["liu"]["official_hc_pct"],
            "liu_community_hc_pct": repro["liu"]["community_hc_pct"],
            "wist_os_pct": wist_os_pct, "wist_lang_pct": wist_lang_pct,
            "wist_sev_total": sev_eco_total,
            "dahl_secret_pct": repro["dahl"]["img_with_secret_pct"],
            "dahl_pk_pct": repro["dahl"]["img_with_private_key_pct"],
            "dahl_pk_images": img_with_pk}}

    # ---- write everything (back up old once) ----
    def backup(p):
        if os.path.exists(p) and not os.path.exists(p + ".bak.dup"):
            shutil.copy2(p, p + ".bak.dup")

    writes = {
        "dedup_analysis.json": master,
        "paper_analysis.json": paper_analysis,
        "rich_analysis.json": rich_analysis,
        "plan_analysis.json": plan_analysis,
        "plan_scatter.json": plan_scatter,
        "extra_analysis.json": extra_analysis,
        "fig_official_vs_community_stats.json": offcomm_stats,
        "step3_recompute.json": step3,
        "analyze_db.stats.json": analyze_stats,
        "temporal_analysis.json": temporal,
        "repro_analysis.json": repro}
    for fn, obj in writes.items():
        p = os.path.join(OUT, fn)
        backup(p)
        with open(p, "w") as fh:
            json.dump(obj, fh, indent=1)
        sys.stderr.write("wrote %s\n" % fn)

    n_distinct_digests = len(seen_digests) + n_missing_digest
    print("=== PER-REPOSITORY SUMMARY ===")
    print("table rows (repos)   : %d" % n_rows)
    print("counted units        : %d" % N)
    print("distinct digests     : %d" % n_distinct_digests)
    print("digest-clone repos   : %d" % (n_rows - n_distinct_digests))
    print("rows missing digest  : %d" % n_missing_digest)
    print("with vuln            : %d (%.1f%%)" % (n_vuln, 100.0*n_vuln/N))
    print("with critical        : %d (%.1f%%)" % (n_crit, 100.0*n_crit/N))
    print("with misconfig       : %d (%.1f%%)" % (n_misconfig_total and
          img_with_misconfig, 100.0*img_with_misconfig/N))
    print("with secret          : %d (%.1f%%)" % (img_with_secret,
          100.0*img_with_secret/N))
    print("vuln/image median    : %.0f  mean %.0f" % (pct(vpi_sorted, 50),
          mean(vpi_sorted)))
    print("pkg-vuln findings     : %d" % pkgvuln_total)
    print("distinct groups       : %d" % total_groups)
    print("distinct CVEs         : %d" % master["n_distinct_cves"])


if __name__ == "__main__":
    main()
