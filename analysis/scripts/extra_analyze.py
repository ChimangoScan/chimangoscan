#!/usr/bin/env python3
"""
Extra analyses for AnonymousSystem paper:
  TASK A - official vs. community
  TASK B - vulnerabilities vs. tag age

Single streaming read-only pass over the reports table. Mongo lookup via ssh host1.
"""
import sqlite3, json, sys, os, math, time, datetime, subprocess

DB = "/media/anonymous/BA1883111882CBB7/scanners_archive/ditector-D2/ditector.db"
OUT = "."
REF_DATE = datetime.datetime(2026, 5, 17, tzinfo=datetime.timezone.utc)


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


def scan_sqlite():
    con = sqlite3.connect(f"file:{DB}?immutable=1", uri=True, timeout=60)
    cur = con.cursor()

    # per-group accumulators for Task A
    grp = {
        "official": {"vpi": [], "with_secret": 0, "n": 0},
        "community": {"vpi": [], "with_secret": 0, "n": 0},
    }
    # per-image records for Task B: (digest, n_pkgvuln)
    per_image = []  # list of (digest_or_None, n_pkgvuln)
    n_reports = 0

    t0 = time.time()
    cur.execute("SELECT report_json FROM reports")
    for (rj,) in cur:
        n_reports += 1
        if n_reports % 5000 == 0:
            sys.stderr.write(f"  ...{n_reports} reports ({time.time()-t0:.0f}s)\n")
            sys.stderr.flush()
        try:
            j = json.loads(rj)
        except Exception:
            continue
        meta = (j.get("target") or {}).get("meta") or {}
        ns = (meta.get("repository_namespace") or "").strip()
        is_official = (ns == "" or ns.lower() == "library")
        g = grp["official"] if is_official else grp["community"]

        digest = meta.get("image_digest")

        n_pkgvuln = 0
        has_secret = False
        for f in j.get("findings", []):
            cat = f.get("category")
            if cat == "pkg-vuln":
                n_pkgvuln += 1
            elif cat == "secret":
                has_secret = True

        g["n"] += 1
        g["vpi"].append(n_pkgvuln)
        if has_secret:
            g["with_secret"] += 1

        per_image.append((digest, n_pkgvuln))

    con.close()
    sys.stderr.write(f"sqlite scan: {n_reports} reports in {time.time()-t0:.0f}s\n")
    return n_reports, grp, per_image


def mongo_lookup(digests):
    """Look up last_updated for a set of digests in tags_data via ssh host1.
    Sends digests in batches to a mongosh $in query, returns dict digest->last_updated."""
    digests = sorted(d for d in digests if d)
    out = {}
    BATCH = 2000
    t0 = time.time()
    for i in range(0, len(digests), BATCH):
        batch = digests[i:i + BATCH]
        js_arr = json.dumps(batch)
        # mongosh script: for each matched doc emit digest<TAB>last_updated
        script = (
            "db.tags_data.find({digest:{$in:" + js_arr + "}},"
            "{_id:0,digest:1,last_updated:1}).forEach("
            "d=>print(d.digest+'\\t'+(d.last_updated||'')));"
        )
        proc = subprocess.run(
            ["ssh", "host1", "docker", "exec", "-i", "ditector_mongo",
             "mongosh", "--quiet", "dockerhub_data", "--eval", script],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode != 0:
            sys.stderr.write(f"mongo batch {i} stderr: {proc.stderr[:300]}\n")
        for line in proc.stdout.splitlines():
            if "\t" not in line:
                continue
            dg, lu = line.split("\t", 1)
            if dg and lu and dg not in out:
                out[dg] = lu
        sys.stderr.write(
            f"  mongo {min(i+BATCH,len(digests))}/{len(digests)} digests, "
            f"{len(out)} matched ({time.time()-t0:.0f}s)\n")
        sys.stderr.flush()
    return out


def parse_iso(s):
    if not s:
        return None
    try:
        dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def make_fig_a(grp):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({
        "font.size": 10, "axes.labelsize": 11, "axes.titlesize": 11,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9,
        "figure.dpi": 150, "axes.spines.top": False, "axes.spines.right": False,
    })

    off = sorted(grp["official"]["vpi"])
    com = sorted(grp["community"]["vpi"])
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.6))

    # left: boxplot of pkg-vuln per image
    ax = axes[0]
    bp = ax.boxplot([off, com], labels=["Official\n(library)", "Community"],
                    showfliers=False, patch_artist=True,
                    medianprops=dict(color="#222222", lw=1.5))
    for patch, c in zip(bp["boxes"], ["#9ecae1", "#fdae6b"]):
        patch.set_facecolor(c)
        patch.set_edgecolor("#444444")
    ax.set_ylabel("Vulnerabilities (pkg-vuln) per image")
    ax.set_title("Distribution of vulnerabilities")
    # annotate medians
    for i, d in enumerate([off, com], start=1):
        m = pct(d, 50)
        ax.text(i, m, f" med={m:.0f}", va="bottom", ha="left",
                fontsize=8, color="#d7301f")

    # right: % images with >=1 secret
    ax = axes[1]
    groups = ["Official", "Community"]
    fracs = []
    for key in ["official", "community"]:
        g = grp[key]
        fracs.append(100.0 * g["with_secret"] / g["n"] if g["n"] else 0.0)
    bars = ax.bar(groups, fracs, color=["#9ecae1", "#fdae6b"],
                  edgecolor="#444444")
    ax.set_ylabel("Imagens com >=1 secret (%)")
    ax.set_title("Secret leakage")
    ax.margins(y=0.20)
    for b, key in zip(bars, ["official", "community"]):
        g = grp[key]
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                f"{b.get_height():.2f}%\n({g['with_secret']}/{g['n']})",
                ha="center", va="bottom", fontsize=8)

    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"fig_official_vs_community.{ext}"),
                    bbox_inches="tight")
    plt.close(fig)
    print("wrote fig_official_vs_community.{pdf,png}")


def make_fig_b(year_buckets):
    """year_buckets: dict year(int) -> list of n_pkgvuln"""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np

    plt.rcParams.update({
        "font.size": 10, "axes.labelsize": 11, "axes.titlesize": 11,
        "xtick.labelsize": 9, "ytick.labelsize": 9, "legend.fontsize": 9,
        "figure.dpi": 150, "axes.spines.top": False, "axes.spines.right": False,
    })

    years = sorted(year_buckets.keys())
    medians = [pct(sorted(year_buckets[y]), 50) for y in years]
    means = [mean(year_buckets[y]) for y in years]
    counts = [len(year_buckets[y]) for y in years]

    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    x = np.arange(len(years))
    bars = ax.bar(x, medians, color="#3182bd", edgecolor="#444444",
                  label="Median vulns/image")
    ax.plot(x, means, "o-", color="#d7301f", lw=1.6, ms=5,
            label="Mean vulns/image")
    ax.set_xticks(x)
    ax.set_xticklabels([str(y) for y in years])
    ax.set_xlabel("Ano de last_updated da tag (Docker Hub)")
    ax.set_ylabel("Vulnerabilities (pkg-vuln) per image")
    ax.set_title("Vulnerabilities vs. tag age")
    ax.legend(frameon=False, loc="upper right")
    ax.margins(y=0.18)
    for b, n, m in zip(bars, counts, medians):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height(),
                f"med={m:.0f}\nn={n}", ha="center", va="bottom", fontsize=7.5)
    fig.tight_layout()
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(OUT, f"fig_vulns_vs_age.{ext}"),
                    bbox_inches="tight")
    plt.close(fig)
    print("wrote fig_vulns_vs_age.{pdf,png}")


def main():
    # ---- streaming SQLite pass ----
    n_reports, grp, per_image = scan_sqlite()

    # ---- Task B: Mongo lookup ----
    digests = {d for d, _ in per_image if d}
    sys.stderr.write(f"unique digests to look up: {len(digests)}\n")
    digest_to_lu = mongo_lookup(digests)

    # save raw stats for safety / re-plot
    raw = {
        "n_reports": n_reports,
        "grp": {k: {"vpi": v["vpi"], "with_secret": v["with_secret"], "n": v["n"]}
                for k, v in grp.items()},
        "per_image": per_image,
        "digest_to_lu": digest_to_lu,
    }
    with open(os.path.join(OUT, "extra_analyze.stats.json"), "w") as fh:
        json.dump(raw, fh)

    # ---- match Task B ----
    year_buckets = {}
    matched = 0
    age_days = []
    for digest, nv in per_image:
        lu = digest_to_lu.get(digest)
        if not lu:
            continue
        dt = parse_iso(lu)
        if dt is None:
            continue
        matched += 1
        year_buckets.setdefault(dt.year, []).append(nv)
        age_days.append(((REF_DATE - dt).total_seconds() / 86400.0, nv))

    # ---- figures ----
    make_fig_a(grp)
    make_fig_b(year_buckets)

    # ---- write extra_results.md ----
    write_md(n_reports, grp, per_image, digest_to_lu, year_buckets,
             matched, age_days)
    print("DONE")


def write_md(n_reports, grp, per_image, digest_to_lu, year_buckets,
             matched, age_days):
    L = []
    w = L.append
    w("# AnonymousSystem - Extra results (Tasks A and B)\n")
    w(f"Generation date: 2026-05-17. Generated by `extra_analyze.py`.\n")
    w(f"SQLite source (read-only, `immutable=1`): `{DB}`")
    w(f"MongoDB source (read-only): host1, container `ditector_mongo`, "
      f"db `dockerhub_data`, collection `tags_data`.\n")
    w(f"Total reports scanned in the `reports` table: **{n_reports}**.\n")

    # ===== TASK A =====
    w("## Task A - Official vs. community images\n")
    w("Classification by `target.meta.repository_namespace`: OFFICIAL if the "
      "namespace is `library` or empty/absent; otherwise COMMUNITY. "
      "Source: a single streaming pass over `reports.report_json`.\n")

    w("### A.1 Group sizes")
    w("| Group | Images (reports) | % of total |")
    w("|---|---|---|")
    for label, key in [("Official (library)", "official"),
                        ("Community", "community")]:
        g = grp[key]
        w(f"| {label} | {g['n']} | {100.0*g['n']/n_reports:.2f}% |")
    w(f"| **Total** | **{n_reports}** | 100% |\n")

    w("### A.2 Distribution of `pkg-vuln` findings per image")
    w("Source: count of `findings[]` with `category=='pkg-vuln'` per report "
      "(merged findings, not deduplicated across scanners).\n")
    w("| Group | n images | min | median | mean | p90 | p99 | max |")
    w("|---|---|---|---|---|---|---|---|")
    for label, key in [("Official", "official"), ("Community", "community")]:
        v = sorted(grp[key]["vpi"])
        w(f"| {label} | {len(v)} | {v[0] if v else 0} | {pct(v,50):.1f} | "
          f"{mean(v):.2f} | {pct(v,90):.1f} | {pct(v,99):.1f} | "
          f"{v[-1] if v else 0} |")
    w("")

    w("### A.3 Fraction of images with >=1 secret (`category=='secret'`)")
    w("Source: the report has >=1 finding with `category=='secret'`.\n")
    w("| Group | images with secret | n images | fraction |")
    w("|---|---|---|---|")
    for label, key in [("Official", "official"), ("Community", "community")]:
        g = grp[key]
        frac = 100.0 * g["with_secret"] / g["n"] if g["n"] else 0.0
        w(f"| {label} | {g['with_secret']} | {g['n']} | {frac:.3f}% |")
    w("")

    # ===== TASK B =====
    w("## Task B - Vulnerabilities vs. tag age\n")
    uniq = {d for d, _ in per_image if d}
    n_with_digest = sum(1 for d, _ in per_image if d)
    w(f"- Reports with `target.meta.image_digest` present: **{n_with_digest}** "
      f"of {n_reports} (unique digests: {len(uniq)}).")
    w(f"- Digests resolved in Mongo's `tags_data`: **{len(digest_to_lu)}**.")
    w(f"- Reports matched by digest with a valid `last_updated`: "
      f"**{matched}** of {n_reports} "
      f"({100.0*matched/n_reports:.2f}%).\n")
    w("digest->last_updated source: an `$in` query on `tags_data` (the "
      "`digest` field matches the reports' `target.meta.image_digest`). "
      "Age = 2026-05-17 minus `last_updated`.\n")

    w("### B.1 Vulnerabilities by `last_updated` year")
    w("Source: matched reports, grouped by the year of `tags_data.last_updated`; "
      "vulns = `pkg-vuln` findings per image.\n")
    w("| last_updated year | n images | median vulns | mean vulns | "
      "p90 vulns |")
    w("|---|---|---|---|---|")
    for y in sorted(year_buckets):
        v = sorted(year_buckets[y])
        w(f"| {y} | {len(v)} | {pct(v,50):.1f} | {mean(v):.2f} | "
          f"{pct(v,90):.1f} |")
    w("")

    # age-band view
    bands = [(0, 90), (90, 180), (180, 365), (365, 730), (730, 1460),
             (1460, 1e9)]
    band_labels = ["0-3 months", "3-6 months", "6-12 months", "1-2 years",
                   "2-4 years", ">4 years"]
    band_buckets = {bl: [] for bl in band_labels}
    for age, nv in age_days:
        for (lo, hi), bl in zip(bands, band_labels):
            if lo <= age < hi:
                band_buckets[bl].append(nv)
                break
    w("### B.2 Vulnerabilities by tag age band")
    w("Source: the same matched reports, grouped by age "
      "(2026-05-17 - last_updated).\n")
    w("| Age band | n images | median vulns | mean vulns | "
      "p90 vulns |")
    w("|---|---|---|---|---|")
    for bl in band_labels:
        v = sorted(band_buckets[bl])
        if not v:
            w(f"| {bl} | 0 | - | - | - |")
            continue
        w(f"| {bl} | {len(v)} | {pct(v,50):.1f} | {mean(v):.2f} | "
          f"{pct(v,90):.1f} |")
    w("")

    # trend: correlation age vs vulns
    if age_days:
        import statistics
        xs = [a for a, _ in age_days]
        ys = [float(v) for _, v in age_days]
        n = len(xs)
        mx, my = mean(xs), mean(ys)
        cov = sum((x-mx)*(y-my) for x, y in zip(xs, ys))
        sx = math.sqrt(sum((x-mx)**2 for x in xs))
        sy = math.sqrt(sum((y-my)**2 for y in ys))
        pearson = cov / (sx*sy) if sx > 0 and sy > 0 else 0.0
        # Spearman via ranks
        def ranks(vals):
            order = sorted(range(len(vals)), key=lambda i: vals[i])
            r = [0.0]*len(vals)
            i = 0
            while i < len(order):
                j = i
                while j+1 < len(order) and vals[order[j+1]] == vals[order[i]]:
                    j += 1
                avg = (i+j)/2.0 + 1
                for k in range(i, j+1):
                    r[order[k]] = avg
                i = j+1
            return r
        rx, ry = ranks(xs), ranks(ys)
        mrx, mry = mean(rx), mean(ry)
        rcov = sum((a-mrx)*(b-mry) for a, b in zip(rx, ry))
        rsx = math.sqrt(sum((a-mrx)**2 for a in rx))
        rsy = math.sqrt(sum((b-mry)**2 for b in ry))
        spearman = rcov/(rsx*rsy) if rsx > 0 and rsy > 0 else 0.0
        w("### B.3 Trend")
        w(f"- n pairs (age_days, vulns) = {n}")
        w(f"- Pearson correlation(age_days, vulns) = **{pearson:+.4f}**")
        w(f"- Spearman correlation(age_days, vulns) = **{spearman:+.4f}**")
        med_young = pct(sorted([v for a, v in age_days if a < 365]), 50)
        med_old = pct(sorted([v for a, v in age_days if a >= 365]), 50)
        w(f"- median vulns for tags <1 year: {med_young:.1f}; "
          f">=1 year: {med_old:.1f}")
        trend = ("rise" if spearman > 0.05 else
                 "fall" if spearman < -0.05 else
                 "show no clear trend")
        w(f"- **Interpretation**: vulnerabilities {trend} with tag age "
          f"(Spearman {spearman:+.3f}).\n")

    w("## Generated files")
    for f in ["fig_official_vs_community.pdf", "fig_official_vs_community.png",
              "fig_vulns_vs_age.pdf", "fig_vulns_vs_age.png",
              "extra_results.md", "extra_analyze.stats.json"]:
        w(f"- `{f}`")
    w("")

    with open(os.path.join(OUT, "extra_results.md"), "w") as fh:
        fh.write("\n".join(L))
    print("wrote extra_results.md")


if __name__ == "__main__":
    main()
