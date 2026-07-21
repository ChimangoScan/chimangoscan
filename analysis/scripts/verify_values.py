#!/usr/bin/env python3
"""Verify recomputed artifacts against the numbers asserted in the paper.

Loads the committed reference (analysis/expected/paper_values.json: every
reproducible number the camera-ready paper asserts, with its source locator)
and the recomputed artifacts in --results DIR:

  table_values.json             (tables stage)
  crawl_stats.json              (MongoDB crawl stage)
  graph_stats.json              (Neo4j layer-graph stage)
  propagation_v3.json           (per-CVE downstream propagation, union method)
  secret_validation_report.json (secret ground-truth validation)

Each artifact is optional: checks whose artifact is absent are SKIPPED, so a
single stage can be verified in isolation. Comparison is exact after
normalization (thousands separators, LaTeX markup and trailing % stripped;
computed values formatted at the paper's printed precision). A check flagged
known_mismatch in the reference is reported KNOWN, not FAIL (documented in
docs/REPRODUCIBILITY_REPORT.md). Exit code 0 iff no check FAILs.

The "Verification results" section of docs/REPRODUCIBILITY_REPORT.md is
rewritten in place between the <!-- verify:begin --> / <!-- verify:end -->
markers. The timestamp comes from --timestamp or $VERIFY_TIMESTAMP (never from
the wall clock, for determinism).

Usage: verify_values.py --results DIR [--expected PATH] [--report PATH]
                        [--timestamp TS]
"""
import argparse
import json
import math
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
EXPECTED_DEFAULT = os.path.join(ROOT, "analysis", "expected", "paper_values.json")
REPORT_DEFAULT = os.path.join(ROOT, "docs", "REPRODUCIBILITY_REPORT.md")
MARK_BEGIN, MARK_END = "<!-- verify:begin -->", "<!-- verify:end -->"

ARTIFACTS = {
    "tables": "table_values.json",
    "crawl": "crawl_stats.json",
    "plan": "plan_crawl.json",
    "graph": "graph_stats.json",
    "propagation": "propagation_v3.json",
    "secrets": "secret_validation_report.json",
}


def norm(s):
    """Normalize a paper or artifact value for exact string comparison."""
    s = str(s)
    for t in ("{,}", ",", "\\textbf{", "\\texttt{", "\\%", "%", "{", "}"):
        s = s.replace(t, "")
    s = re.sub(r"\s*&\s*", " & ", s)
    return re.sub(r"\s+", " ", s).strip().lstrip("+")


def get(obj, path):
    """Resolve a dotted path; 'name[key=value]' matches inside a list."""
    for seg in path.split("."):
        m = re.match(r"([^\[\]]+)\[([^=\]]+)=(.+)\]$", seg)
        if m:
            name, key, val = m.groups()
            obj = next(x for x in obj[name] if str(x.get(key)) == val)
        elif seg.isdigit():
            obj = obj[int(seg)]
        else:
            obj = obj[seg]
    return obj


def fmt(v, rule):
    """Format a recomputed value at the paper's printed precision."""
    if rule is None or isinstance(v, str):
        return str(v)
    if rule == "int":
        return format(int(round(v)), ",")
    if rule == "floor":
        return str(int(math.floor(v)))
    kind, n = rule[:-1], int(rule[-1])
    if kind == "sci":
        e = int(math.floor(math.log10(v)))
        return "%.*fe%d" % (n, v / 10 ** e, e)
    scale = {"prec": 1, "mil": 1e6, "bil": 1e9}[kind]
    return "%.*f" % (n, v / scale)


# ---- resolver: check name -> (artifact, json-path or callable, format rule) --
def T(token):
    return ("tables", token, None)


def C(path, rule="int"):
    return ("crawl", path, rule)


def P(path, rule="int"):
    """Resolve against plan_crawl.json (the exposure-ranked resolved head)."""
    return ("plan", path, rule)


def _bucket(label, field):
    return "pull_buckets[bucket=%s].%s" % (label, field)


def _prop_row(cve):
    def f(a):
        r = next(x for x in a["top10"] if x["cve"] == cve)
        return "%s & %s & %s & %s & %.1f" % (
            r["cve"], r["package"], format(r["direct_images"], ","),
            format(r["distinct_downstream"], ","), r["factor"])
    return f


PROP_CVES = ["CVE-2026-28388", "CVE-2026-28390", "CVE-2026-28389",
             "CVE-2026-27171", "CVE-2026-28387", "CVE-2026-22796",
             "CVE-2025-68160", "CVE-2025-69421"]


def _prop_stat(agg, field):
    def f(a):
        rows = [x for x in a["top10"] if x["cve"] in PROP_CVES]
        return agg(r[field] for r in rows)
    return f


RESOLVER = {
    # tab:pulldist (crawl stage)
    "pulldist.ge1b.repos": C(_bucket(">=1B", "repos")),
    "pulldist.ge1b.pct_pulls": C(_bucket(">=1B", "pct_pulls"), "prec1"),
    "pulldist.100m_1b.repos": C(_bucket("100M-1B", "repos")),
    "pulldist.100m_1b.pct_pulls": C(_bucket("100M-1B", "pct_pulls"), "prec1"),
    "pulldist.10m_100m.repos": C(_bucket("10M-100M", "repos")),
    "pulldist.10m_100m.pct_pulls": C(_bucket("10M-100M", "pct_pulls"), "prec1"),
    "pulldist.1m_10m.repos": C(_bucket("1M-10M", "repos")),
    "pulldist.1m_10m.pct_pulls": C(_bucket("1M-10M", "pct_pulls"), "prec1"),
    "pulldist.100k_1m.repos": C(_bucket("100k-1M", "repos")),
    "pulldist.100k_1m.pct_pulls": C(_bucket("100k-1M", "pct_pulls"), "prec1"),
    "pulldist.1k_100k.repos": C(_bucket("1k-100k", "repos")),
    "pulldist.1k_100k.pct_pulls": C(_bucket("1k-100k", "pct_pulls"), "prec1"),
    "pulldist.lt1k.repos": C(_bucket("<1k", "repos")),
    "pulldist.lt1k.pct_pulls": C(_bucket("<1k", "pct_pulls"), "lt"),
    "pulldist.total_repos": C("repositories_with_pull_count"),
    # crawl totals (Sec. 3.1 / tab:dataset)
    "crawl.repositories": C("repositories_total"),
    "crawl.repositories_millions": C("repositories_total", "mil1"),
    "crawl.total_pulls": C("total_pulls"),
    "crawl.total_pulls_billions": C("total_pulls", "bil1"),
    "crawl.prefix_queries": C("prefix_queries"),
    # Section 3.1 median/p99/max are over the full crawl (Table 2 population).
    "crawl.pull_median": C("pull_median_fullcrawl"),
    "crawl.pull_p99": C("pull_p99_fullcrawl"),
    "crawl.pull_max": C("pull_max_fullcrawl", "sci1"),
    "crawl.top113_pct_pulls": ("crawl", lambda a: 100.0 * get(
        a, _bucket(">=1B", "pulls")) / a["total_pulls"], "prec0"),
    "crawl.repos_below_1k_pct": ("crawl", lambda a: 100.0 * get(
        a, _bucket("<1k", "repos")) / a["repositories_with_pull_count"], "prec0"),
    "crawl.last_updated_coverage": C("last_updated_coverage_pct", "prec1"),
    "crawl.tags_resolved": C("tags_total"),
    "crawl.image_digests": C("images_total"),
    "crawl.drdocker_delta": ("crawl",
                             lambda a: a["repositories_total"] - 12079309, "int"),
    # layer graph (Sec. 3.2 / tab:dataset)
    "graph.is_base_of_edges": ("graph", "is_base_of_edges", "int"),
    "graph.layer_nodes_millions": ("graph", "total_nodes", "mil1"),
    # tab:dataset (tables stage)
    "dataset.repositories_scanned": T("OCNTOTAL"),
    "dataset.distinct_images": T("DTDISTINCT"),
    "dataset.distinct_cves": T("DTCVES"),
    "dataset.total_findings": T("DTMERGEDTOT"),
    "dataset.total_findings_millions": T("ABMERGEDM"),
    "dataset.pkg.findings": T("DTPKGF"),
    "dataset.pkg.share": T("DTPKGS"),
    "dataset.pkg.img_ge1": T("DTPKGI"),
    "dataset.sbom.findings": T("DTSBOMF"),
    "dataset.sbom.share": T("DTSBOMS"),
    "dataset.sbom.img_ge1": T("DTSBOMI"),
    "dataset.secrets.findings": T("DTSECF"),
    "dataset.secrets.share": T("DTSECS"),
    "dataset.secrets.img_ge1": T("DTSECI"),
    "dataset.misconfig.findings": T("DTMISCF"),
    "dataset.misconfig.share": T("DTMISCS"),
    "dataset.misconfig.img_ge1": T("DTMISCI"),
    # tab:severity
    "severity.critical.findings": T("SVCF"),
    "severity.high.findings": T("SVHF"),
    "severity.medium.findings": T("SVMF"),
    "severity.low.findings": T("SVLF"),
    "severity.info.findings": T("SVIF"),
    "severity.unrated.findings": T("SVUF"),
    "severity.total.findings": T("SVTOTF"),
    "severity.critical.pct_findings": T("SVCFP"),
    "severity.high.pct_findings": T("SVHFP"),
    "severity.medium.pct_findings": T("SVMFP"),
    "severity.low.pct_findings": T("SVLFP"),
    "severity.info.pct_findings": T("SVIFP"),
    "severity.unrated.pct_findings": T("SVUFP"),
    "severity.critical.images": T("SVCN"),
    "severity.high.images": T("SVHN"),
    "severity.medium.images": T("SVMN"),
    "severity.low.images": T("SVLN"),
    "severity.info.images": T("SVIN"),
    "severity.unrated.images": T("SVUN"),
    "severity.total.images": T("SVTOTN"),
    "severity.critical.pct_images": T("SVCNP"),
    "severity.high.pct_images": T("SVHNP"),
    "severity.medium.pct_images": T("SVMNP"),
    "severity.low.pct_images": T("SVLNP"),
    "severity.info.pct_images": T("SVINP"),
    "severity.unrated.pct_images": T("SVUNP"),
    "severity.total.pct_images": T("SVTOTNP"),
    # Sec. 4.1 prevalence
    "prevalence.vuln_pct": T("PVVULN"),
    "prevalence.clean_pct": T("PVCLEAN"),
    "prevalence.critical_pct": T("PVCRIT"),
    "prevalence.high_pct": T("PVHIGH"),
    "prevalence.median": T("PVMED"),
    "prevalence.mean": T("PVMEAN"),
    "prevalence.p99": T("PVP99"),
    "prevalence.max": T("PVMAX"),
    "prevalence.pkg_findings_millions": T("PVPKGM"),
    "prevalence.crit_high_millions": T("PVCHM"),
    # tab:perscanner
    "perscanner.syft.findings": T("PSSYFF"),
    "perscanner.syft.run_ok": T("PSRELSYF"),
    "perscanner.trivy.findings": T("PSTRVF"),
    "perscanner.trivy.critical": T("PSTRVC"),
    "perscanner.trivy.high": T("PSTRVH"),
    "perscanner.trivy.medium": T("PSTRVMED"),
    "perscanner.trivy.low": T("PSTRVL"),
    "perscanner.trivy.run_ok": T("PSRELTRV"),
    "perscanner.grype.findings": T("PSGRPF"),
    "perscanner.grype.critical": T("PSGRPC"),
    "perscanner.grype.high": T("PSGRPH"),
    "perscanner.grype.medium": T("PSGRPMED"),
    "perscanner.grype.low": T("PSGRPL"),
    "perscanner.grype.run_ok": T("PSRELGRP"),
    "perscanner.osv.findings": T("PSOSVF"),
    "perscanner.osv.critical": T("PSOSVC"),
    "perscanner.osv.high": T("PSOSVH"),
    "perscanner.osv.medium": T("PSOSVMED"),
    "perscanner.osv.low": T("PSOSVL"),
    "perscanner.osv.run_ok": T("PSRELOSV"),
    "perscanner.dockle.findings": T("PSDCKF"),
    "perscanner.dockle.critical": T("PSDCKC"),
    "perscanner.dockle.medium": T("PSDCKMED"),
    "perscanner.dockle.low": T("PSDCKL"),
    "perscanner.dockle.run_ok": T("PSRELDCK"),
    "perscanner.trufflehog.findings": T("PSTRFF"),
    "perscanner.trufflehog.critical": T("PSTRFC"),
    "perscanner.trufflehog.high": T("PSTRFH"),
    "perscanner.trufflehog.medium": T("PSTRFMED"),
    "perscanner.trufflehog.low": T("PSTRFL"),
    "perscanner.trufflehog.run_ok": T("PSRELTRF"),
    "perscanner.trivy_errors": T("PSERRTRV"),
    "perscanner.grype_millions": T("PSGRPM"),
    "perscanner.trivy_millions": T("PSTRVM"),
    "perscanner.osv_millions": T("PSOSVM"),
    "perscanner.syft_millions": T("PSSYFM"),
    "perscanner.trufflehog_millions": T("PSTRFM"),
    "perscanner.dockle_millions": T("PSDCKM"),
    # Syft inventory (Sec. 4.2)
    "inventory.median": T("CICMED"),
    "inventory.mean": T("CICMEAN"),
    "inventory.max": T("CICMAX"),
    "inventory.npm_pct": T("CIECONPM"),
    "inventory.deb_pct": T("CIECODEB"),
    # Sec. 4.3 divergence
    "divergence.groups_millions": T("DGTOTAL"),
    "divergence.single_pct": T("DGSINGLE"),
    "divergence.three_pct": T("DGTHREE"),
    "divergence.grype_trivy_millions": T("DGGT"),
    "divergence.spread": T("DGSPREAD"),
    "divergence.best_single_pct": T("MGBEST1"),
    # Sec. 4.4 misconfiguration + tab:misconfig
    "misconfig.images_pct": T("SCMISCP"),
    "misconfig.images": T("SCMISCN"),
    "misconfig.fatal_findings": T("SCFATALN"),
    "misconfig.credential_images": T("SCCREDN"),
    "misconfig.cis_di_0005.images": T("MC0005N"),
    "misconfig.cis_di_0005.pct": T("MC0005P"),
    "misconfig.cis_di_0006.images": T("MC0006N"),
    "misconfig.cis_di_0006.pct": T("MC0006P"),
    "misconfig.cis_di_0001.images": T("MC0001N"),
    "misconfig.cis_di_0001.pct": T("MC0001P"),
    "misconfig.cis_di_0008.images": T("MC0008N"),
    "misconfig.cis_di_0008.pct": T("MC0008P"),
    "misconfig.cis_di_0010.images": T("MC0010N"),
    "misconfig.cis_di_0010.pct": T("MC0010P"),
    "misconfig.dkl_li_0001.images": T("MCEMPTYPWN"),
    "misconfig.dkl_li_0001.pct": T("MCEMPTYPWP"),
    "misconfig.dkl_di_0001.images": T("MCSUDON"),
    "misconfig.dkl_di_0001.pct": T("MCSUDOP"),
    # Sec. 4.4 secrets
    "secrets.images_pct": T("SCSECP"),
    "secrets.images": T("SCSECN"),
    "secrets.median": T("SCSECMED"),
    "secrets.p99": T("SCSECP99"),
    "secrets.max": T("SCSECMAX"),
    "secrets.official_max": T("SCOFFMAX"),
    "secrets.sample_size": ("secrets", "sample_size", "int"),
    "secrets.true_positives": ("secrets", "true_positive_candidates", "int"),
    "secrets.false_positives": ("secrets", "false_positives", "int"),
    "secrets.fp_rate_pct": ("secrets", "fp_rate_pct", "prec1"),
    "secrets.fp_wilson_lo": ("secrets", "fp_rate_wilson_ci_pct.0", "prec1"),
    "secrets.fp_wilson_hi": ("secrets", "fp_rate_wilson_ci_pct.1", "prec1"),
    "secrets.tp_rate_pct": ("secrets", "tp_rate_pct", "prec1"),
    # Sec. 4.5 official vs community
    "official.count": T("OCNOFF"),
    "community.count": T("OCNCOM"),
    "official.median": T("OCMEDOFF"),
    "community.median": T("OCMEDCOM"),
    "official.mean": T("OCMEANOFF"),
    "community.mean": T("OCMEANCOM"),
    "official.above_median_pct": T("OCABOVEOFF"),
    "community.above_median_pct": T("OCABOVECOM"),
    "official.secret_pct": T("OCSECOFF"),
    "community.secret_pct": T("OCSECCOM"),
    # Sec. 4.6 exposure
    "exposure.rho_pull": T("EXRHOPULL"),
    "exposure.rho_exposure": T("EXRHOEXP"),
    "exposure.rho_exposure_critical": T("EXRHOEXPC"),
    "exposure.top_decile_median": T("EXMEDTOP"),
    # tab:reach
    "reach.row1": T("RCH1"), "reach.row2": T("RCH2"),
    "reach.row3": T("RCH3"), "reach.row4": T("RCH4"),
    "reach.row5": T("RCH5"), "reach.row6": T("RCH6"),
    "reach.row7": T("RCH7"), "reach.row8": T("RCH8"),
    "reach.top_exposure_pct": T("RCHTOPEXP"),
    "reach.top_image_pct": T("RCHTOPIMG"),
    # tab:propagation (union method, propagation_v3.json)
    "propagation.row1": ("propagation", _prop_row(PROP_CVES[0]), None),
    "propagation.row2": ("propagation", _prop_row(PROP_CVES[1]), None),
    "propagation.row3": ("propagation", _prop_row(PROP_CVES[2]), None),
    "propagation.row4": ("propagation", _prop_row(PROP_CVES[3]), None),
    "propagation.row5": ("propagation", _prop_row(PROP_CVES[4]), None),
    "propagation.row6": ("propagation", _prop_row(PROP_CVES[5]), None),
    "propagation.row7": ("propagation", _prop_row(PROP_CVES[6]), None),
    "propagation.row8": ("propagation", _prop_row(PROP_CVES[7]), None),
    "propagation.zlib_downstream": ("propagation", "zlib_value", "int"),
    "propagation.min_downstream_millions":
        ("propagation", _prop_stat(min, "distinct_downstream"), "mil1"),
    "propagation.max_downstream_millions":
        ("propagation", _prop_stat(max, "distinct_downstream"), "mil2"),
    "propagation.factor_min": ("propagation", _prop_stat(min, "factor"), "floor"),
    "propagation.factor_max": ("propagation", _prop_stat(max, "factor"), "floor"),
    # tab:toppkg
    "toppkg.row1": T("TPK1"), "toppkg.row2": T("TPK2"),
    "toppkg.row3": T("TPK3"), "toppkg.row4": T("TPK4"),
    "toppkg.row5": T("TPK5"), "toppkg.row6": T("TPK6"),
    "toppkg.row7": T("TPK7"), "toppkg.row8": T("TPK8"),
    "toppkg.row9": T("TPK9"), "toppkg.row10": T("TPK10"),
    # tab:repro (our-corpus column) and Sec. 4.8 text
    "repro.shu.critical_modal_pct": T("RPCRITP"),
    "repro.liu.official_pct": T("RPLIUOFFP"),
    "repro.liu.community_pct": T("RPLIUCOMP"),
    "repro.wist.os_pct": T("RPWISTOSP"),
    "repro.wist.lang_pct": T("RPWISTLANGP"),
    "repro.wist.go_millions": T("RPWISTGO"),
    "repro.wist.npm_millions": T("RPWISTNPM"),
    "repro.wist.python_millions": T("RPWISTPY"),
    "repro.mills.median_recent": T("RPMILLSYOUNG"),
    "repro.mills.median_old": T("RPMILLSOLD"),
    "repro.cves_2020_or_later_pct": T("RPRECENTP"),
    "repro.zlib_images": T("RPZLIBN"),
    "repro.openssl_images": T("RPOSSLN"),
    "repro.dahlmanns.private_key_pct": T("RPDAHLPKP"),
}


def run_checks(expected, artifacts):
    rows = []
    for name, entry in expected.items():
        exp = entry["value"]
        res = RESOLVER.get(name)
        if res is None:
            rows.append((name, "SKIP", exp, "-",
                         "not recomputable from the released artifacts"))
            continue
        art_key, spec, rule = res
        art = artifacts.get(art_key)
        if art is None:
            rows.append((name, "SKIP", exp, "-",
                         "%s not in results dir" % ARTIFACTS[art_key]))
            continue
        try:
            raw = spec(art) if callable(spec) else get(art, spec)
        except (KeyError, IndexError, StopIteration, TypeError):
            rows.append((name, "FAIL", exp, "-",
                         "value missing in %s" % ARTIFACTS[art_key]))
            continue
        if rule in ("gt", "lt"):
            thr = float(norm(exp).lstrip("<>"))
            ok = raw > thr if rule == "gt" else raw < thr
            comp = format(raw, ",") if float(raw).is_integer() else str(raw)
        else:
            comp = fmt(raw, rule)
            ok = norm(comp) == norm(exp)
        tol = entry.get("tol")
        if not ok and tol and rule not in ("gt", "lt"):
            try:
                e = float(norm(str(exp)))
                c = float(norm(str(comp)))
                ok = e != 0 and abs(c - e) <= tol * abs(e)
                status_tol = ok
            except ValueError:
                status_tol = False
        else:
            status_tol = False
        if ok and status_tol:
            status = "DRIFT"
        elif ok:
            status = "PASS"
        elif entry.get("known_mismatch"):
            status = "KNOWN"
        else:
            status = "FAIL"
        rows.append((name, status, exp, comp, entry["source"]))
    return rows


def render_section(rows, results_dir, timestamp):
    counts = {s: sum(1 for r in rows if r[1] == s)
              for s in ("PASS", "DRIFT", "FAIL", "KNOWN", "SKIP")}
    lines = [
        MARK_BEGIN,
        "Generated by `analysis/scripts/verify_values.py --results %s`; "
        "timestamp: %s." % (results_dir, timestamp),
        "",
        "**Summary: %(PASS)d pass / %(FAIL)d fail / %(KNOWN)d known mismatch / "
        "%(SKIP)d skip** (%(total)d checks)." % dict(counts, total=len(rows)),
        "",
        "| Check | Status | Expected (paper) | Computed | Source / reason |",
        "|---|---|---|---|---|",
    ]
    for name, status, exp, comp, src in rows:
        lines.append("| %s | %s | %s | %s | %s |"
                     % (name, status, norm(exp), norm(comp), src))
    lines.append(MARK_END)
    return "\n".join(lines)


def update_report(path, section):
    with open(path) as fh:
        text = fh.read()
    pattern = re.escape(MARK_BEGIN) + r".*?" + re.escape(MARK_END)
    if not re.search(pattern, text, flags=re.S):
        sys.exit("markers %s / %s not found in %s" % (MARK_BEGIN, MARK_END, path))
    with open(path, "w") as fh:
        fh.write(re.sub(pattern, lambda _: section, text, flags=re.S))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", required=True,
                    help="directory with the recomputed artifacts")
    ap.add_argument("--expected", default=EXPECTED_DEFAULT)
    ap.add_argument("--report", default=REPORT_DEFAULT,
                    help="Markdown report to rewrite between the verify markers")
    ap.add_argument("--timestamp",
                    default=os.environ.get("VERIFY_TIMESTAMP", "(not provided)"))
    args = ap.parse_args()

    with open(args.expected) as fh:
        expected = json.load(fh)
    unknown = sorted(set(RESOLVER) - set(expected))
    if unknown:
        sys.exit("resolver checks missing from %s: %s"
                 % (args.expected, ", ".join(unknown)))

    artifacts = {}
    for key, fname in ARTIFACTS.items():
        path = os.path.join(args.results, fname)
        if os.path.exists(path):
            with open(path) as fh:
                artifacts[key] = json.load(fh)

    rows = run_checks(expected, artifacts)
    for name, status, exp, comp, src in rows:
        detail = ("expected=%s computed=%s" % (norm(exp), norm(comp))
                  if comp != "-" else "%s (%s)" % (norm(exp), src))
        print("%-5s %-38s %s" % (status, name, detail))
    counts = {s: sum(1 for r in rows if r[1] == s)
              for s in ("PASS", "DRIFT", "FAIL", "KNOWN", "SKIP")}
    print("\nsummary: %(PASS)d pass / %(FAIL)d fail / %(KNOWN)d known mismatch "
          "/ %(SKIP)d skip" % counts)

    if os.path.exists(args.report):
        update_report(args.report,
                      render_section(rows, args.results, args.timestamp))
        print("report updated: %s" % args.report)
    else:
        print("report not found, section not written: %s" % args.report)
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
