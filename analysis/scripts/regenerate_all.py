#!/usr/bin/env python3
"""
regenerate_all.py -- single-command regeneration pipeline for the ChimangoScan
Docker Hub measurement paper.

Every table body and every figure in the paper derives, directly or through one
intermediate JSON, from the SQLite database ditector-good.db. When the database
is updated (after new scans finish) all of those numbers must be recomputed.
This script does that in one command, in the correct order:

  STAGE 1  ANALYSIS  recount_repo.py -- one read-only streaming pass over the
                     database that recomputes ALL per-repository aggregates and
                     writes 11 analysis JSONs:
                       dedup_analysis.json   master numbers + old/new compare
                       paper_analysis.json   Shu panel (severity, CVE-by-year)
                       rich_analysis.json    severity tables, top packages, SBOM
                       plan_analysis.json    analysis plan A/B + N1..N7
                       plan_scatter.json     per-image scatter arrays
                       extra_analysis.json   Venn + official/community
                       fig_official_vs_community_stats.json
                       step3_recompute.json  per-scanner severity (.after)
                       analyze_db.stats.json accumulators for the panels
                       temporal_analysis.json  image age vs vulnerabilities
                       repro_analysis.json   Section 4.8 reproduction study
                     (recount_repo.py consolidates and supersedes the old loose
                     scripts paper_analysis.py, rich_scan.py, plan_analysis.py,
                     repro_analysis.py, temporal_analysis.py and dedup_scan.py.)

  STAGE 2  FIGURES   regenerates every figures/*.pdf produced from those JSONs:
                       plan_figs.py   fig_pull_vs_vuln, fig_allvsdistinct,
                                      fig_secret_cdf, fig_crawl_cdf,
                                      fig_marginal_scanner, fig_panel_divergence
                       square_figs.py fig_panel_results, fig_panel_inventory,
                                      fig_panel_offcomm
                       shu_figs.py    fig_shu_panel
                       panels3.py     fig_venn, fig_timeline
                     (fig_pipeline, fig_crawl and fig_inherit are hand-drawn
                     TikZ inside main.tex and carry no data, so nothing to do.)

  STAGE 3  TABLES    emits table_values.json -- every numeric value and every
                     pre-formatted LaTeX table-row body the paper's tables need
                     (Tables: dataset, severity, per-scanner, marginal,
                     all-vs-distinct, misconfig, reach, propagation, top-package,
                     plus the reproduction-section numbers). This reuses the
                     value-building logic of apply_repo_numbers.py verbatim but
                     is READ-ONLY on main.tex: it dumps the values to JSON
                     instead of substituting tokens. The author can then either
                     copy values manually or run apply_repo_numbers.py against a
                     main.tex that still carries the placeholder tokens.

The database is opened READ-ONLY (file:...?mode=ro). The pipeline never writes
to the database and never edits main.tex or paper.bib. It is idempotent: each
run overwrites its own JSON/PDF outputs and nothing else.

Two inputs are NOT derived from ditector-good.db and are reused as-is (the
pipeline copies them into the run directory if it is a fresh directory, and
errors out if they are missing):
  osv_severity_cache.json  OSV severity backfill, built by osv_step1..3 scripts
  plan_crawl.json          crawl-wide pull/dependency-weight CDF, exported from
                           MongoDB (Stage I), not from the scan database
step3_recompute.json is also seeded as a template: recount_repo.py only rewrites
its .after blocks, so a prior copy must exist (the repo ships one).

USAGE
  python3 regenerate_all.py [--db PATH] [--out DIR] [--tags PATH]
                            [--stage analysis|figures|tables|all] [--sample N]

  --db    PATH   SQLite database (default: $DITECTOR_DB or
                 /mnt/win_ssd/ditector-good.db)
  --out   DIR    run/output directory for all JSONs and figures/*.pdf
                 (default: the paper directory itself). Point this at a
                 scratch directory to validate without touching the paper.
  --tags  PATH   tags_full.jsonl for the temporal analysis
                 (default: $DITECTOR_TAGS or /mnt/cache/tags_full.jsonl;
                 if missing, the temporal analysis is skipped gracefully)
  --stage NAME   run only one stage (default: all)
  --sample N     LIMIT the database scan to N reports rows -- for a quick
                 SAMPLED validation run only; do NOT use for production numbers

ENVIRONMENT (alternative to flags): DITECTOR_DB, DITECTOR_OUT, DITECTOR_TAGS

PRODUCTION RUN (after the database is updated, from the paper directory):
  python3 regenerate_all.py --db /mnt/win_ssd/ditector-good.db
This regenerates every JSON and every figures/*.pdf in place and writes
table_values.json. main.tex is left untouched.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import time

PAPER_DIR = os.path.dirname(os.path.abspath(__file__))

# Loose scripts the pipeline drives, in execution order.
ANALYSIS_SCRIPT = "recount_repo.py"
FIGURE_SCRIPTS = ["plan_figs.py", "square_figs.py", "shu_figs.py", "panels3.py"]
SUPPORT_MODULE = "figstyle.py"          # imported by the figure scripts
TABLE_SCRIPT = "apply_repo_numbers.py"  # value-building logic reused for tables

# Inputs NOT regenerated from the database -- reused as-is.
SEED_INPUTS = ["osv_severity_cache.json", "plan_crawl.json",
               "step3_recompute.json"]

# Outputs expected from each stage (for the post-run check).
ANALYSIS_JSONS = ["dedup_analysis.json", "paper_analysis.json",
                  "rich_analysis.json", "plan_analysis.json",
                  "plan_scatter.json", "extra_analysis.json",
                  "fig_official_vs_community_stats.json",
                  "step3_recompute.json", "analyze_db.stats.json",
                  "temporal_analysis.json", "repro_analysis.json"]
EXPECTED_FIGURES = ["fig_pull_vs_vuln.pdf", "fig_allvsdistinct.pdf",
                    "fig_secret_cdf.pdf", "fig_crawl_cdf.pdf",
                    "fig_marginal_scanner.pdf", "fig_panel_divergence.pdf",
                    "fig_panel_results.pdf", "fig_panel_inventory.pdf",
                    "fig_panel_offcomm.pdf", "fig_shu_panel.pdf",
                    "fig_venn.pdf", "fig_timeline.pdf"]


def log(msg):
    sys.stdout.write("[regen %s] %s\n" % (time.strftime("%H:%M:%S"), msg))
    sys.stdout.flush()


def patch_script(src_path, dst_path, db=None, out=None, tags=None,
                  sample=None):
    """Copy a loose script, overriding its hard-coded DB / OUT / TAGS
    constants so it reads the chosen database and writes into the run
    directory. The legacy scripts all declare these as plain top-level
    `NAME = "literal"` assignments, which makes a line-anchored regex
    substitution safe and self-documenting."""
    src = open(src_path).read()

    def sub_const(text, name, value):
        pat = re.compile(r'^%s = ".*?"' % name, re.M)
        repl = '%s = %r  # overridden by regenerate_all.py' % (name, value)
        new, n = pat.subn(lambda m: repl, text, count=1)
        if n == 0:
            return text  # constant not present in this script -- leave as is
        return new

    if out is not None:
        src = sub_const(src, "OUT", out)
    if db is not None:
        src = sub_const(src, "DB", db)
    if tags is not None:
        src = sub_const(src, "TAGS", tags)

    if sample is not None:
        # SAMPLED validation only: cap the report scan. recount_repo.py runs
        # `for ... in cur.execute("SELECT ... FROM reports ...")`; appending a
        # LIMIT keeps the scan well-formed and short.
        src, n = re.subn(r'(SELECT[^"]*?FROM reports\b[^"]*?)(")',
                         r'\1 LIMIT %d\2' % sample, src, count=1,
                         flags=re.S | re.I)
        if n:
            src = ("# SAMPLED RUN: reports scan capped at LIMIT %d\n" % sample
                   + src)

    open(dst_path, "w").write(src)
    return dst_path


def run(script_path, cwd, tee_log=None):
    """Run a python script, streaming its output; optionally tee to a file."""
    log("running %s" % os.path.basename(script_path))
    proc = subprocess.Popen([sys.executable, script_path], cwd=cwd,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True)
    captured = []
    for line in proc.stdout:
        sys.stdout.write("    " + line)
        captured.append(line)
    proc.wait()
    if tee_log:
        open(tee_log, "w").write("".join(captured))
    if proc.returncode != 0:
        raise SystemExit("FAILED: %s (exit %d)"
                         % (os.path.basename(script_path), proc.returncode))


def stage_analysis(out, db, tags, sample):
    log("STAGE 1/3  ANALYSIS  -- read-only streaming pass over %s" % db)
    if not os.path.exists(db):
        raise SystemExit("database not found: %s" % db)
    for fn in SEED_INPUTS:
        dst = os.path.join(out, fn)
        if not os.path.exists(dst):
            src = os.path.join(PAPER_DIR, fn)
            if not os.path.exists(src):
                raise SystemExit("required input missing: %s" % fn)
            shutil.copy2(src, dst)
            log("seeded %s into run directory" % fn)
    patched = patch_script(os.path.join(PAPER_DIR, ANALYSIS_SCRIPT),
                           os.path.join(out, "_run_" + ANALYSIS_SCRIPT),
                           db=db, out=out, tags=tags, sample=sample)
    # apply_repo_numbers.py reads "distinct digests" out of recount_repo.log,
    # so tee recount_repo.py's stdout there.
    run(patched, cwd=out, tee_log=os.path.join(out, "recount_repo.log"))
    missing = [j for j in ANALYSIS_JSONS
               if not os.path.exists(os.path.join(out, j))]
    if missing:
        raise SystemExit("analysis did not produce: " + ", ".join(missing))
    log("STAGE 1 done -- %d analysis JSONs written" % len(ANALYSIS_JSONS))


def stage_figures(out):
    log("STAGE 2/3  FIGURES   -- regenerating figures/*.pdf")
    figdir = os.path.join(out, "figures")
    os.makedirs(figdir, exist_ok=True)
    # figstyle.py is imported by the figure scripts; make it importable.
    # When out == PAPER_DIR the file is already in place (copying it onto
    # itself raises SameFileError), so only copy when the paths differ.
    _src = os.path.join(PAPER_DIR, SUPPORT_MODULE)
    _dst = os.path.join(out, SUPPORT_MODULE)
    if os.path.abspath(_src) != os.path.abspath(_dst):
        shutil.copy2(_src, _dst)
    for fn in ["plan_crawl.json"]:  # figure-only input not made in stage 1
        dst = os.path.join(out, fn)
        if not os.path.exists(dst):
            shutil.copy2(os.path.join(PAPER_DIR, fn), dst)
    for sc in FIGURE_SCRIPTS:
        patched = patch_script(os.path.join(PAPER_DIR, sc),
                               os.path.join(out, "_run_" + sc), out=out)
        run(patched, cwd=out)
    made = [f for f in EXPECTED_FIGURES
            if os.path.exists(os.path.join(figdir, f))]
    missing = [f for f in EXPECTED_FIGURES if f not in made]
    log("STAGE 2 done -- %d/%d figures present" % (len(made),
                                                   len(EXPECTED_FIGURES)))
    if missing:
        raise SystemExit("figures not produced: " + ", ".join(missing))


def stage_tables(out):
    """Emit table_values.json from the analysis JSONs, reusing the
    value-building logic of apply_repo_numbers.py verbatim. apply_repo_numbers.py
    builds a dict R of token -> value/row-body and then substitutes it into
    main.tex; we keep the build, drop the substitution, and dump R to JSON so
    main.tex is never touched."""
    log("STAGE 3/3  TABLES    -- emitting table_values.json")
    src = open(os.path.join(PAPER_DIR, TABLE_SCRIPT)).read()
    marker = "# ===== apply ====="
    if marker not in src:
        raise SystemExit("apply marker not found in %s" % TABLE_SCRIPT)
    build = src.split(marker)[0]
    build = re.sub(r'^OUT = ".*?"', 'OUT = %r' % out, build, count=1,
                   flags=re.M)
    emit = build + (
        "\n# ===== emit (regenerate_all.py: JSON instead of main.tex) =====\n"
        "import json as _json\n"
        "_missing = sorted(k for k, v in R.items() if v is None)\n"
        "if _missing:\n"
        "    sys.exit('missing table values for: ' + ', '.join(_missing))\n"
        "_out_path = os.path.join(OUT, 'table_values.json')\n"
        "with open(_out_path, 'w') as _fh:\n"
        "    _json.dump(R, _fh, indent=1, sort_keys=True)\n"
        "print('wrote table_values.json (%d table values/row-bodies)'"
        " % len(R))\n")
    patched = os.path.join(out, "_run_emit_table_values.py")
    open(patched, "w").write(emit)
    run(patched, cwd=out)
    tv = os.path.join(out, "table_values.json")
    if not os.path.exists(tv):
        raise SystemExit("table_values.json not produced")
    log("STAGE 3 done -- table_values.json written")


def main():
    ap = argparse.ArgumentParser(
        description="One-command regeneration of all paper analysis JSONs, "
                    "figures and table values from ditector-good.db.")
    ap.add_argument("--db", default=os.environ.get(
        "DITECTOR_DB", "/mnt/win_ssd/ditector-good.db"))
    ap.add_argument("--out", default=os.environ.get(
        "DITECTOR_OUT", PAPER_DIR))
    ap.add_argument("--tags", default=os.environ.get(
        "DITECTOR_TAGS", "/mnt/cache/tags_full.jsonl"))
    ap.add_argument("--stage", choices=["analysis", "figures", "tables", "all"],
                    default="all")
    ap.add_argument("--sample", type=int, default=None,
                    help="LIMIT the reports scan to N rows (sampled "
                         "validation only -- not for production numbers)")
    args = ap.parse_args()

    db = os.path.abspath(args.db)
    out = os.path.abspath(args.out)
    tags = os.path.abspath(args.tags) if args.tags else None
    os.makedirs(out, exist_ok=True)

    log("database : %s (read-only)" % db)
    log("run dir  : %s" % out)
    log("tags     : %s" % (tags or "(none)"))
    if args.sample:
        log("SAMPLED RUN: reports scan capped at %d rows -- numbers are "
            "NOT production-grade" % args.sample)
    t0 = time.time()

    if args.stage in ("analysis", "all"):
        stage_analysis(out, db, tags, args.sample)
    if args.stage in ("figures", "all"):
        stage_figures(out)
    if args.stage in ("tables", "all"):
        stage_tables(out)

    log("ALL DONE in %.1f s -- outputs in %s" % (time.time() - t0, out))
    if out != PAPER_DIR:
        log("NOTE: run directory is not the paper directory; copy the JSONs, "
            "figures/ and table_values.json into the paper to publish.")


if __name__ == "__main__":
    main()
