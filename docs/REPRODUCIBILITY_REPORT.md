# Reproducibility Report

This report accompanies the AnonymousSystem artifact for the paper
*"Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker
Hub Images"*. The committed reference `analysis/expected/paper_values.json`
lists every reproducible number the camera-ready paper asserts (240 checks:
every cell of the pull-distribution, dataset, severity, per-scanner,
misconfiguration, reach, propagation, top-package and reproduction tables, plus
the headline numbers in the abstract, introduction and results text), each with
its source locator in the paper.

To verify a recomputation, point the verifier at the directory holding the
recomputed artifacts (`table_values.json`, `crawl_stats.json`,
`graph_stats.json`, `propagation_v3.json`, `secret_validation_report.json`;
each is optional, so a single stage can be verified in isolation):

```
python3 analysis/scripts/verify_values.py --results artifacts/analysis \
    [--timestamp "$(date -u +%FT%TZ)"]
```

Comparison is exact after normalization (thousands separators and LaTeX markup
stripped; recomputed values formatted at the paper's printed precision). The
verifier prints one PASS/FAIL/SKIP line per check, rewrites the "Verification
results" section below in place, and exits non-zero iff any check FAILs.

## Known limitations and inconsistencies

1. **Severity table, Low "% of findings" (paper typo, fixed).** Earlier
   camera-ready drafts printed 13.8% for the Low row, but the table's own cells
   give 19,418,002 / 141,683,960 = 13.7%. The typo was found by this
   verification and corrected in the camera-ready; `paper_values.json` carries
   the corrected 13.7. Every other percentage in the paper is consistent with
   its underlying counts.
2. **Pull-distribution table had no committed script.** The camera-ready's
   Table 2 (pull-count buckets) was originally computed with ad-hoc queries;
   the MongoDB analysis stage now ships `analysis/scripts/crawl_stats.py`,
   which recomputes every bucket, the crawl totals and the pull-count
   median/p99/max server-side from the Stage I database.
3. **Uncommitted input generators, now added.** The generators for
   `plan_crawl.json` (crawl-wide pull CDF), `tags_full.jsonl` and the top-60k
   corpus filter were never committed with the original analysis; the artifact
   now includes `export_plan_crawl.py`, `export_tags.py` and
   `make_corpus_filter.py` so these seed inputs are reproducible from the raw
   databases instead of being opaque files.
4. **`fig_repro_panel.pdf` was not wired into the figure orchestrator.** The
   figure existed in the paper repository but `regenerate_all.py` did not
   rebuild it; it is now wired into the figures stage, so a full regeneration
   produces all figures the paper embeds.
5. **Shipped extracts predate the Dockle-misconfig keying fix.** Commit
   `a5655ee` fixed how misconfiguration findings are keyed by Dockle check id.
   Analysis extracts produced before that fix (including the stale
   `table_values.json` kept in the private paper repository) carry `MC*` = 0
   and lack the `MCEMPTYPW`/`MCSUDO` tokens; the paper's Table 8 numbers come
   from the fixed recomputation. Verifying a pre-fix `table_values.json`
   therefore FAILs exactly the misconfiguration checks — by design.
6. **Propagation method: union, not sum.** Table 7 uses the union method
   (`propagation_compute.py` → `propagation_v3.json`): the distinct downstream
   set of all images carrying a CVE, so shared descendants are not
   double-counted. Older `PROP*` tokens in `apply_repo_numbers.py` encode a
   superseded per-image-sum variant; the verifier checks Table 7 against the
   union numbers in `propagation_v3.json` and ignores the `PROP*` tokens.
7. **Secret ground-truth labels are committed, not re-elicited.** The manual
   verdicts of the 1,100-detection sample live as `MANUAL_TP` in
   `validate_secrets.py` (the review worksheet's MANUAL column was left empty),
   so a reproduction reuses the committed labels rather than re-labeling by
   hand. Re-labeling would require a human pass over the sample.
8. **The committed secret sample is authoritative.** `secret_sample.py` is
   seeded (`random.seed(42)`) but its reservoir sampling depends on database
   row order, which is not guaranteed to be stable across dumps/restores. The
   committed `secret_sample.json` is therefore the authoritative sample; the
   validation report is deterministic given that file.
9. **Dataset-size statements disagree.** The README has referred to the
   dataset as 146 GB, ~179 GB and 283 GB in different places; the paper's
   Table 3 reports 283 GB total (192 GB reports + 24.9 GB MongoDB + 65.9 GB
   Neo4j). The discrepancy is a documentation artifact (compressed vs.
   uncompressed, and whether the layer graph is included) and does not affect
   any measurement. Storage sizes are environment-dependent and are not
   machine-verified.
10. **Zenodo DOI not yet minted.** The dataset release references a Zenodo
    deposit whose DOI has not been minted yet; until then the download
    locations in `DATASET.md` are provisional.

**Not machine-checkable.** Fourteen paper numbers have no recomputable artifact
in this release and are reported SKIP by the verifier: the Stage II resolution
progress (5,601,045 repositories; 44.05%) and scan-queue size (6.7 M), which
describe the dataset freeze rather than a recomputation; the scanned-corpus
pull-coverage share (84.7%), which needs the exposure ranking join; the scan
wall-times (median 117 s, mean 197 s, max 9,433 s; Grype 35.1 s/image), which
are recomputable only from the raw timing lists in the scan database; the
campaign constants (6 scanners, 13 workers); and the storage sizes (192 / 24.9
/ 65.9 / 283 GB).

## Verification results

<!-- verify:begin -->
No verification run recorded yet. Run
`python3 analysis/scripts/verify_values.py --results <DIR>` to populate this
section.
<!-- verify:end -->
