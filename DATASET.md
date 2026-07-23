# ChimangoScan Dataset

This document describes the complete dataset produced by the ChimangoScan
measurement pipeline. The dataset has three primary components — the **scan
reports**, the **Docker Hub crawl metadata**, and the **image-layer graph** —
plus a small set of **derived artifacts** used by the paper. Every component is
described below with its schema, row counts, on-disk size, and how to read it.

> Unit of measurement: a *repository reference* (one `:latest` image per
> repository). The scanned corpus is the **52,895** highest-exposure references
> (84.7% of all 663.8 B recorded pulls); it deduplicates to **51,751** distinct
> content digests. Reports for **64,595** images are included (the 52,895 plus
> earlier scans retained for completeness).

## Download

The three databases are published as split, checksummed assets on the GitHub
release [`dataset-v1`](https://github.com/ChimangoScan/chimangoscan/releases/tag/dataset-v1)
(each part is under GitHub's 2 GB limit). Fetch, rejoin and verify all of them
with one script — no manual concatenation:

```bash
./scripts/fetch_dataset.sh --out ./dataset      # downloads + rejoins + sha256-verifies
```

This writes `chimangoscan-reports.db.zst`, `dockerhub_data.freeze.archive.gz`,
`neo4j_data.freeze.tar.gz` and `exposure_work.freeze.tar` into `./dataset`. Pass
`--only sqlite-scan-reports` (or `mongodb-crawl` / `neo4j-layer-graph` /
`layer-graph-dumps`) to fetch just one. The analysis driver can fetch
automatically: `./reproduce.sh analysis --dataset ./dataset --fetch --stage all`.

`exposure_work.freeze.tar` holds the **frozen 2026-05-18 layer-graph analysis
dumps** (`edges.tsv.gz`, `toplayers.jsonl.gz`, `repo_pull.tsv.gz`, `tags.tsv.gz`).
The reproduction pipeline uses these to recompute the exposure ranking and the
per-CVE downstream propagation **exactly** as in the paper — see the Neo4j
section below for why the live graph is not used for that.

---

## 1. Scan reports — `chimangoscan-reports.db` (SQLite, 192 GB)

One row per scanned image; the full multi-scanner output is stored as JSON.

**Tables**

| table            | rows    | purpose                                              |
|------------------|---------|------------------------------------------------------|
| `reports`        | 64,595  | one scanned image per row (`image`, `report_json`)   |
| `exposure_state` | 2       | bookkeeping for the exposure-ranked scan queue       |
| `sqlite_stat1`   | —       | SQLite query-planner statistics                      |

**`reports` schema**

- `image` TEXT — repository reference, e.g. `library/alpine:latest` (PK)
- `report_json` TEXT — one JSON document per image (schema below)

**`report_json` document**

```
target, started_at, finished_at, container_ip, open_ports, http_endpoints,
invocations, skipped_reason, findings[]
```

Each entry of `findings[]` is one finding from one scanner:

```
scanner        one of: syft, trivy, grype, osv, dockle, trufflehog
category       sbom-component | pkg-vuln | image-config | secret
severity       critical | high | medium | low | unknown
id, title, description
cvss           CVSS score/vector when applicable
package, version, fixed_version, ecosystem
location       path inside the image
cves[]         associated CVE identifiers
references[]
target_image, target_name, target_ip, endpoint
```

Aggregate: **170.4 M** findings across the corpus (141.7 M package
vulnerabilities, the rest SBOM components, misconfigurations, and secret
detections). Read example:

```python
import sqlite3, json
con = sqlite3.connect("chimangoscan-reports.db")
for image, rj in con.execute("SELECT image, report_json FROM reports"):
    findings = json.loads(rj)["findings"]
    vulns = [f for f in findings if f["category"] == "pkg-vuln"]
```

The dataset is published on the GitHub release `dataset-v1` (see the Download section above); fetch it with `./scripts/fetch_dataset.sh --out ./dataset`.

---

## 2. Docker Hub crawl metadata — MongoDB `dockerhub_data`

Output of Stage I (crawl) and Stage II (layer-graph build). Hosted in the
an ephemeral `mongo:7.0` container started by [`orchestration/analysis_mongo.sh`](orchestration/analysis_mongo.sh) (default port 27100).

| collection          | documents   | description                                        |
|---------------------|-------------|----------------------------------------------------|
| `repositories_data` | 12,716,568  | every public repository enumerated by the crawl    |
| `tags_data`         | 6,399,608   | tags resolved during Stage II (most-recent tags)   |
| `images_data`       | 7,416,671   | distinct image manifests (digests)                 |
| `crawler_keywords`  | 2,051,801   | prefix-trie keyword frontier (resumable crawl)     |

Key fields of `repositories_data`:

- `pull_count` (int) — historical pull total; the crawl sums **663,779,362,551**
  pulls over all repositories. Indexed `pull_count:-1`.
- `graph_built_at` — non-null once Stage II has resolved the repo into the layer
  graph. Indexed. Stage II processed strictly in decreasing pull order and
  resolved every repo with `pull_count >= 72` (5,601,045 repos, 44.05% of the
  crawl — a clean cut: `pull_count >= 1000` is 100% resolved).

Export: `mongodump --db dockerhub_data`. Published as
`dockerhub_data.freeze.archive.gz` on the `dataset-v1` release.

---

## 3. Image-layer graph — Neo4j

Output of Stage II. The forest of `IS_BASE_OF` relations over ancestry-hashed
layer nodes; the substrate for the exposure score and per-CVE propagation.

- **Layer nodes** (~84.7 M): each identified by
  `id = sha256(parent_id || sha256(layer_digest))`, so the id encodes the
  layer's entire ancestry and two layers with identical content under different
  parents are distinct nodes.
- **Image-bearing nodes**: 4,476,440 (a node that is the top layer of at least
  one image references its digests/tags).
- **`IS_BASE_OF` edges**: 54,382,383 (43.7 M after forest resolution — collapsing
  generic shared/metadata layers that appear under multiple parents).

Export: `neo4j-admin database dump`. Published as
`neo4j_data.freeze.tar.gz` on the `dataset-v1` release.

> **Reproducing Stage II — use the frozen dumps, not the live graph.** The layer
> graph keeps growing after the paper freeze: images continue to attach to
> layers, so `image-bearing nodes` rise from **4,476,440** (paper, 2026-05-18) to
> ~6.3 M in the published `neo4j_data.freeze.tar.gz`, and `IS_BASE_OF` edges from
> 54,382,383 to ~56.2 M. Because downstream propagation is a reachability closure
> over image-bearing nodes, recomputing it from the *restored* Neo4j inflates the
> table by ~50%. The paper's Stage-II numbers are therefore reproduced from the
> frozen analysis dumps in **`exposure_work.freeze.tar`** (the 2026-05-18 export,
> which `reproduce.sh` seeds into the working dir); on those the zlib downstream
> total is exactly **1,129,391** as published. The Neo4j archive is provided for
> graph exploration and yields the raw node/edge counts of a slightly later crawl
> snapshot (a few % above the frozen figures above).

---

## 4. Derived artifacts (in this repository / the paper repo)

- **`exposure_ranked_v3.jsonl`** — the exposure ranking, one image per line:
  `{repo, tag, pull_count, exposure, dependency_weight, owner}`. Produced by
  [`analysis/scripts/compute_exposure_ranking.py`](analysis/scripts/compute_exposure_ranking.py) from the layer graph. Sorted by
  exposure descending; the scan queue is its head.
- **Secret-validation ground truth** — `secret_sample.json` (1,100 randomly
  sampled TruffleHog detections, seed 42), `secret_classification.csv` (each
  hand-labeled TP/FP), `secret_validation_report.json` (99.7% false-positive
  rate, Wilson 95% CI 99.2–99.9%). Produced by [`secret_sample.py`](analysis/scripts/secret_sample.py) +
  [`validate_secrets.py`](analysis/scripts/validate_secrets.py).
- **Per-CVE propagation** — `cve_digests_v3.json` (CVE → affected digests) and
  `propagation_v3.json` (downstream blast radius per CVE), via
  [`extract_cve_digests.py`](analysis/scripts/extract_cve_digests.py) + [`propagation_compute.py`](analysis/scripts/propagation_compute.py).

---

## Provenance and integrity

- Crawl window: several months in 2026; scan campaign: 2026.
- Architecture: all images scanned for `linux/amd64`.
- Scanners (pinned versions in [`orchestration/`](orchestration/)): Syft, Trivy, Grype,
  OSV-Scanner, Dockle, TruffleHog.
- `SHA256SUMS` accompanies each published archive; verify with
  `sha256sum -c SHA256SUMS`.

## License

Data released under CC BY 4.0; code under the repository `LICENSE`.
