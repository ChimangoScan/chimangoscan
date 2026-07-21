# ChimangoScan — Reproduction Artifact

*Large-Scale Security Measurement of the Docker Hub Image Ecosystem*

This repository is the **reproduction artifact** for the paper *"Vulnerabilities,
Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images."* It
orchestrates the full measurement pipeline end to end: discovery and
prioritization of Docker Hub images, multi-scanner scanning of the prioritized
images, and regeneration of every data-driven analysis, figure, and table in the
paper.

**Paper abstract (summary).** Docker Hub is the default distribution channel for
containerized software, yet large-scale security measurements of its images are
infrequent and run on a single scanner. We present a pipeline that enumerates the
Docker Hub namespace and ranks images by a layer-graph *exposure* score — an
image's own pull count plus those of every image that inherits its layers. From a
crawl of **12.7 million** repositories we scanned the **52,895** highest-exposure
ones (**84.7%** of all 663.8 billion recorded pulls) with **six** independent
open-source scanners, collecting **170.4 million** findings. The measured posture
is strongly tool-dependent: of the distinct vulnerabilities the three
vulnerability scanners find, only 2.7% are reported by all three and 66.8% by a
single one; TruffleHog flags secrets in 76.9% of images, but hand-labeling shows
99.7% are non-credentials. We release the pipeline and the full 283 GB dataset.

> **Paper:** *Vulnerabilities, Secrets and Misconfiguration in the
> Highest-Exposure Docker Hub Images* — SBSeg 2026.
> **Artifact evaluation (CTA):** this README follows the SBC/SBSeg 2026 minimum
> README template; the reviewer instructions this artifact targets are at
> [subinstrucoes](https://doc-artefatos.github.io/sbseg2026/subinstrucoes.html)
> and [revinstrucoes](https://doc-artefatos.github.io/sbseg2026/revinstrucoes.html).

---

# README structure

This README follows the CTA minimum-README order: *Seals considered → Basic
information → Dependencies → Security concerns → Installation → Minimal test →
Experiments → License*. The repository itself is laid out as follows:

```
chimangoscan/
├── README.md                     this file (artifact roadmap)
├── DATASET.md                    dataset schema and access (reports, crawl, graph)
├── LICENSE                       MIT
├── stages/
│   ├── DITector/                 fork of Dr. Docker's DITector — Stages I+II (Go)
│   └── scanners/                 Stage III, multi-scanner scan (our own, Python)
├── orchestration/
│   ├── run_pipeline.sh           runs the full pipeline end to end
│   ├── minimal_test.sh           minimal test — the reproducibility claim
│   ├── run_analysis.sh           regenerates the paper's analyses/figures/tables
│   └── make_scanners_config.sh   builds the Stage III config from the ranking
└── analysis/
    └── scripts/                  paper analysis scripts: exposure ranker
                                  (compute_exposure_ranking.py), table/figure
                                  regeneration (regenerate_all.py, recount_repo.py,
                                  apply_repo_numbers.py), secret-sampling validation
                                  (secret_sample.py, validate_secrets.py), and
                                  per-CVE propagation (extract_cve_digests.py,
                                  propagation_compute.py)
```

---

# Seals considered

The seals requested for evaluation are: **Available (SeloD), Functional (SeloF),
Sustainable (SeloS), and Reproducible (SeloR)**.

| Seal | Why |
|------|-----|
| **SeloD** | Code public in this repo; dataset on the GitHub release `dataset-v1`. |
| **SeloF** | The *Minimal test* runs the pipeline end to end on one machine. |
| **SeloS** | Modular, documented: Go crawler/builder, one Python adapter per scanner, a docstring per analysis script. |
| **SeloR** | `Claim #3` regenerates every paper number, figure and table from the released databases. |

---

# Basic information

The pipeline has two execution profiles with distinct requirements.

**Minimal test** — validates end-to-end operation; runs on a single machine in
tens of minutes.

| Resource | Minimum |
|----------|---------|
| CPU | 4 cores |
| Memory | 8 GB |
| Disk | 20 GB free (Docker images + databases) |
| Network | Internet access (Docker Hub) |
| Time | ~20–45 min |

**Analysis regeneration** — reproduces the paper's tables and figures from the
released scan database. This is the primary **SeloR** path and does *not* require
re-crawling or re-scanning.

| Resource | Recommended |
|----------|-------------|
| CPU | 4+ cores |
| Memory | 8+ GB |
| Disk | ~192 GB for the released `chimangoscan-reports.db` (or use `--sample` for a quick partial run) |
| Time | ~45–50 min full pass; minutes with `--sample` |

**Full measurement** — reproduces the paper's at-scale crawl and scan. Designed
for distributed operation over days; documented for completeness but **not**
required for any seal.

| Resource | Recommended |
|----------|-------------|
| CPU | 16+ cores per node |
| Memory | 32+ GB per node (Neo4j heap configurable) |
| Disk | hundreds of GB (MongoDB/Neo4j datasets + scan artifacts) |
| Time | days (crawl + build + scan) |

Reference operating system: **Linux x86-64**. All images were scanned for the
`linux/amd64` architecture.

---

# Dependencies

**The host needs only Docker and Docker Compose.** Every pipeline stage — the Go
crawler/builder, the Python exposure ranker, the Stage III scanner orchestration,
and the analysis — runs inside containers, so no language toolchain or library is
installed on the host.

**Host requirements:**

| Component | Version | Notes |
|-----------|---------|-------|
| Docker | recent (tested with 29.x) | the only hard requirement |
| Docker Compose | v2 (recent) | brings up the MongoDB and Neo4j containers |

**Everything else is containerized — nothing to install:**

| Provided as a container | Image | Role |
|-------------------------|-------|------|
| MongoDB | `mongo:latest` (compose) | repositories and tags (Stage I/II) |
| Neo4j | `neo4j:latest` (compose) | layer graph (Stage II) |
| **Runner** | built from [`docker/Dockerfile.runner`](docker/Dockerfile.runner) — Go 1.22, Python 3, uv, matplotlib, numpy, Docker CLI | runs Stages I/II (Go), the exposure ranker, Stage III orchestration, and the analysis |
| Six scanners | Syft, Trivy, Grype, OSV-Scanner, Dockle, TruffleHog — official images **pinned by digest** | Stage III scanning, launched by the runner through the host Docker socket |

The runner image is built **automatically on first use** by any
`orchestration/*.sh` script (via [`orchestration/_runner.sh`](orchestration/_runner.sh); a few minutes, one
time). Stages run inside it with the repository bind-mounted at the same absolute
path and the host Docker socket mounted, so the scanner containers it starts are
siblings on the host daemon. No Go, Python, uv, or plotting library is ever
installed on the host.

Third-party access:

- **Docker Hub accounts** (free accounts suffice) are required by the Stage I
  crawler, supplied in `stages/DITector/accounts.json` (never committed; covered
  by [`.gitignore`](.gitignore)).
- **The released dataset** (192 GB of per-image reports, the 12.7-million-repo
  crawl metadata, and the layer graph) is published on the GitHub release `dataset-v1`; see [`DATASET.md`](DATASET.md)
  for the DOI and schema. The analysis experiments below need only the scan
  database, `chimangoscan-reports.db`.

---

# Security concerns

- The Stage I crawler requires Docker Hub accounts in
  `stages/DITector/accounts.json`. **This file must never be committed** — it is
  already covered by [`.gitignore`](.gitignore).
- Stage III **downloads and runs third-party container images**. The static
  scanners analyze the image artifact only; the (disabled-by-default) dynamic
  scanners would start the target container. Run the scan on an
  isolated/disposable machine, never on a production host.
- Stage III runs the scanner orchestrator inside the runner container with the
  host Docker socket (`/var/run/docker.sock`) bind-mounted, so it can start the
  scanner containers as siblings on the host daemon. Mounting the Docker socket
  confers control of the host Docker daemon — another reason to run the pipeline
  on a disposable machine.
- No step requires root or privileges beyond access to the Docker daemon.

---

# Installation

```bash
# 1. Clone the repository. The two pipeline stages (DITector and scanners)
#    are vendored directly under stages/ -- no submodule init is needed.
git clone https://github.com/ChimangoScan/chimangoscan
cd chimangoscan

# 2. Bring up the database infrastructure (MongoDB + Neo4j)
cd stages/DITector
docker compose up -d mongodb neo4j
cp config_template.yaml config.yaml          # adjust if needed

# 3. Provide Docker Hub accounts for the crawler
cat > accounts.json <<'EOF'
[{"username": "YOUR_USER", "password": "YOUR_PASSWORD"}]
EOF
cd ../..
```

That's the whole host-side setup — **no Go, Python, uv, or pip install**. The
runner image (Go + Python + uv + matplotlib/numpy + Docker CLI) is built
automatically the first time you run any `orchestration/*.sh` script, and every
stage executes inside it. For the analysis experiments, download
the dataset with `./scripts/fetch_dataset.sh --out ./dataset` (see [`DATASET.md`](DATASET.md)); no other setup is
required.

---

# Minimal test

The minimal test is the artifact's reproducibility **claim**:

> *The ChimangoScan pipeline runs end to end — Docker Hub discovery,
> prioritization, and multi-scanner scanning — producing a consolidated report.*

[`orchestration/minimal_test.sh`](orchestration/minimal_test.sh) validates this claim **without** scanning all of
Docker Hub. It:

1. **crawls** Docker Hub briefly, restricted to a few namespace prefixes
   (default `a,b,c`) — Stage I, in miniature;
2. **builds** the layer graph for the discovered repositories — Stage II;
3. runs the **ranker**, ordering all discovered repositories by pull count and
   supply-chain exposure;
4. selects the **top 10** most-exposed repositories and runs the six default
   scanners on them — Stage III;
5. **verifies** that the consolidated corpus report (`report.html`,
   `summary.json`, `analysis.md`) was produced.

```bash
orchestration/minimal_test.sh
# options: --prefixes a,b,c   --crawl-duration 5m   --top 10
```

- **Expected time:** ~20–45 min, dominated by pulling and scanning the 10 images.
- **Expected resources:** 4 cores, 8 GB RAM, ~20 GB disk.
- **Expected result:** the script prints `MINIMAL TEST PASSED` and the path to the
  generated artifacts under `artifacts/`.

---

# Experiments

Every paper number, figure and table is regenerated from the released databases
(re-running the full crawl/scan is not required). One command per claim.

**Fast path — no database, ~1 min.** Regenerate every figure and table value from
the shipped aggregates:

```bash
pip install -r requirements.txt && ./reproduce.sh precomputed
```

Writes `figures/*.pdf` and `figures/table_values.json` (96.3% prevalence, 66.8%
single-scanner, 2.7% all-three). Reduced variant of Claim #3.

## Claim #1 — Pipeline runs end to end (SeloF)

```bash
orchestration/minimal_test.sh --top 10
```

~20–45 min (4 cores / 8 GB / 20 GB). Prints `MINIMAL TEST PASSED` and writes a
consolidated report for 10 scanned images under `artifacts/`.

## Claim #2 — Exposure ranking prioritizes the scan queue (C1)

```bash
python3 analysis/scripts/compute_exposure_ranking.py
```

Writes `exposure_ranked.jsonl` sorted by exposure; the head is the base images
(`alpine`, `ubuntu`, `debian`). Seconds on the minimal-test graph.

## Claim #3 — Headline measurement reproduces from the dataset (C2/C3, main SeloR)

```bash
./reproduce.sh analysis --dataset ./dataset --fetch --stage all
```

Fetches the three databases from the release, recomputes every number/figure/table
and verifies them against the paper ([`analysis/expected/paper_values.json`](analysis/expected/paper_values.json), 240
checks), writing the verdict to [`docs/REPRODUCIBILITY_REPORT.md`](docs/REPRODUCIBILITY_REPORT.md). ~1 h plus the
download; several GB RAM. Add `--stage sqlite|mongo|neo4j|verify` to run one at a time.


# License

The original code of this artifact — the exposure ranker, the six-scanner
Stage III orchestration ([`stages/scanners/`](stages/scanners/)), and the analysis scripts — is
distributed under the MIT License (see [`LICENSE`](LICENSE)). The released
dataset is licensed CC BY 4.0 (see [`DATASET.md`](DATASET.md)).

[`stages/DITector/`](stages/DITector/) is a **fork of Dr. Docker's DITector**
(`github.com/NSSL-SJTU/DITector`, WWW '25): the Stage I crawler (an
unimplemented stub upstream) and the distributed re-engineering of the Stage II
graph builder are ours; the graph-builder and analyzer baseline are theirs and
are credited throughout [`stages/DITector/`](stages/DITector/) (see its [`CHANGELOG.md`](stages/DITector/CHANGELOG.md)). The
upstream carries no license and is included here with attribution.
