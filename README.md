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

The documentation follows the artifact-submission guidelines of the SBC Brazilian
Symposium on Cybersecurity (SBSeg) Artifact Evaluation Committee (CTA).

---

# README structure

This README is organized exactly as the CTA minimum-README requires:

- **Seals considered** — the four seals requested for evaluation.
- **Basic information** — execution environment, hardware/software requirements.
- **Dependencies** — languages, tools, versions, and third-party access.
- **Security concerns** — risks to reviewers and how to contain them.
- **Installation** — clone, bring up the databases, resolve dependencies.
- **Minimal test** — a single command that exercises the whole pipeline in
  miniature (~20–45 min, one machine).
- **Experiments** — the paper's claims, each in its own subsection with the exact
  commands, flags, expected time, expected resources, and expected result.
- **License**.

The repository itself is laid out as follows:

```
chimangoscan/
├── README.md                     this file (artifact roadmap)
├── DATASET.md                    dataset schema and access (reports, crawl, graph)
├── LICENSE                       MIT
├── stages/
│   ├── chimangoscan/             vendored — Stages I+II + exposure ranker (Go + Python)
│   └── scanners/                 vendored — Stage III, multi-scanner scan (Python)
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

> **Not included here:** the paper `main.tex` and PDF, kept in a separate private
> repository. This artifact contains only the code and data that produce the
> paper's results.

---

# Reproduction

Reproduction is fully automated through a top-level `Makefile` and `reproduce.sh`,
in **two modes**.

## Precomputed (figures + tables, no database/network/credentials)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
./reproduce.sh precomputed         # or:  make precomputed
```

This regenerates **every** paper figure and every table value from the small
precomputed data shipped in `analysis/data/` — it needs **no database, no
network access, no credentials, and no Docker**, only Python and the two
libraries pinned in `requirements.txt`. It runs in seconds and writes:

- `figures/*.pdf` — the twelve data-driven figures of the paper;
- `figures/table_values.json` — every numeric value and pre-formatted LaTeX
  table-row body the paper's tables use (e.g. 96.3% vulnerability prevalence,
  66.8% single-scanner findings, 2.7% agreed by all three, 51,751 distinct
  content digests).

Internally this drives the figure scripts (`analysis/scripts/plan_figs.py`,
`square_figs.py`, `shu_figs.py`, `panels3.py`, shared style in `figstyle.py`)
and the table-value emitter (`apply_repo_numbers.py`), orchestrated by
`regenerate_all.py`, over the shipped JSON inputs in `analysis/data/`. The
283 GB scan dataset is **not** required for this path (it is released on
acceptance); the precomputed JSONs are the small per-image aggregates those
scripts consume.

`make precomputed` is self-contained: it creates `.venv`, installs
`requirements.txt`, and runs the precomputed reproduction in one step.

## Full (the real pipeline, end to end, at a configurable scale)

```bash
./reproduce.sh full --scale 10     # or:  make full SCALE=10
```

This runs the real pipeline end to end — **Stage I** (crawl Docker Hub) →
**Stage II** (build the IDEA layer graph) → **exposure ranker** → **Stage III**
(six-scanner scan) → analysis — at a **configurable scale**. The host needs only
Docker; every stage runs inside the containerized runner image
(`docker/Dockerfile.runner`). Scale and targets come from flags
(`--scale`, `--prefixes`, `--crawl-duration`) — there is **no hardcoded
infrastructure**. The default scale is small (a few repositories, one
laptop + Docker) and finishes in tens of minutes. Provide Docker Hub accounts
in `stages/chimangoscan/accounts.json` first (see *Security concerns*).

Reproducing the paper at **full scale (52,895 images, 663.8 billion pulls)**
requires the authors' **multi-machine setup** (distributed crawl, a large Neo4j
layer graph, and a six-scanner sweep over hundreds of GB of images) and runs for
**months**; `./reproduce.sh full` reproduces the *same* pipeline at the scale you
choose. The full pipeline can also be driven directly through
`orchestration/run_pipeline.sh` (see *Experiments*).

---

# Seals considered

The seals requested for evaluation are: **Available (SeloD), Functional (SeloF),
Sustainable (SeloS), and Reproducible (SeloR)**.

| Seal | Code | Justification |
|------|------|---------------|
| Available    | **SeloD** | Code is publicly versioned in this repository (the two pipeline stages are vendored under `stages/`); the dataset is being published on Zenodo (DOI pending; see DATASET.md). |
| Functional   | **SeloF** | The pipeline runs; the *Minimal test* below validates end-to-end operation on a single machine. |
| Sustainable  | **SeloS** | The code is modular and documented: Stages I/II are a distributed Go service, Stage III is a Python scan system with one adapter per scanner and a single `Finding` schema, and every analysis script carries a module docstring. The "Experiments" section maps each paper claim to the exact file and command that produces it. |
| Reproducible | **SeloR** | `orchestration/run_analysis.sh` regenerates *every* number, figure, and table of the paper from the released scan database in one read-only pass. |

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
| Neo4j | `neo4j:latest` (compose) | IDEA layer graph (Stage II) |
| **Runner** | built from `docker/Dockerfile.runner` — Go 1.22, Python 3, uv, matplotlib, numpy, Docker CLI | runs Stages I/II (Go), the exposure ranker, Stage III orchestration, and the analysis |
| Six scanners | Syft, Trivy, Grype, OSV-Scanner, Dockle, TruffleHog — official images **pinned by digest** | Stage III scanning, launched by the runner through the host Docker socket |

The runner image is built **automatically on first use** by any
`orchestration/*.sh` script (via `orchestration/_runner.sh`; a few minutes, one
time). Stages run inside it with the repository bind-mounted at the same absolute
path and the host Docker socket mounted, so the scanner containers it starts are
siblings on the host daemon. No Go, Python, uv, or plotting library is ever
installed on the host.

Third-party access:

- **Docker Hub accounts** (free accounts suffice) are required by the Stage I
  crawler, supplied in `stages/chimangoscan/accounts.json` (never committed; covered
  by `.gitignore`).
- **The released dataset** (192 GB of per-image reports, the 12.7-million-repo
  crawl metadata, and the layer graph) will be published on Zenodo (DOI pending); see `DATASET.md`
  for the DOI and schema. The analysis experiments below need only the scan
  database, `chimangoscan-reports.db`.

---

# Security concerns

- The Stage I crawler requires Docker Hub accounts in
  `stages/chimangoscan/accounts.json`. **This file must never be committed** — it is
  already covered by `.gitignore`.
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
# 1. Clone the repository. The two pipeline stages (ChimangoScan and scanners)
#    are vendored directly under stages/ -- no submodule init is needed.
git clone https://github.com/ChimangoScan/chimangoscan
cd chimangoscan

# 2. Bring up the database infrastructure (MongoDB + Neo4j)
cd stages/chimangoscan
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
`chimangoscan-reports.db` from the Zenodo record (see `DATASET.md`); no other setup is
required.

---

# Minimal test

The minimal test is the artifact's reproducibility **claim**:

> *The ChimangoScan pipeline runs end to end — Docker Hub discovery,
> prioritization, and multi-scanner scanning — producing a consolidated report.*

`orchestration/minimal_test.sh` validates this claim **without** scanning all of
Docker Hub. It:

1. **crawls** Docker Hub briefly, restricted to a few namespace prefixes
   (default `a,b,c`) — Stage I, in miniature;
2. **builds** the IDEA layer graph for the discovered repositories — Stage II;
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

Every table value and every data-driven figure in the paper derives from the
released SQLite scan database `chimangoscan-reports.db`. Re-running the full at-scale
crawl and scan is **not** feasible in a review window (days, 13 machines), so —
as the CTA allows — the experiments below reproduce the paper's **main claims**
from the released artifacts. The only artifact crossing the boundary between the
discovery/prioritization stages and the scan stage is `exposure_ranked.jsonl` —
the pipeline's *contract*.

## Claim 1 — The pipeline runs end to end (SeloF)

*The three stages run in sequence and produce a consolidated multi-scanner
report.* This is the Minimal test above.

- **Command:** `orchestration/minimal_test.sh --prefixes a,b,c --crawl-duration 5m --top 10`
- **Config:** Docker Hub accounts in `stages/chimangoscan/accounts.json`; databases up
  (`docker compose up -d mongodb neo4j`).
- **Expected time / resources:** ~20–45 min; 4 cores, 8 GB RAM, 20 GB disk.
- **Expected result:** `MINIMAL TEST PASSED`; `artifacts/report.html`,
  `summary.json`, and `analysis.md` exist; `summary.json` reports 10 scanned
  images, each with findings from the six scanners.

## Claim 2 — The exposure score prioritizes the scan queue (paper contribution C1)

*The ranker folds an image's own pull count and the pull counts of its entire
downstream layer subtree into a single scalar `E(I)`, attributing each downstream
pull to a single owner (the most-pulled base in its lineage), and orders the scan
queue by it.* At full scale the metric places `alpine:latest` first, with
`E ≈ 8.3 × 10^10`.

- **File:** `analysis/scripts/compute_exposure_ranking.py` (implements Eq. (1) of
  the paper: single-owner downstream attribution over the `IS_BASE_OF` forest).
- **Command (on the released layer graph):**
  ```bash
  NEO4J_URI=bolt://127.0.0.1:7687 \
  MONGO_URI=mongodb://127.0.0.1:27017 \
  python3 analysis/scripts/compute_exposure_ranking.py
  ```
  On the mini-graph produced by the Minimal test, the same script runs in seconds
  and orders that small corpus.
- **Flags / env:** `NEO4J_URI`, `MONGO_URI`, `OUT_PATH`, `RANKER_SHARDS`
  (parallel Neo4j streaming shards).
- **Expected time / resources:** seconds on the minimal-test graph; tens of
  minutes on the full released graph (Neo4j loaded, several GB RAM).
- **Expected result:** `exposure_ranked.jsonl`, one JSON object per repository
  (`repository_namespace`, `repository_name`, `tag_name`, `pull_count`,
  `dependency_weight`, `downstream_pull_sum`, `exposure`), sorted by `exposure`
  descending. On the full graph the head of the file is the general-purpose base
  images (`alpine`, `ubuntu`, `debian`), whose exposure is dominated by downstream
  reuse.

## Claim 3 — The headline measurement reproduces from the released database (C2/C3, main SeloR claim)

*From the released scan database, every data-driven table and figure of the paper
is regenerated in one read-only pass:* 96.3% of images carry a known
vulnerability; the three vulnerability scanners agree on only 2.7% of distinct
findings while 66.8% are single-scanner (a 1.55× volume spread); and 99.7% of a
hand-labeled secret sample are non-credentials.

- **File:** `orchestration/run_analysis.sh` → `analysis/scripts/regenerate_all.py`
  (drives `recount_repo.py` for the analysis JSONs, the figure scripts, and
  `apply_repo_numbers.py` for `table_values.json`).
- **Command (full):**
  ```bash
  orchestration/run_analysis.sh --db /path/to/chimangoscan-reports.db
  # individual stages: --stage analysis | figures | tables
  ```
- **Command (quick sampled validation):**
  ```bash
  orchestration/run_analysis.sh --db /path/to/chimangoscan-reports.db --sample 100000
  ```
- **Flags:** `--db` (database path), `--stage` (run one of analysis/figures/tables/all),
  `--sample N` (cap the scan to N report rows — sampled validation only, not for
  production numbers).
- **Expected time / resources:** ~45–50 min full pass over the 64,595-report
  database; minutes with `--sample`. Needs the ~192 GB `chimangoscan-reports.db` on disk
  and several GB RAM. The database is opened **read-only**; the step is idempotent
  and never edits the paper.
- **Expected result:** the analysis JSONs (e.g., `dedup_analysis.json` reporting
  **52,895** distinct images, **51,751** distinct content digests, 96.3%
  vulnerability prevalence), the regenerated `figures/*.pdf`, and
  `table_values.json` holding every table value — matching the numbers reported in
  the paper.

- **Command (full released dataset — all three databases + verification):**
  ```bash
  ./reproduce.sh analysis --dataset /path/to/dataset --stage all
  ```
  Runs, one database at a time, the MongoDB crawl stage (`--stage mongo`,
  ephemeral container + restore of `dockerhub_data_*.archive.gz`), the Neo4j
  layer-graph stage (`--stage neo4j`, ephemeral container over
  `neo4j_data_*.tar.gz`: graph stats, exposure ranking, per-CVE propagation)
  and the SQLite stage (`--stage sqlite`, the full report scan above plus the
  secrets validation and all figures/tables), then `--stage verify` compares
  every recomputed value against `analysis/expected/paper_values.json`
  (240 checks extracted from the paper; exact match required) and writes the
  verdict into `docs/REPRODUCIBILITY_REPORT.md`. Stages are independent, so
  the ~300 GB dataset can be validated incrementally; `verify` skips checks
  whose stage has not run yet.

> **Full at-scale measurement (optional, not required for any seal).** To
> reproduce the crawl and scan themselves:
> ```bash
> orchestration/run_pipeline.sh --seed a --crawl-duration 24h --threshold 1000 --workers 20
> ```
> This runs Stage I (`go run main.go crawl`), Stage II (`go run main.go build`),
> the ranker (`exposure_ranked.jsonl`), and Stage III (`scanners seed`/`run`/
> `report`). In production this runs distributed over days.

---

# License

Distributed under the MIT License — see [`LICENSE`](LICENSE). The vendored
pipeline stages `stages/chimangoscan/` and `stages/scanners/` carry their own
licenses; the released dataset is licensed CC BY 4.0 (see `DATASET.md`).
ChimangoScan builds on ideas from the DITector framework of Dr. Docker;
the discovery and IDEA-graph method is inspired by *Dr. Docker* (WWW '25), with an
original implementation by the authors of this work.
