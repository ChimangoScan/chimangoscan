# ChimangoScan

A measurement pipeline for the Docker Hub image ecosystem: it enumerates the namespace, reconstructs the image layer graph, ranks images by how much of the ecosystem inherits from them, and scans the most consequential ones with six independent open-source scanners.

This repository contains the pipeline, the analysis code, and pointers to the released dataset. It accompanies the paper *Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images* ([arXiv:2608.02669](https://arxiv.org/abs/2608.02669)).

## What we measured

A flaw in a leaf image affects whoever pulls that image. A flaw in `alpine` reaches every image built `FROM` it, and the reach is enormous: `alpine` itself draws 11.8 billion pulls, and images built on its layers add roughly 71 billion more. Counting an image's own pulls therefore tells you almost nothing about how much damage its defects can do.

So the pipeline ranks images by an **exposure** score: an image's pull count plus the pull counts of every image that inherits its layers. From a crawl of **12.7 million** repositories it scanned the **52,895** highest-exposure ones, covering **84.7%** of all 663.8 billion recorded pulls, and collected **170.4 million** findings.

Three results came out of that:

- **Known vulnerabilities are near-universal.** 96.3% of the scanned images carry at least one, 93.4% carry a critical one, and 98.0% carry a misconfiguration.
- **The reported posture depends heavily on the scanner.** Of the distinct vulnerabilities the three vulnerability scanners find, only **2.7%** are reported by all three, and 66.8% by exactly one. A single scanner's count is largely an artifact of that scanner.
- **Secrets go the other way.** TruffleHog flags secrets in 76.9% of images, but hand-labeling a sample shows **99.7%** of its hits are not credentials.

## Quickstart

Regenerate every figure and table value from the shipped aggregates. No database, no dataset download, about a minute:

```bash
git clone https://github.com/ChimangoScan/chimangoscan
cd chimangoscan
./reproduce.sh precomputed
```

It writes `figures/*.pdf` and `figures/table_values.json`. Nothing is installed into your system Python: the script uses a local `.venv` when the host can provide matplotlib and numpy, and otherwise falls back to a container, so it works on any Docker host.

Everything below assumes you are at the repository root.

## How the pipeline works

The measurement runs in three stages, each independently runnable.

**Stage I, crawl.** Enumerates the Docker Hub namespace and records repository metadata: pull counts, tags, image digests, timestamps. Output lands in MongoDB. Written in Go, in [`stages/DITector/`](stages/DITector/).

**Stage II, layer graph.** Resolves tags to digests, extracts layer identifiers, and builds the graph whose edges mean *this image is built on that one*. Output lands in Neo4j: 54.4 million `base-of` edges over 84.7 million nodes. Also Go.

**Stage III, scan.** Ranks the graph by exposure ([`analysis/scripts/compute_exposure_ranking.py`](analysis/scripts/compute_exposure_ranking.py)), takes the head of that ranking, and runs six scanners over each image:

| Scanner | What it looks for |
|---|---|
| Trivy, Grype, OSV-Scanner | known vulnerabilities in packages |
| Syft | software bill of materials |
| Dockle | image misconfiguration and hardening |
| TruffleHog | secrets and credentials |

The orchestration is in [`stages/scanners/`](stages/scanners/), one Python adapter per scanner. Scanner images are pinned by digest. Three dynamic scanners (Nuclei, Nikto, ZAP) are wired but disabled by default, because they would boot the target container; the paper uses the six static ones.

## Repository layout

```
chimangoscan/
├── reproduce.sh              one entry point for every reproduction path
├── DATASET.md                dataset schema, contents and download
├── stages/
│   ├── DITector/             Stages I and II, crawler and graph builder (Go)
│   └── scanners/             Stage III, six-scanner orchestration (Python)
├── orchestration/
│   ├── run_pipeline.sh       full pipeline, end to end
│   ├── minimal_test.sh       miniature end-to-end run
│   ├── run_analysis.sh       regenerates analyses, figures and tables
│   ├── analysis_sqlite.sh    per-database analysis stages
│   └── make_scanners_config.sh
├── analysis/
│   ├── scripts/              exposure ranker, table and figure regeneration,
│   │                         secret sampling and validation, CVE propagation
│   └── expected/             the paper's published values, for verification
└── docker/                   the runner image
```

## Requirements

**The host needs only Docker and Docker Compose.** Every stage runs inside a container, including the Go crawler, the Python ranker, the scanner orchestration and the analysis, so no language toolchain is installed on your machine. The runner image builds itself the first time you invoke any script, which takes a few minutes once.

| Provided as a container | Image |
|---|---|
| MongoDB, repositories and tags | `mongo:7.0` |
| Neo4j, layer graph | `neo4j:5.26` |
| Runner (Go 1.22, Python 3, matplotlib, numpy, Docker CLI) | built from [`docker/Dockerfile.runner`](docker/Dockerfile.runner) |
| Six scanners | official images, pinned by digest |

Reference platform is Linux x86-64; all images were scanned for `linux/amd64`.

Resource needs depend on which path you take:

| Path | CPU | RAM | Disk | Time |
|---|---|---|---|---|
| Quickstart (`precomputed`) | any | 2 GB | negligible | ~1 min |
| Miniature end-to-end run | 4 cores | 8 GB | 20 GB | 20–45 min |
| Full analysis from the dataset | 4+ cores | 8+ GB | ~192 GB for the scan database | ~1 h plus download |
| Full measurement (crawl and scan) | 16+ cores/node | 32+ GB/node | hundreds of GB | days |

## Running it

### Miniature end-to-end run

Exercises the whole pipeline in small: a brief crawl, a layer graph, the exposure ranker, and the six scanners over the top ten images.

```bash
docker compose -f stages/DITector/docker-compose.yml up -d mongodb neo4j
orchestration/minimal_test.sh --top 10
```

No credentials needed. Without an `accounts.json` the crawler runs anonymously, which is rate-limited but fine at this size; adding Docker Hub accounts only makes the crawl faster. On success it prints `MINIMAL TEST PASSED` and writes `report.html`, `summary.json` and `analysis.md` under `artifacts/`.

### Full analysis from the released dataset

Recomputes every number, figure and table from the published databases and checks them against the paper's values:

```bash
./reproduce.sh analysis --dataset ./dataset --fetch --stage all
```

`--fetch` downloads and verifies the dataset first. The run compares its output against [`analysis/expected/paper_values.json`](analysis/expected/paper_values.json), 240 checks in total, and writes the verdict to [`docs/REPRODUCIBILITY_REPORT.md`](docs/REPRODUCIBILITY_REPORT.md). Use `--stage sqlite|mongo|neo4j|verify` to run one piece at a time. For a fast partial pass, [`orchestration/analysis_sqlite.sh`](orchestration/analysis_sqlite.sh) takes `--sample N` to cap the reports scan to N rows.

### Full measurement

[`orchestration/run_pipeline.sh`](orchestration/run_pipeline.sh) runs the real thing: crawl, graph, rank, scan. It is designed for distributed operation over several days and needs Docker Hub accounts in `stages/DITector/accounts.json`. Re-running it will not reproduce the paper's numbers exactly, because Docker Hub keeps moving. See [Known drift](#known-drift).

## The dataset

The full dataset is published on the GitHub release [`dataset-v1`](https://github.com/ChimangoScan/chimangoscan/releases/tag/dataset-v1), split into parts under GitHub's 2 GB limit, with a `sha256` for every file and a `MANIFEST.txt`. About 33 GB compressed, in four components:

| Component | Contents |
|---|---|
| `chimangoscan-reports.db` | every scanner's raw output, per image (SQLite, 192 GB uncompressed) |
| `dockerhub_data.freeze` | the 12.7-million-repository crawl (MongoDB dump) |
| `neo4j_data.freeze` | the image layer graph (Neo4j dump) |
| `exposure_work.freeze` | the exposure ranking and its intermediates |

Fetch, rejoin and verify all of it with one command:

```bash
./scripts/fetch_dataset.sh --out ./dataset
```

[`DATASET.md`](DATASET.md) documents the schema of each component, field by field. The dataset is licensed CC BY 4.0.

## Safety notes

Read these before running Stage III on a machine you care about.

- **Stage III downloads and runs third-party container images.** The six static scanners only analyze the image artifact, but the disabled-by-default dynamic scanners would start the target container. Use a disposable or isolated host.
- **The runner mounts the host Docker socket** (`/var/run/docker.sock`) so that the scanner containers it launches are siblings on the host daemon. Mounting that socket grants control of the host's Docker daemon, which is a second reason to use a disposable host.
- **Docker Hub credentials live in `stages/DITector/accounts.json`**, which must never be committed. It is already in [`.gitignore`](.gitignore).
- No step needs root, beyond access to the Docker daemon.

## Known drift

Docker Hub is a live system, so a fresh crawl will not match the frozen one exactly. Re-running Stages I and II today lands roughly 3% above the published graph, which is ordinary growth rather than a defect. Numbers derived from the scan database reproduce exactly, because that database is frozen; numbers derived from a live crawl carry a documented tolerance. The verification step labels each check accordingly, and [`docs/REPRODUCIBILITY_REPORT.md`](docs/REPRODUCIBILITY_REPORT.md) records which is which.

Two scoping limits are worth stating plainly. The scanned corpus is the head of the registry by exposure, not a uniform sample of Docker Hub, so the prevalence figures describe the images that matter most by reach and not the average repository. And a scanner finding is a static signal, not proof that anything is exploitable in a running deployment.

## Credits and license

The original code here, meaning the exposure ranker, the six-scanner Stage III orchestration in [`stages/scanners/`](stages/scanners/), and the analysis scripts, is distributed under the MIT License (see [`LICENSE`](LICENSE)). The released dataset is licensed CC BY 4.0.

[`stages/DITector/`](stages/DITector/) is a fork of Dr. Docker's DITector ([NSSL-SJTU/DITector](https://github.com/NSSL-SJTU/DITector), WWW '25). The Stage I crawler, an unimplemented stub upstream, and the distributed re-engineering of the Stage II graph builder are ours; the graph-builder and analyzer baseline are theirs, and are credited throughout the directory and in its [`CHANGELOG.md`](stages/DITector/CHANGELOG.md). The upstream carries no license and is included here with attribution.

## How to cite

Cite the paper, not the repository:

> Kapelinski, C., Machado, B. and Kreutz, D. (2026). Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images. arXiv:2608.02669.

```bibtex
@article{kapelinski2026chimangoscan,
  author  = {Kapelinski, Cristhian and Machado, Beatriz and Kreutz, Diego},
  title   = {Vulnerabilities, Secrets and Misconfiguration in the Highest-Exposure Docker Hub Images},
  journal = {arXiv preprint arXiv:2608.02669},
  year    = {2026},
  doi     = {10.48550/arXiv.2608.02669},
  url     = {https://arxiv.org/abs/2608.02669},
}
```

[`CITATION.cff`](CITATION.cff) carries the same metadata in machine-readable form, so GitHub's "Cite this repository" button and tools such as Zenodo pick it up automatically.
