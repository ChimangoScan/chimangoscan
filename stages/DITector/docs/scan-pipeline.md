# Scanning pipeline — DITector / AnonymousSystem

## 3-stage overview

```
STAGE I — Crawler (Go)                                       [COMPLETE]
  └─ Discovers repositories via prefix search on the Docker Hub Search API
  └─ Mongo dockerhub_data:
       repositories_data   12,716,568 repos indexed     ← written by the crawler
       crawler_keywords     2,051,801 prefixes searched  ← crawler state

STAGE II — Builder (Go)                                      [IN PROGRESS]
  └─ For each repo in repositories_data:
       fetches tags from the Docker Hub API → writes tags_data  (5,732,556 tags)
       fetches manifests by digest          → writes images_data (6,709,152 images)
       pulls the image, extracts layers     → builds the Neo4j IS_BASE_OF graph
  └─ Progress (2026-05-14):  4,964,236 / 12,716,568 repos built (39%)
       ~50 M edges in the graph (includes transitive relations)
       rate: ~207 repos/min → ETA ~30 days for 100%

STAGE III — Distributed scanner (AnonymousSystem)               [IN PROGRESS]
  └─ Queue: 504,837 total jobs ranked by exposure
       done:    8,382 scans completed  (1.66%)
       pending: 488,659 waiting
       skipped: 7,544 (pull failed / image removed)
       failed:  205
       findings: 16,029,295 accumulated (merged, deduplicated across scanners)
  └─ Distributed workers across multiple hosts consume from the same queue over HTTP
  └─ 6 static scanners per image: syft, trivy, grype, osv, dockle, trufflehog
```

---

## Stage I — How the crawler discovers repos (prefix search)

The Docker Hub Search API (`/v2/search/repositories/?query=<term>`) returns at most **10,000 results** per query. The crawler works around this with a prefix-trie traversal:

```
Initial seeds: a b c d ... z 0 1 ... 9 - _    (38 seeds, one per character)

For each prefix:
  1. Calls the Search API — returns up to 10,000 repos that contain the prefix
  2. Saves new repos to Mongo (dedup by namespace/name)
  3. If count >= 10,000 (the API ceiling) → expand:
       prefix "py" → enqueue "pya", "pyb", ..., "py0", "py-", "py_"
  4. If count < 10,000 → prefix exhausted, mark as done

Priority: 255 - len(prefix) → short prefixes first (BFS over the trie)
Token plateau: if a prefix with "-" or "_" returns 10k but 0 new repos
              → children get priority=-1 (deprioritized)
```

**Result**: the traversal covers the Docker Hub name space systematically, without relying on links between repos. The `crawler_keywords` collection in Mongo stores the state of each prefix (`pending` / `processing` / `done`), making the crawler **resumable** after stops.

---

## Stage II — Builder and the IS_BASE_OF graph

For each repo in `repositories_data`, the Go builder:

1. Queries the Docker Hub API and saves **tags** (`tags_data`) and **manifests/digests** (`images_data`)
2. Does a `docker pull` of the image and extracts the layer history (each layer has a digest)
3. For each layer, computes `id = sha256(parent_id + sha256(layer_digest))` and inserts the relation `(Layer)-[:IS_BASE_OF]->(Layer)` into Neo4j
4. On completion, sets `repositories_data.graph_built_at`

The resulting graph is a **forest of out-trees**: each Layer has at most one parent (the ID is deterministic given the parent+digest pair), with `~50 M edges` when complete — including transitive relations (if A is the base of B which is the base of C, both `A→B` and `B→C` are in the graph).

---

## Exposure computation — how the Stage III queue is ordered

Stage III does not scan images in random order. The queue is ranked by **exposure**: images that are the base of many others have priority because a vulnerability in them affects the entire downstream chain.

### Formula

$$
E(I) = p(R_I) + \sum_{N \,\in\, D(L_I)} \sum_{r \,\in\, \mathrm{img}(N)} p(R_r)
$$

$$
W(I) = \sum_{N \,\in\, D(L_I)} |\,\mathrm{img}(N)\,|
$$

Where:
- $E(I)$ — exposure of image $I$ (the priority metric)
- $p(R)$ — historical pulls of repository $R$ on Docker Hub
- $L_I$ — top layer of $I$ in the IS_BASE_OF graph
- $D(L_I)$ — **strict** descendants of $L_I$ (excludes $L_I$ itself)
- $\mathrm{img}(N)$ — image refs whose top layer is node $N$
- $W(I)$ — dependency weight: number of distinct downstream images

**Example:** `alpine:latest` has $p = 10$ billion pulls of its own and 91 billion pulls accumulated across everything that inherits from it → $E = 101$ billion → first in the queue.

### Algorithm (bottom-up subtree sums, O(n))

```
1. Dump Mongo → repo_pull.tsv.gz  (ns, name, pull_count)
2. Dump Neo4j → edges.tsv.gz      (parent_id, child_id, ~50 M lines)
               toplayers.jsonl.gz (layer_id, images[])

3. Dense arrays indexed by the internal Neo4j ID:
   parent[i] = parent of node i  (-1 if root)
   sub_p[i]  = pull_count sum in the subtree   (seed: sum p(R) of i's refs)
   sub_w[i]  = number of images in the subtree (seed: len(images[i]))

4. Kahn bottom-up — leaves first:
   sub_p[parent] += sub_p[child]
   sub_w[parent] += sub_w[child]

5. For each repo:
   downstream_pull_sum = sub_p[L] - self_p[L]
   dependency_weight   = sub_w[L] - self_w[L]
   exposure            = pull_count + downstream_pull_sum
```

The ranker generates one JSONL per repo ordered by descending exposure, and the `exposure-updater` daemon does an UPSERT into the queue every 6 h:

```sql
ON CONFLICT(image) DO UPDATE SET weight = excluded.weight
WHERE status = 'pending'   -- never overwrites done/running
```

---

## Stage III in detail — the scan pipeline for one image

```
Job claim (worker)
    │
    ▼
docker pull <image>@sha256:<digest>       ← pinned by digest; does not change during the scan
    │
    ▼
docker save → /cache/tars/<slug>.tar      ← produced ONCE, shared by the scanners
    │
    ├──► [syft]       ─── reads tarball ──► .syft.json + .cdx.json + .spdx.json
    ├──► [trivy]      ─── reads tarball ──► .trivy.json + .trivy.cdx.json + .trivy.sarif
    ├──► [grype]      ─── reads tarball ──► .grype.json + .grype.sarif + .grype.cdx.json
    ├──► [osv]        ─── reads tarball ──► .osv.json
    ├──► [dockle]     ─── reads tarball ──► .dockle.json
    └──► [trufflehog] ─── reads tarball ──► .trufflehog.jsonl   (stdout captured)
         │
         │   all run in isolated Docker containers (DooD via docker.sock)
         │   scan_parallelism = 2–3 simultaneous scanners per worker slot
         ▼
    Per-scanner adapter (Python)
         │   reads the raw output file
         │   normalizes to the internal Finding schema
         ▼
    Merge + dedup                         ← identical findings across scanners grouped
         │   dedup key: (cve_id | (package, version, scanner_category))
         │   the scanner that detected it goes in Finding.scanners[]
         ▼
    report.json                           ← saved at out/<slug>/report.json
    invocations[]                         ← metadata of each run (status, wall_s, n_findings, severity_dist)
         │
         ▼
    Coordinator — reports table           ← INSERT OR REPLACE; n_findings, report_json, finished_at
    jobs table  — status = 'done'
         │
         ▼
    docker rmi <image>                    ← remove_image_after: true (frees disk)
    rm tarball                            ← tarball removed after the scan
```

---

## The 6 scanners — differences and complementarity

| Scanner | What it detects | Database | Categories | Overlap |
|---------|--------------|---------------|------------|---------|
| **Syft** | Package inventory (SBOM) — lists what is installed, does not detect vulns | — | `sbom-component` (info) | Unique in its role |
| **Trivy** | CVEs in OS packages + libs + secrets in files + image misconfig | NVD + OSS-Index + Trivy Advisories | `pkg-vuln`, `secret`, `image-config` | High overlap with Grype/OSV |
| **Grype** | CVEs in OS packages + language libs | Anchore VulnDB (NVD + GitHub Advisory + more) | `pkg-vuln` | High overlap with Trivy |
| **OSV** | CVEs in language libs (npm, PyPI, Go, Rust, Maven…) | Google OSV Database | `pkg-vuln` | Partial overlap with Trivy/Grype |
| **Dockle** | Image misconfiguration (CIS Docker Benchmark) — not a CVE | Internal CIS checks | `image-config` | Unique in its role |
| **TruffleHog** | Hardcoded secrets and credentials in the image (keys, tokens, passwords) | 700+ proprietary detectors | `secret` | Partial with Trivy |

**Why run Trivy + Grype + OSV together if they all detect CVEs?**
Each covers CVEs the others do not have: Trivy is the most comprehensive (OS + language + secrets + misconfig), Grype uses the Anchore VulnDB with additional sources and sometimes a different severity, OSV focuses on language libs with Google's database updated in real time. The subsequent merge consolidates the overlaps — if all three detect the same CVE in the same package, it becomes a single finding with `"scanners": ["trivy", "grype", "osv"]`.

**The two unique ones in their role:**
- **Syft** — does not detect vulns, only the SBOM. Inventories exactly what is in the image.
- **Dockle** — the only one that looks at the *image configuration* (root user, ADD vs COPY, missing healthcheck, secrets in ENV) instead of the package contents.

---

## The 6 scanners — what they produce and what we save

### 1. Syft

| Field | Value |
|-------|-------|
| **Docker image** | `anchore/syft:latest` |
| **What it does** | Generates an SBOM (Software Bill of Materials) — a complete inventory of packages installed in the image |
| **Findings category** | `sbom-component` |
| **Severity** | always `info` (not a vuln, an inventory) |

**Command run:**
```bash
syft docker-archive:/work/image.tar \
  -o cyclonedx-json=/out/<slug>.cdx.json \
  -o spdx-json=/out/<slug>.spdx.json \
  -o syft-json=/out/<slug>.syft.json
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.syft.json` | Anchore proprietary JSON (artifacts[]) | ✅ **parsed** by the adapter |
| `<slug>.cdx.json` | CycloneDX JSON (OWASP standard SBOM) | ✅ saved to the worker's disk |
| `<slug>.spdx.json` | SPDX JSON (Linux Foundation standard SBOM) | ✅ saved to the worker's disk |

**Raw excerpt (`<slug>.syft.json`):**
```json
{
  "artifacts": [
    {
      "id": "8b7e1a2c3d4f5e6a",
      "name": "@cloudron/pipework",
      "version": "2.1.2",
      "type": "npm",
      "purl": "pkg:npm/%40cloudron/pipework@2.1.2",
      "licenses": ["ISC"],
      "locations": [
        { "path": "/app/code/node_modules/@cloudron/pipework/package.json" }
      ],
      "language": "javascript",
      "cpes": ["cpe:2.3:a:cloudron:pipework:2.1.2:*:*:*:*:*:*:*"]
    }
  ],
  "schema": { "version": "15.0.0", "url": "..." },
  "distro": { "name": "debian", "version": "12" }
}
```

**Normalized finding:**
```json
{
  "scanner": "syft",
  "category": "sbom-component",
  "severity": "info",
  "id": "pkg:npm/%40cloudron/pipework@2.1.2",
  "title": "@cloudron/pipework",
  "description": "ISC",
  "package": "@cloudron/pipework",
  "version": "2.1.2",
  "ecosystem": "npm",
  "location": "/app/code/node_modules/@cloudron/pipework/package.json"
}
```

---

### 2. Trivy

| Field | Value |
|-------|-------|
| **Docker image** | `aquasec/trivy:latest` |
| **What it does** | CVEs in OS packages + language libs + secrets + misconfigurations |
| **Findings category** | `pkg-vuln`, `secret`, `image-config` |
| **Severity** | `critical`, `high`, `medium`, `low`, `unknown` |

**Command run:**
```bash
trivy --cache-dir /cache image \
  --input /work/image.tar \
  --scanners vuln,secret,misconfig,license \
  --format json --output /out/<slug>.trivy.json \
  --list-all-pkgs --quiet

# extras (do not block the main parse):
trivy ... --format cyclonedx --output /out/<slug>.trivy.cdx.json
trivy ... --format sarif --output /out/<slug>.trivy.sarif
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.trivy.json` | Trivy JSON (Results[].Vulnerabilities[]) | ✅ **parsed** |
| `<slug>.trivy.cdx.json` | CycloneDX JSON | ✅ saved |
| `<slug>.trivy.sarif` | SARIF 2.1.0 | ✅ saved |

**Raw excerpt (`<slug>.trivy.json`):**
```json
{
  "SchemaVersion": 2,
  "ArtifactName": "/work/image.tar",
  "Results": [
    {
      "Target": "ubuntu 24.04",
      "Class": "os-pkgs",
      "Type": "ubuntu",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2024-38474",
          "PkgName": "apache2",
          "InstalledVersion": "2.4.58-1ubuntu8.5",
          "FixedVersion": "2.4.58-1ubuntu8.8",
          "Severity": "MEDIUM",
          "Title": "httpd: Substitution encoding issue in mod_rewrite",
          "Description": "...",
          "CVSS": { "nvd": { "V3Score": 9.8 } },
          "References": ["https://..."]
        }
      ],
      "Secrets": [...],
      "Misconfigurations": [...]
    }
  ]
}
```

---

### 3. Grype

| Field | Value |
|-------|-------|
| **Docker image** | `anchore/grype:latest` |
| **What it does** | CVEs via the Anchore VulnDB — focused on OS packages + language ecosystems (Go, npm, PyPI, etc.) |
| **Findings category** | `pkg-vuln` |
| **Severity** | `critical`, `high`, `medium`, `low`, `info`, `unknown` |

**Command run:**
```bash
grype docker-archive:/work/image.tar \
  -o json=/out/<slug>.grype.json \
  -o sarif=/out/<slug>.grype.sarif \
  -o cyclonedx-json=/out/<slug>.grype.cdx.json

# env: GRYPE_DB_CACHE_DIR=/cache  (~100 MB of cached vuln DB)
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.grype.json` | Grype JSON (matches[]) | ✅ **parsed** |
| `<slug>.grype.sarif` | SARIF 2.1.0 | ✅ saved |
| `<slug>.grype.cdx.json` | CycloneDX JSON | ✅ saved |

**Raw excerpt (`<slug>.grype.json`):**
```json
{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2023-44487",
        "severity": "High",
        "cvss": [{ "version": "3.1", "metrics": { "baseScore": 7.5 } }],
        "fix": { "versions": ["1.20.10", "1.21.3"], "state": "fixed" },
        "description": "The HTTP/2 protocol allows a denial of service...",
        "relatedVulnerabilities": []
      },
      "artifact": {
        "name": "stdlib",
        "version": "go1.18.2",
        "type": "go-module",
        "locations": [{ "path": "/usr/local/bin/gosu" }]
      }
    }
  ],
  "source": { "type": "image", "target": { "imageID": "sha256:..." } }
}
```

**Why Trivy + Grype together?** Different databases (NVD/OSS-Index vs Anchore VulnDB). One may have CVEs the other does not. Duplicate findings are removed in the merge by `(package, version, cve_id)`.

---

### 4. OSV

| Field | Value |
|-------|-------|
| **Docker image** | `ghcr.io/google/osv-scanner:latest` |
| **What it does** | CVEs via the OSV database (Google) — specialized in language libs (npm, PyPI, Go, Rust, Maven, etc.) |
| **Findings category** | `pkg-vuln` |
| **Severity** | `unknown` for most (OSV does not include CVSS in every record) |

**Command run:**
```bash
osv-scanner scan image \
  --archive --format json \
  --output-file /out/<slug>.osv.json \
  --all-packages \
  /work/image.tar

# exit code 1 when it finds vulns → treated as success if the file exists
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.osv.json` | OSV-schema JSON (results[].packages[].vulnerabilities[]) | ✅ **parsed** |

**Raw excerpt (`<slug>.osv.json`):**
```json
{
  "results": [
    {
      "source": { "path": "/app/package-lock.json", "type": "lockfile" },
      "packages": [
        {
          "package": { "name": "path-to-regexp", "version": "0.1.7", "ecosystem": "npm" },
          "vulnerabilities": [
            {
              "id": "GHSA-9wv6-86v2-598j",
              "aliases": ["CVE-2024-45296"],
              "summary": "path-to-regexp outputs backtracking regular expressions",
              "details": "...",
              "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" }],
              "references": [{ "type": "ADVISORY", "url": "https://github.com/..." }]
            }
          ]
        }
      ]
    }
  ]
}
```

---

### 5. Dockle

| Field | Value |
|-------|-------|
| **Docker image** | `goodwithtech/dockle:latest` |
| **What it does** | Docker image configuration best practices (CIS Docker Benchmark) — NOT a CVE |
| **Findings category** | `image-config` |
| **Severity** | `high` (FATAL), `medium` (WARN), `low` (INFO) — ignores PASS/SKIP |

**Command run:**
```bash
dockle \
  --input /work/image.tar \
  --format json \
  --output /out/<slug>.dockle.json \
  --exit-code 0
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.dockle.json` | Dockle JSON (details[]) | ✅ **parsed** |

**Raw excerpt (`<slug>.dockle.json`):**
```json
{
  "summary": { "fatal": 2, "warn": 1, "info": 3, "pass": 18, "skip": 0 },
  "details": [
    {
      "code": "CIS-DI-0009",
      "title": "Use COPY instead of ADD in Dockerfile",
      "level": "FATAL",
      "alerts": [
        "ADD supervisor/postgresql.conf supervisor/postgresql-service.conf /etc/supervisor/conf.d/"
      ]
    },
    {
      "code": "CIS-DI-0001",
      "title": "Create a user for the container",
      "level": "WARN",
      "alerts": ["Last user should not be root"]
    }
  ]
}
```

**Checks covered:** root user, secrets in ENV/ARG, ADD vs COPY, missing healthcheck, untagged image, suspicious content in layers.

---

### 6. TruffleHog

| Field | Value |
|-------|-------|
| **Docker image** | `trufflesecurity/trufflehog:latest` |
| **What it does** | Detects secrets, private keys, and hardcoded tokens inside the image |
| **Findings category** | `secret` |
| **Severity** | `critical` (if verified/active), `medium` (unverified) |

**Command run:**
```bash
trufflehog docker \
  --image file:///work/image.tar \
  --json \
  --no-update
# stdout captured as JSONL (one JSON object per line)
```

**Files generated:**
| File | Format | Saved? |
|---------|---------|-----------|
| `<slug>.trufflehog.jsonl` | JSONL (stdout, 1 object per line) | ✅ **parsed** |

**Raw excerpt (`<slug>.trufflehog.jsonl`, one line per finding):**
```json
{
  "DetectorName": "PrivateKey",
  "DecoderName": "BASE64",
  "Verified": false,
  "Raw": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhki...",
  "Redacted": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhki...",
  "ExtraData": null,
  "StructuredData": null,
  "SourceMetadata": {
    "Data": {
      "Docker": {
        "file": "/etc/ssl/private/ssl-cert-snakeoil.key",
        "image": "cloudron/postgresql:6.3.1",
        "layer": "sha256:3a2b..."
      }
    }
  },
  "SourceName": "trufflehog - docker",
  "SourceType": 15
}
```

**Active detectors:** AWS keys, GCP tokens, GitHub tokens, Slack tokens, SSH private keys, JWT, passwords in config files, private certificates, and ~700+ other patterns.

---

## Merge and deduplication

After all scanners finish, the findings go through a **merge** step:

```
Trivy found: CVE-2023-44487 in stdlib go1.18.2
Grype found: CVE-2023-44487 in stdlib go1.18.2
OSV found:   CVE-2023-44487 in stdlib go1.18.2

→ the merge produces ONE finding with:
  {
    "id": "CVE-2023-44487",
    "scanners": ["trivy", "grype", "osv"],  ← all that detected it
    "severity": "high",
    "cvss": 7.5,
    ...
  }
```

**Dedup key:**
- For `pkg-vuln`: `(cve_id, package, version)` if a CVE is available; otherwise `(package, version, title)`
- For `secret`: `(detector_name, location, redacted_prefix)`
- For `image-config`: `(code, location)`
- For `sbom-component` (syft): never deduplicated — each package is unique

---

## What is stored where

```
out/<slug>/
    report.json          ← complete report: target, invocations[], findings[]
    syft/
        <slug>.syft.json         raw syft
        <slug>.cdx.json          CycloneDX
        <slug>.spdx.json         SPDX
    trivy/
        <slug>.trivy.json        raw trivy (parsed)
        <slug>.trivy.cdx.json    CycloneDX
        <slug>.trivy.sarif       SARIF
    grype/
        <slug>.grype.json        raw grype (parsed)
        <slug>.grype.sarif       SARIF
        <slug>.grype.cdx.json    CycloneDX
    osv/
        <slug>.osv.json          raw osv (parsed)
    dockle/
        <slug>.dockle.json       raw dockle (parsed)
    trufflehog/
        <slug>.trufflehog.jsonl  raw trufflehog (parsed)

Coordinator (ditector.db — SQLite):
    jobs.status = 'done'
    reports.report_json = <compressed report.json>
    reports.n_findings  = <total merged>
    reports.finished_at = <epoch>
```

**Note**: with `remove_image_after: true`, the Docker image and the tarball are removed after the scan. The raw files in `out/<slug>/` remain. The `report_json` in the SQLite column is the canonical copy used by the dashboard and the API.

---

## Database schemas

### MongoDB — `dockerhub_data`

#### `repositories_data` (12,716,568 docs)
Populated by **Stage I** (crawler).

```json
{
  "_id":         "ObjectId",
  "namespace":   "library",
  "name":        "alpine",
  "pull_count":  { "high": 0, "low": 10123456789, "unsigned": false },
  "star_count":  { "high": 0, "low": 9999, "unsigned": false },
  "description": "...",
  "is_private":  false,
  "last_updated": "2026-04-01T00:00:00Z",
  "graph_built_at": "2026-05-14T03:00:00Z"   // null if Stage II has not processed it yet
}
```

Indexes: `{namespace,name}` (unique lookup), `{pull_count:-1}` (ranking), `{graph_built_at:1}` (Stage II progress).

---

#### `tags_data` (5,732,556 docs)
Populated by **Stage II** (builder), one entry per tag of each repo.

```json
{
  "_id":                   "ObjectId",
  "repositories_namespace": "library",
  "repositories_name":      "alpine",
  "name":                   "latest",
  "digest":                 "sha256:1775bebec...",
  "content_type":           "image",
  "creator":                0,
  "id":                     123456,
  "last_updated":           "2026-04-01T00:00:00Z",
  "tag_status":             "active",
  "full_size":              { "high": 0, "low": 3500000, "unsigned": false },
  "images": [
    {
      "architecture": "amd64",
      "os":           "linux",
      "digest":       "sha256:abc123...",
      "size":         { "high": 0, "low": 3500000, "unsigned": false },
      "status":       "active",
      "last_pulled":  "2026-04-05T18:33:45Z",
      "last_pushed":  "2026-04-05T14:36:41Z"
    }
  ]
}
```

Indexes: `{repositories_namespace, repositories_name, name}` (lookup by tag), `{repositories_namespace, repositories_name}`.

---

#### `images_data` (6,709,152 docs)
Populated by **Stage II**. One entry per image digest (per architecture).

```json
{
  "_id":         "ObjectId",
  "digest":      "sha256:1e70e0ad...",
  "architecture": "amd64",
  "last_pulled": "2026-04-05T18:33:45Z",
  "last_pushed": "2026-04-05T14:36:41Z",
  "layers": [
    {
      "digest":      "sha256:fd582657...",
      "size":        { "high": 0, "low": 4471206, "unsigned": false },
      "instruction": "COPY /image/ / # buildkit"
    },
    {
      "digest":      "sha256:00000000...",   // empty digest = metadata layer
      "size":        { "high": 0, "low": 0, "unsigned": false },
      "instruction": "USER 65532:65532"
    }
  ]
}
```

Index: `{digest:1}` (lookup by digest).

---

#### `crawler_keywords` (2,051,801 docs)
State of the **Stage I** prefix search.

```json
{
  "_id":        "alpine",          // the searched prefix
  "status":     "done",            // pending | processing | done
  "priority":   251,               // 255 - len(prefix); higher = processed first
  "crawled_at": "2026-04-03T19:17:21Z",
  "finished_at": "2026-04-03T21:48:48Z"
}
```

---

### Neo4j — IS_BASE_OF graph

`Layer` node — represents a Docker image layer:

```
(:Layer {
  id:          "sha256:abc123...",   // Layer.id = sha256(parent_id + sha256(digest))
  digest:      "sha256:fd5826...",   // digest of the layer itself
  size:        4471206,              // bytes
  instruction: "COPY /image/ / # buildkit",  // Dockerfile instruction
  images:      ["docker.io/library/alpine:latest@sha256:1775...",  ...]
               // image refs whose top layer is this node (present only on the top layer)
})
```

`IS_BASE_OF` relation:

```
(:Layer)-[:IS_BASE_OF]->(:Layer)
// parent → child: the child uses the parent as a base layer
// each Layer has at most ONE parent (deterministic ID)
// the graph is a forest of out-trees with ~50 M edges
```

---

### SQLite — `ditector.db` (scan queue)

#### `jobs` (504,837 rows)

```sql
CREATE TABLE jobs (
  id           INTEGER PRIMARY KEY,
  image        TEXT NOT NULL UNIQUE,   -- "ns/repo:tag@sha256:digest"
  name         TEXT NOT NULL,          -- filesystem-safe slug
  target_json  TEXT NOT NULL,          -- JSON with exposure meta (see below)
  weight       REAL NOT NULL DEFAULT 0,-- = exposure; defines the queue order
  status       TEXT NOT NULL DEFAULT 'pending',  -- pending|running|done|skipped|failed
  worker_id    TEXT,                   -- "hostname/pid#slot" of the current worker
  attempts     INTEGER NOT NULL DEFAULT 0,
  error        TEXT,
  created_at   REAL NOT NULL,          -- epoch float
  started_at   REAL,
  heartbeat_at REAL,                   -- updated every ~30s by the worker
  finished_at  REAL
);
```

`target_json` expanded:

```json
{
  "image":  "browsers/chrome:latest@sha256:0a362...",
  "name":   "browsers_chrome_latest",
  "weight": 192453.0,
  "meta": {
    "repository_namespace": "browsers",
    "repository_name":      "chrome",
    "tag_name":             "latest",
    "image_digest":         "sha256:0a362...",
    "pull_count":           189696,
    "dependency_weight":    9,
    "downstream_pull_sum":  2757,
    "exposure":             192453
  }
}
```

Indexes: `idx_jobs_claim (status, weight DESC, id)`, `idx_jobs_status (status)`, `idx_jobs_heartbeat (status, heartbeat_at)`.

---

#### `reports` (8,382 rows)

```sql
CREATE TABLE reports (
  image        TEXT PRIMARY KEY,   -- same value as jobs.image
  report_json  TEXT NOT NULL,      -- the complete report JSON (see below)
  n_findings   INTEGER NOT NULL DEFAULT 0,  -- total merged findings
  finished_at  REAL NOT NULL       -- epoch float
);
```

Indexes: `idx_reports_finished_at (finished_at DESC)`, `idx_reports_n_findings (n_findings)`.

`report_json` expanded:

```json
{
  "target": {
    "image":  "alpine:latest@sha256:1775...",
    "name":   "alpine_latest",
    "weight": 101239064764.0,
    "meta":   { "pull_count": 10123456789, "exposure": 101239064764, ... }
  },
  "started_at":    "2026-05-12T21:15:50Z",
  "finished_at":   "2026-05-12T21:16:03Z",
  "container_ip":  null,
  "open_ports":    [],
  "http_endpoints": [],
  "invocations": [
    {
      "scanner":      "syft",
      "status":       "ok-cached",    // ok | ok-cached | error | skipped | pull-failed | timeout
      "findings":     16,
      "findings_by_severity": { "info": 16 },
      "wall_seconds": 0.0,
      "exit_code":    0,
      "error":        "",
      "image_ref":    "anchore/syft:latest",
      "mode":         "static",
      "started_at":   "2026-05-12T21:15:53Z"
    }
    // ... one per scanner
  ],
  "findings": [ /* list of merged Findings — schema below */ ]
}
```

---

#### `exposure_state` (1 row)
Watermark of the `exposure-updater` daemon.

```sql
CREATE TABLE exposure_state (
  key        TEXT PRIMARY KEY,   -- e.g. "last_run_at"
  value      TEXT NOT NULL,
  updated_at REAL NOT NULL
);
```

---

## Normalized schema of a Finding

All scanners are normalized to this schema before the merge:

```json
{
  "scanner":       "trivy",
  "scanners":      ["trivy", "grype"],
  "category":      "pkg-vuln | sbom-component | secret | image-config",
  "severity":      "critical | high | medium | low | info | unknown",
  "id":            "CVE-2024-38474",
  "title":         "httpd: Substitution encoding issue in mod_rewrite",
  "description":   "...",
  "cvss":          9.8,
  "package":       "apache2",
  "version":       "2.4.58-1ubuntu8.5",
  "fixed_version": "2.4.58-1ubuntu8.8",
  "ecosystem":     "ubuntu",
  "location":      "/work/image.tar (ubuntu 24.04)",
  "cves":          ["CVE-2024-38474"],
  "references":    ["https://..."],
  "target_image":  "budibase/budibase:latest@sha256:ea1293...",
  "target_name":   "budibase_budibase_latest",
  "target_ip":     null,
  "endpoint":      ""
}
```
