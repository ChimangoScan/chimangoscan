# DITector — Large-Scale Docker Hub Security Research Pipeline

> Based on the DITector framework (Dr. Docker), extended to support large-scale distributed crawling, parallel construction of the dependency graph, and generation of prioritized datasets for security scanning.

> **Stages I and II of the AnonymousSystem pipeline — discovery and prioritization.**
> This repository contains the three components of the *discovery and
> prioritization* step:
>
> - **Stage I — Crawler** (Go): distributed crawl of Docker Hub to
>   discover repositories and their *pull counts*.
> - **Stage II — Layer graph** (Go): parallel construction of the IDEA
>   inheritance graph between images in Neo4j.
> - **Exposure ranker** (`scripts/compute_exposure_ranking.py`, Python):
>   computes the exposure of each repository (its own pull count + the sum of the
>   pull counts of the downstream subtree) over the IDEA graph.
>
> The crawler (`crawler/`) and the graph builder (`buildgraph/`, `myutils/neo4j.go`)
> are the **authors' original implementation** in this fork — the *Dr. Docker* paper
> only inspired the method (the keyword DFS strategy and the Layer ID hashing
> scheme); the upstream DITector framework (Dr. Docker) shipped the `crawl`
> subcommand as a *stub* with no implementation. The exposure ranker is also an
> original contribution.
>
> The **output** of this step is the file `exposure_ranked.jsonl` — one JSON line
> per repository, ordered by decreasing exposure. This file is the
> **contract** consumed by Stage III (multi-scanner scanning), which lives in the
> [`scanners`](https://anonymous.4open.science/r/AnonymousSystem-2131/) repository. The
> end-to-end orchestration of the two stages is handled by the
> [`anonymoussystem`](https://anonymous.4open.science/r/AnonymousSystem-2131/) repository.

---

## Table of Contents

1. [Context and Motivation](#1-context-and-motivation)
2. [Pipeline Architecture](#2-pipeline-architecture)
3. [Scientific Methodology (Dr. Docker paper)](#3-scientific-methodology)
4. [What this fork changes](#4-what-this-fork-changes)
5. [Prerequisites and Configuration](#5-prerequisites-and-configuration)
6. [`config.yaml` Configuration](#6-configyaml-configuration)
7. [Stage I — Crawling (Discovery)](#7-stage-i--crawling-discovery)
8. [Stage II — Build (IDEA Graph)](#8-stage-ii--build-idea-graph)
9. [Exposure Ranker (Prioritization)](#9-exposure-ranker-prioritization)
10. [Output and handoff to Stage III](#10-output-and-handoff-to-stage-iii)
11. [Pipeline Automation](#11-pipeline-automation)
12. [Monitoring](#12-monitoring)
13. [Command Reference](#13-command-reference)
14. [Design Decisions and Trade-offs](#14-design-decisions-and-trade-offs)


---

## 1. Context and Motivation

This project implements the collection and prioritization of Docker images for
large-scale security scanning. The goal is to select Docker Hub containers
intelligently — not at random — prioritizing images with:

- **High Pull Count** (widely used, direct impact on users)
- **High Dependency Weight** (base images whose vulnerabilities propagate to child images)
- **High supply-chain exposure** (images whose children, summed up, accumulate a large volume of pulls)

The resulting prioritization (`exposure_ranked.jsonl`) is handed off to Stage III
(the `scanners` repository), which runs the multi-scanner scan.

The scientific basis is the paper **"Dr. Docker: A Large-Scale Security Measurement of Docker Image Ecosystem"** (WWW '25, Shi et al.), which proposes the **DITector** framework to measure the security of the Docker ecosystem at large scale.

---

## 2. Pipeline Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        DITector Research Pipeline                        │
└──────────────────────────────────────────────────────────────────────────┘

  NODE 1 / NODE 2 (Crawlers)           NODE 1 (Databases)
  ┌──────────────────┐                 ┌──────────────────────┐
  │  Docker Hub      │                 │     MongoDB          │
  │  V2 API          │────────────────▶│  (repositories_data) │
  │  /v2/search/     │                 │  namespace, name,    │
  │  Stage I: CRAWL  │                 │  pull_count          │
  │  (DFS + Workers) │                 └──────────┬───────────┘
  └──────────────────┘                            │
                                                  │
  NODE 3 (Builder)                                │
  ┌──────────────────┐                 ┌──────────▼───────────┐
  │  Docker Hub      │                 │     Stage II         │
  │  Tag+Image API   │────────────────▶│     BUILD            │
  │  (JWT authn,     │                 │  Atomic claim +      │
  │   HubClient,     │                 │  HubClient + cache   │
  │   MongoDB cache) │                 │  + Neo4j IDEA        │
  └──────────────────┘                 └──────────┬───────────┘
                                                  │
                                       ┌──────────▼───────────┐
                                       │     Neo4j            │
                                       │  (Layer IDEA graph)  │
                                       │  IS_BASE_OF edges    │
                                       │  ./neo4j_data/       │
                                       └──────────┬───────────┘
                                                  │
                                       ┌──────────▼───────────┐
                                       │  Exposure Ranker     │
                                       │  compute_exposure_   │
                                       │  ranking.py          │
                                       │  subtree pull sum    │
                                       └──────────┬───────────┘
                                                  │
                                       ┌──────────▼───────────┐
                                       │  exposure_ranked     │
                                       │  .jsonl              │
                                       │  (JSONL, one record  │
                                       │   per repository)    │
                                       └──────────┬───────────┘
                                                  │  contract
                                       ┌──────────▼───────────┐
                                       │  Stage III           │
                                       │  `scanners` repo     │
                                       │  6-scanner scan      │
                                       └──────────────────────┘
```

---

## 3. Scientific Methodology

The Dr. Docker paper (WWW '25) defines:

### 3.1 Data Collection

Docker Hub provides two types of repository:
- **Official images**: listed via a public index file (`docker-library/official-images`)
- **Community images**: accessible through the API `GET /v2/search/repositories/?query=<keyword>`

The API accepts queries of 2–255 characters and returns up to **10,000 results** per query. To cover the 12M+ repositories, the paper implements a **DFS keyword generator**:

```
If count(keyword) >= 10,000 → go deeper: enqueue keyword+"a", keyword+"b", ..., keyword+"z", keyword+"0", ..., keyword+"9", keyword+"-", keyword+"_"
If count(keyword) < 10,000  → scrape: fetch all available pages
```

### 3.2 Building the IDEA Graph (Image DEpendency grAph)

The graph models inheritance between images through **Layer nodes**. Each node represents a layer from the standpoint of the dependency chain.

**Node ID computation:**

For a **content layer** (has a `digest`):
```
dig_i      = SHA256(layer_i.digest)
Layer_i.id = SHA256(Layer_{i-1}.id + dig_i)
```

For a **config layer** (only has a Dockerfile instruction, no file content):
```
dig_i      = SHA256(layer_i.instruction)
Layer_i.id = SHA256(Layer_{i-1}.id + dig_i)
```

The node ID of the **bottom layer** (i=0) is computed with `preID = ""`:
```
Layer_0.id = SHA256("" + SHA256(layer_0.digest_or_instruction))
```

**Why this scheme works:** If two images share the same first N layers in the same order, they will share the same `Layer_N.id`. This makes it possible to identify upstream/downstream relations via the graph, without having to compare every layer.

**Graph relations:**
- `(Layer)-[:IS_BASE_OF]->(Layer)` — inheritance relation between layers
- `(Layer)-[:IS_SAME_AS]-(RawLayer)` — association of a layer position to its physical content

### 3.3 Identifying Critical Images

The paper defines two sets of high-impact images:

| Type | Criterion | Count in paper |
|------|----------|--------------|
| **High-Pull-Count** | Pull count ≥ 1,000,000, top 3 most recent tags | 20,673 images |
| **High-Dependency-Weight** | Dependency weight ≥ 10 (≥10 images depend directly on it) | 25,924 images |

**Dependency Weight (Out-Degree):** number of child images that inherit from this image.
**Dependent Weight (In-Degree):** number of images that this image depends on.

### 3.4 Paper Findings

- **93.7%** of the analyzed images contain known vulnerabilities
- **4,437** images with secret leakage (private keys, API tokens, URIs)
- **50** images with misconfigurations (MongoDB, Redis, Elasticsearch, CouchDB)
- **24** malicious images (crypto miners: XMR, PKT, CRP)
- **334** downstream images affected by malicious images (supply-chain propagation)

---

## 4. What this fork changes

The original upstream (the upstream DITector framework, Dr. Docker) declared the `crawl` subcommand but with no implementation (the `Run` field was absent in the corresponding `cobra.Command`). Stages II and III were functional. This version implements the complete Stage I and re-engineers Stage II for large-scale parallel operation.

### 4.1 New `crawler/` package

**File:** `crawler/crawler.go`

Implementation of the distributed crawler described in the paper. The original upstream declared the `crawl` subcommand in `cmd/cmd.go` but with no `Run` field — the command was a stub registered without an implementation. This version implements the complete body of Stage I.

**Task queue architecture:**
- `ParallelCrawler` maintains N workers that consume tasks from the MongoDB collection `crawler_keywords`
- Each task is a DFS prefix with a `status` field: `pending` → `processing` → `done`
- `getNextTask()` uses an atomic `FindOneAndUpdate`, guaranteeing that two workers (including those on different nodes) never process the same prefix simultaneously
- `ensureQueueInitialized()` seeds the alphabet `[a-z0-9-_]` as `pending` only if the collection is empty; on restart, it reverts `processing` tasks → `pending` (self-healing after a crash)
- `processTask()`: collects all pages for the prefix (max 100 pages × 100 results), then inserts 38 children as `pending` if `count >= 10,000` or `len(prefix) == 1` (stopword workaround)
- In-memory deduplication via `seenRepos sync.Map` (O(1)); `PreloadExistingRepos()` warms the cache at boot by loading all repository names from the database into RAM

**Anti-detection strategy — `fetchPage`:**

Docker Hub applies a WAF/Cloudflare with behavioral detection. The response is a multi-layered camouflage stack:

| Layer | Mechanism | Implementation |
|--------|-----------|---------------|
| TLS fingerprint | Forced HTTP/1.1 (no HTTP/2), TLS 1.2+ | `tls.Config{MinVersion: tls.VersionTLS12}` + transport without HTTP/2 |
| Browser headers | Complete set of Chrome 121 headers | `setBrowserHeaders()`: UA, Accept, Referer, Sec-Fetch-*, Connection |
| Per-account identity | Each JWT account has a fixed, exclusive UA | `acc.UserAgent` assigned at boot via round-robin over a pool of 7 UAs |
| Inter-page jitter | Random 400–900 ms between pages | `rand.Intn(500) + 400` ms per request |
| Inter-task jitter | Random 0–1000 ms after each task | `rand.Intn(1000)` ms in the worker loop |
| Keep-Alive / body draining | Body fully read before closing | `io.ReadAll(resp.Body)` — returns the socket to the TCP pool |

**HTTP error handling — no recursive retry:**

| Code | Interpretation | Action | Task fate |
|--------|---------------|------|-------------------|
| 401 | Expired JWT | `ClearToken(token)` + `GetNextClient()` | re-enqueued as `pending` |
| 403 | High bot score / flagged IP | sleep 15 min + `GetNextClient()` | re-enqueued as `pending` |
| 429 | Rate limit per IP/account | sleep 15 s + `GetNextClient()` | re-enqueued as `pending` |
| others | Transient error | returns `nil` | re-enqueued as `pending` |

A task is never discarded: on any failure, `processTask` calls `updateTaskStatus(prefix, "pending")` before returning. On the next iteration of any available worker, it will be resumed.

---

**File:** `crawler/auth_proxy.go`

`IdentityManager` centralizes authentication, User-Agents, and HTTP clients:

- Loads Docker Hub accounts from `accounts.json` (`[{username, password}]`)
- Assigns an exclusive `UserAgent` to each account at load time — round-robin over `globalUAPool` (7 strings representing Chrome 121, Edge, Firefox 122, Safari 17 on Windows, Mac, and Linux)
- `GetNextClient()` returns `(*http.Client, token, ua)`: the UA is returned alongside the token so it can be propagated consistently across every request from that identity
- JWT login via `POST /v2/users/login/` guarded by `loginMu sync.Mutex` — prevents two workers from logging in the same account simultaneously
- `ClearToken(token string)` walks the accounts and clears the `Token` field of the account matching the expired token; on the next call to `GetNextClient`, `LoginDockerHub` is invoked automatically
- The per-client `http.Transport` configures `MaxIdleConns=100`, `IdleConnTimeout=90s`, and `TLSHandshakeTimeout=10s`, maintaining a stable TCP pool and avoiding the massive opening of sockets (a bot signal)

### 4.2 New file `buildgraph/from_mongo.go`

Complete re-engineering of the `build` stage for distributed operation with MongoDB atomic claim:

```
ClaimNextBuildRepo (per goroutine — atomic FindOneAndUpdate)
    │
    ▼ repoWorker × max(NumCPU*8, 32)   ← I/O bound: network wait
    │   (HubClient authenticated per goroutine)
    │   (MongoDB cache → API fallback for tags and images)
    │   (defer MarkRepoGraphBuilt — always executed)
    ▼
jobChan
    │
    ▼ graphWorker × max(NumCPU*2, 8)   ← DB bound: Neo4j writes
    │
    ▼
Neo4j (IDEA graph) + MongoDB (graph_built_at)

checkpointWriter (single-writer goroutine)
    ▼
dataDir/build_checkpoint.jsonl
```

**Atomic claim:** each `repoWorker` uses `ClaimNextBuildRepo` instead of a shared cursor, enabling distributed execution across multiple machines. `ResetStaleBuildClaims` at startup releases orphaned claims from previous runs.

**Checkpointing:** `defer MarkRepoGraphBuilt` in `processRepo` ensures `graph_built_at` is written for every processed repository, including those with no available tags — eliminating the infinite reprocessing of empty repositories.

### 4.3 Change in `myutils/urls.go`

Template and function for the V2 Search API:

```go
V2SearchURLTemplate = `https://hub.docker.com/v2/search/repositories/?query=%s&page=%d&page_size=%d`

func GetV2SearchURL(query string, page, size int) string
```

The `ordering=-pull_count` parameter was removed. Docker Hub uses `best_match` as the default ordering mode, which prioritizes exact prefix matches before popularity-based results. For the prefix DFS, `best_match` is semantically superior: `query="ngin"` returns `nginx` before repositories that merely mention "nginx" in their descriptions, maximizing the relevance of the results collected at each node of the DFS tree.

Cross-page consistency is guaranteed by the unique MongoDB index on `{namespace, name}`, not by arrival order.

The upstream declared the `crawl` subcommand as a stub with no implementation and used no search API.

### 4.4 New file `myutils/hubclient.go`

`HubClient` is the authenticated HTTP client shared by Stages I and II, eliminating code duplication:

- **`IdentityProvider` interface** — an abstraction over `IdentityManager`; lets `myutils` not depend on `crawler`
- **`NewHubClient(ip IdentityProvider) *HubClient`** — one instance per goroutine
- **`Get(url)`** — 3 attempts with rotation on 401/429/403; Chrome 145 headers injected automatically
- **`GetInto(url, dest)`** — `Get` + JSON unmarshal
- **`GetTags(ns, name, pageNum, size)`** — authenticated paginated tag fetch
- **`GetImages(ns, name, tag)`** — authenticated image manifest fetch
- **`setHeaders(req)`** — injects `Accept-Language`, `Referer: https://hub.docker.com/`, `Sec-Fetch-*`
- **`rotate()`** — switches identity internally via `IdentityProvider`

### 4.5 New file `buildgraph/metrics.go`

`BuildMetrics` provides real-time progress tracking for Stage II:

- Atomic counters for `Processed`, tag/image cache hits/misses, Neo4j insertions, errors
- `newBuildMetrics(threshold)` captures the total number of pending repositories at startup
- `startReporter(dataDir, done)` logs and persists to `build_metrics.log` every 60s
- ETA computed after 30s: `rate = processed/elapsed_min`, `ETA = (total−processed)/rate`

### 4.6 Changes in `myutils/mongo.go`

Added to the MongoDB client to support the high-throughput crawler and the distributed Stage II:

- **`BulkUpsertRepositories(repos []*Repository)`** — atomic, unordered bulk write; ~10-50× faster than individual upserts in a loop, processing a whole page of results at once
- **`KeywordsColl`** — new `crawler_keywords` collection for Stage I checkpointing: on restart, already fully crawled keywords are skipped in O(1)
- **`IsKeywordCrawled(keyword)` / `MarkKeywordCrawled(keyword)`** — read/write interface for the Stage I checkpoint
- **`MarkRepoGraphBuilt(namespace, name)`** — writes `graph_built_at` and removes `build_claimed`/`build_started_at` (Stage II checkpoint)
- **`ClaimNextBuildRepo(threshold)`** — atomic `FindOneAndUpdate` to claim a repository in Stage II
- **`ResetStaleBuildClaims()`** — releases orphaned claims at Stage II startup
- **`CountPendingBuildRepos(threshold)`** — checks for an empty queue for the immortal worker pattern
- **`FindImagesByDigests(digests)`** — batched query with `$in`; replaces N individual queries
- **Connection pool**: `SetMaxPoolSize(100)`, `SetMinPoolSize(5)`, `SetMaxConnIdleTime(5m)` — stability under high parallel load
- **Initial ping timeout**: increased from `1s` to `30s` — avoids a false negative on slow connections

### 4.7 Changes in `myutils/neo4j.go`

`InsertImageToNeo4j` was rewritten for a **single transaction per image** (before: one transaction per layer):

1. All layer IDs are computed locally via SHA256 (pure CPU, zero network I/O)
2. The entire layer chain + image tag is inserted in **a single `ExecuteWrite`** — O(1) round-trips per image regardless of the number of layers

Result: insertion latency drops from O(N layers × RTT) to O(1 × RTT).

**Fix in `findLayerNodesByRawLayerDigestFunc`:** the original query used `{id: $digest}` to match a `RawLayer` node, but the stored property is `digest`. Fixed to `{digest: $digest}`. The bug silently broke upstream image tracking.

### 4.8 Changes in `myutils/docker_hub_api_requests.go`

The global HTTP client was restructured:

- **`DisableKeepAlives: true` removed** — keep-alives enabled; TCP connections are reused across requests (saving ~100-300ms of handshake+TLS per request)
- **Connection pool**: `MaxIdleConns: 300`, `MaxIdleConnsPerHost: 50`, `IdleConnTimeout: 90s`
- **`Timeout: 30s`** added to the global client

### 4.9 Changes in `myutils/config.go`

- **Override env vars**: `MONGO_URI` and `NEO4J_URI` override the values in `config.yaml` — lets Node 2 point at Node 1's MongoDB without editing the config file
- **Config location**: `filepath.Dir(os.Args[0])` → `os.Getwd()` — the config is looked up relative to the working directory, not the binary (compatible with `go run`)
- **Optional Neo4j**: if the Neo4j connection fails at startup, the system does not abort — useful for running only Stage I without an active Neo4j

### 4.10 Docker Compose Infrastructure

Complete infrastructure to run the pipeline:

| Service | Image | Port | Purpose |
|---------|--------|-------|-----------|
| `ditector_mongo` | `mongo:latest` | 27017 | Persistence of repos, tags, images |
| `ditector_neo4j` | `neo4j:latest` | 7474/7687 | IDEA dependency graph |
| `ditector_crawler` | `golang:1.22` | — | Runs the crawl with a configurable seed |

The `SEED` environment variable lets you run multiple crawler instances with different seeds (meet-in-the-middle strategy):
```bash
SEED=a docker compose up -d crawler   # Machine 1: a-m
SEED=n docker compose up -d crawler   # Machine 2: n-z
```

`docker-compose.node3.yml` defines the `builder` service for Node 3 (Stage II):
```bash
DB_HOST=<NODE_1_IP> NEO4J_URI=neo4j://<NODE_1_IP>:7687 make start-build
```

The Neo4j volume was migrated from a named Docker volume to the host path `./neo4j_data:/data`, protecting the data against `docker system prune -a --volumes`.

### 4.11 Change in `scripts/calculate_node_dependent_weights.go`

The `if repoDoc.Namespace == "library"` branch had `continue` as its first statement, making all the code below it unreachable. Official Docker images (`library/`) were silently skipped in the dependency-weight computation. The `continue` was removed.

### 4.12 New automation scripts (`automation/`)

- `pipeline_autopilot.sh` — runs the 3 stages sequentially with parameterized configuration
- `test_e2e.sh` — end-to-end integration test: crawl with seed `nginx`, build, rank, verify output

---

## 5. Prerequisites and Configuration

### Required software

```bash
# Go 1.21+
go version

# Docker and Docker Compose
docker --version
docker compose version
```

### Infrastructure

Bring up MongoDB and Neo4j before any command:

```bash
docker compose up -d mongodb neo4j
```

Wait ~10s for the services to start. Verify:

```bash
# MongoDB
mongosh localhost:27017 --eval "db.runCommand({ping: 1})"

# Neo4j
curl -s http://localhost:7474 | head -5
```

### Docker Hub accounts (required for the crawl)

Create `accounts.json` in the project root (do NOT commit):

```json
[
  {"username": "user1", "password": "password1"},
  {"username": "user2", "password": "password2"}
]
```

> Free Docker Hub accounts are sufficient. Multiple accounts increase the rate limit and enable JWT token rotation.

### Proxies (optional)

Create `proxies.txt` in the root (one URL per line):

```
http://user:pass@proxy1.example.com:8080
http://user:pass@proxy2.example.com:8080
socks5://proxy3.example.com:1080
```

---

## 6. `config.yaml` Configuration

Copy the template and adjust it:

```bash
cp config_template.yaml config.yaml
```

Main fields:

```yaml
max_thread: 0              # 0 = use all available CPUs

log_file: "ditector.log"   # path relative to the project root

mongo_config:
  uri: "mongodb://localhost:27017"
  database: "dockerhub_data"
  collections:
    repositories: "repositories_data"
    tags: "tags_data"
    images: "images_data"
    image_results: "image_results"
    layer_results: "layer_results"
    user: "user_data"

neo4j_config:
  neo4j_uri: "neo4j://localhost:7687"
  neo4j_username: "neo4j"
  neo4j_password: ""       # empty if NEO4J_AUTH=none (docker-compose default)

proxy:
  http_proxy: ""           # leave empty if not using a global proxy
  https_proxy: ""
```

> **Important:** For the docker-compose Neo4j (configured with `NEO4J_AUTH=none`), leave `neo4j_password` empty.

---

## 7. Stage I — Crawling (Discovery)

### Representation of repository names on Docker Hub

Docker Hub organizes images in two hierarchical levels: `namespace/name`. There are no nested namespaces (unlike GitHub). The V2 API returns the `repo_name` field in two possible formats:

| Type | `repo_name` in the API | Real namespace | Real name |
|------|--------------------|----------------|-----------|
| Official image (`library`) | `"nginx"` | `library` | `nginx` |
| Official image (`library`) | `"postgres"` | `library` | `postgres` |
| Community image | `"cimg/postgres"` | `cimg` | `postgres` |
| Community image | `"redis/redis-stack"` | `redis` | `redis-stack` |

The `repo_owner` field present in the API response is **always empty** (`""`) for all repository types — it must not be used. The correct `namespace` is extracted exclusively from `repo_name` via `parseRepoName()` in `crawler/crawler.go`:

```go
func parseRepoName(repoName string) (namespace, name string) {
    parts := strings.SplitN(repoName, "/", 2)
    if len(parts) == 2 {
        return parts[0], parts[1]  // community: "nginx/nginx-ingress" → ("nginx", "nginx-ingress")
    }
    return "library", repoName    // official: "nginx" → ("library", "nginx")
}
```

**Why this is critical for `docker pull` and the scanners:**

- `library/` images: the namespace can be omitted. `docker pull nginx` is equivalent to `docker pull library/nginx`.
- Community images: the namespace is **mandatory**. `docker pull cimg/postgres` does not work without the `cimg/` prefix. Without it, Docker interprets it as `library/postgres` — a different image, yielding an invalid scan result.

The correct way to build the pull name from the exported dataset:

```python
ns  = record["repository_namespace"]
img = record["repository_name"]
tag = record["tag_name"]

# For library images, the namespace is omitted in the pull (Docker convention)
image_ref = f"{img}:{tag}" if ns == "library" else f"{ns}/{img}:{tag}"
# docker pull nginx:latest        ← library
# docker pull cimg/postgres:15    ← community
```

**Empirical verification:** In a sample of 1,000 results from the V2 API covering 10 distinct queries (`nginx`, `redis`, `postgres`, `mysql`, `debian`, `ubuntu`, `python`, `node`, `go`, `java`), no `repo_name` had more than one slash. The `namespace/name` format is the structural ceiling of Docker Hub.

### What it does

The crawler scans Docker Hub using the **DFS (Depth-First Search)** strategy over the keyword space, discovering repositories and persisting `namespace`, `name`, and `pull_count` to MongoDB.

**Internal flow:**

```
seed keyword
    │
    ▼
GET /v2/search/repositories/?query=<keyword>&page=1&page_size=100
    │
    ├─ count >= 10,000? → enqueue keyword+[a-z0-9-_] (deepen DFS)
    ├─ count > 0?       → scrapeAllPages: collect all pages
    └─ count == 0?      → keyword with no results, move on
```

### How to run

**Simple mode (one machine):**
```bash
go run main.go crawl \
  --workers 20 \
  --accounts accounts.json \
  --config config.yaml
```

**Accelerated mode (multiple machines / meet-in-the-middle):**
```bash
# Machine 1: seeds a-m
go run main.go crawl --workers 30 --seed 'a' --accounts accounts.json --config config.yaml

# Machine 2: seeds n-z
go run main.go crawl --workers 30 --seed 'n' --accounts accounts.json --config config.yaml
```

**With proxies:**
```bash
go run main.go crawl --workers 20 --proxies proxies.txt --accounts accounts.json --config config.yaml
```

### Parameters

| Flag | Default | Description |
|------|--------|-----------|
| `--workers` / `-w` | 10 | Number of parallel worker goroutines |
| `--seed` | — | Initial keywords for the DFS, comma-separated (no seed = starts from the whole alphabet) |
| `--shard` | -1 | Shard index (0-based) for distributed crawl; requires `--shards` |
| `--shards` | 1 | Total number of shards for meet-in-the-middle distribution (e.g. 2 to split the alphabet across 2 machines) |
| `--accounts` | — | Path to `accounts.json` |
| `--proxies` | — | Path to the proxies file (one URL per line) |
| `--config` / `-c` | `config.yaml` | Path to the configuration file |

### Check progress

```bash
# Count of discovered repositories
mongosh localhost:27017/dockerhub_data --eval 'db.repositories_data.countDocuments()'

# Follow discoveries in real time
tail -f *.log | grep "Discovered repository"

# Top 10 by pull_count
mongosh localhost:27017/dockerhub_data --eval '
  db.repositories_data.find({}, {name:1, pull_count:1, _id:0})
    .sort({pull_count: -1}).limit(10).pretty()
'
```

### Expected volume

With 1 machine and 20 workers running for 24h, you can expect to discover between 500,000 and 2,000,000 repositories, depending on connection speed and rate limits. Docker Hub contains 12M+ repositories in total.

---

## 8. Stage II — Build (IDEA Graph)

### What it does

For each repository in MongoDB with `pull_count >= threshold`, Stage II:

1. Atomically claims the repository via `ClaimNextBuildRepo` (MongoDB `FindOneAndUpdate`), guaranteeing that no other worker processes it simultaneously
2. Queries the MongoDB tag cache; falls back to the Docker Hub API with JWT authentication (HubClient) only when the cache does not contain the data
3. For each tag, queries the MongoDB image cache; accesses the API to obtain layers (digest, instruction, size) when needed
4. Filters out Windows images
5. Inserts the IDEA graph into Neo4j using the layer-ID hashing algorithm (section 3.2 of the paper)
6. Marks the repository as complete via `MarkRepoGraphBuilt` (the `graph_built_at` field) — executed via `defer`, therefore guaranteed even for repositories with 0 tags

Stage II can be run on multiple machines simultaneously. The atomic claim eliminates duplicate reprocessing without any additional coordination between nodes.

### How to run

**Via Makefile (Node 3 — recommended):**
```bash
# Set the variables and start the builder container
DB_HOST=<NODE_1_IP> NEO4J_URI=neo4j://<NODE_1_IP>:7687 make start-build

# Follow the logs
make logs-build
```

**Via the command line (development / local test):**
```bash
go run main.go build \
  --format mongo \
  --threshold 1000 \
  --tags 3 \
  --accounts accounts.json \
  --data_dir /tmp/ditector_build \
  --config config.yaml
```

### Parameters

| Flag | Default | Description |
|------|--------|-----------|
| `--format` | `mongo` | Data source (only `mongo` supported) |
| `--threshold` | 1,000,000 | Minimum pull count to process a repository |
| `--tags` | 10 | Number of most recent tags to process per repository |
| `--accounts` | — | Path to `accounts.json` (JWT authentication — same file as Stage I) |
| `--proxies` | — | Path to the proxies file (optional) |
| `--data_dir` | `.` | Directory for `build_checkpoint.jsonl` and `build_metrics.log` |

The `--page` and `--page_size` parameters were removed: progress control is managed by the `graph_built_at` field in MongoDB (via the atomic claim), not by manual pagination.

**Research recommendations:**
- `--threshold 1000` — covers most repositories with real activity
- `--tags 3` — aligned with the Dr. Docker paper; the 3 most recent tags are enough for inheritance analysis

### Monitoring progress

```bash
# Real-time metrics with ETA
tail -f build_metrics.log

# Example metrics line:
# [METRICS 02:15:00] progress=1234/48000 (2.6%) | rate=45.2 repos/min | ETA=17h22m | cache tags=82% imgs=71% | neo4j=12340 | errors=3 | uptime=27m18s

# Completed repositories (lines in the checkpoint)
wc -l build_checkpoint.jsonl

# Direct count in MongoDB
mongosh <MONGO_URI>/dockerhub_data --eval \
  'db.repositories_data.countDocuments({graph_built_at: {$exists: true}})'

# Nodes in Neo4j
cypher-shell -u neo4j -p "" "MATCH (l:Layer) RETURN count(l) AS total_layers"

# Edges in Neo4j
cypher-shell -u neo4j -p "" "MATCH ()-[r:IS_BASE_OF]->() RETURN count(r) AS total_edges"
```

### Neo4j data persistence

Neo4j persists to `./neo4j_data/` (an explicit host path). This folder is created automatically by Docker Compose on the first start. Unlike named Docker volumes, it is not affected by `docker system prune -a --volumes`. Include `neo4j_data/` in your regular backups alongside `mongo_data_secure/`.

---

## 9. Exposure Ranker (Prioritization)

### What it does

The exposure ranker (`scripts/compute_exposure_ranking.py`) reads the IDEA graph
from Neo4j built in Stage II and produces the final prioritization consumed by
Stage III. It is the authors' original implementation in this fork.

For each repository present in the graph, it picks a representative tag and
computes, in a single *bottom-up* pass (O(nodes)):

- **`dependency_weight`** — number of images in the (strict) *downstream* subtree
  of the image's top layer; how many images inherit from it.
- **`downstream_pull_sum`** — sum of the *pull counts* of the repositories of all
  the images in that downstream subtree.
- **`exposure`** = `pull_count(repo) + downstream_pull_sum` — the prioritization
  metric: combines the direct use of the repository with the supply-chain impact
  of the images that depend on it.

The `IS_BASE_OF` graph is a *forest of out-trees* (each Layer has at most one
parent, since `Layer.id = sha256(parent.id + sha256(digest))`), so the subtree
sum is exact and free of dedup across branches.

**Output schema — `exposure_ranked.jsonl` (one JSON per line, ordered by
decreasing `exposure`):**

```json
{
  "repository_namespace": "library",
  "repository_name": "nginx",
  "tag_name": "latest",
  "image_digest": "sha256:abc123...",
  "pull_count": 1000000000,
  "dependency_weight": 1847,
  "downstream_pull_sum": 5300000000,
  "exposure": 6300000000
}
```

### How to run

```bash
RANKER_SHARDS=4 \
NEO4J_URI=bolt://127.0.0.1:7687 \
MONGO_URI=mongodb://127.0.0.1:27017 \
OUT_PATH=$PWD/exposure_ranked.jsonl \
python3 scripts/compute_exposure_ranking.py
```

| Environment variable | Default | Description |
|----------------------|--------|-----------|
| `NEO4J_URI` | `bolt://127.0.0.1:7687` | IDEA graph built in Stage II |
| `MONGO_URI` | `mongodb://127.0.0.1:27017` | Repository pull counts (Stage I) |
| `WORKDIR` | `~/scanners/data/exposure_work` | Intermediate gzip dumps (resumable) |
| `OUT_PATH` | `~/scanners/data/ditector_exposure_ranked.jsonl` | Output file |
| `RANKER_SHARDS` | `4` | Parallel streaming of Neo4j in N shards |

The run is **resumable**: the Neo4j/Mongo dumps are written to gzip files
first; the recomputation re-reads those dumps without re-querying the databases.

### Contract with Stage III

`exposure_ranked.jsonl` is the only artifact that crosses the boundary into
Stage III. The [`scanners`](https://anonymous.4open.science/r/AnonymousSystem-2131/)
repository consumes it directly via `scanners seed` — its JSONL reader natively
recognizes this schema (`repository_namespace` / `repository_name` /
`tag_name`). No intermediate conversion is needed.

---

## 10. Output and handoff to Stage III

Discovery and prioritization end here. The `exposure_ranked.jsonl` artifact
produced by the ranker (Section 9) is handed off to **Stage III — multi-scanner
scanning**, implemented in the
[`scanners`](https://anonymous.4open.science/r/AnonymousSystem-2131/) repository.

```
DITector (this repo)                       scanners (Stage III)
┌─────────────────────────┐                ┌──────────────────────────┐
│ Stage I  — crawler       │                │ scanners seed            │
│ Stage II — IDEA graph    │  exposure_     │   → work queue           │
│ exposure ranker          │─ranked.jsonl──▶│ scanners run             │
│                          │   (contract)   │   → 6 scanners per target│
└─────────────────────────┘                │ scanners report/analyze  │
                                            └──────────────────────────┘
```

For each prioritized repository, Stage III does: `docker pull`, runs the
six scanners (static against the image, dynamic against the container),
normalizes, and consolidates the *findings*. The details — including integration
with pre-existing OpenVAS scans via `scanners import-openvas` — are
documented in the `README.md` of the `scanners` repository.

The automatic orchestration of the two stages in sequence is in the
[`anonymoussystem`](https://anonymous.4open.science/r/AnonymousSystem-2131/) repository.

---

## 11. Pipeline Automation

### Pipeline Autopilot

Runs the 3 stages sequentially:

```bash
./automation/pipeline_autopilot.sh "a"
```

Configuration inside the script itself:

```bash
WORKERS=20          # crawl workers
CRAWL_DURATION="30s" # crawl time (adjust for real research: "6h", "24h")
PULL_THRESHOLD=1000  # minimum pull count
OUTPUT_FILE="final_prioritized_dataset.json"
```

### E2E Integration Test

Validates that the whole pipeline works end-to-end with real data (seed `nginx`):

```bash
chmod +x automation/test_e2e.sh
./automation/test_e2e.sh
```

What the test checks:
1. Crawl with seed `nginx` for 20s → discovers repositories related to nginx
2. Build with threshold=0 → processes all discovered repositories
3. Rank → generates `test_output.json`
4. Verifies that `test_output.json` exists and is larger than 10 bytes

---

## 12. Monitoring

### MongoDB

```bash
# Total discovered repositories
mongosh localhost:27017/dockerhub_data --eval \
  'db.repositories_data.countDocuments()'

# Repositories with pull_count >= 1M
mongosh localhost:27017/dockerhub_data --eval \
  'db.repositories_data.countDocuments({pull_count: {$gte: 1000000}})'

# Top 20 repos by pull count
mongosh localhost:27017/dockerhub_data --eval \
  'db.repositories_data.find({},{name:1,namespace:1,pull_count:1,_id:0}).sort({pull_count:-1}).limit(20)'
```

### Neo4j (Browser at http://localhost:7474)

```cypher
// Total Layer nodes
MATCH (l:Layer) RETURN count(l)

// Total IS_BASE_OF edges (dependency edges)
MATCH ()-[r:IS_BASE_OF]->() RETURN count(r)

// The 10 images with the most dependents
MATCH (l:Layer)-[:IS_BASE_OF*]->(down:Layer)
WHERE size(l.images) > 0
RETURN l.images[0] AS image, count(down) AS downstream
ORDER BY downstream DESC LIMIT 10

// Check threat propagation: downstream of nginx:latest
MATCH (src:Layer {id: '<nginx_node_id>'})
MATCH (src)-[:IS_BASE_OF*]->(down:Layer)
WHERE size(down.images) > 0
RETURN down.images
```

### Logs

```bash
# Discoveries in real time
tail -f *.log | grep "Discovered repository"

# Build errors
tail -f *.log | grep "ERROR"

# Neo4j insertion rate
tail -f *.log | grep "Inserted into Neo4j" | wc -l
```

---

## 13. Command Reference

### Available subcommands

```
docker-scan crawl      — Phase I: repository discovery
docker-scan build      — Phase II: IDEA graph construction
docker-scan analyze    — Security analysis of a specific image
docker-scan execute    — Runs batch processing scripts
docker-scan calculate  — Computes the node ID of an image from its digest
```

### Global flags

| Flag | Default | Description |
|------|--------|-----------|
| `--config` / `-c` | `config.yaml` | Configuration file |
| `--log_level` / `-l` | `debug` | Log level: debug, info, warn, error, critical |

### `execute --script`

| Script | Description |
|--------|-----------|
| `calculate-node-weights` | (legacy) computes the Dependency Weight of each image and exports JSONL — superseded by the exposure ranker (`scripts/compute_exposure_ranking.py`, Section 9) |
| `analyze-threshold` | Analyzes images with a pull_count above a threshold |
| `analyze-all` | Analyzes all images in MongoDB |
| `count-images-with-upstream` | Counts images with an upstream (In-Degree > 0) |
| `count-images-with-downstream` | Counts images with a downstream (Out-Degree > 0) |
| `export-mongo-result-docs` | Exports analysis results from MongoDB to JSON |
| `check-same-node-as-high-dependent-images` | Identifies intersections between the high-PC and high-DW sets |

---

## 14. Design Decisions and Trade-offs

### Why was the crawler implemented in this fork in Go?

The upstream declared the `crawl` subcommand in `cmd/cmd.go` with no `Run` field — registered but with no implementation. Stage I was implemented in this fork in Go for stack consistency and for its advantages on I/O-intensive workloads:
- **Goroutines**: scales to hundreds of workers at ~2KB/goroutine (vs ~1MB/OS thread)
- **Channels**: type-safe communication between stages without manual locks
- **Single binary**: trivial deployment across multiple machines, with no external runtime

### Why does Build call the live API instead of reading from MongoDB?

The crawler (Stage I) stores only `namespace`, `name`, and `pull_count`. Tags and layers are fetched in Stage II via the live API. A deliberate trade-off:
- **Pros**: the data volume in MongoDB is smaller; the crawler is faster
- **Cons**: the build stage depends on API availability; repositories deleted between crawl and build produce logged errors

Unimplemented alternative: the crawler could store tags/layers directly, making the build stage fully offline.

### Known limitations

1. **JWT expiry and re-login**: on receiving HTTP 401, `fetchPage` calls `ClearToken` to invalidate the expired token and `GetNextClient` to obtain a new identity with automatic login. If all accounts simultaneously have an invalid token, the retry may fail for the page in question.
2. **Build live API**: if a repository is deleted between the crawl and the build, errors are logged but do not interrupt progress.
3. **Neo4j throughput**: one transaction per image (O(1) round-trips). For volumes >1M images, the bottleneck shifts to the Neo4j heap memory — increasing `NEO4J_dbms_memory_heap_max__size` is recommended.

---

*Based on the paper: Hequan Shi et al., "Dr. Docker: A Large-Scale Security Measurement of Docker Image Ecosystem", WWW '25.*
