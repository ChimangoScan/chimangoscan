# Phase II — Building the Dependency Graph

This document describes in detail the architecture, internal workings, and supporting mechanisms of Phase II of DITector. Phase II consumes the repositories collected by Phase I in MongoDB, fetches tag and image metadata from Docker Hub, and inserts each image's layer chain into Neo4j as a dependency graph.

---

## Table of Contents

1. [Pipeline overview](#1-pipeline-overview)
2. [Concurrency and worker sizing](#2-concurrency-and-worker-sizing)
3. [Atomic repository claim](#3-atomic-repository-claim)
4. [Tag selection strategy](#4-tag-selection-strategy)
5. [MongoDB cache layer](#5-mongodb-cache-layer)
6. [Neo4j graph model](#6-neo4j-graph-model)
7. [Layer ID computation (SHA256 chain)](#7-layer-id-computation-sha256-chain)
8. [Neo4j insertion: single transaction per image](#8-neo4j-insertion-single-transaction-per-image)
9. [Checkpoint and crash recovery](#9-checkpoint-and-crash-recovery)
10. [Metrics and log interpretation](#10-metrics-and-log-interpretation)
11. [MongoDB indexes for Phase II](#11-mongodb-indexes-for-phase-ii)
12. [Authentication, rate limiting, and jitter](#12-authentication-rate-limiting-and-jitter)
13. [Multi-node operation](#13-multi-node-operation)
14. [Useful Cypher queries](#14-useful-cypher-queries)

---

## 1. Pipeline overview

```
MongoDB (repositories_data)
        │  ClaimNextBuildRepo() — atomic, pull_count DESC
        ▼
  repoWorker (N workers, controlled by --workers)
        │  getTags()      → tags API (or MongoDB cache)
        │  getImages()    → images API (or MongoDB cache)
        ▼
  batchChan (buffer 10 000)
        │
        ▼
  graphWorker (2×NumCPU, minimum 8)
        │  InsertBatch()
        │  one Neo4j session per batch, one transaction per image
        ▼
  Neo4j (Layer, RawLayer, IS_BASE_OF, IS_SAME_AS)
        │
        ▼
  MongoDB: MarkRepoGraphBuilt() — sets graph_built_at
  build_checkpoint.jsonl — append-only per completed repo
  build_metrics.log      — snapshot every 60 s
```

The pipeline is forked: `repoWorker` is limited by the request rate to Docker Hub, while `graphWorker` is limited by Neo4j latency. The `jobChan` channel decouples the two stages so neither blocks the other.

---

## 2. Concurrency and worker sizing

### repoWorkers (data fetching)

The number of `repoWorker`s is controlled by the `--workers` flag (default: 1). Each worker uses an exclusive `HubClient` with its own identity. The recommended number equals the number of available Docker Hub accounts — one worker per account avoids token collisions between goroutines.

```
numRepo = --workers   # flag in cmd/cmd.go; default 1
```

With 6 accounts and `--workers 6`, there are 6 repository workers in parallel. Each gets ~1.8 req/s on average (the Hub's per-account limit), totaling ~10.8 req/s of tags + images.

### graphWorkers (Neo4j insertion)

```go
numGraph := runtime.NumCPU() * 2
if numGraph < 8 {
    numGraph = 8
}
```

The minimum is 8 to guarantee adequate utilization on machines with few cores. On 4-core machines there will be 8 graph workers; on 16-core machines there will be 32.

---

## 3. Atomic repository claim

`ClaimNextBuildRepo` uses `findAndModify` with an atomic filter and update:

```
Filter:
  pull_count  ≥ threshold
  graph_built_at  = null        (not yet processed)
  build_claimed   ≠ true        (not being processed right now)

Update:
  SET build_claimed = true
  SET build_started_at = now()
```

The operation is atomic in MongoDB: two workers never claim the same repository simultaneously. Repositories are ordered by descending `pull_count`, i.e. the most popular are processed first.

### Recovery of stuck claims

At startup, before any work, Phase II calls `ResetStaleBuildClaims`:

```
Filter:  build_claimed = true  AND  graph_built_at = null
Update:  UNSET build_claimed,  UNSET build_started_at
```

This recovers repositories that had `build_claimed = true` but whose worker died before completing. They go back to the pending pool and will be reprocessed normally. A repository leaves the pool definitively only when `graph_built_at` is set, which happens only after the Neo4j insertion is confirmed and `MarkRepoGraphBuilt` returns without error.

---

## 4. Tag selection strategy

Phase II does not process all of a repository's tags — that would be infeasible for repositories like `library/ubuntu` with hundreds of historical tags. The strategy is:

1. **Most recent tag**: fetches page 1 with `page_size=1` ordered by `last_updated` DESC. Always returns the most recently modified tag.
2. **`latest` tag**: fetched explicitly via `GET /v2/repositories/{ns}/{name}/tags/latest`. Represents what users get with `docker pull {image}` without specifying a tag.
3. **Deduplication**: if the most recent tag is already `latest`, two calls are not made. If they differ, both are processed.

```go
recent, _ := hub.GetTags(ns, name, 1, 1)        // page 1, size 1 → most recent
tags := recent
if len(recent) == 0 || recent[0].Name != "latest" {
    latest, _ := hub.GetTag(ns, name, "latest")  // explicit fetch
    if latest != nil {
        tags = append(tags, latest)
    }
}
```

**Rationale**: The most recent tag captures the current development state (e.g. `ubuntu:24.04`). The `latest` tag captures what most users install by default. Together they cover the two most relevant attack vectors for security analysis without exploding the data volume.

---

## 5. MongoDB cache layer

All Docker Hub API responses are persisted in MongoDB to avoid redundant calls in later runs (or on resume).

### Tag cache

Collection: `tags_data`

Before calling the API, `getTags` checks whether the repository already has saved tags with images:

```go
tags, err := mongo.FindAllTagsByRepoName(ns, name)
if err == nil && allTagsHaveImages(tags) {
    m.TagCacheHits.Add(1)
    return tags  // cache hit
}
// cache miss → call API
```

The `allTagsHaveImages` validation ensures the cache is used only if all tags have the `images` list populated (digest + architecture metadata). Tags saved without images were probably inserted by Phase I with incomplete data.

### Image cache

Collection: `images_data`

The `Tag` struct contains `Images []ImageInTag` with the digests of each image per architecture. `getImages` uses those digests to do a lookup in MongoDB:

```go
if len(t.Images) > 0 {
    imgs, ok := loadImagesFromCache(t.Images)
    if ok {
        m.ImageCacheHits.Add(1)
        return imgs, nil
    }
}
// cache miss → call API /tags/{tag}/images
```

`loadImagesFromCache` fetches all digests via `FindImagesByDigests` and validates that each image has `Layers` populated. If any image is missing or has empty layers, it goes to the API.

### Persistence after the API

After each API call, the responses are queued for asynchronous persistence via `writesCh chan func()`. A dedicated goroutine drains the channel in the background:

```go
// repoWorker never blocks on cache writes:
writesCh <- func() { mongo.UpdateImage(img) }
writesCh <- func() { mongo.UpdateTag(t) }
```

Persistence is asynchronous because the writes are only cache — a failure (crash before draining the channel) causes only a cache miss on the next run, with no impact on the integrity of the Neo4j graph or on the resume mechanism (`graph_built_at`).

This builds the cache progressively: subsequent runs with a different threshold or during failure recovery take advantage of the already-fetched data.

---

## 6. Neo4j graph model

### `Layer` node — context-dependent

A `Layer` node represents **a layer in a specific build context**. The same filesystem digest can generate different `Layer` nodes depending on the layer history that precedes it.

Properties:

| Property      | Type       | Description |
|---------------|------------|-----------|
| `id`          | string     | Chained SHA256 of the layer chain up to this point (see section 7) |
| `digest`      | string     | Digest of the filesystem layer (sha256:...), empty for configuration instructions |
| `size`        | int64      | Layer size in bytes |
| `instruction` | string     | Dockerfile instruction that generated this layer (e.g. `RUN apt-get install nginx`, `EXPOSE 80/tcp`, `CMD ["/bin/bash"]`) |
| `images`      | []string   | List of images that end at this node (format: `registry/ns/repo:tag@digest`) |

The `images` field is only populated on the **last layer** of each inserted image (via `addImageToLayerFunc`). For intermediate layers, `images` stays an empty list.

### `RawLayer` node — content-addressable

A `RawLayer` node represents the **physical content of a layer** independent of context. Two `Layer` nodes with the same `digest` point to the same `RawLayer`.

Properties:

| Property      | Type   | Description |
|---------------|--------|-----------|
| `digest`      | string | SHA256 digest of the layer (primary key, unique in the graph) |
| `size`        | int64  | Size in bytes |
| `instruction` | string | Associated Dockerfile instruction |

**Important**: `RawLayer` is only created for layers with a populated `digest` (filesystem layers with a `tar.gz`). Pure configuration layers — such as `EXPOSE`, `CMD`, `ENV`, `LABEL` — have `digest == ""` and generate only `Layer` nodes, with no corresponding `RawLayer`.

### `IS_BASE_OF` relationship

```
(Layer A) -[:IS_BASE_OF]-> (Layer B)
```

Indicates that layer A is the base of layer B in the build chain. The relationship is directed from the base to the top: root layer → ... → leaf layer.

To reconstruct an image's build order, traverse from A to the node with a non-empty `images` following `IS_BASE_OF`.

### `IS_SAME_AS` relationship

```
(Layer) -[:IS_SAME_AS]- (RawLayer)
```

Relates a specific context to the physical content. It is undirected (bidirectional in the graph). It lets you answer: "in which build contexts was this filesystem layer used?"

### Example diagram

For an image with 3 layers (FROM ubuntu, RUN apt install, EXPOSE 80):

```
(RawLayer digest=sha256:abc)
        |
   IS_SAME_AS
        |
(Layer id=H1, digest=sha256:abc, instruction="FROM ubuntu:22.04")
        |
   IS_BASE_OF
        |
(Layer id=H2, digest=sha256:def, instruction="RUN apt-get install -y nginx")
        |   \
   IS_BASE_OF  IS_SAME_AS
        |         \
        |     (RawLayer digest=sha256:def)
        |
(Layer id=H3, digest="", instruction="EXPOSE 80/tcp", images=["docker.io/library/nginx:latest@sha256:..."])
```

---

## 7. Layer ID computation (SHA256 chain)

The `id` of a `Layer` node is a function of the **complete layer chain** up to that point. It is computed locally (no I/O) before any Neo4j call:

```
dig_i = SHA256(layer.digest)        if layer.digest != ""
dig_i = SHA256(layer.instruction)   if layer.digest == ""

id_0 = SHA256("" + dig_0)           # first layer: prev_id = ""
id_1 = SHA256(id_0 + dig_1)
id_2 = SHA256(id_1 + dig_2)
...
id_N = SHA256(id_{N-1} + dig_N)     # id of the last layer = image ID
```

**Direct consequence**: two images that share the same first N layers will have equal IDs for those layers. Neo4j will use `MERGE` and will not duplicate those nodes — the chains are connected to the existing graph. This is the mechanism that makes the graph a DAG (directed acyclic graph) of real dependencies, not a forest of independent trees.

**Why double SHA256?** The `dig_i` is `SHA256(digest_string)`, not the raw digest. This normalizes inputs of different lengths (64-char digests vs long instructions) and avoids concatenation collisions.

---

## 8. Neo4j insertion: single transaction per image

An image's entire layer chain is inserted in **a single transaction** in Neo4j:

```
BEGIN
  MERGE Layer_0 + IS_SAME_AS RawLayer_0
  MERGE Layer_1 + IS_SAME_AS RawLayer_1 + IS_BASE_OF(Layer_0 → Layer_1)
  ...
  MERGE Layer_N + IS_SAME_AS RawLayer_N + IS_BASE_OF(Layer_{N-1} → Layer_N)
  MATCH Layer_N SET Layer_N.images += [imageName]
COMMIT
```

This reduces the latency from O(N) round-trips to O(1) per image. For a typical image with 10 layers, the latency goes from ~100ms (10 × 10ms) to ~15ms (1 round-trip).

The Cypher uses `MERGE` instead of `CREATE`, which guarantees idempotency: reinserting the same image twice does not duplicate nodes or relationships.

`InsertBatch` reuses a single Neo4j session for all images in the batch (one per repo), creating a new session only per batch — not per image. Images with zero layers after the ID computation are silently skipped.

---

## 9. Checkpoint and crash recovery

### build_checkpoint.jsonl

An append-only file in `data_dir` (mounted at `/app` in the container). Each line is a JSON:

```json
{"ns":"library","name":"ubuntu","built_at":"2025-04-05T14:23:01Z","tags":2}
```

Written by a single goroutine (`checkpointWriter`) consuming a channel — no mutex, no contention. The file survives container restarts because it is on the host-mounted volume.

### Crash recovery

On restart, Phase II does not re-read `build_checkpoint.jsonl`. Recovery is done via MongoDB:

1. `ResetStaleBuildClaims` releases repos with `build_claimed=true` and `graph_built_at=null` (the worker died in the middle of work).
2. `ClaimNextBuildRepo` only returns repos with `graph_built_at=null`. Repos marked as complete are automatically skipped.

The JSONL checkpoint serves as external auditing and for post-mortem statistics, not as a flow-control mechanism.

### build_metrics.log

An append-only file in `data_dir`. Snapshot every 60 seconds. Also written to the process's structured log.

---

## 10. Metrics and log interpretation

Metrics line format:

```
[METRICS 14:23:01] progress=1234/50000 (2.5%) | rate=18.3 repos/min | ETA=44h0m0s | cache tags=72% imgs=85% | neo4j=9870 | errors=3 | uptime=1h7m23s
```

| Field | Meaning |
|-------|-------------|
| `progress=A/B` | A = repos completed in this run; B = total pending at start (captured once at startup) |
| `rate` | repos per minute since the start of this run |
| `ETA` | linear estimate based on the current rate and the total remaining |
| `cache tags` | % of repositories whose tags were read from MongoDB instead of the API |
| `cache imgs` | % of images whose layers were read from MongoDB instead of the API |
| `neo4j` | total images inserted into Neo4j in this run |
| `errors` | total non-fatal errors (getImages failed, tag not found, etc.) |
| `uptime` | time since process startup |

**Note on `progress=X/0`**: the total `B` is computed by `CountPendingBuildRepos` with a 30s timeout at startup. If the query takes longer than 30s (rare, but possible under load), B stays at 0 and the ETA stays undefined. This does not affect processing.

The `[FINAL]` line is emitted when all workers finish (empty queue confirmed).

---

## 11. MongoDB indexes for Phase II

### `pull_count_desc`

```javascript
db.repositories_data.createIndex(
  { pull_count: -1 },
  { name: "pull_count_desc" }
)
```

Used by `ClaimNextBuildRepo` to order repositories by popularity and apply the threshold filter. Also covers `CountPendingBuildRepos`.

### `stage2_partial`

```javascript
db.repositories_data.createIndex(
  { pull_count: -1 },
  {
    name: "stage2_partial",
    partialFilterExpression: { graph_built_at: null }
  }
)
```

A partial index that covers only documents where `graph_built_at` is `null` (absent or explicitly null). Once `graph_built_at` is set on a document, that document **leaves the index** automatically. This makes the index shrink progressively as Phase II advances, keeping queries fast even with 12M documents.

**Why `null` and not `{$exists: false}`?** MongoDB does not support `$not` in `partialFilterExpression`. The expression `{graph_built_at: null}` in MongoDB matches documents where the field is absent **or** explicitly `null` — the desired behavior.

---

## 12. Authentication, rate limiting, and jitter

### Identity rotation

`HubClient` encapsulates automatic JWT rotation. On each request, the headers include:

- `Authorization: JWT <token>` (if authenticated)
- `User-Agent`, `Sec-Ch-Ua`, `Referer`, etc. — a real Chrome browser fingerprint
- `Accept-Language: <browser locale string>` — consistent with the account's locale

In response to HTTP errors:

| Code | Action |
|--------|------|
| 401    | Invalidates the current token (`ClearToken`), rotates to the next identity |
| 429    | Waits 15s, then rotates |
| 403    | Rotates identity immediately |
| others | Returns to the caller without retry (e.g. 404 = tag does not exist) |

Up to 3 attempts per URL before returning an error.

### Anti-fingerprint jitter

```go
// HubClient.Get — before each API call (tags, latest tag, images)
time.Sleep(time.Duration(200+rand.Intn(200)) * time.Millisecond)  // 200–400ms, mean 300ms
```

The jitter is applied **before each HTTP call**, not only between repositories. With ~3 calls per repo (GetTags + GetTag("latest") + GetImages), the total delay per repo is 600–1200ms in jitter alone.

The 200–400ms range was calibrated to evade the Cloudflare tarpit without excessive overhead: values below 200ms increase the rate of 429/captcha responses; above 600ms they waste throughput without a proportional gain in evasion.

---

## 13. Multi-node operation

Multiple machines can run Phase II simultaneously against the same MongoDB and Neo4j. The mutual-exclusion mechanism is `ClaimNextBuildRepo` — atomic in MongoDB.

**Typical configuration (3 machines):**

| Machine | Role | Compose file |
|---------|-------|--------------|
| host1    | Phase I (crawler) | `docker-compose.yml` |
| worker-a      | Phase I (crawler) | `docker-compose.yml` |
| host2    | Phase II (builder) | `docker-compose.node3.yml` |

The machine running Phase II needs network access to the primary machine's MongoDB and Neo4j:

```env
MONGO_URI=mongodb://<PRIMARY_IP>:27017
NEO4J_URI=neo4j://<PRIMARY_IP>:7687
```

To add a second machine to Phase II, just run `make start-build` with the environment variables pointing at the primary machine. The `accounts_builder.json` accounts on each machine must be different to maximize parallelism without token conflicts.

---

## 14. Useful Cypher queries

### Find images that expose a specific port

```cypher
MATCH (l:Layer)
WHERE l.instruction STARTS WITH 'EXPOSE 80'
  AND size(l.images) > 0
RETURN l.images
```

To find **any** layer with EXPOSE (not necessarily the last):

```cypher
MATCH (exposed:Layer)
WHERE exposed.instruction STARTS WITH 'EXPOSE'
WITH exposed
MATCH (exposed)-[:IS_BASE_OF*0..]->(leaf:Layer)
WHERE size(leaf.images) > 0
RETURN DISTINCT exposed.instruction AS port, leaf.images AS images
LIMIT 100
```

### Find images that share a base layer

```cypher
MATCH (base:RawLayer {digest: "sha256:abc123..."})
-[:IS_SAME_AS]-(l:Layer)
-[:IS_BASE_OF*]->(leaf:Layer)
WHERE size(leaf.images) > 0
RETURN DISTINCT leaf.images
```

### Find an image's build chain

```cypher
MATCH path = (root:Layer)-[:IS_BASE_OF*]->(leaf:Layer)
WHERE size(leaf.images) > 0
  AND ANY(img IN leaf.images WHERE img CONTAINS 'library/nginx:latest')
  AND NOT EXISTS { MATCH (x:Layer)-[:IS_BASE_OF]->(root) }
RETURN path
```

### Count nodes and relationships

```cypher
MATCH (l:Layer) RETURN count(l) AS total_layers
MATCH (rl:RawLayer) RETURN count(rl) AS total_rawlayers
MATCH ()-[r:IS_BASE_OF]->() RETURN count(r) AS total_edges
```
