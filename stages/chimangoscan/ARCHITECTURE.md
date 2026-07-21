# Technical Architecture — ChimangoScan Research Fork

**Scientific basis:** Hequan Shi et al., "Dr. Docker: A Large-Scale Security Measurement of Docker Image Ecosystem", WWW '25.

---

## 1. Pipeline Overview

The original upstream (the upstream DITector framework, Dr. Docker) is written entirely in Go and implements stages II and III (layer graph construction and ranking). Stage I was declared as the `crawl` subcommand in `cmd/cmd.go` — with the description "crawl metadata of repositories and images from Docker Hub" — but with no `Run` field: the command was registered without an implementation. This version implements the complete body of Stage I and re-engineers Stage II for large-scale parallel operation.

```
┌─────────────────────────────────────────────────────────────────┐
│                 ChimangoScan Research Pipeline                  │
├──────────────┬──────────────────────┬───────────────────────────┤
│  Stage I     │    Stage II          │       Stage III           │
│  CRAWL       │    BUILD             │       RANK                │
│  (new)       │    (re-engineered)   │       (upstream + fixes)  │
├──────────────┼──────────────────────┼───────────────────────────┤
│ crawler/     │ buildgraph/          │ scripts/                  │
│   crawler.go │   from_mongo.go      │   calculate_node_         │
│   auth_      │ myutils/neo4j.go     │   dependent_weights.go    │
│   proxy.go   │   (rewritten)        │                           │
└──────────────┴──────────────────────┴───────────────────────────┘
         │               │                        │
         ▼               ▼                        ▼
      MongoDB          Neo4j              final_prioritized_
  (repositories_    (layer graph:           dataset.json
      data)          Layer nodes +          (JSONL)
                     IS_BASE_OF edges)
```

---

## 2. Stage I — Crawler with a Persistent Task Queue

### 2.1. Docker Hub API Constraints

The search API (`GET /v2/search/repositories/`) imposes the following relevant constraints:

- **Per-query limit:** 10,000 results maximum, regardless of the real cardinality of the matching repositories.
- **Pagination:** maximum 100 results per page (up to 100 pages per keyword).
- **ElasticSearch stopwords:** single-character queries are treated as stopwords by the Docker Hub search engine, returning artificially low counts. The strategy of unconditionally deepening single-character prefixes works around this limitation.
- **Rate limiting and bot detection:** HTTP 429 for high-frequency IPs; HTTP 403 for sessions identified as automated traffic by the WAF/Cloudflare.

Docker Hub contains more than 12 million public repositories. The combination of the 10,000-result limit per query with the absence of an exhaustive public listing makes the DFS-over-prefixes strategy necessary.

### 2.2. MongoDB Task Queue Architecture

Stage I abandons in-memory recursion in favor of a **physical task queue** in the `crawler_keywords` collection. Each document represents a DFS prefix with a `status` field (`pending`, `processing`, `done`).

**Task processing algorithm** (`processTask`):

```
processTask(prefix):
  res = fetchPage(prefix, page=1)
  if res == nil: updateTaskStatus(prefix, "pending"); return failure

  newInPrefix = processResults(res.Repositories)
  collect remaining pages [2 .. min(ceil(res.count/100), 100)]

  if res.count >= 10,000 OR len(prefix) == 1:
    tokenPlateau = (newInPrefix == 0 && res.count >= 10000
                    && strings.Contains(prefix, "-") && len(prefix) > 1)
    lastChar = prefix[-1]
    isSep = (lastChar == '-' || lastChar == '_')

    for char in [a-z, 0-9, -, _]:
      if isSep && (char == '-' || char == '_'): skip   // separator deduplication
      child = prefix + char
      priority = calcPriority(child, newInPrefix, tokenPlateau)
      UPSERT {_id: child, status: "pending", priority: priority} IF NOT EXISTS

  updateTaskStatus(prefix, "done")

calcPriority(child, newInPrefix, tokenPlateau):
  if tokenPlateau:             return -1  // plateau: deprioritized, but not lost
  if !contains(child, "-"):    return 2   // no hyphen = genuine substring
  if newInPrefix > 0:          return 1   // parent found new repos
  return 0                                // default
```

**Worker life cycle** (`worker`):

```
worker(id):
  emptyCount = 0
  loop:
    prefix = getNextTask()    // FindOneAndUpdate: pending → processing
    if prefix == "":
      emptyCount++
      if emptyCount % 6 == 0:
        if CountDocuments({status: "pending"}) == 0: break   // queue confirmed empty
      sleep 5s; continue

    emptyCount = 0
    success = processTask(prefix, ...)
    if !success: sleep 5s     // backoff before trying the next task
    sleep rand(0..1000ms)     // anti-fingerprint jitter
```

**Queue initialization** (`ensureQueueInitialized`):

```
ensureQueueInitialized(seeds):
  // 1. Self-healing: resets tasks stuck in "processing" from a previous crash
  UPDATE {status: "processing"} → {status: "pending"}

  // 2. If the queue already has tasks (count > 0), resume from where it stopped
  if count > 0: return

  // 3. Empty queue: insert the alphabet seeds as pending
  for s in seeds: UPSERT {_id: s, status: "pending"} IF NOT EXISTS
```

**Architecture properties:**

- **Atomicity:** `getNextTask` uses `FindOneAndUpdate` with the filter `{status: "pending"}` and ordering `{priority: -1, _id: 1}`. Multiple workers (including those on different cluster nodes) never process the same prefix simultaneously — mutual exclusion is guaranteed by MongoDB.
- **Crash resumability:** on restart, all tasks in the `processing` state are reverted to `pending` automatically. Only `done` tasks are permanently skipped.
- **Dynamic prioritization:** `getNextTask` orders by `{priority: -1, _id: 1}`. Prefixes more likely to return new repositories are processed first. Workers never terminate prematurely: they stop only when `CountDocuments({status: "pending"}) == 0` confirms the queue is genuinely empty.

### 2.3. DFS Queue Prioritization and Token-Match Plateau

The `priority int` field in each `crawler_keywords` document controls the processing order. The table below defines the values and their semantics:

| Value | Assignment condition | Semantics |
|-------|------------------------|-----------|
| `2` | Child with no hyphen (`!strings.Contains(child, "-")`) | Genuine substring match in ElasticSearch (no tokenization). High probability of distinct repositories. |
| `1` | Parent found new repositories (`newInPrefix > 0`) | Productive deepening — the region has data. |
| `0` | Default | Parent found no new repositories, but it is not a plateau. |
| `-1` | Token-match plateau | Plateau detected: prefix with a hyphen, ≥ 10,000 results, zero new. Deprioritized but preserved. |

**Token-match plateau:** Docker Hub indexes image names with ElasticSearch using the hyphen as a token separator. The query `tcp-client` matches the whole `tcp-client` token — and all repositories that contain that exact token as a substring have already been collected. Expanding `tcp-client-a`, `tcp-client-b`, etc. returns the same 10,000 results with zero novelty. Instead of pruning these children (which would cause data loss in legitimately dense regions), they are inserted with `priority=-1` and left to the end of the queue, after all higher-return regions.

**Consecutive-separator deduplication:** if the prefix ends in `-` or `_`, the `-` and `_` children are omitted when generating the expansion. Docker Hub treats `--`, `-_`, `_-`, `__` as equivalent to a single separator; generating these children would cause unbounded recursion with no new data.

### 2.4. RAM Cache Warming

Before starting the DFS, `PreloadExistingRepos` loads all repository names already present in MongoDB into the `seenRepos sync.Map` in RAM:

```
PreloadExistingRepos():
  cursor = Find(RepoColl, {}, projection={namespace, name})
  for doc in cursor:
    seenRepos.Store(doc.namespace + "/" + doc.name, true)
```

**Motivation:** secondary cluster nodes connect to the primary node's MongoDB over the network. Without the cache, every discovered repository would be checked against the remote database — saturating the bandwidth with duplicates. With the RAM cache, deduplication happens locally in microseconds.

**Scale:** 5.2 million records occupy approximately 300 MB of RAM. The system supports up to 100 million records with a footprint below 6 GB, within the limits of typical research servers.

### 2.5. Anti-Detection Strategy — Threat Model and Countermeasures

Docker Hub operates behind Cloudflare with multi-layered behavioral inspection. The system implements a corresponding defense stack, with one countermeasure per detection vector.

#### 2.5.1. Vector: TLS Fingerprint (JA3)

**Threat:** Go's default `net/http` stack negotiates TLS ciphers in a different order from any real browser. The resulting JA3 hash is instantly identifiable as an automated script, regardless of the declared User-Agent.

**Countermeasure:** the `http.Transport` is configured to emulate Chrome 121:

```go
&tls.Config{
    MinVersion:               tls.VersionTLS12,
    PreferServerCipherSuites: false, // let the server order the ciphers
}
```

HTTP/2 is deliberately disabled. Beyond the fingerprint difference, HTTP/2 multiplexing creates an additional vector: when the server applies a tarpit (section 6.1), half-open connections block workers indefinitely. With HTTP/1.1, each connection is atomic — timeouts work deterministically.

#### 2.5.2. Vector: Anomalous Headers

**Threat:** Go requests with no explicit configuration omit headers present in every real browser (`Sec-Fetch-*`, `Referer`, `Accept-Language`). The absence of these fields is a low-fidelity signal in the WAF's scoring.

**Countermeasure:** `HubClient.setHeaders` (in `myutils/hubclient.go`) injects the complete header set of a Chrome 145 XHR request to the Docker Hub API. The function was centralized here from `crawler/crawler.go` (where it existed as `setBrowserHeaders`), eliminating the duplication between Stages I and II:

```go
req.Header.Set("Accept",          "application/json, text/plain, */*")
req.Header.Set("Accept-Language", "<browser locale string>")
req.Header.Set("Referer",         "https://hub.docker.com/")
req.Header.Set("Sec-Ch-Ua-Mobile","?0")
req.Header.Set("Sec-Fetch-Dest",  "empty")
req.Header.Set("Sec-Fetch-Mode",  "cors")
req.Header.Set("Sec-Fetch-Site",  "same-origin")
req.Header.Set("Connection",      "keep-alive")
```

The `Referer` (`https://hub.docker.com/`) and the `Sec-Fetch-*` fields reconstruct the browsing context expected of a user on the Docker Hub main interface. The `Accept-Language` value reflects a plausible browser-session locale, completing the impression of a real interactive session.

#### 2.5.3. Vector: Cross-Request Identity Correlation

**Threat:** a stateful WAF can correlate multiple accounts coming from the same IP with the same User-Agent. If account A and account B never coexist in the traffic of a real browser with the same UA, the combination is detectable.

**Countermeasure:** persistent per-account identity (Sticky UA). At load time, each account is assigned a fixed, exclusive User-Agent via round-robin over the pool of 7 strings:

```
Chrome 121 / Windows
Chrome 121 / Mac
Chrome 121 / Linux
Edge 121   / Windows
Firefox 122 / Windows
Safari 17  / Mac
Chrome 119 / Windows (slightly outdated version)
```

The same account always uses the same UA on every request — login, search, manifests. From the server's perspective, each account is a distinct, coherent "browser". Differentiating between nodes (Node 1 emulates Windows, Node 2 emulates Linux/Mac) dilutes the statistical correlation at the cluster level.

#### 2.5.4. Vector: Socket-Opening Pattern

**Threat:** bots with no connection control open a new TCP socket per request. The rate of TLS handshakes per IP (observable by the server) is a strong bot signal, independent of the headers.

**Countermeasure (a):** active connection pool. `DisableKeepAlives` was removed from the upstream `http.Transport`. `MaxIdleConns=100`, `IdleConnTimeout=90s` keep sockets open between requests from the same worker.

**Countermeasure (b):** body draining. In Go, a socket is returned to the pool only if the response body is read to the end before `Close`. `fetchPage` uses `io.ReadAll(resp.Body)` rather than calling `resp.Body.Close()` directly — ensuring each socket is reused on the same worker's next request.

#### 2.5.5. Vector: Rhythmic Temporal Pattern

**Threat:** fixed intervals between requests are statistically unlikely for human browsing and detectable by frequency analysis.

**Countermeasure:** two levels of random jitter:
- **Per API call** (`HubClient.Get`): `200 + rand.Intn(200)` ms → uniform interval in [200, 400] ms, mean 300ms. Applied before each GET to Docker Hub, regardless of the stage.
- **Between consecutive worker tasks** (Stage I crawler): `rand.Intn(1000)` ms → [0, 1000] ms

---

### 2.6. HTTP Error Handling — Re-enqueue Semantics

With the introduction of `HubClient` (section 2.7), the retry and identity-rotation logic was moved into the shared client. `fetchPage` in `crawler/crawler.go` delegates the entire HTTP attempt to `HubClient.Get`, which performs up to 3 attempts with automatic rotation. The only Stage-I-specific behavior that remains in `fetchPage` is the 4-minute cooloff for non-retriable HTTP errors (unexpected responses outside the 401/429/403 set).

```
// Inside HubClient.Get (myutils/hubclient.go):
Get(url):
  for attempts in [0, 3):
    setHeaders(req)
    resp = client.Do(req)
    io.ReadAll(resp.Body)  // mandatory body draining

    401 → rotate() → continue
    429 → rotate() → continue
    403 → rotate() → continue
    200 → return body, 200, nil
    other → return nil, status, err

// Inside fetchPage (crawler/crawler.go — Stage I-specific):
fetchPage(hub, query, page):
  body, status, err = hub.Get(url)
  if err != nil:
    sleep 4 min  // cooloff for non-retriable errors
    return nil, false
  json.Unmarshal(body); return response, true
```

**401 — expired JWT:** `rotate()` calls `ClearToken` on the `IdentityProvider`, clearing the `Token` field of the corresponding account. On the next call to `GetNextClient`, the account triggers `LoginDockerHub` automatically.

**403 — high bot score:** indicates an IP or account with a high bot score in Cloudflare's scoring. Identity rotation happens immediately inside `HubClient`; the 4-minute cooloff at the `fetchPage` level (Stage I) lets the IP "cool down" before the next task.

**429 — rate limit:** request rate exceeded for the account or IP. `HubClient` rotates to the next available identity, distributing the pressure across accounts.

A task is never lost: on any failure that results in `nil` returned from `fetchPage`, `processTask` calls `updateTaskStatus(prefix, "pending")` before returning.

### 2.7. Identity Management — `crawler/auth_proxy.go`

`IdentityManager` centralizes authentication, proxies, and User-Agents:

- Loads accounts from `accounts.json` (`[{username, password}]`)
- Assigns an exclusive `UserAgent` to each account at load time (round-robin over `globalUAPool`)
- JWT auto-login via `POST /v2/users/login/` guarded by `loginMu sync.Mutex` (prevents parallel login of the same account)
- `GetNextClient()` returns `(*http.Client, token, ua)` — the UA is propagated alongside the client and token to ensure the identity is consistent throughout a task's session

`ClearToken(token)` walks the accounts and clears the token of the corresponding account, forcing re-authentication on the next call to `GetNextClient`.

`IdentityManager` implements the `IdentityProvider` interface (section 2.7), which lets the same `HubClient` be used by both Stage I and Stage II without a circular dependency between packages. The dependency flows only from `myutils` (which defines `IdentityProvider`) to `crawler` and `buildgraph` (which implement and consume the interface), and never the other way around.

### 2.8. HubClient — Shared Authenticated HTTP Client

`HubClient` (in `myutils/hubclient.go`) is the central abstraction that eliminates the duplication of authenticated-request logic between Stages I and II.

#### IdentityProvider interface

```go
type IdentityProvider interface {
    GetNextClient() (*http.Client, string, string) // client, token, userAgent
    ClearToken(token string)
}
```

The interface is the decoupling point between `myutils` (which defines `HubClient`) and `crawler` (which implements `IdentityManager`). Any struct that implements these two methods can be used as an identity source for a `HubClient`, allowing substitution in tests or future extension to other authentication providers.

#### HubClient life cycle

The usage pattern is **one instance per goroutine**. In Stage I, each `worker()` calls `myutils.NewHubClient(pc.IM)` at the start of its loop. In Stage II, each `repoWorker` does the same. Instances are not shared between goroutines; the internal state (active HTTP client, current token) is exclusive to each instance, eliminating the need for additional synchronization.

```
HubClient.Get(url):
  for attempts in [0, 3):
    req = buildRequest(url)
    setHeaders(req)             // Chrome 145 headers
    resp = client.Do(req)
    body = io.ReadAll(resp.Body)

    401/429/403 → rotate()     // switch identity; next attempt
    200         → return body, nil
    other       → return nil, err  // non-retriable failure
```

#### High-level methods

| Method | Description |
|--------|-----------|
| `Get(url)` | GET request with 3 attempts and rotation on 401/429/403 |
| `GetInto(url, dest)` | `Get` + `json.Unmarshal` into the provided destination |
| `GetTags(ns, name, pageNum, size)` | Paginated tag fetch for a repository |
| `GetTag(ns, name, tagName)` | Fetch metadata for a specific tag by name; returns `nil, nil` on 404 |
| `GetImages(ns, name, tag)` | Fetch image manifests for a specific tag |

#### Duplication elimination

Before this version, `crawler/crawler.go` and `buildgraph/from_mongo.go` maintained parallel and divergent logic for: header injection, retry on HTTP errors, identity rotation, and body draining. `HubClient` centralizes all of these responsibilities, reducing the maintenance surface and guaranteeing identical behavior across stages.

### 2.9. Monitoring and Telemetry

A separate goroutine logs the queue state every 30 seconds:

```go
go func() {
    for {
        active, _ := KeywordsColl.CountDocuments({status: "pending"})
        Logger.Info(fmt.Sprintf("--- STATS: %d workers active | %d tasks left | Uptime: %v",
            pending, active, time.Since(startTime)))
        time.Sleep(30 * time.Second)
    }
}()
```

`processTask` also logs an **efficiency metric** per prefix: the ratio of new repositories to the total downloaded from the page. Prefixes with low efficiency indicate regions of the DFS space that are already saturated.

### 2.10. Multi-Node Distribution

The `crawl` command supports two partitioning modes:

| Mode | Flags | Behavior |
|------|-------|--------------|
| Automatic shard | `--shard N --shards M` | Splits the alphabet equally across M shards; shard N processes the corresponding fraction. Implemented in `crawler.ShardSeeds(shard, total)` |
| Manual seeds | `--seed a,b,c` | Explicit comma-separated seeds |
| Full alphabet | (no flag) | Seeds the entire alphabet `[a-z, 0-9, -, _]` |

Because the task queue resides in the shared MongoDB, both nodes interact with the same `crawler_keywords` collection. The atomic `FindOneAndUpdate` guarantees that each prefix is processed by exactly one node.

### 2.11. Empirical Results (Production)

Configuration: Node 1 (shard 0/2, 3 workers) + Node 2 (shard 1/2, 4 workers), 7 Docker Hub accounts, MongoDB on Node 1, remote connection Node 2 → Node 1.

| Metric | Value |
|---------|-------|
| Unique repositories accumulated | >2,100,000 |
| Sustained throughput post-optimization | ~10,000–18,000 unique repos/minute |
| Duplicates in the database | 0 (unique MongoDB index `{namespace, name}`) |

---

## 3. Stage II — BuildGraph

### 3.1. Distributed Queue Architecture with Atomic Claim

Stage II was redesigned with the same persistent-queue pattern as Stage I: instead of a centralized MongoDB cursor (vulnerable to partitions and restarts), each worker goroutine atomically claims the next available repository via `ClaimNextBuildRepo`.

**Claim operation (atomic FindOneAndUpdate):**

```
ClaimNextBuildRepo(threshold):
  filter = {
    pull_count:    {$gte: threshold},
    graph_built_at: {$exists: false},
    build_claimed:  {$ne: true}
  }
  update = {
    $set: {build_claimed: true, build_started_at: now()}
  }
  sort = {pull_count: -1}   // more popular repositories take priority
  return collection.FindOneAndUpdate(filter, update, {sort: sort})
```

MongoDB's atomic `FindOneAndUpdate` guarantees mutual exclusion: two workers (on distinct goroutines or distinct machines) never process the same repository simultaneously.

**Initialization and self-healing (ResetStaleBuildClaims):**

At Stage II startup, before starting any worker, `ResetStaleBuildClaims` releases orphaned claims from previous executions that were interrupted without completing:

```
ResetStaleBuildClaims():
  filter = {build_claimed: true, graph_built_at: {$exists: false}}
  update = {$unset: {build_claimed: "", build_started_at: ""}}
  UpdateMany(filter, update)
```

This operation ensures Stage II resumes from where it stopped without reprocessing or skipping repositories after any kind of interruption — crash, OOM, container restart.

**Immortal worker — CountPendingBuildRepos:**

After `ClaimNextBuildRepo` returns "not found", the worker does not terminate immediately. Before stopping, it checks with `CountPendingBuildRepos(threshold)` whether there are genuinely pending repositories:

```
CountPendingBuildRepos(threshold):
  filter = {
    pull_count:    {$gte: threshold},
    graph_built_at: {$exists: false},
    build_claimed:  {$ne: true}
  }
  return collection.CountDocuments(filter)
```

The worker terminates only when the count returns zero. This avoids premature termination when all available repositories are temporarily claimed by other workers.

**Multi-node distribution:** multiple machines can run Stage II simultaneously pointing at the same MongoDB. The atomic claim guarantees that each repository is processed by exactly one machine. No additional coordination between nodes is needed.

### 3.2. Worker Pipeline

```
ClaimNextBuildRepo (per goroutine)
    │
    ▼ repoWorker × len(accounts)          [I/O bound — HTTPS wait]
    │   1. getTags: fetch most recent tag (page 1) + "latest" tag via GetTag;
    │      dedup if they coincide (MongoDB cache + API fallback)
    │   2. getImages: fetch manifests per tag (MongoDB cache + API fallback)
    │   3. discard Windows images
    │   4. defer markBuilt → MarkRepoGraphBuilt always executed
    │
jobChan (buffer)
    │
    ▼ graphWorker × max(NumCPU × 2, 8)   [DB bound — Bolt/TCP → Neo4j]
    │   1. SHA256 chain of IDs (local, CPU)
    │   2. InsertImageToNeo4j (single transaction per image)
    │   3. m.Neo4jInserts++ (atomic counter)
    │
Neo4j (Layer nodes + IS_BASE_OF edges + IS_SAME_AS → RawLayer nodes)

checkpointWriter (single goroutine)
    │
    ▼ dataDir/build_checkpoint.jsonl   [append-only, single-writer]
```

**Worker sizing:**
- `repoWorkers`: `len(accounts)` — one worker per Docker Hub account. Each worker generates ~1.8 req/s; the total request rate scales linearly with the number of accounts, mirroring the Stage I pattern and avoiding per-IP saturation.
- `graphWorkers`: `max(NumCPU × 2, 8)` — Neo4j writes over Bolt are the bottleneck; an excess of simultaneous connections degrades throughput. The factor of 2 balances parallelism with stability.

### 3.3. Authentication and Headers (HubClient)

Stage II uses `HubClient` (section 2.7) with the same pattern as Stage I: one instance per `repoWorker` goroutine, created via `myutils.NewHubClient(ip)` where `ip` is the `IdentityProvider` passed by `buildgraph.Build`.

```go
func repoWorker(ip myutils.IdentityProvider, ...) {
    hub := myutils.NewHubClient(ip)
    for {
        repo := ClaimNextBuildRepo(threshold)
        if repo == nil { break }
        processRepo(hub, repo, ...)
    }
}
```

**MongoDB cache for tags and images:** before calling the API, `getTags` and `getImages` query the corresponding MongoDB collection. The cache hit rate (recorded in `BuildMetrics`) typically exceeds 80% after Stage I, since many repositories already had their tags and images stored. The API fallback only happens when the cache does not contain the data.

**JWT rotation on 401/429/403:** inherited from `HubClient.Get` — behavior identical to Stage I, with no duplicated code.

### 3.4. Metrics and Time Estimation (BuildMetrics)

`BuildMetrics` (in `buildgraph/metrics.go`) tracks Stage II progress with atomic counters, guaranteeing safe reads and writes from multiple goroutines:

| Counter | Description |
|----------|-----------|
| `Processed` | Completed repositories (regardless of success or error) |
| `TagCacheHits` | Tag fetches satisfied by the MongoDB cache |
| `TagAPIFetches` | Tag fetches that fell back to the Docker Hub API |
| `ImageCacheHits` | Image fetches satisfied by the MongoDB cache |
| `ImageAPIFetches` | Image fetches that fell back to the Docker Hub API |
| `Neo4jInserts` | Successful insertions into Neo4j |
| `Errors` | Fatal errors during repository processing |

`startReporter(dataDir, done)` runs in a dedicated goroutine, recording metrics to the log and to `dataDir/build_metrics.log` every 60 seconds:

```
[METRICS 02:15:00] progress=1234/48000 (2.6%) | rate=45.2 repos/min | ETA=17h22m | cache tags=82% imgs=71% | neo4j=12340 | errors=3 | uptime=27m18s
```

The ETA is computed after the first 30 seconds of accumulated data:

```
rate = processed / elapsed_minutes
ETA  = (total - processed) / rate
```

Before 30 seconds, the ETA field shows "calculating..." to avoid unstable estimates during the warm-up phase.

### 3.5. Persistence on Physical Disk

The previous version of `docker-compose.yml` used a named Docker volume (`neo4j_data:/data`) for Neo4j. Named volumes are managed by the Docker Engine and can be destroyed by `docker system prune -a --volumes`, which is a routine cleanup command on shared servers. The Neo4j graph represents weeks of Stage II processing — losing it would be catastrophic.

**Change:** the Neo4j volume was migrated to an explicit host path:

```yaml
# docker-compose.yml — before
volumes:
  - neo4j_data:/data

volumes:  # root section
  neo4j_data:

# docker-compose.yml — after
volumes:
  - ./neo4j_data:/data
# (no root volumes section — there are no named volumes)
```

MongoDB already used `./mongo_data_secure:/data/db` (host path) since version 2.0.0. Now both databases are at explicit paths on the host filesystem, immune to Docker cleanup commands.

**Stage II checkpoint:** the `checkpointWriter` goroutine persists one JSONL line per processed repository to `dataDir/build_checkpoint.jsonl`. The single-writer pattern eliminates the need for a mutex when writing the file.

### 3.6. Layer-ID hashing (Dr. Docker IDEA) and Neo4j Insertion

#### 3.6.1. Layer ID Hashing

The algorithm defined in the Dr. Docker paper (Section 3.2) is implemented in `myutils/neo4j.go`, function `InsertImageToNeo4j`:

**Content layer** (has the SHA256 digest of the tar file):
```
dig_i      = SHA256(layer_i.digest)
Layer_i.id = SHA256(Layer_{i-1}.id || dig_i)
```

**Config layer** (Dockerfile instruction with no physical content, e.g. `ENV`, `CMD`):
```
dig_i      = SHA256(layer_i.instruction)
Layer_i.id = SHA256(Layer_{i-1}.id || dig_i)
```

**Bottom layer** (i=0): uses `preID = ""` as the value preceding the concatenation.

**Fundamental property:** two images that share the same first N layers in the same order produce identical `Layer_N.id`. Inheritance relations are identifiable by ID equality, with no analysis of the layers' content.

#### 3.6.2. Single Transaction per Image in Neo4j

The original upstream implementation ran a separate Neo4j transaction per layer (O(N) round-trips per image). The fork rewrites `InsertImageToNeo4j`:

```
// Phase 1 — local, no network I/O:
records = []layerRecord{}
preID = ""
for each layer_i in image.Layers:
    dig_i  = SHA256(layer_i.digest or layer_i.instruction)
    currID = SHA256(preID + dig_i)
    records.append({prevID: preID, currID: currID, layer: layer_i})
    preID = currID

// Phase 2 — a single transaction:
session.ExecuteWrite(func(tx):
    for each record in records:
        tx.Run(MERGE (l:Layer {id: record.currID}) ...)
        tx.Run(MERGE (l)-[:IS_BASE_OF]->(next) ...)
        tx.Run(MERGE (rl:RawLayer {digest: ...})-[:IS_SAME_AS]-(l) ...)
    tx.Run(SET last_layer.images += [imgName])
)
```

**Network complexity:**
- Previous (upstream): O(N) round-trips per image, N ∈ [5, 30] typically
- Current: O(1) round-trips per image, regardless of N

With a typical Bolt/TCP latency of ~5–10ms per round-trip, an image with 20 layers goes from ~100–200ms to ~5–10ms of insertion network cost.

#### 3.6.3. Neo4j Graph Structure

| Type | Properties | Semantics |
|------|-------------|-----------|
| `Layer` | `id` (SHA256 chain), `digest`, `images[]`, `size`, `instruction` | Position in the inheritance chain |
| `RawLayer` | `digest` | Physical content of the layer |
| `[:IS_BASE_OF]` | — | Predecessor Layer → successor Layer |
| `[:IS_SAME_AS]` | — | Layer ↔ RawLayer (position to content) |

All insertions use `MERGE` (not `CREATE`), guaranteeing idempotency.

---

## 4. Cross-Cutting Changes to the Upstream

### 4.1. `myutils/mongo.go`

| Addition | Description |
|--------|-----------|
| `BulkUpsertRepositories(repos)` | Unordered bulk write; ~10–50× faster than individual upserts for processing a page of results |
| `KeywordsColl` | `crawler_keywords` collection for the Stage I task queue. Each document: `{_id: prefix, status: pending|processing|done, started_at, finished_at}` |
| `MarkRepoGraphBuilt(ns, name)` | Writes `graph_built_at` on the repository and removes `build_claimed` and `build_started_at` (Stage II checkpoint) |
| `ClaimNextBuildRepo(threshold)` | Atomic `FindOneAndUpdate` to claim a repository in Stage II; sets `{build_claimed: true, build_started_at: now}` |
| `ResetStaleBuildClaims()` | At Stage II startup, releases orphaned claims: `{build_claimed: true, graph_built_at: {$exists: false}}` → `$unset build_claimed, build_started_at` |
| `CountPendingBuildRepos(threshold)` | Count of unclaimed repositories without `graph_built_at`; used by the immortal worker pattern |
| `FindImagesByDigests(digests)` | Batched query with `$in`; replaces N individual calls to `FindImageByDigest` — eliminates the N+1 pattern in Stage II |
| Connection pool | `MaxPoolSize=100`, `MinPoolSize=5`, `MaxConnIdleTime=5min` |
| Initial ping timeout | `1s → 30s` (avoids a false negative on slow connections) |

### 4.2. `myutils/docker_hub_api_requests.go`

| Parameter | Before | After | Rationale |
|-----------|-------|--------|---------------|
| `DisableKeepAlives` | `true` | removed (false) | Reuse of TCP/TLS connections; saves ~100–300ms per request |
| `MaxIdleConns` | — | 300 | Connection pool for high concurrency |
| `MaxIdleConnsPerHost` | — | 50 | Limits idle connections per host |
| `IdleConnTimeout` | — | 90s | Discards idle connections |
| `Timeout` | — | 30s | Global per-request timeout |

### 4.3. `myutils/config.go`

| Change | Description |
|-------------|-----------|
| `MONGO_URI` / `NEO4J_URI` env vars | Override `config.yaml` — lets remote nodes point at the central database without changing the local configuration |
| `os.Getwd()` instead of `filepath.Dir(os.Args[0])` | Config looked up relative to the CWD (compatible with `go run` and compiled binaries) |
| Optional Neo4j at startup | A Neo4j connection failure does not abort the process — useful for Stage I without an active Neo4j |

### 4.4. `myutils/neo4j.go` — Critical Bug Fix

**`findLayerNodesByRawLayerDigestFunc`:** the original Cypher query used `{id: $digest}` to match a `RawLayer` node, but `RawLayer` nodes are created with the `digest` property. The `id` property does not exist on `RawLayer`. The query never returned results, silently breaking all upstream-image-tracking functionality.

```cypher
-- Before (upstream, incorrect):
MATCH (l:Layer)-[:IS_SAME_AS]-(rl:RawLayer {id: $digest})

-- After (correct):
MATCH (l:Layer)-[:IS_SAME_AS]-(rl:RawLayer {digest: $digest})
```

### 4.5. `myutils/urls.go`

`V2SearchURLTemplate` and `GetV2SearchURL` provide the canonical URL for the Docker Hub V2 search API:

```go
V2SearchURLTemplate = `https://hub.docker.com/v2/search/repositories/?query=%s&page=%d&page_size=%d`
```

The `&ordering=-pull_count` parameter was removed in this version. The removal is motivated by the semantic difference between the two API ordering modes:

- **`ordering=-pull_count`** (previous): orders results by decreasing pull count within the set of documents that match the query token. This means short, ambiguous queries (such as `"a"`) return popular repositories, but not necessarily those whose name starts with `"a"` — ElasticSearch includes any document where `"a"` appears as a token in any field.
- **`best_match`** (the API default, current behavior): prioritizes exact prefix matches before partial matches. For the prefix DFS, this means `query="ngin"` returns `nginx` before `some-image-with-nginx-in-description`, maximizing the relevance of the results collected at each node of the DFS tree.

Removing the `ordering` parameter does not reduce the determinism of the collection, because deduplication is guaranteed by the unique MongoDB index on `{namespace, name}`, not by the arrival order of the results.

### 4.6. `scripts/calculate_node_dependent_weights.go` — Bug Fix

The `if repoDoc.Namespace == "library"` branch had `continue` as its first statement, making all subsequent code (`FindAllTagsByRepoName`, etc.) unreachable. Official Docker images (the `library` namespace) were silently skipped in the dependency-weight computation.

Fix: `continue` removed. `library` images now go through the same processing as community images.

---

## 5. Known Limitations

1. **JWT expiry:** Docker Hub tokens expire in ~24h. Expiry is handled automatically via `ClearToken` + `GetNextClient`, which triggers a new `LoginDockerHub`. Container restarts also renew all tokens.

2. **Build with the live API:** if a repository is deleted between Stage I and Stage II, errors are logged but do not interrupt processing. The use of `defer markBuilt` in `processRepo` ensures the repository is marked as complete even on API errors, avoiding infinite reprocessing.

3. **Search-space coverage:** the DFS over `[a-z0-9-_]` prefixes does not guarantee coverage of repositories with names composed exclusively of other characters (e.g. Unicode). Practical coverage for descriptive naming is high, but has not been formally quantified.

4. **Neo4j throughput:** one transaction per image (O(1) round-trips). For volumes >1M images, the bottleneck shifts to the Neo4j heap memory — increasing `NEO4J_dbms_memory_heap_max__size` is recommended.

5. **Re-crawl after completion:** when all Stage I tasks reach the `done` state, the queue is not re-initialized automatically. To start a new collection cycle — for example, to capture repositories created after the previous cycle — you must reset the `status` field to `pending` via a MongoDB update or clear the `crawler_keywords` collection. Likewise, a Stage II re-run requires removing the `graph_built_at` fields from the documents to be reprocessed.

---

## 6. Network Resilience and Large-Scale Stability

### 6.1. The HTTP/2 Tarpit Phenomenon

During the massive discovery run, on passing 4.1 million unique records, the cluster reached a critical stall point. The root cause was identified as a tarpit technique applied by Docker Hub (via Cloudflare) on detecting persistent automated traffic.

HTTP/2 uses multiplexing: multiple requests share a single TCP connection. On detecting the traffic pattern, the server stopped sending data frames but kept the TCP connection open indefinitely — a "half-open" connection. Workers got stuck in an I/O-wait state without the application timeouts firing, because the HTTP/2 protocol did not close the session. The result was a progressive degradation of throughput up to a total halt.

### 6.2. Solution: Forced Downgrade to HTTP/1.1

Disabling HTTP/2 (`TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}` absent from the TLSClientConfig) forces pure HTTP/1.1 connections. Each worker manages atomic, independent TCP sessions. The `ResponseHeaderTimeout` and `Timeout` of the `http.Client` work deterministically, killing stuck connections and freeing the worker.

### 6.3. Log Pipeline Stability (IO Deadlock)

It was found that redirecting logs via the shell (`>> log.txt`) caused total freezes when the shell buffers filled up. The Go process blocked on the write call to stdout, halting the entire goroutine that called the logger.

Solution: removal of manual redirections. The Docker Engine manages stdout asynchronously via its log driver (`json-file` or equivalent), guaranteeing that the Go process never blocks waiting for a disk write.
