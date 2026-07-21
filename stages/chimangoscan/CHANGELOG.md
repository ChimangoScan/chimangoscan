# Changelog — ChimangoScan Research Fork

---

## [3.2.0] — 2026-04-06

### Changed

**`myutils/hubclient.go` — reduced jitter:**
- `HubClient.Get`: per-call jitter changed from `400+rand.Intn(500)` ms (range [400, 900], mean 650ms) to `200+rand.Intn(200)` ms (range [200, 400], mean 300ms). A ~54% reduction in sleep overhead per API call. The 200ms minimum interval still evades the Cloudflare tarpit; values below 200ms increase the rate of 429 responses. Estimated gain: +65% throughput per worker (~23 → ~38 repos/min/worker).

**`buildgraph/from_mongo.go` — asynchronous MongoDB writes:**
- `persistImages`, `getTags`: replaced synchronous `UpdateTag`/`UpdateImage` with sends to the `writesCh chan func()` channel. A dedicated goroutine (created in `StartFromMongo`) drains the channel in the background. The `repoWorker` does not block waiting for cache writes — it advances immediately to the next repo. Estimated gain: +5% (~80ms per repo returned to the useful cycle).
- Signatures of `repoWorker`, `collectBatch`, `getTags`, `getImages`, `persistImages` updated to propagate `writesCh`.
- The channel is closed in order after `wgRepo.Wait()` and before `close(cpCh)`, ensuring all in-flight writes complete before shutdown.

**`buildgraph/from_mongo.go` — empty-poll sleep:**
- `repoWorker`: sleep between fruitless claim attempts reduced from 5s to 2s. Reduces re-claim latency in contention scenarios with multiple workers.

---

## [3.1.0] — 2026-04-05

### Added

**`myutils/hubclient.go`:**
- `GetTag(ns, name, tagName string) (*Tag, error)` — fetches the metadata of a specific tag by name via `GetTagMetadataURL`. Returns `nil, nil` on 404 (nonexistent tag), letting the caller decide whether the absence of `latest` is an error or expected behavior.

### Changed

**`buildgraph/from_mongo.go` — tag selection:**
- `getTags` now always fetches two tags per repository: (1) the most recently updated tag (`GetTags` page 1, size 1) and (2) the `latest` tag via `GetTag`. If the two coincide by name, only one is returned. Motivation: `latest` represents the canonical version used by most users; the most recent tag captures the repository's current state — they frequently diverge (e.g. ubuntu has `resolute-20260401` as the most recent and `latest` pointing at the stable LTS).
- The `tagCnt int` parameter was removed from `getTags`, `processRepo`, `repoWorker`, and `StartFromMongo` — tag selection is no longer configurable via flag.

**`buildgraph/build.go`:**
- `Build` signature updated: `Build(format, threshold, workers, ip, dataDir)` — the `tagCnt` parameter was removed.

**`cmd/cmd.go`:**
- The `--tags` flag was removed from the `build` subcommand (obsolete after the removal of `tagCnt`).
- The `build` subcommand's workers are derived automatically from `len(im.Accounts)` instead of a manual flag. If the accounts file is empty, it falls back to 1 worker. The request rate scales linearly with the number of accounts (1 worker/account ≈ 1.8 req/s).

**`docker-compose.node3.yml`:**
- The `--tags` flag and the `TAGS` variable were removed from the `builder` container's entry command.

### Fixed

**`myutils/mongo.go` — `stage2_queue` index replaced by `stage2_partial`:**
- The composite index `{graph_built_at: 1, pull_count: -1}` with `sparse: true` was incorrect: the `sparse` flag has no effect when any other indexed field (`pull_count`) is present in all documents. The index indexed all 12M repositories and never shrank.
- Replaced with a partial index `{pull_count: -1}` with `partialFilterExpression: {graph_built_at: {$exists: false}}`. This index indexes only repositories not yet processed by Stage II, shrinks progressively as `MarkRepoGraphBuilt` is called, and supports `CountPendingBuildRepos` with a pure index scan (no document fetch).

---

## [3.0.0] — 2026-04-06

### Added

**`myutils/hubclient.go` — shared authenticated HTTP client (new file):**
- `IdentityProvider` interface with the methods `GetNextClient() (*http.Client, string, string)` and `ClearToken(string)` — an abstraction that lets the same `HubClient` be used in Stages I and II without a circular package dependency.
- `HubClient` struct — encapsulates authenticated-request logic, reusable by any goroutine that receives an `IdentityProvider`. Each goroutine creates its own instance.
- `NewHubClient(ip IdentityProvider) *HubClient` — constructor.
- `Get(url string) ([]byte, int, error)` — 3 attempts with automatic identity rotation on 401, 429, and 403 responses; browser headers embedded.
- `GetInto(url string, dest interface{}) error` — `Get` followed by `json.Unmarshal`.
- `GetTags(ns, name string, pageNum, size int)` — paginated tag fetch with authentication.
- `GetImages(ns, name, tag string)` — image manifest fetch with authentication.
- `setHeaders(req *http.Request)` — injects Chrome 145 browser headers (centralized; previously duplicated in `crawler.go`).
- `rotate()` — rotates identity internally, called after retriable error responses.

**`buildgraph/metrics.go` — Stage II progress tracking (new file):**
- `BuildMetrics` struct with atomic counters: `Processed`, `TagCacheHits`, `TagAPIFetches`, `ImageCacheHits`, `ImageAPIFetches`, `Neo4jInserts`, `Errors`.
- `newBuildMetrics(threshold int64) *BuildMetrics` — captures `reposTotal` via `CountPendingBuildRepos` after `ResetStaleBuildClaims`.
- `startReporter(dataDir string, done <-chan struct{})` — goroutine that logs metrics to the log and to the `build_metrics.log` file every 60 seconds.
- Formatted log line: `[METRICS HH:MM:SS] progress=N/Total (%) | rate=X repos/min | ETA=Xh | cache tags=% imgs=% | neo4j=N | errors=N | uptime=Xs`.
- ETA computed after 30 seconds of collected data: `ETA = (total−processed) / (processed / elapsed_minutes)`.

**`docker-compose.node3.yml` — Node 3 orchestration (new file):**
- `builder` service for running Stage II exclusively on an auxiliary machine.
- Environment variables: `MONGO_URI`, `NEO4J_URI`, `ACCOUNTS`, `THRESHOLD`, `TAGS`.
- Entry command: compilation and execution of the `build` subcommand with the flags `--accounts`, `--threshold`, `--tags`, `--data_dir`.

**`myutils/mongo.go` — new methods:**
- `ClaimNextBuildRepo(threshold int64) (*Repository, error)` — atomic `FindOneAndUpdate`: applies `{build_claimed: true, build_started_at: now}` on the document. Filter: `{pull_count >= threshold, graph_built_at: {$exists: false}, build_claimed: {$ne: true}}`. Ordering: `{pull_count: -1}`.
- `ResetStaleBuildClaims()` — release of orphaned claims at startup: documents with `{build_claimed: true, graph_built_at: {$exists: false}}` have `build_claimed` and `build_started_at` removed via `$unset`.
- `CountPendingBuildRepos(threshold int64) (int64, error)` — count of repositories without a claim and without `graph_built_at`, used by the immortal worker pattern.
- `FindImagesByDigests(digests []string) (map[string]*Image, error)` — batched query with the `$in` operator; replaces N individual calls to `FindImageByDigest`, reducing the N+1 pattern to a single query.

**`cmd/cmd.go` — new flags for the `build` subcommand:**
- `--accounts` — path to `accounts.json` (Docker Hub accounts for JWT authentication).
- `--proxies` — path to the proxies file.
- `--data_dir` — destination directory for `build_checkpoint.jsonl` and `build_metrics.log`.

**`Makefile` — new targets:**
- `start-build` — starts Stage II via `docker-compose.node3.yml`.
- `logs-build` — shows and follows the `chimangoscan_builder` container's logs.

### Changed

**`crawler/crawler.go`:**
- The `setBrowserHeaders` method was removed; the logic was centralized in `HubClient.setHeaders` (`myutils/hubclient.go`).
- `worker()` instantiates `hub := myutils.NewHubClient(pc.IM)` locally; the `client`, `token`, and `ua` parameters were removed from the internal functions' signatures.
- `fetchPage(hub, query, page)` simplified: it delegates retry and identity rotation to `HubClient.Get`; it keeps only the 4-minute cooloff for non-retriable HTTP errors (Stage-I-specific behavior).
- `processTask(hub, prefix)` no longer receives or returns `client`, `token`, or `ua`.
- The `uaWindows` and `uaLinuxMac` arrays were removed; User-Agent selection by ROLE was removed — the UA is managed exclusively by the `IdentityManager`.
- Immortal worker: `emptyCount` now uses `CountDocuments` to confirm the queue is effectively empty before terminating the worker.
- `getNextTask` timeout: 10s → 30s.

**`buildgraph/from_mongo.go` — complete rewrite:**
- `repoWorker` migrated from a MongoDB cursor to `ClaimNextBuildRepo` (atomic claim), identical to the Stage I `getNextTask` pattern.
- Each `repoWorker` goroutine creates its own authenticated `HubClient` via `IdentityProvider`.
- `processRepo` uses `defer markBuilt` — the repository is marked as complete in any case, including those with 0 tags, eliminating infinite reprocessing.
- `getTags` and `getImages` receive and increment a `*BuildMetrics`.
- `graphWorker(jobChan, m)` increments `m.Neo4jInserts` on each Neo4j insertion.
- `checkpointWriter` goroutine — a single-writer that persists JSONL lines to `dataDir/build_checkpoint.jsonl`.
- Renamed functions: `fetchTags` → `getTags`, `fetchImages` → `getImages`.
- Image cache: the N+1-queries pattern replaced by a single `$in` query via `FindImagesByDigests`.
- `persistImages` extracted as an independent function.

**`myutils/mongo.go`:**
- `MarkRepoGraphBuilt` updated: in addition to writing `graph_built_at`, it now removes `build_claimed` and `build_started_at` via `$unset`.

**`buildgraph/build.go`:**
- `Build` signature updated: `Build(format, tagCnt, threshold, ip IdentityProvider, dataDir)` — the `page` and `pageSize` parameters were removed (they were ignored in the previous implementation).

**`myutils/urls.go`:**
- `V2SearchURLTemplate`: the `&ordering=-pull_count` parameter was removed. Docker Hub uses `best_match` as the default ordering mode, which prioritizes exact matches before popularity-based results.

**`docker-compose.yml`:**
- The Neo4j volume changed from a named Docker volume (`neo4j_data:/data`) to a host volume (`./neo4j_data:/data`), avoiding data loss from `docker system prune -a --volumes`.
- The `volumes:` section (named volumes) was removed from the file.

### Fixed

- **Repositories with 0 tags reprocessed indefinitely:** the previous Stage II did not mark `graph_built_at` on repositories that returned 0 tags from the API, causing infinite reprocessing of those records. The use of `defer markBuilt` in `processRepo` ensures the field is written regardless of the tag-fetch result.
- **Duplicated browser headers between stages:** `setBrowserHeaders` was duplicated in `crawler/crawler.go` and in Stage II calls. Centralizing in `HubClient.setHeaders` eliminates the divergence.
- **Orphaned claims after a Stage II crash:** on restart, `ResetStaleBuildClaims` automatically releases all documents with `build_claimed=true` and no `graph_built_at`, guaranteeing resumption without manual intervention.
- **N+1 queries for the image cache in Stage II:** replaced by a single MongoDB query with the `$in` operator in `FindImagesByDigests`.

---

## [2.5.0] — 2026-04-04

### Added

**Persistent task queue with priority (`crawler/crawler.go`):**
- `ensureQueueInitialized(seeds)` — initializes `crawler_keywords` with the alphabet seeds if empty; automatically reverts tasks in the `"processing"` state to `"pending"` on restart (auto-healing of previous crashes). If the queue already contains tasks, it resumes from where it stopped without re-insertion.
- `getNextTask()` — atomic `FindOneAndUpdate` with the filter `{status: "pending"}` and the composite ordering `{priority: -1, _id: 1}`: higher-priority prefixes are processed first; ties resolved lexicographically.
- `updateTaskStatus(id, status)` — updates the status and `finished_at` of a task; used to transition to `"done"` or revert to `"pending"` on failure.
- `priority int` field in the `crawler_keywords` task document, with semantics defined by match type:
  - `priority=2` — child with no hyphen: genuine substring match, no ElasticSearch tokenization. High probability of new distinct repositories.
  - `priority=1` — child when the parent found new repositories (`newInPrefix > 0`).
  - `priority=0` — default (the parent found no new repositories).
  - `priority=-1` — child of a "token-match plateau" (deprioritized; processed last, but with no data loss).

**Token-match plateau detection and deprioritization (`crawler/crawler.go`):**
- Plateau condition: `newInPrefix == 0 && res.Count >= 10000 && strings.Contains(prefix, "-") && len(prefix) > 1`
- Semantics: Docker Hub uses the hyphen as a token separator in ElasticSearch. A hyphenated prefix returning 10,000 results but zero new repositories is a complete-token match with no novelty for the dataset. Deepening in that direction with normal priority would saturate the queue with low-return tasks.
- Action: all children are inserted with `priority=-1` instead of `priority=0`. Deprioritization without removal — the data is not lost, it is just left to the end of the queue.
- Explicit log: `>>> DEPRIORITIZING [prefix]: token-match plateau (N results, 0 new). Children set to priority=-1.`

**Consecutive-separator deduplication (`crawler/crawler.go`):**
- If the last character of the prefix is `-` or `_`, the `-` and `_` children are omitted when generating the expansion.
- Motivation: Docker Hub's ElasticSearch treats `--`, `-_`, `_-`, `__` as equivalent to a single separator. Generating these children would cause an unbounded-depth DFS returning results identical to the parent, with no new data.

**RAM cache warming (`crawler/crawler.go`):**
- `PreloadExistingRepos()` — runs at startup, before any worker. Does a `Find` on `RepoColl` with the projection `{namespace, name}` and populates `seenRepos sync.Map` with all already-persisted repositories.
- Prevents API calls and database round-trips for repositories already collected in previous runs. Deduplication happens in microseconds in local RAM instead of sub-milliseconds over the network.
- Tested scale: 5.2 million records in ~300 MB of RAM. Progress log every 250,000 records; a final log with the count and total duration.

**Per-prefix efficiency logging (`crawler/crawler.go`):**
- `efficiency = (newInPrefix / pages×100) × 100%`
- Log at the end of each task: `[DONE] Prefix [prefix]: +N unique | Eff: X.X% | Found total: N`
- A diagnostic metric: prefixes with an efficiency near 0% indicate regions of the DFS space already saturated by the cache.

### Changed

**Browser fingerprint — per-account identity (`crawler/auth_proxy.go`):**
- `globalUAPool`: a pool of 7 User-Agents covering Chrome 121/119 (Windows/Mac/Linux), Edge 121, Firefox 122, Safari 17.
- Each account is assigned a fixed UA at load time via round-robin: `acc.UserAgent = globalUAPool[i % len(globalUAPool)]`. The same account always uses the same UA in login, search, and manifests — identity consistency observable by the server.
- `GetNextClient()` returns `(*http.Client, token, ua)` — the three identity attributes propagated together to ensure each request belongs to the same "browser session".
- JWT auto-login guarded by `loginMu sync.Mutex` — prevents parallel login of the same account by multiple workers.
- `ClearToken(token)` clears the token of the corresponding account, forcing re-authentication on the next call to `GetNextClient`.

**TLS stack and network timeouts (`crawler/auth_proxy.go`):**
- `TLSClientConfig{MinVersion: tls.VersionTLS12, PreferServerCipherSuites: false}` — emulates Chrome's TLS negotiation profile (the server picks the cipher order).
- `TLSHandshakeTimeout = 5s`, `ResponseHeaderTimeout = 5s`, total request timeout = 10s.
- HTTP/2 not configured on the transport — deliberately avoided to prevent worker blocking on half-open connections during a rate-limit tarpit (with HTTP/1.1 each connection is atomic and the timeout works deterministically).
- `MaxIdleConns = 100`, `IdleConnTimeout = 90s`, `MaxIdleConnsPerHost = 10` — an active TCP connection pool.

**HTTP 404 status semantics (`crawler/crawler.go`):**
- HTTP 404 in `fetchPage` returns `&V2SearchResponse{}` (empty) with `ok=true` — it is not a failure.
- Interpretation: 404 indicates that `starting_index` exceeds the query's total results. The pagination loop `for p := 2; p <= pages; p++` aborts naturally on receiving an empty slice on any page.
- Before this version, 404 caused re-enqueuing the task as `"pending"` or a 30s cooldown — incorrect behavior that wasted time and reprocessed valid tasks.

**Extended cooldown for unexpected HTTP errors (`crawler/crawler.go`):**
- HTTP codes outside the set `{200, 404, 401, 429, 403}`: log with the first 200 bytes of the diagnostic body and a **4-minute** cooldown before returning a failure.
- Before this version the cooldown was 30 to 90 seconds — insufficient for the caching period of Cloudflare's WAF on error responses.

### Fixed

- **Infinite-depth DFS on consecutive separators:** a prefix ending in `-` or `_` generated children `--`, `-_` whose results were identical to the parent, causing unbounded-depth fan-out with no new data.
- **Premature worker termination on a temporarily empty queue:** workers terminated after N consecutive `getNextTask` failures, even with genuinely pending tasks temporarily claimed by other workers in the cluster. Fixed: a worker terminates only when `CountDocuments({status: "pending"})` confirms zero remaining tasks.
- **DFS saturation in dense regions:** without prioritization, token-match prefixes accumulated hundreds of children covering the same lexical region, blocking high-utility prefixes from reaching the front of the queue.

---

## [2.0.0] — 2026-04-03

### Added

**`crawler/` (Stage I implementation — a stub with no `Run` in the upstream):**
- `crawler/crawler.go`: `ParallelCrawler` with a recursive DFS over the Docker Hub prefix space. N independent workers, each running `crawlDFS` recursively from its seeds. In-memory deduplication via `seenRepos sync.Map`. Forced deepening for single-character prefixes. `repoWriter` goroutine with `BulkWrite` to MongoDB every 2s or 1,000 repositories. Post-order checkpointing per keyword via the `crawler_keywords` collection.
- `crawler/auth_proxy.go`: `IdentityManager` — loads Docker Hub accounts from `accounts.json` and proxies from a text file; JWT auto-login with `sync.Mutex`; round-robin identity rotation via `GetNextClient()`.

**`buildgraph/from_mongo.go` (re-engineered Stage II):**
- Three-stage pipeline decoupled by buffered channels: Loader (MongoDB → `repoChan` buf 4,000), repoWorkers (`max(NumCPU×16, 64)`), and buildGraphWorkers (`max(NumCPU×4, 16)`).
- A `tagConcurrency=4` semaphore per repository to control parallel manifest requests.
- `graph_built_at` checkpointing in MongoDB after each repository completes.

**`myutils/mongo.go`:**
- `BulkUpsertRepositories`: unordered bulk write with upsert by `{namespace, name}`.
- `KeywordsColl`, `IsKeywordCrawled`, `MarkKeywordCrawled`: checkpoint system for Stage I.
- `MarkRepoGraphBuilt`: checkpoint for Stage II.
- Connection pool: `MaxPoolSize=100`, `MinPoolSize=5`, `MaxConnIdleTime=5min`.
- Initial ping timeout: `1s → 30s`.

**`myutils/neo4j.go`:**
- `InsertImageToNeo4j` rewritten: layer IDs pre-computed locally via a SHA256 chain; the entire layer chain inserted in a single `ExecuteWrite` transaction (O(1) round-trips per image, instead of O(N layers)).

**`myutils/urls.go`:**
- `V2SearchURLTemplate` and `GetV2SearchURL` — Docker Hub V2 API with `ordering=-pull_count`.

**`myutils/config.go`:**
- Override via the `MONGO_URI` and `NEO4J_URI` environment variables.
- Config location via `os.Getwd()` (compatible with `go run`).
- Optional Neo4j at startup.

**`myutils/docker_hub_api_requests.go`:**
- Keep-alives enabled (TCP/TLS connections reused across requests).
- Connection pool: `MaxIdleConns=300`, `MaxIdleConnsPerHost=50`, `IdleConnTimeout=90s`, `Timeout=30s`.

**`cmd/cmd.go`:**
- `crawl` subcommand with the flags `--workers`, `--seed`, `--shard`, `--shards`, `--accounts`, `--proxies`, `--config`.

**Infrastructure:**
- `docker-compose.yml`: MongoDB, Neo4j, crawler.
- `docker-compose.node2.yml`: Node 2 pointing at Node 1's MongoDB.
- `automation/pipeline_autopilot.sh`: sequential orchestration of the 3 stages.
- `automation/test_e2e.sh`: end-to-end integration test.

### Fixed

- **`myutils/neo4j.go` — `findLayerNodesByRawLayerDigestFunc` (critical):** the Cypher query used `{id: $digest}` to match a `RawLayer` node, but the stored property is `digest`. The `id` property does not exist on `RawLayer`. The query never returned results, silently breaking upstream image tracking. Fixed to `{digest: $digest}`.

- **`scripts/calculate_node_dependent_weights.go` (medium):** the `if repoDoc.Namespace == "library"` branch had `continue` as its first statement, making all subsequent code unreachable. Official Docker images were skipped in the dependency-weight computation. `continue` removed.

- **`myutils/docker_hub_api_requests.go` (medium):** `DisableKeepAlives: true` prevented the reuse of TCP connections, unnecessarily adding ~100–300ms of handshake+TLS per request. Removed.

- **`automation/test_e2e.sh` (low):** invalid `[ [` bash syntax replaced by `[ "$(expr)" -gt N ]`.

---

## [1.0.0] — upstream baseline (the DITector framework, Dr. Docker)

The original pipeline with the `crawl` subcommand declared in `cmd/cmd.go` with no `Run` field (a stub with no implementation). Stages II and III functional. Implements: `buildgraph/build.go` (synchronous per-layer insertion into Neo4j), `myutils/`, `scripts/`, `analyzer/`, `cmd/`, `main.go`.
