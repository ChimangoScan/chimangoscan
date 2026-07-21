# Research Methodology — Large-Scale Security Analysis of the Docker Hub Ecosystem

**Scientific basis:** Hequan Shi et al., "Dr. Docker: A Large-Scale Security Measurement of Docker Image Ecosystem", WWW '25.

---

## 1. Scope and Objectives

This methodology aims at the qualified selection of Docker Hub containers for submission to dynamic network scans. The selection is driven by two systemic-impact criteria:

- **Pull Count:** an indicator of popularity and breadth of deployment. Vulnerabilities in high-pull-count images directly affect a wide base of infrastructure.
- **Dependency Weight (Out-Degree in the layer graph):** the number of downstream images that inherit layers from this image. A vulnerability in a base image propagates through the supply chain to all derived images — the impact is multiplied by the dependency weight.

The goal is not the exhaustive enumeration of Docker Hub, but the identification of the containers with the greatest potential security impact for prioritizing scans.

---

## 2. Phase I — Exhaustive Discovery (DFS Crawling)

### 2.1. Problem: No Public Listing

Docker Hub does not provide an exhaustive public listing of its repositories. The search API (`GET /v2/search/repositories/`) returns at most 10,000 results per query, with pagination of up to 100 results per page.

### 2.2. Solution: DFS over the Prefix Space

The **Depth-First Search (DFS)** algorithm is applied over the space of alphabetic prefixes, recursively:

```
If count(keyword) >= 10,000 → go deeper: enqueue keyword+a, keyword+b, ..., keyword+_ (38 chars)
If count(keyword) < 10,000  → collect: scrape all available pages
```

Deepening is forced for single-character prefixes regardless of the reported count. The Docker Hub API accepts single-character queries, but the underlying ElasticSearch engine treats these terms as stopwords, returning artificially low counts. Without forced deepening, the DFS tree would be pruned prematurely at these nodes, resulting in the loss of the entire corresponding subtree.

### 2.3. Repository Name Representation

Docker Hub organizes repositories in two levels: `namespace/name`. The V2 API returns the `repo_name` field in two formats:

| Type | `repo_name` in the API | Canonical namespace | Name |
|------|--------------------|--------------------|------|
| Official image | `"nginx"` | `library` | `nginx` |
| Community image | `"cimg/postgres"` | `cimg` | `postgres` |

The `repo_owner` field returned by the API is always empty and must not be used. The namespace is extracted exclusively from `repo_name` via `parseRepoName()`:

```go
func parseRepoName(repoName string) (namespace, name string) {
    parts := strings.SplitN(repoName, "/", 2)
    if len(parts) == 2 {
        return parts[0], parts[1]
    }
    return "library", repoName
}
```

To generate the pull name from the exported dataset:

```python
ns  = record["repository_namespace"]
img = record["repository_name"]
tag = record["tag_name"]
image_ref = f"{img}:{tag}" if ns == "library" else f"{ns}/{img}:{tag}"
```

`library/` images follow the Docker convention: `docker pull nginx:latest` is equivalent to `docker pull library/nginx:latest`. For community images, the namespace is mandatory in the `pull` command.

### 2.4. Stage I Output

MongoDB, `repositories_data` collection: one document per repository with `namespace`, `name`, and `pull_count`.

---

## 3. Phase II — Building the layer graph

### 3.1. Processing Scope

Phase II processes **all repositories** with `pull_count ≥ threshold`, with no heuristic filter by name. The goal is complete coverage of the Docker Hub ecosystem for dependency analysis: repositories that do not expose network ports are equally relevant as base (upstream) images in the layer graph.

The security-relevance filter is applied afterward, in Phase III, via Dependency Weight: repositories that nothing depends on and that do not expose relevant ports get a low score and are naturally deprioritized in the final dataset.

### 3.2. Building the layer graph (built with Dr. Docker's IDEA layer-ID hashing)

For each repository, the system queries the Docker Hub API to obtain the most recently updated tag and the `latest` tag (if different), and for each tag the image metadata (the list of layers with digest, instruction, and size) for all available platforms.

The graph models inheritance between images through a layer-hashing scheme. For each layer i in an image's stack:

**Content layer** (has the SHA256 digest of the content):
```
dig_i      = SHA256(layer_i.digest)
Layer_i.id = SHA256(Layer_{i-1}.id || dig_i)
```

**Config layer** (Dockerfile instruction with no physical content):
```
dig_i      = SHA256(layer_i.instruction)
Layer_i.id = SHA256(Layer_{i-1}.id || dig_i)
```

The bottom layer uses `Layer_{-1}.id = ""`. All IDs are computed locally before any communication with Neo4j.

**Fundamental property:** if two images share the same first N layers in the same order, their `Layer_N.id` will be identical. Inheritance relations are identifiable by node-ID equality — with no content comparison.

### 3.3. Stage II Output

Neo4j with `Layer` nodes, `RawLayer` nodes, and `IS_BASE_OF` edges (inheritance between consecutive layers) and `IS_SAME_AS` edges (layer→physical-content association).

---

## 4. Phase III — Ranking and Dataset Generation

### 4.1. Dependency Weight (Out-Degree)

The **Dependency Weight** of an image is the Out-Degree of the `Layer` node corresponding to its last layer in the layer graph — i.e. the number of child images that inherit directly from this image. Images with a high Out-Degree are widely used base images; vulnerabilities in them propagate through the supply chain.

The Dr. Docker paper defines two sets of high-impact images:

| Set | Criterion | Count in paper |
|----------|----------|---------------|
| High-Pull-Count | Pull count ≥ 1,000,000, top 3 most recent tags | 20,673 images |
| High-Dependency-Weight | Dependency weight ≥ 10 | 25,924 images |

### 4.2. Output Dataset

The exported dataset (`final_prioritized_dataset.json`) is a JSONL file (one JSON record per line):

```json
{
  "repository_namespace": "library",
  "repository_name": "nginx",
  "tag_name": "latest",
  "image_digest": "sha256:...",
  "weights": 1847,
  "downstream_images": ["user1/app:latest", "user2/service:v2"]
}
```

Prioritization for the scan is done by ordering on the `weights` (supply-chain impact) and `pull_count` (direct popularity) fields. There is no composite score function with explicit weights — the choice of ordering criteria is left to the researcher according to the focus of the analysis.

### 4.3. Inter-Stage Checkpointing

| Stage | Mechanism | Field |
|---------|-----------|-------|
| I | MongoDB `crawler_keywords` collection | `_id = keyword`, `crawled_at` |
| II | Field on the repository document | `graph_built_at: <RFC3339>` |

In case of interruption and restart, each stage resumes from where it stopped without reprocessing already-completed items.

---

## 5. Integration with Network Scanning

The final dataset feeds an external network scanner. The expected flow per image:

1. `docker pull <namespace>/<name>:<tag>` (or `<name>:<tag>` for `library/`)
2. `docker run -d --name scan_target <image>`
3. `docker inspect scan_target` → extract the container's IP
4. Network scan with target = the container's IP
5. Collect the report; `docker rm -f scan_target`

The heuristic pre-filter in Stage II reduces the proportion of containers with no network services in the output dataset, lowering the number of fruitless scan attempts for the external scanner.

---

## 6. Findings of the Reference Paper (Dr. Docker, WWW '25)

| Metric | Reported value |
|---------|----------------|
| Images with known vulnerabilities (CVE) | 93.7% |
| Images with secret leakage | 4,437 |
| Images with service misconfigurations | 50 |
| Malicious images (crypto miners: XMR, PKT, CRP) | 24 |
| Downstream images affected by malicious ones (supply chain) | 334 |
| High-Pull-Count (≥1M pulls, top 3 tags) | 20,673 |
| High-Dependency-Weight (Out-Degree ≥ 10) | 25,924 |
