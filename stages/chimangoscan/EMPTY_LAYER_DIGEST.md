# Empty Layer Digest — Reference Note

**Date:** 2026-04-06

---

## Overview

In the IDEA graph (Neo4j), it is expected and correct for multiple `Layer` nodes with
different `instruction` values to share the same `digest`:

```
sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1
```

This digest (32 bytes, compressed) is the canonical identifier for the **Docker empty
layer** — a layer that produces no filesystem changes.

---

## Empirical Proof

The blob `sha256:4f4fb700...` was fetched directly from the OCI registry
(`registry-1.docker.io`) and verified:

```
Compressed blob  → sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1  (32 bytes)
gunzip           → sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef
```

`sha256:5f70bf18...` is the corresponding `diff_id` (uncompressed) in OCI image configs.
Both values identify the same zero-content layer — the difference is only the
compression format:

| Field | Format | Value |
|-------|--------|-------|
| `layer.digest` (Docker Hub API / manifest) | compressed (gzip) | `sha256:4f4fb700...` |
| `rootfs.diff_ids[]` (OCI image config) | uncompressed | `sha256:5f70bf18...` |

---

## Why Multiple Instructions Share This Digest

Any Dockerfile instruction that produces **no filesystem change** results in this layer:

- `WORKDIR /path` — creates a directory entry; treated as empty layer in many BuildKit
  builds when the directory already exists upstream
- `COPY glob /dst/` — if the glob resolves to zero files at build time, BuildKit
  generates a physically empty layer
- `ARG`, `ENV`, `EXPOSE`, `LABEL`, `CMD`, `ENTRYPOINT` — pure metadata instructions;
  always `empty_layer: true` in the OCI config

---

## Graph Integrity

The Neo4j graph stores `layer.digest` as received from the Docker Hub API
(`/v2/repositories/{ns}/{repo}/tags/{tag}/images`). The pipeline is internally
consistent — it never mixes compressed digests with OCI `diff_ids`.

Correct graph state for two instructions that both produced empty layers:

```
(:Layer {id: "3fb5...", digest: "sha256:4f4fb700...", instruction: "COPY envoy.* ..."})
(:Layer {id: "ba24...", digest: "sha256:4f4fb700...", instruction: "WORKDIR /data"})
(:RawLayer {digest: "sha256:4f4fb700..."})

(Layer:3fb5)-[:IS_SAME_AS]->(RawLayer)
(Layer:ba24)-[:IS_SAME_AS]->(RawLayer)
```

- `Layer.id` values are **different** (chain-position hash — each node is unique)
- `Layer.digest` values are **equal** (same physical content — expected and correct)
- The shared `RawLayer` node correctly represents the single physical blob

---

## Investigation History

During development, this pattern was initially suspected to be a Docker Hub API bug
(off-by-one misalignment between `history[]` and `diff_ids[]`). Empirical verification
confirmed there is no bug: the two canonical empty-layer identifiers (`4f4fb700...`
compressed, `5f70bf18...` uncompressed) decompress to identical content, and the graph
data faithfully reflects what the Docker Hub API reports.
