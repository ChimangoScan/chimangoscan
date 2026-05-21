#!/usr/bin/env python3
"""Recompute Table 10 (per-CVE downstream propagation) by the UNION method,
in Python over the layer-graph dumps (NOT Neo4j: Cypher variable-length paths
time out). For each CVE we take the affected images' top-layer nodes and do a
multi-source BFS over IS_BASE_OF children; the union of distinct downstream
images is the sum of len(images) over the distinct reachable nodes, because
each image ref lives in exactly one (top-layer) node.

Inputs : cve_digests_v3.json (from extract_cve_digests.py),
         /mnt/cache/exposure_work/{edges.tsv.gz, toplayers.jsonl.gz}
Output : propagation_v3.json  {top10:[...], range_min, range_max, zlib_value,
         factor_min, factor_max}
"""
import gzip, json, array, sys
from collections import deque

WORK = "/mnt/cache/exposure_work"
EDGES = WORK + "/edges.tsv.gz"
TOPL = WORK + "/toplayers.jsonl.gz"
CVE = "/mnt/win_ssd/chimangoscan-paper/cve_digests_v3.json"
OUT = "/mnt/win_ssd/chimangoscan-paper/propagation_v3.json"


def log(*a):
    print(*a, flush=True)


# only need digest->node for the affected digests of the candidate CVEs
cve_in = json.load(open(CVE))
wanted = set()
for info in cve_in.values():
    wanted.update(info["digests"])
log(f"wanted affected digests (union of {len(cve_in)} CVEs): {len(wanted):,}")

# ---- pass 1: max node id + n_images + digest->node (filtered) --------------
log("loading toplayers (n_images + digest->node)...")
max_node = 0
node_imgs = {}            # node -> count
digest2node = {}          # 'sha256:..' -> node  (only wanted)
with gzip.open(TOPL, "rt") as f:
    for line in f:
        tab = line.index("\t")
        ni = int(line[:tab])
        refs = json.loads(line[tab + 1:])
        if ni > max_node:
            max_node = ni
        node_imgs[ni] = len(refs)
        for r in refs:
            at = r.rfind("@")
            if at != -1:
                d = r[at + 1:]
                if d in wanted:
                    digest2node[d] = ni
log(f"  nodes with images: {len(node_imgs):,}  max_node={max_node:,}  mapped digests={len(digest2node):,}")

# n_images as array for speed
nimg = array.array("i", bytes(4 * (max_node + 1)))
for ni, c in node_imgs.items():
    nimg[ni] = c
del node_imgs

# ---- pass 2: resolve to a FOREST (each node <=1 parent, like the ranker) ----
# The raw edge set is not a pure forest: generic/shared layers (LABEL/CMD
# metadata) appear under several parents (multiparent), which would fuse
# unrelated subtrees and inflate the downstream union. We resolve each node to
# a single parent exactly as compute_exposure_ranking.py does (last writer
# wins), then derive children as the inverse of parent[]. This makes every
# subtree a true tree, consistent with the exposure ranking.
log("resolving parent[] (forest, multiparent collapsed)...")
parent = array.array("q", b"\xff" * (8 * (max_node + 1)))   # -1
with gzip.open(EDGES, "rt") as f:
    for line in f:
        tab = line.index("\t")
        pi = int(line[:tab]); ci = int(line[tab + 1:])
        if pi <= max_node and ci <= max_node:
            parent[ci] = pi
# children CSR from parent[]
deg = array.array("i", bytes(4 * (max_node + 1)))
m = 0
for c in range(max_node + 1):
    p = parent[c]
    if p != -1:
        deg[p] += 1
        m += 1
log(f"  forest edges: {m:,}")
off = array.array("q", bytes(8 * (max_node + 2)))
acc = 0
for i in range(max_node + 1):
    off[i] = acc
    acc += deg[i]
off[max_node + 1] = acc
children = array.array("i", bytes(4 * m))
cur = array.array("q", off[:max_node + 1])
for c in range(max_node + 1):
    p = parent[c]
    if p != -1:
        children[cur[p]] = c
        cur[p] += 1
del cur, deg, parent
log("  children CSR built (forest)")

# ---- per-CVE multi-source BFS ----------------------------------------------
log(f"computing propagation for {len(cve_in)} CVEs...")
visited = bytearray(max_node + 1)
stamp = 0
results = []
for cve, info in cve_in.items():
    stamp += 1
    starts = []
    for d in info["digests"]:
        nd = digest2node.get(d)
        if nd is not None:
            starts.append(nd)
    # multi-source BFS over children; sum nimg of distinct reachable nodes
    dq = deque()
    total = 0
    seen_local = set()
    for s in starts:
        if s not in seen_local:
            seen_local.add(s); dq.append(s)
    # use a fresh visited via set for correctness across CVEs (subtrees ~<1M)
    vis = set(seen_local)
    # distinct downstream IMAGES = distinct reachable nodes that carry an image.
    # Each ancestry-hashed node encodes its full layer stack, so one node == one
    # image (content) digest; multiple refs (tags/repos) of the same node share
    # that digest. Counting nodes-with-images therefore counts distinct digests,
    # consistent with n_direct (also distinct digests).
    while dq:
        x = dq.popleft()
        if nimg[x]:
            total += 1
        a = off[x]; b = off[x + 1]
        for k in range(a, b):
            c = children[k]
            if c not in vis:
                vis.add(c); dq.append(c)
    direct = info["n_direct"]
    results.append({
        "cve": cve, "package": info["package"], "severity": info["severity"],
        "direct_images": direct, "distinct_downstream": total,
        "factor": round(total / direct, 1) if direct else 0.0,
        "reachable_nodes": len(vis),
    })
    log(f"  {cve} {info['package']}: direct={direct} downstream={total} factor={results[-1]['factor']}")

results.sort(key=lambda r: -r["distinct_downstream"])
top = results[:10]
zlibv = next((r["distinct_downstream"] for r in top if r["package"] == "zlib"), None)
out = {
    "top10": top,
    "range_min": min(r["distinct_downstream"] for r in top),
    "range_max": max(r["distinct_downstream"] for r in top),
    "factor_min": min(r["factor"] for r in top),
    "factor_max": max(r["factor"] for r in top),
    "zlib_value": zlibv,
}
json.dump(out, open(OUT, "w"), indent=1)
log(f"\nwrote {OUT}")
log(f"range {out['range_min']:,}-{out['range_max']:,}  factor {out['factor_min']}-{out['factor_max']}  zlib={zlibv}")
