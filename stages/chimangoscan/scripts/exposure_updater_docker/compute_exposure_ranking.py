#!/usr/bin/env python3
"""Compute Docker-image supply-chain exposure ranking from the ChimangoScan layer graph.

Strategy (justified by the graph construction in myutils/neo4j.go):
  - IS_BASE_OF builds a *forest of out-trees*: a Layer's id = sha256(parent.id + sha256(layer.digest)),
    so for a fixed child id the parent id is uniquely determined => each Layer has at most ONE parent.
  - An image lives at its top Layer L (its docker.io/ns/repo:tag@digest string is in L.images).
  - downstream images of image I (at top layer L) = images carried by every *strict* descendant of L.
    Because it is a tree, each descendant node contributes its images exactly once -> no cross-branch dedup.
  - So dependency_weight(I) = sum over strict-descendant nodes N of len(images[N])  (ChimangoScan's metric).
    downstream_pull_sum(I) = sum over strict-descendant nodes N of (sum of repo pull_count over refs in images[N]).
    Both are *subtree sums* (excluding L itself) -> one O(nodes) bottom-up pass, no per-image traversal.

Output: one row per repo present in the graph, at a representative tag
  (latest > most-recently-updated 'active' tag > 'latest'), with the highest-exposure image for that repo,
  sorted by exposure desc. exposure = pull_count(repo) + downstream_pull_sum.

Resumable: Neo4j/Mongo dumps streamed to gzip files first; recomputation re-reads those.
"""
import array
import gzip
import json
import os
import sys
import time
from collections import deque

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
WORKDIR = os.environ.get("WORKDIR", os.path.expanduser("~/scanners/data/exposure_work"))
OUT_PATH = os.environ.get("OUT_PATH", os.path.expanduser("~/scanners/data/chimangoscan_exposure_ranked.jsonl"))

os.makedirs(WORKDIR, exist_ok=True)

EDGES_GZ = os.path.join(WORKDIR, "edges.tsv.gz")
TOPLAYERS_GZ = os.path.join(WORKDIR, "toplayers.jsonl.gz")
REPO_PULL_GZ = os.path.join(WORKDIR, "repo_pull.tsv.gz")
TAGS_GZ = os.path.join(WORKDIR, "tags.tsv.gz")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


# ---------------------------------------------------------------------------
# Phase 1: Mongo dumps
# ---------------------------------------------------------------------------
def dump_mongo():
    from pymongo import MongoClient
    cli = MongoClient(MONGO_URI)
    db = cli["dockerhub_data"]

    if not (os.path.exists(REPO_PULL_GZ) and os.path.getsize(REPO_PULL_GZ) > 0):
        log("dumping repositories_data ...")
        tmp = REPO_PULL_GZ + ".tmp"
        n = 0
        with gzip.open(tmp, "wt") as f:
            for d in db.repositories_data.find({}, {"namespace": 1, "name": 1, "pull_count": 1, "_id": 0},
                                                batch_size=20000):
                ns = d.get("namespace") or ""
                nm = d.get("name") or ""
                pc = d.get("pull_count") or 0
                try:
                    pc = int(pc)
                except (TypeError, ValueError):
                    pc = 0
                if not ns or not nm:
                    continue
                f.write("%s\t%s\t%d\n" % (ns, nm, pc))
                n += 1
                if n % 1_000_000 == 0:
                    log("  repos:", n)
        os.replace(tmp, REPO_PULL_GZ)
        log("repositories_data done:", n)
    else:
        log("repo_pull dump already present, skipping")

    if not (os.path.exists(TAGS_GZ) and os.path.getsize(TAGS_GZ) > 0):
        log("dumping tags_data ...")
        tmp = TAGS_GZ + ".tmp"
        n = 0
        with gzip.open(tmp, "wt") as f:
            for d in db.tags_data.find({}, {"repositories_namespace": 1, "repositories_name": 1,
                                            "name": 1, "last_updated": 1, "tag_status": 1, "_id": 0},
                                       batch_size=20000):
                ns = d.get("repositories_namespace") or ""
                nm = d.get("repositories_name") or ""
                tg = d.get("name") or ""
                lu = str(d.get("last_updated") or "").replace("\t", " ").replace("\n", " ")
                st = str(d.get("tag_status") or "").replace("\t", " ").replace("\n", " ")
                if not ns or not nm or not tg:
                    continue
                f.write("%s\t%s\t%s\t%s\t%s\n" % (ns, nm, tg, lu, st))
                n += 1
                if n % 1_000_000 == 0:
                    log("  tags:", n)
        os.replace(tmp, TAGS_GZ)
        log("tags_data done:", n)
    else:
        log("tags dump already present, skipping")
    cli.close()


# ---------------------------------------------------------------------------
# Phase 2: Neo4j stream
# ---------------------------------------------------------------------------
def dump_neo4j():
    """Stream edges and top-layers using Neo4j *internal* node ids id(n) (no `id` property dereference).

    The builder only inserts nodes (never deletes), so internal ids are stable and roughly dense; we use
    them directly as array indices. The edge query touches only the relationship store -> fast even with a
    cold page cache (no random property reads). Array sizes are derived later from the max id seen in the dumps.
    """
    from neo4j import GraphDatabase
    drv = GraphDatabase.driver(NEO4J_URI, auth=None)

    if not (os.path.exists(EDGES_GZ) and os.path.getsize(EDGES_GZ) > 0):
        log("streaming IS_BASE_OF edges (by internal id) ...")
        tmp = EDGES_GZ + ".tmp"
        n = 0
        with drv.session() as s, gzip.open(tmp, "wt") as f:
            res = s.run("MATCH (a:Layer)-[:IS_BASE_OF]->(b:Layer) RETURN id(a) AS p, id(b) AS c")
            for rec in res:
                p = rec["p"]; c = rec["c"]
                if p is None or c is None:
                    continue
                f.write("%d\t%d\n" % (p, c))
                n += 1
                if n % 2_000_000 == 0:
                    log("  edges:", n)
        os.replace(tmp, EDGES_GZ)
        log("edges done:", n)
    else:
        log("edges dump already present, skipping")

    if not (os.path.exists(TOPLAYERS_GZ) and os.path.getsize(TOPLAYERS_GZ) > 0):
        log("streaming top layers (size(images)>0, by internal id) ...")
        tmp = TOPLAYERS_GZ + ".tmp"
        n = 0
        with drv.session() as s, gzip.open(tmp, "wt") as f:
            res = s.run("MATCH (l:Layer) WHERE l.images IS NOT NULL AND size(l.images) > 0 "
                        "RETURN id(l) AS id, l.images AS images")
            for rec in res:
                lid = rec["id"]; imgs = rec["images"]
                if lid is None or not imgs:
                    continue
                f.write("%d\t%s\n" % (lid, json.dumps(imgs, separators=(",", ":"))))
                n += 1
                if n % 500_000 == 0:
                    log("  top layers:", n)
        os.replace(tmp, TOPLAYERS_GZ)
        log("top layers done:", n)
    else:
        log("toplayers dump already present, skipping")
    drv.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_ref(ref):
    """Parse a graph image ref into (ns, repo, tag, digest).

    The builder writes refs as fmt.Sprintf("docker.io/%s/%s:%s@%s", ns, name, tag, digest)
    where ns/name come straight from MongoDB (ns may be "" with name="user/repo", giving "docker.io//user/repo:tag@d").
    So: strip "@digest", strip trailing ":tag", strip "docker.io/" prefix, then ns = part before first "/",
    repo = everything after (Docker repo names have no ':' so the rpartition on ':' is safe). Falls back to
    DivideImageName-style heuristics for any non-conforming ref.
    """
    digest = ""
    at = ref.find("@")
    if at != -1:
        digest = ref[at + 1:]
        ref = ref[:at]
    # tag: last colon in the whole remaining string (docker.io has no colon)
    col = ref.rfind(":")
    if col != -1 and "/" not in ref[col + 1:]:
        tag = ref[col + 1:]
        ref = ref[:col]
    else:
        tag = "latest"
    # strip registry
    if ref.startswith("docker.io/"):
        rest = ref[len("docker.io/"):]
    elif "/" not in ref:
        # bare repo name (no registry, no namespace) -> library
        return "library", ref, tag, digest
    else:
        # could be "<reg-with-dot>/ns/repo" or "ns/repo"; treat first segment as registry only if it has a dot/colon
        first = ref.split("/", 1)[0]
        if "." in first or ":" in first or first == "localhost":
            rest = ref.split("/", 1)[1]
        else:
            rest = ref
    # rest = "<ns>/<repo>" (ns may be empty)
    if "/" in rest:
        ns, repo = rest.split("/", 1)
    else:
        ns, repo = "library", rest
    return ns, repo, tag, digest


KEYSEP = "\x00"


# ---------------------------------------------------------------------------
# Phase 3+4
# ---------------------------------------------------------------------------
def main():
    t0 = time.time()
    log("PHASE 1: Mongo dumps")
    dump_mongo()
    log("PHASE 2: Neo4j stream")
    dump_neo4j()

    # node ids here are Neo4j internal ids id(n) -> used directly as array indices.

    # ---- load top layers, parse refs, collect needed repos; track max id ----
    log("PHASE 3: load top layers + parse refs")
    top_images = {}         # int node id -> list[ref]
    needed_repos = set()    # "ns\x00repo"
    ref_parsed = {}         # ref -> (ns, repo, tag, digest)
    max_id = 0
    with gzip.open(TOPLAYERS_GZ, "rt") as f:
        for line in f:
            tab = line.index("\t")
            ni = int(line[:tab])
            if ni > max_id:
                max_id = ni
            imgs = json.loads(line[tab + 1:])
            top_images[ni] = imgs
            for ref in imgs:
                pr = ref_parsed.get(ref)
                if pr is None:
                    pr = parse_ref(ref)
                    ref_parsed[ref] = pr
                needed_repos.add(pr[0] + KEYSEP + pr[1])
    n_top = len(top_images)
    log("  top layers:", n_top, " distinct image refs:", len(ref_parsed), " distinct repos referenced:", len(needed_repos), " max top-layer id:", max_id)

    # ---- load only the needed repo pull counts ----
    log("PHASE 3: load repo pull counts (referenced only)")
    repo_pull = {}          # "ns\x00repo" -> int
    seen = 0
    with gzip.open(REPO_PULL_GZ, "rt") as f:
        for line in f:
            ns, nm, pc = line.rstrip("\n").split("\t")
            k = ns + KEYSEP + nm
            if k in needed_repos:
                repo_pull[k] = int(pc)
            seen += 1
            if seen % 4_000_000 == 0:
                log("  scanned repos:", seen)
    log("  repos with pull_count found:", len(repo_pull), "of", len(needed_repos), "referenced")
    del needed_repos

    # ---- edges: pass 1 find max id, pass 2 fill parent[] ----
    log("PHASE 3: load edges - pass 1 (max id)")
    n_edges = 0
    with gzip.open(EDGES_GZ, "rt") as f:
        for line in f:
            tab = line.index("\t")
            pi = int(line[:tab]); ci = int(line[tab + 1:])
            if pi > max_id:
                max_id = pi
            if ci > max_id:
                max_id = ci
            n_edges += 1
            if n_edges % 8_000_000 == 0:
                log("  pass1 edges:", n_edges)
    n_slots = max_id + 1
    log("  edges:", n_edges, " max id:", max_id, " -> array slots:", n_slots)
    if n_slots > 250_000_000:
        log("  ERROR: max internal id too large (%d); id space is sparse, switch to dict-keyed approach." % max_id)
        sys.exit(2)

    log("PHASE 3: allocate parent[] + pass 2 (fill)")
    parent = array.array("q", b"\xff" * (8 * n_slots))   # all bytes 0xff -> every int64 == -1
    multiparent = 0
    with gzip.open(EDGES_GZ, "rt") as f:
        for line in f:
            tab = line.index("\t")
            pi = int(line[:tab]); ci = int(line[tab + 1:])
            if parent[ci] != -1 and parent[ci] != pi:
                multiparent += 1
            parent[ci] = pi
    log("  multiparent (distinct conflicting):", multiparent)
    if multiparent:
        log("  WARNING: graph not a pure forest; subtree-sum metric may double-count shared descendants.")
    # childcount derived from parent[] -> counts each child once (immune to duplicate edges)
    childcount = array.array("q", bytes(8 * n_slots))
    n_roots = 0
    for ci in range(n_slots):
        pa = parent[ci]
        if pa == -1:
            n_roots += 1
        else:
            childcount[pa] += 1
    log("  roots (incl. unused id slots):", n_roots)

    # ---- per-node w/p seed + subtree sums ----
    log("PHASE 3: seed per-node w/p + subtree sums")
    sub_w = array.array("q", bytes(8 * n_slots))   # becomes subtree sum of image-count (incl self)
    sub_p = array.array("q", bytes(8 * n_slots))   # becomes subtree sum of repo-pull-sum (incl self)
    self_w = {}             # node -> len(images)            (top layers only)
    self_p = {}             # node -> sum repo pull over refs (top layers only)
    for ni, imgs in top_images.items():
        s = 0
        for ref in imgs:
            pr = ref_parsed[ref]
            s += repo_pull.get(pr[0] + KEYSEP + pr[1], 0)
        lw = len(imgs)
        sub_w[ni] = lw
        sub_p[ni] = s
        self_w[ni] = lw
        self_p[ni] = s

    # Kahn from leaves: process node when childcount==0, add its subtree to parent.
    q = deque(i for i in range(n_slots) if childcount[i] == 0)
    processed = 0
    while q:
        i = q.popleft()
        processed += 1
        pa = parent[i]
        if pa != -1:
            sub_w[pa] += sub_w[i]
            sub_p[pa] += sub_p[i]
            childcount[pa] -= 1
            if childcount[pa] == 0:
                q.append(pa)
        if processed % 8_000_000 == 0:
            log("  subtree-processed:", processed)
    log("  processed nodes:", processed, "of", n_slots, "slots")
    if processed != n_slots:
        log("  WARNING: not all slots processed (cycle?). processed=%d slots=%d" % (processed, n_slots))
    del childcount, parent

    # ---- representative tag per (ns,repo) ----
    log("PHASE 4: load tags for representative-tag selection")
    has_latest = set()
    best_active = {}        # "ns\x00repo" -> (last_updated, tag)
    best_any = {}
    with gzip.open(TAGS_GZ, "rt") as f:
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 5:
                parts += [""] * (5 - len(parts))
            ns, nm, tg, lu, st = parts[0], parts[1], parts[2], parts[3], parts[4]
            key = ns + KEYSEP + nm
            if tg == "latest":
                has_latest.add(key)
            cur = best_any.get(key)
            if cur is None or lu > cur[0]:
                best_any[key] = (lu, tg)
            if st == "active":
                cura = best_active.get(key)
                if cura is None or lu > cura[0]:
                    best_active[key] = (lu, tg)

    def repr_tag(key):
        if key in has_latest:
            return "latest"
        v = best_active.get(key)
        if v is not None:
            return v[1]
        v = best_any.get(key)
        if v is not None:
            return v[1]
        return "latest"

    # ---- dedup by Layer node ----
    # Images with the SAME top-layer node have identical content (the same layer stack).
    # Scanning all of them is redundant. For each node, we keep only the repo with the highest pull_count
    # (the most "canonical" of the content). Rebrands with 0 pulls do not enter the queue.
    # Repos with few pulls that "inherit" the downstream of base nodes (e.g. alpine) should not
    # appear as canonical representatives — they only confuse the ranking with test-pushes.
    MIN_CANONICAL_PULLS = int(os.environ.get("MIN_CANONICAL_PULLS", "1000"))
    log(f"PHASE 4: dedup by layer node (keep the most popular repo per identical content; min_pulls={MIN_CANONICAL_PULLS})")
    layer_best_ref = {}   # ni -> ref
    n_deduplicated = 0
    n_skipped_low_pull = 0
    for ni, imgs in top_images.items():
        best_ref, best_pc = None, -1
        for ref in imgs:
            ns, repo, _, _ = ref_parsed[ref]
            pc = repo_pull.get(ns + KEYSEP + repo, 0)
            if pc > best_pc:
                best_pc = pc
                best_ref = ref
        if best_ref and best_pc >= MIN_CANONICAL_PULLS:
            layer_best_ref[ni] = best_ref
            n_deduplicated += len(imgs) - 1
        elif best_ref:
            n_skipped_low_pull += 1
    log(f"  layer nodes kept: {len(layer_best_ref)}  refs discarded due to duplicate content: {n_deduplicated}  nodes skipped (winner <{MIN_CANONICAL_PULLS} pulls): {n_skipped_low_pull}")

    # ---- rank ----
    log("PHASE 4: rank images")
    best = {}   # "ns\x00repo" -> (chosen_dict, matched_bool)
    n_refs = 0
    for ni, ref in layer_best_ref.items():
        ns, repo, tag, digest = ref_parsed[ref]
        key = ns + KEYSEP + repo
        pc = repo_pull.get(key, 0)
        # use only the pc of best_ref — self_p[ni] sums ALL repos on the node (includes rebrands)
        # and distorts dps for repos with few pulls that share a node with something huge
        dps = sub_p[ni] - pc
        dw = sub_w[ni] - self_w[ni]
        exposure = pc + dps
        rt = repr_tag(key)
        matched = (tag == rt)
        cand = {
            "repository_namespace": ns,
            "repository_name": repo,
            "tag_name": rt,
            "image_digest": digest,
            "pull_count": pc,
            "dependency_weight": dw,
            "downstream_pull_sum": dps,
            "exposure": exposure,
        }
        rec = best.get(key)
        if rec is None:
            best[key] = (cand, matched)
        else:
            cur, cur_matched = rec
            if matched and not cur_matched:
                best[key] = (cand, True)
            elif matched == cur_matched:
                if exposure > cur["exposure"]:
                    best[key] = (cand, matched)
        n_refs += 1
        if n_refs % 1_000_000 == 0:
            log("  refs:", n_refs)
    log("  total graph image refs:", n_refs, " distinct repos:", len(best))

    rows = []
    for cand, _ in best.values():
        cand = dict(cand)
        cand["weights"] = cand["exposure"]
        rows.append(cand)
    rows.sort(key=lambda r: (r["exposure"], r["pull_count"], r["dependency_weight"]), reverse=True)

    log("PHASE 4: writing output", OUT_PATH)
    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w") as f:
        for r in rows:
            f.write(json.dumps(r, separators=(",", ":")) + "\n")
    os.replace(tmp, OUT_PATH)
    log("DONE. rows:", len(rows), " elapsed: %.1fs" % (time.time() - t0))
    if rows:
        log("exposure max:", rows[0]["exposure"], " min:", rows[-1]["exposure"])
        log("top 5:")
        for r in rows[:5]:
            print(json.dumps(r, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
