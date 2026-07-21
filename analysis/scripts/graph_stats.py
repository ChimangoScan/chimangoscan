#!/usr/bin/env python3
"""Compute the headline statistics of the ChimangoScan layer graph (Neo4j).

Writes a JSON file with:
  total_nodes          all nodes                     (count store, paper: 84.7M)
  is_base_of_edges     IS_BASE_OF relationships      (count store, paper: 54,382,383)
  image_bearing_nodes  Layer nodes with a non-empty images property
                       (one label scan, paper: 4,476,440)

Env: NEO4J_URI (default bolt://127.0.0.1:7687), NEO4J_AUTH ("user/pass" or
"none", default none, matching the auth-disabled ephemeral instance),
OUT_PATH (default ./graph_stats.json).
"""
import json
import os
import time

from neo4j import GraphDatabase

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://127.0.0.1:7687")
NEO4J_AUTH = os.environ.get("NEO4J_AUTH", "none")
OUT_PATH = os.environ.get("OUT_PATH", "./graph_stats.json")

QUERIES = {
    "total_nodes": "MATCH (n) RETURN count(n) AS c",
    "is_base_of_edges": "MATCH ()-[r:IS_BASE_OF]->() RETURN count(r) AS c",
    "image_bearing_nodes": ("MATCH (l:Layer) WHERE l.images IS NOT NULL "
                            "AND size(l.images) > 0 RETURN count(l) AS c"),
}


def auth():
    if NEO4J_AUTH in ("", "none"):
        return None
    user, _, password = NEO4J_AUTH.partition("/")
    return (user, password)


def main():
    drv = GraphDatabase.driver(NEO4J_URI, auth=auth())
    stats = {}
    with drv.session() as s:
        for key, q in QUERIES.items():
            t0 = time.time()
            stats[key] = s.run(q).single()["c"]
            print("%s = %d (%.1fs)" % (key, stats[key], time.time() - t0), flush=True)
    drv.close()
    tmp = OUT_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(stats, f, indent=1)
    os.replace(tmp, OUT_PATH)
    print("wrote", OUT_PATH)


if __name__ == "__main__":
    main()
