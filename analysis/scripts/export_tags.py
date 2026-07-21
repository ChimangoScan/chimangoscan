#!/usr/bin/env python3
"""
Export `tags_full.jsonl` from the Stage I/II MongoDB: one JSON line per
document of `tags_data`, with the fields recount_repo.py's load_tagmap()
consumes (repositories_namespace, repositories_name, name, last_updated).
Streaming cursor, constant memory.

ENVIRONMENT
  MONGO_URI  mongodb://127.0.0.1:27017
  MONGO_DB   dockerhub_data
  OUT        tags_full.jsonl
"""
import json
import os
import sys

from pymongo import MongoClient

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.environ.get("MONGO_DB", "dockerhub_data")
OUT = os.environ.get("OUT", "tags_full.jsonl")

FIELDS = ["repositories_namespace", "repositories_name", "name",
          "last_updated"]


def main():
    cli = MongoClient(MONGO_URI)
    cursor = cli[MONGO_DB].tags_data.find(
        {}, {f: 1 for f in FIELDS} | {"_id": 0}, batch_size=20000)
    tmp = OUT + ".tmp"
    n = 0
    with open(tmp, "w") as fh:
        for doc in cursor:
            fh.write(json.dumps(doc, default=str) + "\n")
            n += 1
    os.replace(tmp, OUT)
    cli.close()
    sys.stderr.write("wrote %s (%d tags)\n" % (OUT, n))


if __name__ == "__main__":
    main()
