#!/usr/bin/env bash
# Download and reassemble the released dataset from its GitHub release.
#
# Reads MANIFEST from the release, downloads every part, verifies each part's
# checksum and the rejoined whole-file digest. Idempotent: a file already
# present with the right digest is skipped.
#
# Usage: scripts/fetch_dataset.sh --out DIR [--tag TAG] [--repo OWNER/REPO]
#                                 [--only ROLE]
set -euo pipefail

TAG="dataset-v1"
REPO="ChimangoScan/chimangoscan"
OUT=""
ONLY=""

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2 ;;
    --tag) TAG="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    *) echo "fetch_dataset.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh CLI required" >&2; exit 1; }
[ -n "$OUT" ] || { echo "fetch_dataset.sh: --out DIR is required" >&2; exit 2; }
mkdir -p "$OUT"

gh release download "$TAG" --repo "$REPO" --pattern MANIFEST.txt --dir "$OUT" --clobber
MANIFEST="$OUT/MANIFEST.txt"

while IFS='|' read -r base sum parts psize role; do
  case "$base" in ''|'#'*) continue ;; esac
  [ -z "$ONLY" ] || [ "$ONLY" = "$role" ] || continue

  if [ -f "$OUT/$base" ] && [ "$(sha256sum "$OUT/$base" | cut -d' ' -f1)" = "$sum" ]; then
    echo "== $base: already present and verified"; continue
  fi

  echo "== $base ($role): downloading $parts parts"
  gh release download "$TAG" --repo "$REPO" --pattern "$base.part*" --pattern "$base.sha256" \
     --dir "$OUT" --clobber
  ( cd "$OUT" && sha256sum -c "$base.sha256" --quiet ) \
     || { echo "fetch: part checksum mismatch for $base" >&2; exit 1; }

  echo "   rejoining -> $base"
  cat "$OUT/$base.part"* > "$OUT/$base"
  got="$(sha256sum "$OUT/$base" | cut -d' ' -f1)"
  [ "$got" = "$sum" ] || { echo "fetch: whole-file digest mismatch for $base ($got != $sum)" >&2; exit 1; }
  rm -f "$OUT/$base.part"* "$OUT/$base.sha256"
  echo "   verified $base"
done < "$MANIFEST"

echo "dataset ready in $OUT"
