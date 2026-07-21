#!/usr/bin/env bash
# Download and reassemble the released dataset from its public GitHub release.
#
# Uses plain curl against the public release assets — no gh CLI, no login. Reads
# the MANIFEST, downloads every part, verifies each part's checksum and the
# rejoined whole-file digest. Idempotent: a file already present with the right
# digest is skipped.
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

command -v curl >/dev/null || { echo "curl required" >&2; exit 1; }
[ -n "$OUT" ] || { echo "fetch_dataset.sh: --out DIR is required" >&2; exit 2; }
mkdir -p "$OUT"

BASE="https://github.com/$REPO/releases/download/$TAG"
get() { curl -fSL --retry 5 --retry-delay 5 -o "$2" "$BASE/$1"; }

get MANIFEST.txt "$OUT/MANIFEST.txt"
MANIFEST="$OUT/MANIFEST.txt"

while IFS='|' read -r base sum parts psize role; do
  case "$base" in ''|'#'*) continue ;; esac
  [ -z "$ONLY" ] || [ "$ONLY" = "$role" ] || continue

  if [ -f "$OUT/$base" ] && [ "$(sha256sum "$OUT/$base" | cut -d' ' -f1)" = "$sum" ]; then
    echo "== $base: already present and verified"; continue
  fi

  echo "== $base ($role): downloading $parts parts"
  get "$base.sha256" "$OUT/$base.sha256"
  i=0
  while [ "$i" -lt "$parts" ]; do
    p=$(printf '%s.part%03d' "$base" "$i")
    get "$p" "$OUT/$p"
    i=$((i + 1))
  done
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
