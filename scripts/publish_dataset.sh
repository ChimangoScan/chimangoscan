#!/usr/bin/env bash
# Publish the released dataset as split assets on a GitHub release.
#
# Each dataset file (already compressed) is split into parts below GitHub's
# 2 GB per-asset limit, checksummed, and uploaded. A committed MANIFEST records
# the whole-file digest and part list so fetch_dataset.sh can rejoin and verify.
#
# Usage: scripts/publish_dataset.sh [--tag TAG] [--repo OWNER/REPO] [--dry-run]
# Env:   DATASET_SRC (dir holding the files in dataset/dataset.conf; required
#        unless the paths are absolute), PART_SIZE (default 1900M).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT/dataset/dataset.conf"
MANIFEST="$ROOT/dataset/MANIFEST.txt"
TAG="dataset-v1"
REPO="ChimangoScan/chimangoscan"
PART_SIZE="${PART_SIZE:-1900M}"
DRY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --repo) REPO="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "publish_dataset.sh: unknown option '$1'" >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh CLI required" >&2; exit 1; }
[ -f "$CONF" ] || { echo "missing $CONF" >&2; exit 1; }

# Split parts are staged NEXT TO each source file (same filesystem, guaranteed
# space) unless DATASET_WORK overrides it. Never /tmp: a multi-GB split there
# fills the host tmpfs. The staging dir is cleaned per file.
SRC="${DATASET_SRC:-$ROOT/dataset}"

if [ "$DRY" = 0 ]; then
  gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1 \
    || gh release create "$TAG" --repo "$REPO" --title "ChimangoScan dataset ($TAG)" \
         --notes "Split, checksummed dataset assets. Rejoin with scripts/fetch_dataset.sh." --draft
fi

: > "$MANIFEST"
echo "# file|sha256|parts|part_size|role  (rejoin: cat file.part* > file)" >> "$MANIFEST"

while IFS='|' read -r path base role; do
  case "$path" in ''|'#'*) continue ;; esac
  case "$path" in /*) f="$path" ;; *) f="$SRC/$path" ;; esac
  [ -f "$f" ] || { echo "publish: SKIP $base (source not found: $f)" >&2; continue; }

  WORK="${DATASET_WORK:-$(dirname "$f")/.chimango_publish}"
  mkdir -p "$WORK"
  echo "== $base ($role): hashing"
  sum="$(sha256sum "$f" | cut -d' ' -f1)"
  echo "   splitting into $PART_SIZE parts under $WORK"
  split -b "$PART_SIZE" -d -a 3 "$f" "$WORK/$base.part"
  parts=("$WORK/$base.part"*)
  echo "$base|$sum|${#parts[@]}|$PART_SIZE|$role" >> "$MANIFEST"
  ( cd "$WORK" && sha256sum "$base.part"* > "$base.sha256" )

  if [ "$DRY" = 0 ]; then
    echo "   uploading ${#parts[@]} parts + checksums"
    gh release upload "$TAG" --repo "$REPO" --clobber "${parts[@]}" "$WORK/$base.sha256"
  else
    echo "   [dry-run] ${#parts[@]} parts, whole-file sha256 $sum"
  fi
  rm -f "$WORK/$base.part"* "$WORK/$base.sha256"; rmdir "$WORK" 2>/dev/null || true
done < "$CONF"

[ "$DRY" = 0 ] && gh release upload "$TAG" --repo "$REPO" --clobber "$MANIFEST"
echo "done: manifest at $MANIFEST"
