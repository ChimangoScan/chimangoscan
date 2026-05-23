#!/usr/bin/env bash
# Shared helper sourced by the orchestration scripts so that every stage runs
# inside the AnonymousSystem runner image. The host only needs Docker installed.
#
#   ensure_runner          build the runner image once (no-op if it exists)
#   in_runner CMD...       run CMD inside the runner image with:
#       --network host                reach the MongoDB / Neo4j containers on 127.0.0.1
#       -v $ROOT:$ROOT (same path)    repo, submodules and artifacts, paths unchanged
#       -v /var/run/docker.sock       Stage III starts the scanner containers (siblings)
#       persistent go / uv caches     fast re-runs
#
# Callers may set, per invocation:
#   RUNNER_WORKDIR        working directory inside the container (default: $ROOT)
#   RUNNER_EXTRA_MOUNT    extra "-v /host/path:/host/path" args (e.g. the analysis DB)
#
# $ROOT must be set by the sourcing script (the repository root).

RUNNER_IMG="${RUNNER_IMG:-anonymoussystem/runner:local}"

ensure_runner() {
  if ! docker image inspect "$RUNNER_IMG" >/dev/null 2>&1; then
    echo "=== building runner image $RUNNER_IMG (one-time, a few minutes) ==="
    docker build -t "$RUNNER_IMG" -f "$ROOT/docker/Dockerfile.runner" "$ROOT/docker"
  fi
}

in_runner() {
  docker run --rm \
    --network host \
    -e MPLBACKEND=Agg -e MPLCONFIGDIR=/tmp/mpl \
    -v "$ROOT:$ROOT" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v anonymoussystem-gocache:/go \
    -v anonymoussystem-uvcache:/root/.cache/uv \
    ${RUNNER_EXTRA_MOUNT:-} \
    -w "${RUNNER_WORKDIR:-$ROOT}" \
    "$RUNNER_IMG" "$@"
}
