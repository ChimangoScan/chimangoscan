#!/bin/bash
# End-to-End Integration Test — validates the full 3-stage pipeline with a
# minimal real crawl using an isolated test database.
#
# Network architecture (no "expose"):
#   - This script and the Go binary run directly on the host.
#   - MongoDB runs natively on 127.0.0.1:27017 (no container).
#   - Neo4j runs (or is started) in Docker with a port-map of localhost:7687.
#   - The test binary uses the 'dockerhub_e2e' database (isolated from the prod crawler).
#
# Expected time: ~60 s (+ up to 60 s of Neo4j startup the first time)

set -euo pipefail

# ── config ────────────────────────────────────────────────────────────────────
SEED="nginx"
THRESHOLD="100000000"   # 100 M+ pulls → limits Stage II to ~2 repos
WORKERS="3"
CRAWL_TIMEOUT="20"
BUILD_TIMEOUT="60"
OUTPUT="/tmp/ditector_e2e_output.json"
BINARY="/tmp/ditector_e2e"
E2E_DB="dockerhub_e2e"                   # ISOLATED database — does not conflict with the crawler
E2E_CONFIG="/tmp/ditector_e2e_config.yaml"

_step() { echo ""; echo "[${1}] ${2}"; }
_ok()   { echo "      ✓ ${1}"; }
_fail() { echo "      ✗ ${1}"; exit 1; }

echo "=== DITector E2E Test  seed='${SEED}'  threshold=${THRESHOLD} ==="

# Build a temporary config pointing at the isolated test database.
# Reads the real config only to inherit rule/account paths; replaces the DB.
DB_LINE=$(grep -A2 'mongo_config:' config.yaml | grep 'uri:' | sed "s/'[^']*'/'mongodb:\/\/localhost:27017'/" || echo "  uri: 'mongodb://localhost:27017'")
cat > "$E2E_CONFIG" <<YAML
max_thread: 0
log_file: '/tmp/ditector_e2e'
repo_with_many_tags_file: '/tmp/ditector_e2e_repos.txt'
tmp_dir: '/tmp'
proxy:
  http_proxy: ''
  https_proxy: ''
mongo_config:
  uri: 'mongodb://localhost:27017'
  database: '${E2E_DB}'
  collections:
    repositories: 'repositories_data'
    tags: 'tags_data'
    images: 'images_data'
    image_results: 'image_results'
    layer_results: 'layer_results'
    user: 'user'
neo4j_config:
  neo4j_uri: 'neo4j://localhost:7687'
  neo4j_username: 'neo4j'
  neo4j_password: ''
rules_config:
  secret_rules_file: 'rules/secret_rules.yaml'
  sensitive_param_rules_file: 'rules/sensitive_param_rules.yaml'
trufflehog_config:
  filepath: ''
  verify: false
anchore_config:
  filepath: ''
YAML

# ── 0. prerequisites ──────────────────────────────────────────────────────────
_step "0/4" "Prerequisites..."

[ -f accounts.json ] || _fail "accounts.json not found in $(pwd)"

mongosh --eval "db.runCommand({ping:1})" --quiet &>/dev/null \
    || _fail "MongoDB not reachable at localhost:27017"
_ok "MongoDB up (native)"

if ! nc -z localhost 7687 &>/dev/null 2>&1; then
    echo "      Neo4j is not running — starting container..."
    docker compose --profile db up -d neo4j 2>&1 | grep -v "^time=" || true
    echo -n "      Waiting for port 7687 (up to 60 s)"
    for _ in $(seq 1 30); do
        sleep 2
        nc -z localhost 7687 &>/dev/null && break
        echo -n "."
    done
    echo ""
    nc -z localhost 7687 &>/dev/null || _fail "Neo4j did not become ready in 60 s"
fi
_ok "Neo4j up (docker, localhost:7687)"

# Clean the isolated test database
mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval "db.dropDatabase();" &>/dev/null || true
rm -f "$OUTPUT"
_ok "Database '${E2E_DB}' cleaned"

# ── compile ─────────────────────────────────────────────────────────────────
echo ""
echo "[pre] Compiling..."
go build -o "$BINARY" . 2>&1 || _fail "go build failed"
_ok "Binary: $BINARY"

# ── 1. Stage I — Crawl ───────────────────────────────────────────────────────
_step "1/4" "CRAWL  seed='${SEED}'  workers=${WORKERS}  timeout=${CRAWL_TIMEOUT}s..."

timeout "${CRAWL_TIMEOUT}s" "$BINARY" crawl \
    --workers  "$WORKERS" \
    --seed     "$SEED" \
    --accounts accounts.json \
    --config   "$E2E_CONFIG" &>/dev/null || true   # exit by timeout is expected

REPO_COUNT=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.repositories_data.countDocuments()' 2>/dev/null || echo 0)
_ok "Repos discovered: $REPO_COUNT"
[ "$REPO_COUNT" -gt 0 ] || _fail "No repo discovered — check accounts.json and network"

NS_OK=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.repositories_data.countDocuments({namespace:{$ne:""}})' 2>/dev/null || echo 0)
_ok "With correct namespace: $NS_OK / $REPO_COUNT"

# ── 2. Stage II — Build ───────────────────────────────────────────────────────
_step "2/4" "BUILD  threshold=${THRESHOLD}  timeout=${BUILD_TIMEOUT}s..."

timeout "${BUILD_TIMEOUT}s" "$BINARY" build \
    --format    mongo \
    --threshold "$THRESHOLD" \
    --accounts  accounts.json \
    --config    "$E2E_CONFIG" \
    --data_dir  /tmp &>/dev/null || true

BUILT=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.repositories_data.countDocuments({graph_built_at:{$exists:true}})' 2>/dev/null || echo 0)
TAG_COUNT=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.tags_data.countDocuments()' 2>/dev/null || echo 0)
IMG_COUNT=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.images_data.countDocuments()' 2>/dev/null || echo 0)

_ok "Repos with graph_built_at: $BUILT"
_ok "Tags saved in MongoDB: $TAG_COUNT"
_ok "Images saved in MongoDB: $IMG_COUNT"
[ "$BUILT"     -gt 0 ] || _fail "No repo built — check the Neo4j connection and accounts.json"
[ "$TAG_COUNT" -gt 0 ] || _fail "No tag saved — regression in the getTags fix #1"
[ "$IMG_COUNT" -gt 0 ] || _fail "No image saved — regression in persistImages"

# Verify that the rich ImageInTag metadata was preserved (fix #2):
# at least one tag must have the images.status field populated.
STATUS_OK=$(mongosh "localhost:27017/${E2E_DB}" --quiet \
    --eval 'db.tags_data.countDocuments({"images.status":{$exists:true,$ne:""}})' 2>/dev/null || echo 0)
_ok "Tags with images.status preserved: $STATUS_OK"
[ "$STATUS_OK" -gt 0 ] || _fail "images.status empty — regression in the ImageInTag overwrite (fix #2)"

# ── 3. Stage III — Rank ───────────────────────────────────────────────────────
_step "3/4" "RANK  threshold=${THRESHOLD}  page_size=3..."

"$BINARY" execute \
    --script    calculate-node-weights \
    --threshold "$THRESHOLD" \
    --page_size 3 \
    --file      "$OUTPUT" \
    --config    "$E2E_CONFIG" &>/dev/null || _fail "calculate-node-weights failed"

[ -f "$OUTPUT" ] || _fail "Output file not generated: $OUTPUT"
RECORD_COUNT=$(wc -l < "$OUTPUT")
_ok "Output: $OUTPUT  ($RECORD_COUNT records)"
[ "$RECORD_COUNT" -gt 0 ] || _fail "Output file is empty"

# ── 4. Verify output ──────────────────────────────────────────────────────────
_step "4/4" "Verifying output..."

NS_IN_OUTPUT=$(grep -c '"repository_namespace":"[^"]' "$OUTPUT" 2>/dev/null || echo 0)
_ok "Records with repository_namespace: $NS_IN_OUTPUT / $RECORD_COUNT"
[ "$NS_IN_OUTPUT" -gt 0 ] || _fail "No record with a namespace in the output"

echo ""
echo "      Sample (first record):"
head -n 1 "$OUTPUT" | python3 -m json.tool 2>/dev/null || head -n 1 "$OUTPUT"
echo ""

# Clean the test database at the end
mongosh "localhost:27017/${E2E_DB}" --quiet --eval "db.dropDatabase();" &>/dev/null || true
rm -f "$E2E_CONFIG" "$OUTPUT"

echo "=== RESULT: PASSED ==="
