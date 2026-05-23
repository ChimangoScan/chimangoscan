#!/bin/bash

# ==============================================================================
# DITector Research Pipeline Autopilot
# Rationale: Automates the transition between discovery, graph building, and ranking.
# ==============================================================================

# Configuration
SEED=${1:-"a"}
WORKERS=20
CRAWL_DURATION="30s"
PULL_THRESHOLD=1000
OUTPUT_FILE="final_prioritized_dataset.json"

echo "[1/3] STAGE: Discovery (Parallel Crawl)..."
echo "Running for $CRAWL_DURATION with seed '$SEED'..."
timeout $CRAWL_DURATION go run main.go crawl --workers $WORKERS --seed "$SEED" --accounts accounts.json --config config.yaml

echo -e "\n[2/3] STAGE: Graph Construction (Parallel Build)..."
# Process discovered repos into Neo4j
go run main.go build --format mongo --threshold $PULL_THRESHOLD --page_size 50 --config config.yaml

echo -e "\n[3/3] STAGE: Impact Analysis (Ranking)..."
# Calculate weights and export prioritized list
go run main.go execute --script calculate-node-weights --threshold $PULL_THRESHOLD --file $OUTPUT_FILE --config config.yaml

echo -e "\n=============================================================================="
echo "PIPELINE COMPLETE!"
echo "Final prioritized dataset exported to: $OUTPUT_FILE"
echo "Total repositories discovered: $(docker exec -it ditector_mongo mongosh localhost:27017/dockerhub_data --quiet --eval 'db.repositories_data.countDocuments()')"
echo "=============================================================================="
