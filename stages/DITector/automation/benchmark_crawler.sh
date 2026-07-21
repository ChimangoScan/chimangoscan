#!/bin/bash
# benchmark_crawler.sh — empirically tests workers and PAGE_CONCURRENCY
# Measures repos/min added to MongoDB for each configuration.
#
# Usage: bash automation/benchmark_crawler.sh
# Total duration: ~30 min (5 configs × ~6 min each)

set -e
cd "$(dirname "$0")/.."

MEASURE_SECS=180   # 3 min of measurement per config
COMPILE_WAIT=90    # wait time for the Go compilation on the first run
RESULTS_FILE="benchmark_results_$(date +%Y%m%d_%H%M%S).txt"

mongo_count() {
    docker exec chimangoscan_mongo mongosh --quiet \
        --eval 'db.getSiblingDB("dockerhub_data").repositories_data.countDocuments()' 2>/dev/null || echo 0
}

wait_for_crawler() {
    local max=120
    local i=0
    echo -n "    Aguardando crawler conectar ao MongoDB..."
    while ! docker logs chimangoscan_crawler 2>&1 | grep -q "Connect to MongoDB"; do
        sleep 3; i=$((i+3))
        if [ $i -ge $max ]; then echo " timeout"; return 1; fi
        echo -n "."
    done
    echo " OK"
}

run_config() {
    local label="$1"
    local workers="$2"
    local page_conc="$3"

    echo ""
    echo "========================================"
    echo "CONFIG: $label  (workers=$workers, PAGE_CONCURRENCY=$page_conc)"
    echo "========================================"

    # Restart the container with the new config
    docker-compose stop crawler 2>/dev/null
    docker-compose rm -f crawler 2>/dev/null
    WORKERS=$workers PAGE_CONCURRENCY=$page_conc docker-compose up -d crawler 2>/dev/null

    # Wait for compilation + connection
    echo "    Compiling and starting (waiting ${COMPILE_WAIT}s)..."
    sleep $COMPILE_WAIT
    wait_for_crawler || { echo "    ERROR: crawler did not start"; return; }

    # Let it stabilize 15s after connecting
    sleep 15

    # Measure for MEASURE_SECS
    local t0=$(date +%s)
    local c0=$(mongo_count)
    echo "    [t=0s] repos in MongoDB: $c0"

    # Samples every 30s
    local samples=()
    for i in 30 60 90 120 150 180; do
        sleep 30
        local c=$(mongo_count)
        local elapsed=$(( $(date +%s) - t0 ))
        local added=$((c - c0))
        local rate=$(echo "scale=1; $added * 60 / $elapsed" | bc 2>/dev/null || echo "?")
        echo "    [t=${elapsed}s] repos: $c  (+${added})  taxa: ${rate} repos/min"
        samples+=("$rate")
    done

    local c1=$(mongo_count)
    local total_added=$((c1 - c0))
    local rate_avg=$(echo "scale=1; $total_added * 60 / $MEASURE_SECS" | bc 2>/dev/null || echo "?")

    echo "    RESULTADO: +${total_added} repos em ${MEASURE_SECS}s = ${rate_avg} repos/min"
    echo "$label | workers=$workers | page_conc=$page_conc | repos/min=$rate_avg | total_added=$total_added" >> "$RESULTS_FILE"
}

echo "Benchmark Crawler ChimangoScan" > "$RESULTS_FILE"
echo "Data: $(date)" >> "$RESULTS_FILE"
echo "GPU1 — $(docker exec chimangoscan_mongo mongosh --quiet --eval 'db.version()' 2>/dev/null)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# The first run compiles the binary — the following ones reuse it if the volume is the same.
# The binary lives in /tmp/chimangoscan (inside the container) — if the container is removed, it recompiles.
# To avoid recompiling: use an extra volume or leave the container stopped (not removed).
# Here: we compile to /app/chimangoscan_bin, which is mounted on the .:/app volume

# Configs to test: workers × page_concurrency
run_config "W25_PC8"   25  8
run_config "W50_PC8"   50  8
run_config "W100_PC8" 100  8
run_config "W50_PC4"   50  4
run_config "W50_PC16"  50 16

echo ""
echo "========================================"
echo "FINAL RESULTS"
echo "========================================"
cat "$RESULTS_FILE"
echo ""
echo "File saved to: $RESULTS_FILE"

# Restore the default config
WORKERS=50 PAGE_CONCURRENCY=8 docker-compose up -d crawler 2>/dev/null
echo "Crawler restored with the default config (workers=50, PAGE_CONCURRENCY=8)"
