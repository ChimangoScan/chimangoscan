#!/bin/bash
# benchmark_low.sh — focused on finding the sweet spot with few workers.
#
# Usage: bash automation/benchmark_low.sh

set -e
cd "$(dirname "$0")/.."

MEASURE_SECS=180
COMPILE_WAIT=45    # Already compiled from the previous run
RESULTS_FILE="benchmark_low_results_$(date +%Y%m%d_%H%M%S).txt"

mongo_count() {
    docker exec chimangoscan_mongo mongosh --quiet \
        --eval 'db.getSiblingDB("dockerhub_data").repositories_data.countDocuments()' 2>/dev/null || echo 0
}

wait_for_crawler() {
    local max=120
    local i=0
    echo -n "    Waiting for crawler to connect..."
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
    echo "CONFIG: $label  (workers=$workers, PC=$page_conc)"
    echo "========================================"

    docker-compose stop crawler 2>/dev/null
    docker-compose rm -f crawler 2>/dev/null
    WORKERS=$workers PAGE_CONCURRENCY=$page_conc docker-compose up -d crawler 2>/dev/null

    echo "    Starting (waiting ${COMPILE_WAIT}s)..."
    sleep $COMPILE_WAIT
    wait_for_crawler || { echo "    ERROR: crawler did not start"; return; }
    sleep 15

    local t0=$(date +%s)
    local c0=$(mongo_count)
    echo "    [t=0s] repos: $c0"

    for i in 60 120 180; do
        sleep 60
        local c=$(mongo_count)
        local elapsed=$(( $(date +%s) - t0 ))
        local added=$((c - c0))
        local rate=$(echo "scale=1; $added * 60 / $elapsed" | bc 2>/dev/null || echo "?")
        echo "    [t=${elapsed}s] repos: $c  (+${added})  rate: ${rate} repos/min"
    done

    local c1=$(mongo_count)
    local total_added=$((c1 - c0))
    local rate_avg=$(echo "scale=1; $total_added * 60 / $MEASURE_SECS" | bc 2>/dev/null || echo "?")

    echo "    RESULT: +${total_added} repos in ${MEASURE_SECS}s = ${rate_avg} repos/min"
    echo "$label | workers=$workers | page_conc=$page_conc | repos/min=$rate_avg" >> "$RESULTS_FILE"
}

echo "Benchmark Low Concurrency ChimangoScan" > "$RESULTS_FILE"
echo "Date: $(date)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

run_config "W15_PC8"  15  8
run_config "W10_PC8"  10  8
run_config "W5_PC8"    5  8
run_config "W2_PC8"    2  8
run_config "W1_PC8"    1  8
run_config "W5_PC16"   5 16

echo ""
echo "========================================"
echo "FINAL RESULTS"
echo "========================================"
cat "$RESULTS_FILE"
