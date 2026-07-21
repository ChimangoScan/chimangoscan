package buildgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ChimangoScan/chimangoscan/myutils"
)

// BuildMetrics tracks Stage II progress with lock-free atomic counters.
// All fields are safe for concurrent use by multiple goroutines.
type BuildMetrics struct {
	startTime  time.Time
	reposTotal int64 // pending repos at startup (denominator for ETA)
	reposDone  int64 // already processed in previous runs (offset for cumulative display)

	Processed       atomic.Int64
	TagCacheHits    atomic.Int64
	TagAPIFetches   atomic.Int64
	ImageCacheHits  atomic.Int64
	ImageAPIFetches atomic.Int64
	Neo4jInserts    atomic.Int64
	Errors          atomic.Int64
}

func newBuildMetrics(threshold int64) *BuildMetrics {
	m := &BuildMetrics{startTime: time.Now()}
	if myutils.GlobalDBClient.MongoFlag {
		var pending, all int64
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); pending, _ = myutils.GlobalDBClient.Mongo.CountPendingBuildRepos(threshold, true) }()
		go func() { defer wg.Done(); all, _ = myutils.GlobalDBClient.Mongo.CountAllEligibleRepos(threshold) }()
		wg.Wait()
		m.reposTotal = pending
		m.reposDone = all - pending
	}
	myutils.Logger.Info(fmt.Sprintf(">>> BUILD METRICS: %d feitos, %d pendentes (total %d)",
		m.reposDone, m.reposTotal, m.reposDone+m.reposTotal))
	return m
}

// startReporter launches a background goroutine that writes a metrics snapshot
// every 60s to both the logger and dataDir/build_metrics.log. Stops when done is closed.
func (m *BuildMetrics) startReporter(dataDir string, done <-chan struct{}) {
	path := filepath.Join(dataDir, "build_metrics.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		myutils.Logger.Error(fmt.Sprintf("metrics log open %s: %v", path, err))
		f = nil
	}
	go func() {
		if f != nil {
			defer f.Close()
		}
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				line := "[FINAL] " + m.snapshot()
				myutils.Logger.Info(line)
				if f != nil {
					fmt.Fprintln(f, line)
				}
				return
			case <-ticker.C:
				line := m.snapshot()
				myutils.Logger.Info(line)
				if f != nil {
					fmt.Fprintln(f, line)
				}
			}
		}
	}()
}

func (m *BuildMetrics) snapshot() string {
	thisRun := m.Processed.Load()
	cumulative := m.reposDone + thisRun
	grandTotal := m.reposDone + m.reposTotal
	elapsed := time.Since(m.startTime)

	pct := 0.0
	if grandTotal > 0 {
		pct = float64(cumulative) / float64(grandTotal) * 100
	}

	// ETA uses current-run rate against remaining pending repos.
	rate := 0.0
	eta := "calculando..."
	if elapsed.Seconds() >= 30 && thisRun > 0 {
		rate = float64(thisRun) / elapsed.Minutes()
		if rate > 0 && m.reposTotal > 0 {
			remaining := m.reposTotal - thisRun
			if remaining > 0 {
				etaDur := time.Duration(float64(remaining)/rate*float64(time.Minute)).Round(time.Minute)
				eta = etaDur.String()
			} else {
				eta = "concluindo..."
			}
		}
	}

	tagTotal := m.TagCacheHits.Load() + m.TagAPIFetches.Load()
	imgTotal := m.ImageCacheHits.Load() + m.ImageAPIFetches.Load()
	tagCachePct, imgCachePct := 0.0, 0.0
	if tagTotal > 0 {
		tagCachePct = float64(m.TagCacheHits.Load()) / float64(tagTotal) * 100
	}
	if imgTotal > 0 {
		imgCachePct = float64(m.ImageCacheHits.Load()) / float64(imgTotal) * 100
	}

	return fmt.Sprintf(
		"[METRICS %s] progresso=%d/%d (%.1f%%) | taxa=%.1f repos/min | ETA=%s | cache tags=%.0f%% imgs=%.0f%% | neo4j=%d | erros=%d | uptime=%s",
		time.Now().Format("15:04:05"),
		cumulative, grandTotal, pct,
		rate, eta,
		tagCachePct, imgCachePct,
		m.Neo4jInserts.Load(),
		m.Errors.Load(),
		elapsed.Round(time.Second),
	)
}
