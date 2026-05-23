package buildgraph

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/anonymous/DITector/myutils"
)

type cpEntry struct {
	Namespace string `json:"ns"`
	Name      string `json:"name"`
	BuiltAt   string `json:"built_at"`
	Tags      int    `json:"tags"`
}

// GraphBatch groups all images collected for a single repo so the graphWorker
// can insert them atomically and only mark the repo as built on full success.
type GraphBatch struct {
	Repo *myutils.Repository
	Jobs []GraphJob
	m    *BuildMetrics
}

// StartFromMongo runs the Stage II distributed pipeline.
//
// Multiple machines can run this concurrently — ClaimNextBuildRepo is atomic,
// so no two workers ever process the same repo. On restart, ResetStaleBuildClaims
// recovers any repos that were mid-flight when the previous run crashed.
//
// Progress is checkpointed to dataDir/build_checkpoint.jsonl (host-mounted path)
// so it survives container restarts independently of the Docker daemon.
// Metrics are written every 60s to dataDir/build_metrics.log with ETA.
func StartFromMongo(threshold int64, workers int, ip myutils.IdentityProvider, dataDir string) {
	// Stage II requires both Mongo and Neo4j. Failing fast (and exiting non-zero)
	// lets Docker's restart policy retry until the dependency becomes available,
	// instead of silently proceeding with a nil driver and panicking later.
	if !myutils.GlobalDBClient.MongoFlag {
		myutils.Logger.Error("MongoDB not connected — Stage II cannot start; exiting for restart")
		os.Exit(1)
	}
	if !myutils.GlobalDBClient.Neo4jFlag {
		myutils.Logger.Error("Neo4j not connected — Stage II cannot start; exiting for restart")
		os.Exit(1)
	}
	myutils.GlobalDBClient.Mongo.ResetStaleBuildClaims()

	m := newBuildMetrics(threshold)
	metricsDone := make(chan struct{})
	m.startReporter(dataDir, metricsDone)

	cpCh := make(chan cpEntry, 1000)
	go checkpointWriter(cpCh, dataDir)

	// Async MongoDB cache writes: fire-and-forget so repoWorkers are never
	// blocked waiting for UpdateTag/UpdateImage round-trips.
	writesCh := make(chan func(), 10000)
	go func() {
		for fn := range writesCh {
			fn()
		}
	}()

	numRepo := workers
	if numRepo <= 0 {
		numRepo = 1
	}

	// Large buffer so repoWorkers never block waiting for Neo4j inserts.
	// Mirrors the original jobChan buffer=10000: the repoWorker pipeline
	// (Hub API + jitter) must never stall on graphWorker throughput.
	batchChan := make(chan GraphBatch, 10000)

	numGraph := runtime.NumCPU() * 2
	if numGraph < 8 {
		numGraph = 8
	}
	var wgGraph sync.WaitGroup
	for i := 0; i < numGraph; i++ {
		wgGraph.Add(1)
		go func() {
			defer wgGraph.Done()
			graphWorker(batchChan, cpCh)
		}()
	}

	var wgRepo sync.WaitGroup
	for i := 0; i < numRepo; i++ {
		wgRepo.Add(1)
		go func() {
			defer wgRepo.Done()
			repoWorker(myutils.NewHubClient(ip), threshold, batchChan, cpCh, m, writesCh)
		}()
	}

	wgRepo.Wait()
	close(batchChan)
	wgGraph.Wait()
	close(writesCh)
	close(cpCh)
	close(metricsDone)
}

// repoWorker claims repos one at a time and fetches their tags/images from the
// Hub API. On success it sends a GraphBatch to batchChan and immediately moves
// to the next repo — Neo4j latency does not block it.
func repoWorker(hub *myutils.HubClient, threshold int64, batchChan chan<- GraphBatch, cpCh chan<- cpEntry, m *BuildMetrics, writesCh chan<- func()) {
	emptyCount := 0
	consecutiveFail := 0
	for {
		repo, err := myutils.GlobalDBClient.Mongo.ClaimNextBuildRepo(threshold)
		if err != nil || repo == nil {
			emptyCount++
			if emptyCount%6 == 0 {
				count, _ := myutils.GlobalDBClient.Mongo.CountPendingBuildRepos(threshold, false)
				if count == 0 {
					break
				}
			}
			time.Sleep(2 * time.Second)
			continue
		}
		emptyCount = 0

		batch, ok := collectBatch(hub, repo, m, writesCh)
		if !ok {
			consecutiveFail++
			cool := coolOff(consecutiveFail)
			myutils.Logger.Warn(fmt.Sprintf("!!! collectBatch failed for %s/%s (consecutive=%d), cooling off %s...", repo.Namespace, repo.Name, consecutiveFail, cool))
			time.Sleep(cool)
			continue
		}
		consecutiveFail = 0
		batchChan <- batch
	}
}

// coolOff returns the sleep duration after a collectBatch failure. Short for
// isolated failures (most are single-repo 401/network blips recovered on the
// next repo), ramping up if failures keep stacking (systemic auth/quota issue
// — back off to avoid hammering the Hub).
func coolOff(consecutive int) time.Duration {
	switch {
	case consecutive <= 2:
		return 2 * time.Second
	case consecutive <= 5:
		return 10 * time.Second
	default:
		return 30 * time.Second
	}
}

// collectBatch fetches all tags and images for a repo from the Hub (or Mongo
// cache) and returns a GraphBatch ready to be sent to graphWorker.
// Returns (batch, false) on any API error — the repo stays claimed so
// ResetStaleBuildClaims will retry it on the next run.
func collectBatch(hub *myutils.HubClient, repo *myutils.Repository, m *BuildMetrics, writesCh chan<- func()) (GraphBatch, bool) {
	tags := getTags(hub, repo, m, writesCh)
	if tags == nil {
		return GraphBatch{}, false
	}

	var jobs []GraphJob
	for _, tag := range tags {
		imgs, err := getImages(hub, repo, tag, m, writesCh)
		if err != nil {
			m.Errors.Add(1)
			myutils.Logger.Warn(fmt.Sprintf("getImages %s/%s:%s: %v", repo.Namespace, repo.Name, tag.Name, err))
			return GraphBatch{}, false
		}
		for _, img := range imgs {
			jobs = append(jobs, GraphJob{
				Registry:      "docker.io",
				RepoNamespace: repo.Namespace,
				RepoName:      repo.Name,
				TagName:       tag.Name,
				ImageMeta:     img,
			})
		}
	}
	return GraphBatch{Repo: repo, Jobs: jobs, m: m}, true
}

// graphWorker inserts all images in each batch into Neo4j using a single
// session per batch. Only on full success does it call markBuilt.
func graphWorker(batchChan <-chan GraphBatch, cpCh chan<- cpEntry) {
	for batch := range batchChan {
		items := make([]myutils.ImageInsert, 0, len(batch.Jobs))
		for _, job := range batch.Jobs {
			items = append(items, myutils.ImageInsert{
				Name:  fmt.Sprintf("docker.io/%s/%s:%s@%s", job.RepoNamespace, job.RepoName, job.TagName, job.ImageMeta.Digest),
				Image: job.ImageMeta,
			})
		}
		if err := myutils.GlobalDBClient.Neo4j.InsertBatch(items); err != nil {
			batch.m.Errors.Add(1)
			myutils.Logger.Warn(fmt.Sprintf("!!! Neo4j batch failed for %s/%s — will retry on restart", batch.Repo.Namespace, batch.Repo.Name))
			continue
		}
		batch.m.Neo4jInserts.Add(int64(len(items)))
		markBuilt(batch.Repo, batch.m, cpCh)
	}
}

	// markBuilt sets graph_built_at in MongoDB. Called by graphWorker only after
// all Neo4j inserts for this repo succeed — this is the atomicity guarantee.
func markBuilt(repo *myutils.Repository, m *BuildMetrics, cpCh chan<- cpEntry) {
	if !myutils.GlobalDBClient.MongoFlag {
		return
	}
	if err := myutils.GlobalDBClient.Mongo.MarkRepoGraphBuilt(repo.Namespace, repo.Name); err != nil {
		myutils.Logger.Error(fmt.Sprintf("MarkRepoGraphBuilt %s/%s: %v", repo.Namespace, repo.Name, err))
		m.Errors.Add(1)
		return
	}
	m.Processed.Add(1)
	cpCh <- cpEntry{
		Namespace: repo.Namespace,
		Name:      repo.Name,
		BuiltAt:   time.Now().UTC().Format(time.RFC3339),
	}
}

func getTags(hub *myutils.HubClient, repo *myutils.Repository, m *BuildMetrics, writesCh chan<- func()) []*myutils.Tag {
	if myutils.GlobalDBClient.MongoFlag {
		tags, err := myutils.GlobalDBClient.Mongo.FindAllTagsByRepoName(repo.Namespace, repo.Name)
		if err == nil && len(tags) > 0 && allTagsHaveImages(tags) {
			m.TagCacheHits.Add(1)
			return tags
		}
	}
	// Always fetch the most recently updated tag (page 1, size 1) plus
	// "latest" explicitly. Deduplicate in case they are the same tag.
	recent, err := hub.GetTags(repo.Namespace, repo.Name, 1, 1)
	if err != nil {
		m.Errors.Add(1)
		myutils.Logger.Warn(fmt.Sprintf("GetTags %s/%s: %v", repo.Namespace, repo.Name, err))
		return nil
	}
	m.TagAPIFetches.Add(1)

	tags := recent
	if len(recent) == 0 || recent[0].Name != "latest" {
		latest, err := hub.GetTag(repo.Namespace, repo.Name, "latest")
		if err != nil {
			myutils.Logger.Warn(fmt.Sprintf("GetTag %s/%s:latest: %v", repo.Namespace, repo.Name, err))
		} else if latest != nil {
			tags = append(tags, latest)
		}
	}

	if myutils.GlobalDBClient.MongoFlag {
		for _, t := range tags {
			t := t
			writesCh <- func() { myutils.GlobalDBClient.Mongo.UpdateTag(t) }
		}
	}
	// Both GetTags and GetTag("latest") returned nil+nil → repo was deleted
	// on Docker Hub after the crawl. Return an empty (not nil) slice so
	// collectBatch proceeds to markBuilt with zero jobs; otherwise the repo
	// stays build_claimed forever and the worker burns cooldowns on it.
	if tags == nil {
		tags = []*myutils.Tag{}
	}
	return tags
}

func getImages(hub *myutils.HubClient, repo *myutils.Repository, t *myutils.Tag, m *BuildMetrics, writesCh chan<- func()) ([]*myutils.Image, error) {
	if myutils.GlobalDBClient.MongoFlag && len(t.Images) > 0 {
		if imgs, ok := loadImagesFromCache(t.Images); ok {
			m.ImageCacheHits.Add(1)
			return imgs, nil
		}
	}
	imgs, err := hub.GetImages(repo.Namespace, repo.Name, t.Name)
	if err != nil {
		return nil, err
	}
	m.ImageAPIFetches.Add(1)
	if myutils.GlobalDBClient.MongoFlag {
		persistImages(repo, t, imgs, writesCh)
	}
	return imgs, nil
}

func persistImages(repo *myutils.Repository, t *myutils.Tag, imgs []*myutils.Image, writesCh chan<- func()) {
	for _, img := range imgs {
		img := img
		writesCh <- func() { myutils.GlobalDBClient.Mongo.UpdateImage(img) }
	}
	// t.Images already carries the full ImageInTag payload from the tags API
	// (Features, Variant, Status, LastPulled, LastPushed, etc.) — do not overwrite.
	writesCh <- func() { myutils.GlobalDBClient.Mongo.UpdateTag(t) }
}

func allTagsHaveImages(tags []*myutils.Tag) bool {
	if len(tags) == 0 {
		return false
	}
	for _, t := range tags {
		if len(t.Images) == 0 {
			return false
		}
	}
	return true
}

func loadImagesFromCache(refs []myutils.ImageInTag) ([]*myutils.Image, bool) {
	digests := make([]string, 0, len(refs))
	for _, ref := range refs {
		digests = append(digests, ref.Digest)
	}
	byDigest, err := myutils.GlobalDBClient.Mongo.FindImagesByDigests(digests)
	if err != nil {
		return nil, false
	}
	imgs := make([]*myutils.Image, 0, len(refs))
	for _, ref := range refs {
		img, ok := byDigest[ref.Digest]
		if !ok || len(img.Layers) == 0 {
			return nil, false
		}
		imgs = append(imgs, img)
	}
	return imgs, true
}

func checkpointWriter(ch <-chan cpEntry, dir string) {
	path := filepath.Join(dir, "build_checkpoint.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		myutils.Logger.Error(fmt.Sprintf("checkpoint open %s: %v", path, err))
		for range ch {
		}
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for e := range ch {
		_ = enc.Encode(e)
	}
}
