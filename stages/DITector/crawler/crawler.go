package crawler

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anonymous/DITector/myutils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-_"

type ParallelCrawler struct {
	WorkerCount int
	RepoChan    chan *myutils.Repository
	WG          sync.WaitGroup
	IM          *IdentityManager
	seenRepos   sync.Map
	pending     int32
	startTime   time.Time
}

func NewParallelCrawler(workers int, im *IdentityManager) *ParallelCrawler {
	return &ParallelCrawler{
		WorkerCount: workers,
		RepoChan:    make(chan *myutils.Repository, 100000),
		IM:          im,
		startTime:   time.Now(),
	}
}

func parseRepoName(repoName string) (namespace, name string) {
	parts := strings.SplitN(repoName, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "library", repoName
}

func (pc *ParallelCrawler) PreloadExistingRepos() {
	if !myutils.GlobalDBClient.MongoFlag {
		return
	}
	myutils.Logger.Info(">>> CACHE WARM-UP: Loading existing dataset to RAM...")
	coll := myutils.GlobalDBClient.Mongo.RepoColl
	cursor, err := coll.Find(context.TODO(), bson.M{}, options.Find().SetProjection(bson.M{"namespace": 1, "name": 1, "_id": 0}))
	if err != nil {
		myutils.Logger.Error(fmt.Sprintf("!!! CRITICAL: Failed to preload repos: %v", err))
		return
	}
	defer cursor.Close(context.TODO())
	count := 0
	start := time.Now()
	for cursor.Next(context.TODO()) {
		var r struct {
			Namespace string `bson:"namespace"`
			Name      string `bson:"name"`
		}
		if err := cursor.Decode(&r); err != nil {
			continue
		}
		pc.seenRepos.Store(r.Namespace+"/"+r.Name, true)
		count++
		if count%250000 == 0 {
			myutils.Logger.Info(fmt.Sprintf("... Preloading: %.1f Million repos in RAM", float64(count)/1000000.0))
		}
	}
	myutils.Logger.Info(fmt.Sprintf(">>> WARM-UP COMPLETE: %d repos loaded in %v", count, time.Since(start).Round(time.Second)))
}

func (pc *ParallelCrawler) repoWriter(ctx context.Context, done chan struct{}) {
	defer close(done)
	buffer := make([]*myutils.Repository, 0, 1000)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	flush := func() {
		if len(buffer) == 0 {
			return
		}
		count := len(buffer)
		if err := myutils.GlobalDBClient.Mongo.BulkUpsertRepositories(buffer); err != nil {
			myutils.Logger.Error(fmt.Sprintf("!!! DATABASE ERROR: %v", err))
			return
		}
		myutils.Logger.Info(fmt.Sprintf(">>> DB SYNC: Flushed %d NEW repos to central database", count))
		buffer = buffer[:0]
	}
	for {
		select {
		case repo, ok := <-pc.RepoChan:
			if !ok {
				flush()
				return
			}
			buffer = append(buffer, repo)
			if len(buffer) >= 1000 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (pc *ParallelCrawler) Start(seeds []string) {
	pc.PreloadExistingRepos()
	myutils.Logger.Info(fmt.Sprintf(">>> CORE START: Discovery Pipeline Active [W:%d]", pc.WorkerCount))
	if len(seeds) == 0 {
		for _, ch := range alphabet {
			seeds = append(seeds, string(ch))
		}
	}
	pc.ensureQueueInitialized(seeds)
	writerDone := make(chan struct{})
	go pc.repoWriter(context.Background(), writerDone)
	for i := 0; i < pc.WorkerCount; i++ {
		pc.WG.Add(1)
		go pc.worker(i)
	}
	go func() {
		for {
			p := atomic.LoadInt32(&pc.pending)
			active, _ := myutils.GlobalDBClient.Mongo.KeywordsColl.CountDocuments(context.TODO(), bson.M{"status": "pending"})
			myutils.Logger.Info(fmt.Sprintf("--- STATS: %d workers active | %d tasks left | Uptime: %v", p, active, time.Since(pc.startTime).Round(time.Second)))
			time.Sleep(30 * time.Second)
		}
	}()
	pc.WG.Wait()
	close(pc.RepoChan)
	<-writerDone
	myutils.Logger.Info(">>> PIPELINE HALTED: Discovery Cycle Finished")
}

func (pc *ParallelCrawler) ensureQueueInitialized(seeds []string) {
	if !myutils.GlobalDBClient.MongoFlag {
		return
	}
	coll := myutils.GlobalDBClient.Mongo.KeywordsColl
	_, _ = coll.UpdateMany(context.TODO(), bson.M{"status": "processing"}, bson.M{"$set": bson.M{"status": "pending"}})
	count, _ := coll.CountDocuments(context.TODO(), bson.M{})
	if count > 0 {
		return
	}
	var models []mongo.WriteModel
	for _, s := range seeds {
		models = append(models, mongo.NewUpdateOneModel().
			SetFilter(bson.M{"_id": s}).
			SetUpdate(bson.M{"$setOnInsert": bson.M{"status": "pending"}}).
			SetUpsert(true))
	}
	_, _ = coll.BulkWrite(context.TODO(), models)
}

func (pc *ParallelCrawler) worker(id int) {
	defer pc.WG.Done()
	hub := myutils.NewHubClient(pc.IM)
	emptyCount := 0
	for {
		prefix := pc.getNextTask()
		if prefix == "" {
			emptyCount++
			if emptyCount%6 == 0 {
				count, _ := myutils.GlobalDBClient.Mongo.KeywordsColl.CountDocuments(
					context.TODO(), bson.M{"status": "pending"})
				if count == 0 {
					break
				}
			}
			time.Sleep(5 * time.Second)
			continue
		}
		emptyCount = 0
		atomic.AddInt32(&pc.pending, 1)
		success := pc.processTask(hub, prefix)
		atomic.AddInt32(&pc.pending, -1)
		if !success {
			time.Sleep(5 * time.Second)
		}
		time.Sleep(time.Duration(rand.Intn(1000)) * time.Millisecond)
	}
}

func (pc *ParallelCrawler) getNextTask() string {
	if !myutils.GlobalDBClient.MongoFlag {
		return ""
	}
	var doc struct{ ID string `bson:"_id"` }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := myutils.GlobalDBClient.Mongo.KeywordsColl.FindOneAndUpdate(
		ctx,
		bson.M{"status": "pending"},
		bson.M{"$set": bson.M{"status": "processing", "started_at": time.Now()}},
		options.FindOneAndUpdate().SetReturnDocument(options.After).SetSort(bson.D{{Key: "priority", Value: -1}, {Key: "_id", Value: 1}}),
	).Decode(&doc)
	if err != nil {
		return ""
	}
	return doc.ID
}

func (pc *ParallelCrawler) processTask(hub *myutils.HubClient, prefix string) bool {
	myutils.Logger.Info(fmt.Sprintf("[TASK] Exploring: [%s]", prefix))
	res, ok := pc.fetchPage(hub, prefix, 1)
	if !ok {
		pc.updateTaskStatus(prefix, "pending")
		return false
	}
	newInPrefix := pc.processResults(res.Repositories)
	pages := (res.Count / 100) + 1
	if pages > 100 {
		pages = 100
	}
	for p := 2; p <= pages; p++ {
		resP, ok := pc.fetchPage(hub, prefix, p)
		if !ok {
			pc.updateTaskStatus(prefix, "pending")
			return false
		}
		if len(resP.Repositories) == 0 {
			break
		}
		newInPrefix += pc.processResults(resP.Repositories)
	}
	if (res.Count >= 10000 || len(prefix) == 1) && len(prefix) < 255 {
		tokenPlateau := newInPrefix == 0 && res.Count >= 10000 && strings.Contains(prefix, "-") && len(prefix) > 1
		lastChar := prefix[len(prefix)-1]
		isSep := lastChar == '-' || lastChar == '_'
		var models []mongo.WriteModel
		for _, char := range alphabet {
			if isSep && (char == '-' || char == '_') {
				continue
			}
			child := prefix + string(char)
			priority := 255 - len(child)
			if tokenPlateau {
				priority = -1
			}
			models = append(models, mongo.NewUpdateOneModel().
				SetFilter(bson.M{"_id": child}).
				SetUpdate(bson.M{"$setOnInsert": bson.M{"status": "pending", "priority": priority}}).
				SetUpsert(true))
		}
		if tokenPlateau {
			myutils.Logger.Info(fmt.Sprintf(">>> DEPRIORITIZING [%s]: token-match plateau (%d results, 0 new). Children set to priority=-1.", prefix, res.Count))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = myutils.GlobalDBClient.Mongo.KeywordsColl.BulkWrite(ctx, models)
	}
	efficiency := (float64(newInPrefix) / float64(pages*100)) * 100.0
	myutils.Logger.Info(fmt.Sprintf("[DONE] Prefix [%s]: +%d unique | Eff: %.1f%% | Found total: %d", prefix, newInPrefix, efficiency, res.Count))
	pc.updateTaskStatus(prefix, "done")
	return true
}

func (pc *ParallelCrawler) updateTaskStatus(id, status string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = myutils.GlobalDBClient.Mongo.KeywordsColl.UpdateOne(ctx, bson.M{"_id": id}, bson.M{"$set": bson.M{"status": status, "finished_at": time.Now()}})
}

// fetchPage fetches one page of search results. The 4-minute cooloff on unexpected
// HTTP status codes is Stage I-specific (prevents hot-loops on server errors).
func (pc *ParallelCrawler) fetchPage(hub *myutils.HubClient, query string, page int) (*V2SearchResponse, bool) {
	url := myutils.GetV2SearchURL(query, page, 100)
	body, status, err := hub.Get(url)
	if err != nil {
		return nil, false
	}
	switch status {
	case 200:
		var res V2SearchResponse
		if err := json.Unmarshal(body, &res); err != nil {
			return nil, false
		}
		return &res, true
	case 404:
		return &V2SearchResponse{}, true
	default:
		if len(body) > 200 {
			body = body[:200]
		}
		myutils.Logger.Warn(fmt.Sprintf("!!! HTTP %d [%s]: %s. Cooling off 4m...", status, query, string(body)))
		time.Sleep(4 * time.Minute)
		return nil, false
	}
}

func (pc *ParallelCrawler) processResults(repos []struct {
	RepoName  string "json:\"repo_name\""
	PullCount int64  "json:\"pull_count\""
}) int {
	newCount := 0
	for _, r := range repos {
		if r.RepoName == "" {
			continue
		}
		if _, seen := pc.seenRepos.LoadOrStore(r.RepoName, true); seen {
			continue
		}
		ns, name := parseRepoName(r.RepoName)
		select {
		case pc.RepoChan <- &myutils.Repository{Namespace: ns, Name: name, PullCount: r.PullCount}:
			newCount++
		default:
		}
	}
	return newCount
}

// TODO: expand to capture all fields returned by the search API (description as
// "short_description", star_count, is_automated, is_official) and propagate them
// through processResults → Repository → BulkUpsertRepositories. Zero extra
// requests — data is already in the response payload.
type V2SearchResponse struct {
	Count        int `json:"count"`
	Repositories []struct {
		RepoName  string `json:"repo_name"`
		PullCount int64  `json:"pull_count"`
	} `json:"results"`
}

func ShardSeeds(shard, total int) []string {
	chars := []rune(alphabet)
	n := len(chars)
	size := n / total
	start, end := shard*size, (shard+1)*size
	if shard == total-1 {
		end = n
	}
	var seeds []string
	for _, ch := range chars[start:end] {
		seeds = append(seeds, string(ch))
	}
	return seeds
}
