package buildgraph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ChimangoScan/DITector/myutils"
	"go.mongodb.org/mongo-driver/bson"
)

// ---- test infrastructure ----

// mockIP is a trivial IdentityProvider that always returns the given http.Client.
type mockIP struct{ client *http.Client }

func (m *mockIP) GetNextClient() (*http.Client, string, string) {
	return m.client, "", "test-ua/1.0"
}
func (m *mockIP) ClearToken(string)                    {}
func (m *mockIP) RefreshToken(string) (string, bool)   { return "", false }

// redirectTransport rewrites every outgoing request to point to the test server,
// regardless of the original host. Allows HubClient to hit the mock server.
type redirectTransport struct{ host string }

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	r2.URL.Host = t.host
	r2.URL.Scheme = "http"
	return http.DefaultTransport.RoundTrip(r2)
}

// newTestHub creates a HubClient whose HTTP calls are redirected to server.
func newTestHub(server *httptest.Server) *myutils.HubClient {
	host := strings.TrimPrefix(server.URL, "http://")
	return myutils.NewHubClient(&mockIP{
		client: &http.Client{Transport: &redirectTransport{host: host}},
	})
}

// TestMain initialises the logger and an isolated test MongoDB database,
// runs all tests, then drops the test database.
func TestMain(m *testing.M) {
	const cfg = `
max_thread: 0
log_file: '/tmp/chimangoscan_test'
repo_with_many_tags_file: '/tmp/chimangoscan_test_repos.txt'
tmp_dir: '/tmp'
proxy:
  http_proxy: ''
  https_proxy: ''
mongo_config:
  uri: 'mongodb://localhost:27017'
  database: 'dockerhub_test_buildgraph'
  collections:
    repositories: 'repositories'
    tags: 'tags'
    images: 'images'
    image_results: 'image_results'
    layer_results: 'layer_results'
    user: 'users'
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
`
	const cfgFile = "/tmp/chimangoscan_test_config.yaml"
	if err := os.WriteFile(cfgFile, []byte(cfg), 0644); err != nil {
		panic("could not write test config: " + err.Error())
	}
	defer os.Remove(cfgFile)

	// Initialises Logger, MongoDB, and optionally Neo4j (failure is non-fatal).
	myutils.LoadConfigFromFile(cfgFile, 2 /* info */)

	code := m.Run()

	if myutils.GlobalDBClient.MongoFlag {
		_ = myutils.GlobalDBClient.Mongo.DockerHubDB.Drop(context.Background())
		_ = myutils.GlobalDBClient.Mongo.Client.Disconnect(context.Background())
	}
	os.Exit(code)
}

// requireMongo skips the test when the local MongoDB is unavailable.
func requireMongo(t *testing.T) {
	t.Helper()
	if !myutils.GlobalDBClient.MongoFlag {
		t.Skip("MongoDB unavailable — skipping integration test")
	}
}

// cleanCollections truncates the three collections touched by Stage II.
func cleanCollections(t *testing.T) {
	t.Helper()
	requireMongo(t)
	db := myutils.GlobalDBClient.Mongo
	_, _ = db.TagColl.DeleteMany(context.Background(), bson.M{})
	_, _ = db.ImgColl.DeleteMany(context.Background(), bson.M{})
	_, _ = db.RepoColl.DeleteMany(context.Background(), bson.M{})
}

// ---- pure function: allTagsHaveImages ----

func TestAllTagsHaveImages_Nil(t *testing.T) {
	if allTagsHaveImages(nil) {
		t.Fatal("nil slice: expected false")
	}
}

func TestAllTagsHaveImages_Empty(t *testing.T) {
	if allTagsHaveImages([]*myutils.Tag{}) {
		t.Fatal("empty slice: expected false")
	}
}

func TestAllTagsHaveImages_TagWithNoImages(t *testing.T) {
	tags := []*myutils.Tag{{Name: "latest", Images: nil}}
	if allTagsHaveImages(tags) {
		t.Fatal("tag with nil Images: expected false")
	}
}

func TestAllTagsHaveImages_AllHaveImages(t *testing.T) {
	tags := []*myutils.Tag{
		{Name: "latest", Images: []myutils.ImageInTag{{Digest: "sha256:aaa"}}},
		{Name: "v1.0", Images: []myutils.ImageInTag{{Digest: "sha256:bbb"}}},
	}
	if !allTagsHaveImages(tags) {
		t.Fatal("all tags have images: expected true")
	}
}

func TestAllTagsHaveImages_Mixed(t *testing.T) {
	tags := []*myutils.Tag{
		{Name: "latest", Images: []myutils.ImageInTag{{Digest: "sha256:aaa"}}},
		{Name: "v1.0", Images: nil},
	}
	if allTagsHaveImages(tags) {
		t.Fatal("mixed — one tag has no images: expected false")
	}
}

// ---- MongoDB integration: loadImagesFromCache ----

func TestLoadImagesFromCache_Hit(t *testing.T) {
	cleanCollections(t)
	db := myutils.GlobalDBClient.Mongo

	img := &myutils.Image{
		Digest: "sha256:" + strings.Repeat("a", 64),
		OS:     "linux",
		Layers: []myutils.Layer{{Instruction: "CMD bash"}},
	}
	if err := db.UpdateImage(img); err != nil {
		t.Fatalf("UpdateImage: %v", err)
	}

	refs := []myutils.ImageInTag{{Digest: img.Digest}}
	imgs, ok := loadImagesFromCache(refs)
	if !ok {
		t.Fatal("expected cache hit (ok=true)")
	}
	if len(imgs) != 1 || imgs[0].Digest != img.Digest {
		t.Fatalf("wrong image returned from cache: %v", imgs)
	}
}

func TestLoadImagesFromCache_MissingDigest(t *testing.T) {
	cleanCollections(t)

	refs := []myutils.ImageInTag{{Digest: "sha256:" + strings.Repeat("b", 64)}}
	_, ok := loadImagesFromCache(refs)
	if ok {
		t.Fatal("digest absent from DB: expected cache miss (ok=false)")
	}
}

func TestLoadImagesFromCache_EmptyLayers(t *testing.T) {
	cleanCollections(t)
	db := myutils.GlobalDBClient.Mongo

	// Image exists in DB but has no layers → considered incomplete, must be
	// fetched from the API again.
	img := &myutils.Image{
		Digest: "sha256:" + strings.Repeat("c", 64),
		OS:     "linux",
		Layers: nil,
	}
	if err := db.UpdateImage(img); err != nil {
		t.Fatalf("UpdateImage: %v", err)
	}

	refs := []myutils.ImageInTag{{Digest: img.Digest}}
	_, ok := loadImagesFromCache(refs)
	if ok {
		t.Fatal("image with no layers: expected cache miss (ok=false)")
	}
}

// ---- Key fix #1: getTags must persist each tag to MongoDB after an API fetch ----

func TestGetTags_SavesTagToMongo(t *testing.T) {
	cleanCollections(t)

	const (
		ns      = "testns"
		name    = "testname"
		tagName = "latest"
	)

	resp := myutils.TagsPage{
		Count: 1,
		Results: []*myutils.Tag{{
			RepositoryNamespace: ns,
			RepositoryName:      name,
			Name:                tagName,
			LastUpdated:         "2024-01-01T00:00:00Z",
			Images: []myutils.ImageInTag{{
				Architecture: "amd64",
				Digest:       "sha256:" + strings.Repeat("d", 64),
				OS:           "linux",
				Features:     "feature_x",
				Status:       "active",
			}},
		}},
	}
	body, _ := json.Marshal(resp)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	hub := newTestHub(ts)
	repo := &myutils.Repository{Namespace: ns, Name: name}
	m := &BuildMetrics{}

	tags := getTags(hub, repo, m)
	if len(tags) != 1 || tags[0].Name != tagName {
		t.Fatalf("getTags returned unexpected result: %v", tags)
	}
	if m.TagAPIFetches.Load() != 1 {
		t.Fatalf("TagAPIFetches: got %d, want 1", m.TagAPIFetches.Load())
	}

	// Key assertion: the tag must be findable in MongoDB.
	stored, err := myutils.GlobalDBClient.Mongo.FindTagByName(ns, name, tagName)
	if err != nil {
		t.Fatalf("tag not found in MongoDB after getTags (fix #1 regression): %v", err)
	}
	if stored.Name != tagName {
		t.Fatalf("stored tag name: got %q, want %q", stored.Name, tagName)
	}
}

// ---- Key fix #2: persistImages must not overwrite t.Images with a minimal struct ----
//
// The old bug stripped Features, Variant, Status, LastPulled, LastPushed from the
// ImageInTag records that the tags API already returned. persistImages now calls
// UpdateTag(t) with the original tag — all fields must survive the round-trip.

func TestPersistImages_DoesNotOverwriteTagImages(t *testing.T) {
	cleanCollections(t)

	const (
		ns      = "testns2"
		name    = "testname2"
		tagName = "v2.0"
	)

	richImages := []myutils.ImageInTag{{
		Architecture: "arm64",
		Digest:       "sha256:" + strings.Repeat("e", 64),
		OS:           "linux",
		Features:     "arm_feature",
		Variant:      "v8",
		Status:       "active",
		LastPulled:   "2024-03-01T00:00:00Z",
		LastPushed:   "2024-03-01T00:00:00Z",
	}}

	tag := &myutils.Tag{
		RepositoryNamespace: ns,
		RepositoryName:      name,
		Name:                tagName,
		LastUpdated:         "2024-03-01T00:00:00Z",
		Images:              richImages,
	}

	img := &myutils.Image{
		Digest:       richImages[0].Digest,
		Architecture: "arm64",
		OS:           "linux",
		Layers:       []myutils.Layer{{Instruction: "RUN apt-get install -y curl"}},
	}

	repo := &myutils.Repository{Namespace: ns, Name: name}
	persistImages(repo, tag, []*myutils.Image{img})

	stored, err := myutils.GlobalDBClient.Mongo.FindTagByName(ns, name, tagName)
	if err != nil {
		t.Fatalf("tag not found after persistImages: %v", err)
	}
	if len(stored.Images) == 0 {
		t.Fatal("t.Images was cleared by persistImages (fix #2 regression)")
	}
	got := stored.Images[0]
	if got.Features != "arm_feature" {
		t.Errorf("Images[0].Features: got %q, want %q", got.Features, "arm_feature")
	}
	if got.Variant != "v8" {
		t.Errorf("Images[0].Variant: got %q, want %q", got.Variant, "v8")
	}
	if got.Status != "active" {
		t.Errorf("Images[0].Status: got %q, want %q", got.Status, "active")
	}
	if got.LastPulled != "2024-03-01T00:00:00Z" {
		t.Errorf("Images[0].LastPulled: got %q, want %q", got.LastPulled, "2024-03-01T00:00:00Z")
	}
}

// ---- processRepo edge cases ----

func TestCollectBatch_ReturnsFalseWhenTagsFail(t *testing.T) {
	cleanCollections(t)

	// Server always returns 500 — getTags will fail, collectBatch must return false.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	hub := newTestHub(ts)
	repo := &myutils.Repository{Namespace: "failns", Name: "failrepo"}
	m := &BuildMetrics{}

	_, ok := collectBatch(hub, repo, m)
	if ok {
		t.Fatal("expected collectBatch=false when tags API returns 500")
	}
}

func TestCollectBatch_SkipsWindowsImages(t *testing.T) {
	cleanCollections(t)

	const (
		ns      = "wintest"
		name    = "winrepo"
		tagName = "latest"
	)

	tagsResp := myutils.TagsPage{
		Count: 1,
		Results: []*myutils.Tag{{
			RepositoryNamespace: ns,
			RepositoryName:      name,
			Name:                tagName,
			LastUpdated:         "2024-01-01T00:00:00Z",
			Images:              nil,
		}},
	}
	tagsBody, _ := json.Marshal(tagsResp)

	windowsImgs := []*myutils.Image{{
		Architecture: "amd64",
		Digest:       "sha256:" + strings.Repeat("f", 64),
		OS:           "windows",
		Layers:       []myutils.Layer{{Instruction: "RUN powershell"}},
	}}
	imgsBody, _ := json.Marshal(windowsImgs)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/images") {
			_, _ = w.Write(imgsBody)
		} else {
			_, _ = w.Write(tagsBody)
		}
	}))
	defer ts.Close()

	hub := newTestHub(ts)
	repo := &myutils.Repository{Namespace: ns, Name: name}
	m := &BuildMetrics{}

	batch, ok := collectBatch(hub, repo, m)
	if !ok {
		t.Fatal("collectBatch should return true even when all images are windows")
	}
	if len(batch.Jobs) != 0 {
		t.Fatalf("windows images must be skipped — expected 0 jobs, got %d", len(batch.Jobs))
	}
}
