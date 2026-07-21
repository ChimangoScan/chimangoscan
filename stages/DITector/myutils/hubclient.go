package myutils

import (
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"
)

// IdentityProvider abstracts JWT rotation. crawler.IdentityManager satisfies this.
type IdentityProvider interface {
	GetNextClient() (*http.Client, string, string) // client, token, userAgent
	ClearToken(string)
	RefreshToken(oldToken string) (string, bool) // re-login same account
}

// HubClient is a Docker Hub HTTP client with JWT auth, browser fingerprinting,
// and automatic retry+rotation on 401/429/403. Shared by Stage I and II (DRY).
// Each goroutine should have its own instance — not safe for concurrent use.
type HubClient struct {
	ip     IdentityProvider
	client *http.Client
	token  string
	ua     string
}

func NewHubClient(ip IdentityProvider) *HubClient {
	c, t, u := ip.GetNextClient()
	return &HubClient{ip: ip, client: c, token: t, ua: u}
}

// Get performs an authenticated GET with up to 3 attempts, rotating identity on
// 401/429/403. Returns (body, statusCode, error). Non-retriable non-200 responses
// are returned without error — the caller decides semantics (e.g. 404 vs 500).
func (h *HubClient) Get(url string) ([]byte, int, error) {
	for i := 0; i < 3; i++ {
		time.Sleep(time.Duration(200+rand.Intn(200)) * time.Millisecond) // Jitter per request
		req, _ := http.NewRequest("GET", url, nil)
		h.setHeaders(req)
		resp, err := h.client.Do(req)
		if err != nil {
			h.rotate()
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			return body, 200, nil
		case 401:
			// First attempt: try refreshing current identity — the most common
			// cause of 401 is a JWT that simply timed out. Cheaper than rotation
			// and avoids burning attempts on other accounts whose caches are
			// also stale. If a subsequent attempt still 401s, the account is
			// likely blocked or the endpoint is private — rotate then.
			if i == 0 {
				if newToken, ok := h.ip.RefreshToken(h.token); ok {
					Logger.Warn(fmt.Sprintf("HTTP 401 (attempt %d/3): %s — refreshed JWT for current identity", i+1, url))
					h.token = newToken
					continue
				}
			}
			Logger.Warn(fmt.Sprintf("HTTP 401 (attempt %d/3): %s — rotating identity", i+1, url))
			h.ip.ClearToken(h.token)
			h.rotate()
		case 429:
			Logger.Warn(fmt.Sprintf("HTTP 429 rate-limit (attempt %d/3): %s — sleeping 15s then rotating", i+1, url))
			time.Sleep(15 * time.Second)
			h.rotate()
		case 403:
			Logger.Warn(fmt.Sprintf("HTTP 403 (attempt %d/3): %s — rotating identity", i+1, url))
			h.rotate()
		default:
			return body, resp.StatusCode, nil
		}
	}
	return nil, 0, fmt.Errorf("all 3 attempts failed: %s", url)
}

// GetInto calls Get and JSON-unmarshals a 200 response into dest.
func (h *HubClient) GetInto(url string, dest any) (int, error) {
	body, code, err := h.Get(url)
	if err != nil || code != 200 {
		return code, err
	}
	return code, json.Unmarshal(body, dest)
}

// GetTags fetches one page of tags for a repo.
func (h *HubClient) GetTags(ns, name string, pageNum, size int) ([]*Tag, error) {
	var result TagsPage
	code, err := h.GetInto(GetRepoTagsURL(ns, name, pageNum, size), &result)
	if err != nil {
		return nil, err
	}
	if code == 404 {
		return nil, nil
	}
	if code != 200 {
		return nil, fmt.Errorf("GetTags %s/%s page %d: HTTP %d", ns, name, pageNum, code)
	}
	for _, t := range result.Results {
		t.RepositoryNamespace = ns
		t.RepositoryName = name
	}
	return result.Results, nil
}

// GetTag fetches metadata for a single named tag. Returns nil, nil if the tag
// does not exist (404).
func (h *HubClient) GetTag(ns, name, tagName string) (*Tag, error) {
	var t Tag
	code, err := h.GetInto(GetTagMetadataURL(ns, name, tagName), &t)
	if err != nil {
		return nil, err
	}
	if code == 404 {
		return nil, nil
	}
	if code != 200 {
		return nil, fmt.Errorf("GetTag %s/%s:%s: HTTP %d", ns, name, tagName, code)
	}
	t.RepositoryNamespace = ns
	t.RepositoryName = name
	return &t, nil
}

// GetImages fetches image manifests for a tag.
func (h *HubClient) GetImages(ns, name, tag string) ([]*Image, error) {
	var imgs []*Image
	code, err := h.GetInto(GetImageMetadataURL(ns, name, tag), &imgs)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("GetImages %s/%s:%s: HTTP %d", ns, name, tag, code)
	}
	return imgs, nil
}

func (h *HubClient) rotate() {
	h.client, h.token, h.ua = h.ip.GetNextClient()
}

func (h *HubClient) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", h.ua)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	req.Header.Set("Referer", "https://hub.docker.com/")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-Ch-Ua", `"Not:A-Brand";v="99", "Google Chrome";v="145", "Chromium";v="145"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Connection", "keep-alive")
	if h.token != "" {
		req.Header.Set("Authorization", "JWT "+h.token)
	}
}
