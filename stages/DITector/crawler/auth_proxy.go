package crawler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"crypto/tls"

	"github.com/anonymous/DITector/myutils"
)

// Account represents a Docker Hub account with its own sticky User-Agent
type Account struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Token     string `json:"token,omitempty"`
	UserAgent string `json:"-"` // Sticky UA assigned at runtime
}

var globalUAPool = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
}

// IdentityManager handles rotation of IPs and Accounts
type IdentityManager struct {
	Proxies  []string
	Accounts []*Account
	mu       sync.Mutex
	proxyIdx int
	accIdx   int
}

// LoadIdentities loads proxies and accounts and assigns unique UAs
func LoadIdentities(proxyFile, accountFile string) (*IdentityManager, error) {
	im := &IdentityManager{}

	if proxyFile != "" {
		data, err := os.ReadFile(proxyFile)
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
				if line = strings.TrimSpace(line); line != "" {
					im.Proxies = append(im.Proxies, line)
				}
			}
		}
	}

	if accountFile != "" {
		data, err := os.ReadFile(accountFile)
		if err == nil {
			json.Unmarshal(data, &im.Accounts)
			// Assign unique sticky UA to each account
			for i, acc := range im.Accounts {
				acc.UserAgent = globalUAPool[i % len(globalUAPool)]
			}
			fmt.Printf("Loaded %d accounts with unique User-Agents\n", len(im.Accounts))
		}
	}

	return im, nil
}

var loginMu sync.Mutex

func (im *IdentityManager) LoginDockerHub(acc *Account) error {
	loginMu.Lock()
	defer loginMu.Unlock()

	if acc.Token != "" { return nil }

	myutils.Logger.Info(fmt.Sprintf("Attempting login for user: %s", acc.Username))
	
	payload, _ := json.Marshal(map[string]string{
		"username": acc.Username,
		"password": acc.Password,
	})

	req, _ := http.NewRequest("POST", "https://hub.docker.com/v2/users/login/", bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", acc.UserAgent) // Use account's sticky UA for login

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed status %d: %s", resp.StatusCode, string(body))
	}

	var res struct{ Token string `json:"token"` }
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil { return err }

	acc.Token = res.Token
	myutils.Logger.Info(fmt.Sprintf("Successfully obtained new JWT for %s", acc.Username))
	return nil
}

func (im *IdentityManager) ClearToken(token string) {
	if token == "" { return }
	im.mu.Lock()
	defer im.mu.Unlock()
	for _, acc := range im.Accounts {
		if acc.Token == token {
			acc.Token = ""
			return
		}
	}
}

// RefreshToken clears and re-logs in the account that currently holds oldToken,
// returning the freshly minted token. Unlike ClearToken+GetNextClient, this
// keeps the same identity (avoiding a rotation that may land on another
// account whose cached token is also stale). Returns ok=false if the token
// does not belong to any known account or the relogin fails.
func (im *IdentityManager) RefreshToken(oldToken string) (string, bool) {
	if oldToken == "" {
		return "", false
	}
	im.mu.Lock()
	var target *Account
	for _, acc := range im.Accounts {
		if acc.Token == oldToken {
			target = acc
			acc.Token = ""
			break
		}
	}
	im.mu.Unlock()
	if target == nil {
		return "", false
	}
	if err := im.LoginDockerHub(target); err != nil {
		myutils.Logger.Warn(fmt.Sprintf("RefreshToken login failed for %s: %v", target.Username, err))
		return "", false
	}
	return target.Token, true
}

// GetNextClient returns http.Client, Token and the Sticky User-Agent
func (im *IdentityManager) GetNextClient() (*http.Client, string, string) {
	im.mu.Lock()
	defer im.mu.Unlock()

	transport := &http.Transport{
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 10,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			PreferServerCipherSuites: false,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	if len(im.Accounts) == 0 {
		return client, "", globalUAPool[0]
	}

	acc := im.Accounts[im.accIdx]
	if acc.Token == "" {
		_ = im.LoginDockerHub(acc)
	}
	
	token := acc.Token
	ua := acc.UserAgent
	im.accIdx = (im.accIdx + 1) % len(im.Accounts)

	return client, token, ua
}
