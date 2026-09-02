package booi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"pape-sdk/internal/config"
)

type Role struct {
	ServerID    uint32 `json:"server_id,omitempty"`
	AccountID   uint64 `json:"account_id"`
	OpenID      string `json:"openid"`
	ZoneID      uint32 `json:"zone_id"`
	Name        string `json:"name"`
	FamilyName  string `json:"family_name"`
	Level       int32  `json:"level"`
	LoginCount  int32  `json:"login_count"`
	CreatedAt   int64  `json:"created_at"`
	LastLoginAt int64  `json:"last_login_at"`
}

type Pool struct {
	clients map[uint32]*Client
}

type Client struct {
	baseURL   string
	authToken string
	http      *http.Client
}

func New(peer config.Peer) *Client {
	return &Client{
		baseURL:   strings.TrimRight(peer.BaseURL, "/"),
		authToken: peer.AuthToken,
		http:      &http.Client{Timeout: time.Duration(peer.TimeoutSeconds) * time.Second},
	}
}

func NewPool(peers map[uint32]config.Peer) *Pool {
	pool := &Pool{clients: make(map[uint32]*Client, len(peers))}
	for serverID, peer := range peers {
		pool.clients[serverID] = New(peer)
	}
	return pool
}

func (p *Pool) Client(serverID uint32) (*Client, bool) {
	if p == nil {
		return nil, false
	}
	client, ok := p.clients[serverID]
	return client, ok
}

// Roles queries every configured BOOI. A failed BOOI does not hide roles from
// healthy servers; the call fails only when no configured BOOI answered.
func (p *Pool) Roles(ctx context.Context, openID string) ([]Role, error) {
	if p == nil || len(p.clients) == 0 {
		return nil, errors.New("booi_inner has no configured servers")
	}
	type result struct {
		serverID uint32
		roles    []Role
		err      error
	}
	results := make(chan result, len(p.clients))
	var wait sync.WaitGroup
	for serverID, client := range p.clients {
		wait.Add(1)
		go func(serverID uint32, client *Client) {
			defer wait.Done()
			roles, err := client.Roles(ctx, openID)
			results <- result{serverID: serverID, roles: roles, err: err}
		}(serverID, client)
	}
	wait.Wait()
	close(results)

	succeeded := 0
	roles := []Role{}
	var failures []error
	seen := map[string]struct{}{}
	for item := range results {
		if item.err != nil {
			failure := fmt.Errorf("BOOI server %d: %w", item.serverID, item.err)
			failures = append(failures, failure)
			log.Printf("[booi-inner] %v", failure)
			continue
		}
		succeeded++
		for _, role := range item.roles {
			role.ServerID = item.serverID
			key := fmt.Sprintf("%d:%d:%d", role.ServerID, role.ZoneID, role.AccountID)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			roles = append(roles, role)
		}
	}
	if succeeded == 0 {
		return nil, errors.Join(failures...)
	}
	sort.Slice(roles, func(i, j int) bool {
		if roles[i].ServerID != roles[j].ServerID {
			return roles[i].ServerID < roles[j].ServerID
		}
		if roles[i].ZoneID != roles[j].ZoneID {
			return roles[i].ZoneID < roles[j].ZoneID
		}
		return roles[i].AccountID < roles[j].AccountID
	})
	return roles, nil
}

func (c *Client) Roles(ctx context.Context, openID string) ([]Role, error) {
	if c.baseURL == "" {
		return nil, fmt.Errorf("booi_inner.base_url is not configured")
	}
	payload, err := json.Marshal(map[string]string{"openid": openID})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/inner/v1/players/roles/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("BOOI inner unavailable: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Roles []Role `json:"roles"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode BOOI inner response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		if result.Error == "" {
			result.Error = resp.Status
		}
		return nil, fmt.Errorf("BOOI inner: %s", result.Error)
	}
	return result.Roles, nil
}

// UnbindRoles requires every configured BOOI to confirm that its roles are no
// longer bound to the SDK account. Successful nodes may be retried safely.
func (p *Pool) UnbindRoles(ctx context.Context, openID string) error {
	if p == nil || len(p.clients) == 0 {
		return errors.New("booi_inner has no configured servers")
	}
	type result struct {
		serverID uint32
		err      error
	}
	results := make(chan result, len(p.clients))
	var wait sync.WaitGroup
	for serverID, client := range p.clients {
		wait.Add(1)
		go func(serverID uint32, client *Client) {
			defer wait.Done()
			_, err := client.UnbindRoles(ctx, openID)
			results <- result{serverID: serverID, err: err}
		}(serverID, client)
	}
	wait.Wait()
	close(results)
	failures := []error{}
	for item := range results {
		if item.err != nil {
			failure := fmt.Errorf("BOOI server %d: %w", item.serverID, item.err)
			failures = append(failures, failure)
			log.Printf("[booi-inner] role unbind failed: %v", failure)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	return nil
}

func (c *Client) UnbindRoles(ctx context.Context, openID string) (int64, error) {
	if c.baseURL == "" {
		return 0, fmt.Errorf("booi_inner.base_url is not configured")
	}
	payload, err := json.Marshal(map[string]string{"openid": openID})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/inner/v1/players/roles/unbind", bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.authToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("BOOI inner unavailable: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Success      bool   `json:"success"`
		UnboundRoles int64  `json:"unbound_roles"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("decode BOOI inner response: %w", err)
	}
	if resp.StatusCode != http.StatusOK || !result.Success {
		if result.Error == "" {
			result.Error = resp.Status
		}
		return 0, fmt.Errorf("BOOI inner: %s", result.Error)
	}
	return result.UnboundRoles, nil
}
