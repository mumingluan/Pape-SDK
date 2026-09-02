package booi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"pape-sdk/internal/config"
)

func TestPoolQueriesEveryConfiguredBOOI(t *testing.T) {
	server := func(accountID uint64, zoneID uint32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/inner/v1/players/roles/query" || r.Header.Get("Authorization") != "Bearer secret" {
				t.Fatalf("unexpected request path=%s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"roles": []map[string]any{{
				"account_id": accountID, "openid": "open-1", "zone_id": zoneID,
				"name": "Player", "family_name": "Hunter", "level": zoneID,
			}}})
		}))
	}
	first := server(101, 1)
	defer first.Close()
	second := server(202, 2)
	defer second.Close()
	pool := NewPool(map[uint32]config.Peer{
		500058: {BaseURL: first.URL, AuthToken: "secret", TimeoutSeconds: 2},
		500059: {BaseURL: second.URL, AuthToken: "secret", TimeoutSeconds: 2},
	})
	roles, err := pool.Roles(context.Background(), "open-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 2 || roles[0].ServerID != 500058 || roles[0].ZoneID != 1 || roles[1].ServerID != 500059 || roles[1].ZoneID != 2 {
		t.Fatalf("roles=%+v", roles)
	}
}

func TestPoolReturnsHealthyServersWhenOneBOOIIsDown(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"roles": []map[string]any{{"account_id": 1, "openid": "open-1", "zone_id": 1}}})
	}))
	defer healthy.Close()
	pool := NewPool(map[uint32]config.Peer{
		500058: {BaseURL: healthy.URL, TimeoutSeconds: 2},
		500059: {BaseURL: "http://127.0.0.1:1", TimeoutSeconds: 1},
	})
	roles, err := pool.Roles(context.Background(), "open-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(roles) != 1 || roles[0].ServerID != 500058 {
		t.Fatalf("roles=%+v", roles)
	}
}

func TestPoolUnbindRequiresEveryConfiguredBOOI(t *testing.T) {
	calls := make(chan string, 2)
	server := func(status int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls <- r.URL.Path
			if r.URL.Path != "/inner/v1/players/roles/unbind" || r.Header.Get("Authorization") != "Bearer secret" {
				t.Fatalf("unexpected request path=%s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
			}
			w.WriteHeader(status)
			if status == http.StatusOK {
				_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "unbound_roles": 1})
			} else {
				_ = json.NewEncoder(w).Encode(map[string]any{"error": "failed"})
			}
		}))
	}
	healthy := server(http.StatusOK)
	defer healthy.Close()
	failing := server(http.StatusInternalServerError)
	defer failing.Close()
	pool := NewPool(map[uint32]config.Peer{
		500058: {BaseURL: healthy.URL, AuthToken: "secret", TimeoutSeconds: 2},
		500059: {BaseURL: failing.URL, AuthToken: "secret", TimeoutSeconds: 2},
	})
	if err := pool.UnbindRoles(context.Background(), "100000001"); err == nil {
		t.Fatal("expected one BOOI failure to block unbind")
	}
	if len(calls) != 2 {
		t.Fatalf("called %d BOOI servers, want 2", len(calls))
	}
}

func TestPoolUnbindSucceedsOnlyAfterAllConfirm(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "unbound_roles": 0})
	}))
	defer server.Close()
	pool := NewPool(map[uint32]config.Peer{
		500058: {BaseURL: server.URL, TimeoutSeconds: 2},
		500059: {BaseURL: server.URL, TimeoutSeconds: 2},
	})
	if err := pool.UnbindRoles(context.Background(), "100000001"); err != nil {
		t.Fatal(err)
	}
}
