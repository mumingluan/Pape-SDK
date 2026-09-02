package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAcquire(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/upload-tokens" || r.Header.Get("Authorization") != "Bearer secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request AcquireRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Category != "photo/a" || request.OriginalFilename != "upload.bin" {
			t.Fatalf("request = %+v", request)
		}
		_ = json.NewEncoder(w).Encode(AcquireResponse{
			Address: "https://storage.example", URL: "https://storage.example/photo/a/id.bin",
			AddForm: map[string]string{"key": "photo/a/id.bin", "x-oss-security-token": "temporary"},
		})
	}))
	defer server.Close()
	client, err := New(server.URL, "secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Acquire(context.Background(), AcquireRequest{Category: "photo/a", OriginalFilename: "upload.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if response.AddForm["key"] != "photo/a/id.bin" {
		t.Fatalf("response = %+v", response)
	}
}
