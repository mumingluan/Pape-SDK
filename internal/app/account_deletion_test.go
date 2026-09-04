package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"pape-sdk/internal/booi"
	"pape-sdk/internal/config"
	"pape-sdk/internal/store"
)

func TestUnbindAndDeleteUserRequiresBOOIConfirmation(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := store.Open("sqlite://"+filepath.Join(temp, "delete.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, err := dataStore.CreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}

	app := &App{store: dataStore}
	if err := app.unbindAndDeleteUser(context.Background(), user.ID, false); err == nil {
		t.Fatal("account deletion succeeded without BOOI confirmation")
	}
	if account, ok, err := dataStore.AdminAccountByID(user.ID); err != nil || !ok || account.DeletedAt != 0 {
		t.Fatalf("failed unbind changed SDK account: account=%+v ok=%t err=%v", account, ok, err)
	}

	unbound := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inner/v1/players/roles/unbind" {
			t.Fatalf("unexpected BOOI path %s", r.URL.Path)
		}
		var payload struct {
			OpenID string `json:"openid"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		unbound = payload.OpenID
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"unbound_roles":1}`))
	}))
	defer upstream.Close()
	app.booi = booi.NewPool(map[uint32]config.Peer{500058: {
		BaseURL: upstream.URL, AuthToken: "test", TimeoutSeconds: 1,
	}})
	if err := app.unbindAndDeleteUser(context.Background(), user.ID, false); err != nil {
		t.Fatal(err)
	}
	if unbound != strconv.FormatInt(user.ID, 10) {
		t.Fatalf("unbound OpenID=%q", unbound)
	}
	if account, ok, err := dataStore.AdminAccountByID(user.ID); err != nil || !ok || account.DeletedAt == 0 {
		t.Fatalf("soft delete result account=%+v ok=%t err=%v", account, ok, err)
	}
}
