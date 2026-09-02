package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"pape-sdk/internal/config"
	"pape-sdk/internal/store"
)

func TestSDKInnerValidatesMatchingOpenIDAndToken(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := store.Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: &config.Config{Inner: config.InnerService{AuthToken: "secret"}}, store: dataStore}
	aliases := map[string]string{
		"canonical":  user.OpenID,
		"legacy_id":  strconv.FormatInt(user.ID, 10),
		"legacy_nid": strconv.FormatInt(user.NID, 10),
	}
	for name, openID := range aliases {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"openid": openID, "token": user.Token})
			request := httptest.NewRequest(http.MethodPost, "/inner/v1/accounts/verify-login", strings.NewReader(string(body)))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer secret")
			recorder := httptest.NewRecorder()
			app.innerRouter().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			var response map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if response["valid"] != true || response["openid"] != user.OpenID {
				t.Fatalf("unexpected response: %#v", response)
			}
		})
	}
}

func TestSDKPublicRouterDoesNotMountNuanLogin(t *testing.T) {
	app := &App{cfg: &config.Config{}, store: nil}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/rpc/nuanlogin", nil)
	app.publicRouter(true, false).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestSDKInnerBlocksGameLoginDuringCancellationCoolingOff(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := store.Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if err := dataStore.SetCancellation(user.ID, cancellationStatusCoolingOff, time.Now().Add(15*24*time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	app := &App{cfg: &config.Config{Inner: config.InnerService{AuthToken: "secret"}}, store: dataStore}
	body, _ := json.Marshal(map[string]string{"openid": user.OpenID, "token": user.Token})
	request := httptest.NewRequest(http.MethodPost, "/inner/v1/accounts/verify-login", strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	app.innerRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusLocked || !strings.Contains(recorder.Body.String(), "注销冷静期") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
