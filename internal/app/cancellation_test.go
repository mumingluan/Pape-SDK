package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/booi"
	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/store"
)

func TestCancellationLifecycle(t *testing.T) {
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
	bff := bffcrypto.BFF{AppID: "1010013", AppKey: "test-key", AESKey: "1234567890abcdef"}
	unbinder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inner/v1/players/roles/unbind" {
			t.Fatalf("unexpected unbind path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "unbound_roles": 1})
	}))
	defer unbinder.Close()
	a := &App{store: dataStore, userCenterBFF: bff, userCenterClientID: "1003", booi: booi.NewPool(map[uint32]config.Peer{
		500058: {BaseURL: unbinder.URL, TimeoutSeconds: 2},
	})}
	router := gin.New()
	a.mountCancellationRoutes(router)

	status := cancellationRequest(t, router, bff, "/v1/user/cancellation/status", user.Token, nil)
	if status["status"] != float64(1) {
		t.Fatalf("initial cancellation status = %#v, want 1", status["status"])
	}
	for _, action := range []string{"1", "2", "3", "4"} {
		result := cancellationRequest(t, router, bff, "/v1/user/cancellation/handle", user.Token, map[string]string{"action": action})
		if result["status"] != float64(cancellationStatusNormal) {
			t.Fatalf("intermediate cancellation action %s changed status: %#v", action, result)
		}
	}
	cancellationRequest(t, router, bff, "/v1/user/cancellation/handle", user.Token, map[string]string{"action": "5"})
	status = cancellationRequest(t, router, bff, "/v1/user/cancellation/status", user.Token, nil)
	if status["status"] != float64(2) || status["cancel_at"] == "" {
		t.Fatalf("submitted cancellation status = %#v", status)
	}
	cancellationRequest(t, router, bff, "/v1/user/cancellation/handle", user.Token, map[string]string{"action": "6"})
	status = cancellationRequest(t, router, bff, "/v1/user/cancellation/status", user.Token, nil)
	if status["status"] != float64(1) {
		t.Fatalf("cancelled cancellation status = %#v, want 1", status["status"])
	}
	cancellationRequest(t, router, bff, "/v1/user/cancellation/handle", user.Token, map[string]string{"action": "5"})
	cancellationRequest(t, router, bff, "/v1/user/cancellation/handle", user.Token, map[string]string{"action": "7"})
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || !ok {
		t.Fatalf("action 7 bypassed the cooling-off period: ok=%t err=%v", ok, err)
	}
	status = cancellationRequest(t, router, bff, "/v1/user/cancellation/status", user.Token, nil)
	if status["status"] != float64(2) {
		t.Fatalf("action 7 changed cooling-off status: %#v", status)
	}
	if err := dataStore.SetCancellation(user.ID, cancellationStatusCoolingOff, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	a.finalizeDueCancellations(context.Background())
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || ok {
		t.Fatalf("due cancellation did not complete: ok=%t err=%v", ok, err)
	}
}

func TestCancellationBlockedUntilEveryBOOIUnbinds(t *testing.T) {
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
	var healthyCalls, failingCalls atomic.Int32
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		healthyCalls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "unbound_roles": 1})
	}))
	defer healthy.Close()
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		failingCalls.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "unavailable"})
	}))
	defer failing.Close()
	bff := bffcrypto.BFF{AppID: "1010013", AppKey: "test-key", AESKey: "1234567890abcdef"}
	a := &App{store: dataStore, userCenterBFF: bff, userCenterClientID: "1003", booi: booi.NewPool(map[uint32]config.Peer{
		500058: {BaseURL: healthy.URL, TimeoutSeconds: 2},
		500059: {BaseURL: failing.URL, TimeoutSeconds: 2},
	})}
	router := gin.New()
	a.mountCancellationRoutes(router)
	if err := dataStore.SetCancellation(user.ID, cancellationStatusCoolingOff, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	a.finalizeDueCancellations(context.Background())
	if healthyCalls.Load() != 1 || failingCalls.Load() != 1 {
		t.Fatalf("BOOI calls healthy=%d failing=%d", healthyCalls.Load(), failingCalls.Load())
	}
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || !ok {
		t.Fatalf("SDK account was deleted despite BOOI failure: ok=%t err=%v", ok, err)
	}
	status, _, err := dataStore.Cancellation(user.ID)
	if err != nil || status != cancellationStatusCoolingOff {
		t.Fatalf("failed finalization did not remain pending: status=%d err=%v", status, err)
	}
}

type cancellationEnvelope struct {
	Code int            `json:"code"`
	Info string         `json:"info"`
	Data map[string]any `json:"data"`
}

func cancellationRequest(t *testing.T, router http.Handler, bff bffcrypto.BFF, path, token string, extra map[string]string) map[string]any {
	t.Helper()
	envelope := cancellationRequestResult(t, router, bff, path, token, extra)
	if envelope.Code != 0 {
		t.Fatalf("%s failed: code=%d info=%s", path, envelope.Code, envelope.Info)
	}
	return envelope.Data
}

func cancellationRequestResult(t *testing.T, router http.Handler, bff bffcrypto.BFF, path, token string, extra map[string]string) cancellationEnvelope {
	t.Helper()
	fields := map[string]string{"clientid": "1003", "token": token}
	for key, value := range extra {
		fields[key] = value
	}
	fields["sign"] = bff.Sign(fields)
	values := url.Values{}
	for key, value := range fields {
		values.Set(key, value)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s returned HTTP %d: %s", path, recorder.Code, recorder.Body.String())
	}
	var envelope cancellationEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	return envelope
}
