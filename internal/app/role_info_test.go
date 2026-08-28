package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/booi"
	"pape-sdk/internal/config"
	"pape-sdk/internal/store"
)

func TestRoleInfoComesFromConfiguredBOOI(t *testing.T) {
	booiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"roles": []map[string]any{{
			"account_id": 9001, "openid": "ignored-by-client", "zone_id": 1,
			"name": "Alice", "family_name": "Hunter", "level": 17,
			"created_at": 100, "last_login_at": 200,
		}}})
	}))
	defer booiServer.Close()
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
	a := &App{
		store: dataStore,
		booi:  booi.NewPool(map[uint32]config.Peer{500058: {BaseURL: booiServer.URL, TimeoutSeconds: 2}}),
	}
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodGet, "/roleinfo?token="+url.QueryEscape(user.Token), nil)
	a.roleInfo(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		RoleInfo map[string]struct {
			ServerID uint32 `json:"ServerID"`
			Level    int32  `json:"Level"`
			Name     string `json:"Name"`
		} `json:"roleinfo"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	role := response.RoleInfo["1"]
	if role.ServerID != 500058 || role.Level != 17 || role.Name != "Alice" {
		t.Fatalf("response=%s", recorder.Body.String())
	}
}
