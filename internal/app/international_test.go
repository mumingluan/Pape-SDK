package app

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"os"
	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/store"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmailRegisterLoginAndUnbind(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	s, err := store.Open("sqlite://"+filepath.Join(root, "test.db"), root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	bff := bffcrypto.BFF{AppID: "international", AppKey: "test-key", AESKey: "1234567890abcdef"}
	a := &App{cfg: &config.Config{BaseDir: root, Auth: config.Authentication{AllowRegister: true, RealPassword: true}, Email: config.Email{Mode: "outbox"}}, store: s, bff: bff}
	router := gin.New()
	a.mountAuthenticationRoutes(router)
	a.mountAccountCompatibilityRoutes(router)
	sent := authenticationRequest(t, router, bff, "/v1/user/account/send/code", map[string]string{"account": "user@example.com", "scene": "register"})
	if sent.Code != 0 {
		t.Fatal(sent)
	}
	files, _ := filepath.Glob(filepath.Join(root, "data/email-outbox/*.json"))
	if len(files) != 1 {
		t.Fatal(files)
	}
	raw, _ := os.ReadFile(files[0])
	var mail map[string]any
	json.Unmarshal(raw, &mail)
	result := authenticationRequest(t, router, bff, "/v1/user/email/register", map[string]string{"email": "user@example.com", "code": mail["code"].(string), "password": "test-password"})
	if result.Code != 0 {
		t.Fatal(result)
	}
	result = authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{"account": "user@example.com", "password": "test-password"})
	if result.Code != 0 {
		t.Fatal(result)
	}
	u, ok, err := s.UserByPhone("user@example.com")
	if err != nil || !ok {
		t.Fatal(err)
	}
	phone := "13800138000"
	if err = s.UpdateBindings(u.ID, &phone, nil); err != nil {
		t.Fatal(err)
	}
	s.MirrorSMS("user@example.com", "unbind", "123456", "test")
	result = authenticationRequest(t, router, bff, "/v1/user/account/unbind", map[string]string{"nid": u.OpenID, "token": u.Token, "kind": "phone", "code": "123456"})
	if result.Code != 0 {
		t.Fatal(result)
	}
	result = authenticationRequest(t, router, bff, "/v1/user/account/unbind", map[string]string{"nid": u.OpenID, "token": u.Token, "kind": "email", "code": "123456"})
	if result.Code == 0 {
		t.Fatal("last binding removed")
	}
}
func TestAppSpecificConfigAndCrypto(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "en"), 0755)
	os.WriteFile(filepath.Join(root, "en/parameter.json"), []byte(`{}`), 0600)
	a := &App{cfg: &config.Config{BaseDir: root, ConfigDir: "common", Applications: map[string]config.Application{"en": {Constants: config.Constants{AppID: "en", AppKey: "en-key", AESKey: "en-aes", ClientID: 1070}, GameClientID: "1067", Channel: "76", ConfigDir: "en"}}}}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/?clientid=1067&channel=76", nil)
	if a.requestConfigPath(c, "parameter.json") != filepath.Join(root, "en/parameter.json") {
		t.Fatal("wrong app config")
	}
	if a.bffFor(map[string]string{"app_id": "en"}).AppKey != "en-key" {
		t.Fatal("wrong signing key")
	}
	if isPapegamesHost("infoldgames.com.evil.test") || !isPapegamesHost("passport.infoldgames.com") {
		t.Fatal("domain boundary")
	}
}

func TestInternationalConfigSelectors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "game"), 0755)
	os.MkdirAll(filepath.Join(root, "common"), 0755)
	os.WriteFile(filepath.Join(root, "game/entries.json"), []byte(`{"CMP_Popup":[{"code":"CMP_Popup"}],"America_Age_Policy_Parameter":[]}`), 0600)
	os.WriteFile(filepath.Join(root, "game/privacyagreement_area_5.json"), []byte(`{"game_config_privacy_agreement":{"area_id":5}}`), 0600)
	os.WriteFile(filepath.Join(root, "common/sdkclient.json"), []byte(`{"country":"cn"}`), 0600)
	a := &App{cfg: &config.Config{BaseDir: root, ConfigDir: "common", GameConfigDirs: map[string]string{"1067": "game"}}}
	router := gin.New()
	router.Any("/entries", a.entries)
	router.GET("/privacy", a.privacyAgreement)
	for _, tc := range []struct {
		method, path, body string
		count              int
	}{
		{"GET", "/entries?clientid=1067&codes=%255B%2522CMP_Popup%2522%255D", "", 1},
		{"POST", "/entries", "clientid=1067&codes=%5B%22America_Age_Policy_Parameter%22%5D", 0},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		router.ServeHTTP(w, r)
		var result struct {
			Entries []any `json:"gameConfigEntries"`
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || len(result.Entries) != tc.count {
			t.Fatalf("wrong entries: %s", w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, httptest.NewRequest("GET", "/privacy?clientid=1067&areaid=5", nil))
	if !strings.Contains(w.Body.String(), `"area_id":5`) {
		t.Fatal(w.Body.String())
	}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("GET", "/?clientid=1067", nil)
	if a.requestConfigPath(c, "sdkclient.json") != filepath.Join(root, "game/sdkclient.json") {
		t.Fatal("international request leaked common CN config")
	}
}

func TestUserCenterBuildAssetsAndDeepLinks(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "static/usercenter/assets"), 0755)
	os.WriteFile(filepath.Join(root, "static/usercenter/index.html"), []byte(`<script src="/assets/app.js"></script>`), 0600)
	os.WriteFile(filepath.Join(root, "static/usercenter/assets/app.js"), []byte(`console.log("ready")`), 0600)
	a := &App{cfg: &config.Config{BaseDir: root}}
	r := a.publicRouter(false, true)
	for _, path := range []string{"/usercenter", "/account/signup", "/security/accBind", "/assets/app.js"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/assets/missing.js", nil))
	if w.Code != 404 {
		t.Fatal("missing asset must not return HTML")
	}
}
