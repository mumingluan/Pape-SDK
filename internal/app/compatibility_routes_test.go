package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/store"
)

func TestCheckRealInfoAndSafeStatus(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := store.Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, err := dataStore.CreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	bff := bffcrypto.BFF{AppID: "1010013", AppKey: "test-key", AESKey: "1234567890abcdef"}
	a := &App{store: dataStore, bff: bff, userCenterBFF: bff, userCenterClientID: "1003", cfg: &config.Config{RealNameIdentity: config.RealNameIdentity{RealName: "测试实名", RealID: "110101199001010010"}}}
	router := gin.New()
	a.mountAuthenticationRoutes(router)

	matched := signedGET(t, router, bff, "/v1/user/checkrealinfo", map[string]string{
		"token": user.Token, "realname": "测试实名", "realid": "110101199001010010",
	})
	if matched["realinfostatus"] != true {
		t.Fatalf("matching real info response=%#v", matched)
	}
	mismatch := signedGET(t, router, bff, "/v1/user/checkrealinfo", map[string]string{
		"token": user.Token, "realname": "错误姓名", "realid": "110101199001010010",
	})
	if mismatch["realinfostatus"] != false {
		t.Fatalf("mismatching real info response=%#v", mismatch)
	}
	safe := signedGET(t, router, bff, "/v1/user/getsafestatus", map[string]string{"token": user.Token})
	if safe["safestatus"] != float64(0) {
		t.Fatalf("new account safe response=%#v", safe)
	}
	if err := dataStore.UpdatePhone(user.ID, "13900139000"); err != nil {
		t.Fatal(err)
	}
	unsafe := signedGET(t, router, bff, "/v1/user/getsafestatus", map[string]string{"token": user.Token})
	if unsafe["safestatus"] != float64(1) {
		t.Fatalf("changed account safe response=%#v", unsafe)
	}
}

func TestCompatibilityStaticResponses(t *testing.T) {
	location := locateIP("127.0.0.1")
	if location.CountryCode != "CN" || location.ContinentCode != "AS" {
		t.Fatalf("private IP fallback=%+v", location)
	}
	a := &App{}
	router := gin.New()
	router.GET("/v1/user/unfinishedorder", a.unfinishedOrder)
	request := httptest.NewRequest(http.MethodGet, "/v1/user/unfinishedorder", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["unfinished"] != false || response["ret"] != float64(0) {
		t.Fatalf("unfinished order response=%#v", response)
	}
}

func signedGET(t *testing.T, router http.Handler, bff bffcrypto.BFF, path string, fields map[string]string) map[string]any {
	t.Helper()
	fields["clientid"] = "1068"
	fields["sign"] = bff.Sign(fields)
	query := url.Values{}
	for key, value := range fields {
		query.Set(key, value)
	}
	request := httptest.NewRequest(http.MethodGet, path+"?"+query.Encode(), nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s returned %d: %s", path, recorder.Code, recorder.Body.String())
	}
	var response map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}
