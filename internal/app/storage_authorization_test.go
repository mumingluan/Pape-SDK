package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	storageclient "pape-sdk/internal/storage"
	"pape-sdk/internal/store"
)

func TestStorageAuthorizationUsesBFFAndStorageAdminAPI(t *testing.T) {
	storageServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/upload-tokens" || r.Header.Get("Authorization") != "Bearer admin-secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var request storageclient.AcquireRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.ChannelID != "LocalDataRecord" || request.Category != "CommonBiz/account" ||
			request.ObjectName != "HandBook_2_82797752.bin" || request.Extension != "bin" {
			t.Fatalf("storage request = %+v", request)
		}
		_ = json.NewEncoder(w).Encode(storageclient.AcquireResponse{
			Address: "https://storage-deepspace.papegames.com",
			URL:     "https://storage-deepspace.papegames.com/CommonBiz/account/HandBook_2_82797752.bin",
			AddForm: map[string]string{
				"key": "CommonBiz/account/HandBook_2_82797752.bin", "x-oss-security-token": "temporary",
			},
			AddHeader: map[string]string{"Date": "Wed, 02 Sep 2026 09:22:35 GMT"},
		})
	}))
	defer storageServer.Close()
	storageClient, err := storageclient.New(storageServer.URL, "admin-secret", time.Second)
	if err != nil {
		t.Fatal(err)
	}
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
	bff := bffcrypto.BFF{AppID: "kmT84W9D", AppKey: "Efytc7XAliCx1P4Z", AESKey: "fVFLsy60quh79M2b"}
	a := &App{cfg: &config.Config{}, store: dataStore, bff: bff, objectStorage: storageClient}
	router := gin.New()
	a.mountAuthenticationRoutes(router)

	timestamp := int64(1788340955)
	inner := map[string]string{
		"token": user.Token, "channel_id": "LocalDataRecord", "category": "CommonBiz/account",
		"file_name": "HandBook_2_82797752.bin", "ext": "bin", "original_filename": "2.bin",
	}
	encrypted, err := bff.EncryptData(inner, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	outer := map[string]string{
		"app_id": bff.AppID, "clientid": "1068", "data": encrypted,
		"timestamp": "1788340955", "sign_type": "hmac",
	}
	outer["sign"] = bff.Sign(outer)
	values := url.Values{}
	for key, value := range outer {
		values.Set(key, value)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/user/oss/authorization", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var envelope struct {
		Code int    `json:"code"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Code != 0 {
		t.Fatalf("response = %s", recorder.Body.String())
	}
	decrypted, err := bff.DecryptData(envelope.Data, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted["address"] != "https://storage-deepspace.papegames.com" ||
		!strings.Contains(decrypted["add_form"], "temporary") {
		t.Fatalf("decrypted response = %+v", decrypted)
	}
}
