package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"pape-sdk/internal/config"
	bffcrypto "pape-sdk/internal/crypto"
	"pape-sdk/internal/store"
)

type authenticationEnvelope struct {
	Code int             `json:"code"`
	Info string          `json:"info"`
	Data json.RawMessage `json:"data"`
}

func TestPasswordLoginDoesNotRevealAccountState(t *testing.T) {
	dataStore, err := store.Open("sqlite://"+filepath.Join(t.TempDir(), "sdk.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()

	withPassword, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := dataStore.GetOrCreateUser("13900139000"); err != nil {
		t.Fatal(err)
	}
	a := &App{store: dataStore}
	if err := a.setPassword(withPassword.ID, "correct-password"); err != nil {
		t.Fatal(err)
	}

	for name, credentials := range map[string][2]string{
		"unknown account": {"13700137000", "wrong-password"},
		"unset password":  {"13900139000", "wrong-password"},
		"wrong password":  {"13800138000", "wrong-password"},
		"invalid account": {"not-a-phone", "wrong-password"},
		"empty password":  {"13800138000", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := a.passwordLogin(credentials[0], credentials[1])
			if err == nil || err.Error() != "用户名或密码有误" {
				t.Fatalf("passwordLogin() error = %v, want 用户名或密码有误", err)
			}
		})
	}
}

func TestAuthenticationEndpointsDoNotExposeAccountExistence(t *testing.T) {
	dataStore, err := store.Open("sqlite://"+filepath.Join(t.TempDir(), "sdk.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	bff := bffcrypto.BFF{AppID: "1010013", AppKey: "test-key", AESKey: "1234567890abcdef"}
	a := &App{
		cfg:                &config.Config{Auth: config.Authentication{RealPassword: true, AllowRegister: true}},
		store:              dataStore,
		bff:                bff,
		userCenterBFF:      bff,
		userCenterClientID: "1003",
	}
	if err := a.setPassword(user.ID, "correct-password"); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	a.mountAuthenticationRoutes(router)
	a.mountAccountCompatibilityRoutes(router)

	forged := rawAuthenticationRequest(t, router, "/v1/user/login", map[string]string{
		"clientid": "1003", "phone": "13800138000", "sig": "forged",
	})
	if forged.Code == 0 {
		t.Fatalf("forged sig was accepted: %#v", forged)
	}
	withoutProof := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{"phone": "13800138000"})
	if withoutProof.Code == 0 {
		t.Fatalf("login without password or SMS proof was accepted: %#v", withoutProof)
	}
	if err := dataStore.MirrorSMS("13600136000", "login", "246810", "test"); err != nil {
		t.Fatal(err)
	}
	smsLogin := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{
		"phone": "13600136000", "scene": "login", "code": "246810",
	})
	if smsLogin.Code != 0 {
		t.Fatalf("valid SMS login was rejected: %#v", smsLogin)
	}
	replayedSMS := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{
		"phone": "13600136000", "scene": "login", "code": "246810",
	})
	if replayedSMS.Code == 0 {
		t.Fatalf("consumed SMS code was accepted twice: %#v", replayedSMS)
	}

	for name, fields := range map[string]map[string]string{
		"unknown account": {"phone": "13700137000", "password": "wrong-password"},
		"wrong password":  {"phone": "13800138000", "password": "wrong-password"},
		"invalid account": {"phone": "not-a-phone", "password": "wrong-password"},
		"empty password":  {"phone": "13800138000", "password": ""},
	} {
		t.Run(name, func(t *testing.T) {
			envelope := authenticationRequest(t, router, bff, "/v1/user/login", fields)
			if envelope.Code != 1 || envelope.Info != "用户名或密码有误" {
				t.Fatalf("login response = code %d info %q", envelope.Code, envelope.Info)
			}
		})
	}

	existing := authenticationRequest(t, router, bff, "/v1/user/account/exists", map[string]string{"phone": "13800138000"})
	missing := authenticationRequest(t, router, bff, "/v1/user/account/exists", map[string]string{"phone": "13700137000"})
	for _, envelope := range []authenticationEnvelope{existing, missing} {
		var data map[string]any
		if err := json.Unmarshal(envelope.Data, &data); err != nil {
			t.Fatal(err)
		}
		if envelope.Code != 0 || data["exists"] != true || data["account_exists"] != true {
			t.Fatalf("account exists response exposes state: %#v", envelope)
		}
	}

	if err := dataStore.MirrorSMS("13800138000", "password", "138000", "test"); err != nil {
		t.Fatal(err)
	}
	if err := dataStore.MirrorSMS("13700137000", "password", "137000", "test"); err != nil {
		t.Fatal(err)
	}
	existingReset := authenticationRequest(t, router, bff, "/v1/user/password/reset", map[string]string{
		"phone": "13800138000", "code": "138000", "scene": "password", "password": "new-password",
	})
	missingReset := authenticationRequest(t, router, bff, "/v1/user/password/reset", map[string]string{
		"phone": "13700137000", "code": "137000", "scene": "password", "password": "new-password",
	})
	if existingReset.Code != 0 || missingReset.Code != 0 || string(existingReset.Data) != string(missingReset.Data) {
		t.Fatalf("password reset responses differ: existing=%#v missing=%#v", existingReset, missingReset)
	}
	if _, ok, err := dataStore.UserByPhone("13700137000"); err != nil || ok {
		t.Fatalf("password reset created a missing account: ok=%t err=%v", ok, err)
	}

	if err := dataStore.MirrorSMS("13800138000", "register", "138000", "test"); err != nil {
		t.Fatal(err)
	}
	if err := dataStore.MirrorSMS("13600136000", "register", "136000", "test"); err != nil {
		t.Fatal(err)
	}
	existingRegistration := authenticationRequest(t, router, bff, "/v1/user/mobile/register", map[string]string{
		"phone": "13800138000", "code": "138000", "scene": "register",
	})
	missingRegistration := authenticationRequest(t, router, bff, "/v1/user/mobile/register", map[string]string{
		"phone": "13600136000", "code": "136000", "scene": "register",
	})
	if existingRegistration.Code != 0 || missingRegistration.Code != 0 {
		t.Fatalf("registration reveals account state: existing=%#v missing=%#v", existingRegistration, missingRegistration)
	}

	unauthenticatedBind := authenticationRequest(t, router, bff, "/v1/user/account/bind", map[string]string{
		"phone": "13500135000", "code": "135000", "scene": "bind",
	})
	if unauthenticatedBind.Code == 0 {
		t.Fatalf("account bind accepted a request without a login token: %#v", unauthenticatedBind)
	}
	unchanged, ok, err := dataStore.UserByPhone("13800138000")
	if err != nil || !ok || unchanged.ID != user.ID {
		t.Fatalf("account bind changed the latest user without authentication: ok=%t err=%v user=%#v", ok, err, unchanged)
	}
}

func TestRegistrationAndSMSOnlyPolicies(t *testing.T) {
	dataStore, err := store.Open("sqlite://"+filepath.Join(t.TempDir(), "sdk.db"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	bff := bffcrypto.BFF{AppID: "1010013", AppKey: "test-key", AESKey: "1234567890abcdef"}
	a := &App{
		cfg:                &config.Config{Auth: config.Authentication{RealPassword: true}},
		store:              dataStore,
		bff:                bff,
		userCenterBFF:      bff,
		userCenterClientID: "1003",
	}
	router := gin.New()
	a.mountAuthenticationRoutes(router)

	const blockedPhone = "13500135000"
	if _, issued, err := a.issueSMSForScene(blockedPhone, "register", "test", false); err != nil || issued {
		t.Fatalf("registration-disabled SMS issued=%t err=%v", issued, err)
	}
	if err := dataStore.CheckSMS(blockedPhone, "register", blockedPhone[len(blockedPhone)-6:]); err == nil {
		t.Fatal("registration-disabled fake SMS code was stored")
	}
	if err := dataStore.MirrorSMS(blockedPhone, "register", "135000", "test"); err != nil {
		t.Fatal(err)
	}
	blocked := authenticationRequest(t, router, bff, "/v1/user/mobile/register", map[string]string{
		"phone": blockedPhone, "scene": "register", "code": "135000", "password": "blocked-password",
	})
	if blocked.Code == 0 {
		t.Fatalf("registration-disabled account was created: %#v", blocked)
	}
	if _, ok, err := dataStore.UserByPhone(blockedPhone); err != nil || ok {
		t.Fatalf("blocked phone exists=%t err=%v", ok, err)
	}

	a.cfg.Auth.AllowRegister = true
	a.cfg.Auth.SMSOnlyRegister = true
	passwordUser, _, err := dataStore.GetOrCreateUser("13600136000")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.setPassword(passwordUser.ID, "existing-password"); err != nil {
		t.Fatal(err)
	}
	passwordlessUser, _, err := dataStore.GetOrCreateUser("13700137000")
	if err != nil {
		t.Fatal(err)
	}
	for _, phone := range []string{passwordUser.Phone, passwordlessUser.Phone} {
		if _, issued, err := a.issueSMSForScene(phone, "login", "test", false); err != nil || issued {
			t.Fatalf("existing account login SMS phone=%s issued=%t err=%v", phone, issued, err)
		}
	}
	if err := dataStore.MirrorSMS(passwordUser.Phone, "login", "136000", "test"); err != nil {
		t.Fatal(err)
	}
	smsLogin := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{
		"phone": passwordUser.Phone, "scene": "login", "code": "136000",
	})
	if smsLogin.Code == 0 {
		t.Fatalf("existing account logged in by injected SMS: %#v", smsLogin)
	}
	passwordLogin := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{
		"phone": passwordUser.Phone, "password": "existing-password",
	})
	if passwordLogin.Code != 0 {
		t.Fatalf("password login rejected: %#v", passwordLogin)
	}
	passwordlessLogin := authenticationRequest(t, router, bff, "/v1/user/login", map[string]string{
		"phone": passwordlessUser.Phone, "password": "any-password",
	})
	if passwordlessLogin.Code == 0 {
		t.Fatalf("passwordless account logged in before recovery: %#v", passwordlessLogin)
	}

	const newPhone = "13800138000"
	code, issued, err := a.issueSMSForScene(newPhone, "register", "test", false)
	if err != nil || !issued {
		t.Fatalf("new-account registration SMS issued=%t err=%v", issued, err)
	}
	registered := authenticationRequest(t, router, bff, "/v1/user/mobile/register", map[string]string{
		"phone": newPhone, "scene": "register", "code": code, "password": "new-password",
	})
	if registered.Code != 0 {
		t.Fatalf("new-account registration rejected: %#v", registered)
	}

	recoveryCode, issued, err := a.issueSMSForScene(passwordlessUser.Phone, "password", "test", false)
	if err != nil || !issued {
		t.Fatalf("passwordless recovery SMS issued=%t err=%v", issued, err)
	}
	recovered := authenticationRequest(t, router, bff, "/v1/user/password/reset", map[string]string{
		"phone": passwordlessUser.Phone, "scene": "password", "code": recoveryCode, "password": "first-password",
	})
	if recovered.Code != 0 {
		t.Fatalf("first password setup rejected: %#v", recovered)
	}
	if _, issued, err := a.issueSMSForScene(passwordlessUser.Phone, "password", "test", false); err != nil || issued {
		t.Fatalf("password recovery remained enabled after setup: issued=%t err=%v", issued, err)
	}
	if err := dataStore.MirrorSMS(passwordlessUser.Phone, "password", "137000", "test"); err != nil {
		t.Fatal(err)
	}
	authenticationRequest(t, router, bff, "/v1/user/password/reset", map[string]string{
		"phone": passwordlessUser.Phone, "scene": "password", "code": "137000", "password": "replacement-password",
	})
	if _, err := a.passwordLogin(passwordlessUser.Phone, "first-password"); err != nil {
		t.Fatalf("injected recovery changed existing password: %v", err)
	}
	if _, err := a.passwordLogin(passwordlessUser.Phone, "replacement-password"); err == nil {
		t.Fatal("replacement password was accepted")
	}

	if code, issued, err := a.issueSMSForScene(passwordUser.Phone, "cancellation", "test", false); err != nil || !issued {
		t.Fatalf("cancellation SMS issued=%t code=%q err=%v", issued, code, err)
	}
	if code, issued, err := a.issueSMSForScene("13900139000", "change_phone", "test", false); err != nil || !issued {
		t.Fatalf("change-phone SMS issued=%t code=%q err=%v", issued, code, err)
	}
}

func rawAuthenticationRequest(t *testing.T, router http.Handler, path string, fields map[string]string) authenticationEnvelope {
	t.Helper()
	values := url.Values{}
	for key, value := range fields {
		values.Set(key, value)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	var envelope authenticationEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	return envelope
}

func authenticationRequest(t *testing.T, router http.Handler, bff bffcrypto.BFF, path string, fields map[string]string) authenticationEnvelope {
	t.Helper()
	signed := map[string]string{"clientid": "1003"}
	for key, value := range fields {
		signed[key] = value
	}
	signed["sign"] = bff.Sign(signed)
	values := url.Values{}
	for key, value := range signed {
		values.Set(key, value)
	}
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s returned HTTP %d: %s", path, recorder.Code, recorder.Body.String())
	}
	var envelope authenticationEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode %s response: %v", path, err)
	}
	return envelope
}
