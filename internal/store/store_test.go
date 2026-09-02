package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestLegacyUserIdentityMigrationUpdatesReferences(t *testing.T) {
	temp := t.TempDir()
	dbPath := filepath.Join(temp, "sdk.db")
	raw, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := raw.Exec(`
		create table users (id integer primary key autoincrement, phone text unique not null,
			openid text unique not null, nid integer unique not null, token text not null,
			refresh_token text, long_token text, password_hash text, deleted_at integer,
			created_at integer not null, last_login_at integer not null);
		create table comet_sessions (id text primary key, user_id integer not null, token text not null, created_at integer not null);
		insert into users(id, phone, openid, nid, token, created_at, last_login_at) values (7, '13800138000', '900000007', 251000007, 'token', ?, ?);
		insert into comet_sessions(id, user_id, token, created_at) values ('session', 7, 'comet', ?);`, now, now, now); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	dataStore, err := Open("sqlite://"+dbPath, temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, ok, err := dataStore.UserByPhone("13800138000")
	if err != nil || !ok || user.ID != firstUserID || user.OpenID != "100000001" || user.NID != firstUserID {
		t.Fatalf("migrated user=%+v ok=%t err=%v", user, ok, err)
	}
	var sessionUserID int64
	if err := dataStore.db.QueryRow("select user_id from comet_sessions where id = 'session'").Scan(&sessionUserID); err != nil || sessionUserID != firstUserID {
		t.Fatalf("session user_id=%d err=%v", sessionUserID, err)
	}
	for _, column := range []string{"openid", "nid"} {
		if exists, err := dataStore.hasUserColumn(column); err != nil || exists {
			t.Fatalf("legacy column %s still exists=%t err=%v", column, exists, err)
		}
	}
}

func TestUserIDsStartAtConfiguredBaseAndStayUnified(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	first, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := dataStore.GetOrCreateUser("13900139000")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != firstUserID || first.OpenID != "100000001" || first.NID != firstUserID {
		t.Fatalf("first user identity = %+v", first)
	}
	if second.ID != firstUserID+1 || second.OpenID != "100000002" || second.NID != firstUserID+1 {
		t.Fatalf("second user identity = %+v", second)
	}
}

func TestExistingUserKeepsStableOpenIDAndNID(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	first, created, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil || !created {
		t.Fatalf("first=%+v created=%t err=%v", first, created, err)
	}
	second, created, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil || created {
		t.Fatalf("second=%+v created=%t err=%v", second, created, err)
	}
	if second.ID != first.ID || second.OpenID != first.OpenID || second.NID != first.NID || second.Token == first.Token {
		t.Fatalf("identity changed across login: first=%+v second=%+v", first, second)
	}
}

func TestAccessAndRefreshTokensExpireAndCanBeRevoked(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	user, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || !ok {
		t.Fatalf("fresh access token rejected: ok=%t err=%v", ok, err)
	}
	if _, err := dataStore.db.Exec("update auth_sessions set access_expires_at = ? where access_token = ?", time.Now().Add(-time.Minute).Unix(), user.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || ok {
		t.Fatalf("expired access token accepted: ok=%t err=%v", ok, err)
	}
	if _, err := dataStore.TouchLogin(user.ID); err != nil {
		t.Fatal(err)
	}
	user, _, err = dataStore.UserByPhone("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if err := dataStore.RevokeTokens(user.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dataStore.UserByToken(user.Token); err != nil || ok {
		t.Fatalf("revoked access token accepted: ok=%t err=%v", ok, err)
	}
	if _, ok, err := dataStore.UserByRefreshToken(user.RefreshToken.String); err != nil || ok {
		t.Fatalf("revoked refresh token accepted: ok=%t err=%v", ok, err)
	}
}

func TestMultipleDeviceSessionsRefreshIndependently(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	first, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := dataStore.GetOrCreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	for name, session := range map[string]User{"first": first, "second": second} {
		if _, ok, err := dataStore.UserByToken(session.Token); err != nil || !ok {
			t.Fatalf("%s access token rejected: ok=%t err=%v", name, ok, err)
		}
		if _, ok, err := dataStore.UserByRefreshToken(session.RefreshToken.String); err != nil || !ok {
			t.Fatalf("%s refresh token rejected: ok=%t err=%v", name, ok, err)
		}
	}
	refreshedFirst, newAccess, err := dataStore.RefreshByToken(first.RefreshToken.String)
	if err != nil {
		t.Fatal(err)
	}
	if newAccess == first.Token || refreshedFirst.RefreshToken.String == first.RefreshToken.String {
		t.Fatalf("first session did not rotate: old=%+v new=%+v", first, refreshedFirst)
	}
	if _, ok, err := dataStore.UserByRefreshToken(first.RefreshToken.String); err != nil || ok {
		t.Fatalf("used refresh token remained valid: ok=%t err=%v", ok, err)
	}
	if _, ok, err := dataStore.UserByToken(first.Token); err != nil || ok {
		t.Fatalf("rotated access token remained valid: ok=%t err=%v", ok, err)
	}
	if _, ok, err := dataStore.UserByRefreshToken(second.RefreshToken.String); err != nil || !ok {
		t.Fatalf("second device refresh token was invalidated: ok=%t err=%v", ok, err)
	}
	if _, ok, err := dataStore.UserByToken(second.Token); err != nil || !ok {
		t.Fatalf("second device access token was invalidated: ok=%t err=%v", ok, err)
	}
	if err := dataStore.RevokeSessionByToken(refreshedFirst.RefreshToken.String); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dataStore.UserByToken(refreshedFirst.Token); err != nil || ok {
		t.Fatalf("single-device revocation failed: ok=%t err=%v", ok, err)
	}
	if _, ok, err := dataStore.UserByToken(second.Token); err != nil || !ok {
		t.Fatalf("single-device revocation affected second device: ok=%t err=%v", ok, err)
	}
	if err := dataStore.RevokeTokens(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := dataStore.UserByToken(second.Token); err != nil || ok {
		t.Fatalf("account-wide revocation left second device active: ok=%t err=%v", ok, err)
	}
}
