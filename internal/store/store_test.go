package store

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCreateUserRetriesOpenIDAndNIDCollision(t *testing.T) {
	temp := t.TempDir()
	dataStore, err := Open("sqlite://"+filepath.Join(temp, "sdk.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer dataStore.Close()
	now := time.Now().Unix()
	if _, err := dataStore.db.Exec(
		"insert into users(phone, openid, nid, token, refresh_token, created_at, last_login_at) values (?, ?, ?, ?, ?, ?, ?)",
		"13800138000", "300000000", int64(251000001), "existing", "existing-refresh", now, now,
	); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	generate := func() (string, int64) {
		attempts++
		if attempts == 1 {
			return "300000000", 251000001
		}
		return "300000001", 251000002
	}
	user, created, err := dataStore.createUserWithIdentityGenerator("13900139000", generate)
	if err != nil {
		t.Fatal(err)
	}
	if !created || attempts != 2 || user.OpenID != "300000001" || user.NID != 251000002 {
		t.Fatalf("created=%t attempts=%d user=%+v", created, attempts, user)
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
