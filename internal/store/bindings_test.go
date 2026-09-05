package store

import (
	"path/filepath"
	"testing"
)

func TestBindingsLifecycleAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := Open("sqlite://"+path, "")
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.CreateAccount("", "TEST@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.ID < firstUserID {
		t.Fatal(u.ID)
	}
	phone := "13800138000"
	if err = s.UpdateBindings(u.ID, &phone, nil); err != nil {
		t.Fatal(err)
	}
	for _, account := range []string{phone, "test@example.com"} {
		v, ok, err := s.UserByPhone(account)
		if err != nil || !ok || v.ID != u.ID {
			t.Fatalf("lookup %s: %v %v", account, ok, err)
		}
	}
	if _, err = s.CreateAccount("13900139000", "test@example.com", ""); err == nil {
		t.Fatal("duplicate email accepted")
	}
	empty := ""
	if err = s.UpdateBindings(u.ID, &empty, nil); err != nil {
		t.Fatal(err)
	}
	if err = s.UpdateBindings(u.ID, nil, &empty); err == nil {
		t.Fatal("last binding removed")
	}
	v, err := s.CreateAccount("13900139000", "other@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err = s.HardDeleteUser(u.ID); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open("sqlite://"+path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	restored, ok, err := s.UserByPhone("other@example.com")
	if err != nil || !ok || restored.ID != v.ID {
		t.Fatalf("identity lost after restart: %v %v", restored, err)
	}
	if _, err = s.CreateAccount("", "", ""); err == nil {
		t.Fatal("empty bindings accepted")
	}
}
