package store

import (
	"path/filepath"
	"testing"
)

func TestAdminAccountCRUD(t *testing.T) {
	temp := t.TempDir()
	s, err := Open("sqlite://"+filepath.Join(temp, "admin.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, err := s.CreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	accounts, err := s.AdminAccounts("1380013", 50, 0)
	if err != nil || len(accounts) != 1 || accounts[0].ID != user.ID {
		t.Fatalf("accounts=%+v err=%v", accounts, err)
	}
	if err := s.AdminUpdateAccount(user.ID, "13900139000"); err != nil {
		t.Fatal(err)
	}
	account, ok, err := s.AdminAccountByID(user.ID)
	if err != nil || !ok || account.Phone != "13900139000" {
		t.Fatalf("account=%+v ok=%t err=%v", account, ok, err)
	}
	if err := s.DeleteUser(user.ID); err != nil {
		t.Fatal(err)
	}
	deleted, ok, err := s.AdminAccountByID(user.ID)
	if err != nil || !ok || deleted.DeletedAt == 0 {
		t.Fatalf("soft deleted account=%+v ok=%t err=%v", deleted, ok, err)
	}
	if err := s.RestoreUser(user.ID, "13700137000"); err != nil {
		t.Fatal(err)
	}
	restored, ok, err := s.AdminAccountByID(user.ID)
	if err != nil || !ok || restored.DeletedAt != 0 || restored.Phone != "13700137000" {
		t.Fatalf("restored account=%+v ok=%t err=%v", restored, ok, err)
	}
	if err := s.HardDeleteUser(user.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.AdminAccountByID(user.ID); err != nil || ok {
		t.Fatalf("hard deleted account ok=%t err=%v", ok, err)
	}
}

func TestAccountSecurityStatus(t *testing.T) {
	temp := t.TempDir()
	s, err := Open("sqlite://"+filepath.Join(temp, "security.db"), temp)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, err := s.CreateUser("13800138000")
	if err != nil {
		t.Fatal(err)
	}
	if safe, err := s.UserSafeStatus(user.ID); err != nil || !safe {
		t.Fatalf("new account safe=%t err=%v", safe, err)
	}
	if err := s.SetPasswordHash(user.ID, "first-hash"); err != nil {
		t.Fatal(err)
	}
	if safe, err := s.UserSafeStatus(user.ID); err != nil || !safe {
		t.Fatalf("first password safe=%t err=%v", safe, err)
	}
	if err := s.SetPasswordHash(user.ID, "changed-hash"); err != nil {
		t.Fatal(err)
	}
	if safe, err := s.UserSafeStatus(user.ID); err != nil || safe {
		t.Fatalf("changed password safe=%t err=%v", safe, err)
	}
	if err := s.SetSecurityOverride(user.ID, true); err != nil {
		t.Fatal(err)
	}
	if safe, err := s.UserSafeStatus(user.ID); err != nil || !safe {
		t.Fatalf("manual safe override=%t err=%v", safe, err)
	}
	if err := s.UpdatePhone(user.ID, "13900139000"); err != nil {
		t.Fatal(err)
	}
	account, ok, err := s.AdminAccountByID(user.ID)
	if err != nil || !ok || account.IsSafe || account.SecurityOverride != nil || account.SecurityChangedAt == 0 {
		t.Fatalf("phone change account=%+v ok=%t err=%v", account, ok, err)
	}
}
