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
	if _, ok, err := s.AdminAccountByID(user.ID); err != nil || ok {
		t.Fatalf("deleted account ok=%t err=%v", ok, err)
	}
}
