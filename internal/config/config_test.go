package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadBOOIInnerByServerID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte(`
db_uri: sqlite://./data.db
booi_inner:
  500058:
    base_url: http://127.0.0.1:18082
    auth_token: local
  500059:
    base_url: http://100.64.0.1:18082
    auth_token: remote
    timeout_seconds: 9
`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.BOOIInner) != 2 || cfg.BOOIInner[500058].TimeoutSeconds != 5 || cfg.BOOIInner[500059].TimeoutSeconds != 9 {
		t.Fatalf("booi_inner=%+v", cfg.BOOIInner)
	}
}

func TestLoadPatchListPassthrough(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("db_uri: sqlite://./data.db\npatchlist:\n  passthrough: true\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PatchList.Passthrough {
		t.Fatal("patchlist passthrough was not loaded")
	}
}

func TestLoadRejectsLegacyFieldNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("db_uri: sqlite://./data.db\nsdk:\n  bindhost: 127.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("legacy bindhost field was silently accepted")
	}
}

func TestExampleConfigUsesCurrentSchema(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "config.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sdk.BindPort != 8088 || cfg.Inner.BindPort != 18081 || cfg.UserCenter.BindPort != 8089 || cfg.Proxy.BindPort != 8888 {
		t.Fatalf("unexpected example listeners: sdk=%d inner=%d user_center=%d proxy=%d", cfg.Sdk.BindPort, cfg.Inner.BindPort, cfg.UserCenter.BindPort, cfg.Proxy.BindPort)
	}
}
