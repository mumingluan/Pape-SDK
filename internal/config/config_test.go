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
