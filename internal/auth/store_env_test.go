package auth

import "testing"

func TestParseKeysGood(t *testing.T) {
	m, err := ParseKeys("k1:dev:Dev Tenant, k2:acme-corp:Acme Corp,k3:solo")
	if err != nil {
		t.Fatal(err)
	}
	if m["k1"] != (Tenant{ID: "dev", Name: "Dev Tenant"}) || m["k2"].ID != "acme-corp" || m["k3"].Name != "solo" {
		t.Fatalf("unexpected: %+v", m)
	}
}

func TestParseKeysMalformed(t *testing.T) {
	for _, in := range []string{"onlykey", ":tenant:Name", "key::Name"} {
		if _, err := ParseKeys(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestNewStoreFromEnv(t *testing.T) {
	t.Setenv(EnvKeys, "")
	s, err := NewStoreFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate("Bearer key-dev-local"); err != nil {
		t.Error("empty env should fall back to default store")
	}
	t.Setenv(EnvKeys, "k1:dev:Dev")
	s, _ = NewStoreFromEnv()
	if _, err := s.Authenticate("Bearer k1"); err != nil {
		t.Error("env key should authenticate")
	}
	if _, err := s.Authenticate("Bearer key-dev-local"); err == nil {
		t.Error("dev key must not work when env is set")
	}
	t.Setenv(EnvKeys, "bad")
	if _, err := NewStoreFromEnv(); err == nil {
		t.Error("expected error for malformed env")
	}
}
