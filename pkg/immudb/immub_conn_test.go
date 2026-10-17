package immudb

import (
	"fmt"
	"testing"
)

func TestImmuClientIntegration(t *testing.T) {
	t.Setenv("IMMUB_ADDR", "127.0.0.1")
	t.Setenv("IMMUB_PORT", "3322")
	t.Setenv("IMMUB_USER", "immub")
	t.Setenv("IMMUB_PASSWORD", "immudb")
	t.Setenv("IMMUB_DB", "securesoftwaresupplychain")

	s := Open()
	if s == nil {
		t.Fatal("Open() returned nil")
	}
	defer func() { _ = s.Close() }()

	key := "signature:test-build-001"
	value := `{"kind":"signature","build":"test-build-001","subject":"spiffe://td/ns/default/sa/supply-chain-runner","issuer":"https://oidc.example.idp","keyFingerprint":"sha256:0123456789abcdef"}`
	idx, root, err := s.Put(key, value)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Logf("Write OK: key=%s idx=%d root=%x", key, idx, root)

	got, ridx, rroot, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	t.Logf("Read OK: key=%s value=%q idx=%d root=%x", got, key, ridx, rroot)

	if got != key {
		t.Fatalf("Get value mismatch: got %q want %q", got, key)
	}

	ok, verr := s.Verify(root, idx, got)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatalf("Verify FAILED")
	}
	t.Log("RESULT: immudb connection verified and evidence recorded (tamper-evident).")
}
