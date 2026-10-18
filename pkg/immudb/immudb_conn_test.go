/*
Copyright 2026 The BlanketOps Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package immudb

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// TestImmudbClientIntegration talks to a real immudb server. It calls New()
// directly rather than Open(), so it cannot pass on the in-memory fallback.
// It is skipped only when nothing listens on IMMUDB_ADDR:IMMUDB_PORT; once a
// server is reachable, any login or session error fails the test.
func TestImmudbClientIntegration(t *testing.T) {
	addr := getenv("IMMUDB_ADDR", "127.0.0.1")
	port := getenvInt("IMMUDB_PORT", 3322)
	user := getenv("IMMUDB_USER", "immudb")
	password := getenv("IMMUDB_PASSWORD", "immudb")
	database := getenv("IMMUDB_DB", "securesoftwaresupplychain")

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), 2*time.Second)
	if err != nil {
		t.Skipf("no immudb server at %s:%d: %v", addr, port, err)
	}
	_ = conn.Close()

	s, err := New(addr, port, user, password, database)
	if err != nil {
		t.Fatalf("New(%s:%d, user=%s, db=%s): %v", addr, port, user, database, err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// A unique key per run: immudb is persistent, so a fixed key would collide
	// with the previous run's record.
	key := "signature:test-build-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	value := `{"kind":"signature","subject":"spiffe://td/ns/default/sa/supply-chain-runner","issuer":"https://oidc.example.idp","keyFingerprint":"sha256:0123456789abcdef"}`
	idx, root, err := s.Put(key, value)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Logf("write: key=%s tx=%d root=%x", key, idx, root)

	got, ridx, rroot, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != value {
		t.Fatalf("Get value mismatch: got %q want %q", got, value)
	}
	t.Logf("read: key=%s tx=%d root=%x", key, ridx, rroot)

	ok, err := s.Verify(rroot, ridx, got)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for an untampered record")
	}

	if ok, _ := s.Verify(rroot, ridx, got+"tampered"); ok {
		t.Fatal("Verify accepted a tampered value")
	}
}
