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
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// openTestStore connects to the immudb server from the environment (see
// Open), on the test database, never the pipeline's. The tests need a
// running immudb and fail when there is none.
func openTestStore(t *testing.T) Store {
	t.Helper()
	// immudbtest.Use, which this package cannot import: it imports immudb.
	name := os.Getenv("IMMUDB_TEST_DB")
	if name == "" {
		name = "securesoftwaresupplychain_test"
	}
	if !strings.HasSuffix(name, "_test") {
		t.Fatalf("IMMUDB_TEST_DB=%s does not end in _test; tests do not write to a pipeline database", name)
	}
	if err := CreateDatabase(name); err != nil {
		t.Fatalf("immudb is required for these tests: %v", err)
	}
	t.Setenv("IMMUDB_DB", name)
	s, err := Open()
	if err != nil {
		t.Fatalf("immudb is required for these tests: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// uniqueKey returns a key no earlier run has written: immudb keeps every
// write, so fixed keys would collide with the previous run.
func uniqueKey(t *testing.T, name string) string {
	return t.Name() + "/" + name + "/" + strconv.FormatInt(time.Now().UnixNano(), 10)
}

func put(t *testing.T, s Store, key, value string) (uint64, []byte) {
	t.Helper()
	tx, root, err := s.Put(key, value)
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	if tx == 0 || len(root) == 0 {
		t.Fatalf("Put(%q) = tx %d, root %x: want a transaction and its root", key, tx, root)
	}
	return tx, root
}

func TestPutGetVerifyRoundTrip(t *testing.T) {
	s := openTestStore(t)
	key, value := uniqueKey(t, "sig"), "sha256:abc"
	tx, root := put(t, s, key, value)

	got, gtx, groot, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != value || gtx != tx || !bytes.Equal(groot, root) {
		t.Fatalf("Get = %q, tx %d, root %x; want %q, tx %d, root %x", got, gtx, groot, value, tx, root)
	}
	if ok, err := s.Verify(key, root, tx, value); err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true", ok, err)
	}
}

// TestVerifyRejectsTampering: Verify must fail for any value, root, key or
// transaction other than the ones written.
func TestVerifyRejectsTampering(t *testing.T) {
	s := openTestStore(t)
	key := uniqueKey(t, "sig")
	tx, root := put(t, s, key, "sha256:abc")
	otherTx, otherRoot := put(t, s, uniqueKey(t, "att"), "sha256:abc")

	cases := map[string]struct {
		key   string
		root  []byte
		tx    uint64
		value string
	}{
		"value":       {key, root, tx, "sha256:abd"},
		"root":        {key, otherRoot, tx, "sha256:abc"},
		"transaction": {key, root, otherTx, "sha256:abc"},
		"key":         {uniqueKey(t, "absent"), root, tx, "sha256:abc"},
	}
	for name, c := range cases {
		if ok, err := s.Verify(c.key, c.root, c.tx, c.value); ok {
			t.Errorf("Verify with a different %s = true (err %v); want false", name, err)
		}
	}
}

func TestDuplicateRejected(t *testing.T) {
	s := openTestStore(t)
	key := uniqueKey(t, "sig")
	put(t, s, key, "sha256:abc")
	if _, _, err := s.Put(key, "sha256:other"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second Put = %v; want ErrDuplicate", err)
	}
	if got, _, _, err := s.Get(key); err != nil || got != "sha256:abc" {
		t.Fatalf("Get after rejected Put = %q, %v; want the first value", got, err)
	}
}

func TestNotFound(t *testing.T) {
	s := openTestStore(t)
	if _, _, _, err := s.Get(uniqueKey(t, "absent")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get = %v; want ErrNotFound", err)
	}
}

// TestPutAllIsOneTransaction: every entry of a PutAll lands in the same
// transaction and verifies against its root.
func TestPutAllIsOneTransaction(t *testing.T) {
	s := openTestStore(t)
	entries := []Entry{
		{Key: uniqueKey(t, "sig"), Value: "signature"},
		{Key: uniqueKey(t, "att"), Value: "attestation"},
		{Key: uniqueKey(t, "sbom"), Value: "sbom"},
	}
	tx, root, err := s.PutAll(entries)
	if err != nil {
		t.Fatalf("PutAll: %v", err)
	}
	for _, e := range entries {
		got, gtx, groot, err := s.Get(e.Key)
		if err != nil || got != e.Value || gtx != tx || !bytes.Equal(groot, root) {
			t.Fatalf("Get(%s) = %q, tx %d, %v; want %q in tx %d", e.Key, got, gtx, err, e.Value, tx)
		}
		if ok, err := s.Verify(e.Key, root, tx, e.Value); err != nil || !ok {
			t.Fatalf("Verify(%s) = %v, %v; want true", e.Key, ok, err)
		}
	}
}

// TestPutAllIsAtomic: if one key exists, none of the entries is written.
func TestPutAllIsAtomic(t *testing.T) {
	s := openTestStore(t)
	existing := uniqueKey(t, "existing")
	put(t, s, existing, "first")
	fresh := uniqueKey(t, "fresh")

	_, _, err := s.PutAll([]Entry{{Key: fresh, Value: "new"}, {Key: existing, Value: "second"}})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("PutAll with an existing key = %v; want ErrDuplicate", err)
	}
	if _, _, _, err := s.Get(fresh); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(%s) after the rejected PutAll = %v; want ErrNotFound", fresh, err)
	}
}

func TestPutAllRejectsRepeatedKeyAndEmpty(t *testing.T) {
	s := openTestStore(t)
	key := uniqueKey(t, "sig")
	if _, _, err := s.PutAll([]Entry{{Key: key, Value: "a"}, {Key: key, Value: "b"}}); err == nil {
		t.Fatal("PutAll with a repeated key = nil error")
	}
	if _, _, err := s.PutAll(nil); err == nil {
		t.Fatal("PutAll with no entries = nil error")
	}
}

// TestAppendDoesNotBreakEarlierProof: later writes must not invalidate the
// proof of an earlier one.
func TestAppendDoesNotBreakEarlierProof(t *testing.T) {
	s := openTestStore(t)
	key := uniqueKey(t, "sig")
	tx, root := put(t, s, key, "sha256:abc")
	put(t, s, uniqueKey(t, "att"), "sha256:def")

	if ok, err := s.Verify(key, root, tx, "sha256:abc"); err != nil || !ok {
		t.Fatalf("Verify after a later write = %v, %v; want true", ok, err)
	}
}

// TestReadFromAnotherSession: entries live in the database, not the client,
// so a second session reads and verifies what the first wrote.
func TestReadFromAnotherSession(t *testing.T) {
	key, value := uniqueKey(t, "sig"), "sha256:abc"
	tx, root := put(t, openTestStore(t), key, value)

	other := openTestStore(t)
	got, gtx, groot, err := other.Get(key)
	if err != nil || got != value || gtx != tx || !bytes.Equal(groot, root) {
		t.Fatalf("Get from a second session = %q, tx %d, root %x, %v; want %q, tx %d, root %x",
			got, gtx, groot, err, value, tx, root)
	}
	if ok, err := other.Verify(key, root, tx, value); err != nil || !ok {
		t.Fatalf("Verify from a second session = %v, %v; want true", ok, err)
	}
}

// TestOpenFailsWithoutServer: there is no fallback store; an unreachable
// server is an error.
func TestOpenFailsWithoutServer(t *testing.T) {
	t.Setenv("IMMUDB_PORT", "1")
	s, err := Open()
	if err == nil {
		_ = s.Close()
		t.Fatal("Open with no server = nil error; want ErrConnect")
	}
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("Open with no server = %v; want ErrConnect", err)
	}
}

func TestOpenFailsWithWrongPassword(t *testing.T) {
	t.Setenv("IMMUDB_PASSWORD", "not-the-password")
	s, err := Open()
	if err == nil {
		_ = s.Close()
		t.Fatal("Open with a wrong password = nil error; want ErrConnect")
	}
	if !errors.Is(err, ErrConnect) {
		t.Fatalf("Open with a wrong password = %v; want ErrConnect", err)
	}
}

// TestCreateDatabase: a database is created once and can be opened; creating
// it again is not an error.
func TestCreateDatabase(t *testing.T) {
	const name = "securesoftwaresupplychain_test"
	for range 2 {
		if err := CreateDatabase(name); err != nil {
			t.Fatalf("CreateDatabase(%s): %v", name, err)
		}
	}
	t.Setenv("IMMUDB_DB", name)
	s, err := Open()
	if err != nil {
		t.Fatalf("Open of the created database: %v", err)
	}
	defer func() { _ = s.Close() }()
	if s.Database() != name {
		t.Fatalf("opened %s; want %s", s.Database(), name)
	}
}

func TestCreateDatabaseRejectsBadName(t *testing.T) {
	if err := CreateDatabase("not-allowed"); err == nil {
		t.Fatal("CreateDatabase with a dash in the name = nil error")
	}
}
