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

import "testing"

func fresh() Store {
	return newMemStore("immudb-spike-test-salt")
}

// TestPutGetVerifyRoundTrip: a record must verify against the root captured at
// the moment of the read.
func TestPutGetVerifyRoundTrip(t *testing.T) {
	s := fresh()
	rootA := putAndGet(t, s, "sig", "sha256:abc")
	rootB := putAndGet(t, s, "att", "sha256:def")

	if !verifyOK(t, s, rootA, rootIdx(t, s, "sig"), "sha256:abc") {
		t.Fatalf("expected Sig to verify against its own root")
	}
	if !verifyOK(t, s, rootB, rootIdx(t, s, "att"), "sha256:def") {
		t.Fatalf("expected Att to verify against its own root")
	}
}

// TestTamperDetection_Value: the core invariant. A read is verifiable against
// its frozen root; any change to the stored value after the read must fail it.
func TestTamperDetection_Value(t *testing.T) {
	s := fresh()
	root := putAndGet(t, s, "sig", "sha256:abc")
	idx := rootIdx(t, s, "sig")

	mutateValue(t, s, "sig", "sha256:abd") // a tamperer flipped a byte

	if ok, err := s.Verify(root, idx, "sha256:abc"); err != nil || ok {
		t.Fatalf("expected Verify(false) after value tamper: %v %v", ok, err)
	}
}

func TestDuplicateRejected(t *testing.T) {
	s := fresh()
	putAndGet(t, s, "sig", "sha256:abc")
	if _, _, err := s.Put("sig", "sha256:abc"); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate on repeated key, got %v", err)
	}
}

func TestNotFound(t *testing.T) {
	s := fresh()
	if _, _, _, err := s.Get("does-not-exist"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestIndexesSequential(t *testing.T) {
	s := fresh()
	for _, k := range []string{"sig", "att", "prov"} {
		if _, _, _, err := s.Get(k); err != ErrNotFound {
			t.Fatalf("before Put(%q): %v", k, err)
		}
		putAndGet(t, s, k, "sha256:xx")
	}
	for i, k := range []string{"sig", "att", "prov"} {
		if got := rootIdx(t, s, k); got != uint64(i) {
			t.Fatalf("index of %s = %d, want %d", k, got, i)
		}
	}
}

func TestAppendDoesNotBreakEarlierProof(t *testing.T) {
	s := fresh()
	root := putAndGet(t, s, "sig", "sha256:abc")
	idx := rootIdx(t, s, "sig")

	if !verifyOK(t, s, root, idx, "sha256:abc") {
		t.Fatalf("expected Sig to verify before further writes")
	}

	putAndGet(t, s, "att", "sha256:def") // later append must not invalidate the first proof

	if !verifyOK(t, s, root, idx, "sha256:abc") {
		t.Fatalf("expected Sig to remain valid after an append")
	}
}

func TestLeafInjective(t *testing.T) {
	s := fresh()
	putAndGet(t, s, "sig", "sha256:abc")
	putAndGet(t, s, "att", "sha256:abc") // same value, different key must land at a different index
	if rootIdx(t, s, "sig") == rootIdx(t, s, "att") {
		t.Fatalf("distinct entries must be at distinct indices")
	}
}

func putAndGet(t *testing.T, s Store, key, value string) []byte {
	t.Helper()
	idx, root, err := s.Put(key, value)
	if err != nil {
		t.Fatalf("Put(%q): %v", key, err)
	}
	if got, _, _, err := s.Get(key); err != nil || got != value {
		t.Fatalf("Get mismatch: got %q, %v", got, err)
	}
	if idx != rootIdx(t, s, key) {
		t.Fatalf("put index %d != get index %d", idx, rootIdx(t, s, key))
	}
	return root
}

func rootIdx(t *testing.T, s Store, key string) uint64 {
	t.Helper()
	_, idx, _, err := s.Get(key)
	if err != nil {
		t.Fatalf("Get(%q): %v", key, err)
	}
	return idx
}

func verifyOK(t *testing.T, s Store, root []byte, idx uint64, value string) bool {
	t.Helper()
	ok, err := s.Verify(root, idx, value)
	return err == nil && ok
}

// mutateValue simulates an external storage tamper: it flips the value stored
// for a key after a read, so Verify() must report that the snapshot is no longer
// authentic. It reaches through the concrete memStore (white-box, same package)
// to exercise the tamper path without building a real immudb server.
func mutateValue(t *testing.T, s Store, key, value string) {
	t.Helper()
	m := s.(*memStore)
	m.valByKey[key] = value
}
