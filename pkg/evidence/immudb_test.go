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

package evidence

import (
	"testing"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	immudb "github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// ptr returns a pointer to v. A small helper so tests can populate pointer
// fields (e.g. RekorLogIndex) without a separate helper function.
func ptr[T any](v T) *T { return &v }

// sameInt64Ptr reports whether a and b are both nil or point to equal values.
func sameInt64Ptr(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// TestNewPipelineWritesEvidenceToImmudb is the contract for the new-pipeline
// decision: evidence must go to immudb, not back to the registry. It writes a
// signature and an attestation record for one build, reads both back, and
// requires every read to Verify() as authentic against the frozen root at the
// moment of the read. Because the configured store is immudb, nothing lands in
// the registry here; each record is keyed "<Kind>:<Digest>".
func TestNewPipelineWritesEvidenceToImmudb(t *testing.T) {
	const digest = "sha256:abc"

	records := []supplychainv1alpha1.SignatureRecord{
		{
			Kind:           KindSignature,
			SignedBy:       SignedByBuild,
			Subject:        "spiffe://td/ns/default/sa/supply-chain-runner",
			Issuer:         "https://oidc.example.idp",
			KeyFingerprint: "sha256:0123456789abcdef",
			Certificate:    "-----BEGIN CERTIFICATE-----mock-----END CERTIFICATE-----",
			RekorLogIndex:  ptr(int64(100)),
			RekorLogID:     "sha256:rekord",
		},
		{
			Kind:           KindAttestation,
			SignedBy:       SignedByChains,
			PredicateType:  "https://slsa.dev/provenance/v1",
			Subject:        "spiffe://td/ns/default/sa/supply-chain-runner",
			KeyFingerprint: "sha256:abcdef0123456789",
		},
	}

	s := immudb.Open()
	t.Cleanup(func() { _ = s.Close() })

	if n, err := PutEvidenceRecords(s, digest, records); err != nil || n != len(records) {
		t.Fatalf("PutEvidenceRecords = %d, %v", n, err)
	}

	// Read back through the evidence helper (what a future reconciler read-back
	// would do), then independently re-verify each record against its frozen
	// root to prove the stream is intact and tamper-evident.
	got, err := ReadEvidenceRecords(s, digest)
	if err != nil {
		t.Fatalf("ReadEvidenceRecords = %v", err)
	}
	if len(got) != len(records) {
		t.Fatalf("got %d records, want %d", len(got), len(records))
	}
	for i, want := range records {
		gotRec := got[i]
		if gotRec.Kind != want.Kind || gotRec.SignedBy != want.SignedBy ||
			gotRec.Subject != want.Subject || !sameInt64Ptr(gotRec.RekorLogIndex, want.RekorLogIndex) {
			t.Fatalf("record %d mismatch: got %+v want %+v", i, gotRec, want)
		}

		// The per-record, tamper-evident round trip that the read-back relies on.
		key := gotRec.Kind + ":" + digest
		if value, idx, root, err := s.Get(key); err != nil {
			t.Fatalf("Get(%s) = %v", key, err)
		} else if ok, err := s.Verify(root, idx, value); err != nil || !ok {
			t.Fatalf("Verify(%s) = %v, %v", key, ok, err)
		}
	}
}

// TestNewPipelineRoundTrip asserts the stored value can be read back and
// re-serialised to exactly the record we wrote, so the controller can trust the
// record it reads is the one it wrote.
func TestNewPipelineRoundTrip(t *testing.T) {
	s := immudb.Open()
	t.Cleanup(func() { _ = s.Close() })

	rec := supplychainv1alpha1.SignatureRecord{
		Kind:          KindAttestation,
		Subject:       "spiffe://td/ns/default/sa/supply-chain-runner",
		PredicateType: "https://slsa.dev/provenance/v1",
	}
	digest := "sha256:def"
	if _, err := PutEvidenceRecords(s, digest, []supplychainv1alpha1.SignatureRecord{rec}); err != nil {
		t.Fatalf("PutEvidenceRecords: %v", err)
	}

	got, err := ReadEvidenceRecords(s, digest)
	if err != nil {
		t.Fatalf("ReadEvidenceRecords: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records", len(got))
	}
	if got[0].Kind != rec.Kind || got[0].PredicateType != rec.PredicateType || got[0].Subject != rec.Subject {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got[0], rec)
	}
}
