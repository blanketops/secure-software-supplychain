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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	immudb "github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// ptr returns a pointer to v, for the pointer fields of a record.
func ptr[T any](v T) *T { return &v }

// openStore connects to the immudb server from the environment. These tests
// need a running immudb and fail when there is none.
func openStore(t *testing.T) immudb.Store {
	t.Helper()
	s, err := immudb.Open()
	if err != nil {
		t.Fatalf("immudb is required for these tests: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// uniqueDigest returns an image digest no earlier run has stored evidence
// for: immudb keeps every write.
func uniqueDigest(t *testing.T) string {
	sum := sha256.Sum256([]byte(t.Name() + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// buildRecords is the evidence of one build as Collect returns it: the
// .sig tag holds the build's and Chains' signatures, the .att tag the
// authorization attestation and the SLSA provenance.
func buildRecords() []supplychainv1alpha1.SignatureRecord {
	const subject = "spiffe://td/ns/default/sa/supply-chain-runner"
	return []supplychainv1alpha1.SignatureRecord{
		{Kind: KindSignature, SignedBy: SignedByBuild, Subject: subject, Issuer: "https://oidc.example.idp",
			KeyFingerprint: "sha256:0123456789abcdef", RekorLogIndex: ptr(int64(100)), RekorLogID: "sha256:rekor"},
		{Kind: KindAttestation, SignedBy: SignedByBuild, Subject: subject,
			PredicateType: "https://blanketops.dev/authorization/v1", RekorLogIndex: ptr(int64(101)), RekorLogID: "sha256:rekor"},
		{Kind: KindSignature, SignedBy: SignedByChains, Subject: "spiffe://td/ns/tekton-chains/sa/tekton-chains-controller",
			RekorLogIndex: ptr(int64(102)), RekorLogID: "sha256:rekor"},
		{Kind: KindAttestation, SignedBy: SignedByChains, Subject: "spiffe://td/ns/tekton-chains/sa/tekton-chains-controller",
			PredicateType: "https://slsa.dev/provenance/v1", RekorLogIndex: ptr(int64(103)), RekorLogID: "sha256:rekor"},
	}
}

// TestBuildEvidenceIsOneTransaction: every record of a build, and its index,
// is written in one immudb transaction and reads back unchanged.
func TestBuildEvidenceIsOneTransaction(t *testing.T) {
	s := openStore(t)
	digest := uniqueDigest(t)
	records := buildRecords()

	tx, root, err := PutBuildEvidence(s, digest, records)
	if err != nil {
		t.Fatalf("PutBuildEvidence: %v", err)
	}
	t.Logf("build %s: %d records in immudb tx %d, root %x", digest, len(records), tx, root)

	got, err := ReadBuildEvidence(s, digest)
	if err != nil {
		t.Fatalf("ReadBuildEvidence: %v", err)
	}
	if got.Tx != tx {
		t.Fatalf("read tx %d; want the write's tx %d", got.Tx, tx)
	}
	if !reflect.DeepEqual(got.Records, records) {
		t.Fatalf("records read back differ:\n got %+v\nwant %+v", got.Records, records)
	}
	for n := range records {
		if _, rtx, _, err := s.Get(recordKey(digest, n)); err != nil || rtx != tx {
			t.Fatalf("record %d: tx %d, %v; want tx %d", n, rtx, err, tx)
		}
	}
}

// TestBuildEvidenceWrittenOnce: a second write for the same build is
// rejected and leaves the first one intact.
func TestBuildEvidenceWrittenOnce(t *testing.T) {
	s := openStore(t)
	digest := uniqueDigest(t)
	tx, _, err := PutBuildEvidence(s, digest, buildRecords())
	if err != nil {
		t.Fatalf("PutBuildEvidence: %v", err)
	}
	if _, _, err := PutBuildEvidence(s, digest, buildRecords()[:1]); !errors.Is(err, immudb.ErrDuplicate) {
		t.Fatalf("second PutBuildEvidence = %v; want ErrDuplicate", err)
	}
	got, err := ReadBuildEvidence(s, digest)
	if err != nil || got.Tx != tx || len(got.Records) != len(buildRecords()) {
		t.Fatalf("ReadBuildEvidence after the rejected write = %+v, %v; want the first write", got, err)
	}
}

func TestReadBuildEvidenceNotFound(t *testing.T) {
	if _, err := ReadBuildEvidence(openStore(t), uniqueDigest(t)); !errors.Is(err, immudb.ErrNotFound) {
		t.Fatalf("ReadBuildEvidence of an unknown build = %v; want ErrNotFound", err)
	}
}

// TestReadBuildEvidenceRejectsRecordFromAnotherTransaction: an index that
// lists a record written outside the build's transaction is not evidence of
// that build.
func TestReadBuildEvidenceRejectsRecordFromAnotherTransaction(t *testing.T) {
	s := openStore(t)
	digest := uniqueDigest(t)
	record, _ := json.Marshal(buildRecords()[0])
	if _, _, err := s.Put(recordKey(digest, 0), string(record)); err != nil {
		t.Fatalf("Put record: %v", err)
	}
	index, _ := json.Marshal(buildIndex{Digest: digest, Records: []string{recordKey(digest, 0)}})
	if _, _, err := s.Put(buildKey(digest), string(index)); err != nil {
		t.Fatalf("Put index: %v", err)
	}
	if _, err := ReadBuildEvidence(s, digest); err == nil {
		t.Fatal("ReadBuildEvidence accepted a record from another transaction")
	}
}

func TestPutBuildEvidenceRejectsEmpty(t *testing.T) {
	if _, _, err := PutBuildEvidence(nil, "", buildRecords()); err == nil {
		t.Error("PutBuildEvidence with no digest = nil error")
	}
	if _, _, err := PutBuildEvidence(nil, "sha256:abc", nil); err == nil {
		t.Error("PutBuildEvidence with no records = nil error")
	}
}
