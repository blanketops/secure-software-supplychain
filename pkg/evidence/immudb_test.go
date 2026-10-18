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
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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

// testBuild is a build no earlier run has stored evidence for: immudb keeps
// every write. Its image names the test, so test rows are told apart from
// real builds in the tables.
func testBuild(t *testing.T) Build {
	sum := sha256.Sum256([]byte(t.Name() + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return Build{
		Digest:     "sha256:" + hex.EncodeToString(sum[:]),
		Image:      "test.invalid/" + t.Name(),
		ImageBuild: "test/" + t.Name(),
		Commit:     "0123456789abcdef0123456789abcdef01234567",
	}
}

// buildRecords is the evidence of one build as Collect returns it: the
// .sig tag holds the build's and Chains' signatures, the .att tag the
// authorization attestation and the SLSA provenance.
func buildRecords() []supplychainv1alpha1.SignatureRecord {
	const subject = "spiffe://td/ns/default/sa/supply-chain-runner"
	at := func(min int) *metav1.Time {
		return ptr(metav1.NewTime(time.Date(2026, 10, 18, 11, min, 0, 0, time.UTC)))
	}
	return []supplychainv1alpha1.SignatureRecord{
		{Kind: KindSignature, SignedBy: SignedByBuild, Subject: subject, Issuer: "https://oidc.example.idp",
			KeyFingerprint: "sha256:0123456789abcdef", CertificateFingerprint: "sha256:fedcba9876543210",
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			NotBefore:   at(0), NotAfter: at(10), IntegratedAt: at(1),
			RekorLogIndex: ptr(int64(100)), RekorLogID: "sha256:rekor"},
		{Kind: KindAttestation, SignedBy: SignedByBuild, Subject: subject,
			PredicateType: "https://blanketops.dev/authorization/v1", RekorLogIndex: ptr(int64(101)), RekorLogID: "sha256:rekor"},
		{Kind: KindSignature, SignedBy: SignedByChains, Subject: "spiffe://td/ns/tekton-chains/sa/tekton-chains-controller"},
		{Kind: KindAttestation, SignedBy: SignedByChains, Subject: "spiffe://td/ns/tekton-chains/sa/tekton-chains-controller",
			PredicateType: "https://slsa.dev/provenance/v1", RekorLogIndex: ptr(int64(103)), RekorLogID: "sha256:rekor"},
		{Kind: KindAttestation, SignedBy: SignedByBuild, Subject: subject,
			PredicateType: "https://cyclonedx.org/bom", RekorLogIndex: ptr(int64(104)), RekorLogID: "sha256:rekor"},
	}
}

// sameRecords compares records the way the API server would serve them:
// as JSON, where a time is RFC 3339 whatever its location.
func sameRecords(t *testing.T, got, want []supplychainv1alpha1.SignatureRecord) {
	t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		t.Fatalf("records read back differ:\n got %s\nwant %s", g, w)
	}
}

// TestBuildEvidenceIsOneTransaction: the build's row and every record's row
// are written in one immudb transaction and read back unchanged.
func TestBuildEvidenceIsOneTransaction(t *testing.T) {
	s := openStore(t)
	b, records := testBuild(t), buildRecords()

	tx, root, err := PutBuildEvidence(s, b, records)
	if err != nil {
		t.Fatalf("PutBuildEvidence: %v", err)
	}
	if tx == 0 || len(root) == 0 {
		t.Fatalf("PutBuildEvidence = tx %d, root %x; want a transaction and its root", tx, root)
	}
	t.Logf("build %s: %d records in immudb tx %d, root %x", b.Digest, len(records), tx, root)

	got, err := ReadBuildEvidence(s, b.Digest)
	if err != nil {
		t.Fatalf("ReadBuildEvidence: %v", err)
	}
	if got.Tx != tx || string(got.Root) != string(root) {
		t.Fatalf("read tx %d root %x; want the write's tx %d root %x", got.Tx, got.Root, tx, root)
	}
	if got.Build != b {
		t.Fatalf("build read back = %+v; want %+v", got.Build, b)
	}
	sameRecords(t, got.Records, records)
}

// TestBuildEvidenceTables: each kind of record lands in its own table, one
// row each, so it can be queried with SQL: signatures, SLSA provenance,
// SBOMs, and other attestations (the authorization proofs).
func TestBuildEvidenceTables(t *testing.T) {
	s := openStore(t)
	b := testBuild(t)
	tx, _, err := PutBuildEvidence(s, b, buildRecords())
	if err != nil {
		t.Fatalf("PutBuildEvidence: %v", err)
	}

	builds, err := s.QueryVerified(TableBuilds, []string{"digest"},
		"SELECT digest, records FROM "+TableBuilds+" WHERE digest = @digest", map[string]any{"digest": b.Digest})
	if err != nil {
		t.Fatalf("%s: %v", TableBuilds, err)
	}
	if len(builds) != 1 || builds[0].Values["records"] != int64(5) || builds[0].Tx != tx {
		t.Fatalf("%s rows = %+v; want one row of 5 records in tx %d", TableBuilds, builds, tx)
	}

	for table, want := range map[string][]int64{
		TableSignatures: {0, 2}, TableAttestations: {1}, TableProvenances: {3}, TableSBOMs: {4},
	} {
		rows, err := s.QueryVerified(table, []string{"digest", "n"},
			"SELECT digest, n FROM "+table+" WHERE digest = @digest ORDER BY n", map[string]any{"digest": b.Digest})
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		var got []int64
		for _, r := range rows {
			got = append(got, r.Values["n"].(int64))
			if r.Tx != tx {
				t.Errorf("%s row %v in tx %d; want %d", table, r.Values["n"], r.Tx, tx)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s holds records %v; want %v", table, got, want)
		}
	}
}

// TestBuildEvidenceWrittenOnce: a second write for the same build is
// rejected and leaves the first one intact.
func TestBuildEvidenceWrittenOnce(t *testing.T) {
	s := openStore(t)
	b := testBuild(t)
	tx, _, err := PutBuildEvidence(s, b, buildRecords())
	if err != nil {
		t.Fatalf("PutBuildEvidence: %v", err)
	}
	if _, _, err := PutBuildEvidence(s, b, buildRecords()[:1]); !errors.Is(err, immudb.ErrDuplicate) {
		t.Fatalf("second PutBuildEvidence = %v; want ErrDuplicate", err)
	}
	got, err := ReadBuildEvidence(s, b.Digest)
	if err != nil || got.Tx != tx || len(got.Records) != len(buildRecords()) {
		t.Fatalf("ReadBuildEvidence after the rejected write = %+v, %v; want the first write", got, err)
	}
}

func TestReadBuildEvidenceNotFound(t *testing.T) {
	if _, err := ReadBuildEvidence(openStore(t), testBuild(t).Digest); !errors.Is(err, immudb.ErrNotFound) {
		t.Fatalf("ReadBuildEvidence of an unknown build = %v; want ErrNotFound", err)
	}
}

// TestReadBuildEvidenceRejectsRecordFromAnotherTransaction: a record row
// written outside the build's transaction is not evidence of that build.
func TestReadBuildEvidenceRejectsRecordFromAnotherTransaction(t *testing.T) {
	s := openStore(t)
	b := testBuild(t)
	if err := EnsureSchema(s); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	params := map[string]any{"digest": b.Digest, "image": b.Image}
	if _, _, err := s.ExecAll(immudb.Statement{
		SQL: "INSERT INTO " + TableSignatures + " (digest, n, signed_by) VALUES (@digest, 0, 'Build')", Params: params,
	}); err != nil {
		t.Fatalf("inserting the record: %v", err)
	}
	if _, _, err := s.ExecAll(immudb.Statement{
		SQL: "INSERT INTO " + TableBuilds + " (digest, image, records) VALUES (@digest, @image, 1)", Params: params,
	}); err != nil {
		t.Fatalf("inserting the build: %v", err)
	}
	if _, err := ReadBuildEvidence(s, b.Digest); err == nil {
		t.Fatal("ReadBuildEvidence accepted a record from another transaction")
	}
}

// TestReadBuildEvidenceRejectsMissingRecord: a build whose row counts more
// records than its tables hold is incomplete, not evidence.
func TestReadBuildEvidenceRejectsMissingRecord(t *testing.T) {
	s := openStore(t)
	b := testBuild(t)
	if err := EnsureSchema(s); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	params := map[string]any{"digest": b.Digest, "image": b.Image}
	if _, _, err := s.ExecAll(
		immudb.Statement{SQL: "INSERT INTO " + TableBuilds + " (digest, image, records) VALUES (@digest, @image, 2)", Params: params},
		immudb.Statement{SQL: "INSERT INTO " + TableSignatures + " (digest, n, signed_by) VALUES (@digest, 0, 'Build')", Params: params},
	); err != nil {
		t.Fatalf("inserting: %v", err)
	}
	if _, err := ReadBuildEvidence(s, b.Digest); err == nil {
		t.Fatal("ReadBuildEvidence accepted a build missing one of its records")
	}
}

// TestPutBuildEvidenceRecordTooLarge: a record over MaxRecordBytes fails the
// whole build's write, before anything is stored: a build's rows must stay
// small enough to be read back and verified.
func TestPutBuildEvidenceRecordTooLarge(t *testing.T) {
	s := openStore(t)
	b := testBuild(t)
	records := buildRecords()
	records[2].Certificate = strings.Repeat("A", MaxRecordBytes)
	if _, _, err := PutBuildEvidence(s, b, records); err == nil {
		t.Fatalf("PutBuildEvidence with a record over %d bytes = nil error", MaxRecordBytes)
	}
	if _, err := ReadBuildEvidence(s, b.Digest); !errors.Is(err, immudb.ErrNotFound) {
		t.Fatalf("after the failed write: %v; want nothing stored", err)
	}
}

func TestPutBuildEvidenceRejectsBadInput(t *testing.T) {
	b := Build{Digest: "sha256:abc"}
	if _, _, err := PutBuildEvidence(nil, Build{}, buildRecords()); err == nil {
		t.Error("PutBuildEvidence with no digest = nil error")
	}
	if _, _, err := PutBuildEvidence(nil, b, nil); err == nil {
		t.Error("PutBuildEvidence with no records = nil error")
	}
	if _, _, err := PutBuildEvidence(nil, b, []supplychainv1alpha1.SignatureRecord{{Kind: "Sbom"}}); err == nil {
		t.Error("PutBuildEvidence with a record of unknown kind = nil error")
	}
}
