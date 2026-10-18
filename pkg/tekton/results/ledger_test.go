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
package results

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	"github.com/blanketops/secure-software-supplychain/pkg/evidence"
	"github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// ledgerFixture is a succeeded build with collected evidence, for an image
// digest no earlier run has stored: immudb keeps every write.
func ledgerFixture(t *testing.T) (*supplyv1alpha1.ImageBuild, *supplyv1alpha1.ImageBuildResult) {
	t.Helper()
	sum := sha256.Sum256([]byte(t.Name() + strconv.FormatInt(time.Now().UnixNano(), 10)))
	digest := "sha256:" + hex.EncodeToString(sum[:])
	index := int64(7)
	ib := &supplyv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "dev"}}
	result := &supplyv1alpha1.ImageBuildResult{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "dev"},
		Status: supplyv1alpha1.ImageBuildResultStatus{
			Phase:       phaseSucceeded,
			ImageDigest: digest,
			Evidence: &supplyv1alpha1.BuildEvidence{
				Complete: true,
				Signatures: []supplyv1alpha1.SignatureRecord{
					{Kind: evidence.KindSignature, SignedBy: evidence.SignedByBuild, RekorLogIndex: &index},
					{Kind: evidence.KindSignature, SignedBy: evidence.SignedByChains},
					{Kind: evidence.KindAttestation, SignedBy: evidence.SignedByChains,
						PredicateType: "https://slsa.dev/provenance/v1"},
				},
			},
		},
	}
	return ib, result
}

func ledgerClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := supplyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).
		WithStatusSubresource(&supplyv1alpha1.ImageBuildResult{}).Build()
}

// openImmudb connects to the immudb server from the environment. These tests
// need a running immudb and fail when there is none.
func openImmudb() (immudb.Store, error) { return immudb.Open() }

func storedResult(t *testing.T, c client.Client, ib *supplyv1alpha1.ImageBuild) *supplyv1alpha1.ImageBuildResult {
	t.Helper()
	var got supplyv1alpha1.ImageBuildResult
	if err := c.Get(context.Background(), client.ObjectKeyFromObject(ib), &got); err != nil {
		t.Fatal(err)
	}
	return &got
}

// TestStoreEvidenceWritesTheBuildToImmudb: the evidence of a finished build
// lands in immudb as one transaction, which the ImageBuildResult records.
func TestStoreEvidenceWritesTheBuildToImmudb(t *testing.T) {
	ib, result := ledgerFixture(t)
	c := ledgerClient(t, result)
	r := &Recorder{Client: c, Log: logr.Discard(), OpenLedger: openImmudb}

	if err := r.StoreEvidence(context.Background(), ib); err != nil {
		t.Fatalf("StoreEvidence: %v", err)
	}
	ledger := storedResult(t, c, ib).Status.Evidence.Ledger
	if ledger == nil || ledger.Tx == 0 || ledger.Root == "" || ledger.Records != 3 || ledger.Database == "" {
		t.Fatalf("ledger = %+v; want the transaction holding 3 records", ledger)
	}

	s, err := immudb.Open()
	if err != nil {
		t.Fatalf("immudb is required for this test: %v", err)
	}
	defer func() { _ = s.Close() }()
	stored, err := evidence.ReadBuildEvidence(s, result.Status.ImageDigest)
	if err != nil {
		t.Fatalf("ReadBuildEvidence: %v", err)
	}
	if int64(stored.Tx) != ledger.Tx || hex.EncodeToString(stored.Root) != ledger.Root || len(stored.Records) != 3 {
		t.Fatalf("immudb holds tx %d root %x (%d records); the status says tx %d root %s",
			stored.Tx, stored.Root, len(stored.Records), ledger.Tx, ledger.Root)
	}

	// Stored once: a second call changes nothing.
	if err := r.StoreEvidence(context.Background(), ib); err != nil {
		t.Fatalf("second StoreEvidence: %v", err)
	}
	if again := storedResult(t, c, ib).Status.Evidence.Ledger; again.Tx != ledger.Tx {
		t.Fatalf("second StoreEvidence moved the ledger to tx %d from %d", again.Tx, ledger.Tx)
	}
}

// TestStoreEvidenceFindsWhatIsAlreadyStored: if the status update after a
// write was lost, the next call records the stored transaction instead of
// failing on the duplicate.
func TestStoreEvidenceFindsWhatIsAlreadyStored(t *testing.T) {
	ib, result := ledgerFixture(t)
	first := ledgerClient(t, result.DeepCopy())
	r := &Recorder{Client: first, Log: logr.Discard(), OpenLedger: openImmudb}
	if err := r.StoreEvidence(context.Background(), ib); err != nil {
		t.Fatalf("StoreEvidence: %v", err)
	}
	want := storedResult(t, first, ib).Status.Evidence.Ledger

	lost := ledgerClient(t, result.DeepCopy())
	r.Client = lost
	if err := r.StoreEvidence(context.Background(), ib); err != nil {
		t.Fatalf("StoreEvidence after a lost status update: %v", err)
	}
	if got := storedResult(t, lost, ib).Status.Evidence.Ledger; got == nil || got.Tx != want.Tx || got.Root != want.Root {
		t.Fatalf("ledger = %+v; want the stored tx %d", got, want.Tx)
	}
}

// TestStoreEvidenceFailsLoudly: when immudb cannot be reached the error is
// returned, so the build is reconciled again, and recorded on the result.
func TestStoreEvidenceFailsLoudly(t *testing.T) {
	ib, result := ledgerFixture(t)
	c := ledgerClient(t, result)
	unreachable := errors.New("immudb: failed to open immudb session at 10.0.0.1:3322")
	r := &Recorder{Client: c, Log: logr.Discard(), OpenLedger: func() (immudb.Store, error) { return nil, unreachable }}

	if err := r.StoreEvidence(context.Background(), ib); !errors.Is(err, unreachable) {
		t.Fatalf("StoreEvidence = %v; want the connection error", err)
	}
	ev := storedResult(t, c, ib).Status.Evidence
	if ev.Ledger != nil || ev.LedgerMessage == "" {
		t.Fatalf("evidence = ledger %+v, message %q; want no ledger and the error", ev.Ledger, ev.LedgerMessage)
	}

	r.OpenLedger = nil
	if err := r.StoreEvidence(context.Background(), ib); err == nil {
		t.Fatal("StoreEvidence with no evidence store configured = nil error")
	}
}

// TestStoreEvidenceSkipsWhatIsNotFinalEvidence: a failed build, or one with
// no evidence, has nothing to store and must not touch immudb.
func TestStoreEvidenceSkipsWhatIsNotFinalEvidence(t *testing.T) {
	failed, failedResult := ledgerFixture(t)
	failedResult.Status.Phase = "Failed"
	unsigned, unsignedResult := ledgerFixture(t)
	unsignedResult.Status.Evidence.Signatures = nil

	for name, c := range map[string]struct {
		ib     *supplyv1alpha1.ImageBuild
		result *supplyv1alpha1.ImageBuildResult
	}{"failed": {failed, failedResult}, "unsigned": {unsigned, unsignedResult}} {
		r := &Recorder{Client: ledgerClient(t, c.result), Log: logr.Discard(),
			OpenLedger: func() (immudb.Store, error) {
				t.Errorf("%s: immudb opened for a build with nothing to store", name)
				return nil, errors.New("unexpected")
			}}
		if err := r.StoreEvidence(context.Background(), c.ib); err != nil {
			t.Errorf("%s: StoreEvidence = %v; want nil", name, err)
		}
	}
}
