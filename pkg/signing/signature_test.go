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

package signing

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// signatureFixture creates a fake client with a single ImageSignature for
// "app-1" in "team-a" and a reader for its main object. The status subresource
// is kept separate because Record() writes to it via Status().Update, and the
// main object's status field is only updated when that subresource commit
// lands.
func signatureFixture(t *testing.T) (*SignatureReconciler, *supplyv1alpha1.ImageBuild, func() *supplyv1alpha1.ImageSignature) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := supplyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ib := &supplyv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"}}
	base := &supplyv1alpha1.ImageSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"},
		Spec:       supplyv1alpha1.ImageSignatureSpec{Image: "docker.io/org/app:v1"},
		Status:     supplyv1alpha1.ImageSignatureStatus{Phase: PhasePending},
	}
	pending := base.DeepCopy()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pending).WithStatusSubresource(pending).Build()
	read := func() *supplyv1alpha1.ImageSignature {
		t.Helper()
		var sig supplyv1alpha1.ImageSignature
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pending), &sig); err != nil {
			t.Fatal(err)
		}
		return &sig
	}
	return NewSignatureReconciler(c, logr.Discard()), ib, read
}

// statusOnlyFixture is like signatureFixture, but returns a reader that reads
// back the status subresource (what Record() writes), so tests can assert on
// EvidenceGathered, EvidenceMessage and the Signed condition.
func statusOnlyFixture(t *testing.T) (*SignatureReconciler, *supplyv1alpha1.ImageBuild, func() supplyv1alpha1.ImageSignatureStatus) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := supplyv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	ib := &supplyv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"}}
	base := &supplyv1alpha1.ImageSignature{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"},
		Spec:       supplyv1alpha1.ImageSignatureSpec{Image: "docker.io/org/app:v1"},
		Status:     supplyv1alpha1.ImageSignatureStatus{Phase: PhasePending},
	}
	pending := base.DeepCopy()
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(pending).WithStatusSubresource(pending).Build()
	readStatus := func() supplyv1alpha1.ImageSignatureStatus {
		t.Helper()
		var sig supplyv1alpha1.ImageSignature
		if err := c.Get(context.Background(), client.ObjectKeyFromObject(pending), &sig); err != nil {
			t.Fatal(err)
		}
		return sig.Status
	}
	return NewSignatureReconciler(c, logr.Discard()), ib, readStatus
}

// The record is what was read back from the registry and the log: the index,
// the certificate and the time are the signature's own, not the controller's.
func TestRecordTakesTheSignatureFromTheEvidence(t *testing.T) {
	signatures, ib, read := signatureFixture(t)
	index := int64(51)
	logged := metav1.NewTime(time.Date(2026, 10, 5, 22, 21, 31, 0, time.UTC))
	signature := &supplyv1alpha1.SignatureRecord{
		Kind: "Signature", SignedBy: "Build",
		Subject:                "spiffe://blanketops.dev/ns/team-a/sa/supply-chain-runner",
		Issuer:                 "http://oidc.spire.svc",
		Certificate:            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
		CertificateFingerprint: "sha256:cert",
		KeyFingerprint:         "sha256:key",
		RekorLogIndex:          &index,
		RekorLogID:             "log-id",
		IntegratedAt:           &logged,
	}

	if err := signatures.Record(context.Background(), ib, "sha256:abc", signature, ""); err != nil {
		t.Fatal(err)
	}
	got := read()
	if got.Spec.Digest != "sha256:abc" {
		t.Errorf("digest = %q", got.Spec.Digest)
	}
	status := got.Status
	if status.Phase != PhaseSigned || status.RekorLogIndex == nil || *status.RekorLogIndex != 51 {
		t.Fatalf("phase %q, index %v; want Signed at 51", status.Phase, status.RekorLogIndex)
	}
	if status.Subject != signature.Subject || status.Issuer != signature.Issuer || status.RekorLogID != "log-id" ||
		status.Certificate != signature.Certificate || status.CertificateFingerprint != "sha256:cert" || status.KeyFingerprint != "sha256:key" {
		t.Errorf("status does not carry the signature: %+v", status)
	}
	if status.SignedAt == nil || !status.SignedAt.Time.Equal(logged.Time) {
		t.Errorf("signedAt = %v, want when the log accepted it, %v", status.SignedAt, logged)
	}
	if !meta.IsStatusConditionTrue(status.Conditions, ConditionSigned) {
		t.Errorf("condition %s is not true: %+v", ConditionSigned, status.Conditions)
	}
}

// A pipeline that succeeded is not a signature. Without one found on the
// image the record stays Pending, with no index, and says why.
func TestRecordDoesNotClaimASignatureItDidNotFind(t *testing.T) {
	signatures, ib, read := signatureFixture(t)

	const why = "reading the registry: timeout"
	if err := signatures.Record(context.Background(), ib, "sha256:abc", nil, why); err != nil {
		t.Fatal(err)
	}
	status := read().Status
	if status.Phase != PhasePending || status.RekorLogIndex != nil || status.Certificate != "" || status.SignedAt != nil {
		t.Fatalf("status claims a signature that was not found: %+v", status)
	}
	condition := meta.FindStatusCondition(status.Conditions, ConditionSigned)
	if condition == nil || condition.Status != metav1.ConditionFalse || condition.Message != why {
		t.Errorf("condition = %+v, want False with the reason", condition)
	}
}

func TestRecordKeepsAFoundSignature(t *testing.T) {
	signatures, ib, read := signatureFixture(t)
	index := int64(7)
	found := &supplyv1alpha1.SignatureRecord{Kind: "Signature", SignedBy: "Build", RekorLogIndex: &index}
	ctx := context.Background()

	if err := signatures.Record(ctx, ib, "sha256:abc", found, ""); err != nil {
		t.Fatal(err)
	}
	status := read().Status
	if status.Phase != PhaseSigned || status.RekorLogIndex == nil || *status.RekorLogIndex != 7 {
		t.Errorf("status = %+v, want the signature kept", status)
	}
}

// When the log entry is found for the build's signature, EvidenceGathered is
// set true and the evidence message is empty. A later evidence collection
// that cannot reach the log does not reset this.
func TestRecordWithMissingLogEntriesReportsTheGap(t *testing.T) {
	signatures, ib, readStatus := statusOnlyFixture(t)
	index := int64(51)
	found := &supplyv1alpha1.SignatureRecord{
		Kind: "Signature", SignedBy: "Build", RekorLogIndex: &index,
		Subject: "spiffe://blanketops.dev/ns/team-a/sa/supply-chain-runner",
	}
	ctx := context.Background()

	if err := signatures.Record(ctx, ib, "sha256:abc", found, ""); err != nil {
		t.Fatal(err)
	}
	if err := signatures.Record(ctx, ib, "sha256:abc", found, "transparency log entry not found"); err != nil {
		t.Fatal(err)
	}
	status := readStatus()
	if status.Phase != PhaseSigned {
		t.Errorf("phase = %q, want Signed", status.Phase)
	}
	if status.EvidenceGathered == nil || !*status.EvidenceGathered {
		t.Errorf("EvidenceGathered = %v, want true (the log entry was found)", status.EvidenceGathered)
	}
	if status.EvidenceMessage != "" {
		t.Errorf("EvidenceMessage = %q, want empty (log entry was found)", status.EvidenceMessage)
	}
}

// An ephemeral failure to reach the registry or the log must not flip a
// successfully recorded signature back. The build's own signature was found
// and logged, so it stays Signed.
func TestRecordDoesNotResetASignedSignature(t *testing.T) {
	signatures, ib, read := signatureFixture(t)
	index := int64(7)
	found := &supplyv1alpha1.SignatureRecord{Kind: "Signature", SignedBy: "Build", RekorLogIndex: &index}

	ctx := context.Background()
	if err := signatures.Record(ctx, ib, "sha256:abc", found, ""); err != nil {
		t.Fatal(err)
	}
	// A second evidence collection that cannot reach the log leaves the
	// signature as Signed — it does not reset to Pending.
	if err := signatures.Record(ctx, ib, "sha256:abc", nil, "transparency log is throttled"); err != nil {
		t.Fatal(err)
	}
	status := read().Status
	if status.Phase != PhaseSigned || status.RekorLogIndex == nil || *status.RekorLogIndex != 7 {
		t.Errorf("status = %+v, want the signature kept", status)
	}
	if !meta.IsStatusConditionTrue(status.Conditions, ConditionSigned) {
		t.Errorf("condition %s is not true: %+v", ConditionSigned, status.Conditions)
	}
}
