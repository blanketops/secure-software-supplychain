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
	"fmt"

	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// SignatureReconciler creates and updates the ImageSignature CR for a build.
//
// Flow:
//  1. EnsureSignature — called when PipelineRun is created, creates ImageSignature
//     with Phase=Pending and the full signing identity from the RunSigningContext.
//  2. MarkSigned — called when PipelineRun succeeds, transitions to Phase=Signed.
//  3. MarkFailed — called when PipelineRun fails, transitions to Phase=Failed.
//
// The ImageSignature is created early (before the pipeline) because the signing
// identity (Fulcio cert, SAR proofs) is established before execution. The cert
// expiry is proof that this identity was authorised at the time of the build.
type SignatureReconciler struct {
	Client client.Client
	Log    logr.Logger
}

func NewSignatureReconciler(c client.Client, log logr.Logger) *SignatureReconciler {
	return &SignatureReconciler{
		Client: c,
		Log:    log,
	}
}

// EnsureSignature creates the ImageSignature CR with Phase=Pending.
// Called immediately after the PipelineRun is created.
// Idempotent — safe to call on every reconcile.
func (s *SignatureReconciler) EnsureSignature(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	sc *supplyv1alpha1.SupplyChain,
	sigCtx *RunSigningContext,
	imageRef string,
) error {
	log := s.Log.WithValues(
		"imageBuild", ib.Name,
		"namespace", ib.Namespace,
	)

	fulcioURL := "https://fulcio.sigstore.dev"
	rekorURL := "https://rekor.sigstore.dev"
	if sc.Spec.Signing != nil {
		if sc.Spec.Signing.FulcioURL != "" {
			fulcioURL = sc.Spec.Signing.FulcioURL
		}
		if sc.Spec.Signing.RekorURL != "" {
			rekorURL = sc.Spec.Signing.RekorURL
		}
	}

	desired := &supplyv1alpha1.ImageSignature{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ib.Name,
			Namespace: ib.Namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/image-build":  ib.Name,
				"blanketops.dev/supply-chain": sc.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         ib.APIVersion,
					Kind:               ib.Kind,
					Name:               ib.Name,
					UID:                ib.UID,
					Controller:         boolPtr(true),
					BlockOwnerDeletion: boolPtr(true),
				},
			},
		},
		Spec: supplyv1alpha1.ImageSignatureSpec{
			Image:       imageRef,
			Digest:      "", // populated by MarkSigned after pipeline completes
			SignedBy:    sigCtx.ScopeProof.Principal,
			FulcioURL:   fulcioURL,
			RekorURL:    rekorURL,
			SupplyChain: sc.Name,
			ImageBuild:  ib.Name,
		},
	}

	var existing supplyv1alpha1.ImageSignature
	err := s.Client.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if apierrors.IsNotFound(err) {
		if createErr := s.Client.Create(ctx, desired); createErr != nil {
			return fmt.Errorf("creating ImageSignature: %w", createErr)
		}
		// Set initial Pending status.
		desired.Status.Phase = "Pending"
		_ = s.Client.Status().Update(ctx, desired)
		log.Info("ImageSignature created", "phase", "Pending")
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetching ImageSignature: %w", err)
	}

	// Already exists — nothing to update at this stage.
	log.V(1).Info("ImageSignature already exists, skipping create")
	return nil
}

// MarkSigned transitions the ImageSignature to Phase=Signed.
// Called when the PipelineRun succeeds.
// Populates the image digest extracted from PipelineRun results.
func (s *SignatureReconciler) MarkSigned(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	imageDigest string,
	certPEM []byte,
) error {
	log := s.Log.WithValues("imageBuild", ib.Name)

	var sig supplyv1alpha1.ImageSignature
	if err := s.Client.Get(ctx, client.ObjectKey{
		Name:      ib.Name,
		Namespace: ib.Namespace,
	}, &sig); err != nil {
		return fmt.Errorf("fetching ImageSignature for MarkSigned: %w", err)
	}

	// Update spec digest — now we have the real registry digest.
	sig.Spec.Digest = imageDigest
	if updateErr := s.Client.Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature spec: %w", updateErr)
	}

	// Update status.
	now := metav1.Now()
	sig.Status.Phase = "Signed"
	sig.Status.SignedAt = &now
	if len(certPEM) > 0 {
		sig.Status.Certificate = string(certPEM)
	}

	if updateErr := s.Client.Status().Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature status: %w", updateErr)
	}

	log.Info("ImageSignature marked Signed",
		"digest", imageDigest,
	)
	return nil
}

// MarkFailed transitions the ImageSignature to Phase=Failed.
// Called when the PipelineRun fails.
func (s *SignatureReconciler) MarkFailed(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
) error {
	log := s.Log.WithValues("imageBuild", ib.Name)

	var sig supplyv1alpha1.ImageSignature
	if err := s.Client.Get(ctx, client.ObjectKey{
		Name:      ib.Name,
		Namespace: ib.Namespace,
	}, &sig); err != nil {
		if apierrors.IsNotFound(err) {
			return nil // nothing to mark
		}
		return fmt.Errorf("fetching ImageSignature for MarkFailed: %w", err)
	}

	sig.Status.Phase = "Failed"
	if updateErr := s.Client.Status().Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature status to Failed: %w", updateErr)
	}

	log.Info("ImageSignature marked Failed")
	return nil
}

func boolPtr(b bool) *bool {
	return &b
}
