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
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// SignatureReconciler creates and updates the ImageSignature CR for a build.
//
// Flow:
//  1. EnsureSignature — called when PipelineRun is created, creates ImageSignature
//     with Phase=Pending and the full signing identity from the RunSigningContext.
//  2. Record — called when the build is over, with the build's signature as
//     read back from the registry and the transparency log. Only then, and
//     only if it was found, does the phase become Signed.
//  3. MarkFailed — called when PipelineRun fails, transitions to Phase=Failed.
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
				"blanketops.dev/image-build":  ib.LabelValue(),
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
			Digest:      "",
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
		desired.Status.Phase = PhasePending
		_ = s.Client.Status().Update(ctx, desired)
		log.Info("ImageSignature created", "phase", "Pending")
		return nil
	}
	if err != nil {
		return fmt.Errorf("fetching ImageSignature: %w", err)
	}

	log.V(1).Info("ImageSignature already exists, skipping create")
	return nil
}

// ConditionSigned is the condition that says whether the build's signature
// was found on the image and in the transparency log.
const ConditionSigned = "Signed"

// Phases of an ImageSignature.
const (
	PhasePending = "Pending"
	PhaseSigned  = "Signed"
	PhaseFailed  = "Failed"
)

// Record completes the ImageSignature from the build's signature as it was
// read back from the registry and the transparency log.
//
// signature is nil when no such signature was found. The record then stays
// Pending and says why: that a pipeline succeeded is not evidence that the
// image carries a signature, and nothing here is filled in from what the
// controller expects to be true.
func (s *SignatureReconciler) Record(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	imageDigest string,
	signature *supplyv1alpha1.SignatureRecord,
	missing string,
) error {
	log := s.Log.WithValues("imageBuild", ib.Name)

	var sig supplyv1alpha1.ImageSignature
	if err := s.Client.Get(ctx, client.ObjectKey{Name: ib.Name, Namespace: ib.Namespace}, &sig); err != nil {
		return fmt.Errorf("fetching ImageSignature: %w", err)
	}

	if sig.Spec.Digest != imageDigest {
		sig.Spec.Digest = imageDigest
		if err := s.Client.Update(ctx, &sig); err != nil {
			return fmt.Errorf("updating ImageSignature spec: %w", err)
		}
	}

	if signature == nil {
		if sig.Status.Phase == PhaseSigned {
			// Found before; a registry that cannot be read now takes nothing back.
			return nil
		}
		if missing == "" {
			missing = "the build's signature was not found on the image"
		}
		sig.Status.Phase = PhasePending
		meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
			Type:               ConditionSigned,
			Status:             metav1.ConditionFalse,
			Reason:             "SignatureNotFound",
			Message:            missing,
			ObservedGeneration: sig.Generation,
		})
		if err := s.Client.Status().Update(ctx, &sig); err != nil {
			return fmt.Errorf("updating ImageSignature status: %w", err)
		}
		log.Info("Build signature not found; ImageSignature left Pending", "reason", missing)
		return nil
	}

	sig.Status.Phase = PhaseSigned
	sig.Status.Subject = signature.Subject
	sig.Status.Issuer = signature.Issuer
	sig.Status.RekorLogIndex = signature.RekorLogIndex
	sig.Status.RekorLogID = signature.RekorLogID
	sig.Status.Certificate = signature.Certificate
	sig.Status.CertificateFingerprint = signature.CertificateFingerprint
	sig.Status.KeyFingerprint = signature.KeyFingerprint
	sig.Status.SignedAt = signature.IntegratedAt
	meta.SetStatusCondition(&sig.Status.Conditions, metav1.Condition{
		Type:               ConditionSigned,
		Status:             metav1.ConditionTrue,
		Reason:             "SignatureLogged",
		Message:            fmt.Sprintf("Signed by %s; transparency log entry %d", signature.Subject, *signature.RekorLogIndex),
		ObservedGeneration: sig.Generation,
	})
	if err := s.Client.Status().Update(ctx, &sig); err != nil {
		return fmt.Errorf("updating ImageSignature status: %w", err)
	}
	log.Info("ImageSignature recorded",
		"digest", imageDigest, "subject", signature.Subject, "rekorLogIndex", *signature.RekorLogIndex)
	return nil
}

// MarkFailed transitions the ImageSignature to Phase=Failed.
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
			return nil
		}
		return fmt.Errorf("fetching ImageSignature for MarkFailed: %w", err)
	}

	sig.Status.Phase = PhaseFailed
	if updateErr := s.Client.Status().Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature status to Failed: %w", updateErr)
	}

	log.Info("ImageSignature marked Failed")
	return nil
}

func boolPtr(b bool) *bool {
	return &b
}
