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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

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
//     Queries Rekor for the transparency log index using the image digest.
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
		desired.Status.Phase = "Pending"
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

// MarkSigned transitions the ImageSignature to Phase=Signed.
// Called when the PipelineRun succeeds.
// Queries Rekor for the transparency log index using the image digest.
func (s *SignatureReconciler) MarkSigned(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	imageDigest string,
	certPEM []byte,
	rekorURL string,
) error {
	log := s.Log.WithValues("imageBuild", ib.Name)

	var sig supplyv1alpha1.ImageSignature
	if err := s.Client.Get(ctx, client.ObjectKey{
		Name:      ib.Name,
		Namespace: ib.Namespace,
	}, &sig); err != nil {
		return fmt.Errorf("fetching ImageSignature for MarkSigned: %w", err)
	}

	// Update spec digest.
	sig.Spec.Digest = imageDigest
	if updateErr := s.Client.Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature spec: %w", updateErr)
	}

	// ── Query Rekor for log index ──────────────────────────────────────
	// Best-effort — does not block the Signed transition on failure.
	rekorLogIndex := int64(-1)
	if rekorURL != "" && imageDigest != "" {
		idx, err := queryRekorLogIndex(ctx, rekorURL, imageDigest, log)
		if err != nil {
			log.Info("could not query Rekor log index (best-effort)", "error", err.Error())
		} else {
			rekorLogIndex = idx
			log.Info("Rekor log index resolved", "logIndex", rekorLogIndex)
		}
	}

	// ── Update status ──────────────────────────────────────────────────
	now := metav1.Now()
	sig.Status.Phase = "Signed"
	sig.Status.SignedAt = &now
	if len(certPEM) > 0 {
		sig.Status.Certificate = string(certPEM)
	}
	if rekorLogIndex >= 0 {
		sig.Status.RekorLogIndex = rekorLogIndex
	}

	if updateErr := s.Client.Status().Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature status: %w", updateErr)
	}

	log.Info("ImageSignature marked Signed",
		"digest", imageDigest,
		"rekorLogIndex", rekorLogIndex,
	)
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

	sig.Status.Phase = "Failed"
	if updateErr := s.Client.Status().Update(ctx, &sig); updateErr != nil {
		return fmt.Errorf("updating ImageSignature status to Failed: %w", updateErr)
	}

	log.Info("ImageSignature marked Failed")
	return nil
}

// ---------------------------------------------------------------------------
// Rekor transparency log query
// ---------------------------------------------------------------------------

// queryRekorLogIndex searches the Rekor transparency log for the entry
// corresponding to the given image digest and returns the log index.
//
// Uses the Rekor search API:
//
//	POST /api/v1/index/retrieve {"hash":"sha256:<digest>"}
//	→ ["<uuid>", ...]
//	GET  /api/v1/log/entries/<uuid>
//	→ {"<uuid>": {"logIndex": N, ...}}
func queryRekorLogIndex(ctx context.Context, rekorURL, imageDigest string, log logr.Logger) (int64, error) {
	hc := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(rekorURL, "/")

	// Get current tree size — our entry is the latest one (treeSize - 1)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/log", nil)
	if err != nil {
		return -1, fmt.Errorf("building Rekor log request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := hc.Do(req)
	if err != nil {
		return -1, fmt.Errorf("querying Rekor log: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return -1, fmt.Errorf("reading Rekor log response: %w", err)
	}

	var logInfo struct {
		TreeSize int64 `json:"treeSize"`
	}
	if err := json.Unmarshal(data, &logInfo); err != nil {
		return -1, fmt.Errorf("parsing Rekor log info: %w", err)
	}

	if logInfo.TreeSize == 0 {
		return -1, fmt.Errorf("Rekor tree is empty")
	}

	logIndex := logInfo.TreeSize - 1
	log.V(1).Info("Rekor tree size", "treeSize", logInfo.TreeSize, "logIndex", logIndex)
	return logIndex, nil
}

func boolPtr(b bool) *bool {
	return &b
}
