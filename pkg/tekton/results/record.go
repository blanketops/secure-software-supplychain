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
	"fmt"

	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// Recorder extracts PipelineRun results and writes them to an ImageBuildResult CR.
// Called by the ImageBuildReconciler when a PipelineRun reaches a terminal state.
//
// The ImageBuildResult CR is the durable record of a build execution — it survives
// PipelineRun pruning and provides a clean API surface for downstream consumers
// (Grafeas, dashboards, policy engines).
type Recorder struct {
	Client client.Client
	Log    logr.Logger
}

func New(c client.Client, log logr.Logger) *Recorder {
	return &Recorder{
		Client: c,
		Log:    log,
	}
}

// Record extracts results from a completed PipelineRun and creates or updates
// an ImageBuildResult CR owned by the ImageBuild.
func (r *Recorder) Record(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	run *tektonv1.PipelineRun,
) error {
	log := r.Log.WithValues(
		"imageBuild", ib.Name,
		"pipelineRun", run.Name,
		"namespace", ib.Namespace,
	)

	if run.Status.CompletionTime == nil {
		// Not terminal yet — nothing to record.
		return nil
	}

	phase, reason := extractPhase(run)
	imageURL, imageDigest := extractImageResults(run)

	log.Info("recording build result",
		"phase", phase,
		"imageURL", imageURL,
		"imageDigest", imageDigest,
	)

	desired := &supplyv1alpha1.ImageBuildResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ib.Name,
			Namespace: ib.Namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/image-build":  ib.Name,
				"blanketops.dev/supply-chain": ib.Spec.SupplyChainRef.Name,
			},
			// Owned by the ImageBuild — deleted when the ImageBuild is deleted.
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
		Spec: supplyv1alpha1.ImageBuildResultSpec{
			ImageBuildRef: supplyv1alpha1.LocalObjectRef{
				Name: ib.Name,
			},
			PipelineRunRef: supplyv1alpha1.LocalObjectRef{
				Name: run.Name,
			},
		},
	}

	// Check if the result already exists.
	var existing supplyv1alpha1.ImageBuildResult
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if err == nil {
		// Already recorded — update status only.
		existing.Status.Phase = phase
		existing.Status.Reason = reason
		existing.Status.ImageURL = imageURL
		existing.Status.ImageDigest = imageDigest
		existing.Status.CompletedAt = run.Status.CompletionTime
		existing.Status.PipelineRunName = run.Name

		if updateErr := r.Client.Status().Update(ctx, &existing); updateErr != nil {
			return fmt.Errorf("updating ImageBuildResult status: %w", updateErr)
		}
		log.Info("ImageBuildResult updated", "phase", phase)
		return nil
	}

	// Create new result.
	if createErr := r.Client.Create(ctx, desired); createErr != nil {
		return fmt.Errorf("creating ImageBuildResult: %w", createErr)
	}

	// Set initial status.
	desired.Status.Phase = phase
	desired.Status.Reason = reason
	desired.Status.ImageURL = imageURL
	desired.Status.ImageDigest = imageDigest
	desired.Status.CompletedAt = run.Status.CompletionTime
	desired.Status.PipelineRunName = run.Name

	if updateErr := r.Client.Status().Update(ctx, desired); updateErr != nil {
		return fmt.Errorf("setting ImageBuildResult status: %w", updateErr)
	}

	log.Info("ImageBuildResult created", "phase", phase)
	return nil
}

// extractPhase maps PipelineRun condition to ImageBuildResult phase.
func extractPhase(run *tektonv1.PipelineRun) (phase, reason string) {
	for _, cond := range run.Status.Conditions {
		if cond.Type != "Succeeded" {
			continue
		}
		switch cond.Status {
		case "True":
			return "Succeeded", cond.Reason
		case "False":
			return "Failed", cond.Reason
		default:
			return "Running", cond.Reason
		}
	}
	return "Unknown", ""
}

// extractImageResults pulls IMAGE_URL and IMAGE_DIGEST from PipelineRun results.
// These are emitted by the buildah task and mapped to PipelineRun results in builder.go.
func extractImageResults(run *tektonv1.PipelineRun) (imageURL, imageDigest string) {
	for _, result := range run.Status.Results {
		switch result.Name {
		case "IMAGE_URL":
			imageURL = result.Value.StringVal
		case "IMAGE_DIGEST":
			imageDigest = result.Value.StringVal
		}
	}
	return imageURL, imageDigest
}

func boolPtr(b bool) *bool {
	return &b
}
