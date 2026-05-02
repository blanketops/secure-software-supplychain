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
type Recorder struct {
	Client client.Client
	Log    logr.Logger
}

func New(c client.Client, log logr.Logger) *Recorder {
	return &Recorder{Client: c, Log: log}
}

// Record extracts all results from a completed PipelineRun and creates or
// updates an ImageBuildResult CR owned by the ImageBuild.
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
		return nil
	}

	phase, reason := extractPhase(run)
	buildResults := ExtractAllResults(run)

	log.Info("recording build result",
		"phase", phase,
		"imageURL", buildResults.ImageURL,
		"imageDigest", buildResults.ImageDigest,
		"trivySummary", buildResults.TrivyScanSummary,
		"sonarGate", buildResults.SonarGateStatus,
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
			ImageBuildRef:  supplyv1alpha1.LocalObjectRef{Name: ib.Name},
			PipelineRunRef: supplyv1alpha1.LocalObjectRef{Name: run.Name},
		},
	}

	var existing supplyv1alpha1.ImageBuildResult
	err := r.Client.Get(ctx, client.ObjectKeyFromObject(desired), &existing)
	if err == nil {
		applyStatus(&existing.Status, phase, reason, run.Name, run.Status.CompletionTime, buildResults)
		if updateErr := r.Client.Status().Update(ctx, &existing); updateErr != nil {
			return fmt.Errorf("updating ImageBuildResult status: %w", updateErr)
		}
		log.Info("ImageBuildResult updated", "phase", phase)
		return nil
	}

	if createErr := r.Client.Create(ctx, desired); createErr != nil {
		return fmt.Errorf("creating ImageBuildResult: %w", createErr)
	}

	applyStatus(&desired.Status, phase, reason, run.Name, run.Status.CompletionTime, buildResults)
	if updateErr := r.Client.Status().Update(ctx, desired); updateErr != nil {
		return fmt.Errorf("setting ImageBuildResult status: %w", updateErr)
	}

	log.Info("ImageBuildResult created", "phase", phase)
	return nil
}

// ExtractAllResults pulls the full set of results from all 9 pipeline steps.
// Exported so the ImageBuildReconciler terminal block can call it directly.
//
// Result name mapping (matches PipelineRun results in builder.go):
//
//	git-clone:              commit, committer-date, url
//	build-image-buildah:    IMAGE_URL, IMAGE_DIGEST
//	vulnerability-scan-trivy: TRIVY_SCAN_SUMMARY, TRIVY_CRITICAL_COUNT,
//	                           TRIVY_HIGH_COUNT, TRIVY_TOTAL_COUNT, TRIVY_SARIF_PATH
//	code-scan-sonarqube:    SONAR_GATE_STATUS
//	publish-metadata-grafeas: GRAFEAS_OCCURRENCE
func ExtractAllResults(run *tektonv1.PipelineRun) *supplyv1alpha1.PipelineStepResults {
	r := &supplyv1alpha1.PipelineStepResults{}
	for _, result := range run.Status.Results {
		switch result.Name {
		// Git
		case "commit":
			r.Commit = result.Value.StringVal
		case "committer-date":
			r.CommitterDate = result.Value.StringVal
		case "url":
			r.RepoURL = result.Value.StringVal
		// Build
		case "IMAGE_URL":
			r.ImageURL = result.Value.StringVal
		case "IMAGE_DIGEST":
			r.ImageDigest = result.Value.StringVal
		// Trivy
		case "TRIVY_SCAN_SUMMARY":
			r.TrivyScanSummary = result.Value.StringVal
		case "TRIVY_CRITICAL_COUNT":
			r.TrivyCriticalCount = result.Value.StringVal
		case "TRIVY_HIGH_COUNT":
			r.TrivyHighCount = result.Value.StringVal
		case "TRIVY_TOTAL_COUNT":
			r.TrivyTotalCount = result.Value.StringVal
		case "TRIVY_SARIF_PATH":
			r.TrivySarifPath = result.Value.StringVal
		// SonarQube
		case "SONAR_GATE_STATUS":
			r.SonarGateStatus = result.Value.StringVal
		// Grafeas
		case "GRAFEAS_OCCURRENCE":
			r.GrafeasOccurrence = result.Value.StringVal
		}
	}
	return r
}

// ExtractImageResults returns just IMAGE_URL and IMAGE_DIGEST.
// Kept for backwards compatibility with callers that only need the image ref.
func ExtractImageResults(run *tektonv1.PipelineRun) (imageURL, imageDigest string) {
	r := ExtractAllResults(run)
	return r.ImageURL, r.ImageDigest
}

func applyStatus(
	s *supplyv1alpha1.ImageBuildResultStatus,
	phase, reason, pipelineRunName string,
	completedAt *metav1.Time,
	br *supplyv1alpha1.PipelineStepResults,
) {
	s.Phase = phase
	s.Reason = reason
	s.PipelineRunName = pipelineRunName
	s.CompletedAt = completedAt
	s.ImageURL = br.ImageURL
	s.ImageDigest = br.ImageDigest
	s.BuildResults = br
}

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

func boolPtr(b bool) *bool {
	return &b
}
