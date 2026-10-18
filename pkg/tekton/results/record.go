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
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	"github.com/blanketops/secure-software-supplychain/pkg/evidence"
	"github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// phaseSucceeded is the ImageBuild phase for a run that finished successfully.
const phaseSucceeded = "Succeeded"

// Recorder extracts PipelineRun results and writes them to an ImageBuildResult
// CR, and stores each build's evidence in immudb.
type Recorder struct {
	Client client.Client
	Log    logr.Logger
	// OpenLedger opens the immudb store the evidence is written to.
	OpenLedger func() (immudb.Store, error)
}

func New(c client.Client, log logr.Logger) *Recorder {
	return &Recorder{Client: c, Log: log, OpenLedger: immudb.Open}
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

	var taskRuns tektonv1.TaskRunList
	if err := r.Client.List(ctx, &taskRuns,
		client.InNamespace(run.Namespace),
		client.MatchingLabels{"tekton.dev/pipelineRun": run.Name},
	); err != nil {
		log.Error(err, "Failed to list TaskRuns; recording the pipeline results only")
	} else {
		FillFromTaskRuns(buildResults, taskRuns.Items)
	}

	_, err := r.write(ctx, ib, run, phase, reason, run.Status.CompletionTime, buildResults)
	return err
}

// write creates or updates the ImageBuildResult of ib.
func (r *Recorder) write(
	ctx context.Context,
	ib *supplyv1alpha1.ImageBuild,
	run *tektonv1.PipelineRun,
	phase, reason string,
	completedAt *metav1.Time,
	buildResults *supplyv1alpha1.PipelineStepResults,
) (*supplyv1alpha1.ImageBuildResult, error) {
	log := r.Log.WithValues(
		"imageBuild", ib.Name,
		"pipelineRun", run.Name,
		"namespace", ib.Namespace,
	)

	log.Info("recording build result",
		"phase", phase,
		"imageURL", buildResults.ImageURL,
		"imageDigest", buildResults.ImageDigest,
		"trivySummary", buildResults.TrivyScanSummary,
		"sonarGate", buildResults.SonarGateStatus,
	)

	var existing supplyv1alpha1.ImageBuildResult
	err := r.Client.Get(ctx, client.ObjectKey{Namespace: ib.Namespace, Name: ib.Name}, &existing)
	if client.IgnoreNotFound(err) != nil {
		return nil, fmt.Errorf("reading ImageBuildResult: %w", err)
	}
	found := err == nil

	collected := r.collectEvidence(ctx, ib, run, phase, buildResults, existing.Status.Evidence)

	desired := &supplyv1alpha1.ImageBuildResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ib.Name,
			Namespace: ib.Namespace,
			Labels: map[string]string{
				"blanketops.dev/managed":      "true",
				"blanketops.dev/image-build":  ib.LabelValue(),
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

	if found {
		applyStatus(&existing.Status, phase, reason, run.Name, completedAt, buildResults)
		existing.Status.Evidence = collected
		if updateErr := r.Client.Status().Update(ctx, &existing); updateErr != nil {
			return nil, fmt.Errorf("updating ImageBuildResult status: %w", updateErr)
		}
		log.Info("ImageBuildResult updated", "phase", phase)
		return &existing, nil
	}

	if createErr := r.Client.Create(ctx, desired); createErr != nil {
		return nil, fmt.Errorf("creating ImageBuildResult: %w", createErr)
	}

	applyStatus(&desired.Status, phase, reason, run.Name, completedAt, buildResults)
	desired.Status.Evidence = collected
	if updateErr := r.Client.Status().Update(ctx, desired); updateErr != nil {
		return nil, fmt.Errorf("setting ImageBuildResult status: %w", updateErr)
	}

	log.Info("ImageBuildResult created", "phase", phase)
	return desired, nil
}

// collectEvidence reads the signatures and attestations of the pushed image
// and their transparency log entries. Evidence that is already complete is
// kept as it is: nothing more will be added to the image, and the registry
// need not be asked again on every reconcile.
func (r *Recorder) collectEvidence(ctx context.Context, ib *supplyv1alpha1.ImageBuild, run *tektonv1.PipelineRun, phase string, buildResults *supplyv1alpha1.PipelineStepResults, have *supplyv1alpha1.BuildEvidence) *supplyv1alpha1.BuildEvidence {
	if have != nil && have.Complete {
		return have
	}
	if phase != phaseSucceeded || buildResults.ImageURL == "" || buildResults.ImageDigest == "" {
		return have
	}
	var sc supplyv1alpha1.SupplyChain
	key := client.ObjectKey{Namespace: ib.Namespace, Name: ib.Spec.SupplyChainRef.Name}
	if err := r.Client.Get(ctx, key, &sc); err != nil {
		r.Log.Error(err, "Failed to read SupplyChain; evidence not collected", "supplyChain", key.Name)
		return have
	}
	collected := evidence.ForBuild(ctx, r.Client, &sc, run, buildResults.ImageURL, buildResults.ImageDigest)
	if collected.Message != "" {
		r.Log.Info("Collected evidence with gaps", "imageBuild", ib.Name, "message", collected.Message)
	}
	if have != nil {
		// Where the evidence is stored is not something the registry says.
		collected.Ledger, collected.LedgerMessage = have.Ledger, have.LedgerMessage
	}
	return collected
}

// StoreEvidence writes the evidence recorded for the build of ib to immudb,
// all of it in one transaction, and records that transaction on the
// ImageBuildResult. Call it once the record is final: a build's evidence is
// written once.
//
// It does nothing for a build that did not succeed, has no evidence, or whose
// evidence is already stored. A failure is recorded on the ImageBuildResult
// and returned, so the build is reconciled again.
func (r *Recorder) StoreEvidence(ctx context.Context, ib *supplyv1alpha1.ImageBuild) error {
	var result supplyv1alpha1.ImageBuildResult
	if err := r.Client.Get(ctx, client.ObjectKeyFromObject(ib), &result); err != nil {
		return client.IgnoreNotFound(err)
	}
	ev := result.Status.Evidence
	if result.Status.Phase != phaseSucceeded || ev == nil || ev.Ledger != nil || len(ev.Signatures) == 0 {
		return nil
	}

	ledger, err := r.storeEvidence(buildOf(ib, &result), ev.Signatures)
	if err != nil {
		err = fmt.Errorf("storing the evidence of %s in immudb: %w", result.Status.ImageDigest, err)
		ev.LedgerMessage = err.Error()
		if updateErr := r.Client.Status().Update(ctx, &result); updateErr != nil {
			return errors.Join(err, fmt.Errorf("updating ImageBuildResult status: %w", updateErr))
		}
		return err
	}
	ev.Ledger, ev.LedgerMessage = ledger, ""
	if err := r.Client.Status().Update(ctx, &result); err != nil {
		return fmt.Errorf("recording the immudb transaction of the evidence: %w", err)
	}
	r.Log.Info("Evidence stored in immudb", "imageBuild", ib.Name, "digest", result.Status.ImageDigest,
		"database", ledger.Database, "tx", ledger.Tx, "records", ledger.Records)
	return nil
}

// buildOf is the build an ImageBuildResult records, as its evidence is
// stored: the image digest and where the image came from.
func buildOf(ib *supplyv1alpha1.ImageBuild, result *supplyv1alpha1.ImageBuildResult) evidence.Build {
	b := evidence.Build{
		Digest:     result.Status.ImageDigest,
		Image:      result.Status.ImageURL,
		ImageBuild: ib.Namespace + "/" + ib.Name,
	}
	if result.Status.BuildResults != nil {
		b.Commit = result.Status.BuildResults.Commit
	}
	return b
}

func (r *Recorder) storeEvidence(b evidence.Build, records []supplyv1alpha1.SignatureRecord) (*supplyv1alpha1.EvidenceLedger, error) {
	if r.OpenLedger == nil {
		return nil, errors.New("no immudb evidence store is configured")
	}
	s, err := r.OpenLedger()
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()

	tx, root, err := evidence.PutBuildEvidence(s, b, records)
	n := len(records)
	if errors.Is(err, immudb.ErrDuplicate) {
		// Stored by an earlier reconcile whose status update was lost, or by
		// another build of the same image: what is stored is the record.
		stored, readErr := evidence.ReadBuildEvidence(s, b.Digest)
		if readErr != nil {
			return nil, fmt.Errorf("already stored, but it does not read back: %w", readErr)
		}
		tx, root, n, err = stored.Tx, stored.Root, len(stored.Records), nil
	}
	if err != nil {
		return nil, err
	}
	return &supplyv1alpha1.EvidenceLedger{
		Database: s.Database(),
		Tx:       int64(tx),
		Root:     hex.EncodeToString(root),
		Records:  int32(n),
		StoredAt: metav1.Now(),
	}, nil
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
//	verify-image-policy:    POLICY_VERIFICATION, VERIFIED_SIGNER
func ExtractAllResults(run *tektonv1.PipelineRun) *supplyv1alpha1.PipelineStepResults {
	r := &supplyv1alpha1.PipelineStepResults{}
	for _, result := range run.Status.Results {
		setResult(r, result.Name, result.Value.StringVal)
	}
	return r
}

// setResult stores one named result in its field. It reports whether the name
// is one it knows.
func setResult(r *supplyv1alpha1.PipelineStepResults, name, value string) bool {
	if field := resultField(r, name); field != nil {
		*field = value
		return true
	}
	return false
}

func resultField(r *supplyv1alpha1.PipelineStepResults, name string) *string {
	switch name {
	// Git
	case "commit":
		return &r.Commit
	case "committer-date":
		return &r.CommitterDate
	case "url":
		return &r.RepoURL
	// Build
	case "IMAGE_URL":
		return &r.ImageURL
	case "IMAGE_DIGEST":
		return &r.ImageDigest
	// Trivy
	case "TRIVY_SCAN_SUMMARY":
		return &r.TrivyScanSummary
	case "TRIVY_CRITICAL_COUNT":
		return &r.TrivyCriticalCount
	case "TRIVY_HIGH_COUNT":
		return &r.TrivyHighCount
	case "TRIVY_TOTAL_COUNT":
		return &r.TrivyTotalCount
	case "TRIVY_SARIF_PATH":
		return &r.TrivySarifPath
	// SonarQube
	case "SONAR_GATE_STATUS":
		return &r.SonarGateStatus
	// Policy
	case "POLICY_VERIFICATION":
		return &r.PolicyVerification
	case "VERIFIED_SIGNER":
		return &r.VerifiedSigner
	}
	return nil
}

// FillFromTaskRuns adds what the tasks of a run reported but the run itself
// did not. A PipelineRun only publishes results of tasks that succeeded, so
// for a build stopped by a gate the reason (how many vulnerabilities, say) is
// only on the TaskRun.
//
// The image URL and digest are never taken from here: only the pipeline's own
// values say what was published, and a build that failed before the push
// published nothing.
func FillFromTaskRuns(r *supplyv1alpha1.PipelineStepResults, taskRuns []tektonv1.TaskRun) {
	for i := range taskRuns {
		for _, result := range taskRuns[i].Status.Results {
			if result.Name == "IMAGE_URL" || result.Name == "IMAGE_DIGEST" {
				continue
			}
			if field := resultField(r, result.Name); field != nil && *field == "" {
				*field = result.Value.StringVal
			}
		}
	}
}

// ExtractImageResults returns just IMAGE_URL and IMAGE_DIGEST.
// Kept for backwards compatibility with callers that only need the image ref.
func ExtractImageResults(run *tektonv1.PipelineRun) (imageURL, imageDigest string) {
	r := ExtractAllResults(run)
	return r.ImageURL, r.ImageDigest
}

func applyStatus(s *supplyv1alpha1.ImageBuildResultStatus, phase, reason, pipelineRunName string, completedAt *metav1.Time, br *supplyv1alpha1.PipelineStepResults) {
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
			return phaseSucceeded, cond.Reason
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
