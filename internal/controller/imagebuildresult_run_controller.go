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

package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tektonv1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/results"
)

// ImageBuildResultRunReconciler publishes build results to Tekton.
//
// When a build is over, the ImageBuild controller creates a CustomRun that
// refers to the ImageBuildResult kind. Tekton leaves such a run to whoever
// owns the kind. This reconciler completes it: it reports a summary of the
// ImageBuildResult as the results of the run, so the outcome of a build and
// the evidence for it can be read in Tekton, with the runs that produced it.
type ImageBuildResultRunReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=tekton.dev,resources=customruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=tekton.dev,resources=customruns/status,verbs=get;update;patch

func (r *ImageBuildResultRunReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var run tektonv1beta1.CustomRun
	if err := r.Get(ctx, req.NamespacedName, &run); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !results.IsRun(&run) || run.IsDone() {
		return ctrl.Result{}, nil
	}
	if run.Status.StartTime == nil {
		now := metav1.Now()
		run.Status.StartTime = &now
	}

	// Tekton cancels a CustomRun, on a pipeline timeout for instance, by
	// setting spec.status and expects the owner of the kind to end it.
	if run.IsCancelled() {
		now := metav1.Now()
		run.Status.CompletionTime = &now
		run.Status.MarkCustomRunFailed(string(tektonv1beta1.CustomRunReasonCancelled), "%s",
			"Cancelled before the ImageBuildResult was published")
		return ctrl.Result{}, r.Status().Update(ctx, &run)
	}

	result, err := r.result(ctx, &run)
	now := metav1.Now()
	run.Status.CompletionTime = &now
	if err != nil {
		log.Error(err, "Could not publish ImageBuildResult", "customRun", run.Name)
		run.Status.MarkCustomRunFailed("ResultNotFound", "%s", err.Error())
	} else {
		run.Status.Results = runResults(result)
		run.Status.MarkCustomRunSucceeded("Published",
			"ImageBuildResult %s records a build that %s", result.Name, strings.ToLower(result.Status.Phase))
		log.Info("Published ImageBuildResult", "customRun", run.Name, "imageBuildResult", result.Name)
	}
	if err := r.Status().Update(ctx, &run); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// result reads the ImageBuildResult the run was created to publish.
func (r *ImageBuildResultRunReconciler) result(
	ctx context.Context,
	run *tektonv1beta1.CustomRun,
) (*supplychainv1alpha1.ImageBuildResult, error) {
	var buildName string
	for _, param := range run.Spec.Params {
		if param.Name == results.RunParamImageBuild {
			buildName = param.Value.StringVal
		}
	}
	if buildName == "" {
		return nil, fmt.Errorf("parameter %s is not set", results.RunParamImageBuild)
	}
	var result supplychainv1alpha1.ImageBuildResult
	if err := r.Get(ctx, types.NamespacedName{Namespace: run.Namespace, Name: buildName}, &result); err != nil {
		return nil, fmt.Errorf("reading ImageBuildResult %s: %w", buildName, err)
	}
	return &result, nil
}

// runResults is the summary of an ImageBuildResult shown on the CustomRun.
// The full record stays on the ImageBuildResult; Tekton results are strings.
func runResults(result *supplychainv1alpha1.ImageBuildResult) []tektonv1beta1.CustomRunResult {
	status := result.Status
	out := []tektonv1beta1.CustomRunResult{
		{Name: "IMAGE_BUILD_RESULT", Value: result.Name},
		{Name: "PHASE", Value: status.Phase},
	}
	add := func(name, value string) {
		if value != "" {
			out = append(out, tektonv1beta1.CustomRunResult{Name: name, Value: value})
		}
	}
	add("IMAGE_URL", status.ImageURL)
	add("IMAGE_DIGEST", status.ImageDigest)
	if steps := status.BuildResults; steps != nil {
		add("COMMIT", steps.Commit)
		add("TRIVY_SCAN_SUMMARY", steps.TrivyScanSummary)
		add("TRIVY_CRITICAL_COUNT", steps.TrivyCriticalCount)
		add("SONAR_GATE_STATUS", steps.SonarGateStatus)
		add("POLICY_VERIFICATION", steps.PolicyVerification)
	}
	if evidence := status.Evidence; evidence != nil {
		entries := make([]string, 0, len(evidence.Signatures))
		for _, record := range evidence.Signatures {
			entry := record.SignedBy + " " + strings.ToLower(record.Kind)
			if record.RekorLogIndex != nil {
				entry += " @" + strconv.FormatInt(*record.RekorLogIndex, 10)
			}
			entries = append(entries, entry)
		}
		add("SIGNATURES", strings.Join(entries, ", "))
		add("PROVENANCE_LOG_ENTRY", evidence.ProvenanceLogEntry)
		add("EVIDENCE_COMPLETE", strconv.FormatBool(evidence.Complete))
		add("REKOR_URL", evidence.RekorURL)
		if anchors := evidence.TrustAnchors; anchors != nil {
			add("REKOR_KEY", anchors.RekorKey)
			add("FULCIO_ROOT", anchors.FulcioRoot)
		}
		add("EVIDENCE_GAPS", evidence.Message)
	}
	return out
}

func (r *ImageBuildResultRunReconciler) SetupWithManager(mgr ctrl.Manager) error {
	ours := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		run, ok := obj.(*tektonv1beta1.CustomRun)
		return ok && results.IsRun(run)
	})
	return ctrl.NewControllerManagedBy(mgr).
		Named("imagebuildresult-run").
		For(&tektonv1beta1.CustomRun{}, builder.WithPredicates(ours)).
		Complete(r)
}
