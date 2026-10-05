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
	"testing"

	tektonv1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/results"
)

func TestRecognisesItsOwnRuns(t *testing.T) {
	run := func(apiVersion, kind string) *tektonv1beta1.CustomRun {
		return &tektonv1beta1.CustomRun{Spec: tektonv1beta1.CustomRunSpec{
			CustomRef: &tektonv1beta1.TaskRef{APIVersion: apiVersion, Kind: tektonv1beta1.TaskKind(kind)},
		}}
	}
	ib := &supplychainv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "app-1", Namespace: "team-a"}}
	if !results.IsRun(results.NewRun(ib, "run-app-1")) {
		t.Error("the run created for a build is not recognised")
	}
	for _, other := range []*tektonv1beta1.CustomRun{
		run("supplychain.blanketops.dev/v1alpha1", "ImageBuild"),
		run("example.dev/v1", "ImageBuildResult"),
		{},
	} {
		if results.IsRun(other) {
			t.Errorf("CustomRun %+v belongs to someone else", other.Spec.CustomRef)
		}
	}
}

// The CustomRun shows a summary: what was built, whether the gates passed,
// and who signed it where in the log.
func TestRunResults(t *testing.T) {
	index := func(i int64) *int64 { return &i }
	result := &supplychainv1alpha1.ImageBuildResult{
		ObjectMeta: metav1.ObjectMeta{Name: "app-1"},
		Status: supplychainv1alpha1.ImageBuildResultStatus{
			Phase:       "Succeeded",
			ImageURL:    "docker.io/org/app:v1",
			ImageDigest: "sha256:abc",
			BuildResults: &supplychainv1alpha1.PipelineStepResults{
				TrivyScanSummary: "PASS", PolicyVerification: "PASS",
			},
			Evidence: &supplychainv1alpha1.BuildEvidence{
				RekorURL: "http://rekor",
				Signatures: []supplychainv1alpha1.SignatureRecord{
					{Kind: "Signature", SignedBy: "Chains", RekorLogIndex: index(50)},
					{Kind: "Signature", SignedBy: "Build", RekorLogIndex: index(51)},
					{Kind: "Attestation", SignedBy: "Build"},
				},
			},
		},
	}
	got := map[string]string{}
	for _, r := range runResults(result) {
		got[r.Name] = r.Value
	}
	want := map[string]string{
		"IMAGE_BUILD_RESULT":  "app-1",
		"PHASE":               "Succeeded",
		"IMAGE_DIGEST":        "sha256:abc",
		"POLICY_VERIFICATION": "PASS",
		"SIGNATURES":          "Chains signature @50, Build signature @51, Build attestation",
		"REKOR_URL":           "http://rekor",
	}
	for name, value := range want {
		if got[name] != value {
			t.Errorf("%s = %q, want %q", name, got[name], value)
		}
	}
	if _, set := got["SONAR_GATE_STATUS"]; set {
		t.Error("an empty value was reported as a result")
	}
}
