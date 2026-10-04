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
package pipeline

import (
	"strings"
	"testing"
	"time"

	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/authz"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

func testPipelineRun(t *testing.T) *tektonv1.PipelineRun {
	t.Helper()
	sc := &supplyv1alpha1.SupplyChain{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: supplyv1alpha1.SupplyChainSpec{
			Image:              supplyv1alpha1.ImageSpec{Registry: "docker.io", Name: "org/app"},
			Steps:              supplyv1alpha1.StepsSpec{Sign: true, Attest: true},
			ServiceAccountName: "supply-chain-runner",
		},
	}
	ib := &supplyv1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "default"},
		Spec:       supplyv1alpha1.ImageBuildSpec{GitRef: supplyv1alpha1.GitRef{URL: "git@example.com:org/app.git"}},
	}
	proof := func(resource, verb string) *authz.AuthzProof {
		return &authz.AuthzProof{
			Principal: "system:serviceaccount:default:supply-chain-runner",
			Resource:  resource, Verb: verb, Allowed: true, EvaluatedAt: time.Unix(0, 0),
		}
	}
	sigCtx := &signing.RunSigningContext{
		ScopeProof:  proof("supplychains", "get"),
		IntentProof: proof("imagebuilds", "create"),
		OutputProof: proof("imagesignatures", "create"),
	}
	return BuildPipelineRun("run", "default", sc, ib, "docker.io/org/app:tag", sigCtx)
}

func findTask(t *testing.T, pr *tektonv1.PipelineRun, name string) tektonv1.PipelineTask {
	t.Helper()
	for _, task := range pr.Spec.PipelineSpec.Tasks {
		if task.Name == name {
			return task
		}
	}
	t.Fatalf("pipeline has no task %q", name)
	return tektonv1.PipelineTask{}
}

func param(t *testing.T, params tektonv1.Params, name string) string {
	t.Helper()
	for _, p := range params {
		if p.Name == name {
			return p.Value.StringVal
		}
	}
	t.Fatalf("no param %q", name)
	return ""
}

// The digest that gets signed, attested and reported must be the one the
// registry serves. The build archive's digest changes when the image is pushed,
// so a signature over it is attached to an image nobody can pull.
func TestSignsThePushedDigest(t *testing.T) {
	pr := testPipelineRun(t)
	const pushed = "$(tasks." + stepPushImage + ".results.IMAGE_DIGEST)"

	if got := param(t, findTask(t, pr, stepSign).Params, "DIGEST"); got != pushed {
		t.Errorf("sign task DIGEST = %q, want the push task's digest %q", got, pushed)
	}

	var reported string
	for _, result := range pr.Spec.PipelineSpec.Results {
		if result.Name == "IMAGE_DIGEST" {
			reported = result.Value.StringVal
		}
	}
	if reported != pushed {
		t.Errorf("pipeline result IMAGE_DIGEST = %q, want %q", reported, pushed)
	}

	push := findTask(t, pr, stepPushImage).TaskSpec.TaskSpec
	if len(push.Results) != 1 || push.Results[0].Name != "IMAGE_DIGEST" {
		t.Fatalf("push task results = %v, want IMAGE_DIGEST", push.Results)
	}
	if script := push.Steps[0].Script; !strings.Contains(script, "--digestfile") ||
		!strings.Contains(script, "$(results.IMAGE_DIGEST.path)") {
		t.Errorf("push step does not record the pushed digest:\n%s", script)
	}
}

func TestSignTaskAttestsTheAuthorizationProofs(t *testing.T) {
	sign := findTask(t, testPipelineRun(t), stepSign)

	steps := sign.TaskSpec.TaskSpec.Steps
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	if got := strings.Join(names, ","); got != "sign,write-authorization-predicate,attest-authorization" {
		t.Fatalf("sign task steps = %s", got)
	}

	attest := strings.Join(steps[2].Args, " ")
	for _, want := range []string{
		"attest",
		"--type=" + signing.AuthorizationPredicateType,
		"$(params.IMAGE)@$(params.DIGEST)",
	} {
		if !strings.Contains(attest, want) {
			t.Errorf("attest step args %q are missing %q", attest, want)
		}
	}

	predicate := param(t, sign.Params, "AUTHORIZATION_PREDICATE")
	for _, want := range []string{`"scope"`, `"intent"`, `"output"`, `"allowed":true`} {
		if !strings.Contains(predicate, want) {
			t.Errorf("predicate %s is missing %s", predicate, want)
		}
	}
}
