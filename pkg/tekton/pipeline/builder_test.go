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
	return testPipelineRunAs(t, signing.Identity{})
}

func testPipelineRunAs(t *testing.T, identity signing.Identity) *tektonv1.PipelineRun {
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
		Identity:    identity,
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

	// The push is the only task that reports the IMAGE_URL / IMAGE_DIGEST
	// pair, which is what Tekton Chains reads to decide what a run produced.
	push := findTask(t, pr, stepPushImage).TaskSpec.TaskSpec
	names := map[string]bool{}
	for _, result := range push.Results {
		names[result.Name] = true
	}
	if !names["IMAGE_URL"] || !names["IMAGE_DIGEST"] {
		t.Fatalf("push task results = %v, want IMAGE_URL and IMAGE_DIGEST", push.Results)
	}
	if !strings.Contains(push.Steps[0].Script, "$(results.IMAGE_URL.path)") {
		t.Error("push step does not write the IMAGE_URL result it declares")
	}
	for _, result := range pr.Spec.PipelineSpec.Results {
		if result.Name == "IMAGE_URL" || result.Name == "IMAGE_DIGEST" {
			if want := "$(tasks." + stepPushImage + ".results." + result.Name + ")"; result.Value.StringVal != want {
				t.Errorf("pipeline result %s = %q, want %q", result.Name, result.Value.StringVal, want)
			}
		}
	}
	if script := push.Steps[0].Script; !strings.Contains(script, "--digestfile") ||
		!strings.Contains(script, "$(results.IMAGE_DIGEST.path)") {
		t.Errorf("push step does not record the pushed digest:\n%s", script)
	}
}

// The build's last task must check the published image the way admission does:
// same digest, same signer, and the same authorization policy text.
func TestVerifiesTheImageAgainstThePolicyLast(t *testing.T) {
	pr := testPipelineRun(t)
	tasks := pr.Spec.PipelineSpec.Tasks
	verify := tasks[len(tasks)-1]
	if verify.Name != stepVerify {
		t.Fatalf("last task = %q, want %q", verify.Name, stepVerify)
	}
	if len(verify.RunAfter) != 1 || verify.RunAfter[0] != stepAttest {
		t.Errorf("verify runs after %v, want %q", verify.RunAfter, stepAttest)
	}

	if got, want := param(t, verify.Params, "DIGEST"), "$(tasks."+stepPushImage+".results.IMAGE_DIGEST)"; got != want {
		t.Errorf("verify DIGEST = %q, want the pushed digest %q", got, want)
	}
	const identity = "https://kubernetes.io/namespaces/default/serviceaccounts/supply-chain-runner"
	if got := param(t, verify.Params, "IDENTITY"); got != identity {
		t.Errorf("verify IDENTITY = %q, want %q", got, identity)
	}
	wantPolicy := signing.AuthorizationPolicyCUE("system:serviceaccount:default:supply-chain-runner")
	if got := param(t, verify.Params, "AUTHORIZATION_POLICY"); got != wantPolicy {
		t.Errorf("verify policy differs from the admission policy:\n%s", got)
	}

	steps := verify.TaskSpec.Steps
	signature, authorization := strings.Join(steps[1].Args, " "), strings.Join(steps[2].Args, " ")
	if !strings.HasPrefix(signature, "verify ") || !strings.HasPrefix(authorization, "verify-attestation ") {
		t.Fatalf("verify steps run %q and %q", steps[1].Args[0], steps[2].Args[0])
	}
	for _, args := range []string{signature, authorization} {
		for _, want := range []string{
			"--certificate-identity=$(params.IDENTITY)",
			"--certificate-oidc-issuer=" + signing.KubernetesOIDCIssuer,
			"$(params.IMAGE)@$(params.DIGEST)",
		} {
			if !strings.Contains(args, want) {
				t.Errorf("%q is missing %q", args, want)
			}
		}
	}
	if !strings.Contains(authorization, "--type="+signing.AuthorizationPredicateType) {
		t.Errorf("verify-attestation does not select the authorization predicate: %q", authorization)
	}

	// The outcome is reported last, so it is only written when both passed,
	// and it is surfaced as pipeline results for the ImageBuildResult.
	report := steps[len(steps)-1]
	if report.Name != "report" || !strings.Contains(report.Script, "$(results.POLICY_VERIFICATION.path)") {
		t.Errorf("last verify step %q does not report the outcome", report.Name)
	}
	reported := map[string]string{}
	for _, result := range pr.Spec.PipelineSpec.Results {
		reported[result.Name] = result.Value.StringVal
	}
	for _, name := range []string{"POLICY_VERIFICATION", "VERIFIED_SIGNER"} {
		if want := "$(tasks." + stepVerify + ".results." + name + ")"; reported[name] != want {
			t.Errorf("pipeline result %s = %q, want %q", name, reported[name], want)
		}
	}
}

// Under SPIFFE the cosign steps get their identity from the Workload API
// socket, not from a ServiceAccount token, and everything downstream expects
// the SPIFFE ID.
func TestSignsWithSPIFFEIdentity(t *testing.T) {
	pr := testPipelineRunAs(t, signing.Identity{
		Provider: signing.ProviderSPIFFE, Issuer: "http://oidc.spire.svc", TrustDomain: "blanketops.dev",
	})

	sign := findTask(t, pr, stepSign).TaskSpec.TaskSpec
	var csi, token bool
	for _, volume := range sign.Volumes {
		csi = csi || (volume.CSI != nil && volume.CSI.Driver == signing.SPIFFECSIDriver)
		token = token || volume.Projected != nil
	}
	if !csi || token {
		t.Errorf("sign task volumes: SPIFFE CSI=%v, projected token=%v; want the socket and no token", csi, token)
	}
	for _, step := range []tektonv1.Step{sign.Steps[1], sign.Steps[len(sign.Steps)-1]} {
		args := strings.Join(step.Args, " ")
		for _, want := range []string{"--oidc-provider=spiffe", "--oidc-issuer=http://oidc.spire.svc"} {
			if !strings.Contains(args, want) {
				t.Errorf("step %s args %q are missing %q", step.Name, args, want)
			}
		}
		var socket bool
		for _, env := range step.Env {
			socket = socket || (env.Name == signing.SPIFFESocketEnv && env.Value == signing.SPIFFESocketValue)
		}
		if !socket {
			t.Errorf("step %s does not point cosign at the Workload API socket", step.Name)
		}
	}

	verify := findTask(t, pr, stepVerify)
	if got, want := param(t, verify.Params, "IDENTITY"), "spiffe://blanketops.dev/ns/default/sa/supply-chain-runner"; got != want {
		t.Errorf("verify IDENTITY = %q, want %q", got, want)
	}
	if args := strings.Join(verify.TaskSpec.TaskSpec.Steps[1].Args, " "); !strings.Contains(args,
		"--certificate-oidc-issuer=http://oidc.spire.svc") {
		t.Errorf("verify does not expect the SPIFFE issuer: %q", args)
	}
	if got, want := param(t, verify.Params, "CHAINS_IDENTITY"),
		"spiffe://blanketops.dev/ns/tekton-chains/sa/tekton-chains-controller"; got != want {
		t.Errorf("verify CHAINS_IDENTITY = %q, want %q", got, want)
	}
}

// The runner and Chains write their signatures to the same registry tag, so
// the runner has to wait for Chains; and the build is only verified when both
// tiers are: the runner's signature and authorization, Chains' signature and
// provenance.
func TestRunnerSignsAfterChainsAndBothAreVerified(t *testing.T) {
	pr := testPipelineRun(t)

	sign := findTask(t, pr, stepSign).TaskSpec.TaskSpec
	if first := sign.Steps[0]; first.Name != "await-chains-signature" || !strings.Contains(first.Script, ".sig") {
		t.Errorf("sign task starts with %q, want it to wait for Chains' signature", first.Name)
	}

	steps := map[string]string{}
	for _, step := range findTask(t, pr, stepVerify).TaskSpec.Steps {
		steps[step.Name] = strings.Join(step.Args, " ")
	}
	for name, identity := range map[string]string{
		"verify-signature":        "--certificate-identity=$(params.IDENTITY)",
		"verify-authorization":    "--certificate-identity=$(params.IDENTITY)",
		"verify-chains-signature": "--certificate-identity=$(params.CHAINS_IDENTITY)",
		"verify-provenance":       "--certificate-identity=$(params.CHAINS_IDENTITY)",
	} {
		if !strings.Contains(steps[name], identity) {
			t.Errorf("verify step %s args %q are missing %q", name, steps[name], identity)
		}
	}
	if !strings.Contains(steps["verify-provenance"], "--type=slsaprovenance1") {
		t.Errorf("verify-provenance does not check SLSA provenance: %q", steps["verify-provenance"])
	}
}

// With the Kubernetes identity nothing about SPIFFE may appear: a CSI volume
// for a driver that is not installed would keep the pod from starting.
func TestKubernetesIdentityUsesNoSPIFFE(t *testing.T) {
	sign := findTask(t, testPipelineRun(t), stepSign).TaskSpec.TaskSpec
	for _, volume := range sign.Volumes {
		if volume.CSI != nil {
			t.Errorf("sign task mounts CSI volume %q under the Kubernetes identity", volume.Name)
		}
	}
	if args := strings.Join(sign.Steps[1].Args, " "); strings.Contains(args, "--oidc-provider") ||
		!strings.Contains(args, "--oidc-issuer="+signing.KubernetesOIDCIssuer) {
		t.Errorf("sign args under the Kubernetes identity: %q", args)
	}
}

func TestNoVerifyWithoutSigning(t *testing.T) {
	sc := &supplyv1alpha1.SupplyChain{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec:       supplyv1alpha1.SupplyChainSpec{Image: supplyv1alpha1.ImageSpec{Registry: "docker.io", Name: "org/app"}},
	}
	ib := &supplyv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "default"}}
	pr := BuildPipelineRun("run", "default", sc, ib, "docker.io/org/app:tag", nil)
	for _, task := range pr.Spec.PipelineSpec.Tasks {
		if task.Name == stepVerify || task.Name == stepSign {
			t.Errorf("pipeline with signing off has task %q", task.Name)
		}
	}
	for _, result := range pr.Spec.PipelineSpec.Results {
		if result.Name == "POLICY_VERIFICATION" {
			t.Error("pipeline with signing off reports a result of the verify task it does not have")
		}
	}
}

// An image with critical vulnerabilities must not reach the registry, so the
// scan runs on the build archive and the push waits for it.
func TestScansBeforePushing(t *testing.T) {
	sc := &supplyv1alpha1.SupplyChain{
		ObjectMeta: metav1.ObjectMeta{Name: "app", Namespace: "default"},
		Spec: supplyv1alpha1.SupplyChainSpec{
			Image: supplyv1alpha1.ImageSpec{Registry: "docker.io", Name: "org/app"},
			Steps: supplyv1alpha1.StepsSpec{Trivy: true},
		},
	}
	ib := &supplyv1alpha1.ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: "build", Namespace: "default"}}
	pr := BuildPipelineRun("run", "default", sc, ib, "docker.io/org/app:tag", nil)

	scan, push := findTask(t, pr, stepTrivy), findTask(t, pr, stepPushImage)
	if len(scan.RunAfter) != 1 || scan.RunAfter[0] != stepBuildImage {
		t.Errorf("scan runs after %v, want the build %q", scan.RunAfter, stepBuildImage)
	}
	if len(push.RunAfter) != 1 || push.RunAfter[0] != stepTrivy {
		t.Errorf("push runs after %v, want the scan %q", push.RunAfter, stepTrivy)
	}
	if got := param(t, scan.Params, "IMAGE_TAR"); got != imageArchive {
		t.Errorf("scan IMAGE_TAR = %q, want the build archive %q", got, imageArchive)
	}
}

func TestSignTaskAttestsTheAuthorizationProofs(t *testing.T) {
	sign := findTask(t, testPipelineRun(t), stepSign)

	steps := sign.TaskSpec.Steps
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, step.Name)
	}
	if got := strings.Join(names, ","); got != "await-chains-signature,sign,write-authorization-predicate,attest-authorization" {
		t.Fatalf("sign task steps = %s", got)
	}

	attest := strings.Join(steps[3].Args, " ")
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
