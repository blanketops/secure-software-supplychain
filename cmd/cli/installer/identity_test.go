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
package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

func spiffeOptions() Options {
	return Options{SigningIdentity: IdentitySPIFFE, TrustDomain: "blanketops.dev"}
}

func TestOptionsDefaultsAndValidation(t *testing.T) {
	var opts Options
	if err := opts.defaultAndValidate(); err != nil {
		t.Fatal(err)
	}
	if opts.SigningIdentity != IdentityKubernetes || opts.TrustDomain != DefaultTrustDomain || opts.UIHost != DefaultUIHost {
		t.Errorf("defaults = %+v", opts)
	}
	for name, bad := range map[string]Options{
		"unknown identity":       {SigningIdentity: "oidc"},
		"upper-case domain":      {TrustDomain: "BlanketOps.dev"},
		"domain with a scheme":   {TrustDomain: "spiffe://blanketops.dev"},
		"domain ending in a dot": {TrustDomain: "blanketops.dev."},
	} {
		if err := bad.defaultAndValidate(); err == nil {
			t.Errorf("%s: accepted %+v", name, bad)
		}
	}
}

// The values the installer writes are the ones the operator reads back to
// decide how signers are named. They must describe the same identity.
func TestChainsConfigIsReadBackAsTheSameIdentity(t *testing.T) {
	toStrings := func(in map[string]any) map[string]string {
		out := map[string]string{}
		for k, v := range in {
			out[k] = v.(string)
		}
		return out
	}

	kubernetes, err := signing.IdentityFromConfig(toStrings(chainsConfig(Options{SigningIdentity: IdentityKubernetes})), nil)
	if err != nil {
		t.Fatal(err)
	}
	if kubernetes != signing.KubernetesIdentity() {
		t.Errorf("kubernetes install is read back as %+v", kubernetes)
	}

	opts := spiffeOptions()
	cfg := chainsConfig(opts)
	if _, set := cfg["signers.x509.identity.token.file"]; set {
		t.Error("the SPIFFE config still points Chains at a ServiceAccount token file")
	}
	spiffe, err := signing.IdentityFromConfig(toStrings(cfg), map[string]string{signing.SpireConfigTrustDomain: opts.TrustDomain})
	if err != nil {
		t.Fatal(err)
	}
	want := signing.Identity{Provider: signing.ProviderSPIFFE, Issuer: spireOIDCIssuer, TrustDomain: "blanketops.dev"}
	if spiffe != want {
		t.Errorf("spiffe install is read back as %+v, want %+v", spiffe, want)
	}
}

func TestFulcioConfig(t *testing.T) {
	type config struct {
		OIDCIssuers map[string]struct {
			IssuerURL, ClientID, Type, SPIFFETrustDomain string
		}
	}
	parse := func(opts Options) config {
		t.Helper()
		raw, err := fulcioConfig(opts)
		if err != nil {
			t.Fatal(err)
		}
		var c config
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("fulcio config is not JSON: %v\n%s", err, raw)
		}
		return c
	}

	kubernetes := parse(Options{SigningIdentity: IdentityKubernetes})
	if len(kubernetes.OIDCIssuers) != 1 || kubernetes.OIDCIssuers[signerOIDCIssuer].Type != "kubernetes" {
		t.Errorf("kubernetes issuers = %+v", kubernetes.OIDCIssuers)
	}

	spiffe := parse(spiffeOptions())
	// The operator still gets its pre-build certificate with a ServiceAccount token.
	if spiffe.OIDCIssuers[signerOIDCIssuer].Type != "kubernetes" {
		t.Error("the SPIFFE config dropped the Kubernetes issuer")
	}
	got := spiffe.OIDCIssuers[spireOIDCIssuer]
	if got.Type != "spiffe" || got.SPIFFETrustDomain != "blanketops.dev" || got.IssuerURL != spireOIDCIssuer || got.ClientID != "sigstore" {
		t.Errorf("SPIFFE issuer = %+v", got)
	}
}

func decodeAll(t *testing.T, path string) []*unstructured.Unstructured {
	t.Helper()
	data, err := manifests.Dependencies.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var objs []*unstructured.Unstructured
	for doc := range bytes.SplitSeq(data, []byte("\n---")) {
		obj := &unstructured.Unstructured{}
		if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc)).Decode(obj); err != nil || obj.GetKind() == "" {
			continue
		}
		objs = append(objs, obj)
	}
	return objs
}

func TestAddSPIFFESocketToChains(t *testing.T) {
	var deployment *unstructured.Unstructured
	for _, obj := range decodeAll(t, "dependencies/tekton/chains/release.yaml") {
		if obj.GetKind() == "Deployment" && obj.GetName() == "tekton-chains-controller" {
			deployment = obj
		}
	}
	if deployment == nil {
		t.Fatal("tekton-chains-controller Deployment not found")
	}

	// Twice: re-running the installer must not duplicate anything.
	for range 2 {
		if err := addSPIFFESocket(deployment); err != nil {
			t.Fatal(err)
		}
	}

	count := func(items []any, name string) int {
		n := 0
		for _, item := range items {
			if item.(map[string]any)["name"] == name {
				n++
			}
		}
		return n
	}
	volumes, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "volumes")
	containers, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	container := containers[0].(map[string]any)
	if n := count(volumes, "spiffe-workload-api"); n != 1 {
		t.Errorf("%d spiffe-workload-api volumes, want 1", n)
	}
	if n := count(container["volumeMounts"].([]any), "spiffe-workload-api"); n != 1 {
		t.Errorf("%d spiffe-workload-api mounts, want 1", n)
	}
	if n := count(container["env"].([]any), "SPIFFE_ENDPOINT_SOCKET"); n != 1 {
		t.Errorf("%d SPIFFE_ENDPOINT_SOCKET variables, want 1", n)
	}
	// What was there before must survive: the trust anchors and the token.
	for _, name := range []string{"sigstore-roots", "oidc-info", "signing-secrets"} {
		if count(volumes, name) != 1 {
			t.Errorf("volume %q was lost", name)
		}
	}
}

// The vendored SPIRE manifests were rendered with a placeholder trust domain
// and a fixed OIDC issuer. The installer relies on both.
func TestSpireManifests(t *testing.T) {
	release, err := manifests.Dependencies.ReadFile("dependencies/spire/release/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(release, []byte(trustDomainPlaceholder)) {
		t.Fatal("the SPIRE release does not contain the trust domain placeholder")
	}
	if !bytes.Contains(release, []byte(`"jwt_issuer": "`+spireOIDCIssuer+`"`)) {
		t.Errorf("SPIRE is not rendered with the issuer the installer gives Fulcio and Chains (%s)", spireOIDCIssuer)
	}

	i := &Installer{opts: spiffeOptions()}
	substituted := i.substituteManifest(release)
	if bytes.Contains(substituted, []byte(trustDomainPlaceholder)) {
		t.Error("the placeholder survives substitution")
	}
	if !bytes.Contains(substituted, []byte("blanketops.dev")) {
		t.Error("the trust domain was not substituted in")
	}

	kinds := map[string]int{}
	for _, dir := range []string{"crds/crds.yaml", "release/release.yaml", "identities/identities.yaml"} {
		for _, obj := range decodeAll(t, "dependencies/spire/"+dir) {
			kinds[obj.GetKind()]++
			if obj.GetKind() == "ClusterSPIFFEID" && obj.GetName() == defaultClusterSPIFFEID {
				t.Errorf("%s gives every pod an identity; identities are granted, not default", obj.GetName())
			}
			if obj.GetKind() == "ClusterSPIFFEID" && !strings.HasSuffix(dir, "identities.yaml") {
				t.Errorf("ClusterSPIFFEID %s is in %s; it must be applied after the server is up", obj.GetName(), dir)
			}
		}
	}
	// Two ClusterSPIFFEIDs, not the chart's three: the default one, which gives
	// every pod an identity, is left out. Chains and the node alias are
	// registered as static entries instead.
	for kind, want := range map[string]int{
		"CustomResourceDefinition": 3, "StatefulSet": 1, "CSIDriver": 1,
		"ClusterSPIFFEID": 2, "ClusterStaticEntry": 2,
	} {
		if kinds[kind] != want {
			t.Errorf("%d %s objects in the SPIRE manifests, want %d", kinds[kind], kind, want)
		}
	}
}

func TestSpireStepsOnlyForSPIFFE(t *testing.T) {
	steps := func(opts Options) (names []string) {
		i := &Installer{opts: opts}
		for _, s := range installOrder {
			if s.Skip == nil || !s.Skip(i) {
				names = append(names, s.Name)
			}
		}
		return names
	}
	if joined := strings.Join(steps(Options{SigningIdentity: IdentityKubernetes}), ","); strings.Contains(joined, "SPIRE") {
		t.Errorf("a Kubernetes-identity install includes SPIRE steps: %s", joined)
	}
	joined := strings.Join(steps(spiffeOptions()), ",")
	// SPIRE has to be up before Fulcio is told to trust its issuer.
	if !strings.Contains(joined, "SPIRE CRDs,SPIRE,SPIRE Identities,Fulcio") {
		t.Errorf("SPIFFE install order = %s", joined)
	}
}

func TestFindEmbeddedJob(t *testing.T) {
	job, err := findEmbeddedJob("dependencies/sigstore/rekor", "trillian-system", "rekor-trillian-createdb")
	if err != nil {
		t.Fatal(err)
	}
	if job.GetKind() != "Job" || job.GetName() != "rekor-trillian-createdb" {
		t.Errorf("found %s/%s", job.GetKind(), job.GetName())
	}
	if _, err := findEmbeddedJob("dependencies/sigstore/rekor", "trillian-system", "no-such-job"); err == nil {
		t.Error("found a job that does not exist")
	}
}

func TestJobGaveUp(t *testing.T) {
	job := func(conditionType, status string, succeeded int64) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"status": map[string]any{
				"succeeded":  succeeded,
				"conditions": []any{map[string]any{"type": conditionType, "status": status}},
			},
		}}
	}
	if !jobGaveUp(job("Failed", "True", 0)) {
		t.Error("a Job with Failed=True is not seen as given up")
	}
	if jobGaveUp(job("Complete", "True", 1)) || jobGaveUp(job("Failed", "False", 0)) {
		t.Error("a Job that has not failed is seen as given up")
	}
	if !jobSucceeded(job("Complete", "True", 1)) || jobSucceeded(job("Failed", "True", 0)) {
		t.Error("jobSucceeded disagrees with status.succeeded")
	}
}

func TestStepsToRunFromStep(t *testing.T) {
	i := &Installer{opts: Options{SigningIdentity: IdentitySPIFFE, FromStep: "tekton chains"}}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Name != "Tekton Chains" {
		t.Errorf("resumes at %q, want Tekton Chains", steps[0].Name)
	}
	for _, s := range steps {
		// The steps that generate keys come before it and must not run again.
		if s.Name == "Fulcio" || s.Name == "Rekor" || strings.HasPrefix(s.Name, "SPIRE") {
			t.Errorf("resuming from Tekton Chains still runs %q", s.Name)
		}
	}

	i.opts.FromStep = "Policy Controller"
	if steps, _ := i.stepsToRun(); steps[0].Name != "Policy Controller" {
		t.Errorf("resumes at %q, want Policy Controller", steps[0].Name)
	}

	i.opts.FromStep = "no such step"
	if _, err := i.stepsToRun(); err == nil || !strings.Contains(err.Error(), "Tekton Chains") {
		t.Errorf("err = %v, want it to list the valid steps", err)
	}
}

// Every key-generating Job named in keyJobs must exist in the manifests, or
// the guard protects nothing.
func TestKeyJobsExistInManifests(t *testing.T) {
	for key := range keyJobs {
		namespace, name, _ := strings.Cut(key, "/")
		if _, err := findEmbeddedJob("dependencies/sigstore/fulcio", namespace, name); err != nil {
			t.Errorf("keyJobs names %s, which is not in the Fulcio manifests: %v", key, err)
		}
	}
}
