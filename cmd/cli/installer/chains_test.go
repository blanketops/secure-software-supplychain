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
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

func TestChainsConfig(t *testing.T) {
	cfg := chainsConfig()

	// Provenance has to be findable next to the image, in the current format.
	if repo, set := cfg["storage.oci.repository"]; set {
		t.Errorf("storage.oci.repository = %v; attestations must be stored alongside the image", repo)
	}
	for _, key := range []string{"artifacts.taskrun.format", "artifacts.pipelinerun.format"} {
		if cfg[key] != "slsa/v2alpha4" {
			t.Errorf("%s = %v, want slsa/v2alpha4 (SLSA v1.0 provenance)", key, cfg[key])
		}
	}

	// Keyless against the in-cluster Fulcio, with the token the Deployment mounts.
	if cfg["signers.x509.fulcio.enabled"] != "true" {
		t.Error("Fulcio keyless signing is not enabled")
	}
	if provider, set := cfg["signers.x509.fulcio.provider"]; set {
		t.Errorf("signers.x509.fulcio.provider = %v; the controller has a token file, not that provider", provider)
	}
	if cfg["signers.x509.identity.token.file"] != chainsIdentityTokenFile {
		t.Errorf("identity token file = %v, want %q", cfg["signers.x509.identity.token.file"], chainsIdentityTokenFile)
	}
}

// The Chains Deployment must mount the token chainsConfig points at and the
// trust anchors of the in-cluster sigstore, or keyless signing cannot work.
func TestChainsDeploymentMatchesConfig(t *testing.T) {
	data, err := manifests.Dependencies.ReadFile("dependencies/tekton/chains/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var deployment *unstructured.Unstructured
	for _, doc := range bytes.Split(data, []byte("\n---")) {
		obj := &unstructured.Unstructured{}
		if err := yaml.NewYAMLOrJSONDecoder(bytes.NewReader(doc), len(doc)).Decode(obj); err != nil {
			continue
		}
		if obj.GetKind() == "Deployment" && obj.GetName() == "tekton-chains-controller" {
			deployment = obj
		}
	}
	if deployment == nil {
		t.Fatal("tekton-chains-controller Deployment not found in the Chains release")
	}

	containers, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "containers")
	container := containers[0].(map[string]interface{})

	mounts := map[string]string{}
	for _, m := range container["volumeMounts"].([]interface{}) {
		mount := m.(map[string]interface{})
		mounts[mount["name"].(string)] = mount["mountPath"].(string)
	}
	if !strings.HasPrefix(chainsIdentityTokenFile, mounts["oidc-info"]+"/") {
		t.Errorf("token file %q is not under the oidc-info mount %q", chainsIdentityTokenFile, mounts["oidc-info"])
	}
	rootsMount, ok := mounts["sigstore-roots"]
	if !ok {
		t.Fatal("the sigstore trust anchors are not mounted")
	}

	env := map[string]string{}
	for _, e := range container["env"].([]interface{}) {
		v := e.(map[string]interface{})
		if value, ok := v["value"].(string); ok {
			env[v["name"].(string)] = value
		}
	}
	for name, file := range map[string]string{
		"SIGSTORE_ROOT_FILE":              "fulcio-root.pem",
		"SIGSTORE_REKOR_PUBLIC_KEY":       "rekor.pub",
		"SIGSTORE_CT_LOG_PUBLIC_KEY_FILE": "ctfe.pub",
	} {
		if want := rootsMount + "/" + file; env[name] != want {
			t.Errorf("%s = %q, want %q", name, env[name], want)
		}
	}

	volumes, _, _ := unstructured.NestedSlice(deployment.Object, "spec", "template", "spec", "volumes")
	for _, v := range volumes {
		volume := v.(map[string]interface{})
		if volume["name"] != "sigstore-roots" {
			continue
		}
		cm := volume["configMap"].(map[string]interface{})
		if cm["name"] != sigstoreRootsName {
			t.Errorf("trust anchors come from ConfigMap %v, want %q", cm["name"], sigstoreRootsName)
		}
		// It is created after the Deployment; a required volume would deadlock
		// the installer, which waits for this Deployment first.
		if cm["optional"] != true {
			t.Error("the trust anchor volume must be optional")
		}
		return
	}
	t.Error("no sigstore-roots volume")
}
