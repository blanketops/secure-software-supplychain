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
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

// manifestObjects parses every object in an embedded manifest file.
func manifestObjects(t *testing.T, file string) []*unstructured.Unstructured {
	t.Helper()
	data, err := manifests.Dependencies.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var objects []*unstructured.Unstructured
	decoder := yaml.NewYAMLOrJSONDecoder(strings.NewReader(string(data)), 4096)
	for {
		obj := &unstructured.Unstructured{}
		if err := decoder.Decode(&obj.Object); err != nil {
			break
		}
		if obj.GetKind() != "" {
			objects = append(objects, obj)
		}
	}
	return objects
}

func find(t *testing.T, objects []*unstructured.Unstructured, kind, name string) *unstructured.Unstructured {
	t.Helper()
	for _, obj := range objects {
		if obj.GetKind() == kind && obj.GetName() == name {
			return obj
		}
	}
	t.Fatalf("no %s %s in the manifest", kind, name)
	return nil
}

// Rekor only speaks plain HTTP. It must not be reachable that way from
// outside its pod: the server listens on loopback, the Service offers the TLS
// port alone, and the chart's plain-HTTP Ingress is gone.
func TestRekorIsOnlyReachableOverTLS(t *testing.T) {
	objects := manifestObjects(t, "dependencies/sigstore/rekor/release.yaml")

	ports, _, _ := unstructured.NestedSlice(find(t, objects, "Service", "rekor-server").Object, "spec", "ports")
	for _, p := range ports {
		port := p.(map[string]any)
		if port["name"] == "2112-tcp" { // metrics
			continue
		}
		if fmt.Sprint(port["port"]) != "443" || fmt.Sprint(port["targetPort"]) != "8443" {
			t.Errorf("the Service exposes %v; want only 443 to the TLS container", port)
		}
	}

	containers, _, _ := unstructured.NestedSlice(
		find(t, objects, "Deployment", "rekor-server").Object, "spec", "template", "spec", "containers")
	var server, proxy map[string]any
	for _, c := range containers {
		container := c.(map[string]any)
		switch container["name"] {
		case "rekor-server":
			server = container
		case "tls":
			proxy = container
		}
	}
	if server == nil || proxy == nil {
		t.Fatal("the Deployment needs the rekor-server and tls containers")
	}
	args, _ := server["args"].([]any)
	if !reflect.DeepEqual(filter(args, "--rekor_server.address="), []any{"--rekor_server.address=127.0.0.1"}) {
		t.Errorf("rekor-server must listen on loopback only; args: %v", args)
	}
	if _, probed := server["readinessProbe"]; probed {
		t.Error("the kubelet cannot probe a loopback listener; the probe belongs on the tls container")
	}
	if scheme, _, _ := unstructured.NestedString(proxy, "readinessProbe", "httpGet", "scheme"); scheme != "HTTPS" {
		t.Errorf("the tls container's readiness probe uses %q, want HTTPS", scheme)
	}
	for _, obj := range objects {
		if obj.GetKind() == "Ingress" {
			t.Errorf("Ingress %s would route plain HTTP to Rekor", obj.GetName())
		}
	}

	// The certificate has to carry the name clients use.
	cert := find(t, manifestObjects(t, "dependencies/sigstore/rekor/tls.yaml"), "Certificate", "rekor-server-tls")
	names, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames")
	host, isHTTPS := strings.CutPrefix(rekorURL, "https://")
	if !isHTTPS || !slices.Contains(names, host) {
		t.Errorf("the certificate is for %v, which does not include %s", names, rekorURL)
	}
	if issuer, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name"); issuer != caIssuer {
		t.Errorf("the certificate is issued by %q, want %s", issuer, caIssuer)
	}
}

func filter(args []any, prefix string) []any {
	var out []any
	for _, arg := range args {
		if s, ok := arg.(string); ok && strings.HasPrefix(s, prefix) {
			out = append(out, arg)
		}
	}
	return out
}

// The CA manifest and the installer have to agree on the names of the Secret
// and the issuer, since the installer reads one and waits for the other.
func TestCertificateAuthorityManifest(t *testing.T) {
	objects := manifestObjects(t, "dependencies/cert-manager/ca/ca.yaml")
	ca := find(t, objects, "Certificate", "supply-chain-ca")
	if ca.GetNamespace() != certManagerNamespace {
		t.Errorf("the CA is in %s; a ClusterIssuer reads its Secret from %s", ca.GetNamespace(), certManagerNamespace)
	}
	if secret, _, _ := unstructured.NestedString(ca.Object, "spec", "secretName"); secret != caSecret {
		t.Errorf("the CA's Secret is %q, want %s", secret, caSecret)
	}
	if isCA, _, _ := unstructured.NestedBool(ca.Object, "spec", "isCA"); !isCA {
		t.Error("the CA certificate is not marked as a CA")
	}
	issuer := find(t, objects, "ClusterIssuer", caIssuer)
	if secret, _, _ := unstructured.NestedString(issuer.Object, "spec", "ca", "secretName"); secret != caSecret {
		t.Errorf("the issuer signs with %q, want %s", secret, caSecret)
	}
}

// A workload is given the CA in addition to the public CAs of its image, and
// giving it twice changes nothing.
func TestAddCATrust(t *testing.T) {
	deployment := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{"name": "controller"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{
				"name": "controller",
				"env":  []any{map[string]any{"name": "EXISTING", "value": "kept"}},
			}},
		}}},
	}}
	for range 2 {
		if err := addCATrust(deployment); err != nil {
			t.Fatal(err)
		}
	}
	spec, _, _ := unstructured.NestedMap(deployment.Object, "spec", "template", "spec")
	want := map[string]any{
		"volumes": []any{map[string]any{"name": "supply-chain-ca", "configMap": map[string]any{"name": caConfigMap}}},
		"containers": []any{map[string]any{
			"name": "controller",
			"env": []any{
				map[string]any{"name": "EXISTING", "value": "kept"},
				map[string]any{"name": "SSL_CERT_DIR", "value": "/etc/supply-chain-ca:/etc/ssl/certs"},
			},
			"volumeMounts": []any{map[string]any{"name": "supply-chain-ca", "mountPath": caMountDir, "readOnly": true}},
		}},
	}
	if !reflect.DeepEqual(spec, want) {
		t.Errorf("pod spec = %v\nwant %v", spec, want)
	}
}

// Chains records what it signs in Rekor, at the address the certificate is for.
func TestChainsReachesRekorOverTLS(t *testing.T) {
	config := chainsConfig(Options{SigningIdentity: IdentitySPIFFE})
	for _, key := range []string{"transparency.url", "signers.x509.rekor.address"} {
		if config[key] != rekorURL {
			t.Errorf("%s = %v, want %s", key, config[key], rekorURL)
		}
	}
}
