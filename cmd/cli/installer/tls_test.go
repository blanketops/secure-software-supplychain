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
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/yaml"

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
	decoder := utilyaml.NewYAMLOrJSONDecoder(strings.NewReader(string(data)), 4096)
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

// Rekor, Fulcio and the CT log only speak plain HTTP in a form that is safe
// to expose. None of them may be reachable that way from outside its pod:
// the server listens on loopback, the Service offers the TLS port alone, and
// the charts' plain-HTTP Ingresses are gone.
func TestSigstoreServicesAreOnlyReachableOverTLS(t *testing.T) {
	for _, tc := range []struct {
		name, dir, server string
		loopback          []string // the arguments that bind the server
		url               string   // what clients are told to use
	}{
		{"rekor-server", "dependencies/sigstore/rekor", "rekor-server",
			[]string{"--rekor_server.address=127.0.0.1"}, rekorURL},
		{"fulcio-server", "dependencies/sigstore/fulcio", "fulcio-server",
			[]string{"--host=127.0.0.1", "--grpc-host=127.0.0.1"}, fulcioURL},
		{"ctlog", "dependencies/sigstore/fulcio", "ctlog",
			[]string{"--http_endpoint=127.0.0.1:6962"}, ctLogURL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			objects := manifestObjects(t, tc.dir+"/release.yaml")

			ports, _, _ := unstructured.NestedSlice(find(t, objects, "Service", tc.name).Object, "spec", "ports")
			for _, p := range ports {
				port := p.(map[string]any)
				if fmt.Sprint(port["targetPort"]) == fmt.Sprint(port["port"]) { // metrics
					continue
				}
				if fmt.Sprint(port["port"]) != "443" || fmt.Sprint(port["targetPort"]) != "8443" {
					t.Errorf("the Service exposes %v; want only 443 to the TLS container", port)
				}
			}

			containers, _, _ := unstructured.NestedSlice(
				find(t, objects, "Deployment", tc.name).Object, "spec", "template", "spec", "containers")
			var server, proxy map[string]any
			for _, c := range containers {
				container := c.(map[string]any)
				switch container["name"] {
				case tc.server:
					server = container
				case "tls":
					proxy = container
				}
			}
			if server == nil || proxy == nil {
				t.Fatalf("the Deployment needs the %s and tls containers", tc.server)
			}
			args, _ := server["args"].([]any)
			for _, want := range tc.loopback {
				if !slices.Contains(args, any(want)) {
					t.Errorf("the server must listen on loopback only: %s is not among %v", want, args)
				}
			}
			for _, arg := range args {
				if strings.Contains(fmt.Sprint(arg), "0.0.0.0") && !strings.Contains(fmt.Sprint(arg), "metrics") {
					t.Errorf("%v listens on every address", arg)
				}
			}
			if _, probed := server["readinessProbe"]; probed {
				t.Error("the kubelet cannot probe a loopback listener; the probe belongs on the tls container")
			}
			if scheme, _, _ := unstructured.NestedString(proxy, "readinessProbe", "httpGet", "scheme"); scheme != "HTTPS" {
				t.Errorf("the tls container's readiness probe uses %q, want HTTPS", scheme)
			}
			for _, obj := range objects {
				if obj.GetKind() == "Ingress" {
					t.Errorf("Ingress %s would route plain HTTP to the service", obj.GetName())
				}
			}

			// The certificate has to carry the name clients are given.
			cert := find(t, manifestObjects(t, tc.dir+"/tls.yaml"), "Certificate", tc.name+"-tls")
			names, _, _ := unstructured.NestedStringSlice(cert.Object, "spec", "dnsNames")
			host, isHTTPS := strings.CutPrefix(tc.url, "https://")
			host, _, _ = strings.Cut(host, "/")
			if !isHTTPS || !slices.Contains(names, host) {
				t.Errorf("the certificate is for %v, which does not include %s", names, tc.url)
			}
			if issuer, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name"); issuer != caIssuer {
				t.Errorf("the certificate is issued by %q, want %s", issuer, caIssuer)
			}
		})
	}
}

// Fulcio submits every certificate it issues to the CT log, and the Job that
// configures the CT log asks Fulcio for its root. Both connections are TLS,
// verified against the CA.
func TestFulcioAndTheCTLogReachEachOtherOverTLS(t *testing.T) {
	objects := manifestObjects(t, "dependencies/sigstore/fulcio/release.yaml")
	text := func(kind, name string) string {
		data, err := yaml.Marshal(find(t, objects, kind, name).Object)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	fulcio := text("Deployment", "fulcio-server")
	for _, want := range []string{"--ct-log-url=" + ctLogURL, "--ct-log.tls-ca-cert=" + caMountDir + "/" + caKey} {
		if !strings.Contains(fulcio, want) {
			t.Errorf("fulcio-server is not started with %s", want)
		}
	}
	job := text("Job", "fulcio-ctlog-createctconfig")
	for _, want := range []string{"--fulcio-url=https://fulcio-server.fulcio-system.svc", "SSL_CERT_DIR", caMountDir} {
		if !strings.Contains(job, want) {
			t.Errorf("the CT log's configuration Job does not have %s", want)
		}
	}
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

// Chains gets its certificate from Fulcio and records what it signs in Rekor,
// at the addresses their certificates are for.
func TestChainsReachesSigstoreOverTLS(t *testing.T) {
	config := chainsConfig(Options{SigningIdentity: IdentitySPIFFE})
	for key, want := range map[string]string{
		"transparency.url":            rekorURL,
		"signers.x509.rekor.address":  rekorURL,
		"signers.x509.fulcio.address": fulcioURL,
	} {
		if config[key] != want {
			t.Errorf("%s = %v, want %s", key, config[key], want)
		}
	}
}
