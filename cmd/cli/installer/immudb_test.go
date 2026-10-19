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
	"context"
	"reflect"
	"strings"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"

	manifests "github.com/blanketops/secure-software-supplychain"

	"github.com/blanketops/secure-software-supplychain/pkg/secrets/store"
	"github.com/blanketops/secure-software-supplychain/pkg/signing"
)

// immudb is one ledger: a StatefulSet of one, its data on a volume of its
// own, its admin password from Vault, reachable only from the operator.
func TestImmudbManifests(t *testing.T) {
	objects := manifestObjects(t, "dependencies/immudb/immudb.yaml")
	for _, obj := range objects {
		if obj.GetKind() == "Ingress" {
			t.Errorf("immudb has an Ingress %s; it is reached inside the cluster only", obj.GetName())
		}
		if obj.GetKind() != "Namespace" && obj.GetNamespace() != immudbNamespace {
			t.Errorf("%s %s is in namespace %q; want %s", obj.GetKind(), obj.GetName(), obj.GetNamespace(), immudbNamespace)
		}
	}
	find(t, objects, "Namespace", immudbNamespace)

	sts := find(t, objects, "StatefulSet", "immudb")
	if replicas := number(sts.Object["spec"].(map[string]any)["replicas"]); replicas != 1 {
		t.Errorf("immudb has %d replicas; more would be separate ledgers", replicas)
	}
	containers, _, _ := unstructured.NestedSlice(sts.Object, "spec", "template", "spec", "containers")
	// A Service named immudb makes Kubernetes inject IMMUDB_PORT=tcp://...,
	// which immudb reads as its port: it then listens on port 0.
	if links, found, _ := unstructured.NestedBool(sts.Object, "spec", "template", "spec", "enableServiceLinks"); !found || links {
		t.Error("immudb's pod has service links: IMMUDB_PORT would be tcp://<service>:3322 and immudb would listen on port 0")
	}
	server := containers[0].(map[string]any)
	if image := server["image"].(string); !strings.Contains(image, "@sha256:") {
		t.Errorf("immudb image %s is not pinned by digest", image)
	}
	env := map[string]any{}
	for _, e := range server["env"].([]any) {
		env[e.(map[string]any)["name"].(string)] = e.(map[string]any)
	}
	password, _ := env["IMMUDB_ADMIN_PASSWORD"].(map[string]any)
	if ref, _, _ := unstructured.NestedMap(password, "valueFrom", "secretKeyRef"); ref["name"] != immudbAdminSecret {
		t.Errorf("IMMUDB_ADMIN_PASSWORD comes from %v; want Secret %s", ref, immudbAdminSecret)
	}
	for name, want := range map[string]string{"IMMUDB_DEVMODE": "false", "IMMUDB_PGSQL_SERVER": "false"} {
		if got, _ := env[name].(map[string]any); got["value"] != want {
			t.Errorf("%s = %v; want %s", name, got["value"], want)
		}
	}
	claims, _, _ := unstructured.NestedSlice(sts.Object, "spec", "volumeClaimTemplates")
	mounts, _ := server["volumeMounts"].([]any)
	if len(claims) != 1 || len(mounts) != 1 ||
		mounts[0].(map[string]any)["name"] != claims[0].(map[string]any)["metadata"].(map[string]any)["name"] ||
		mounts[0].(map[string]any)["mountPath"] != "/var/lib/immudb" {
		t.Errorf("immudb's data is not on its volume claim: claims %v, mounts %v", claims, mounts)
	}

	es := find(t, objects, "ExternalSecret", immudbAdminSecret)
	data, _, _ := unstructured.NestedSlice(es.Object, "spec", "data")
	if len(data) != 1 || !reflect.DeepEqual(data[0].(map[string]any)["remoteRef"], store.RemoteRef(store.ImmudbPassword)) ||
		data[0].(map[string]any)["secretKey"] != "IMMUDB_ADMIN_PASSWORD" {
		t.Errorf("ExternalSecret %s data = %v; want IMMUDB_ADMIN_PASSWORD from %s", immudbAdminSecret, data, store.ImmudbPassword)
	}
	if ref, _, _ := unstructured.NestedMap(es.Object, "spec", "secretStoreRef"); !reflect.DeepEqual(ref, store.Ref()) {
		t.Errorf("ExternalSecret %s reads from %v; want %v", immudbAdminSecret, ref, store.Ref())
	}

	svc := find(t, objects, "Service", "immudb")
	ports, _, _ := unstructured.NestedSlice(svc.Object, "spec", "ports")
	var grpc bool
	for _, p := range ports {
		grpc = grpc || number(p.(map[string]any)["port"]) == 3322
	}
	if !grpc {
		t.Errorf("Service immudb does not serve 3322: %v", ports)
	}

	// Only the operator's namespace may connect, and only to the gRPC port.
	np := find(t, objects, "NetworkPolicy", "immudb")
	ingress, _, _ := unstructured.NestedSlice(np.Object, "spec", "ingress")
	if len(ingress) != 1 {
		t.Fatalf("NetworkPolicy immudb has %d ingress rules; want 1", len(ingress))
	}
	rule := ingress[0].(map[string]any)
	from := rule["from"].([]any)[0].(map[string]any)
	if ns, _, _ := unstructured.NestedString(from, "namespaceSelector", "matchLabels", "kubernetes.io/metadata.name"); ns != operatorNamespace {
		t.Errorf("immudb admits namespace %q; want only %s", ns, operatorNamespace)
	}
	if p := rule["ports"].([]any); len(p) != 1 || number(p[0].(map[string]any)["port"]) != 3322 {
		t.Errorf("immudb admits ports %v; want only 3322", p)
	}
}

// number reads a number of a decoded manifest, which JSON decoding makes a
// float64.
func number(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return -1
}

// immudb reads its admin password from Vault through the secret store, so it
// is installed after it.
func TestImmudbIsInstalledAfterTheSecretStore(t *testing.T) {
	at := map[string]int{}
	for i, s := range installOrder {
		at[s.Name] = i
	}
	immudb, ok := at["immudb"]
	if !ok {
		t.Fatal("no immudb step")
	}
	if immudb < at["Secret Store"] {
		t.Errorf("immudb (step %d) comes before the Secret Store (step %d)", immudb, at["Secret Store"])
	}
}

// The trust anchors are written where the operator copies them from, and not
// to default: nothing runs there.
func TestTrustAnchorsAreNotWrittenToDefault(t *testing.T) {
	if len(sigstoreRootsNamespaces) != 1 || sigstoreRootsNamespaces[0] != signing.RootsSourceNamespace {
		t.Fatalf("trust anchors are written to %v; want only %s", sigstoreRootsNamespaces, signing.RootsSourceNamespace)
	}
}

// SonarQube, its database and its route are in sonarqube-system, and it
// finds its database there.
func TestSonarQubeIsInItsOwnNamespace(t *testing.T) {
	var objects []*unstructured.Unstructured
	for _, file := range []string{"00-namespace.yaml", "postgresql.yaml", "release.yaml", "ingress.yaml"} {
		objects = append(objects, manifestObjects(t, "dependencies/sonarqube/"+file)...)
	}
	find(t, objects, "Namespace", sonarNamespace)
	find(t, objects, "Ingress", "sonarqube")
	for _, obj := range objects {
		if obj.GetKind() != "Namespace" && obj.GetNamespace() != sonarNamespace {
			t.Errorf("%s %s is in namespace %q; want %s", obj.GetKind(), obj.GetName(), obj.GetNamespace(), sonarNamespace)
		}
	}
	data, err := manifests.Dependencies.ReadFile("dependencies/sonarqube/release.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "sonarqube-postgresql."+sonarNamespace+".svc.cluster.local") ||
		strings.Contains(string(data), ".default.svc") {
		t.Error("SonarQube's JDBC URL does not point at its database in " + sonarNamespace)
	}
	if sonarNamespace != "sonarqube-system" {
		t.Errorf("sonarNamespace = %s; want sonarqube-system", sonarNamespace)
	}
}

// SonarQube's password Secret is made before its manifests are applied, in a
// namespace that is not default any more: the hook brings the namespace. The
// fake refuses a Secret in a namespace that does not exist, as the API
// server does.
func TestSonarQubePasswordComesWithItsNamespace(t *testing.T) {
	nsGVR := schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	client.PrependReactor("create", "secrets", func(action clienttesting.Action) (bool, runtime.Object, error) {
		ns := action.GetNamespace()
		if _, err := client.Tracker().Get(nsGVR, "", ns); err != nil {
			return true, nil, apierrors.NewNotFound(nsGVR.GroupResource(), ns)
		}
		return false, nil, nil
	})
	i := &Installer{dynamic: client}
	if err := i.ensureSonarQubeDatabasePassword(context.Background()); err != nil {
		t.Fatalf("ensureSonarQubeDatabasePassword: %v", err)
	}
	if _, err := client.Resource(secretGVR).Namespace(sonarNamespace).Get(context.Background(), sonarDatabaseSecret, metav1.GetOptions{}); err != nil {
		t.Fatalf("no Secret %s/%s: %v", sonarNamespace, sonarDatabaseSecret, err)
	}
}
