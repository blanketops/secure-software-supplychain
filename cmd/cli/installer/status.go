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
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/blanketops/secure-software-supplychain/pkg/secrets/store"
)

// workload is one Deployment, StatefulSet or DaemonSet the stack runs.
type workload struct {
	Kind, Namespace, Name, Label string
}

// statusGroup is a part of the stack as the status report shows it.
type statusGroup struct {
	Title string
	// Optional is why the group may be absent from a working install. An
	// absent group without it is reported as missing.
	Optional  string
	Workloads []workload
}

// statusGroups is everything `supplychain install` sets up, in the order it
// is installed. Each step of the installer that runs something has its
// workloads here.
var statusGroups = []statusGroup{
	{Title: "Certificates", Workloads: []workload{
		{kindDeployment, certManagerNamespace, "cert-manager", "cert-manager"},
		{kindDeployment, certManagerNamespace, "cert-manager-webhook", "cert-manager webhook"},
		{kindDeployment, certManagerNamespace, "cert-manager-cainjector", "cert-manager CA injector"},
	}},
	{Title: "Tekton", Workloads: []workload{
		{kindDeployment, "tekton-pipelines", "tekton-pipelines-controller", "Pipelines"},
		{kindDeployment, "tekton-pipelines", "tekton-pipelines-webhook", "Pipelines webhook"},
		{kindDeployment, "tekton-pipelines", "tekton-events-controller", "Pipelines events"},
		{kindDeployment, "tekton-pipelines-resolvers", "tekton-pipelines-remote-resolvers", "Pipelines resolvers"},
		{kindDeployment, "tekton-pipelines", "tekton-triggers-controller", "Triggers"},
		{kindDeployment, "tekton-pipelines", "tekton-triggers-webhook", "Triggers webhook"},
		{kindDeployment, "tekton-pipelines", "tekton-triggers-core-interceptors", "Interceptors"},
		{kindDeployment, "tekton-chains", "tekton-chains-controller", "Chains"},
		{kindDeployment, "tekton-pipelines", "tekton-dashboard", "Dashboard"},
		{kindDeployment, "tekton-pipelines", "tekton-results-api", "Results API"},
		{kindDeployment, "tekton-pipelines", "tekton-results-watcher", "Results watcher"},
		{kindDeployment, "tekton-pipelines", "tekton-results-retention-policy-agent", "Results retention"},
		{"StatefulSet", "tekton-pipelines", "tekton-results-postgres", "Results database"},
		{kindDeployment, "tekton-pipelines", "tekton-pruner-controller", "Pruner"},
		{kindDeployment, "tekton-pipelines", "tekton-pruner-webhook", "Pruner webhook"},
	}},
	{Title: "SPIRE", Optional: "only with --signing-identity spiffe", Workloads: []workload{
		{"StatefulSet", spireNamespace, "spire-server", "Server"},
		{"DaemonSet", spireNamespace, "spire-agent", "Agent"},
		{"DaemonSet", spireNamespace, "spire-spiffe-csi-driver", "CSI driver"},
		{kindDeployment, spireNamespace, "spire-spiffe-oidc-discovery-provider", "OIDC discovery"},
	}},
	{Title: "Sigstore", Workloads: []workload{
		{kindDeployment, "fulcio-system", "fulcio-server", "Fulcio"},
		{kindDeployment, "ctlog-system", "ctlog", "CT log"},
		{kindDeployment, "rekor-system", "rekor-server", "Rekor"},
		{kindDeployment, "rekor-system", "rekor-redis", "Rekor search index"},
		{kindDeployment, "trillian-system", "trillian-logserver", "Trillian log server"},
		{kindDeployment, "trillian-system", "trillian-logsigner", "Trillian log signer"},
		{kindDeployment, "trillian-system", "trillian-mysql", "Trillian database"},
		{kindDeployment, "cosign-system", "policy-controller-webhook", "Policy controller"},
	}},
	{Title: "Ingress", Workloads: []workload{
		{kindDeployment, "metallb-system", "controller", "MetalLB"},
		{kindDeployment, "ingress-nginx", "ingress-nginx-controller", "NGINX ingress"},
	}},
	{Title: "Credentials", Optional: "not with --vault-addr or --external-secret-store", Workloads: []workload{
		{"StatefulSet", vaultNamespace, vaultSTS, "Vault"},
	}},
	{Title: "Code analysis", Workloads: []workload{
		{"StatefulSet", "default", "sonarqube-sonarqube", "SonarQube"},
		{"StatefulSet", "default", "sonarqube-postgresql", "SonarQube database"},
	}},
}

// Kubernetes kinds the installer applies and asserts on.
const (
	kindDeployment = "Deployment"
	kindJob        = "Job"
)

var workloadGVRs = map[string]schema.GroupVersionResource{
	kindDeployment: {Group: "apps", Version: "v1", Resource: "deployments"},
	"StatefulSet":  {Group: "apps", Version: "v1", Resource: "statefulsets"},
	"DaemonSet":    {Group: "apps", Version: "v1", Resource: "daemonsets"},
}

var (
	certificateGVR = schema.GroupVersionResource{Group: "cert-manager.io", Version: "v1", Resource: "certificates"}
	secretStoreGVR = schema.GroupVersionResource{
		Group: "external-secrets.io", Version: "v1", Resource: "clustersecretstores",
	}
)

// Status reports on everything `supplychain install` sets up: each workload,
// the certificate authority and the certificates it has issued, and the
// secret store. It returns an error when something that should be there is
// missing or not ready, so that it can be used in scripts.
func (i *Installer) Status(ctx context.Context) error {
	fmt.Println("Secure software supply chain dependencies")
	problems := 0
	for _, group := range statusGroups {
		lines, absent, notReady := i.groupStatus(ctx, group)
		fmt.Printf("\n%s\n", group.Title)
		if absent == len(group.Workloads) && group.Optional != "" {
			fmt.Printf("  - not installed (%s)\n", group.Optional)
		} else {
			for _, line := range lines {
				fmt.Println(line)
			}
			problems += absent + notReady
		}
		switch group.Title {
		case "Certificates":
			problems += i.certificateStatus(ctx)
		case "SPIRE":
			i.tornjakStatus(ctx, absent == len(group.Workloads))
		case "Credentials":
			problems += i.secretStoreStatus(ctx)
		}
	}
	fmt.Println()
	if problems > 0 {
		return fmt.Errorf("%d of the dependencies are missing or not ready", problems)
	}
	fmt.Println("Everything is running.")
	return nil
}

// groupStatus renders one line per workload and counts those that are absent
// and those that are there but not ready.
func (i *Installer) groupStatus(ctx context.Context, group statusGroup) (lines []string, absent, notReady int) {
	for _, w := range group.Workloads {
		obj, err := i.dynamic.Resource(workloadGVRs[w.Kind]).Namespace(w.Namespace).Get(ctx, w.Name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			absent++
			lines = append(lines, fmt.Sprintf("  ✗ %-38s not installed", w.Label))
		case err != nil:
			notReady++
			lines = append(lines, fmt.Sprintf("  ✗ %-38s %v", w.Label, err))
		default:
			ready, want := readiness(obj)
			if want > 0 && ready >= want {
				lines = append(lines, fmt.Sprintf("  ✓ %-38s running (%d/%d)", w.Label, ready, want))
			} else {
				notReady++
				lines = append(lines, fmt.Sprintf("  … %-38s starting (%d/%d)", w.Label, ready, want))
			}
		}
	}
	return lines, absent, notReady
}

// readiness is how many pods of a workload are ready and how many it wants.
// A Vault that is sealed is not ready, which is what the count then shows.
func readiness(obj *unstructured.Unstructured) (ready, want int64) {
	if obj.GetKind() == "DaemonSet" {
		ready, _, _ = unstructured.NestedInt64(obj.Object, "status", "numberReady")
		want, _, _ = unstructured.NestedInt64(obj.Object, "status", "desiredNumberScheduled")
		return ready, want
	}
	ready, _, _ = unstructured.NestedInt64(obj.Object, "status", "readyReplicas")
	want, _, _ = unstructured.NestedInt64(obj.Object, "spec", "replicas")
	return ready, want
}

// certificateStatus reports the certificate authority and every certificate
// issued from it, with the day each one is renewed. It returns the number
// that are not ready.
func (i *Installer) certificateStatus(ctx context.Context) int {
	issuer, err := i.dynamic.Resource(clusterIssuerGVR).Get(ctx, caIssuer, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("  ✗ %-38s %s\n", "Certificate authority", absentOr(err))
		return 1
	}
	problems := 0
	if conditionTrue(issuer) {
		fmt.Printf("  ✓ %-38s ready (ClusterIssuer %s)\n", "Certificate authority", caIssuer)
	} else {
		problems++
		fmt.Printf("  … %-38s not ready (ClusterIssuer %s)\n", "Certificate authority", caIssuer)
	}

	certificates, err := i.dynamic.Resource(certificateGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return problems
	}
	for _, cert := range certificates.Items {
		if name, _, _ := unstructured.NestedString(cert.Object, "spec", "issuerRef", "name"); name != caIssuer {
			continue
		}
		label := "TLS " + cert.GetNamespace() + "/" + cert.GetName()
		if !conditionTrue(&cert) {
			problems++
			fmt.Printf("  … %-38s not issued\n", label)
			continue
		}
		renewal, _, _ := unstructured.NestedString(cert.Object, "status", "renewalTime")
		if at, err := time.Parse(time.RFC3339, renewal); err == nil {
			renewal = at.Format("2006-01-02")
		}
		fmt.Printf("  ✓ %-38s issued, renews %s\n", label, renewal)
	}
	return problems
}

// secretStoreStatus reports whether External Secrets can log in to the store
// the builds' credentials are read through, and how. It returns 1 when it
// cannot.
func (i *Installer) secretStoreStatus(ctx context.Context) int {
	const label = "Secret store"
	obj, err := i.dynamic.Resource(secretStoreGVR).Get(ctx, store.Name, metav1.GetOptions{})
	if err != nil {
		fmt.Printf("  ✗ %-38s %s\n", label, absentOr(err))
		return 1
	}
	login := "a provider of your own"
	if auth, found, _ := unstructured.NestedMap(obj.Object, "spec", "provider", "vault", "auth"); found {
		switch {
		case auth["kubernetes"] != nil:
			login = "Vault, as a ServiceAccount"
		case hasNested(auth, "jwt", "secretRef"):
			login = "Vault, with a SPIFFE identity"
		case auth["jwt"] != nil:
			login = "Vault, with a ServiceAccount token"
		}
	}
	if !conditionTrue(obj) {
		fmt.Printf("  … %-38s cannot log in (%s)\n", label, login)
		return 1
	}
	fmt.Printf("  ✓ %-38s logged in (%s)\n", label, login)
	return 0
}

// tornjakStatus reports the Tornjak UI, which runs as sidecars in the
// spire-server pod. It is informational only — it does not add to the problem
// count, because the "Server" workload line already gates that pod — and it is
// silent when SPIRE is not installed (spireAbsent), since Tornjak only exists
// under --signing-identity spiffe.
func (i *Installer) tornjakStatus(ctx context.Context, spireAbsent bool) {
	if spireAbsent {
		return
	}
	pods, err := i.dynamic.Resource(podGVR).Namespace(spireNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=server,app.kubernetes.io/instance=spire",
	})
	if err != nil || len(pods.Items) == 0 {
		return
	}
	// Both sidecars must be ready for the UI to serve: the frontend calls the
	// backend, and the backend reaches the SPIRE server socket.
	wanted := map[string]bool{"tornjak-backend": false, "tornjak-frontend": false}
	statuses, _, _ := unstructured.NestedSlice(pods.Items[0].Object, "status", "containerStatuses")
	for _, s := range statuses {
		cs, _ := s.(map[string]any)
		name, _ := cs["name"].(string)
		if _, ok := wanted[name]; ok {
			ready, _ := cs["ready"].(bool)
			wanted[name] = ready
		}
	}
	if wanted["tornjak-backend"] && wanted["tornjak-frontend"] {
		fmt.Printf("  ✓ %-38s running (port-forward svc/tornjak 3000:3000 10000:10000)\n", "Tornjak UI")
	} else {
		fmt.Printf("  … %-38s starting\n", "Tornjak UI")
	}
}

// hasNested reports whether a nested field exists.
func hasNested(obj map[string]any, fields ...string) bool {
	_, found, _ := unstructured.NestedFieldNoCopy(obj, fields...)
	return found
}

// absentOr says "not installed" for something that is not there, including a
// kind the cluster does not know, and the error otherwise.
func absentOr(err error) string {
	if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) ||
		strings.Contains(err.Error(), "could not find the requested resource") {
		return "not installed"
	}
	return err.Error()
}
