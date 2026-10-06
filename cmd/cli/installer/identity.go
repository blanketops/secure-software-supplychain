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
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// Signing identities. With "kubernetes", workloads prove who they are to
// Fulcio with a projected ServiceAccount token. With "spiffe", SPIRE is
// installed and they use a JWT-SVID instead, so certificates carry
// spiffe://<trust-domain>/ns/<namespace>/sa/<serviceaccount>.
const (
	IdentityKubernetes = "kubernetes"
	IdentitySPIFFE     = "spiffe"

	// DefaultTrustDomain is the SPIFFE trust domain when none is given.
	DefaultTrustDomain = "blanketops.dev"

	// trustDomainPlaceholder is the trust domain the SPIRE manifests under
	// dependencies/spire were rendered with. It is replaced at apply time.
	trustDomainPlaceholder = "trust-domain.placeholder.invalid"

	spireNamespace = "spire-server"

	// spireOIDCIssuer is where SPIRE serves OIDC discovery for its JWT-SVIDs,
	// and the issuer written into them. The SPIRE manifests were rendered with
	// this value; Fulcio and Chains must be given the same one.
	spireOIDCIssuer = "http://spire-spiffe-oidc-discovery-provider.spire-server.svc.cluster.local"

	// SPIFFE Workload API as the SPIFFE CSI driver exposes it in a pod.
	spiffeCSIDriver   = "csi.spiffe.io"
	spiffeSocketDir   = "/spiffe-workload-api"
	spiffeSocketValue = spiffeSocketDir + "/spire-agent.sock"
)

var trustDomainPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// Options configures an install.
type Options struct {
	// WebhookHost is the public hostname GitHub delivers webhooks to.
	WebhookHost string
	// UIHost is the hostname the Tekton Dashboard and SonarQube are served on.
	UIHost string
	// SigningIdentity is IdentityKubernetes or IdentitySPIFFE.
	SigningIdentity string
	// TrustDomain is the SPIFFE trust domain. Only used with IdentitySPIFFE.
	TrustDomain string
	// FromStep resumes an interrupted install at the named step instead of
	// starting again from the first one.
	FromStep string
}

func (o *Options) defaultAndValidate() error {
	if o.UIHost == "" {
		o.UIHost = DefaultUIHost
	}
	if o.SigningIdentity == "" {
		o.SigningIdentity = IdentityKubernetes
	}
	if o.TrustDomain == "" {
		o.TrustDomain = DefaultTrustDomain
	}
	if o.SigningIdentity != IdentityKubernetes && o.SigningIdentity != IdentitySPIFFE {
		return fmt.Errorf("signing identity %q: must be %q or %q", o.SigningIdentity, IdentityKubernetes, IdentitySPIFFE)
	}
	if !trustDomainPattern.MatchString(o.TrustDomain) {
		return fmt.Errorf("trust domain %q: must be lower-case letters, digits, dots, dashes and underscores", o.TrustDomain)
	}
	return nil
}

func (i *Installer) spiffe() bool { return i.opts.SigningIdentity == IdentitySPIFFE }

// fulcioConfig is Fulcio's issuer configuration. The Kubernetes issuer is
// always accepted: the operator itself obtains a certificate with a
// ServiceAccount token before each build. With SPIFFE, SPIRE's issuer is
// accepted too, for identities in the trust domain.
func fulcioConfig(opts Options) (string, error) {
	type issuer struct {
		IssuerURL         string `json:"IssuerURL"`
		ClientID          string `json:"ClientID"`
		Type              string `json:"Type"`
		SPIFFETrustDomain string `json:"SPIFFETrustDomain,omitempty"`
	}
	// One issuer, the one the cluster signs with. Fulcio certifies whatever
	// an issuer it trusts vouches for. Under SPIFFE an identity exists only
	// for a ServiceAccount that passed its authorization checks; if Fulcio
	// accepted Kubernetes tokens as well, any pod could present its own
	// ServiceAccount token and be issued a certificate without them.
	issuers := map[string]issuer{
		signerOIDCIssuer: {IssuerURL: signerOIDCIssuer, ClientID: "sigstore", Type: "kubernetes"},
	}
	if opts.SigningIdentity == IdentitySPIFFE {
		issuers = map[string]issuer{
			spireOIDCIssuer: {
				IssuerURL: spireOIDCIssuer, ClientID: "sigstore", Type: "spiffe", SPIFFETrustDomain: opts.TrustDomain,
			},
		}
	}
	data, err := json.MarshalIndent(map[string]any{"OIDCIssuers": issuers, "MetaIssuers": map[string]any{}}, "", "  ")
	return string(data), err
}

var (
	configMapGVR   = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
	deploymentGVR  = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}
	statefulSetGVR = schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}
)

// configureFulcioIssuers writes Fulcio's issuer configuration and restarts it,
// since Fulcio reads the file once at startup.
func (i *Installer) configureFulcioIssuers(ctx context.Context) error {
	config, err := fulcioConfig(i.opts)
	if err != nil {
		return err
	}
	cms := i.dynamic.Resource(configMapGVR).Namespace("fulcio-system")
	cm, err := cms.Get(ctx, "fulcio-server-config", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading Fulcio config: %w", err)
	}
	if err := unstructured.SetNestedField(cm.Object, config, "data", "config.json"); err != nil {
		return err
	}
	if _, err := cms.Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("writing Fulcio config: %w", err)
	}
	return i.restartDeployment(ctx, "fulcio-system", "fulcio-server")
}

// restartDeployment rolls a Deployment the way `kubectl rollout restart` does.
func (i *Installer) restartDeployment(ctx context.Context, namespace, name string) error {
	deployments := i.dynamic.Resource(deploymentGVR).Namespace(namespace)
	deployment, err := deployments.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := unstructured.SetNestedField(deployment.Object, time.Now().UTC().Format(time.RFC3339),
		"spec", "template", "metadata", "annotations", "blanketops.dev/restarted-at"); err != nil {
		return err
	}
	_, err = deployments.Update(ctx, deployment, metav1.UpdateOptions{})
	return err
}

// giveChainsSPIFFEIdentity mounts the SPIFFE Workload API socket into the
// Chains controller. It is done here rather than in the vendored manifest
// because a pod with a CSI volume cannot start when the driver is not
// installed, and SPIRE is only installed for the SPIFFE identity.
func (i *Installer) giveChainsSPIFFEIdentity(ctx context.Context) error {
	deployments := i.dynamic.Resource(deploymentGVR).Namespace("tekton-chains")
	deployment, err := deployments.Get(ctx, "tekton-chains-controller", metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := addSPIFFESocket(deployment); err != nil {
		return err
	}
	_, err = deployments.Update(ctx, deployment, metav1.UpdateOptions{})
	return err
}

// addSPIFFESocket adds the Workload API volume, its mount and the socket
// environment variable to the first container of a Deployment. It is safe to
// apply twice.
func addSPIFFESocket(deployment *unstructured.Unstructured) error {
	const volumeName = "spiffe-workload-api"
	podSpec := []string{"spec", "template", "spec"}

	volumes, _, _ := unstructured.NestedSlice(deployment.Object, append(podSpec, "volumes")...)
	if !hasNamed(volumes, volumeName) {
		volumes = append(volumes, map[string]any{
			"name": volumeName,
			"csi":  map[string]any{"driver": spiffeCSIDriver, "readOnly": true},
		})
	}
	if err := unstructured.SetNestedSlice(deployment.Object, volumes, append(podSpec, "volumes")...); err != nil {
		return err
	}

	containers, _, _ := unstructured.NestedSlice(deployment.Object, append(podSpec, "containers")...)
	if len(containers) == 0 {
		return fmt.Errorf("deployment %s has no containers", deployment.GetName())
	}
	container, ok := containers[0].(map[string]any)
	if !ok {
		return fmt.Errorf("deployment %s: unexpected container shape", deployment.GetName())
	}
	mounts, _ := container["volumeMounts"].([]any)
	if !hasNamed(mounts, volumeName) {
		mounts = append(mounts, map[string]any{"name": volumeName, "mountPath": spiffeSocketDir, "readOnly": true})
	}
	container["volumeMounts"] = mounts
	env, _ := container["env"].([]any)
	if !hasNamed(env, "SPIFFE_ENDPOINT_SOCKET") {
		env = append(env, map[string]any{"name": "SPIFFE_ENDPOINT_SOCKET", "value": spiffeSocketValue})
	}
	container["env"] = env
	containers[0] = container
	return unstructured.SetNestedSlice(deployment.Object, containers, append(podSpec, "containers")...)
}

func hasNamed(items []any, name string) bool {
	for _, item := range items {
		if m, ok := item.(map[string]any); ok && m["name"] == name {
			return true
		}
	}
	return false
}

// applyTektonSpireConfig records the trust domain in Tekton's SPIRE
// configuration, which is where the operator reads it from.
func (i *Installer) applyTektonSpireConfig(ctx context.Context) error {
	cms := i.dynamic.Resource(configMapGVR).Namespace("tekton-pipelines")
	cm, err := cms.Get(ctx, "config-spire", metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("reading Tekton SPIRE config: %w", err)
	}
	for key, value := range map[string]string{
		"spire-trust-domain": i.opts.TrustDomain,
		"spire-socket-path":  spiffeSocketValue,
		"spire-server-addr":  "spire-server." + spireNamespace + ".svc.cluster.local:443",
	} {
		if err := unstructured.SetNestedField(cm.Object, value, "data", key); err != nil {
			return err
		}
	}
	_, err = cms.Update(ctx, cm, metav1.UpdateOptions{})
	return err
}

// waitForStatefulSet polls until every replica of a StatefulSet is ready.
func (i *Installer) waitForStatefulSet(ctx context.Context, namespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sts, err := i.dynamic.Resource(statefulSetGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err == nil {
			ready, _, _ := unstructured.NestedInt64(sts.Object, "status", "readyReplicas")
			desired, _, _ := unstructured.NestedInt64(sts.Object, "spec", "replicas")
			if ready >= desired && desired > 0 {
				return nil
			}
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("statefulset %s/%s not ready after %s", namespace, name, timeout)
}

// defaultClusterSPIFFEID is the SPIRE chart's rule that gives every pod in
// the cluster a SPIFFE ID.
const defaultClusterSPIFFEID = "spire-server-spire-default"

// removeDefaultSPIFFEID deletes that rule from clusters installed before it
// was dropped from the manifests. With it in place any pod could obtain a
// Fulcio certificate, whether or not its ServiceAccount was authorized to
// build.
func (i *Installer) removeDefaultSPIFFEID(ctx context.Context) error {
	ids := i.dynamic.Resource(schema.GroupVersionResource{
		Group: "spire.spiffe.io", Version: "v1alpha1", Resource: "clusterspiffeids",
	})
	err := ids.Delete(ctx, defaultClusterSPIFFEID, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("removing ClusterSPIFFEID %s: %w", defaultClusterSPIFFEID, err)
	}
	return nil
}
