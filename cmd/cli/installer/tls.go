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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// The services of the secure software supply chain talk to each other over TLS, with
// certificates cert-manager issues from one private CA. See
// dependencies/cert-manager/ca.
const (
	certManagerNamespace = "cert-manager"
	certManagerVersion   = "v1.19.4"

	// conditionStatusTrue is the value a Kubernetes status condition carries
	// when it is satisfied.
	conditionStatusTrue = "True"

	// conditionTypeReady is the condition type the installer waits on.
	conditionTypeReady = "Ready"

	// caSecret holds the CA's certificate and key; caIssuer signs with it.
	caSecret = "supply-chain-ca"
	caIssuer = "supply-chain-ca"

	// caConfigMap is the CA's certificate alone, copied to each namespace
	// with a workload that has to trust it, under caKey.
	caConfigMap = "supply-chain-ca"
	caKey       = "ca.crt"
	// caMountDir is where a workload given the CA finds it.
	caMountDir = "/etc/supply-chain-ca"

	// Where the cluster reaches Rekor, Fulcio and the CT log. Each name is
	// one its certificate is issued for.
	rekorURL  = "https://rekor-server.rekor-system.svc.cluster.local"
	fulcioURL = "https://fulcio-server.fulcio-system.svc.cluster.local"
	ctLogURL  = "https://ctlog.ctlog-system.svc/fulcio"
)

var clusterIssuerGVR = schema.GroupVersionResource{
	Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
}

// certManagerIsSomeoneElses reports whether the cluster already runs a
// cert-manager this installer did not put there. It is then used as it is:
// replacing it with the version pinned here would change it under whatever
// else depends on it.
func (i *Installer) certManagerIsSomeoneElses(ctx context.Context) bool {
	if i.dryRun || i.dynamic == nil {
		return false
	}
	deployment, err := i.dynamic.Resource(deploymentGVR).Namespace(certManagerNamespace).
		Get(ctx, "cert-manager", metav1.GetOptions{})
	if err != nil {
		return false
	}
	return deployment.GetLabels()["app.kubernetes.io/version"] != certManagerVersion
}

// waitForCertManager waits for cert-manager and, last, for its webhook: until
// that answers, no Issuer or Certificate can be created.
func (i *Installer) waitForCertManager(ctx context.Context) error {
	for _, name := range []string{"cert-manager", "cert-manager-cainjector", "cert-manager-webhook"} {
		if err := i.waitForDeployment(ctx, certManagerNamespace, name); err != nil {
			return fmt.Errorf("cert-manager is not ready: %w", err)
		}
	}
	return nil
}

// waitForCA waits until the CA exists and its issuer can sign.
func (i *Installer) waitForCA(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		issuer, err := i.dynamic.Resource(clusterIssuerGVR).Get(ctx, caIssuer, metav1.GetOptions{})
		if err == nil && conditionTrue(issuer) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ClusterIssuer %s is not ready: the CA was not issued", caIssuer)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
}

// conditionTrue reports whether an object's status has the Ready condition set.
func conditionTrue(obj *unstructured.Unstructured) bool {
	conditions, _, _ := unstructured.NestedSlice(obj.Object, "status", "conditions")
	for _, c := range conditions {
		if condition, ok := c.(map[string]any); ok && condition["type"] == conditionTypeReady {
			return condition["status"] == conditionStatusTrue
		}
	}
	return false
}

// supplyChainCA returns the CA's certificate, PEM-encoded.
func (i *Installer) supplyChainCA(ctx context.Context) (string, error) {
	ca, err := i.readSecretValue(ctx, certManagerNamespace, caSecret, "tls.crt")
	if err != nil {
		return "", fmt.Errorf("reading the secure software supply chain's CA: %w", err)
	}
	if !strings.Contains(ca, "BEGIN CERTIFICATE") {
		return "", errors.New("the secure software supply chain's CA has not been issued yet")
	}
	return ca, nil
}

// publishCA copies the CA's certificate into a namespace, for the workloads
// there that connect to the secure software supply chain's services.
func (i *Installer) publishCA(ctx context.Context, namespace string) error {
	ca, err := i.supplyChainCA(ctx)
	if err != nil {
		return err
	}
	return i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      caConfigMap,
			"namespace": namespace,
			"labels":    map[string]any{"blanketops.dev/managed": "true"},
		},
		"data": map[string]any{caKey: ca},
	}})
}

// trustCAIn makes a Deployment's first container trust the secure software supply chain's CA,
// in addition to the public CAs its image ships.
func (i *Installer) trustCAIn(ctx context.Context, namespace, name string) error {
	if err := i.publishCA(ctx, namespace); err != nil {
		return err
	}
	deployments := i.dynamic.Resource(deploymentGVR).Namespace(namespace)
	deployment, err := deployments.Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if err := addCATrust(deployment); err != nil {
		return err
	}
	_, err = deployments.Update(ctx, deployment, metav1.UpdateOptions{})
	if apierrors.IsConflict(err) {
		return i.trustCAIn(ctx, namespace, name)
	}
	return err
}

// addCATrust mounts the CA's certificate into the first container of a
// Deployment and points Go's TLS at it. SSL_CERT_DIR adds a directory of
// trusted certificates; the bundle file of public CAs in the image is still
// read, so registries and other public endpoints keep working. It is safe to
// apply twice.
func addCATrust(deployment *unstructured.Unstructured) error {
	const volumeName = "supply-chain-ca"
	podSpec := []string{"spec", "template", "spec"}

	volumes, _, _ := unstructured.NestedSlice(deployment.Object, append(podSpec, "volumes")...)
	if !hasNamed(volumes, volumeName) {
		volumes = append(volumes, map[string]any{
			"name":      volumeName,
			"configMap": map[string]any{"name": caConfigMap},
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
		mounts = append(mounts, map[string]any{"name": volumeName, "mountPath": caMountDir, "readOnly": true})
	}
	container["volumeMounts"] = mounts
	env, _ := container["env"].([]any)
	if !hasNamed(env, "SSL_CERT_DIR") {
		env = append(env, map[string]any{"name": "SSL_CERT_DIR", "value": caMountDir + ":/etc/ssl/certs"})
	}
	container["env"] = env
	containers[0] = container
	return unstructured.SetNestedSlice(deployment.Object, containers, append(podSpec, "containers")...)
}

// httpsToPod opens a connection to a port of one of a Deployment's pods and
// returns the URL to use and a client that verifies the pod's certificate
// against the secure software supply chain's CA, as serverName. The CLI reaches the cluster's
// services this way, and holds them to the same certificate their clients in
// the cluster see.
func (i *Installer) httpsToPod(
	ctx context.Context, namespace, selector string, port int, serverName string,
) (string, *http.Client, func(), error) {
	ca, err := i.supplyChainCA(ctx)
	if err != nil {
		return "", nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(ca)) {
		return "", nil, nil, errors.New("the secure software supply chain's CA is not a certificate")
	}
	pods, err := i.dynamic.Resource(podGVR).Namespace(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return "", nil, nil, err
	}
	for _, pod := range pods.Items {
		// Not one that is on its way out: it may be the last of a version
		// that is being replaced.
		if phase, _, _ := unstructured.NestedString(pod.Object, "status", "phase"); phase != "Running" ||
			pod.GetDeletionTimestamp() != nil {
			continue
		}
		base, closeForward, err := i.forwardToPod(ctx, namespace, pod.GetName(), port)
		if err != nil {
			return "", nil, nil, err
		}
		client := &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{
				RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12,
			}},
		}
		return "https://" + strings.TrimPrefix(base, "http://"), client, closeForward, nil
	}
	return "", nil, nil, fmt.Errorf("no running pod in %s matches %s", namespace, selector)
}
