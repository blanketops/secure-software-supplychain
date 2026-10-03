//go:build e2e
// +build e2e

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

package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os/exec"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
	"github.com/ntlaletsi70/secure-software-supply-chain/test/utils"
)

const (
	// policyNamespace holds the SupplyChain, its trust anchors and the policy.
	policyNamespace = "scp-e2e"
	// workloadNamespace is opted in to policy-controller enforcement.
	workloadNamespace = "scp-e2e-workloads"

	policyName = "pause"
	// renderedName is the cluster-scoped TrustRoot and signature
	// ClusterImagePolicy name; authorizationName the attestation policy.
	renderedName      = policyNamespace + "-" + policyName
	authorizationName = renderedName + "-authorization"

	// unsignedImage is public and carries no signature from the test trust
	// root, so a policy covering it must reject it.
	unsignedRegistry = "registry.k8s.io"
	unsignedName     = "pause"
	unsignedImage    = unsignedRegistry + "/" + unsignedName + ":3.10"
)

// verifySupplyChainPolicy drives a SupplyChainPolicy through the real
// policy-controller: the rendered TrustRoot and ClusterImagePolicy must be
// accepted by its webhooks, an unsigned image the policy covers must be
// rejected, warn mode must let it through, and deleting the policy must remove
// what it rendered.
func verifySupplyChainPolicy() {
	DeferCleanup(func() {
		for _, args := range [][]string{
			{"delete", "supplychainpolicy", policyName, "-n", policyNamespace, "--ignore-not-found", "--timeout=1m"},
			{"delete", "supplychain", policyName, "-n", policyNamespace, "--ignore-not-found", "--timeout=1m"},
			{"delete", "clusterrole,clusterrolebinding", "scp-e2e-policy-runner", "--ignore-not-found"},
			{"delete", "ns", policyNamespace, workloadNamespace, "--ignore-not-found", "--wait=false"},
		} {
			_, _ = utils.Run(exec.Command("kubectl", args...))
		}
	})

	By("creating the SupplyChain, its trust anchors and the SupplyChainPolicy")
	kubectlApply(fmt.Sprintf(`
apiVersion: v1
kind: Namespace
metadata:
  name: %[1]s
---
apiVersion: v1
kind: Namespace
metadata:
  name: %[2]s
  labels:
    policy.sigstore.dev/include: "true"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: %[3]s
  namespace: %[1]s
data:
  %[4]s: |
%[5]s
  %[6]s: |
%[7]s
  %[8]s: |
%[9]s
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: scp-e2e-policy-runner
rules:
- apiGroups: ["supplychain.blanketops.dev"]
  resources: ["supplychains"]
  verbs: ["get"]
- apiGroups: ["supplychain.blanketops.dev"]
  resources: ["supplychainpolicies"]
  verbs: ["create"]
- apiGroups: ["policy.sigstore.dev"]
  resources: ["clusterimagepolicies"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: scp-e2e-policy-runner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: scp-e2e-policy-runner
subjects:
- kind: ServiceAccount
  name: supply-chain-policy-runner
  namespace: %[1]s
---
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChain
metadata:
  name: %[10]s
  namespace: %[1]s
spec:
  repository: blanketops/pause
  serviceAccountName: supply-chain-runner
  image:
    registry: %[11]s
    name: %[12]s
  steps:
    sign: true
  signing:
    fulcioURL: http://fulcio-server.fulcio-system.svc.cluster.local
    rekorURL: http://rekor-server.rekor-system.svc.cluster.local
    ctLogURL: http://ctlog.ctlog-system.svc/fulcio
---
apiVersion: supplychain.blanketops.dev/v1alpha1
kind: SupplyChainPolicy
metadata:
  name: %[10]s
  namespace: %[1]s
spec:
  supplyChainRef:
    name: %[10]s
  mode: enforce
  signers:
  - serviceAccountName: supply-chain-runner
  rekor:
    url: http://rekor-server.rekor-system.svc.cluster.local
`,
		policyNamespace, workloadNamespace, signing.RootsConfigMap,
		signing.RootsFulcioKey, indent(newRootCertPEM()),
		signing.RootsRekorKey, indent(newPublicKeyPEM()),
		signing.RootsCTLogKey, indent(newPublicKeyPEM()),
		policyName, unsignedRegistry, unsignedName,
	))

	By("waiting for the SupplyChainPolicy to become Ready")
	Eventually(func(g Gomega) {
		ready, err := kubectl("get", "supplychainpolicy", policyName, "-n", policyNamespace,
			"-o", "jsonpath={.status.conditions[?(@.type=='Ready')].status}/{.status.conditions[?(@.type=='Ready')].message}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(ready).To(HavePrefix("True/"))
	}).Should(Succeed())

	By("checking what the policy admits")
	status, err := kubectl("get", "supplychainpolicy", policyName, "-n", policyNamespace,
		"-o", "jsonpath={.status.clusterImagePolicies[*]} {.status.trustRoot} {.status.images[0]} {.status.signers[0].subject} {.status.rekorURL}")
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.Fields(status)).To(Equal([]string{
		renderedName,
		authorizationName,
		renderedName,
		unsignedRegistry + "/" + unsignedName + "**",
		signing.ServiceAccountIdentity(policyNamespace, "supply-chain-runner"),
		"http://rekor-server.rekor-system.svc.cluster.local",
	}))

	By("checking the policy's ServiceAccount passed its three authorization checks")
	proofs, err := kubectl("get", "supplychainpolicy", policyName, "-n", policyNamespace,
		"-o", "jsonpath={.status.authorization.scope.allowed} {.status.authorization.intent.allowed} "+
			"{.status.authorization.output.allowed} {.status.authorization.output.principal}")
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.Fields(proofs)).To(Equal([]string{
		"true", "true", "true", "system:serviceaccount:" + policyNamespace + ":supply-chain-policy-runner",
	}))

	By("checking policy-controller accepted the rendered resources")
	trustRootRef, err := kubectl("get", "clusterimagepolicy", renderedName,
		"-o", "jsonpath={.spec.authorities[0].keyless.trustRootRef}")
	Expect(err).NotTo(HaveOccurred())
	Expect(trustRootRef).To(Equal(renderedName))
	_, err = kubectl("get", "trustroot", renderedName)
	Expect(err).NotTo(HaveOccurred())
	predicateType, err := kubectl("get", "clusterimagepolicy", authorizationName,
		"-o", "jsonpath={.spec.authorities[0].attestations[0].predicateType}")
	Expect(err).NotTo(HaveOccurred())
	Expect(predicateType).To(Equal(signing.AuthorizationPredicateType))

	By("rejecting an unsigned image the policy covers")
	// policy-controller picks the policy up asynchronously, so the rejection
	// has to name this policy rather than merely happen.
	Eventually(func(g Gomega) {
		out, err := kubectl("run", "unsigned", "--image="+unsignedImage, "--restart=Never", "-n", workloadNamespace)
		if err == nil {
			_, _ = kubectl("delete", "pod", "unsigned", "-n", workloadNamespace, "--wait=false")
		}
		g.Expect(err).To(HaveOccurred(), "unsigned image was admitted")
		g.Expect(out).To(ContainSubstring("policy.sigstore.dev"))
		g.Expect(out).To(ContainSubstring(renderedName))
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	By("admitting it once the policy only warns")
	_, err = kubectl("patch", "supplychainpolicy", policyName, "-n", policyNamespace,
		"--type=merge", "-p", `{"spec":{"mode":"warn"}}`)
	Expect(err).NotTo(HaveOccurred())
	Eventually(func(g Gomega) {
		modes, err := kubectl("get", "clusterimagepolicy", renderedName, authorizationName,
			"-o", "jsonpath={.items[*].spec.mode}")
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(strings.Fields(modes)).To(Equal([]string{"warn", "warn"}))
	}).Should(Succeed())
	Eventually(func(g Gomega) {
		_, err := kubectl("run", "unsigned", "--image="+unsignedImage, "--restart=Never", "-n", workloadNamespace)
		g.Expect(err).NotTo(HaveOccurred())
	}, 3*time.Minute, 5*time.Second).Should(Succeed())

	By("removing the rendered resources when the SupplyChainPolicy is deleted")
	_, err = kubectl("delete", "supplychainpolicy", policyName, "-n", policyNamespace, "--timeout=1m")
	Expect(err).NotTo(HaveOccurred())
	for _, resource := range [][]string{
		{"clusterimagepolicy", renderedName},
		{"clusterimagepolicy", authorizationName},
		{"trustroot", renderedName},
	} {
		out, err := kubectl("get", resource[0], resource[1], "--ignore-not-found", "-o", "name")
		Expect(err).NotTo(HaveOccurred())
		Expect(out).To(BeEmpty(), "%s %s was left behind", resource[0], resource[1])
	}
}

func kubectl(args ...string) (string, error) {
	return utils.Run(exec.Command("kubectl", args...))
}

func kubectlApply(manifest string) {
	cmd := exec.Command("kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
}

// indent nests a PEM block under a YAML block scalar.
func indent(pemData string) string {
	lines := strings.Split(strings.TrimSpace(pemData), "\n")
	return "    " + strings.Join(lines, "\n    ")
}

func newKey() *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ExpectWithOffset(2, err).NotTo(HaveOccurred())
	return key
}

// newRootCertPEM stands in for the Fulcio root the installer collects.
func newRootCertPEM() string {
	key := newKey()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"blanketops.dev"}, CommonName: "fulcio-e2e"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newPublicKeyPEM stands in for the Rekor and CT log public keys.
func newPublicKeyPEM() string {
	der, err := x509.MarshalPKIXPublicKey(&newKey().PublicKey)
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}
