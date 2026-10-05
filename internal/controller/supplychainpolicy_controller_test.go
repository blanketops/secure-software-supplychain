/*
Copyright 2026.

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

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/policy"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

// selfSignedRoot stands in for the Fulcio root the installer collects.
func selfSignedRoot() string {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"blanketops.dev"}, CommonName: "fulcio"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	Expect(err).NotTo(HaveOccurred())
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

var _ = Describe("SupplyChainPolicy Controller", func() {
	const (
		namespace       = "default"
		supplyChainName = "policy-test-chain"
		policyName      = "policy-test"
		renderedName    = namespace + "-" + policyName
		// authorizationName is the ClusterImagePolicy requiring the attestation.
		authorizationName = renderedName + "-authorization"
	)

	ctx := context.Background()
	policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}

	reconcilePolicy := func() (reconcile.Result, error) {
		r := &SupplyChainPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		return r.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
	}
	readyCondition := func() *metav1.Condition {
		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		return meta.FindStatusCondition(scp.Status.Conditions, conditionReady)
	}
	getNamed := func(gvk schema.GroupVersionKind, name string) (*unstructured.Unstructured, error) {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		return obj, k8sClient.Get(ctx, types.NamespacedName{Name: name}, obj)
	}
	getRendered := func(gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
		return getNamed(gvk, renderedName)
	}
	createSupplyChain := func() {
		sc := forKanikoAppSupplyChain(supplyChainName)
		sc.Spec.Repository = "ntlaletsi70/policy-test-app"
		sc.Spec.Image.Name = "nkanyezisolutions/policy-test-app"
		Expect(k8sClient.Create(ctx, sc)).To(Succeed())
	}
	createRoots := func() {
		Expect(k8sClient.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: signing.RootsConfigMap, Namespace: namespace},
			Data: map[string]string{
				signing.RootsFulcioKey: selfSignedRoot(),
				signing.RootsRekorKey:  "rekor-public-key",
				signing.RootsCTLogKey:  "ctlog-public-key",
			},
		})).To(Succeed())
	}

	// grantPolicyRunner gives the policy's ServiceAccount what its three proofs
	// require, as config/samples/supplychain_v1alpha1_policyrole.yaml does.
	grantPolicyRunner := func() {
		const name = "policy-test-runner"
		role := &rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{policy.ScopeCheck.Group}, Resources: []string{policy.ScopeCheck.Resource},
					Verbs: []string{policy.ScopeCheck.Verb}},
				{APIGroups: []string{policy.IntentCheck.Group}, Resources: []string{policy.IntentCheck.Resource},
					Verbs: []string{policy.IntentCheck.Verb}},
				{APIGroups: []string{policy.OutputCheck.Group}, Resources: []string{policy.OutputCheck.Resource},
					Verbs: []string{policy.OutputCheck.Verb}},
			},
		}
		binding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: name},
			Subjects: []rbacv1.Subject{{
				Kind: rbacv1.ServiceAccountKind, Name: policy.DefaultServiceAccount, Namespace: namespace,
			}},
		}
		for _, obj := range []client.Object{role, binding} {
			Expect(client.IgnoreAlreadyExists(k8sClient.Create(ctx, obj))).To(Succeed())
		}
	}

	BeforeEach(func() {
		grantPolicyRunner()
		Expect(k8sClient.Create(ctx, &supplychainv1alpha1.SupplyChainPolicy{
			ObjectMeta: metav1.ObjectMeta{Name: policyName, Namespace: namespace},
			Spec: supplychainv1alpha1.SupplyChainPolicySpec{
				SupplyChainRef: supplychainv1alpha1.LocalObjectRef{Name: supplyChainName},
			},
		})).To(Succeed())
	})

	AfterEach(func() {
		var scp supplychainv1alpha1.SupplyChainPolicy
		if err := k8sClient.Get(ctx, policyKey, &scp); err == nil {
			Expect(k8sClient.Delete(ctx, &scp)).To(Succeed())
			_, err := reconcilePolicy()
			Expect(err).NotTo(HaveOccurred())
		}
		Expect(apierrors.IsNotFound(k8sClient.Get(ctx, policyKey, &scp))).To(BeTrue())

		for _, obj := range []client.Object{
			&supplychainv1alpha1.SupplyChain{ObjectMeta: metav1.ObjectMeta{Name: supplyChainName, Namespace: namespace}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: signing.RootsConfigMap, Namespace: namespace}},
		} {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
		}
	})

	It("renders nothing for a ServiceAccount that is not authorized", func() {
		createSupplyChain()
		createRoots()

		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		scp.Spec.ServiceAccountName = "unprivileged-policy-runner"
		Expect(k8sClient.Update(ctx, &scp)).To(Succeed())

		result, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		Expect(result.RequeueAfter).To(Equal(authorizationRetry))

		ready := readyCondition()
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("AuthorizationDenied"))

		By("recording all three denials")
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		authorization := scp.Status.Authorization
		Expect(authorization).NotTo(BeNil())
		for _, proof := range []*supplychainv1alpha1.AuthorizationProof{
			authorization.Scope, authorization.Intent, authorization.Output,
		} {
			Expect(proof).NotTo(BeNil())
			Expect(proof.Allowed).To(BeFalse())
			Expect(proof.Principal).To(Equal("system:serviceaccount:default:unprivileged-policy-runner"))
		}

		By("creating the ServiceAccount but no policy")
		var sa corev1.ServiceAccount
		Expect(k8sClient.Get(ctx, types.NamespacedName{
			Namespace: namespace, Name: "unprivileged-policy-runner",
		}, &sa)).To(Succeed())
		_, err = getRendered(policy.ClusterImagePolicyGVK)
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("reports a missing SupplyChain", func() {
		_, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())

		ready := readyCondition()
		Expect(ready).NotTo(BeNil())
		Expect(ready.Status).To(Equal(metav1.ConditionFalse))
		Expect(ready.Reason).To(Equal("SupplyChainNotFound"))
	})

	It("reports missing trust anchors", func() {
		createSupplyChain()

		_, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		Expect(readyCondition().Reason).To(Equal("TrustAnchorsNotFound"))
	})

	It("renders the TrustRoot and ClusterImagePolicy and removes them on deletion", func() {
		createSupplyChain()
		createRoots()

		_, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())

		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		Expect(meta.IsStatusConditionTrue(scp.Status.Conditions, conditionReady)).To(BeTrue())
		Expect(scp.Status.TrustRoot).To(Equal(renderedName))
		Expect(scp.Status.ClusterImagePolicies).To(Equal([]string{
			renderedName, authorizationName, renderedName + "-chains", renderedName + "-provenance",
		}))
		Expect(scp.Status.Images).To(ConsistOf("index.docker.io/nkanyezisolutions/policy-test-app**"))
		Expect(scp.Status.Signers).To(Equal([]supplychainv1alpha1.SignerIdentity{{
			Issuer:  signing.KubernetesOIDCIssuer,
			Subject: "https://kubernetes.io/namespaces/default/serviceaccounts/supply-chain-runner",
		}}))
		Expect(scp.Status.RekorURL).To(Equal("http://rekor-server.rekor-system.svc.cluster.local"))

		By("recording the three proofs of the policy's ServiceAccount")
		Expect(scp.Spec.ServiceAccountName).To(Equal(policy.DefaultServiceAccount))
		proofs := scp.Status.Authorization
		Expect(proofs).NotTo(BeNil())
		Expect(proofs.Scope.Allowed).To(BeTrue())
		Expect(proofs.Intent.Allowed).To(BeTrue())
		Expect(proofs.Output.Allowed).To(BeTrue())
		Expect(proofs.Output.Group).To(Equal("policy.sigstore.dev"))
		Expect(proofs.Output.Principal).To(Equal("system:serviceaccount:default:supply-chain-policy-runner"))

		trustRoot, err := getRendered(policy.TrustRootGVK)
		Expect(err).NotTo(HaveOccurred())
		cas, _, _ := unstructured.NestedSlice(trustRoot.Object, "spec", "sigstoreKeys", "certificateAuthorities")
		Expect(cas).To(HaveLen(1))
		Expect(cas[0]).To(HaveKeyWithValue("uri", "http://fulcio-server.fulcio-system.svc.cluster.local"))

		cip, err := getRendered(policy.ClusterImagePolicyGVK)
		Expect(err).NotTo(HaveOccurred())
		mode, _, _ := unstructured.NestedString(cip.Object, "spec", "mode")
		Expect(mode).To(Equal("enforce"))
		authorities, _, _ := unstructured.NestedSlice(cip.Object, "spec", "authorities")
		Expect(authorities).To(HaveLen(1))
		ref, _, _ := unstructured.NestedString(authorities[0].(map[string]any), "keyless", "trustRootRef")
		Expect(ref).To(Equal(renderedName))

		By("requiring the authorization attestation in a second policy")
		authorization, err := getNamed(policy.ClusterImagePolicyGVK, authorizationName)
		Expect(err).NotTo(HaveOccurred())
		authorities, _, _ = unstructured.NestedSlice(authorization.Object, "spec", "authorities")
		attestations, _, _ := unstructured.NestedSlice(authorities[0].(map[string]any), "attestations")
		Expect(attestations).To(HaveLen(1))
		Expect(attestations[0]).To(HaveKeyWithValue("predicateType", signing.AuthorizationPredicateType))

		By("leaving the resources untouched when nothing changed")
		_, err = reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		again, err := getRendered(policy.ClusterImagePolicyGVK)
		Expect(err).NotTo(HaveOccurred())
		Expect(again.GetResourceVersion()).To(Equal(cip.GetResourceVersion()))

		By("deleting the SupplyChainPolicy")
		Expect(k8sClient.Delete(ctx, &scp)).To(Succeed())
		_, err = reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		for _, gvk := range []schema.GroupVersionKind{policy.TrustRootGVK, policy.ClusterImagePolicyGVK} {
			_, err := getRendered(gvk)
			Expect(apierrors.IsNotFound(err)).To(BeTrue(), gvk.Kind)
		}
		_, err = getNamed(policy.ClusterImagePolicyGVK, authorizationName)
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
	})

	It("accepts stated signers and a pinned Rekor log", func() {
		createSupplyChain()
		createRoots()

		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		scp.Spec.Signers = []supplychainv1alpha1.PolicySigner{
			{ServiceAccountName: "supply-chain-runner"},
			{Subject: "release@blanketops.dev", Issuer: "https://accounts.example.com"},
		}
		scp.Spec.TrustRoot = &supplychainv1alpha1.PolicyTrustRoot{
			Rekor: &supplychainv1alpha1.TrustedAuthority{URL: "http://rekor.pinned"},
		}
		Expect(k8sClient.Update(ctx, &scp)).To(Succeed())

		_, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		Expect(scp.Status.Signers).To(Equal([]supplychainv1alpha1.SignerIdentity{
			{Issuer: signing.KubernetesOIDCIssuer,
				Subject: "https://kubernetes.io/namespaces/default/serviceaccounts/supply-chain-runner"},
			{Issuer: "https://accounts.example.com", Subject: "release@blanketops.dev"},
		}))
		Expect(scp.Status.RekorURL).To(Equal("http://rekor.pinned"))

		cip, err := getRendered(policy.ClusterImagePolicyGVK)
		Expect(err).NotTo(HaveOccurred())
		authorities, _, _ := unstructured.NestedSlice(cip.Object, "spec", "authorities")
		identities, _, _ := unstructured.NestedSlice(authorities[0].(map[string]any), "keyless", "identities")
		Expect(identities).To(HaveLen(2))
		rekorURL, _, _ := unstructured.NestedString(authorities[0].(map[string]any), "ctlog", "url")
		Expect(rekorURL).To(Equal("http://rekor.pinned"))
	})

	It("composes the trust root from the ConfigMap keys the policy points at", func() {
		createSupplyChain()
		createRoots()
		corpRoot := selfSignedRoot()
		Expect(k8sClient.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: "corp-trust", Namespace: namespace},
			Data:       map[string]string{"ca.pem": corpRoot},
		})).To(Succeed())
		DeferCleanup(func() {
			Expect(k8sClient.Delete(ctx, &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{Name: "corp-trust", Namespace: namespace},
			})).To(Succeed())
		})

		By("reporting the default trust anchors first")
		_, err := reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		Expect(scp.Status.TrustAnchors).NotTo(BeNil())
		defaultRoot := scp.Status.TrustAnchors.FulcioRoot
		Expect(defaultRoot).To(HavePrefix("sha256:"))

		By("pointing Fulcio at another ConfigMap and URL")
		scp.Spec.TrustRoot = &supplychainv1alpha1.PolicyTrustRoot{
			Fulcio: &supplychainv1alpha1.TrustedAuthority{
				URL:    "https://fulcio.example.com",
				PEMRef: &supplychainv1alpha1.ConfigMapKeyRef{Name: "corp-trust", Key: "ca.pem"},
			},
		}
		Expect(k8sClient.Update(ctx, &scp)).To(Succeed())
		_, err = reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())

		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		Expect(scp.Status.FulcioURL).To(Equal("https://fulcio.example.com"))
		Expect(scp.Status.TrustAnchors.FulcioRoot).NotTo(Equal(defaultRoot))

		trustRoot, err := getRendered(policy.TrustRootGVK)
		Expect(err).NotTo(HaveOccurred())
		cas, _, _ := unstructured.NestedSlice(trustRoot.Object, "spec", "sigstoreKeys", "certificateAuthorities")
		Expect(cas[0]).To(HaveKeyWithValue("uri", "https://fulcio.example.com"))
		Expect(cas[0]).To(HaveKeyWithValue("certChain", base64.StdEncoding.EncodeToString([]byte(corpRoot))))

		By("reporting a trust ConfigMap that does not exist")
		scp.Spec.TrustRoot.Fulcio.PEMRef.Name = "no-such-trust"
		Expect(k8sClient.Update(ctx, &scp)).To(Succeed())
		_, err = reconcilePolicy()
		Expect(err).NotTo(HaveOccurred())
		ready := readyCondition()
		Expect(ready.Reason).To(Equal("TrustAnchorsNotFound"))
		Expect(ready.Message).To(ContainSubstring("no-such-trust"))
	})

	It("rejects a signer that is not exactly one of serviceAccountName or subject", func() {
		var scp supplychainv1alpha1.SupplyChainPolicy
		for _, signer := range []supplychainv1alpha1.PolicySigner{
			{},
			{ServiceAccountName: "runner", Subject: "someone@example.com"},
		} {
			Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
			scp.Spec.Signers = []supplychainv1alpha1.PolicySigner{signer}
			Expect(k8sClient.Update(ctx, &scp)).To(MatchError(ContainSubstring("exactly one of")))
		}
	})

	It("does not take over a resource it does not own", func() {
		createSupplyChain()
		createRoots()

		foreign := &unstructured.Unstructured{}
		foreign.SetGroupVersionKind(policy.TrustRootGVK)
		foreign.SetName(renderedName)
		Expect(k8sClient.Create(ctx, foreign)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, foreign)).To(Succeed()) })

		_, err := reconcilePolicy()
		Expect(err).To(MatchError(ContainSubstring("not managed by this SupplyChainPolicy")))
		Expect(readyCondition().Reason).To(Equal("ApplyFailed"))
	})
})
