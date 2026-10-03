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
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
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
	)

	ctx := context.Background()
	policyKey := types.NamespacedName{Name: policyName, Namespace: namespace}
	renderedKey := types.NamespacedName{Name: renderedName}

	reconcilePolicy := func() (reconcile.Result, error) {
		r := &SupplyChainPolicyReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		return r.Reconcile(ctx, reconcile.Request{NamespacedName: policyKey})
	}
	readyCondition := func() *metav1.Condition {
		var scp supplychainv1alpha1.SupplyChainPolicy
		Expect(k8sClient.Get(ctx, policyKey, &scp)).To(Succeed())
		return meta.FindStatusCondition(scp.Status.Conditions, conditionReady)
	}
	getRendered := func(gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
		obj := &unstructured.Unstructured{}
		obj.SetGroupVersionKind(gvk)
		return obj, k8sClient.Get(ctx, renderedKey, obj)
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

	BeforeEach(func() {
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
		Expect(scp.Status.ClusterImagePolicy).To(Equal(renderedName))
		Expect(scp.Status.Images).To(ConsistOf("index.docker.io/nkanyezisolutions/policy-test-app**"))
		Expect(scp.Status.Identity).To(Equal(
			"https://kubernetes.io/namespaces/default/serviceaccounts/supply-chain-runner"))

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
