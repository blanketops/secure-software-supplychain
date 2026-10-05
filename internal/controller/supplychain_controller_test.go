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
package controller

import (
	"context"
	corev1 "k8s.io/api/core/v1"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// forKanikoAppSupplyChain returns a SupplyChain that exactly mirrors
// config/samples/supplychain_v1alpha1_supplychain.yaml (for-kaniko-app).
// This is the source of truth for what the controller must handle.
func forKanikoAppSupplyChain(name string) *supplychainv1alpha1.SupplyChain {
	return &supplychainv1alpha1.SupplyChain{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				"app.kubernetes.io/name":       "secure-software-supply-chain",
				"app.kubernetes.io/managed-by": "kustomize",
			},
		},
		Spec: supplychainv1alpha1.SupplyChainSpec{
			Repository:         "ntlaletsi70/for-kaniko-app",
			ServiceAccountName: "supply-chain-runner",
			Image: supplychainv1alpha1.ImageSpec{
				Registry:          "docker.io",
				Name:              "nkanyezisolutions/for-kaniko-app",
				TagStrategy:       "git-sha",
				CloneSecretRef:    "github-ssh-credentials",
				RegistrySecretRef: "registry-credentials",
			},
			Steps: supplychainv1alpha1.StepsSpec{
				Buildpacks: true,
				Trivy:      true,
				Sign:       true,
				Attest:     true,
				SonarQube: &supplychainv1alpha1.SonarQubeSpec{
					Enabled:        true,
					ServerURL:      "http://sonarqube-sonarqube.default.svc.cluster.local:9000",
					TokenSecretRef: "sonarqube-token",
					ProjectKey:     "ntlaletsi70_for-kaniko-app",
				},
			},
			Signing: &supplychainv1alpha1.SigningSpec{
				FulcioURL: "http://fulcio-server.fulcio-system.svc.cluster.local",
				RekorURL:  "http://rekor-server.rekor-system.svc.cluster.local",
			},
		},
	}
}

var _ = Describe("SupplyChain Controller", func() {

	const (
		resourceName = "for-kaniko-app"
		namespace    = "default"
	)

	ctx := context.Background()

	namespacedName := types.NamespacedName{
		Name:      resourceName,
		Namespace: namespace,
	}

	// ── lifecycle ─────────────────────────────────────────────────────────

	BeforeEach(func() {
		By("creating the SupplyChain CR if it does not exist")
		var existing supplychainv1alpha1.SupplyChain
		err := k8sClient.Get(ctx, namespacedName, &existing)
		if err != nil && apierrors.IsNotFound(err) {
			Expect(k8sClient.Create(ctx, forKanikoAppSupplyChain(resourceName))).To(Succeed())
		}
	})

	AfterEach(func() {
		By("cleaning up the SupplyChain CR")
		var sc supplychainv1alpha1.SupplyChain
		err := k8sClient.Get(ctx, namespacedName, &sc)
		if err == nil {
			Expect(k8sClient.Delete(ctx, &sc)).To(Succeed())
		}
	})

	// ── reconciliation ────────────────────────────────────────────────────

	It("should reconcile without error", func() {
		By("running the reconciler against the for-kaniko-app SupplyChain")
		r := &SupplyChainReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		_, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: namespacedName})
		Expect(err).NotTo(HaveOccurred())
	})

	// ── spec assertions ───────────────────────────────────────────────────

	It("should store the correct repository", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.Repository).To(Equal("ntlaletsi70/for-kaniko-app"))
	})

	It("should store the correct service account name", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.ServiceAccountName).To(Equal("supply-chain-runner"))
	})

	It("should store the correct image spec", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.Image.Registry).To(Equal("docker.io"))
		Expect(sc.Spec.Image.Name).To(Equal("nkanyezisolutions/for-kaniko-app"))
		Expect(sc.Spec.Image.TagStrategy).To(Equal("git-sha"))
		Expect(sc.Spec.Image.CloneSecretRef).To(Equal("github-ssh-credentials"))
		Expect(sc.Spec.Image.RegistrySecretRef).To(Equal("registry-credentials"))
	})

	It("should have SonarQube enabled with the correct project key", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.Steps.SonarQube.Enabled).To(BeTrue())
		Expect(sc.Spec.Steps.SonarQube.ServerURL).To(Equal("http://sonarqube-sonarqube.default.svc.cluster.local:9000"))
		Expect(sc.Spec.Steps.SonarQube.TokenSecretRef).To(Equal("sonarqube-token"))
		Expect(sc.Spec.Steps.SonarQube.ProjectKey).To(Equal("ntlaletsi70_for-kaniko-app"))
	})

	It("should have the correct Fulcio and Rekor URLs", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.Signing).NotTo(BeNil())
		Expect(sc.Spec.Signing.FulcioURL).To(Equal("http://fulcio-server.fulcio-system.svc.cluster.local"))
		Expect(sc.Spec.Signing.RekorURL).To(Equal("http://rekor-server.rekor-system.svc.cluster.local"))
	})

	It("should have pipeline steps enabled", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		Expect(sc.Spec.Steps.Buildpacks).To(BeTrue())
		Expect(sc.Spec.Steps.Trivy).To(BeTrue())
		Expect(sc.Spec.Steps.Sign).To(BeTrue())
		Expect(sc.Spec.Steps.Attest).To(BeTrue())
	})

	// ── ServiceAccount ────────────────────────────────────────────────────

	It("should give the runner ServiceAccount the registry credentials Tekton Chains needs", func() {
		var sc supplychainv1alpha1.SupplyChain
		Expect(k8sClient.Get(ctx, namespacedName, &sc)).To(Succeed())
		r := &SupplyChainReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		const name = "chains-credentials-runner"
		key := types.NamespacedName{Namespace: namespace, Name: name}
		pullSecret := corev1.LocalObjectReference{Name: "registry-credentials-chains"}

		By("creating it with the pull secret")
		Expect(r.ensureServiceAccount(ctx, &sc, name)).To(Succeed())
		var sa corev1.ServiceAccount
		Expect(k8sClient.Get(ctx, key, &sa)).To(Succeed())
		DeferCleanup(func() { Expect(k8sClient.Delete(ctx, &sa)).To(Succeed()) })
		Expect(sa.ImagePullSecrets).To(ConsistOf(pullSecret))

		By("adding it to one that exists without it, keeping what is there")
		sa.ImagePullSecrets = []corev1.LocalObjectReference{{Name: "someone-elses"}}
		Expect(k8sClient.Update(ctx, &sa)).To(Succeed())
		Expect(r.ensureServiceAccount(ctx, &sc, name)).To(Succeed())
		Expect(k8sClient.Get(ctx, key, &sa)).To(Succeed())
		Expect(sa.ImagePullSecrets).To(ConsistOf(corev1.LocalObjectReference{Name: "someone-elses"}, pullSecret))

		By("changing nothing when it is already there")
		version := sa.ResourceVersion
		Expect(r.ensureServiceAccount(ctx, &sc, name)).To(Succeed())
		Expect(k8sClient.Get(ctx, key, &sa)).To(Succeed())
		Expect(sa.ResourceVersion).To(Equal(version))
	})

	// ── 1:1 repo uniqueness ───────────────────────────────────────────────

	It("should enforce one SupplyChain per repository", func() {
		By("attempting to create a second SupplyChain for the same repository")
		duplicate := forKanikoAppSupplyChain("for-kaniko-app-duplicate")
		err := k8sClient.Create(ctx, duplicate)
		// Creation itself may succeed — the controller enforces uniqueness on reconcile.
		// If it was created, clean it up.
		if err == nil {
			r := &SupplyChainReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
			req := reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      "for-kaniko-app-duplicate",
					Namespace: namespace,
				},
			}
			// The first pass only adds the finalizer and requeues.
			_, reconcileErr := r.Reconcile(ctx, req)
			Expect(reconcileErr).NotTo(HaveOccurred())

			// Reconciler should return an error for the duplicate repo
			_, reconcileErr = r.Reconcile(ctx, req)
			Expect(reconcileErr).To(HaveOccurred())
			Expect(reconcileErr.Error()).To(ContainSubstring("one SupplyChain per repository is law"))

			// Delete, then reconcile once more so the finalizer is released.
			Expect(k8sClient.Delete(ctx, duplicate)).To(Succeed())
			_, reconcileErr = r.Reconcile(ctx, req)
			Expect(reconcileErr).NotTo(HaveOccurred())
		}
	})
})
