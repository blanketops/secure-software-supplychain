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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// newImageBuild returns an ImageBuild as would be auto-created by the
// TriggerTemplate from a GitHub push event — matching the real ImageBuildSpec.
func newImageBuild(name, supplyChainName, revision, sha string) *supplychainv1alpha1.ImageBuild {
	return &supplychainv1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "default",
			Labels: map[string]string{
				"blanketops.dev/supply-chain": supplyChainName,
				"blanketops.dev/triggered-by": "github-push",
				"blanketops.dev/repo":         "ntlaletsi70/for-kaniko-app",
			},
			Annotations: map[string]string{
				"blanketops.dev/git-commit-sha": sha,
				"blanketops.dev/git-repo-url":   "git@github.com:ntlaletsi70/for-kaniko-app.git",
			},
		},
		Spec: supplychainv1alpha1.ImageBuildSpec{
			SupplyChainRef: supplychainv1alpha1.LocalObjectRef{
				Name: supplyChainName,
			},
			GitRef: supplychainv1alpha1.GitRef{
				URL:      "git@github.com:ntlaletsi70/for-kaniko-app.git",
				Revision: revision,
			},
			ImageTag: sha,
		},
	}
}

var _ = Describe("ImageBuild Controller", func() {

	const (
		ibTimeout  = 30 * time.Second
		ibInterval = 250 * time.Millisecond
	)

	// ── terminal state guard ──────────────────────────────────────────────

	Context("when ImageBuild is already in a terminal state", func() {
		It("should skip reconciliation for Succeeded phase", func() {
			ib := newImageBuild("terminal-succeeded", "for-kaniko-app", "main", "abc1234")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			ib.Status.Phase = "Succeeded"
			Expect(k8sClient.Status().Update(ctx, ib)).To(Succeed())

			Eventually(func() string {
				var found supplychainv1alpha1.ImageBuild
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name: "terminal-succeeded", Namespace: "default",
				}, &found)
				return found.Status.Phase
			}, ibTimeout, ibInterval).Should(Equal("Succeeded"))

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})

		It("should skip reconciliation for Failed phase", func() {
			ib := newImageBuild("terminal-failed", "for-kaniko-app", "main", "abc1234")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			ib.Status.Phase = "Failed"
			Expect(k8sClient.Status().Update(ctx, ib)).To(Succeed())

			Eventually(func() string {
				var found supplychainv1alpha1.ImageBuild
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name: "terminal-failed", Namespace: "default",
				}, &found)
				return found.Status.Phase
			}, ibTimeout, ibInterval).Should(Equal("Failed"))

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})
	})

	// ── supplychain dependency ────────────────────────────────────────────

	Context("when SupplyChain does not exist", func() {
		It("should wait without erroring", func() {
			ib := newImageBuild("waiting-for-chain", "nonexistent-chain", "main", "abc1234")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			Consistently(func() string {
				var found supplychainv1alpha1.ImageBuild
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name: "waiting-for-chain", Namespace: "default",
				}, &found)
				return found.Status.Phase
			}, 3*time.Second, ibInterval).Should(BeEmpty())

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})
	})

	Context("when SupplyChain exists but is not Ready", func() {
		It("should wait for SupplyChain to become Ready", func() {
			sc := forKanikoAppSupplyChain("not-ready-chain")
			sc.Name = "not-ready-chain"
			sc.Spec.Repository = "ntlaletsi70/not-ready-repo" // avoid uniqueness conflict
			Expect(k8sClient.Create(ctx, sc)).To(Succeed())

			ib := newImageBuild("waiting-for-ready", "not-ready-chain", "main", "abc1234")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			Consistently(func() string {
				var found supplychainv1alpha1.ImageBuild
				_ = k8sClient.Get(ctx, types.NamespacedName{
					Name: "waiting-for-ready", Namespace: "default",
				}, &found)
				return found.Status.Phase
			}, 3*time.Second, ibInterval).Should(BeEmpty())

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
			Expect(k8sClient.Delete(ctx, sc)).To(Succeed())
		})
	})

	// ── spec correctness ─────────────────────────────────────────────────

	Context("when ImageBuild is created with full spec", func() {
		It("should persist all spec fields correctly", func() {
			ib := newImageBuild("full-spec-build", "for-kaniko-app", "master", "def5678")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			var found supplychainv1alpha1.ImageBuild
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name: "full-spec-build", Namespace: "default",
				}, &found)
			}, ibTimeout, ibInterval).Should(Succeed())

			Expect(found.Spec.SupplyChainRef.Name).To(Equal("for-kaniko-app"))
			Expect(found.Spec.GitRef.URL).To(Equal("git@github.com:ntlaletsi70/for-kaniko-app.git"))
			Expect(found.Spec.GitRef.Revision).To(Equal("master"))
			Expect(found.Spec.ImageTag).To(Equal("def5678"))

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})
	})

	// ── trigger labels ────────────────────────────────────────────────────

	Context("when ImageBuild is auto-created by EventListener", func() {
		It("should carry correct trigger labels and annotations", func() {
			ib := newImageBuild("triggered-build", "for-kaniko-app", "main", "abc1234567890")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			var found supplychainv1alpha1.ImageBuild
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: "triggered-build", Namespace: "default",
			}, &found)).To(Succeed())

			Expect(found.Labels["blanketops.dev/triggered-by"]).To(Equal("github-push"))
			Expect(found.Labels["blanketops.dev/supply-chain"]).To(Equal("for-kaniko-app"))
			Expect(found.Labels["blanketops.dev/repo"]).To(Equal("ntlaletsi70/for-kaniko-app"))
			Expect(found.Annotations["blanketops.dev/git-commit-sha"]).To(Equal("abc1234567890"))
			Expect(found.Annotations["blanketops.dev/git-repo-url"]).To(Equal("git@github.com:ntlaletsi70/for-kaniko-app.git"))
			Expect(found.Spec.ImageTag).To(Equal("abc1234567890"))

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})
	})

	// ── phase transitions ─────────────────────────────────────────────────

	Context("phase validation", func() {
		It("should accept valid phases", func() {
			ib := newImageBuild("phase-test-build", "for-kaniko-app", "main", "abc1234")
			Expect(k8sClient.Create(ctx, ib)).To(Succeed())

			for _, phase := range []string{"Pending", "Running", "Succeeded", "Failed"} {
				ib.Status.Phase = phase
				Expect(k8sClient.Status().Update(ctx, ib)).To(Succeed())

				var found supplychainv1alpha1.ImageBuild
				Expect(k8sClient.Get(ctx, types.NamespacedName{
					Name: "phase-test-build", Namespace: "default",
				}, &found)).To(Succeed())
				Expect(found.Status.Phase).To(Equal(phase))
			}

			Expect(k8sClient.Delete(ctx, ib)).To(Succeed())
		})
	})
})
