//go:build e2e
// +build e2e

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

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/ntlaletsi70/secure-software-supply-chain/test/utils"
)

var (
	// managerImage is the manager image to be built and loaded for testing.
	managerImage = "example.com/secure-software-supply-chain:v0.0.1"
	// shouldCleanupCertManager tracks whether CertManager was installed by this suite.
	shouldCleanupCertManager = false
)

// TestE2E runs the e2e test suite to validate the solution in an isolated environment.
// The default setup requires Kind and CertManager.
//
// To skip CertManager installation, set: CERT_MANAGER_INSTALL_SKIP=true
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting secure-software-supply-chain e2e test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("building the manager image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", managerImage))
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager image")

	// TODO(user): If you want to change the e2e test vendor from Kind,
	// ensure the image is built and available, then remove the following block.
	By("loading the manager image on Kind")
	err = utils.LoadImageToKindClusterWithName(managerImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager image into Kind")

	setupCertManager()
	installDependencies()
})

var _ = AfterSuite(func() {
	teardownCertManager()
})

// setupCertManager installs CertManager if needed for webhook tests.
// Skips installation if CERT_MANAGER_INSTALL_SKIP=true or if already present.
func setupCertManager() {
	if os.Getenv("CERT_MANAGER_INSTALL_SKIP") == "true" {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager installation (CERT_MANAGER_INSTALL_SKIP=true)\n")
		return
	}

	By("checking if CertManager is already installed")
	if utils.IsCertManagerCRDsInstalled() {
		_, _ = fmt.Fprintf(GinkgoWriter, "CertManager is already installed. Skipping installation.\n")
		return
	}

	// Mark for cleanup before installation to handle interruptions and partial installs.
	shouldCleanupCertManager = true

	By("installing CertManager")
	Expect(utils.InstallCertManager()).To(Succeed(), "Failed to install CertManager")
}

// teardownCertManager uninstalls CertManager if it was installed by setupCertManager.
// This ensures we only remove what we installed.
func teardownCertManager() {
	if !shouldCleanupCertManager {
		_, _ = fmt.Fprintf(GinkgoWriter, "Skipping CertManager cleanup (not installed by this suite)\n")
		return
	}

	By("uninstalling CertManager")
	utils.UninstallCertManager()
}

// installDependencies installs what the manager cannot run without: the Tekton
// CRDs its controllers watch, and policy-controller, which serves the resources
// SupplyChainPolicy renders.
//
// Only the CRDs are taken from the Tekton releases. Nothing here runs a
// pipeline, and the Tekton images would only queue ahead of the ones the tests
// wait for.
func installDependencies() {
	for _, release := range []string{
		"dependencies/tekton/pipelines/release.yaml",
		"dependencies/tekton/triggers/core/release.yaml",
	} {
		By("installing the CRDs of " + release)
		crds, err := customResourceDefinitions(release)
		ExpectWithOffset(1, err).NotTo(HaveOccurred())
		// Server-side: the Tekton CRDs are too large for a client-side apply annotation.
		cmd := exec.Command("kubectl", "apply", "--server-side", "--force-conflicts", "-f", "-")
		cmd.Stdin = strings.NewReader(crds)
		_, err = utils.Run(cmd)
		ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to install the CRDs of "+release)
	}

	By("installing policy-controller")
	cmd := exec.Command("kubectl", "apply", "--server-side", "--force-conflicts",
		"-f", "dependencies/sigstore/policy-controller")
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to install policy-controller")

	By("waiting for the dependency CRDs to be established")
	cmd = exec.Command("kubectl", "wait", "--for=condition=Established", "crd", "--all", "--timeout=2m")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Dependency CRDs were not established")

	By("waiting for policy-controller to be available")
	// Not "rollout status": that gives up at the Deployment's progress deadline,
	// which a slow image pull can exceed.
	cmd = exec.Command("kubectl", "wait", "--for=condition=Available", "deployment/policy-controller-webhook",
		"-n", "cosign-system", "--timeout=15m")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "policy-controller did not become available")
}

// customResourceDefinitions returns only the CRD documents of a multi-document
// manifest, relative to the project root.
func customResourceDefinitions(manifest string) (string, error) {
	dir, err := utils.GetProjectDir()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(filepath.Join(dir, manifest))
	if err != nil {
		return "", err
	}
	var crds []string
	for _, doc := range strings.Split(string(data), "\n---") {
		if strings.Contains(doc, "\nkind: CustomResourceDefinition\n") {
			crds = append(crds, doc)
		}
	}
	if len(crds) == 0 {
		return "", fmt.Errorf("no CustomResourceDefinition found in %s", manifest)
	}
	return strings.Join(crds, "\n---"), nil
}
