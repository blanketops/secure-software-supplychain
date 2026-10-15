//go:build mage

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

// The project's build. "mage help" lists the targets and their settings.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Default is what a bare "mage" runs: the list of targets.
var Default = Help

// Help lists the targets and the settings they read from the environment.
func Help() error {
	// The compiled magefile lists its own targets.
	if err := sh.RunV(os.Args[0], "-l"); err != nil {
		return err
	}
	fmt.Print(`
Settings, read from the environment:
  IMG               the controller image, for example ghcr.io/your-org/controller:v1
                    (default controller:latest)
  PLATFORMS         what ko:push builds for (default linux/amd64,linux/arm64)
  IMAGE_ARCHIVE     where ko:build writes the image (default bin/controller-image.tar)
  KIND_CLUSTER      the kind cluster ko:load and the e2e tests use
  IGNORE_NOT_FOUND  "true" lets uninstall and undeploy pass when something is already gone

Examples:
  mage test
  IMG=ghcr.io/your-org/controller:v1 mage ko:push deploy
  IMG=controller:dev KIND_CLUSTER=my-cluster mage ko:build ko:load install deploy

Without mage installed: go run mage.go <target>
`)
	return nil
}

const defaultKindCluster = "secure-software-supply-chain-test-e2e"

var (
	image        = env("IMG", "controller:latest")
	platforms    = env("PLATFORMS", "linux/amd64,linux/arm64")
	kindCluster  = env("KIND_CLUSTER", defaultKindCluster)
	imageArchive = env("IMAGE_ARCHIVE", filepath.Join("bin", "controller-image.tar"))
)

// ── Development ──────────────────────────────────────────────────────────────

// Manifests generates the CRDs, the ClusterRole and the webhook configuration from the markers.
func Manifests() error {
	mg.Deps(Tools.ControllerGen)
	return sh.RunV(binary("controller-gen"), "rbac:roleName=manager-role", "crd", "webhook",
		"paths=./...", "output:crd:artifacts:config=config/crd/bases")
}

// Generate generates the DeepCopy methods.
func Generate() error {
	mg.Deps(Tools.ControllerGen)
	return sh.RunV(binary("controller-gen"), "object:headerFile=hack/boilerplate.go.txt", "paths=./...")
}

// Fmt runs go fmt.
func Fmt() error { return sh.RunV("go", "fmt", "./...") }

// Vet runs go vet.
func Vet() error { return sh.RunV("go", "vet", "./...") }

// Test runs the unit and controller tests, against a real API server and etcd from envtest.
func Test() error {
	mg.SerialDeps(Manifests, Generate, Fmt, Vet)
	assets, err := envtestAssets()
	if err != nil {
		return err
	}
	packages, err := sh.Output("go", "list", "./...")
	if err != nil {
		return err
	}
	args := []string{"test", "-v"}
	for pkg := range strings.FieldsSeq(packages) {
		if !strings.Contains(pkg, "/e2e") {
			args = append(args, pkg)
		}
	}
	args = append(args, "-coverprofile", "cover.out")
	return testWithReport("unit", map[string]string{"KUBEBUILDER_ASSETS": assets}, args...)
}

// SetupEnvtest downloads the API server and etcd the tests run against.
func SetupEnvtest() error {
	_, err := envtestAssets()
	return err
}

func envtestAssets() (string, error) {
	mg.Deps(Tools.Envtest)
	version, err := envtestKubernetesVersion()
	if err != nil {
		return "", err
	}
	fmt.Printf("Setting up envtest binaries for Kubernetes %s\n", version)
	return sh.Output(binary("setup-envtest"), "use", version, "--bin-dir", localBin(), "-p", "path")
}

// SetupTestE2E creates the kind cluster the e2e tests run in, if it is not there.
func SetupTestE2E() error {
	clusters, err := sh.Output(kind, "get", "clusters")
	if err != nil {
		return fmt.Errorf("kind is needed for the e2e tests: %w", err)
	}
	if slices.Contains(strings.Fields(clusters), kindCluster) {
		fmt.Printf("Kind cluster %q already exists\n", kindCluster)
		return nil
	}
	return sh.RunV(kind, "create", "cluster", "--name", kindCluster)
}

// TestE2E runs the e2e tests in a kind cluster of their own, and removes it afterwards.
func TestE2E() error {
	mg.SerialDeps(SetupTestE2E, Manifests, Generate, Fmt, Vet)
	err := testWithReport("e2e", map[string]string{"KIND": kind, "KIND_CLUSTER": kindCluster},
		"test", "-tags=e2e", "./test/e2e/", "-v", "-ginkgo.v", "-timeout", "30m")
	return errors.Join(err, CleanupTestE2E())
}

// testResultsDir is where the JUnit XML reports are written. JUnit is kept as
// a secondary artifact (CI systems read it); the Allure report itself is built
// from allureResultsDir, which carries each test's body.
func testResultsDir() string { return env("TEST_RESULTS", "test-results") }

// allureResultsDir holds the Allure-native result files go2allure writes, one
// per test with the test's own output attached. `allure generate` reads this
// directory. JUnit alone leaves passing tests with an empty body ("no
// execution" in the report); these result files are what give them one.
func allureResultsDir() string { return env("ALLURE_RESULTS", "allure-results") }

// testWithReport runs a `go test` invocation as `go test -json`, streams the
// human-readable form to the terminal, and from the one JSON stream writes
// both a JUnit XML report (test-results/junit-<suite>.xml, for CI) and Allure
// result files with per-test bodies (allure-results/, for the Allure report).
// The test's own exit status is preserved: a failing suite still fails the
// target, with both reports written either way.
func testWithReport(suite string, environment map[string]string, args ...string) error {
	report, err := tool("go-junit-report", "github.com/jstemmer/go-junit-report/v2", goJunitReportVersion)
	if err != nil {
		return err
	}
	allure, err := goAllure()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(testResultsDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(allureResultsDir(), 0o755); err != nil {
		return err
	}
	xmlPath := filepath.Join(testResultsDir(), "junit-"+suite+".xml")

	// Run as JSON so both the test's per-test output (for Allure bodies) and
	// the structure (for JUnit) come from one stream. The first arg is "test".
	jsonArgs := append([]string{"test", "-json"}, args[1:]...)
	test := exec.Command("go", jsonArgs...)
	test.Env = os.Environ()
	for key, value := range environment {
		test.Env = append(test.Env, key+"="+value)
	}
	pipe, err := test.StdoutPipe()
	if err != nil {
		return err
	}
	test.Stderr = os.Stderr

	// The JSON stream is captured to a temp file, so the two converters and
	// the terminal echo each read the whole of it without racing on a pipe.
	jsonFile, err := os.CreateTemp("", "gotest-"+suite+"-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(jsonFile.Name()) }()
	defer func() { _ = jsonFile.Close() }()

	if err := test.Start(); err != nil {
		return err
	}
	if _, err := io.Copy(jsonFile, pipe); err != nil {
		return err
	}
	testErr := test.Wait()
	if _, err := jsonFile.Seek(0, io.SeekStart); err != nil {
		return err
	}

	// JUnit XML from the JSON stream (go-junit-report reads -parser gojson).
	xmlFile, err := os.Create(xmlPath)
	if err != nil {
		return err
	}
	junit := exec.Command(report, "-parser", "gojson")
	junit.Stdin = jsonFile
	junit.Stdout = xmlFile
	junit.Stderr = os.Stderr
	junitErr := junit.Run()
	_ = xmlFile.Close()

	// Allure result files (with bodies) from the same JSON stream.
	if _, err := jsonFile.Seek(0, io.SeekStart); err != nil {
		return err
	}
	allureCmd := exec.Command(allure, "-o", allureResultsDir())
	allureCmd.Stdin = jsonFile
	allureCmd.Stdout = os.Stdout
	allureCmd.Stderr = os.Stderr
	allureErr := allureCmd.Run()

	fmt.Printf("Wrote %s and Allure results to %s\n", xmlPath, allureResultsDir())
	if testErr != nil {
		return testErr
	}
	return errors.Join(junitErr, allureErr)
}

// CleanupTestE2E deletes the kind cluster the e2e tests ran in.
func CleanupTestE2E() error {
	return sh.RunV(kind, "delete", "cluster", "--name", kindCluster)
}

// Lint runs golangci-lint.
func Lint() error {
	mg.Deps(Tools.GolangciLint)
	return sh.RunV(binary("golangci-lint"), "run")
}

// LintFix runs golangci-lint and applies its fixes.
func LintFix() error {
	mg.Deps(Tools.GolangciLint)
	return sh.RunV(binary("golangci-lint"), "run", "--fix")
}

// LintConfig verifies the golangci-lint configuration.
func LintConfig() error {
	mg.Deps(Tools.GolangciLint)
	return sh.RunV(binary("golangci-lint"), "config", "verify")
}

// VerifyRBAC checks the RBAC markers for the mistake that breaks manifest generation.
func VerifyRBAC() error {
	files, err := filepath.Glob("internal/controller/*.go")
	if err != nil {
		return err
	}
	var broken []string
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for n, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "kubebuilder:rbac") && strings.Contains(line, "http://") {
				broken = append(broken, fmt.Sprintf("%s:%d", file, n+1))
			}
		}
	}
	if len(broken) > 0 {
		return fmt.Errorf("broken RBAC markers, fix before running manifests: %s", strings.Join(broken, ", "))
	}
	fmt.Println("RBAC markers are clean")
	return nil
}

// ── Build ────────────────────────────────────────────────────────────────────

// Build builds the manager binary into bin/.
func Build() error {
	mg.SerialDeps(Manifests, Generate, Fmt, Vet)
	return sh.RunV("go", "build", "-o", filepath.Join("bin", "manager"), "./cmd")
}

// Run runs the controller on this machine, against the current kubeconfig context.
func Run() error {
	mg.SerialDeps(Manifests, Generate, Fmt, Vet)
	return sh.RunV("go", "run", "./cmd")
}

// Ko builds the controller's image with ko, from .ko.yaml: no Dockerfile and no container daemon.
type Ko mg.Namespace

// Build builds the image for this machine's architecture into IMAGE_ARCHIVE, named IMG. Nothing is pushed.
func (Ko) Build() error {
	mg.Deps(Tools.Ko)
	repository, tag := splitImage(image)
	if err := os.MkdirAll(filepath.Dir(imageArchive), 0o755); err != nil {
		return err
	}
	return sh.RunWithV(map[string]string{"KO_DOCKER_REPO": repository}, binary("ko"), "build", "./cmd",
		"--bare", "--tags", tag, "--platform", "linux/"+runtime.GOARCH, "--sbom", "none",
		"--push=false", "--tarball", imageArchive)
}

// Load loads the image ko:build made into the kind cluster KIND_CLUSTER.
func (Ko) Load() error {
	// Newer kind (v0.29+) uses `-n`; older used `--name`. Pick whichever the
	// installed kind accepts so the suite is CI-version-independent.
	if err := sh.RunV(kind, "load", "image-archive", imageArchive, "-n", kindCluster); err != nil {
		// Fall back to the older --name flag on very old versions.
		return sh.RunV(kind, "load", "image-archive", imageArchive, "--name", kindCluster)
	}
	return nil
}

// Push builds the image for PLATFORMS and pushes it to IMG, with an SPDX SBOM attached.
func (Ko) Push() error {
	mg.Deps(Tools.Ko)
	repository, tag := splitImage(image)
	return sh.RunWithV(map[string]string{"KO_DOCKER_REPO": repository}, binary("ko"), "build", "./cmd",
		"--bare", "--tags", tag, "--platform", platforms, "--sbom", "spdx")
}

// splitImage separates an image reference into the repository ko publishes to
// and the tag it gives the image. A reference without a tag gets "latest"; a
// registry port (localhost:5000/controller) is not mistaken for one.
func splitImage(reference string) (repository, tag string) {
	name := path.Base(reference)
	if i := strings.LastIndex(name, ":"); i >= 0 {
		tag = name[i+1:]
		return strings.TrimSuffix(reference, ":"+tag), tag
	}
	return reference, "latest"
}

// BuildInstaller writes dist/install.yaml: the CRDs and the controller in one file, for IMG.
func BuildInstaller() error {
	mg.SerialDeps(Manifests, Generate, Tools.Kustomize)
	manifests, err := controllerManifests()
	if err != nil {
		return err
	}
	if err := os.MkdirAll("dist", 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join("dist", "install.yaml"), []byte(manifests), 0o644)
}

// ── Secure software supply chain CLI ─────────────────────────────────────────────────────────

// Cli builds and runs the supplychain CLI, which installs what the operator depends on.
type Cli mg.Namespace

// Build builds bin/supplychain.
func (Cli) Build() error {
	mg.SerialDeps(Fmt, Vet)
	return sh.RunV("go", "build", "-o", filepath.Join("bin", "supplychain"), "./cmd/cli")
}

// Install installs the secure software supply chain's dependencies onto the current cluster.
func (Cli) Install() error {
	mg.Deps(Cli.Build)
	return sh.RunV(binary("supplychain"), "install")
}

// Uninstall removes the secure software supply chain's dependencies from the current cluster.
func (Cli) Uninstall() error {
	mg.Deps(Cli.Build)
	return sh.RunV(binary("supplychain"), "uninstall")
}

// Status checks the secure software supply chain's dependencies.
func (Cli) Status() error {
	mg.Deps(Cli.Build)
	return sh.RunV(binary("supplychain"), "status")
}

// Reinstall uninstalls and then installs the secure software supply chain's dependencies.
func (Cli) Reinstall() error {
	mg.Deps(Cli.Build)
	_ = sh.RunV(binary("supplychain"), "uninstall")
	return sh.RunV(binary("supplychain"), "install")
}

// ── Deployment ───────────────────────────────────────────────────────────────

// Install installs the CRDs into the cluster of the current kubeconfig context.
func Install() error {
	mg.SerialDeps(Manifests, Tools.Kustomize)
	crds, err := sh.Output(binary("kustomize"), "build", "config/crd")
	if err != nil || strings.TrimSpace(crds) == "" {
		fmt.Println("No CRDs to install")
		return nil
	}
	return kubectlWith(crds, "apply", "-f", "-")
}

// Uninstall removes the CRDs, and with them every resource of those kinds.
func Uninstall() error {
	mg.SerialDeps(Manifests, Tools.Kustomize)
	crds, err := sh.Output(binary("kustomize"), "build", "config/crd")
	if err != nil || strings.TrimSpace(crds) == "" {
		fmt.Println("No CRDs to delete")
		return nil
	}
	return kubectlWith(crds, "delete", "--ignore-not-found="+ignoreNotFound(), "-f", "-")
}

// ForceUninstall removes the finalizers from the project's resources, then the CRDs.
// It is for a cluster whose controller is gone; nothing the finalizers guard is cleaned up.
// Only the kinds whose controllers actually set a finalizer are listed: SupplyChain,
// GitHubWebhook and SupplyChainPolicy. ImageBuild and the result kinds carry none —
// their children are cleaned up by owner-reference garbage collection, not a finalizer.
func ForceUninstall() error {
	for _, kind := range []string{"supplychain", "githubwebhook", "supplychainpolicy"} {
		fmt.Printf("Removing finalizers from %s resources\n", kind)
		list, err := sh.Output(kubectl, "get", kind, "--all-namespaces", "-o",
			`jsonpath={range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}`)
		if err != nil {
			continue // the kind is not installed
		}
		for line := range strings.SplitSeq(list, "\n") {
			if fields := strings.Fields(line); len(fields) == 2 {
				_ = sh.Run(kubectl, "patch", kind, fields[1], "-n", fields[0],
					"--type=merge", "-p", `{"metadata":{"finalizers":[]}}`)
			}
		}
	}
	return Uninstall()
}

// Deploy deploys the controller, running IMG, to the cluster of the current kubeconfig context.
func Deploy() error {
	mg.SerialDeps(Manifests, Tools.Kustomize)
	manifests, err := controllerManifests()
	if err != nil {
		return err
	}
	return kubectlWith(manifests, "apply", "-f", "-")
}

// Undeploy removes the controller.
func Undeploy() error {
	mg.Deps(Tools.Kustomize)
	manifests, err := sh.Output(binary("kustomize"), "build", "config/default")
	if err != nil {
		return err
	}
	return kubectlWith(manifests, "delete", "--ignore-not-found="+ignoreNotFound(), "-f", "-")
}

// controllerManifests renders config/default with the controller's image set
// to IMG. Kustomize can only set an image by editing the kustomization, which
// is a tracked file, so it is put back as it was afterwards.
func controllerManifests() (string, error) {
	kustomization := filepath.Join("config", "manager", "kustomization.yaml")
	original, err := os.ReadFile(kustomization)
	if err != nil {
		return "", err
	}
	defer func() { _ = os.WriteFile(kustomization, original, 0o644) }()

	edit := exec.Command(binary("kustomize"), "edit", "set", "image", "controller="+image)
	edit.Dir = filepath.Dir(kustomization)
	if out, err := edit.CombinedOutput(); err != nil {
		return "", fmt.Errorf("setting the image: %w: %s", err, out)
	}
	return sh.Output(binary("kustomize"), "build", "config/default")
}

// kubectlWith runs kubectl with manifests on its standard input.
func kubectlWith(manifests string, args ...string) error {
	file, err := os.CreateTemp("", "manifests-*.yaml")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err := file.WriteString(manifests); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	for i, arg := range args {
		if arg == "-" && i > 0 && args[i-1] == "-f" {
			args[i] = file.Name()
		}
	}
	return sh.RunV(kubectl, args...)
}

func ignoreNotFound() string { return env("IGNORE_NOT_FOUND", "false") }
