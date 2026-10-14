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

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

// Versions of the tools the build downloads into bin/. Each can be overridden
// from the environment.
var (
	kustomizeVersion      = env("KUSTOMIZE_VERSION", "v5.8.1")
	controllerGenVersion  = env("CONTROLLER_TOOLS_VERSION", "v0.20.1")
	golangciLintVersion   = env("GOLANGCI_LINT_VERSION", "v2.8.0")
	koVersion             = env("KO_VERSION", "v0.18.1")
	goJunitReportVersion  = env("GO_JUNIT_REPORT_VERSION", "v2.1.0")
	kubectl               = env("KUBECTL", "kubectl")
	kind                  = env("KIND", "kind")
	customLinterConfig    = ".custom-gcl.yml"
	releaseVersionPattern = regexp.MustCompile(`^v?(\d+)\.(\d+)`)
)

// Tools downloads the tools the build uses into bin/.
type Tools mg.Namespace

// Kustomize downloads kustomize if necessary.
func (Tools) Kustomize() error {
	_, err := tool("kustomize", "sigs.k8s.io/kustomize/kustomize/v5", kustomizeVersion)
	return err
}

// ControllerGen downloads controller-gen if necessary.
func (Tools) ControllerGen() error {
	_, err := tool("controller-gen", "sigs.k8s.io/controller-tools/cmd/controller-gen", controllerGenVersion)
	return err
}

// Envtest downloads setup-envtest if necessary.
func (Tools) Envtest() error {
	version, err := envtestVersion()
	if err != nil {
		return err
	}
	_, err = tool("setup-envtest", "sigs.k8s.io/controller-runtime/tools/setup-envtest", version)
	return err
}

// Ko downloads ko if necessary.
func (Tools) Ko() error {
	_, err := tool("ko", "github.com/google/ko", koVersion)
	return err
}

// GoJunitReport downloads go-junit-report if necessary. It turns `go test`
// output into JUnit XML, which Allure ingests to build its report.
func (Tools) GoJunitReport() error {
	_, err := tool("go-junit-report", "github.com/jstemmer/go-junit-report/v2", goJunitReportVersion)
	return err
}

// GolangciLint downloads golangci-lint if necessary, and builds it with the
// plugins named in .custom-gcl.yml when that file exists.
func (Tools) GolangciLint() error {
	plain, err := tool("golangci-lint", "github.com/golangci/golangci-lint/v2/cmd/golangci-lint", golangciLintVersion)
	if err != nil {
		return err
	}
	if _, err := os.Stat(customLinterConfig); err != nil {
		return nil
	}
	custom := "golangci-lint-" + golangciLintVersion + "-custom"
	if _, err := os.Stat(filepath.Join(localBin(), custom)); err != nil {
		fmt.Println("Building golangci-lint with plugins")
		if err := sh.RunV(plain, "custom", "--destination", localBin(), "--name", custom); err != nil {
			return err
		}
	}
	return link(filepath.Join(localBin(), custom), binary("golangci-lint"))
}

// localBin is where tools and build output go.
func localBin() string {
	if dir := os.Getenv("LOCALBIN"); dir != "" {
		return dir
	}
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return filepath.Join(wd, "bin")
}

// binary is the path of a tool in bin/.
func binary(name string) string { return filepath.Join(localBin(), name) }

// tool installs one version of a Go tool as bin/<name>-<version> and points
// bin/<name> at it, so that changing the version installs the new one and
// going back does not download the old one again.
func tool(name, pkg, version string) (string, error) {
	versioned := binary(name + "-" + version)
	if _, err := os.Stat(versioned); err != nil {
		if err := os.MkdirAll(localBin(), 0o755); err != nil {
			return "", err
		}
		fmt.Printf("Downloading %s@%s\n", pkg, version)
		_ = os.Remove(binary(name))
		if err := sh.RunWithV(map[string]string{"GOBIN": localBin()}, "go", "install", pkg+"@"+version); err != nil {
			return "", err
		}
		if err := os.Rename(binary(name), versioned); err != nil {
			return "", err
		}
	}
	return versioned, link(versioned, binary(name))
}

// link points the symbolic link at to target, replacing what is there.
func link(target, at string) error {
	if current, err := os.Readlink(at); err == nil && current == target {
		return nil
	}
	_ = os.Remove(at)
	return os.Symlink(target, at)
}

// moduleVersion is the version of a module this project builds against.
func moduleVersion(module string) (string, error) {
	version, err := sh.Output("go", "list", "-m", "-f",
		"{{if .Replace}}{{.Replace.Version}}{{else}}{{.Version}}{{end}}", module)
	if err != nil {
		return "", err
	}
	if !releaseVersionPattern.MatchString(version) {
		return "", fmt.Errorf("%s has no tagged version (%q)", module, version)
	}
	return strings.TrimSpace(version), nil
}

// envtestVersion is the setup-envtest branch that matches controller-runtime,
// for example release-0.22.
func envtestVersion() (string, error) {
	if version := os.Getenv("ENVTEST_VERSION"); version != "" {
		return version, nil
	}
	version, err := moduleVersion("sigs.k8s.io/controller-runtime")
	if err != nil {
		return "", fmt.Errorf("set ENVTEST_VERSION: %w", err)
	}
	parts := releaseVersionPattern.FindStringSubmatch(version)
	return "release-" + parts[1] + "." + parts[2], nil
}

// envtestKubernetesVersion is the Kubernetes version the tests' API server
// and etcd are downloaded for, for example 1.35, which follows k8s.io/api.
func envtestKubernetesVersion() (string, error) {
	if version := os.Getenv("ENVTEST_K8S_VERSION"); version != "" {
		return version, nil
	}
	version, err := moduleVersion("k8s.io/api")
	if err != nil {
		return "", fmt.Errorf("set ENVTEST_K8S_VERSION: %w", err)
	}
	return "1." + releaseVersionPattern.FindStringSubmatch(version)[2], nil
}

// env is an environment variable, or a default when it is not set.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
