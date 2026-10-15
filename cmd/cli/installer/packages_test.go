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
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// spiffeInstaller has no Kubernetes client; the SPIFFE identity avoids the one
// Skip rule that reads the cluster (cert-manager ownership), so the step list
// resolves from the static install order alone.
func spiffeInstaller() *Installer {
	return &Installer{opts: Options{SigningIdentity: IdentitySPIFFE, TrustDomain: "example.test"}}
}

// A token names exactly one package: by its exact name, its slug, or a unique
// prefix of the slug, case-insensitively.
func TestResolveStepMatches(t *testing.T) {
	i := spiffeInstaller()
	for token, want := range map[string]string{
		"Fulcio":             "Fulcio",
		"fulcio":             "Fulcio",
		"FULCIO":             "Fulcio",
		"metallb-install":    "MetalLB Install",
		"nginx":              "NGINX Ingress Controller", // unique prefix
		"cert-manager":       "cert-manager",
		"ingress-controller": "NGINX Ingress Controller", // unique substring, not a prefix
	} {
		got, err := i.resolveStep(token)
		if err != nil {
			t.Errorf("resolveStep(%q): %v", token, err)
			continue
		}
		if got != want {
			t.Errorf("resolveStep(%q) = %q, want %q", token, got, want)
		}
	}
}

// A token that could be more than one package is refused, and the message
// names the candidates so the reader can pick.
func TestResolveStepAmbiguous(t *testing.T) {
	_, err := spiffeInstaller().resolveStep("metallb")
	if err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Fatalf("resolveStep(metallb) error = %v, want an ambiguity error", err)
	}
	if !strings.Contains(err.Error(), "metallb-install") || !strings.Contains(err.Error(), "metallb-dependencies") {
		t.Errorf("the ambiguity error does not list both candidates: %v", err)
	}
}

// An unknown token is refused, and the message lists the packages there are.
func TestResolveStepUnknown(t *testing.T) {
	_, err := spiffeInstaller().resolveStep("there-is-no-such-package")
	if err == nil || !strings.Contains(err.Error(), "no step") {
		t.Fatalf("resolveStep of an unknown token error = %v", err)
	}
	if !strings.Contains(err.Error(), "fulcio") {
		t.Errorf("the error does not list the packages: %v", err)
	}
}

// SelectSteps narrows an install to exactly the named packages, and stepsToRun
// then returns those in install order regardless of the order they were asked
// for. Each package pulls its own images when applied; there is no pull-ahead.
func TestSelectStepsNarrowsToNamedPackages(t *testing.T) {
	i := spiffeInstaller()
	if err := i.SelectSteps([]string{"rekor", "fulcio"}); err != nil {
		t.Fatal(err)
	}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want Fulcio + Rekor", len(steps))
	}
	// Install order is Fulcio before Rekor, not the order given.
	if steps[0].Name != "Fulcio" || steps[1].Name != "Rekor" {
		t.Errorf("steps = %q, %q; want Fulcio then Rekor in install order", steps[0].Name, steps[1].Name)
	}
}

// With no selection, stepsToRun returns the whole install. (The CLI refuses a
// bare `install` with no package; stepsToRun itself still yields them all.)
func TestSelectStepsEmptyIsFullInstall(t *testing.T) {
	i := spiffeInstaller()
	if err := i.SelectSteps(nil); err != nil {
		t.Fatal(err)
	}
	full, _ := i.stepsToRun()
	if len(full) < 10 {
		t.Errorf("an empty selection runs %d steps; it should be the whole install", len(full))
	}
}

// --list shows the packages a reader can name: every installable step, and
// MetalLB Install (the first) among them.
func TestStepNamesListsInstallablePackages(t *testing.T) {
	names := spiffeInstaller().StepNames()
	if len(names) == 0 || names[0] != "MetalLB Install" {
		t.Errorf("StepNames = %v; want it to start with MetalLB Install", names)
	}
}

// The "install order" table in docs/installation.md is documented as
// authoritative — the exact order the installer applies the packages. This
// keeps it honest: the package names in that table, in order, must equal the
// names in installOrder. If a step is added, removed or reordered in code and
// the doc is not updated (or vice versa), this fails.
func TestInstallOrderDocMatchesCode(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "installation.md"))
	if err != nil {
		t.Fatal(err)
	}
	// Rows of the "# | Package | Condition to run" table look like
	// "| 1 | MetalLB Install | always |". Pull the package column, in order.
	row := regexp.MustCompile(`^\|\s*\d+\s*\|\s*([^|]+?)\s*\|`)
	var documented []string
	for _, line := range strings.Split(string(data), "\n") {
		if m := row.FindStringSubmatch(line); m != nil {
			documented = append(documented, m[1])
		}
	}

	var coded []string
	for _, s := range installOrder {
		coded = append(coded, s.Name)
	}

	if len(documented) != len(coded) {
		t.Fatalf("docs list %d install steps, installOrder has %d:\n  docs: %v\n  code: %v",
			len(documented), len(coded), documented, coded)
	}
	for i := range coded {
		if documented[i] != coded[i] {
			t.Errorf("step %d: docs say %q, installOrder has %q", i+1, documented[i], coded[i])
		}
	}
}
