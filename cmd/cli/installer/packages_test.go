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
		"Fulcio":          "Fulcio",
		"fulcio":          "Fulcio",
		"FULCIO":          "Fulcio",
		"metallb-install": "MetalLB Install",
		"nginx":           "NGINX Ingress Controller", // unique prefix
		"cert-manager":    "cert-manager",
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
// then returns those plus the image pull-ahead, in install order regardless of
// the order they were asked for.
func TestSelectStepsNarrowsAndKeepsImagePull(t *testing.T) {
	i := spiffeInstaller()
	if err := i.SelectSteps([]string{"rekor", "fulcio"}); err != nil {
		t.Fatal(err)
	}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 3 {
		t.Fatalf("got %d steps, want Images + Fulcio + Rekor", len(steps))
	}
	if !steps[0].PullsImages {
		t.Errorf("the first step is %q; images are still pulled ahead", steps[0].Name)
	}
	// Install order is Fulcio before Rekor, not the order given.
	if steps[1].Name != "Fulcio" || steps[2].Name != "Rekor" {
		t.Errorf("steps = %q, %q; want Fulcio then Rekor in install order", steps[1].Name, steps[2].Name)
	}
}

// With no selection, the full install runs.
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

// --list shows the packages a reader can name, and leaves out the Images step,
// which applies nothing of its own.
func TestStepNamesOmitsImages(t *testing.T) {
	for _, name := range spiffeInstaller().StepNames() {
		if name == "Images" {
			t.Error("StepNames lists the Images pull-ahead step; it is not installable on its own")
		}
	}
}
