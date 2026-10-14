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

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// Every image the install runs is asked for at the start: those of the
// workloads, of the Jobs that set things up, and of the Tasks the first build
// would otherwise have to pull.
func TestStepImages(t *testing.T) {
	i := &Installer{opts: Options{SigningIdentity: IdentitySPIFFE}}
	steps, err := i.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if !steps[0].PullsImages {
		t.Fatalf("the first step is %q; images have to be asked for before anything else", steps[0].Name)
	}
	images, err := stepImages(steps)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, image := range images {
		if seen[image] {
			t.Errorf("%s is listed twice", image)
		}
		seen[image] = true
		if strings.Contains(image, "$(") || strings.TrimSpace(image) != image || image == "" {
			t.Errorf("%q is not an image that can be pulled", image)
		}
	}
	for _, want := range []string{
		"hashicorp/vault:2.0.3",                               // a StatefulSet
		"quay.io/jetstack/cert-manager-controller:v1.19.4",    // a Deployment
		"ghcr.io/spiffe/spire-agent:1.15.3",                   // a DaemonSet
		"docker.io/nginxinc/nginx-unprivileged:1.30.0-alpine", // the tls containers
		"gcr.io/projectsigstore/cosign:v2.2.3",                // a Task's step
	} {
		if !seen[want] {
			t.Errorf("%s is not among the %d images pulled ahead", want, len(images))
		}
	}
	// What Tekton adds to every step is named in its controller's arguments,
	// and what a Task runs by default in its parameters.
	for _, want := range []string{
		"/entrypoint-", "cgr.dev/chainguard/busybox", "git-clone:v1.1.0", "buildah/stable", "trivy-db",
	} {
		if !hasImage(images, want) {
			t.Errorf("no image matching %q is pulled ahead", want)
		}
	}
	for _, image := range images {
		if !looksLikeImage(image) && !strings.Contains(image, ":") {
			t.Errorf("%q does not look like an image", image)
		}
	}
	if !hasImage(images, "/createctconfig") {
		t.Error("the images of the setup Jobs are not pulled ahead")
	}

	// Without SPIRE, its images are not pulled.
	kubernetes := &Installer{opts: Options{SigningIdentity: IdentityKubernetes}}
	steps, _ = kubernetes.stepsToRun()
	if images, _ = stepImages(steps); hasImage(images, "spire") {
		t.Error("SPIRE's images are pulled for an install that does not use SPIRE")
	}
	// And the step can be left out.
	skipped := &Installer{opts: Options{NoImagePull: true}}
	if steps, _ = skipped.stepsToRun(); steps[0].PullsImages {
		t.Error("--no-image-pull did not leave the step out")
	}
}

func hasImage(images []string, part string) bool {
	for _, image := range images {
		if strings.Contains(image, part) {
			return true
		}
	}
	return false
}

// The pod that pulls an image is not meant to run. These are the states it
// was seen in on a cluster: with the image there it fails to start, and that
// counts as pulled.
func TestImagePullState(t *testing.T) {
	pod := func(status map[string]any) *unstructured.Unstructured {
		obj := map[string]any{"status": map[string]any{}}
		if status != nil {
			obj["status"] = map[string]any{"containerStatuses": []any{status}}
		}
		return &unstructured.Unstructured{Object: obj}
	}
	waiting := func(reason string) map[string]any {
		return map[string]any{"state": map[string]any{"waiting": map[string]any{"reason": reason}}}
	}
	terminated := func(reason, imageID string) map[string]any {
		return map[string]any{"imageID": imageID, "state": map[string]any{"terminated": map[string]any{"reason": reason}}}
	}
	for name, tc := range map[string]struct {
		status map[string]any
		want   string
	}{
		"not scheduled yet":     {nil, imagePulling},
		"downloading":           {waiting("ContainerCreating"), imagePulling},
		"pulled, did not start": {terminated("StartError", "sha256:abc"), imagePulled},
		"pulled, ran":           {terminated("Completed", ""), imagePulled},
		"pulled, cannot create": {waiting("CreateContainerError"), imagePulled},
		"no such image":         {waiting("ErrImagePull"), imageFailing},
		"backing off":           {waiting("ImagePullBackOff"), imageFailing},
	} {
		if got, _ := imagePullState(pod(tc.status)); got != tc.want {
			t.Errorf("%s: %s, want %s", name, got, tc.want)
		}
	}
}

// The progress line says what is being waited for, by name.
func TestPullProgress(t *testing.T) {
	if got, want := pullProgress(57, 57, nil), "Pulling images: 57 of 57 done"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	got := pullProgress(12, 57,
		[]string{"vault:2.0.3", "redis", "rekor-server:v1.5.1", "fulcio:v1.8.5", "ct_server:v0.7.31"})
	want := "Pulling images: 12 of 57 done · waiting for ct_server:v0.7.31, fulcio:v1.8.5, redis and 2 more"
	if got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if got := shortImage("ghcr.io/sigstore/rekor/rekor-server:v1.5.1@sha256:63c8"); got != "rekor-server:v1.5.1" {
		t.Errorf("shortImage = %q", got)
	}
}

// Resuming an install pulls ahead for the steps that are left, and for no
// others; running one step pulls only as that step does.
func TestResumingPullsImagesForWhatIsLeft(t *testing.T) {
	resumed := &Installer{opts: Options{SigningIdentity: IdentitySPIFFE, FromStep: "sonarqube"}}
	steps, err := resumed.stepsToRun()
	if err != nil {
		t.Fatal(err)
	}
	if !steps[0].PullsImages || steps[1].Name != "SonarQube" {
		t.Fatalf("resuming at SonarQube runs %q then %q", steps[0].Name, steps[1].Name)
	}
	images, _ := stepImages(steps[1:])
	if !hasImage(images, "sonarqube") || hasImage(images, "rekor") {
		t.Errorf("resuming at SonarQube pulls %v", images)
	}

	one := &Installer{opts: Options{SigningIdentity: IdentitySPIFFE, OnlyStep: "vault"}}
	if steps, _ = one.stepsToRun(); len(steps) != 1 || steps[0].PullsImages {
		t.Errorf("--only-step runs %d steps", len(steps))
	}
	first := &Installer{opts: Options{SigningIdentity: IdentitySPIFFE, FromStep: "images"}}
	if steps, _ = first.stepsToRun(); !steps[0].PullsImages || steps[1].PullsImages {
		t.Error("resuming at the first step repeats it")
	}
}

// The pod that pulls an image is named after it, so that a run that follows
// an interrupted one asks for the same pods and not for new ones.
func TestImagePullPodIsNamedAfterItsImage(t *testing.T) {
	a, again := imagePullPod("hashicorp/vault:2.0.3"), imagePullPod("hashicorp/vault:2.0.3")
	b := imagePullPod("hashicorp/vault:2.0.4")
	if a.GetName() != again.GetName() || a.GetName() == b.GetName() || !strings.HasPrefix(a.GetName(), "pull-") {
		t.Errorf("pod names: %s, %s, %s", a.GetName(), again.GetName(), b.GetName())
	}
	if a.GetAnnotations()[imagePullAnnotation] != "hashicorp/vault:2.0.3" || a.GetNamespace() != imagePullNamespace {
		t.Errorf("pod: %v in %s", a.GetAnnotations(), a.GetNamespace())
	}
}
