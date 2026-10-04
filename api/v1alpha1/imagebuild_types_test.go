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
package v1alpha1

import (
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func TestImageBuildLabelValue(t *testing.T) {
	const sha = "200506848db5cd7ceefb5c33b090dc23d1ddea2c"
	build := func(name string) *ImageBuild {
		return &ImageBuild{ObjectMeta: metav1.ObjectMeta{Name: name}}
	}

	short := "for-kaniko-app-main-" + sha
	if got := build(short).LabelValue(); got != short {
		t.Errorf("LabelValue() = %q, want the name unchanged when it fits", got)
	}

	// The name a push to a longer branch produces; it does not fit in a label.
	long := "for-kaniko-app-policy-test-" + sha
	got := build(long).LabelValue()
	if errs := validation.IsValidLabelValue(got); len(errs) > 0 {
		t.Errorf("LabelValue() = %q is not a valid label value: %v", got, errs)
	}
	if got != build(long).LabelValue() {
		t.Error("LabelValue() is not stable for the same name")
	}

	// Two long names that share their first 63 characters must not collide.
	other := build(long + "-retry").LabelValue()
	if other == got {
		t.Errorf("different builds share the label value %q", got)
	}
	if errs := validation.IsValidLabelValue(other); len(errs) > 0 {
		t.Errorf("LabelValue() = %q is not a valid label value: %v", other, errs)
	}
}
