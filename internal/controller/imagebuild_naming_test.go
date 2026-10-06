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
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	supplychainv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// A push names its build <supplychain>-<branch>-<sha>; a build made by hand
// can be named anything. Whatever the name, the PipelineRun's must be valid:
// "your-app-demo" used to give "run-your-app-demo-", which the API server
// rejects, and the build failed before it started.
func TestPipelineRunName(t *testing.T) {
	for build, want := range map[string]string{
		"your-app-main-5728a2197c0d4e5f": "run-your-app-main-5728a219",
		"your-app-demo":                  "run-your-app-demo",
		"your-app-manual-001":            "run-your-app-manual-001",
		"something-else":                 "run-your-app-something-else",
		"oneword":                        "run-your-app-oneword",
		"your-app-" + strings.Repeat("feature-", 8) + "0123456789abcdef": "",
	} {
		ib := &supplychainv1alpha1.ImageBuild{
			ObjectMeta: metav1.ObjectMeta{Name: build},
			Spec: supplychainv1alpha1.ImageBuildSpec{
				SupplyChainRef: supplychainv1alpha1.LocalObjectRef{Name: "your-app"},
			},
		}
		got := pipelineRunName(ib)
		if want != "" && got != want {
			t.Errorf("pipelineRunName(%q) = %q, want %q", build, got, want)
		}
		if len(got) > 63 {
			t.Errorf("pipelineRunName(%q) = %q is %d characters", build, got, len(got))
		}
		if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
			t.Errorf("pipelineRunName(%q) = %q is not a valid name: %v", build, got, errs)
		}
	}
}
