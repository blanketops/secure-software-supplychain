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

package results

import (
	tektonv1beta1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
)

// A build's result is published to Tekton as a CustomRun that refers to the
// ImageBuildResult kind. Tekton shows it with the runs it knows, and anything
// that reads Tekton sees what was built, whether the gates passed, and who
// signed it where in the transparency log.
//
// It is a run of its own, not a task of the build's pipeline. Tekton Chains
// only signs a PipelineRun whose children are all TaskRuns; a custom task in
// the pipeline would cost the run its provenance.
const (
	RunAPIVersion = "supplychain.blanketops.dev/v1alpha1"
	RunKind       = "ImageBuildResult"

	// RunParamImageBuild names the ImageBuild whose result the run publishes.
	RunParamImageBuild = "image-build"

	// Labels that tie the run to what it reports on.
	LabelImageBuild  = "blanketops.dev/image-build"
	LabelSupplyChain = "blanketops.dev/supply-chain"
	LabelPipelineRun = "blanketops.dev/pipeline-run"
)

// RunName is the name of the CustomRun that publishes the result of a
// PipelineRun.
func RunName(pipelineRun string) string {
	const suffix = "-result"
	if len(pipelineRun)+len(suffix) > 253 {
		pipelineRun = pipelineRun[:253-len(suffix)]
	}
	return pipelineRun + suffix
}

// NewRun is the CustomRun that publishes the result of ib. The ImageBuild
// owns it, so it goes when the build does.
func NewRun(ib *supplyv1alpha1.ImageBuild, pipelineRun string) *tektonv1beta1.CustomRun {
	controller, blockOwnerDeletion := true, true
	labels := map[string]string{
		"blanketops.dev/managed": "true",
		LabelImageBuild:          ib.LabelValue(),
		LabelSupplyChain:         ib.Spec.SupplyChainRef.Name,
	}
	if len(pipelineRun) <= 63 {
		labels[LabelPipelineRun] = pipelineRun
	}
	return &tektonv1beta1.CustomRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      RunName(pipelineRun),
			Namespace: ib.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion:         supplyv1alpha1.GroupVersion.String(),
				Kind:               "ImageBuild",
				Name:               ib.Name,
				UID:                ib.UID,
				Controller:         &controller,
				BlockOwnerDeletion: &blockOwnerDeletion,
			}},
		},
		Spec: tektonv1beta1.CustomRunSpec{
			CustomRef: &tektonv1beta1.TaskRef{APIVersion: RunAPIVersion, Kind: RunKind},
			Params: tektonv1beta1.Params{{
				Name:  RunParamImageBuild,
				Value: tektonv1beta1.ParamValue{Type: tektonv1beta1.ParamTypeString, StringVal: ib.Name},
			}},
		},
	}
}

// IsRun reports whether a CustomRun is one of these.
func IsRun(run *tektonv1beta1.CustomRun) bool {
	ref := run.Spec.CustomRef
	return ref != nil && ref.APIVersion == RunAPIVersion && string(ref.Kind) == RunKind
}
