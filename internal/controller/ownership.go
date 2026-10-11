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
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// managedLabel marks an object this operator created. Only those are given
// owners: an object somebody else made is used and left as it is.
const managedLabel = "blanketops.dev/managed"

// shareWith records owner as one of the owners of an object several resources
// may use at once: the ServiceAccount more than one SupplyChain builds with,
// or the Tasks every SupplyChain in a namespace runs. Kubernetes removes the
// object when the last of its owners is gone, and not before. It reports
// whether the object was changed.
func shareWith(owner, obj client.Object, scheme *runtime.Scheme) (bool, error) {
	owned, err := controllerutil.HasOwnerReference(obj.GetOwnerReferences(), owner, scheme)
	if err != nil || owned {
		return false, err
	}
	return true, controllerutil.SetOwnerReference(owner, obj, scheme)
}

// managed reports whether this operator created the object.
func managed(obj client.Object) bool {
	return obj.GetLabels()[managedLabel] == "true"
}
