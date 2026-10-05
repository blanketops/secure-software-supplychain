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
package signing

import (
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	// SPIREClassName is the class the installer's SPIRE controller manager
	// reconciles.
	SPIREClassName = "spire-server-spire"

	// SPIRENodesPath is the path of the SPIFFE ID the installer registers for
	// the cluster's nodes as a whole (ClusterStaticEntry "supply-chain-nodes").
	SPIRENodesPath = "/supply-chain/nodes"
)

// ClusterStaticEntryGVK is SPIRE's registration entry resource.
var ClusterStaticEntryGVK = schema.GroupVersionKind{
	Group: "spire.spiffe.io", Version: "v1alpha1", Kind: "ClusterStaticEntry",
}

// WorkloadEntryName is the name of the registration entry of a ServiceAccount.
func WorkloadEntryName(namespace, serviceAccount string) string {
	return namespace + "-" + serviceAccount
}

// WorkloadEntry registers a ServiceAccount's SPIFFE identity with SPIRE ahead
// of time.
//
// SPIRE's per-pod identities are registered only once a pod exists, and reach
// the node agent some seconds later. A build step that signs as soon as its
// pod starts asks before that and is refused. An entry that selects the
// ServiceAccount rather than one pod is already there when the pod starts.
func WorkloadEntry(identity Identity, namespace, serviceAccount string) *unstructured.Unstructured {
	entry := &unstructured.Unstructured{}
	entry.SetGroupVersionKind(ClusterStaticEntryGVK)
	entry.SetName(WorkloadEntryName(namespace, serviceAccount))
	entry.SetLabels(map[string]string{"blanketops.dev/managed": "true"})
	entry.Object["spec"] = map[string]any{
		"className": SPIREClassName,
		"spiffeID":  identity.Subject(namespace, serviceAccount),
		"parentID":  fmt.Sprintf("spiffe://%s%s", identity.TrustDomain, SPIRENodesPath),
		"selectors": []any{
			"k8s:ns:" + namespace,
			"k8s:sa:" + serviceAccount,
		},
	}
	return entry
}
