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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
)

// Almost all of an install's time is image pulls, and without help they
// happen one step at a time: a step's images are only asked for when the
// installer reaches it, and each step waits for its own before the next
// starts. The "Images" step asks for every image the install will use at the
// start, all at once, so that the node downloads continuously, and in
// parallel when its kubelet allows that. Later steps then find their images
// already there.
//
// It is an optimisation and never fails an install: an image it could not
// pull is pulled again, with its own errors, by the step that needs it.

const (
	// imagePullNamespace holds the pods that exist only to pull images. It is
	// removed when the step ends.
	imagePullNamespace = "supply-chain-image-pull"
	// imagePullGiveUp is how long images that fail to pull are retried while
	// nothing else is still downloading.
	imagePullGiveUp = 5 * time.Minute
)

var namespaceGVR = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}

// stepImages lists every container image the steps' manifests run, in the
// order the steps are installed and without repeats. It includes the images
// of Jobs and of Tekton Tasks' steps, which the first build would otherwise
// have to pull. An image given as a parameter is left out: what it will be is
// not known here.
func stepImages(steps []step) ([]string, error) {
	var images []string
	seen := map[string]bool{}
	for _, s := range steps {
		for _, dir := range s.Paths {
			entries, err := manifests.Dependencies.ReadDir(dir)
			if err != nil {
				return nil, err
			}
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
					continue
				}
				file, err := manifests.Dependencies.Open(dir + "/" + entry.Name())
				if err != nil {
					return nil, err
				}
				decoder := utilyaml.NewYAMLOrJSONDecoder(file, 4096)
				for {
					var obj map[string]any
					if err := decoder.Decode(&obj); err != nil {
						break
					}
					collectImages(obj, false, func(image string) {
						if !seen[image] {
							seen[image] = true
							images = append(images, image)
						}
					})
				}
				_ = file.Close()
			}
		}
	}
	return images, nil
}

// collectImages finds the "image" of every entry of a list of containers,
// wherever in an object such a list is.
func collectImages(v any, inContainers bool, found func(string)) {
	switch value := v.(type) {
	case map[string]any:
		if image, ok := value["image"].(string); ok && inContainers {
			if image = strings.TrimSpace(image); image != "" && !strings.Contains(image, "$(") {
				found(image)
			}
		}
		for key, child := range value {
			switch key {
			case "containers", "initContainers", "steps", "sidecars":
				collectImages(child, true, found)
			default:
				collectImages(child, false, found)
			}
		}
	case []any:
		for _, child := range value {
			collectImages(child, inContainers, found)
		}
	}
}

// Pull states of one image.
const (
	imagePulled  = "pulled"
	imagePulling = "pulling"
	imageFailing = "failing"
)

// imagePullState reads from a pod how far the pull of its one image is. The
// pod's container is not meant to run, and whether it does is not looked at:
// any state that can only be reached with the image present means pulled.
func imagePullState(pod *unstructured.Unstructured) (state, reason string) {
	statuses, _, _ := unstructured.NestedSlice(pod.Object, "status", "containerStatuses")
	if len(statuses) == 0 {
		return imagePulling, ""
	}
	status, _ := statuses[0].(map[string]any)
	if id, _ := status["imageID"].(string); id != "" {
		return imagePulled, ""
	}
	if waiting, found, _ := unstructured.NestedMap(status, "state", "waiting"); found {
		reason, _ := waiting["reason"].(string)
		switch reason {
		case "", "ContainerCreating", "PodInitializing":
			return imagePulling, ""
		case "ErrImagePull", "ImagePullBackOff", "InvalidImageName", "ErrImageNeverPull", "RegistryUnavailable":
			return imageFailing, reason
		}
	}
	// Running, terminated, or failed to start: the image is there.
	return imagePulled, ""
}

// imagePullPod is a pod whose only purpose is to make the node pull an image.
// Its command does not exist in any image, so nothing of the image runs.
func imagePullPod(index int, image string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":        fmt.Sprintf("pull-%03d", index),
			"namespace":   imagePullNamespace,
			"annotations": map[string]any{"supply-chain.blanketops.dev/image": image},
		},
		"spec": map[string]any{
			"restartPolicy":                 "Never",
			"automountServiceAccountToken":  false,
			"enableServiceLinks":            false,
			"terminationGracePeriodSeconds": int64(0),
			"tolerations":                   []any{map[string]any{"operator": "Exists"}},
			"containers": []any{map[string]any{
				"name":            "pull",
				"image":           image,
				"imagePullPolicy": "IfNotPresent",
				"command":         []any{"/supply-chain-image-pull-only"},
				"resources": map[string]any{
					"requests": map[string]any{"cpu": "1m", "memory": "4Mi"},
				},
			}},
		},
	}}
}

// shortImage is an image's name without its registry path and digest, for a
// progress line.
func shortImage(image string) string {
	image, _, _ = strings.Cut(image, "@")
	if i := strings.LastIndex(image, "/"); i >= 0 {
		image = image[i+1:]
	}
	return image
}

// pullProgress is the progress line: how many are done and which are being
// waited for.
func pullProgress(done, total int, waiting []string) string {
	sort.Strings(waiting)
	names := waiting
	if len(names) > 3 {
		names = names[:3]
	}
	line := fmt.Sprintf("Pulling images: %d of %d done", done, total)
	if len(waiting) > 0 {
		line += " · waiting for " + strings.Join(names, ", ")
		if more := len(waiting) - len(names); more > 0 {
			line += fmt.Sprintf(" and %d more", more)
		}
	}
	return line
}

// prePullImages makes the node pull every image the steps will use, and
// waits for them. It reports what could not be pulled and returns no error:
// see the comment at the top of this file.
func (i *Installer) prePullImages(ctx context.Context, steps []step) {
	images, err := stepImages(steps)
	if err != nil || len(images) == 0 {
		return
	}
	if serial := i.nodesPullingOneAtATime(ctx); len(serial) > 0 {
		fmt.Printf("  ! %s pulls one image at a time (the kubelet's serializeImagePulls).\n"+
			"    Images are still pulled from the start, but not in parallel.\n"+
			"    On kind, hack/kind-parallel-pulls.sh turns parallel pulls on.\n", strings.Join(serial, ", "))
	}

	namespaces := i.dynamic.Resource(namespaceGVR)
	pods := i.dynamic.Resource(podGVR).Namespace(imagePullNamespace)
	cleanup := func() {
		policy := metav1.DeletePropagationBackground
		_ = namespaces.Delete(context.WithoutCancel(ctx), imagePullNamespace,
			metav1.DeleteOptions{PropagationPolicy: &policy})
	}
	if err := i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": imagePullNamespace},
	}}); err != nil {
		fmt.Printf("  ! Images are not pulled ahead: %v\n", err)
		return
	}
	defer cleanup()
	for index, image := range images {
		if _, err := pods.Create(ctx, imagePullPod(index, image), metav1.CreateOptions{}); err != nil {
			// Left over from a run that was interrupted, or refused: either
			// way the step that needs the image will pull it.
			continue
		}
	}

	sp := newSpinner(pullProgress(0, len(images), nil))
	sp.start()
	deadline := time.Now().Add(readyTimeout)
	var onlyFailingSince time.Time
	for {
		list, err := pods.List(ctx, metav1.ListOptions{})
		done, waiting, failing := 0, []string{}, map[string]string{}
		if err == nil {
			for idx := range list.Items {
				pod := &list.Items[idx]
				image := pod.GetAnnotations()["supply-chain.blanketops.dev/image"]
				switch state, reason := imagePullState(pod); state {
				case imagePulled:
					done++
				case imageFailing:
					failing[image] = reason
				default:
					waiting = append(waiting, shortImage(image))
				}
			}
			if done+len(failing) == len(list.Items) && len(failing) == 0 {
				sp.succeed(fmt.Sprintf("%d images pulled", done))
				return
			}
			retrying := make([]string, 0, len(failing))
			for image := range failing {
				retrying = append(retrying, shortImage(image)+" (retrying)")
			}
			sp.updateMessage(pullProgress(done, len(list.Items), append(waiting, retrying...)))

			// Only failures left: give them a while, then leave them to the
			// steps that need them.
			if len(waiting) == 0 && len(failing) > 0 {
				if onlyFailingSince.IsZero() {
					onlyFailingSince = time.Now()
				}
			} else {
				onlyFailingSince = time.Time{}
			}
		}
		gaveUp := !onlyFailingSince.IsZero() && time.Since(onlyFailingSince) > imagePullGiveUp
		if gaveUp || time.Now().After(deadline) {
			sp.succeed(fmt.Sprintf("%d of %d images pulled; the rest are pulled by the steps that use them", done, len(images)))
			for image, reason := range failing {
				fmt.Printf("  ! could not pull %s (%s)\n", image, reason)
			}
			return
		}
		select {
		case <-ctx.Done():
			sp.fail("Interrupted while pulling images")
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// nodesPullingOneAtATime names the nodes whose kubelet downloads one image at
// a time, which is the default. A node it cannot ask is not named.
func (i *Installer) nodesPullingOneAtATime(ctx context.Context) []string {
	client, err := rest.HTTPClientFor(i.restConfig)
	if err != nil {
		return nil
	}
	nodes, err := i.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "nodes"}).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}
	var serial []string
	for _, node := range nodes.Items {
		url := strings.TrimRight(i.restConfig.Host, "/") + "/api/v1/nodes/" + node.GetName() + "/proxy/configz"
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		var config struct {
			Kubelet struct {
				SerializeImagePulls *bool `json:"serializeImagePulls"`
			} `json:"kubeletconfig"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(data, &config) != nil {
			continue
		}
		if config.Kubelet.SerializeImagePulls == nil || *config.Kubelet.SerializeImagePulls {
			serial = append(serial, node.GetName())
		}
	}
	return serial
}
