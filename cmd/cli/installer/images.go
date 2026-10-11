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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"

	manifests "github.com/ntlaletsi70/secure-software-supply-chain"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/tekton/pipeline"
)

// Almost all of an install's time is image pulls, and without help they
// happen one step at a time: a step's images are only asked for when the
// installer reaches it, and each step waits for its own before the next
// starts. The "Images" step asks for every image the install will use at the
// start, all at once, so that the node downloads continuously, and in
// parallel when its kubelet allows that. It does not wait for them: the steps
// go ahead, each waiting only for its own images, which by then are there or
// well on their way. What is still downloading when the last step is done,
// the images only a build uses, is waited for at the end.
//
// It is an optimisation and never fails an install: an image it could not
// pull is pulled again, with its own errors, by the step that needs it.

const (
	// imagePullNamespace holds the pods that exist only to pull images. It is
	// removed when the step ends.
	imagePullNamespace  = "supply-chain-image-pull"
	imagePullAnnotation = "supply-chain.blanketops.dev/image"
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

// imageFlag is an argument that names an image a controller will run later,
// such as Tekton's -entrypoint-image.
var imageFlag = regexp.MustCompile(`^--?[a-z-]*image$`)

// looksLikeImage tells an image reference from the other things a parameter
// called "image" may default to: a path, or nothing.
func looksLikeImage(value string) bool {
	return value != "" && strings.Contains(value, "/") && !strings.ContainsAny(value, " $") &&
		!strings.HasPrefix(value, "/") && !strings.HasPrefix(value, ".")
}

// collectImages finds the images an object will make the node pull: the
// "image" of every entry of a list of containers, wherever in the object such
// a list is; the images a container is told about in its arguments, which is
// how Tekton names the ones it adds to every step; and the images a Task's
// parameters default to.
func collectImages(v any, inContainers bool, found func(string)) {
	switch value := v.(type) {
	case map[string]any:
		if image, ok := value["image"].(string); ok && inContainers {
			if image = strings.TrimSpace(image); image != "" && !strings.Contains(image, "$(") {
				found(image)
			}
		}
		if args, ok := value["args"].([]any); ok && inContainers {
			for n, arg := range args {
				flag, _ := arg.(string)
				if name, image, joined := strings.Cut(flag, "="); joined && imageFlag.MatchString(name) && looksLikeImage(image) {
					found(image)
				} else if imageFlag.MatchString(flag) && n+1 < len(args) {
					if image, _ := args[n+1].(string); looksLikeImage(image) {
						found(image)
					}
				}
			}
		}
		if value["kind"] == "Task" {
			params, _, _ := unstructured.NestedSlice(value, "spec", "params")
			for _, p := range params {
				param, _ := p.(map[string]any)
				name, _ := param["name"].(string)
				image, _ := param["default"].(string)
				if strings.Contains(strings.ToLower(name), "image") && looksLikeImage(image) {
					found(image)
				}
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
func imagePullPod(image string) *unstructured.Unstructured {
	// Named after the image, so that a second run asks for the same pod.
	sum := sha256.Sum256([]byte(image))
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]any{
			"name":        "pull-" + hex.EncodeToString(sum[:6]),
			"namespace":   imagePullNamespace,
			"annotations": map[string]any{imagePullAnnotation: image},
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

// startImagePulls asks the node for every image the steps will use, and
// returns at once: the steps go ahead while the images download, and each
// waits only for its own. It reports whether anything was asked for.
func (i *Installer) startImagePulls(ctx context.Context, steps []step) bool {
	images, err := stepImages(steps)
	if err != nil || len(images) == 0 {
		return false
	}
	// And what the pipeline's own steps run, which the first build would
	// otherwise wait for.
	for _, image := range pipeline.Images() {
		if !slices.Contains(images, image) {
			images = append(images, image)
		}
	}
	if err := i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": imagePullNamespace},
	}}); err != nil {
		fmt.Printf("  ! Images are not pulled ahead: %v\n", err)
		return false
	}
	pods := i.dynamic.Resource(podGVR).Namespace(imagePullNamespace)
	for _, image := range images {
		// A pod that is already there, from a run that was interrupted, is
		// pulling or has pulled the same image: its name is made from it.
		_, _ = pods.Create(ctx, imagePullPod(image), metav1.CreateOptions{})
	}
	fmt.Printf("  ✓ Asked the node for %d images; the steps go ahead while they download\n", len(images))
	if serial := i.nodesPullingOneAtATime(ctx); len(serial) > 0 {
		fmt.Printf("  ! %s pulls one image at a time (the kubelet's serializeImagePulls).\n"+
			"    On kind, hack/kind-parallel-pulls.sh turns parallel pulls on.\n", strings.Join(serial, ", "))
	}
	return true
}

// imagePullCounts reads how far the pulls are: how many images are on the
// node, which are still coming, and which are failing and why.
func (i *Installer) imagePullCounts(ctx context.Context, pulledByEvent map[string]bool) (
	done, total int, waiting []string, failing map[string]string, err error,
) {
	// The kubelet says "Pulled" the moment an image is there. A pod's status
	// can lag behind that for a long time when its container then fails to
	// start, which here it always does, so the event is believed as well.
	events := i.dynamic.Resource(schema.GroupVersionResource{Version: "v1", Resource: "events"}).
		Namespace(imagePullNamespace)
	if said, err := events.List(ctx, metav1.ListOptions{FieldSelector: "reason=Pulled"}); err == nil {
		for _, event := range said.Items {
			if name, _, _ := unstructured.NestedString(event.Object, "involvedObject", "name"); name != "" {
				pulledByEvent[name] = true
			}
		}
	}
	list, err := i.dynamic.Resource(podGVR).Namespace(imagePullNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, 0, nil, nil, err
	}
	failing = map[string]string{}
	for idx := range list.Items {
		pod := &list.Items[idx]
		image := pod.GetAnnotations()[imagePullAnnotation]
		state, reason := imagePullState(pod)
		if pulledByEvent[pod.GetName()] {
			state = imagePulled
		}
		switch state {
		case imagePulled:
			done++
		case imageFailing:
			failing[image] = reason
		default:
			waiting = append(waiting, shortImage(image))
		}
	}
	return done, len(list.Items), waiting, failing, nil
}

// imagePullNote is a one-line account of the pulls, shown between steps.
func (i *Installer) imagePullNote(ctx context.Context) string {
	done, total, _, _, err := i.imagePullCounts(ctx, map[string]bool{})
	if err != nil || total == 0 || done == total {
		return ""
	}
	return fmt.Sprintf("%d of %d images are on the node", done, total)
}

// finishImagePulls waits for what is still downloading once every step is
// done, which is the images only a build uses, and removes the pods. It
// reports what could not be pulled and returns no error: see the comment at
// the top of this file.
func (i *Installer) finishImagePulls(ctx context.Context) {
	cleanup := func() {
		policy := metav1.DeletePropagationBackground
		_ = i.dynamic.Resource(namespaceGVR).Delete(context.WithoutCancel(ctx), imagePullNamespace,
			metav1.DeleteOptions{PropagationPolicy: &policy})
	}
	defer cleanup()

	sp := newSpinner("Waiting for the images builds use...")
	sp.start()
	deadline := time.Now().Add(readyTimeout)
	var onlyFailingSince time.Time
	pulledByEvent := map[string]bool{}
	for {
		done, total, waiting, failing, err := i.imagePullCounts(ctx, pulledByEvent)
		if err == nil {
			if done == total {
				sp.succeed(fmt.Sprintf("All %d images are on the node", done))
				return
			}
			retrying := make([]string, 0, len(failing))
			for image := range failing {
				retrying = append(retrying, shortImage(image)+" (retrying)")
			}
			sp.updateMessage(pullProgress(done, total, append(waiting, retrying...)))

			// Only failures left: give them a while, then leave them to the
			// builds that need them.
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
			sp.succeed(fmt.Sprintf("%d of %d images are on the node; the rest are pulled when first used", done, total))
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
