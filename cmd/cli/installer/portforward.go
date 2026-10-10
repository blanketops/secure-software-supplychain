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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
)

// forwardToPod opens a port-forward to a pod and returns the URL its port is
// reachable at and a func to close it. It is how the CLI reaches services
// that have no address outside the cluster, from wherever the kubeconfig
// works.
func (i *Installer) forwardToPod(ctx context.Context, namespace, pod string, port int) (string, func(), error) {
	transport, upgrader, err := spdy.RoundTripperFor(i.restConfig)
	if err != nil {
		return "", nil, err
	}
	host := strings.TrimRight(i.restConfig.Host, "/")
	target, err := url.Parse(fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/portforward", host, namespace, pod))
	if err != nil {
		return "", nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, http.MethodPost, target)

	stop, ready := make(chan struct{}), make(chan struct{})
	// Local port 0: any free port.
	ports := []string{fmt.Sprintf("0:%d", port)}
	forwarder, err := portforward.New(dialer, ports, stop, ready, io.Discard, io.Discard)
	if err != nil {
		return "", nil, err
	}
	failed := make(chan error, 1)
	go func() { failed <- forwarder.ForwardPorts() }()

	select {
	case <-ready:
	case err := <-failed:
		return "", nil, fmt.Errorf("port-forward to pod %s/%s: %w", namespace, pod, err)
	case <-ctx.Done():
		close(stop)
		return "", nil, ctx.Err()
	}
	forwarded, err := forwarder.GetPorts()
	if err != nil || len(forwarded) == 0 {
		close(stop)
		return "", nil, fmt.Errorf("port-forward to pod %s/%s gave no port: %v", namespace, pod, err)
	}
	return fmt.Sprintf("http://127.0.0.1:%d", forwarded[0].Local), func() { close(stop) }, nil
}
