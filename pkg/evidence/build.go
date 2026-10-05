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

package evidence

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	supplyv1alpha1 "github.com/ntlaletsi70/secure-software-supply-chain/api/v1alpha1"
	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/signing"
)

// Annotations Tekton Chains sets on a run once it has signed it.
const (
	ChainsSignedAnnotation       = "chains.tekton.dev/signed"
	ChainsTransparencyAnnotation = "chains.tekton.dev/transparency"
)

// ChainsDone reports whether Tekton Chains has finished with a run. Until
// then it may still add a signature or an attestation to the image.
func ChainsDone(run *tektonv1.PipelineRun) bool {
	return run.Annotations[ChainsSignedAnnotation] == "true"
}

// ForBuild collects the evidence for the image a build pushed. It always
// returns a result: what could not be read is said in its message, so a
// registry or a log that is briefly unreachable does not lose the rest.
func ForBuild(
	ctx context.Context,
	c client.Reader,
	sc *supplyv1alpha1.SupplyChain,
	run *tektonv1.PipelineRun,
	imageURL, digest string,
) *supplyv1alpha1.BuildEvidence {
	now := metav1.Now()
	endpoints := signing.EndpointsFor(sc)
	result := &supplyv1alpha1.BuildEvidence{
		FulcioURL:          endpoints.FulcioURL,
		RekorURL:           endpoints.RekorURL,
		ProvenanceLogEntry: run.Annotations[ChainsTransparencyAnnotation],
		Complete:           ChainsDone(run),
		CollectedAt:        &now,
	}
	var problems []string

	var roots corev1.ConfigMap
	if err := c.Get(ctx, client.ObjectKey{Namespace: sc.Namespace, Name: signing.RootsConfigMap}, &roots); err != nil {
		problems = append(problems, fmt.Sprintf("trust anchors: %v", err))
	} else {
		result.TrustAnchors = &supplyv1alpha1.TrustAnchorFingerprints{
			FulcioRoot: signing.Fingerprint(roots.Data[signing.RootsFulcioKey]),
			RekorKey:   signing.Fingerprint(roots.Data[signing.RootsRekorKey]),
			CTLogKey:   signing.Fingerprint(roots.Data[signing.RootsCTLogKey]),
		}
	}

	identity, err := signing.LoadIdentity(ctx, c)
	if err != nil {
		problems = append(problems, fmt.Sprintf("signing identity: %v", err))
		identity = signing.KubernetesIdentity()
	}
	serviceAccount := sc.Spec.ServiceAccountName
	if serviceAccount == "" {
		serviceAccount = "default"
	}

	keychain, err := registryKeychain(ctx, c, sc)
	if err != nil {
		// Signatures of a public image can still be read without credentials.
		problems = append(problems, fmt.Sprintf("registry credentials: %v", err))
	}

	records, err := Collect(ctx, Options{
		Image:         imageURL,
		Digest:        digest,
		RekorURL:      endpoints.RekorURL,
		BuildSubject:  identity.Subject(sc.Namespace, serviceAccount),
		ChainsSubject: identity.ChainsSubject(),
		Keychain:      keychain,
	})
	if err != nil {
		problems = append(problems, err.Error())
	}
	result.Signatures = records
	result.Message = strings.Join(problems, "; ")
	return result
}

// registryKeychain reads the SupplyChain's registry credentials: a Docker
// config, under either of the two keys such Secrets use.
func registryKeychain(ctx context.Context, c client.Reader, sc *supplyv1alpha1.SupplyChain) (authn.Keychain, error) {
	if sc.Spec.Image.RegistrySecretRef == "" {
		return nil, nil
	}
	var secret corev1.Secret
	key := client.ObjectKey{Namespace: sc.Namespace, Name: sc.Spec.Image.RegistrySecretRef}
	if err := c.Get(ctx, key, &secret); err != nil {
		return nil, err
	}
	for _, name := range []string{"config.json", corev1.DockerConfigJsonKey} {
		if data, ok := secret.Data[name]; ok {
			return newDockerConfigKeychain(data)
		}
	}
	return nil, fmt.Errorf("secret %s has neither config.json nor %s", key, corev1.DockerConfigJsonKey)
}

// dockerConfigKeychain resolves registry credentials from a Docker config.
type dockerConfigKeychain map[string]authn.AuthConfig

func newDockerConfigKeychain(data []byte) (authn.Keychain, error) {
	var config struct {
		Auths map[string]struct {
			Auth          string `json:"auth"`
			Username      string `json:"username"`
			Password      string `json:"password"`
			IdentityToken string `json:"identitytoken"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parsing Docker config: %w", err)
	}
	keychain := dockerConfigKeychain{}
	for server, entry := range config.Auths {
		auth := authn.AuthConfig{
			Username: entry.Username, Password: entry.Password, IdentityToken: entry.IdentityToken,
		}
		if auth.Username == "" && entry.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
			if err != nil {
				return nil, fmt.Errorf("entry for %s in the Docker config is not base64", server)
			}
			auth.Username, auth.Password, _ = strings.Cut(string(decoded), ":")
		}
		keychain[registryHost(server)] = auth
	}
	return keychain, nil
}

// Resolve implements authn.Keychain.
func (k dockerConfigKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if auth, ok := k[registryHost(resource.RegistryStr())]; ok {
		return authn.FromConfig(auth), nil
	}
	return authn.Anonymous, nil
}

// registryHost reduces the ways a registry is written in a Docker config
// ("https://index.docker.io/v1/", "docker.io", "registry:5000") to a host.
// Docker Hub goes by several names; they are one registry.
func registryHost(server string) string {
	host := server
	if strings.Contains(server, "://") {
		if parsed, err := url.Parse(server); err == nil {
			host = parsed.Host
		}
	} else {
		host, _, _ = strings.Cut(server, "/")
	}
	switch host {
	case "docker.io", "registry-1.docker.io", "registry.hub.docker.com":
		return "index.docker.io"
	}
	return host
}
