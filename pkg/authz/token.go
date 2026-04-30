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
package authz

import (
	"context"
	"fmt"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// RequestScopedToken mints a short-lived SA token scoped to the given audience.
// Only call this AFTER VerifyAuthorization passes.
//
// This is NOT the SA's default mounted token. It's a purpose-built, short-lived
// credential generated via the TokenRequest API. The audience is set to "sigstore"
// so Fulcio accepts it as an OIDC proof of identity.
//
// The SA's regular token continues to handle secrets, RBAC, and API server
// communication. This token exists solely for the Fulcio handshake.
func RequestScopedToken(
	ctx context.Context,
	clientset kubernetes.Interface,
	serviceAccount string,
	namespace string,
	audience string,
	expirationSeconds int64,
) (string, error) {
	treq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &expirationSeconds,
		},
	}

	resp, err := clientset.CoreV1().
		ServiceAccounts(namespace).
		CreateToken(ctx, serviceAccount, treq, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("token request failed for %s/%s: %w", namespace, serviceAccount, err)
	}

	if resp.Status.Token == "" {
		return "", fmt.Errorf("token request returned empty token for %s/%s", namespace, serviceAccount)
	}

	return resp.Status.Token, nil
}
