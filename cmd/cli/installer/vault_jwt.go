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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// serviceAccountKeys returns the issuer the cluster puts in its ServiceAccount
// tokens and the public keys it signs them with, PEM-encoded.
//
// These are what a Vault outside the cluster is given so that it can check a
// token by itself. They are public: the API server publishes them for exactly
// this purpose.
func (i *Installer) serviceAccountKeys(ctx context.Context) (issuer string, keys []string, err error) {
	rest := i.discovery.RESTClient()
	if rest == nil {
		return "", nil, errors.New("no connection to the API server")
	}
	raw, err := rest.Get().AbsPath("/.well-known/openid-configuration").DoRaw(ctx)
	if err != nil {
		return "", nil, err
	}
	var discovery struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &discovery); err != nil || discovery.Issuer == "" {
		return "", nil, fmt.Errorf("the API server's OIDC discovery document names no issuer: %v", err)
	}
	raw, err = rest.Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	if err != nil {
		return "", nil, err
	}
	keys, err = publicKeysFromJWKS(raw)
	return discovery.Issuer, keys, err
}

// publicKeysFromJWKS turns a JSON Web Key Set into PEM public keys.
func publicKeysFromJWKS(raw []byte) ([]string, error) {
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			N   string `json:"n"`
			E   string `json:"e"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a JSON Web Key Set: %w", err)
	}
	number := func(encoded string) (*big.Int, error) {
		data, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(data) == 0 {
			return nil, fmt.Errorf("malformed key component: %v", err)
		}
		return new(big.Int).SetBytes(data), nil
	}

	var keys []string
	for _, jwk := range set.Keys {
		var public any
		switch jwk.Kty {
		case "RSA":
			n, err := number(jwk.N)
			if err != nil {
				return nil, err
			}
			e, err := number(jwk.E)
			if err != nil {
				return nil, err
			}
			public = &rsa.PublicKey{N: n, E: int(e.Int64())}
		case "EC":
			curves := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}
			curve, ok := curves[jwk.Crv]
			if !ok {
				return nil, fmt.Errorf("unsupported curve %q", jwk.Crv)
			}
			x, err := number(jwk.X)
			if err != nil {
				return nil, err
			}
			y, err := number(jwk.Y)
			if err != nil {
				return nil, err
			}
			public = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		default:
			return nil, fmt.Errorf("unsupported key type %q", jwk.Kty)
		}
		der, err := x509.MarshalPKIXPublicKey(public)
		if err != nil {
			return nil, err
		}
		keys = append(keys, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	}
	if len(keys) == 0 {
		return nil, errors.New("the key set is empty")
	}
	return keys, nil
}
