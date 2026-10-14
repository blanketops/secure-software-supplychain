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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/big"
	"net/http"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/ntlaletsi70/secure-software-supply-chain/pkg/secrets/store"
)

// Where the keys everything else is verified against are kept is the
// installer's --key-residency.
//
// Two keys are roots of trust: the one Fulcio signs certificates with, and
// the one Rekor signs the transparency log with. Whoever holds the first can
// issue a signing certificate for any identity; whoever holds the second can
// make the log vouch for entries that were never made.
//
//   - "cluster": both are files in Kubernetes Secrets, as the sigstore charts
//     set them up. Anyone who can read Secrets in those namespaces has them.
//   - "vault": both are made inside Vault's Transit engine and never leave it.
//     Fulcio and Rekor ask Vault to sign, each logged in as itself and allowed
//     to use its own key and nothing else, and Vault's audit log has every
//     signature. The key cannot be read through any API, Vault's included.
//
// "vault" keeps a key the way a hardware security module does, in software:
// what protects it is Vault's seal. With the unseal key next to Vault, as the
// installer leaves it, the root has moved rather than gone; unsealing Vault
// from a KMS or a hardware device outside the cluster is what completes it,
// and from then on the same configuration is backed by hardware.
const (
	ResidencyCluster = "cluster"
	ResidencyVault   = "vault"

	transitMount = "transit"
	// The keys, and the Vault role and policy each service signs through.
	fulcioKey        = "fulcio-ca"
	rekorKey         = "rekor"
	fulcioSignerRole = "fulcio-signer"
	rekorSignerRole  = "rekor-signer"

	fulcioNamespace = "fulcio-system"
	// fulcioRootSecret is where the sigstore chart leaves Fulcio's root
	// certificate, and where it is read from as a trust anchor.
	fulcioRootSecret    = "fulcio-pub-key"
	fulcioRootSecretKey = "cert"
	fulcioChainDir      = "/etc/fulcio-kms"

	// The agent that logs a service in to Vault and keeps its token fresh
	// listens here, inside the pod.
	vaultAgentAddress   = "http://127.0.0.1:8100"
	vaultAgentConfigMap = "vault-agent"
	vaultAgentImage     = "hashicorp/vault:2.0.3"
)

func (i *Installer) keysInVault() bool { return i.opts.KeyResidency == ResidencyVault }

// signingService is one of the two services that sign with a key in Vault.
type signingService struct {
	Namespace, ServiceAccount, Key, Role string
}

var signingServices = []signingService{
	{Namespace: fulcioNamespace, ServiceAccount: "fulcio-server", Key: fulcioKey, Role: fulcioSignerRole},
	{Namespace: rekorNamespace, ServiceAccount: "rekor-server", Key: rekorKey, Role: rekorSignerRole},
}

// signerPolicy lets its holder sign and verify with one key and read its
// public half. It cannot create, rotate, export or delete a key. Sigstore's
// client names the hash algorithm at the end of the path
// (transit/sign/<key>/sha2-256), so each of the two is allowed with and
// without one.
func signerPolicy(key string) string {
	return fmt.Sprintf(`path "%[1]s/sign/%[2]s" {
  capabilities = ["update"]
}
path "%[1]s/sign/%[2]s/*" {
  capabilities = ["update"]
}
path "%[1]s/verify/%[2]s" {
  capabilities = ["update"]
}
path "%[1]s/verify/%[2]s/*" {
  capabilities = ["update"]
}
path "%[1]s/keys/%[2]s" {
  capabilities = ["read"]
}
`, transitMount, key)
}

// vaultAgentConfig is the configuration of the agent container: it logs in as
// the pod's ServiceAccount, renews the token it is given, and puts that token
// on every request the service makes through it. The service itself never
// holds a Vault credential.
func vaultAgentConfig(role string) string {
	return fmt.Sprintf(`vault {
  address = %q
  ca_cert = %q
}

auto_auth {
  method "kubernetes" {
    mount_path = "auth/%s"
    config = {
      role = %q
    }
  }
}

api_proxy {
  use_auto_auth_token = "force"
}

listener "tcp" {
  address     = %q
  tls_disable = true
}
`, vaultAddress, caMountDir+"/"+caKey, vaultAuthMount, role, strings.TrimPrefix(vaultAgentAddress, "http://"))
}

// ensureSigningKeys makes the two keys in Vault, once, gives Fulcio and Rekor
// the right to sign with their own, and issues Fulcio's root certificate from
// the key Vault holds.
func (i *Installer) ensureSigningKeys(ctx context.Context) error {
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()

	if err := ensureTransitEngine(ctx, vault); err != nil {
		return err
	}
	if err := ensureKubernetesAuthMount(ctx, vault); err != nil {
		return err
	}
	// A record of every signature: Vault logs each request it serves.
	if err := ensureAudit(ctx, vault); err != nil {
		return err
	}
	for _, svc := range signingServices {
		if err := ensureTransitKey(ctx, vault, svc.Key); err != nil {
			return err
		}
		if err := ensureSignerPolicy(ctx, vault, svc); err != nil {
			return err
		}
		role := map[string]any{
			"bound_service_account_names":      []string{svc.ServiceAccount},
			"bound_service_account_namespaces": []string{svc.Namespace},
			"token_policies":                   []string{svc.Role},
			"token_ttl":                        "1h",
		}
		if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultAuthMount+"/role/"+svc.Role, role, nil); err != nil {
			return fmt.Errorf("writing role %s: %w", svc.Role, err)
		}
		// The namespace and the agent's configuration have to be there before
		// the service's pod is.
		if err := i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": svc.Namespace},
		}}); err != nil {
			return err
		}
		if err := i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name": vaultAgentConfigMap, "namespace": svc.Namespace,
				"labels": map[string]any{"blanketops.dev/managed": "true"},
			},
			"data": map[string]any{"agent.hcl": vaultAgentConfig(svc.Role)},
		}}); err != nil {
			return err
		}
	}
	if err := i.ensureFulcioRoot(ctx, vault); err != nil {
		return err
	}
	// A cluster that kept its keys in Secrets before has them still. They
	// sign nothing any more, and a key that is not used should not lie about.
	for namespace, name := range map[string]string{
		fulcioNamespace: "fulcio-server-secret", rekorNamespace: "rekor-signing-key",
	} {
		err := i.dynamic.Resource(secretGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("removing the key file %s/%s: %w", namespace, name, err)
		}
	}
	return nil
}

// ensureSignerPolicy writes the policy that lets a service sign with its
// key. A service that was suspended on purpose stays suspended: running the
// installer again is not how signing is turned back on.
func ensureSignerPolicy(ctx context.Context, vault *vaultClient, svc signingService) error {
	var have struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/policies/acl/"+svc.Role, nil, &have); err == nil &&
		have.Data.Policy == suspendedPolicy(svc.Key) {
		return nil
	}
	policy := map[string]any{"policy": signerPolicy(svc.Key)}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/policies/acl/"+svc.Role, policy, nil); err != nil {
		return fmt.Errorf("writing policy %s: %w", svc.Role, err)
	}
	return nil
}

// ensureTransitEngine enables the Transit engine, unless it is there.
func ensureTransitEngine(ctx context.Context, vault *vaultClient) error {
	var listed struct {
		Data map[string]struct {
			Type string `json:"type"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/mounts", nil, &listed); err != nil {
		return fmt.Errorf("listing Vault's secret engines: %w", err)
	}
	if mount, ok := listed.Data[transitMount+"/"]; ok {
		if mount.Type != "transit" {
			return fmt.Errorf("vault has %s/ mounted as %s; the signing keys need the transit engine there",
				transitMount, mount.Type)
		}
		return nil
	}
	engine := map[string]any{"type": "transit"}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/sys/mounts/"+transitMount, engine, nil); err != nil {
		return fmt.Errorf("enabling the transit engine: %w", err)
	}
	return nil
}

// ensureKubernetesAuthMount makes Vault able to check a ServiceAccount's
// token with the cluster, without giving any ServiceAccount a role.
func ensureKubernetesAuthMount(ctx context.Context, vault *vaultClient) error {
	if err := ensureAuthMethod(ctx, vault, vaultAuthMount, "kubernetes"); err != nil {
		return err
	}
	config := map[string]any{"kubernetes_host": "https://kubernetes.default.svc"}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/auth/"+vaultAuthMount+"/config", config, nil); err != nil {
		return fmt.Errorf("configuring Kubernetes auth: %w", err)
	}
	return nil
}

// ensureTransitKey creates a signing key in Vault unless one of that name
// exists. An existing key is never replaced or rotated here: everything
// signed with it would stop verifying. The key is not exportable, which is
// Transit's default and cannot be turned off again once it is left off.
func ensureTransitKey(ctx context.Context, vault *vaultClient, name string) error {
	status, err := vault.call(ctx, http.MethodGet, "/v1/"+transitMount+"/keys/"+name, nil, nil)
	if err == nil {
		return nil
	}
	if status != http.StatusNotFound {
		return fmt.Errorf("reading key %s: %w", name, err)
	}
	key := map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}
	if _, err := vault.call(ctx, http.MethodPost, "/v1/"+transitMount+"/keys/"+name, key, nil); err != nil {
		return fmt.Errorf("creating key %s: %w", name, err)
	}
	return nil
}

// transitSigner signs with a key that stays in Vault. It is what lets the
// installer issue a certificate for a key it never sees.
type transitSigner struct {
	ctx   context.Context
	vault *vaultClient
	key   string
	pub   crypto.PublicKey
}

func newTransitSigner(ctx context.Context, vault *vaultClient, key string) (*transitSigner, error) {
	var got struct {
		Data struct {
			LatestVersion int `json:"latest_version"`
			Keys          map[string]struct {
				PublicKey string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/"+transitMount+"/keys/"+key, nil, &got); err != nil {
		return nil, fmt.Errorf("reading key %s: %w", key, err)
	}
	version := got.Data.Keys[fmt.Sprint(got.Data.LatestVersion)]
	block, _ := pem.Decode([]byte(version.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("vault returned no public key for %s", key)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key of %s: %w", key, err)
	}
	return &transitSigner{ctx: ctx, vault: vault, key: key, pub: pub}, nil
}

func (s *transitSigner) Public() crypto.PublicKey { return s.pub }

// Sign asks Vault to sign a digest that is already computed, and returns the
// signature in the encoding X.509 uses.
func (s *transitSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("the transit signer signs SHA-256 digests")
	}
	request := map[string]any{
		"input":                base64.StdEncoding.EncodeToString(digest),
		"prehashed":            true,
		"hash_algorithm":       "sha2-256",
		"marshaling_algorithm": "asn1",
	}
	var got struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if _, err := s.vault.call(s.ctx, http.MethodPost, "/v1/"+transitMount+"/sign/"+s.key, request, &got); err != nil {
		return nil, fmt.Errorf("signing with %s: %w", s.key, err)
	}
	// "vault:v<version>:<base64 signature>"
	parts := strings.Split(got.Data.Signature, ":")
	if len(parts) != 3 {
		return nil, fmt.Errorf("vault returned a signature it should not have: %q", got.Data.Signature)
	}
	return base64.StdEncoding.DecodeString(parts[2])
}

// fulcioRootCertificate issues the self-signed certificate of Fulcio's CA for
// the key behind signer. It is the trust anchor every signing certificate
// chains to, so it is made once and kept.
func fulcioRootCertificate(signer crypto.Signer, now time.Time) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"Secure Software Supply Chain"}, CommonName: "fulcio"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("issuing Fulcio's root certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// certifies reports whether a PEM certificate is for the given public key.
func certifies(certPEM []byte, pub crypto.PublicKey) bool {
	block, _ := pem.Decode(bytes.TrimSpace(certPEM))
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	have, ok := cert.PublicKey.(*ecdsa.PublicKey)
	want, isECDSA := pub.(*ecdsa.PublicKey)
	return ok && isECDSA && have.Equal(want)
}

// fulcioRootVaultKey is where a second copy of Fulcio's root certificate is
// kept, in Vault's key-value engine, next to the key it is for.
const fulcioRootVaultKey = store.Prefix + "/signing/fulcio-root"

// ensureFulcioRoot leaves Fulcio's root certificate where Fulcio and the
// trust anchors read it, a Secret. The certificate is a trust anchor: every
// signing certificate chains to it, and is only valid while it is. So it is
// issued once, and never again while a copy of it can be found.
//
// The Secret is not a safe only copy. Anything that writes to it replaces
// the trust anchor, and a new certificate for the same key does not help:
// it is not valid at the time the earlier signatures were made. A second
// copy is therefore kept in Vault, and is what the Secret is restored from.
func (i *Installer) ensureFulcioRoot(ctx context.Context, vault *vaultClient) error {
	signer, err := newTransitSigner(ctx, vault, fulcioKey)
	if err != nil {
		return err
	}
	if err := ensureSecretEngine(ctx, vault); err != nil {
		return err
	}
	kept, err := vault.read(ctx, fulcioRootVaultKey)
	if err != nil {
		return err
	}
	inSecret := ""
	secrets := i.dynamic.Resource(secretGVR).Namespace(fulcioNamespace)
	if existing, err := secrets.Get(ctx, fulcioRootSecret, metav1.GetOptions{}); err == nil {
		encoded, _, _ := unstructured.NestedString(existing.Object, "data", fulcioRootSecretKey)
		if decoded, decodeErr := base64.StdEncoding.DecodeString(encoded); decodeErr == nil {
			inSecret = string(decoded)
		}
	} else if !apierrors.IsNotFound(err) {
		return err
	}

	root, fromVault := chooseFulcioRoot(kept, inSecret, signer.Public())
	if root == "" {
		issued, err := fulcioRootCertificate(signer, time.Now())
		if err != nil {
			return err
		}
		root = string(issued)
	}
	if !fromVault {
		if err := vault.write(ctx, fulcioRootVaultKey, root); err != nil {
			return fmt.Errorf("keeping a copy of Fulcio's root in Vault: %w", err)
		}
	}
	if root == inSecret {
		return nil
	}
	return i.applyObject(ctx, &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]any{
			"name": fulcioRootSecret, "namespace": fulcioNamespace,
			"labels": map[string]any{"blanketops.dev/managed": "true"},
		},
		"type":       "Opaque",
		"stringData": map[string]any{fulcioRootSecretKey: root},
	}})
}

// chooseFulcioRoot picks the root certificate to use from the copies there
// are: the one kept in Vault if it is for the key, else the one in the
// Secret if that is. It returns "" when neither is, and one has to be issued.
func chooseFulcioRoot(inVault, inSecret string, key crypto.PublicKey) (root string, fromVault bool) {
	switch {
	case certifies([]byte(inVault), key):
		return inVault, true
	case certifies([]byte(inSecret), key):
		return inSecret, false
	}
	return "", false
}

// ── What changes in the manifests ────────────────────────────────────────────

// mutateForKeyResidency is the Mutate of the Fulcio and Rekor steps.
func mutateForKeyResidency(i *Installer, obj *unstructured.Unstructured) bool {
	if !i.keysInVault() {
		return true
	}
	return keysInVaultMutation(obj)
}

// keysInVaultMutation rewrites Fulcio's and Rekor's manifests for keys kept
// in Vault. It reports false for an object that is not applied at all.
func keysInVaultMutation(obj *unstructured.Unstructured) bool {
	switch {
	case obj.GetKind() == kindJob && obj.GetName() == "fulcio-createcerts":
		// Makes a CA key and puts it in a Secret, which is what is avoided.
		return false
	case obj.GetKind() == kindDeployment && obj.GetName() == "fulcio-server":
		signWithVault(obj, "fulcio-server", func(c map[string]any) {
			c["args"] = fulcioKMSArgs(stringsOf(c["args"]))
			c["env"] = without(c["env"], "PASSWORD")
			c["volumeMounts"] = append(without(c["volumeMounts"], "fulcio-cert"),
				map[string]any{"name": "fulcio-root", "mountPath": fulcioChainDir, "readOnly": true})
		})
		setVolume(obj, "fulcio-cert", nil)
		setVolume(obj, "fulcio-root", map[string]any{"secret": map[string]any{"secretName": fulcioRootSecret}})
	case obj.GetKind() == kindDeployment && obj.GetName() == "rekor-server":
		signWithVault(obj, "rekor-server", func(c map[string]any) {
			args := stringsOf(c["args"])
			for n, arg := range args {
				if strings.HasPrefix(arg, "--rekor_server.signer=") {
					args[n] = "--rekor_server.signer=hashivault://" + rekorKey
				}
			}
			c["args"] = anys(args)
			c["volumeMounts"] = without(c["volumeMounts"], "signing-key")
		})
		setVolume(obj, "signing-key", nil)
		// The agent verifies Vault against the CA, which cert-manager puts
		// in the Secret of the pod's own certificate.
		setVolume(obj, "tls-ca", map[string]any{"secret": map[string]any{
			"secretName": "rekor-server-tls",
			"items":      []any{map[string]any{"key": caKey, "path": caKey}},
		}})
	}
	return true
}

// fulcioKMSArgs replaces the arguments that point Fulcio at a CA key in a
// file with the ones for a key in Vault.
func fulcioKMSArgs(args []string) []any {
	out := []any{}
	for n := 0; n < len(args); n++ {
		switch arg := args[n]; arg {
		case "--ca=fileca":
			out = append(out, "--ca=kmsca", "--kms-resource=hashivault://"+fulcioKey,
				"--kms-cert-chain-path="+fulcioChainDir+"/"+fulcioRootSecretKey)
		case "--fileca-key", "--fileca-cert", "--fileca-key-passwd":
			n++ // and its value
		default:
			out = append(out, arg)
		}
	}
	return out
}

// signWithVault points a service's container at the Vault agent and adds the
// agent to the pod. change makes the rest of the changes to the container.
func signWithVault(deployment *unstructured.Unstructured, container string, change func(map[string]any)) {
	podSpec := []string{"spec", "template", "spec"}
	containers, _, _ := unstructured.NestedSlice(deployment.Object, append(podSpec, "containers")...)
	for n, c := range containers {
		spec, ok := c.(map[string]any)
		if !ok || spec["name"] != container {
			continue
		}
		change(spec)
		env, _ := spec["env"].([]any)
		spec["env"] = append(env,
			map[string]any{"name": "VAULT_ADDR", "value": vaultAgentAddress},
			// Sigstore's Vault client will not start without a token. The
			// agent replaces whatever is sent with the one it logged in for.
			map[string]any{"name": "VAULT_TOKEN", "value": "set-by-the-vault-agent"},
			map[string]any{"name": "TRANSIT_SECRET_ENGINE_PATH", "value": transitMount},
		)
		containers[n] = spec
	}
	containers = append(containers, map[string]any{
		"name":  "vault-agent",
		"image": vaultAgentImage,
		"args":  []any{"agent", "-config=/etc/vault-agent/agent.hcl"},
		// The image's entrypoint would otherwise try to give the binary a
		// capability, which an unprivileged container may not.
		"env": []any{map[string]any{"name": "SKIP_SETCAP", "value": "true"}},
		"securityContext": map[string]any{
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []any{"ALL"}},
		},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": "10m", "memory": "32Mi"},
			"limits":   map[string]any{"memory": "128Mi"},
		},
		"volumeMounts": []any{
			map[string]any{"name": "vault-agent", "mountPath": "/etc/vault-agent", "readOnly": true},
			map[string]any{"name": "tls-ca", "mountPath": caMountDir, "readOnly": true},
		},
	})
	_ = unstructured.SetNestedSlice(deployment.Object, containers, append(podSpec, "containers")...)
	// Which role the agent logs in for is in its configuration, one per
	// namespace.
	setVolume(deployment, "vault-agent", map[string]any{"configMap": map[string]any{"name": vaultAgentConfigMap}})
}

// setVolume sets, replaces or, with a nil source, removes a pod volume.
func setVolume(deployment *unstructured.Unstructured, name string, source map[string]any) {
	path := []string{"spec", "template", "spec", "volumes"}
	volumes, _, _ := unstructured.NestedSlice(deployment.Object, path...)
	volumes = without(volumes, name)
	if source != nil {
		volume := map[string]any{"name": name}
		maps.Copy(volume, source)
		volumes = append(volumes, volume)
	}
	_ = unstructured.SetNestedSlice(deployment.Object, volumes, path...)
}

// without returns a list of named things without the one of that name.
func without(list any, name string) []any {
	items, _ := list.([]any)
	out := make([]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok && m["name"] == name {
			continue
		}
		out = append(out, item)
	}
	return out
}

func stringsOf(list any) []string {
	items, _ := list.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, fmt.Sprint(item))
	}
	return out
}

func anys(list []string) []any {
	out := make([]any, 0, len(list))
	for _, item := range list {
		out = append(out, item)
	}
	return out
}
