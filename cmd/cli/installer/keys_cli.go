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
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/rest"
)

// What `supplychain keys` shows and does: a look at the signing keys while
// they are in use, and a way to stop one of the two services signing without
// touching its key.

// auditDevice is the name of the audit device the installer enables. Vault
// writes one line to its own output for every request, with secrets hashed,
// which is the record of what was signed, when and for whom.
const auditDevice = "stdout"

// KeyReport is the state of one signing key and of the one service that may
// use it.
type KeyReport struct {
	Name        string
	Type        string
	Exportable  bool
	Deletable   bool
	Version     int
	Created     time.Time
	Fingerprint string
	// Who may sign with it, and whether that is currently allowed.
	ServiceAccount string
	Suspended      bool
	// Signatures is how many times it was used to sign according to Vault's
	// audit log, as far back as the log read goes; -1 when it was not read.
	Signatures int
	LastSigned time.Time
}

// signingServiceNamed finds one of the two services by the name a person
// would use for it.
func signingServiceNamed(name string) (signingService, error) {
	for _, svc := range signingServices {
		if name == svc.Key || name == svc.ServiceAccount || name == strings.TrimSuffix(svc.Role, "-signer") {
			return svc, nil
		}
	}
	return signingService{}, fmt.Errorf("%q is not a signing key; they are fulcio and rekor", name)
}

// ensureAudit turns on Vault's audit log, to its own output, unless a device
// is already enabled.
func ensureAudit(ctx context.Context, vault *vaultClient) error {
	var listed struct {
		Data map[string]any `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/audit", nil, &listed); err != nil {
		return fmt.Errorf("listing Vault's audit devices: %w", err)
	}
	if len(listed.Data) > 0 {
		return nil
	}
	device := map[string]any{"type": "file", "options": map[string]any{"file_path": "stdout"}}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/audit/"+auditDevice, device, nil); err != nil {
		return fmt.Errorf("enabling Vault's audit log: %w", err)
	}
	return nil
}

// keyReport reads one key and its service's standing from Vault.
func keyReport(ctx context.Context, vault *vaultClient, svc signingService) (KeyReport, error) {
	report := KeyReport{Name: svc.Key, ServiceAccount: svc.Namespace + "/" + svc.ServiceAccount, Signatures: -1}
	var key struct {
		Data struct {
			Type          string `json:"type"`
			Exportable    bool   `json:"exportable"`
			Deletable     bool   `json:"deletion_allowed"`
			LatestVersion int    `json:"latest_version"`
			Keys          map[string]struct {
				Created   time.Time `json:"creation_time"`
				PublicKey string    `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/"+transitMount+"/keys/"+svc.Key, nil, &key); err != nil {
		return report, err
	}
	report.Type, report.Exportable, report.Deletable = key.Data.Type, key.Data.Exportable, key.Data.Deletable
	report.Version = key.Data.LatestVersion
	latest := key.Data.Keys[fmt.Sprint(key.Data.LatestVersion)]
	report.Created = latest.Created
	if block, _ := pem.Decode([]byte(latest.PublicKey)); block != nil {
		sum := sha256.Sum256(block.Bytes)
		report.Fingerprint = "sha256:" + hex.EncodeToString(sum[:])
	}

	var policy struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/policies/acl/"+svc.Role, nil, &policy); err != nil {
		report.Suspended = true
	} else {
		report.Suspended = !strings.Contains(policy.Data.Policy, transitMount+"/sign/"+svc.Key)
	}
	return report, nil
}

// suspendedPolicy is what a service's policy is replaced with to stop it
// signing. The key, the role and the service's login are left as they are.
func suspendedPolicy(key string) string {
	return fmt.Sprintf("# Signing with %s is suspended. `supplychain keys resume` restores it.\n", key)
}

// SetKeySuspended stops, or lets again, one of the two services sign with its
// key. It takes effect on the service's next request: Vault reads a token's
// policies each time. Nothing that is already signed is affected.
func (i *Installer) SetKeySuspended(ctx context.Context, name string, suspended bool) error {
	svc, err := signingServiceNamed(name)
	if err != nil {
		return err
	}
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	if _, err := vault.call(ctx, http.MethodGet, "/v1/"+transitMount+"/keys/"+svc.Key, nil, nil); err != nil {
		return fmt.Errorf("there is no key %s in Vault; the keys are there only with --key-residency vault: %w", svc.Key, err)
	}
	text, done := signerPolicy(svc.Key), "may sign again"
	if suspended {
		text, done = suspendedPolicy(svc.Key), "can no longer sign"
	}
	policy := map[string]any{"policy": text}
	if _, err := vault.call(ctx, http.MethodPut, "/v1/sys/policies/acl/"+svc.Role, policy, nil); err != nil {
		return fmt.Errorf("writing policy %s: %w", svc.Role, err)
	}
	fmt.Printf("  ✓ %s %s with %s\n", svc.ServiceAccount, done, svc.Key)
	return nil
}

// signaturesFromAudit counts, per key, the successful signing requests in
// Vault's audit log, and finds the last of each.
func signaturesFromAudit(log *bufio.Scanner) (map[string]int, map[string]time.Time) {
	counts, last := map[string]int{}, map[string]time.Time{}
	for log.Scan() {
		line := log.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var entry struct {
			Type    string    `json:"type"`
			Time    time.Time `json:"time"`
			Error   string    `json:"error"`
			Request struct {
				Path string `json:"path"`
			} `json:"request"`
		}
		if json.Unmarshal(line, &entry) != nil || entry.Type != "response" || entry.Error != "" {
			continue
		}
		signed, isSign := strings.CutPrefix(entry.Request.Path, transitMount+"/sign/")
		if !isSign {
			continue
		}
		key, _, _ := strings.Cut(signed, "/")
		counts[key]++
		if entry.Time.After(last[key]) {
			last[key] = entry.Time
		}
	}
	return counts, last
}

// vaultAuditLog reads the end of Vault's output, where the audit log is.
func (i *Installer) vaultAuditLog(ctx context.Context) (*bufio.Scanner, func(), error) {
	client, err := rest.HTTPClientFor(i.restConfig)
	if err != nil {
		return nil, nil, err
	}
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/pods/%s/log?container=vault&tailLines=20000",
		strings.TrimRight(i.restConfig.Host, "/"), vaultNamespace, vaultPod)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, nil, errors.New(resp.Status)
	}
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)
	return scanner, func() { _ = resp.Body.Close() }, nil
}

// ShowKeys prints what Vault holds for the two signing keys while they are
// in use: what each is, that it cannot leave, who may sign with it and
// whether that is allowed now, and how often it has signed.
func (i *Installer) ShowKeys(ctx context.Context) error {
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()

	var seal struct {
		Sealed  bool   `json:"sealed"`
		Type    string `json:"type"`
		Version string `json:"version"`
	}
	if _, err := vault.call(ctx, http.MethodGet, "/v1/sys/seal-status", nil, &seal); err != nil {
		return err
	}
	state := "unsealed"
	if seal.Sealed {
		state = "SEALED: nothing can be signed until it is unsealed"
	}
	fmt.Printf("Vault %s, %s seal, %s\n", seal.Version, seal.Type, state)

	reports := make([]KeyReport, 0, len(signingServices))
	for _, svc := range signingServices {
		report, err := keyReport(ctx, vault, svc)
		if err != nil {
			fmt.Printf("\nNo key %s in Vault. Fulcio's and Rekor's keys are files in Kubernetes Secrets,\n"+
				"which is --key-residency cluster. They are kept in Vault only when the stack is\n"+
				"installed with --key-residency vault.\n", svc.Key)
			return nil
		}
		reports = append(reports, report)
	}

	audited := false
	if log, closeLog, err := i.vaultAuditLog(ctx); err == nil {
		counts, last := signaturesFromAudit(log)
		closeLog()
		for n := range reports {
			reports[n].Signatures, reports[n].LastSigned = counts[reports[n].Name], last[reports[n].Name]
			audited = audited || counts[reports[n].Name] > 0
		}
	}

	sort.Slice(reports, func(a, b int) bool { return reports[a].Name < reports[b].Name })
	for _, r := range reports {
		leaves := "cannot be exported, backed up in the clear, or deleted"
		if r.Exportable || r.Deletable {
			leaves = "CAN be exported or deleted: this is not how the installer makes it"
		}
		signing := "allowed"
		if r.Suspended {
			signing = "SUSPENDED (supplychain keys resume " + strings.TrimSuffix(r.Name, "-ca") + ")"
		}
		fmt.Printf("\n%s\n", r.Name)
		fmt.Printf("  kind         %s, version %d, made %s\n", r.Type, r.Version, r.Created.Local().Format("2006-01-02 15:04"))
		fmt.Printf("  public key   %s\n", r.Fingerprint)
		fmt.Printf("  leaves Vault no: it %s\n", leaves)
		fmt.Printf("  signs for    %s, and nobody else\n", r.ServiceAccount)
		fmt.Printf("  signing      %s\n", signing)
		switch {
		case r.Signatures > 0:
			fmt.Printf("  used         %d times in the audit log, last %s\n", r.Signatures, r.LastSigned.Local().Format("2006-01-02 15:04:05"))
		case r.Signatures == 0:
			fmt.Printf("  used         not in the part of the audit log that was read\n")
		}
	}
	if !audited {
		fmt.Println("\nThe audit log has no signatures: it is off, or nothing has been signed since it was\n" +
			"turned on. `supplychain install --only-step \"Signing Keys\"` turns it on.")
	}
	return nil
}
