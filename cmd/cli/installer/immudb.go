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
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/blanketops/secure-software-supplychain/pkg/secrets/store"
)

const (
	// immudbNamespace holds immudb, the ledger of the builds' evidence.
	immudbNamespace = "immudb-system"
	// immudbAdminSecret is the Secret, filled from Vault, that immudb is
	// initialised with.
	immudbAdminSecret = "immudb-admin"
	// operatorNamespace is the operator's, the only one immudb admits.
	operatorNamespace = "secure-software-supply-chain-system"
)

// ensureImmudbPassword puts a generated admin password for immudb in Vault,
// unless one is there. It is never replaced: immudb reads it only when it
// initialises an empty data directory, so a new one would lock the operator
// out of the ledger it already has. With a secret store of your own, setting
// it is yours to do.
func (i *Installer) ensureImmudbPassword(ctx context.Context) error {
	if i.opts.ExternalSecretStore {
		return nil
	}
	vault, closeVault, err := i.openVault(ctx)
	if err != nil {
		return err
	}
	defer closeVault()
	existing, err := vault.read(ctx, store.ImmudbPassword)
	if err != nil {
		return fmt.Errorf("reading %s: %w", store.ImmudbPassword, err)
	}
	if existing != "" {
		return nil
	}
	random := make([]byte, 24)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("generating immudb's admin password: %w", err)
	}
	if err := vault.write(ctx, store.ImmudbPassword, hex.EncodeToString(random)); err != nil {
		return fmt.Errorf("writing %s: %w", store.ImmudbPassword, err)
	}
	return nil
}
