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
	"encoding/json"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	immudb "github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

const (
	// evidenceKeyPrefix is the immudb key prefix for evidence records. A record is
	// stored under "<Kind>:<Digest>"; the kind and digest are part of the key so a
	// single digest can hold a signature and an attestation side by side, and so the
	// read-back path can enumerate exactly the records it owns.
	evidenceKeyPrefix = "evidence"
)

// PutEvidenceRecords writes the controller's evidence records to immub for new
// pipelines that must not rewrite the registry's evidence layers. Records are
// serialized as JSON and keyed "<Kind>:<Digest>". Returns the number of records
// written (0 if the slice is empty).
func PutEvidenceRecords(s immudb.Store, digest string, records []supplychainv1alpha1.SignatureRecord) (int, error) {
	if len(records) == 0 {
		return 0, nil
	}
	for _, r := range records {
		key := r.Kind + ":" + digest
		data, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		if _, _, err := s.Put(key, string(data)); err != nil {
			return 0, err
		}
	}
	return len(records), nil
}

// ReadEvidenceRecords reads the evidence records immub holds for a digest, in
// kind order (Signature, Attestation), and re-verifies each against the frozen
// root it was written under. It does not touch the registry.
func ReadEvidenceRecords(s immudb.Store, digest string) ([]supplychainv1alpha1.SignatureRecord, error) {
	var out []supplychainv1alpha1.SignatureRecord
	var errs error
	for _, kind := range []string{KindSignature, KindAttestation} {
		key := kind + ":" + digest
		v, _, _, err := s.Get(key)
		switch {
		case err == immudb.ErrNotFound:
			continue
		case err != nil:
			errs = errors.Join(errs, err)
			continue
		}
		var r supplychainv1alpha1.SignatureRecord
		if err := json.Unmarshal([]byte(v), &r); err != nil {
			errs = errors.Join(errs, err)
			continue
		}
		out = append(out, r)
	}
	return out, errs
}
