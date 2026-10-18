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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	supplychainv1alpha1 "github.com/blanketops/secure-software-supplychain/api/v1alpha1"
	immudb "github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// evidenceKeyPrefix starts every immudb key the evidence of a build is
// stored under. A build, identified by its image digest, has:
//
//	evidence/<digest>      the build's index: the keys of its records
//	evidence/<digest>/<n>  one record per signature, attestation or SBOM
//
// All of them are written in one immudb transaction.
const evidenceKeyPrefix = "evidence"

// buildIndex is the value stored under a build's index key.
type buildIndex struct {
	Digest  string   `json:"digest"`
	Records []string `json:"records"`
}

func buildKey(digest string) string { return evidenceKeyPrefix + "/" + digest }

func recordKey(digest string, n int) string { return buildKey(digest) + "/" + strconv.Itoa(n) }

// StoredBuildEvidence is the evidence of one build as read back from immudb.
type StoredBuildEvidence struct {
	Records []supplychainv1alpha1.SignatureRecord
	// Tx is the immudb transaction that wrote the build's evidence and Root
	// that transaction's root.
	Tx   uint64
	Root []byte
}

// PutBuildEvidence writes every evidence record of the build of digest (its
// signatures, attestations and SBOMs) to immudb in a single transaction.
// A build is written once: if its evidence is already stored, nothing is
// written and the error is immudb.ErrDuplicate.
func PutBuildEvidence(s immudb.Store, digest string, records []supplychainv1alpha1.SignatureRecord) (tx uint64, root []byte, err error) {
	if digest == "" {
		return 0, nil, errors.New("evidence: no image digest")
	}
	if len(records) == 0 {
		return 0, nil, fmt.Errorf("evidence: no records for %s", digest)
	}
	index := buildIndex{Digest: digest}
	entries := make([]immudb.Entry, 0, len(records)+1)
	for n, r := range records {
		data, err := json.Marshal(r)
		if err != nil {
			return 0, nil, fmt.Errorf("evidence: encoding record %d of %s: %w", n, digest, err)
		}
		key := recordKey(digest, n)
		index.Records = append(index.Records, key)
		entries = append(entries, immudb.Entry{Key: key, Value: string(data)})
	}
	data, err := json.Marshal(index)
	if err != nil {
		return 0, nil, fmt.Errorf("evidence: encoding the index of %s: %w", digest, err)
	}
	entries = append(entries, immudb.Entry{Key: buildKey(digest), Value: string(data)})
	return s.PutAll(entries)
}

// ReadBuildEvidence reads the evidence of the build of digest back from
// immudb. Every record must have been written in the same transaction as the
// build's index and must verify against that transaction's root; otherwise
// the error says which record does not. It does not touch the registry.
func ReadBuildEvidence(s immudb.Store, digest string) (*StoredBuildEvidence, error) {
	value, tx, root, err := s.Get(buildKey(digest))
	if err != nil {
		return nil, fmt.Errorf("evidence: reading the index of %s: %w", digest, err)
	}
	var index buildIndex
	if err := json.Unmarshal([]byte(value), &index); err != nil {
		return nil, fmt.Errorf("evidence: decoding the index of %s: %w", digest, err)
	}
	if index.Digest != digest {
		return nil, fmt.Errorf("evidence: the index of %s names digest %s", digest, index.Digest)
	}

	out := &StoredBuildEvidence{Tx: tx, Root: root}
	for _, key := range index.Records {
		v, rtx, rroot, err := s.Get(key)
		if err != nil {
			return nil, fmt.Errorf("evidence: reading %s: %w", key, err)
		}
		if rtx != tx || !bytes.Equal(rroot, root) {
			return nil, fmt.Errorf("evidence: %s was written in tx %d, not in the build's tx %d", key, rtx, tx)
		}
		if ok, err := s.Verify(key, root, tx, v); err != nil || !ok {
			return nil, fmt.Errorf("evidence: %s does not verify against tx %d: %v", key, tx, err)
		}
		var r supplychainv1alpha1.SignatureRecord
		if err := json.Unmarshal([]byte(v), &r); err != nil {
			return nil, fmt.Errorf("evidence: decoding %s: %w", key, err)
		}
		out.Records = append(out.Records, r)
	}
	return out, nil
}
