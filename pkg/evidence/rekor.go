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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// rekor is the part of the Rekor API needed to find entries by what they are
// about.
type rekor struct {
	base string
	http *http.Client
}

// logEntry is one transparency log entry.
type logEntry struct {
	LogIndex       int64
	LogID          string
	IntegratedTime int64
	Body           entryBody
}

// entryBody is the part of an entry that tells entries with the same index
// key apart. Which fields are set depends on the kind:
//
//	hashedrekord: spec.signature.content
//	dsse:         spec.payloadHash.value
//	intoto:       spec.content.payloadHash.value
type entryBody struct {
	Kind string `json:"kind"`
	Spec struct {
		Signature struct {
			Content string `json:"content"`
		} `json:"signature"`
		PayloadHash hashValue `json:"payloadHash"`
		Content     struct {
			PayloadHash hashValue `json:"payloadHash"`
		} `json:"content"`
	} `json:"spec"`
}

type hashValue struct {
	Value string `json:"value"`
}

// find returns the entries the log indexed under hash ("sha256:...").
func (r *rekor) find(ctx context.Context, hash string) ([]logEntry, error) {
	if r.base == "" {
		return nil, fmt.Errorf("no Rekor URL configured")
	}
	var uuids []string
	if err := r.post(ctx, "/api/v1/index/retrieve", map[string]any{"hash": hash}, &uuids); err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return nil, nil
	}

	var found []map[string]struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}
	if err := r.post(ctx, "/api/v1/log/entries/retrieve", map[string]any{"entryUUIDs": uuids}, &found); err != nil {
		return nil, err
	}
	var entries []logEntry
	for _, byUUID := range found {
		for _, raw := range byUUID {
			entry := logEntry{LogIndex: raw.LogIndex, LogID: raw.LogID, IntegratedTime: raw.IntegratedTime}
			body, err := base64.StdEncoding.DecodeString(raw.Body)
			if err != nil {
				continue
			}
			if err := json.Unmarshal(body, &entry.Body); err != nil {
				continue
			}
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (r *rekor) post(ctx context.Context, path string, request, response any) error {
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.base+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBlobSize))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rekor %s: HTTP %d: %.200s", path, resp.StatusCode, data)
	}
	return json.Unmarshal(data, response)
}
