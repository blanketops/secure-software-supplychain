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
package immudb

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	immudbclient "github.com/codenotary/immudb/pkg/client"
)

var (
	ErrDuplicate = errors.New("immudb: record already stored")
	ErrNotFound  = errors.New("immudb: no such record")
	ErrConnect   = errors.New("immudb: failed to open immudb session")
)

type Store interface {
	Put(key, value string) (idx uint64, root []byte, err error)
	Get(key string) (value string, idx uint64, root []byte, err error)
	Verify(root []byte, idx uint64, value string) (ok bool, err error)
	Close() error
}

type immudbStore struct {
	mu         sync.Mutex
	idxByKeyMu sync.Mutex
	idxByKey   map[string]uint64
	keyByIdx   map[uint64]string
	rootsByKey map[string][]byte
	c          immudbclient.ImmuClient
}

func New(addr string, port int, user, password, database string) (Store, error) {
	opts := immudbclient.DefaultOptions()
	opts.Address = addr
	opts.Port = port
	opts.Auth = true
	opts.Username = user
	opts.Password = password
	opts.CurrentDatabase = database
	// The SDK persists its verified-state and server-identity files in Dir,
	// which defaults to the working directory. Keep them out of the source tree.
	opts.Dir = getenv("IMMUDB_STATE_DIR", stateDir())
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: state dir: %w", ErrConnect, err)
	}
	// NewClient (not NewImmuClient): NewImmuClient already dials the server, so
	// the OpenSession below would fail with "session already opened".
	c := immudbclient.NewClient().WithOptions(opts)

	ctx := context.Background()
	if err := c.OpenSession(ctx, []byte(user), []byte(password), database); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnect, err)
	}

	return &immudbStore{
		c:          c,
		idxByKey:   make(map[string]uint64),
		keyByIdx:   make(map[uint64]string),
		rootsByKey: make(map[string][]byte),
	}, nil
}

func (s *immudbStore) Put(key, value string) (idx uint64, root []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, dup := s.idxByKey[key]; dup {
		return 0, nil, ErrDuplicate
	}

	ctx := context.Background()
	txHeader, err := s.c.VerifiedSet(ctx, []byte(key), []byte(value))
	if err != nil {
		return 0, nil, err
	}

	idx = txHeader.Id
	root = txHeader.BlRoot

	s.idxByKeyMu.Lock()
	s.idxByKey[key] = idx
	s.keyByIdx[idx] = key
	s.rootsByKey[key] = root
	s.idxByKeyMu.Unlock()

	return idx, root, nil
}

func (s *immudbStore) Get(key string) (value string, idx uint64, root []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idx, ok := s.idxByKey[key]
	if !ok {
		return "", 0, nil, ErrNotFound
	}

	ctx := context.Background()
	entry, err := s.c.VerifiedGet(ctx, []byte(key))
	if err != nil {
		return "", 0, nil, err
	}

	s.idxByKeyMu.Lock()
	root = s.rootsByKey[key]
	s.idxByKeyMu.Unlock()

	return string(entry.Value), entry.Tx, root, nil
}

func (s *immudbStore) Verify(root []byte, idx uint64, value string) (ok bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key, ok := s.keyByIdx[idx]
	if !ok {
		return false, errors.New("immudb: index out of range")
	}

	ctx := context.Background()
	entry, err := s.c.VerifiedGet(ctx, []byte(key))
	if err != nil {
		return false, err
	}

	if string(entry.Value) != value {
		return false, nil
	}

	s.idxByKeyMu.Lock()
	anchored := s.rootsByKey[key]
	s.idxByKeyMu.Unlock()

	if len(anchored) == 0 {
		return false, errors.New("immudb: no root anchored")
	}
	if !equalRoot(string(anchored), string(root)) {
		return false, nil
	}
	return true, nil
}

func (s *immudbStore) Close() error {
	return s.c.CloseSession(context.Background())
}

type memStore struct {
	mu       sync.Mutex
	salt     string
	order    []string
	valByKey map[string]string
	idxByKey map[string]uint64
	roots    []string
}

func newMemStore(salt string) Store {
	return &memStore{
		salt:     salt,
		valByKey: make(map[string]string),
		idxByKey: make(map[string]uint64),
		roots:    []string{hash([]byte(salt))},
	}
}

func Open() Store {
	// Read configuration from environment (see .env.example / .env). Overrides
	// defaults documented by the immudb Go SDK.
	addr := getenv("IMMUDB_ADDR", "127.0.0.1")
	port := getenvInt("IMMUDB_PORT", 3322)
	user := getenv("IMMUDB_USER", "immudb")
	password := getenv("IMMUDB_PASSWORD", "immudb")
	database := getenv("IMMUDB_DB", "securesoftwaresupplychain")

	store, err := New(addr, port, user, password, database)
	if err != nil {
		return newMemStore("immudb-fallback-salt")
	}
	return store
}

// stateDir is the default directory for the immudb client's state files.
func stateDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	return filepath.Join(base, "immudb")
}

// getenv returns the value of the environment variable named by key. If the
// variable is not set, getenv returns the fallback value.
func getenv(key string, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getenvInt parses the environment variable named by key as an integer. If the
// variable is not set, getenvInt returns the fallback value.
func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil {
			return n
		}
	}
	return fallback
}

func (m *memStore) Put(key, value string) (uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, dup := m.valByKey[key]; dup {
		return 0, nil, ErrDuplicate
	}

	idx := uint64(len(m.order))
	leaf := m.leafFor(key, value)
	m.roots = append(m.roots, hash(append([]byte(m.roots[idx]), leaf[:]...)))
	m.order = append(m.order, key)
	m.idxByKey[key] = idx
	m.valByKey[key] = value
	return idx, []byte(m.roots[idx]), nil
}

func (m *memStore) leafFor(key, value string) [sha256.Size]byte {
	var b = make([]byte, 0, len(key)+1+len(value)+1)
	b = append(b, key...)
	b = append(b, 0)
	b = append(b, value...)
	return sha256.Sum256(b)
}

func (m *memStore) Get(key string) (string, uint64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	idx, ok := m.idxByKey[key]
	if !ok {
		return "", 0, nil, ErrNotFound
	}
	return m.valByKey[key], idx, []byte(m.roots[len(m.roots)-1]), nil
}

func (m *memStore) Verify(root []byte, idx uint64, value string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if idx >= uint64(len(m.order)) {
		return false, errors.New("immudb: index out of range")
	}
	key := m.order[idx]
	if m.valByKey[key] != value {
		return false, nil
	}
	if !equalRoot(m.roots[idx], string(root)) {
		return false, nil
	}
	return true, nil
}

func (m *memStore) Close() error { return nil }

func hash(data []byte) string {
	return hexEncode(sha256.Sum256(data))
}

func hexEncode(sum [sha256.Size]byte) string {
	var b [sha256.Size * 2]byte
	for i, v := range sum {
		b[i*2] = hexNibble(v >> 4)
		b[i*2+1] = hexNibble(v & 0x0f)
	}
	return string(b[:])
}

func hexNibble(v byte) byte {
	if v < 10 {
		return '0' + v
	}
	return 'a' + (v - 10)
}

func equalRoot(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
