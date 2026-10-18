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

// Package immudb stores supply chain evidence in an immudb database. Every
// write and read goes to the server and is verified against the client's
// trusted state; there is no in-memory fallback.
package immudb

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/codenotary/immudb/embedded"
	"github.com/codenotary/immudb/pkg/api/schema"
	immudbclient "github.com/codenotary/immudb/pkg/client"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrDuplicate = errors.New("immudb: record already stored")
	ErrNotFound  = errors.New("immudb: no such record")
	ErrConnect   = errors.New("immudb: failed to open immudb session")
)

// Store is an append-only, tamper-evident key-value store.
//
// tx is the immudb transaction that wrote the value. root is that
// transaction's accumulated linear hash (Alh), which commits to the whole
// history up to and including the write.
type Store interface {
	// Put writes a new key. It returns ErrDuplicate if the key exists.
	Put(key, value string) (tx uint64, root []byte, err error)
	// PutAll writes every entry in a single transaction. Every key must be
	// new: if any exists, nothing is written and the error is ErrDuplicate.
	PutAll(entries []Entry) (tx uint64, root []byte, err error)
	// Get returns the current value of key, or ErrNotFound.
	Get(key string) (value string, tx uint64, root []byte, err error)
	// Verify reports whether transaction tx wrote value under key and its
	// root is root.
	Verify(key string, root []byte, tx uint64, value string) (ok bool, err error)
	// ExecAll runs SQL statements in one transaction: all are committed or
	// none. Inserting an existing primary key is ErrDuplicate.
	ExecAll(stmts ...Statement) (tx uint64, root []byte, err error)
	// QueryVerified runs a SELECT on table and verifies every returned row;
	// pk names the primary key columns, which the query must select.
	QueryVerified(table string, pk []string, sql string, params map[string]any) ([]Row, error)
	// Root returns the root of transaction tx, verified against the
	// client's trusted state.
	Root(tx uint64) ([]byte, error)
	// Columns returns the columns of table, in order.
	Columns(table string) ([]string, error)
	// Database is the immudb database the store reads and writes.
	Database() string
	Close() error
}

// Entry is one key and value of a PutAll transaction.
type Entry struct {
	Key   string
	Value string
}

type immudbStore struct {
	c        immudbclient.ImmuClient
	database string
}

func (s *immudbStore) Database() string { return s.database }

// Open connects to the immudb server configured by IMMUDB_ADDR, IMMUDB_PORT,
// IMMUDB_USER, IMMUDB_PASSWORD and IMMUDB_DB (defaults: the immudb container's
// 127.0.0.1:3322, immudb/immudb, database securesoftwaresupplychain). It
// returns an error if the server cannot be reached or rejects the login.
func Open() (Store, error) {
	return New(
		getenv("IMMUDB_ADDR", "127.0.0.1"),
		getenvInt("IMMUDB_PORT", 3322),
		getenv("IMMUDB_USER", "immudb"),
		getenv("IMMUDB_PASSWORD", "immudb"),
		getenv("IMMUDB_DB", "securesoftwaresupplychain"),
	)
}

// New opens a session on the given immudb server and database.
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
	if err := c.OpenSession(context.Background(), []byte(user), []byte(password), database); err != nil {
		return nil, fmt.Errorf("%w at %s:%d (user %s, database %s): %w", ErrConnect, addr, port, user, database, err)
	}
	return &immudbStore{c: c, database: database}, nil
}

func (s *immudbStore) Put(key, value string) (uint64, []byte, error) {
	return s.PutAll([]Entry{{Key: key, Value: value}})
}

func (s *immudbStore) PutAll(entries []Entry) (uint64, []byte, error) {
	if len(entries) == 0 {
		return 0, nil, errors.New("immudb: no entries to write")
	}
	ctx := context.Background()
	req := &schema.SetRequest{}
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		if seen[e.Key] {
			return 0, nil, fmt.Errorf("immudb: key %s appears twice in one transaction", e.Key)
		}
		seen[e.Key] = true
		k := []byte(e.Key)
		req.KVs = append(req.KVs, &schema.KeyValue{Key: k, Value: []byte(e.Value)})
		req.Preconditions = append(req.Preconditions, schema.PreconditionKeyMustNotExist(k))
	}

	// VerifiedSet takes no preconditions and only one key, so write with
	// SetAll and then prove the write with verified reads of every key and of
	// the transaction.
	hdr, err := s.c.SetAll(ctx, req)
	if err != nil {
		if status.Code(err) == codes.FailedPrecondition {
			return 0, nil, fmt.Errorf("%w: a key of the %d-entry transaction starting with %s exists", ErrDuplicate, len(entries), entries[0].Key)
		}
		return 0, nil, fmt.Errorf("immudb: put %s: %w", entries[0].Key, err)
	}
	for _, e := range entries {
		entry, err := s.c.VerifiedGetAt(ctx, []byte(e.Key), hdr.Id)
		if err != nil {
			return 0, nil, fmt.Errorf("immudb: verify put %s at tx %d: %w", e.Key, hdr.Id, err)
		}
		if string(entry.Value) != e.Value {
			return 0, nil, fmt.Errorf("immudb: put %s at tx %d: stored value differs from the value written", e.Key, hdr.Id)
		}
	}
	root, err := s.root(ctx, hdr.Id)
	if err != nil {
		return 0, nil, err
	}
	return hdr.Id, root, nil
}

func (s *immudbStore) Get(key string) (string, uint64, []byte, error) {
	ctx := context.Background()
	entry, err := s.c.VerifiedGet(ctx, []byte(key))
	if err != nil {
		if isKeyNotFound(err) {
			return "", 0, nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return "", 0, nil, fmt.Errorf("immudb: get %s: %w", key, err)
	}
	root, err := s.root(ctx, entry.Tx)
	if err != nil {
		return "", 0, nil, err
	}
	return string(entry.Value), entry.Tx, root, nil
}

func (s *immudbStore) Verify(key string, root []byte, tx uint64, value string) (bool, error) {
	ctx := context.Background()
	entry, err := s.c.VerifiedGetAt(ctx, []byte(key), tx)
	if err != nil {
		if isKeyNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("immudb: verify %s at tx %d: %w", key, tx, err)
	}
	if entry.Tx != tx || string(entry.Value) != value {
		return false, nil
	}
	got, err := s.root(ctx, tx)
	if err != nil {
		return false, err
	}
	return bytes.Equal(got, root), nil
}

func (s *immudbStore) Close() error {
	return s.c.CloseSession(context.Background())
}

func (s *immudbStore) Root(tx uint64) ([]byte, error) {
	return s.root(context.Background(), tx)
}

// CreateDatabase creates the database name on the immudb server configured
// by the IMMUDB_* variables, if it does not exist. The login must be allowed
// to create databases. A name is lowercase letters, digits and underscores,
// as immudb requires.
func CreateDatabase(name string) error {
	if !isIdentifier(name) {
		return fmt.Errorf("immudb: %q is not a database name: use lowercase letters, digits and underscores", name)
	}
	s, err := New(
		getenv("IMMUDB_ADDR", "127.0.0.1"),
		getenvInt("IMMUDB_PORT", 3322),
		getenv("IMMUDB_USER", "immudb"),
		getenv("IMMUDB_PASSWORD", "immudb"),
		"defaultdb",
	)
	if err != nil {
		return err
	}
	defer func() { _ = s.Close() }()
	if _, err := s.(*immudbStore).c.SQLExec(context.Background(), "CREATE DATABASE IF NOT EXISTS "+name, nil); err != nil {
		return fmt.Errorf("immudb: create database %s: %w", name, err)
	}
	return nil
}

// isIdentifier reports whether name is a database or table name immudb
// accepts and that is safe to place in SQL text: lowercase letters, digits
// and underscores.
func isIdentifier(name string) bool {
	return name != "" && strings.TrimFunc(name, func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_'
	}) == ""
}

// root returns the accumulated linear hash of transaction tx, read with a
// proof against the client's trusted state.
func (s *immudbStore) root(ctx context.Context, tx uint64) ([]byte, error) {
	vtx, err := s.c.VerifiedTxByID(ctx, tx)
	if err != nil {
		return nil, fmt.Errorf("immudb: verify tx %d: %w", tx, err)
	}
	alh := schema.TxHeaderFromProto(vtx.Header).Alh()
	return alh[:], nil
}

// isKeyNotFound reports whether err is the server's "key not found". The
// server sends it as gRPC Unknown, so only the message identifies it.
func isKeyNotFound(err error) bool {
	st, ok := status.FromError(err)
	return ok && strings.HasSuffix(st.Message(), embedded.ErrKeyNotFound.Error())
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
