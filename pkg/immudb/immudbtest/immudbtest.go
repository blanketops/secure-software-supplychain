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

// Package immudbtest opens the immudb database tests write to. It is never
// the pipeline's database: immudb keeps every write, so test rows written
// there would stay next to real builds' evidence for good.
package immudbtest

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/blanketops/secure-software-supplychain/pkg/immudb"
)

// DefaultDatabase is the test database when IMMUDB_TEST_DB is not set: the
// pipeline database's name with a _test suffix.
const DefaultDatabase = "securesoftwaresupplychain_test"

// Database is the test database, IMMUDB_TEST_DB or DefaultDatabase. A name
// without the _test suffix is refused: it could be the pipeline's.
func Database() (string, error) {
	name := os.Getenv("IMMUDB_TEST_DB")
	if name == "" {
		name = DefaultDatabase
	}
	if !strings.HasSuffix(name, "_test") {
		return "", fmt.Errorf("IMMUDB_TEST_DB=%s does not end in _test; tests do not write to a pipeline database", name)
	}
	return name, nil
}

// Use points IMMUDB_DB at the test database for the rest of the test and
// creates it if needed, so that immudb.Open opens it. The test fails if the
// server cannot be reached: there is no fallback.
func Use(t testing.TB) {
	t.Helper()
	name, err := Database()
	if err != nil {
		t.Fatal(err)
	}
	if err := immudb.CreateDatabase(name); err != nil {
		t.Fatalf("immudb is required for these tests: %v", err)
	}
	t.Setenv("IMMUDB_DB", name)
}

// Open opens a store on the test database, closed when the test ends.
func Open(t testing.TB) immudb.Store {
	t.Helper()
	Use(t)
	s, err := immudb.Open()
	if err != nil {
		t.Fatalf("immudb is required for these tests: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
