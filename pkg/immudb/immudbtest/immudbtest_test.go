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

package immudbtest

import (
	"testing"
)

// TestOpenUsesTheTestDatabase: tests write to the test database, never the
// pipeline's.
func TestOpenUsesTheTestDatabase(t *testing.T) {
	t.Setenv("IMMUDB_TEST_DB", "")
	if got := Open(t).Database(); got != DefaultDatabase {
		t.Fatalf("Open opened %s; want %s", got, DefaultDatabase)
	}
}

func TestDatabaseFromTheEnvironment(t *testing.T) {
	t.Setenv("IMMUDB_TEST_DB", "other_test")
	if got, err := Database(); err != nil || got != "other_test" {
		t.Fatalf("Database() = %s, %v; want other_test", got, err)
	}
}

// TestDatabaseRefusesAPipelineDatabase: a name without the _test suffix could
// be the pipeline's database, which the tests must not write to.
func TestDatabaseRefusesAPipelineDatabase(t *testing.T) {
	t.Setenv("IMMUDB_TEST_DB", "securesoftwaresupplychain")
	if got, err := Database(); err == nil {
		t.Fatalf("Database() = %s with IMMUDB_TEST_DB=securesoftwaresupplychain; want an error", got)
	}
}
