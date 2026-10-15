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

// Command go2allure converts `go test -json` output into Allure result files.
//
// Allure's JUnit reader gives each test a pass/fail and a duration but no body:
// go-junit-report emits an empty <testcase> for a passing test, so the Allure
// report shows "no execution" when a test is opened. Allure's native result
// files carry the test's own output, which `go test -json` streams per test as
// "output" events. This reads that stream and writes one
// <uuid>-result.json per test into the output directory, each with the test's
// captured log as an attachment, so every test — passing or failing — has a
// body to read.
//
// It changes no test: the tests run exactly as before, piped through here.
//
//	go test -json ./... | go2allure -o allure-results
//
// The test's own exit status is not this tool's concern; the caller keeps the
// go test exit code. This always exits 0 unless it cannot write the results.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// event is one line of `go test -json` output. Only the fields used here are
// declared; the rest of each line is ignored.
type event struct {
	Time    time.Time `json:"Time"`
	Action  string    `json:"Action"` // run, output, pass, fail, skip, ...
	Package string    `json:"Package"`
	Test    string    `json:"Test"` // empty for package-level events
	Output  string    `json:"Output"`
	Elapsed float64   `json:"Elapsed"` // seconds, on pass/fail/skip
}

// result is the subset of the Allure result schema this tool writes. Allure
// ignores fields it does not know and fills in defaults for those left out.
type result struct {
	UUID          string        `json:"uuid"`
	HistoryID     string        `json:"historyId"`
	Name          string        `json:"name"`
	FullName      string        `json:"fullName"`
	Status        string        `json:"status"` // passed, failed, broken, skipped
	StatusDetails statusDetails `json:"statusDetails,omitempty"`
	Stage         string        `json:"stage"` // finished
	Start         int64         `json:"start"` // epoch ms
	Stop          int64         `json:"stop"`  // epoch ms
	Labels        []label       `json:"labels"`
	Attachments   []attachment  `json:"attachments,omitempty"`
}

type statusDetails struct {
	Message string `json:"message,omitempty"`
	Trace   string `json:"trace,omitempty"`
}

type label struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type attachment struct {
	Name   string `json:"name"`
	Source string `json:"source"` // file name within the results dir
	Type   string `json:"type"`   // MIME type
}

// testRun accumulates the events of one test until it ends.
type testRun struct {
	pkg     string
	name    string
	output  strings.Builder
	start   time.Time
	stop    time.Time
	status  string
	elapsed float64
}

func main() {
	out := flag.String("o", "allure-results", "directory to write Allure result files into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "go2allure: %v\n", err)
		os.Exit(1)
	}

	// key is package + "." + test; a test name is only unique within its
	// package, and subtests share a parent's prefix.
	runs := map[string]*testRun{}
	order := []string{}

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] != '{' {
			continue // not a JSON event (e.g. a build error line)
		}
		var ev event
		if err := json.Unmarshal(line, &ev); err != nil {
			continue
		}
		if ev.Test == "" {
			continue // package-level event, not a test
		}
		key := ev.Package + "." + ev.Test
		run, ok := runs[key]
		if !ok {
			run = &testRun{pkg: ev.Package, name: ev.Test, start: ev.Time}
			runs[key] = run
			order = append(order, key)
		}
		switch ev.Action {
		case "run":
			run.start = ev.Time
		case "output":
			run.output.WriteString(ev.Output)
		case "pass":
			run.status, run.stop, run.elapsed = "passed", ev.Time, ev.Elapsed
		case "fail":
			run.status, run.stop, run.elapsed = "failed", ev.Time, ev.Elapsed
		case "skip":
			run.status, run.stop, run.elapsed = "skipped", ev.Time, ev.Elapsed
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "go2allure: reading input: %v\n", err)
		os.Exit(1)
	}

	written := 0
	for _, key := range order {
		run := runs[key]
		if run.status == "" {
			// A test with no terminal event (e.g. a panic took the process
			// down) is reported as broken so it is not silently dropped.
			run.status = "broken"
			run.stop = run.start
		}
		if err := writeResult(*out, run); err != nil {
			fmt.Fprintf(os.Stderr, "go2allure: %v\n", err)
			os.Exit(1)
		}
		written++
	}
	fmt.Fprintf(os.Stderr, "go2allure: wrote %d result files to %s\n", written, *out)
}

// writeResult writes one test's result file and its output attachment.
func writeResult(dir string, run *testRun) error {
	body := run.output.String()

	// A stable id so Allure can track a test across runs: the package and the
	// full test name identify it, independent of where it ran.
	sum := sha256.Sum256([]byte(run.pkg + "." + run.name))
	uuid := hex.EncodeToString(sum[:16])

	res := result{
		UUID:      uuid,
		HistoryID: uuid,
		Name:      displayName(run.name),
		FullName:  run.pkg + "." + run.name,
		Status:    run.status,
		Stage:     "finished",
		Start:     run.start.UnixMilli(),
		Stop:      stop(run),
		Labels: []label{
			{Name: "package", Value: run.pkg},
			{Name: "suite", Value: run.pkg},
			{Name: "framework", Value: "go-test"},
			{Name: "language", Value: "go"},
		},
	}

	// The test's captured output is its body: attach it so opening the test in
	// Allure shows what it logged, which is what "no execution" was missing.
	if strings.TrimSpace(body) != "" {
		attName := uuid + "-output.txt"
		if err := os.WriteFile(filepath.Join(dir, attName), []byte(body), 0o644); err != nil {
			return err
		}
		res.Attachments = []attachment{{Name: "Test output", Source: attName, Type: "text/plain"}}
		// A failed test's last lines are the most useful thing to see first.
		if run.status == "failed" || run.status == "broken" {
			res.StatusDetails = statusDetails{Message: lastLine(body), Trace: body}
		}
	}

	data, err := json.MarshalIndent(&res, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, uuid+"-result.json"), data, 0o644)
}

// stop returns the stop time, derived from the elapsed seconds when the stream
// gave one, so a sub-millisecond test still shows a non-zero duration.
func stop(run *testRun) int64 {
	if !run.stop.IsZero() {
		return run.stop.UnixMilli()
	}
	return run.start.Add(time.Duration(run.elapsed * float64(time.Second))).UnixMilli()
}

// displayName is the last segment of a Go subtest name ("Parent/child" -> the
// part shown), so subtests read cleanly while fullName keeps the whole path.
func displayName(name string) string {
	if i := strings.LastIndex(name, "/"); i >= 0 {
		return name[i+1:]
	}
	return name
}

// lastLine is the final non-empty line of the output, used as the one-line
// failure message in the Allure list view.
func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			return strings.TrimSpace(lines[i])
		}
	}
	return ""
}
