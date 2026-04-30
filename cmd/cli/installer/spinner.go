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
	"fmt"
	"sync"
	"time"
)

// spinner provides a simple terminal spinner for long-running operations.
// It renders a cycling animation on a single line, then clears itself
// when stopped so the caller can print the final status.
type spinner struct {
	message string
	frames  []string
	stop    chan struct{}
	done    chan struct{}
	mu      sync.Mutex
}

// newSpinner creates a spinner with the given message.
func newSpinner(message string) *spinner {
	return &spinner{
		message: message,
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// start begins the spinner animation in a goroutine.
func (s *spinner) start() {
	go func() {
		defer close(s.done)
		i := 0
		for {
			select {
			case <-s.stop:
				// Clear the spinner line.
				fmt.Printf("\r\033[K")
				return
			default:
				s.mu.Lock()
				fmt.Printf("\r  %s %s", s.frames[i%len(s.frames)], s.message)
				s.mu.Unlock()
				i++
				time.Sleep(80 * time.Millisecond)
			}
		}
	}()
}

// updateMessage changes the spinner message while it's running.
func (s *spinner) updateMessage(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.message = msg
}

// succeed stops the spinner and prints a success message.
func (s *spinner) succeed(msg string) {
	close(s.stop)
	<-s.done
	fmt.Printf("  ✓ %s\n", msg)
}

// fail stops the spinner and prints a failure message.
func (s *spinner) fail(msg string) {
	close(s.stop)
	<-s.done
	fmt.Printf("  ✗ %s\n", msg)
}
