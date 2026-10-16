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
package ui

import (
	"context"
	"embed"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"
)

//go:embed observer.html observer.css
var static embed.FS

const (
	proxyAddr  = "127.0.0.1:8001"
	serveAddr  = "127.0.0.1:8002"
	proxyReady = 5 * time.Second
)

// Options choose the cluster the observer reads and whether it opens a browser.
type Options struct {
	// Context is the kubeconfig context to read; empty means the current one.
	Context string
	// NoBrowser leaves the browser closed, for running the observer as a service.
	NoBrowser bool
}

// Serve starts kubectl proxy, serves the embedded UI on :8002, and reverse-proxies
// the page's Kubernetes reads to kubectl proxy on :8001, refusing every other
// request (see readOnly). This avoids CORS entirely — the browser talks only to :8002.
// Blocks until Ctrl+C.
func Serve(ctx context.Context, opts Options) error {
	// ── 1. start kubectl proxy ──────────────────────────────────────────
	proxy, err := startProxy(opts.Context)
	if err != nil {
		return fmt.Errorf("kubectl proxy: %w", err)
	}
	defer proxy.stop()

	// ── 2. wait for proxy ───────────────────────────────────────────────
	fmt.Printf("  waiting for kubectl proxy on %s...\n", proxyAddr)
	if err := waitForPort(proxyAddr, proxyReady); err != nil {
		return fmt.Errorf("proxy did not come up: %w", err)
	}
	fmt.Println("  proxy ready ✓")

	// ── 3. reverse proxy → kubectl proxy on :8001 ──────────────────────
	k8sTarget, _ := url.Parse("http://" + proxyAddr)
	rp := newAPIProxy(k8sTarget)

	// ── 4. routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// The page and its stylesheet.
	serveFile := func(file, contentType string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			data, err := static.ReadFile(file)
			if err != nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", contentType)
			_, _ = w.Write(data)
		}
	}
	page := serveFile("observer.html", "text/html; charset=utf-8")
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page(w, r)
	})
	mux.HandleFunc("/observer.css", serveFile("observer.css", "text/css; charset=utf-8"))

	// Kubernetes API: only the page's reads, forwarded to kubectl proxy.
	api := readOnly(rp)
	mux.Handle("/api", api)
	mux.Handle("/api/", api)
	mux.Handle("/apis/", api)

	// What Rekor, Fulcio and the CT log themselves say, decoded for the page.
	mux.Handle("/sigstore/", newQuerier("http://"+proxyAddr).handler())

	// ── 5. start server ─────────────────────────────────────────────────
	srv := &http.Server{
		Addr:    serveAddr,
		Handler: mux,
	}

	serverErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	uiURL := fmt.Sprintf("http://%s", serveAddr)
	fmt.Printf("  UI at %s\n", uiURL)
	fmt.Println("  press Ctrl+C to stop")

	// ── 6. open browser ─────────────────────────────────────────────────
	if !opts.NoBrowser {
		time.Sleep(300 * time.Millisecond)
		if err := openBrowser(uiURL); err != nil {
			fmt.Printf("  open %s in your browser\n", uiURL)
		}
	}

	// ── 7. block until Ctrl+C, or until either half stops working ──────
	// Returning an error when kubectl proxy or the server dies lets a
	// service manager start the observer again instead of serving errors.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-quit:
	case <-ctx.Done():
	case <-proxy.exited:
		return fmt.Errorf("kubectl proxy exited: %v", proxy.err)
	case err := <-serverErr:
		return fmt.Errorf("ui server on %s: %w", serveAddr, err)
	}

	fmt.Println("\n  shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

// newAPIProxy forwards to kubectl proxy under its own address. kubectl proxy
// refuses any Host but localhost (--accept-hosts), and a reverse proxy keeps
// the browser's Host by default, so the page broke whenever it was opened by
// any other name, such as a Tailscale one.
func newAPIProxy(target *url.URL) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(target)
	direct := rp.Director
	rp.Director = func(r *http.Request) {
		direct(r)
		r.Host = target.Host
	}
	return rp
}

// proxyProcess is the kubectl proxy the observer started.
type proxyProcess struct {
	cmd    *exec.Cmd
	exited chan struct{} // closed once kubectl proxy has exited
	err    error         // why it exited, valid once exited is closed
	once   sync.Once
}

// stop kills kubectl proxy and waits for it, so it never outlives the observer
// and holds the port for the next one.
func (p *proxyProcess) stop() {
	p.once.Do(func() {
		_ = p.cmd.Process.Kill()
		<-p.exited
	})
}

func startProxy(kubeContext string) (*proxyProcess, error) {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return nil, fmt.Errorf("kubectl not found in PATH")
	}
	// Anything already on the port would answer for us, possibly for another
	// cluster or with no access at all; refuse rather than read through it.
	l, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("%s is in use; stop whatever holds it (often an earlier kubectl proxy): %w", proxyAddr, err)
	}
	_ = l.Close()

	args := []string{"proxy", "--port=8001", "--address=127.0.0.1"}
	if kubeContext != "" {
		args = append(args, "--context="+kubeContext)
	}
	cmd := exec.Command("kubectl", args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting kubectl proxy: %w", err)
	}
	fmt.Printf("  kubectl proxy started (pid %d)\n", cmd.Process.Pid)
	p := &proxyProcess{cmd: cmd, exited: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.exited)
	}()
	return p, nil
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

func openBrowser(rawURL string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "linux":
		cmd, args = "xdg-open", []string{rawURL}
	case "darwin":
		cmd, args = "open", []string{rawURL}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", rawURL}
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	return exec.Command(cmd, args...).Start()
}
