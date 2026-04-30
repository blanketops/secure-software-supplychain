/*
Copyright 2026.
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
	"syscall"
	"time"
)

//go:embed supply_chain.html rbac.html
var static embed.FS

const (
	proxyAddr  = "127.0.0.1:8001"
	serveAddr  = "127.0.0.1:8002"
	proxyReady = 5 * time.Second
)

// Serve starts kubectl proxy, serves the embedded UI on :8002, and reverse-proxies
// all /api/ and /apis/ requests to kubectl proxy on :8001.
// This avoids CORS entirely — the browser talks only to :8002.
// Blocks until Ctrl+C.
func Serve(ctx context.Context, page string) error {
	// ── 1. start kubectl proxy ──────────────────────────────────────────
	proxyCtx, proxyCancel := context.WithCancel(ctx)
	defer proxyCancel()

	if err := startProxy(proxyCtx); err != nil {
		return fmt.Errorf("kubectl proxy: %w", err)
	}

	// ── 2. wait for proxy ───────────────────────────────────────────────
	fmt.Printf("  waiting for kubectl proxy on %s...\n", proxyAddr)
	if err := waitForPort(proxyAddr, proxyReady); err != nil {
		return fmt.Errorf("proxy did not come up: %w", err)
	}
	fmt.Println("  proxy ready ✓")

	// ── 3. reverse proxy → kubectl proxy on :8001 ──────────────────────
	k8sTarget, _ := url.Parse("http://" + proxyAddr)
	rp := httputil.NewSingleHostReverseProxy(k8sTarget)

	// ── 4. routes ───────────────────────────────────────────────────────
	mux := http.NewServeMux()

	// UI page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		f := page
		if f == "" {
			f = "supply_chain.html"
		}
		data, err := static.ReadFile(f)
		if err != nil {
			http.Error(w, "page not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	// Kubernetes core API — forwarded to kubectl proxy
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r)
	})

	// Kubernetes extension APIs — forwarded to kubectl proxy
	mux.HandleFunc("/apis/", func(w http.ResponseWriter, r *http.Request) {
		rp.ServeHTTP(w, r)
	})

	// ── 5. start server ─────────────────────────────────────────────────
	srv := &http.Server{
		Addr:    serveAddr,
		Handler: mux,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "  ui server error: %v\n", err)
		}
	}()

	uiURL := fmt.Sprintf("http://%s", serveAddr)
	fmt.Printf("  UI at %s\n", uiURL)
	fmt.Println("  press Ctrl+C to stop")

	// ── 6. open browser ─────────────────────────────────────────────────
	time.Sleep(300 * time.Millisecond)
	if err := openBrowser(uiURL); err != nil {
		fmt.Printf("  open %s in your browser\n", uiURL)
	}

	// ── 7. block until Ctrl+C ───────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("\n  shutting down...")
	shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return srv.Shutdown(shutCtx)
}

func startProxy(ctx context.Context) error {
	if _, err := exec.LookPath("kubectl"); err != nil {
		return fmt.Errorf("kubectl not found in PATH")
	}
	cmd := exec.CommandContext(ctx, "kubectl", "proxy", "--port=8001", "--address=127.0.0.1")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting kubectl proxy: %w", err)
	}
	fmt.Printf("  kubectl proxy started (pid %d)\n", cmd.Process.Pid)
	go func() {
		<-ctx.Done()
		_ = cmd.Process.Kill()
	}()
	return nil
}

func waitForPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s", addr)
}

func openBrowser(url string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "linux":
		cmd, args = "xdg-open", []string{url}
	case "darwin":
		cmd, args = "open", []string{url}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	return exec.Command(cmd, args...).Start()
}
