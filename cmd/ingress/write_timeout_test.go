package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestProxyStreamingOutlivesWriteTimeout(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", http2), func(t *testing.T) {
			const timeout = 200 * time.Millisecond
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "audio/aacp")
				for range 20 {
					if _, err := io.WriteString(w, "audio\n"); err != nil {
						return
					}
					if err := http.NewResponseController(w).Flush(); err != nil {
						return
					}
					select {
					case <-time.After(25 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
				}
			}))
			defer backend.Close()
			target, err := url.Parse(backend.URL)
			if err != nil {
				t.Fatal(err)
			}
			proxy := httputil.NewSingleHostReverseProxy(target)
			// Match the statusWriter/ResponseController stack in serveHTTPForOwner.
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				proxy.ServeHTTP(&statusWriter{ResponseWriter: w}, r)
			})
			server := httptest.NewUnstartedServer(withWriteIdleTimeout(handler, timeout))
			server.EnableHTTP2 = http2
			server.Config.WriteTimeout = timeout
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = 3 * time.Second
			start := time.Now()
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			if http2 && resp.ProtoMajor != 2 {
				t.Fatalf("expected HTTP/2, got %s", resp.Proto)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(body), strings.Repeat("audio\n", 20); got != want {
				t.Fatalf("truncated response: got %d, want %d bytes", len(got), len(want))
			}
			if time.Since(start) < 2*timeout {
				t.Fatal("stream did not outlive the original write deadline")
			}
		})
	}
}

func TestIdleResponseStillTimesOut(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("HTTP2=%t", http2), func(t *testing.T) {
			const timeout = 100 * time.Millisecond
			done := make(chan error, 1)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.WriteString(w, "start\n"); err != nil {
					done <- err
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					done <- err
					return
				}
				select {
				case <-time.After(3 * timeout):
					_, err := io.WriteString(w, "too late\n")
					if err == nil {
						err = http.NewResponseController(w).Flush()
					}
					done <- err
				case <-r.Context().Done():
					done <- r.Context().Err()
				}
			})
			server := httptest.NewUnstartedServer(withWriteIdleTimeout(handler, timeout))
			server.EnableHTTP2 = http2
			server.Config.WriteTimeout = timeout
			server.StartTLS()
			defer server.Close()
			client := server.Client()
			client.Timeout = 2 * time.Second
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err == nil {
				t.Fatalf("idle response unexpectedly completed: %q", body)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("idle writer did not time out")
				}
			case <-time.After(time.Second):
				t.Fatal("idle handler did not stop")
			}
		})
	}
}
