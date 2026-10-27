package main

import (
	"errors"
	"net/http"
	"os"
	"time"
)

const responseWriteIdleTimeout = 2 * time.Minute

// Refresh the write deadline as a response progresses. http.Server.WriteTimeout
// alone is an absolute response lifetime, which cuts off active radio streams,
// SSE and other long responses. A blocked write still expires after timeout.
func withWriteIdleTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		iw := &idleTimeoutWriter{ResponseWriter: w, timeout: timeout}
		if err := iw.refreshDeadline(); err != nil {
			http.Error(w, "Unable to initialize response deadline", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(iw, r)
	})
}

type idleTimeoutWriter struct {
	http.ResponseWriter
	timeout  time.Duration
	deadline time.Time
}

func (w *idleTimeoutWriter) refreshDeadline() error {
	now := time.Now()
	// Do not revive an already expired HTTP/1 write deadline. Unlike HTTP/2,
	// HTTP/1 only notices expiry when another network operation occurs.
	if !w.deadline.IsZero() && !now.Before(w.deadline) {
		return os.ErrDeadlineExceeded
	}
	w.deadline = now.Add(w.timeout)
	err := http.NewResponseController(w.ResponseWriter).SetWriteDeadline(w.deadline)
	if errors.Is(err, http.ErrNotSupported) {
		return nil
	}
	return err
}

func (w *idleTimeoutWriter) Write(b []byte) (int, error) {
	if err := w.refreshDeadline(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(b)
}

func (w *idleTimeoutWriter) FlushError() error {
	if err := w.refreshDeadline(); err != nil {
		return err
	}
	return http.NewResponseController(w.ResponseWriter).Flush()
}

// Preserve ResponseController access to Hijack and other underlying operations.
func (w *idleTimeoutWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
