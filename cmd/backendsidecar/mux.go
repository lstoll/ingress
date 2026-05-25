package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

// TLS records begin with byte 0x16 (handshake).
const tlsRecordTypeHandshake = 0x16

type probeHandler struct {
	logger   *slog.Logger
	prefixes []string
	forward  string
	proxy    *httputil.ReverseProxy
}

func newProbeHandler(logger *slog.Logger, forwardAddr string, pathPrefixes []string) (*probeHandler, error) {
	prefixes := normalizePathPrefixes(pathPrefixes)
	if len(prefixes) == 0 {
		return nil, nil
	}

	upstreamURL, err := url.Parse("http://" + forwardAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing probe forward address: %w", err)
	}

	p := &probeHandler{
		logger:   logger,
		prefixes: prefixes,
		forward:  forwardAddr,
	}
	p.proxy = &httputil.ReverseProxy{
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(upstreamURL)
			req.Out.Host = upstreamURL.Host
		},
		ErrorHandler: func(rw http.ResponseWriter, req *http.Request, err error) {
			logger.Warn("probe proxy error", "path", req.URL.Path, "error", err)
			http.Error(rw, http.StatusText(http.StatusBadGateway), http.StatusBadGateway)
		},
	}
	return p, nil
}

func (p *probeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !p.pathAllowed(r.URL.Path) {
		p.logger.Debug("probe path denied", "path", r.URL.Path, "remote", r.RemoteAddr)
		http.NotFound(w, r)
		return
	}
	p.proxy.ServeHTTP(w, r)
}

func (p *probeHandler) pathAllowed(path string) bool {
	path = normalizeProbePath(path)
	for _, prefix := range p.prefixes {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

func normalizeProbePath(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if path != "/" {
		path = strings.TrimSuffix(path, "/")
	}
	return path
}

func normalizePathPrefixes(prefixes []string) []string {
	var out []string
	for _, p := range prefixes {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, normalizeProbePath(p))
	}
	return out
}

func validateProbeForward(probeForward string, pathPrefixes []string) error {
	if len(pathPrefixes) > 0 && len(normalizePathPrefixes(pathPrefixes)) == 0 {
		return fmt.Errorf("--probe-path-prefix must not be empty when set")
	}
	if probeForward == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(probeForward); err != nil {
		return fmt.Errorf("invalid --probe-forward %q: %w", probeForward, err)
	}
	return nil
}

type sidecarMux struct {
	logger    *slog.Logger
	tlsConfig *tls.Config
	forward   string
	probe     *probeHandler
}

func newSidecarMux(logger *slog.Logger, tlsConfig *tls.Config, forward, probeForward string, pathPrefixes []string) (*sidecarMux, error) {
	probe, err := newProbeHandler(logger.With("component", "probe"), probeForward, pathPrefixes)
	if err != nil {
		return nil, err
	}
	return &sidecarMux{
		logger:    logger,
		tlsConfig: tlsConfig,
		forward:   forward,
		probe:     probe,
	}, nil
}

func (m *sidecarMux) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}
	br := bufio.NewReader(conn)
	kind, err := peekConnKind(br)
	if err != nil {
		m.logger.Debug("peeking connection kind", "remote", conn.RemoteAddr(), "error", err)
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	wrapped := &bufioConn{Conn: conn, r: br}

	switch kind {
	case connKindTLS:
		tlsConn := tls.Server(wrapped, m.tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			m.logger.Debug("tls handshake failed", "remote", conn.RemoteAddr(), "error", err)
			return
		}
		m.logger.Debug("proxying mTLS connection", "remote", conn.RemoteAddr(), "forward", m.forward)
		proxyConn(m.logger, tlsConn, m.forward)
	case connKindHTTP:
		if m.probe == nil {
			m.logger.Debug("rejecting plain HTTP connection; no probe path prefixes configured", "remote", conn.RemoteAddr())
			return
		}
		m.logger.Debug("serving probe HTTP", "remote", conn.RemoteAddr())
		serveProbeHTTP(m.probe, wrapped, br)
	default:
		m.logger.Debug("unsupported connection kind", "remote", conn.RemoteAddr(), "kind", kind)
	}
}

type connKind int

const (
	connKindUnknown connKind = iota
	connKindTLS
	connKindHTTP
)

func peekConnKind(br *bufio.Reader) (connKind, error) {
	b, err := br.Peek(1)
	if err != nil {
		return connKindUnknown, err
	}
	switch b[0] {
	case tlsRecordTypeHandshake:
		return connKindTLS, nil
	case 'G', 'H', 'P', 'D', 'C', 'T', 'O': // common HTTP methods
		return connKindHTTP, nil
	default:
		return connKindUnknown, nil
	}
}

type bufioConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufioConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func serveProbeHTTP(h http.Handler, conn net.Conn, br *bufio.Reader) {
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		req.RemoteAddr = conn.RemoteAddr().String()

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		resp := rec.Result()
		resp.Request = req
		if err := resp.Write(conn); err != nil {
			return
		}
		if req.Close || resp.Close {
			return
		}
	}
}

func proxyConn(logger *slog.Logger, client net.Conn, forwardAddr string) {
	upstream, err := net.DialTimeout("tcp", forwardAddr, 10*time.Second)
	if err != nil {
		logger.Warn("dialing forward target", "forward", forwardAddr, "error", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, client)
		closeWrite(upstream)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		closeWrite(client)
	}()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
