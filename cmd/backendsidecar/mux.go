package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	// Bound how long a probe waits on the app; the default transport has no
	// response-header timeout, so a wedged app would hang scrapes forever.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	p.proxy = &httputil.ReverseProxy{
		Transport: transport,
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
		p.logger.Warn("probe path denied",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"allowed_prefixes", p.prefixes,
		)
		metricProbeRequestsTotal.WithLabelValues("denied").Inc()
		http.Error(w, "probe path not allowed", http.StatusNotFound)
		return
	}
	metricProbeRequestsTotal.WithLabelValues("allowed").Inc()
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
		for _, part := range strings.Split(p, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			out = append(out, normalizeProbePath(part))
		}
	}
	return out
}

func validateProbeConfig(probeListen, probeForward string, pathPrefixes []string) error {
	prefixes := normalizePathPrefixes(pathPrefixes)
	if len(pathPrefixes) > 0 && len(prefixes) == 0 {
		return fmt.Errorf("--probe-path-prefix must not be empty when set")
	}
	if probeListen != "" {
		if len(prefixes) == 0 {
			return fmt.Errorf("--probe-listen requires at least one --probe-path-prefix")
		}
		if _, _, err := net.SplitHostPort(probeListen); err != nil {
			return fmt.Errorf("invalid --probe-listen %q: %w", probeListen, err)
		}
	}
	if probeForward == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(probeForward); err != nil {
		return fmt.Errorf("invalid --probe-forward %q: %w", probeForward, err)
	}
	return nil
}

// probeServer serves plain-HTTP probe connections with a real http.Server, so
// framing, keep-alive, streaming and timeouts are handled by net/http rather
// than by hand. Connections are fed in by the mux (after it has peeked the
// first byte) or by the dedicated --probe-listen accept loop.
type probeServer struct {
	srv *http.Server
	ln  *connListener
}

func newProbeServer(logger *slog.Logger, h http.Handler) *probeServer {
	ps := &probeServer{
		srv: &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
			ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		},
		ln: newConnListener(),
	}
	go func() { _ = ps.srv.Serve(ps.ln) }()
	return ps
}

// serveConn hands conn to the server, which then owns closing it.
func (ps *probeServer) serveConn(conn net.Conn) {
	if !ps.ln.push(conn) {
		_ = conn.Close()
	}
}

func (ps *probeServer) Close() error {
	return ps.srv.Close()
}

// connListener is a net.Listener whose connections are pushed in by the
// caller rather than accepted from a socket.
type connListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newConnListener() *connListener {
	return &connListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) push(c net.Conn) bool {
	select {
	case l.conns <- c:
		return true
	case <-l.done:
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return probeListenerAddr{} }

type probeListenerAddr struct{}

func (probeListenerAddr) Network() string { return "probe" }
func (probeListenerAddr) String() string  { return "probe" }

type sidecarMux struct {
	logger            *slog.Logger
	tlsConfig         *tls.Config
	forward           string
	probe             *probeHandler
	probeSrv          *probeServer
	allowHTTPOnListen bool
}

func newSidecarMux(logger *slog.Logger, tlsConfig *tls.Config, forward, probeForward, probeListen string, pathPrefixes []string) (*sidecarMux, error) {
	probe, err := newProbeHandler(logger.With("component", "probe"), probeForward, pathPrefixes)
	if err != nil {
		return nil, err
	}
	m := &sidecarMux{
		logger:            logger,
		tlsConfig:         tlsConfig,
		forward:           forward,
		probe:             probe,
		allowHTTPOnListen: probeListen == "",
	}
	if probe != nil {
		m.probeSrv = newProbeServer(logger.With("component", "probe"), probe)
	}
	return m, nil
}

// handleProbeConn serves a connection from the dedicated --probe-listen port.
func (m *sidecarMux) handleProbeConn(conn net.Conn) {
	if m.probeSrv == nil {
		_ = conn.Close()
		return
	}
	m.probeSrv.serveConn(conn)
}

// Close stops the probe server and any connections it is serving.
func (m *sidecarMux) Close() error {
	if m.probeSrv == nil {
		return nil
	}
	return m.probeSrv.Close()
}

func (m *sidecarMux) handle(conn net.Conn) {
	handedOff := false
	defer func() {
		if !handedOff {
			_ = conn.Close()
		}
	}()

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
			metricMTLSHandshakeErrorsTotal.Inc()
			m.logger.Debug("tls handshake failed", "remote", conn.RemoteAddr(), "error", err)
			return
		}
		metricMTLSConnectionsTotal.Inc()
		m.logger.Debug("proxying mTLS connection", "remote", conn.RemoteAddr(), "forward", m.forward)
		proxyConn(m.logger, tlsConn, m.forward)
	case connKindHTTP:
		if m.probe == nil {
			metricUnsupportedConnectionsTotal.Inc()
			m.logger.Debug("rejecting plain HTTP connection; no probe path prefixes configured", "remote", conn.RemoteAddr())
			return
		}
		if !m.allowHTTPOnListen {
			metricUnsupportedConnectionsTotal.Inc()
			m.logger.Debug("rejecting plain HTTP on mTLS listen port; configure --probe-listen for kubelet probes", "remote", conn.RemoteAddr())
			return
		}
		m.logger.Debug("serving probe HTTP", "remote", conn.RemoteAddr())
		handedOff = true
		m.probeSrv.serveConn(wrapped)
	default:
		metricUnsupportedConnectionsTotal.Inc()
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
