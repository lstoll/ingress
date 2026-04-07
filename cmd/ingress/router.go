// TLS front router: two data structures, one mutex.
//
// Layer 1 — tlsHostnameToService: "this TLS SNI (canonical hostname) is claimed
// by which Kubernetes Service?" Used for tcpproxy matching, cert allowlists,
// and HTTP→HTTPS redirects. No handlers or upstream addresses.
//
// Layer 2 — serviceBindings: "for this Service (NamespacedName), what is the
// workload?" (mode, ClusterIP:port, passthrough dial proxy, per-host HTTPS
// stacks). Every byte after SNI resolution is handled only via the binding for
// the Service that owns that SNI.
//
// HTTPS: one http.Server per Service, channel-fed; Host must match SNI (421).
//
// Mutex ordering (no nesting; always acquired/released sequentially):
//   mu        — protects layer 1 + layer 2 maps (RWMutex, short hold)
//   ownerMu   — protects ownerCancel map
//   httpsMu   — protects httpsByOwner map + HTTP server lifecycle

package main

import (
	"context"
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

	"golang.org/x/net/http2"
	"inet.af/tcpproxy"
	"k8s.io/apimachinery/pkg/types"
)

var _ tcpproxy.Target = (*ingressRouter)(nil)

// serviceBinding is the full ingress spec for one Kubernetes Service (from
// annotations). Upstreams and HTTP handlers exist only here—not in the SNI map.
type serviceBinding struct {
	serviceRef types.NamespacedName // which Service this binding belongs to
	mode       string
	targetAddr string

	passthrough *tcpproxy.DialProxy

	// modeHTTPS: canonical hostname → vhost handler chain for that Service.
	httpsHosts map[string]httpsHostBinding

	hostnames []string // canonical names this Service claims (for index cleanup)
}

type httpsHostBinding struct {
	handler http.Handler
	proxy   *httputil.ReverseProxy
	oidc    *oidcConfig
}

// route is a snapshot for tests and introspection (RouteFor).
type route struct {
	Owner       types.NamespacedName
	TargetAddr  string
	Mode        string
	Proxy       *tcpproxy.DialProxy
	HTTPProxy   *httputil.ReverseProxy
	HTTPHandler http.Handler
	OIDC        *oidcConfig
}

type ingressRouter struct {
	logger  *slog.Logger
	baseCtx context.Context

	authMiddlewareBuilder func(ctx context.Context, host string, cfg oidcConfig) (func(http.Handler) http.Handler, error)

	mu sync.RWMutex // see mutex ordering comment at top of file

	// Layer 1 — SNI / redirect / cert policy: canonical hostname → owning Service.
	tlsHostnameToService map[string]types.NamespacedName
	// Layer 2 — workload: Service → how to run traffic for that Service.
	serviceBindings map[types.NamespacedName]*serviceBinding

	cp CertProvider

	ownerMu     sync.Mutex // see mutex ordering comment at top of file
	ownerCancel map[types.NamespacedName]context.CancelFunc

	httpsMu      sync.Mutex // see mutex ordering comment at top of file
	httpsByOwner map[types.NamespacedName]*ownerHTTPSStack

	// Graceful drain for TLS-termination bidirectional copies. Close() signals
	// closeCh (to interrupt active connections) and waits on drainWg.
	closeCh chan struct{}
	drainWg sync.WaitGroup
}

type ownerHTTPSStack struct {
	ln  *chanListener
	srv *http.Server
}

func newIngressRouter(logger *slog.Logger, baseCtx context.Context, cp CertProvider) *ingressRouter {
	return &ingressRouter{
		logger:               logger,
		baseCtx:              baseCtx,
		tlsHostnameToService: make(map[string]types.NamespacedName),
		serviceBindings:      make(map[types.NamespacedName]*serviceBinding),
		cp:                   cp,
		ownerCancel:          make(map[types.NamespacedName]context.CancelFunc),
		httpsByOwner:         make(map[types.NamespacedName]*ownerHTTPSStack),
		closeCh:              make(chan struct{}),
	}
}

// canonicalTLSHostname normalizes a hostname for SNI index and map keys (DNS is case-insensitive).
func canonicalTLSHostname(host string) string {
	return strings.ToLower(strings.TrimSpace(host))
}

// -----------------------------------------------------------------------------
// Layer 1 — TLS hostname index (which Service owns each SNI). No handlers here.
// -----------------------------------------------------------------------------

// matchSNI (tcpproxy.Matcher) consults only the SNI index—no binding logic.
func (r *ingressRouter) matchSNI(_ context.Context, hostname string) bool {
	return r.tlsHostnameKnown(canonicalTLSHostname(hostname))
}

func (r *ingressRouter) tlsHostnameKnown(canon string) bool {
	if canon == "" {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tlsHostnameToService[canon]
	return ok
}

// lookupBindingByTLSHostname returns the Service binding for this TLS hostname,
// or nil. Caller must not use the result without checking mode and fields.
func (r *ingressRouter) lookupBindingByTLSHostname(canon string) *serviceBinding {
	if canon == "" {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.tlsHostnameToService[canon]
	if !ok {
		return nil
	}
	return r.serviceBindings[svc]
}

// -----------------------------------------------------------------------------
// Reconcile: replace layer-1 + layer-2 for one Kubernetes Service.
// -----------------------------------------------------------------------------

func (r *ingressRouter) cancelOwner(owner types.NamespacedName) {
	r.ownerMu.Lock()
	defer r.ownerMu.Unlock()
	if c, ok := r.ownerCancel[owner]; ok {
		c()
		delete(r.ownerCancel, owner)
	}
}

func (r *ingressRouter) registerOwnerCancel(owner types.NamespacedName, cancel context.CancelFunc) {
	r.ownerMu.Lock()
	defer r.ownerMu.Unlock()
	r.ownerCancel[owner] = cancel
}

func (r *ingressRouter) SetRoute(owner types.NamespacedName, hostnames []string, targetAddr, mode string, proxyProto bool, oidcCfg *oidcConfig) error {
	r.cancelOwner(owner)

	// --- Phase 1: build everything outside the route mutex ---

	var claimed []string
	for _, h := range hostnames {
		canon := canonicalTLSHostname(h)
		if canon != "" {
			claimed = append(claimed, canon)
		}
	}

	ppVersion := 0
	if proxyProto {
		ppVersion = 1
	}

	var oidcCtx context.Context
	var oidcCancel context.CancelFunc
	if oidcCfg != nil {
		oidcCtx, oidcCancel = context.WithCancel(r.baseCtx)
	}
	// Ensure we cancel on any error path.
	oidcCancelled := false
	defer func() {
		if oidcCancel != nil && !oidcCancelled {
			oidcCancel()
		}
	}()

	binding := &serviceBinding{
		serviceRef: owner,
		mode:       mode,
		targetAddr: targetAddr,
		hostnames:  append([]string(nil), claimed...),
	}

	switch mode {
	case modeTLSPassthrough:
		binding.passthrough = &tcpproxy.DialProxy{
			Addr:                 targetAddr,
			ProxyProtocolVersion: ppVersion,
		}
	case modeHTTPS:
		binding.httpsHosts = make(map[string]httpsHostBinding)
		for _, canon := range claimed {
			upstreamURL, err := url.Parse("http://" + targetAddr)
			if err != nil {
				return fmt.Errorf("parsing upstream url for host %s: %w", canon, err)
			}
			rev := httputil.NewSingleHostReverseProxy(upstreamURL)
			hdl := http.Handler(rev)
			if oidcCfg != nil {
				builder := r.authMiddlewareBuilder
				if builder == nil {
					builder = buildMiddlewareForHost
				}
				mw, err := builder(oidcCtx, canon, *oidcCfg)
				if err != nil {
					return fmt.Errorf("building oidc middleware for host %s: %w", canon, err)
				}
				hdl = mw(hdl)
			}
			binding.httpsHosts[canon] = httpsHostBinding{
				handler: hdl,
				proxy:   rev,
				oidc:    oidcCfg,
			}
		}
	case modeTLSTermination:
		// no httpsHosts
	default:
		return fmt.Errorf("unsupported mode %q", mode)
	}

	// --- Phase 2: install under the route mutex ---

	if err := r.installBinding(owner, claimed, binding); err != nil {
		return err
	}

	if oidcCancel != nil {
		r.registerOwnerCancel(owner, oidcCancel)
		oidcCancelled = true
	}

	if mode == modeHTTPS {
		if err := r.rebuildOwnerHTTPServer(owner); err != nil {
			return err
		}
	} else {
		r.stopOwnerHTTPServer(owner)
	}

	return nil
}

// installBinding atomically validates hostname conflicts, clears old state, and
// installs the new binding. Returns an error if a hostname is already claimed by
// a different Service.
func (r *ingressRouter) installBinding(owner types.NamespacedName, claimed []string, binding *serviceBinding) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, canon := range claimed {
		if existing, ok := r.tlsHostnameToService[canon]; ok && existing != owner {
			r.logger.Warn("route conflict", "hostname", canon, "existing_owner", existing.String(), "new_owner", owner.String())
			return fmt.Errorf("host %s already in use", canon)
		}
	}

	// Drop SNI index entries previously owned by this service.
	for h, svc := range r.tlsHostnameToService {
		if svc == owner {
			delete(r.tlsHostnameToService, h)
		}
	}
	delete(r.serviceBindings, owner)

	for _, canon := range claimed {
		r.tlsHostnameToService[canon] = owner
		r.logger.Info("set route", "hostname", canon, "owner", owner.String(), "mode", binding.mode, "target", binding.targetAddr)
	}
	r.serviceBindings[owner] = binding
	return nil
}

func (r *ingressRouter) RemoveRoute(owner types.NamespacedName) {
	r.cancelOwner(owner)

	r.mu.Lock()
	for h, svc := range r.tlsHostnameToService {
		if svc == owner {
			delete(r.tlsHostnameToService, h)
			r.logger.Info("removed route", "owner", owner.String(), "hostname", h)
		}
	}
	delete(r.serviceBindings, owner)
	r.mu.Unlock()

	r.stopOwnerHTTPServer(owner)
}

// -----------------------------------------------------------------------------
// Introspection: cert allowlist, redirects, unit tests (via SNI index + bindings).
// -----------------------------------------------------------------------------

// RouteFor returns a flattened view for tests (back-compat).
func (r *ingressRouter) RouteFor(hostName string) (route, bool) {
	key := canonicalTLSHostname(hostName)
	if key == "" {
		return route{}, false
	}
	b := r.lookupBindingByTLSHostname(key)
	if b == nil {
		return route{}, false
	}
	rt := route{
		Owner:      b.serviceRef,
		TargetAddr: b.targetAddr,
		Mode:       b.mode,
		Proxy:      b.passthrough,
	}
	if b.mode == modeHTTPS {
		if hh, ok := b.httpsHosts[key]; ok {
			rt.HTTPProxy = hh.proxy
			rt.HTTPHandler = hh.handler
			rt.OIDC = hh.oidc
		}
	}
	return rt, true
}

func (r *ingressRouter) HasHost(hostName string) bool {
	return r.tlsHostnameKnown(canonicalTLSHostname(hostName))
}

func (r *ingressRouter) DialProxyFor(hostName string) (*tcpproxy.DialProxy, error) {
	rt, ok := r.RouteFor(hostName)
	if !ok {
		return nil, nil
	}
	return rt.Proxy, nil
}

// -----------------------------------------------------------------------------
// Terminated HTTPS: one http.Server per Service; Host must equal TLS SNI.
// -----------------------------------------------------------------------------

func (r *ingressRouter) serveHTTPForOwner(owner types.NamespacedName) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.TLS == nil {
			http.Error(w, "internal: expected TLS request", http.StatusInternalServerError)
			return
		}
		sni := strings.TrimSpace(req.TLS.ServerName)
		if sni == "" {
			http.Error(w, "missing TLS server name", http.StatusBadRequest)
			return
		}
		hostHdr := hostOnly(req.Host)
		if hostHdr == "" {
			http.Error(w, "missing host", http.StatusBadRequest)
			return
		}
		if !strings.EqualFold(sni, hostHdr) {
			r.logger.Warn("https request host does not match TLS SNI",
				"sni", sni, "host", hostHdr, "owner", owner.String())
			http.Error(w, http.StatusText(http.StatusMisdirectedRequest), http.StatusMisdirectedRequest)
			return
		}

		key := canonicalTLSHostname(hostHdr)
		r.mu.RLock()
		svcOwner, inIndex := r.tlsHostnameToService[key]
		b := r.serviceBindings[owner]
		var hdl http.Handler
		if b != nil && b.mode == modeHTTPS && inIndex && svcOwner == owner {
			if hh, ok := b.httpsHosts[key]; ok {
				hdl = hh.handler
			}
		}
		r.mu.RUnlock()

		if hdl == nil {
			http.NotFound(w, req)
			return
		}
		hdl.ServeHTTP(w, req)
	})
}

func hostOnly(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.TrimSpace(host)
}

// -----------------------------------------------------------------------------
// tcpproxy.Target: SNI already matched; dispatch from binding only.
// -----------------------------------------------------------------------------

func (r *ingressRouter) HandleConn(c net.Conn) {
	uc, ok := c.(*tcpproxy.Conn)
	if !ok {
		r.logger.Debug("non *tcpproxy.Conn received")
		_ = c.Close()
		return
	}

	sni := canonicalTLSHostname(uc.HostName)
	r.logger.Debug("incoming connection", "host", uc.HostName)

	b := r.lookupBindingByTLSHostname(sni)
	if b == nil {
		r.logger.Debug("no sni route", "host", uc.HostName)
		_ = c.Close()
		return
	}

	switch b.mode {
	case modeTLSTermination, modeHTTPS:
		if err := r.handleTerminateRoute(uc, b); err != nil {
			r.logger.Error("handling terminated tls route", "host", uc.HostName, "error", err)
			_ = c.Close()
		}
	case modeTLSPassthrough:
		if b.passthrough == nil {
			_ = c.Close()
			return
		}
		r.logger.Debug("dialing passthrough target", "host", uc.HostName, "target", b.passthrough.Addr)
		b.passthrough.HandleConn(c)
	default:
		_ = c.Close()
	}
}

func (r *ingressRouter) ownerHasHTTPSRoute(owner types.NamespacedName) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b := r.serviceBindings[owner]
	return b != nil && b.mode == modeHTTPS && len(b.httpsHosts) > 0
}

func (r *ingressRouter) stopOwnerHTTPServer(owner types.NamespacedName) {
	r.httpsMu.Lock()
	defer r.httpsMu.Unlock()
	r.stopOwnerHTTPServerLocked(owner)
}

func (r *ingressRouter) stopOwnerHTTPServerLocked(owner types.NamespacedName) {
	s := r.httpsByOwner[owner]
	if s == nil {
		return
	}
	delete(r.httpsByOwner, owner)
	if s.srv != nil {
		_ = s.srv.Close()
	}
	if s.ln != nil {
		_ = s.ln.Close()
	}
}

func (r *ingressRouter) rebuildOwnerHTTPServer(owner types.NamespacedName) error {
	if !r.ownerHasHTTPSRoute(owner) {
		r.stopOwnerHTTPServer(owner)
		return nil
	}

	r.httpsMu.Lock()
	defer r.httpsMu.Unlock()
	_, err := r.buildOwnerHTTPServerLocked(owner)
	return err
}

// buildOwnerHTTPServerLocked tears down any existing server for owner and
// creates a new one. Caller must hold httpsMu.
func (r *ingressRouter) buildOwnerHTTPServerLocked(owner types.NamespacedName) (*chanListener, error) {
	r.stopOwnerHTTPServerLocked(owner)

	ln := newChanListener()
	srv := &http.Server{
		Handler:           r.serveHTTPForOwner(owner),
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
	}
	if err := http2.ConfigureServer(srv, &http2.Server{}); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("configuring http2: %w", err)
	}
	r.httpsByOwner[owner] = &ownerHTTPSStack{ln: ln, srv: srv}

	go func() {
		err := srv.Serve(ln)
		if err != nil && err != http.ErrServerClosed {
			r.logger.Error("https server exited", "owner", owner.String(), "error", err)
		}
	}()
	return ln, nil
}

// ensureOwnerHTTPServer returns the chanListener for owner's HTTP server,
// creating one if needed. The entire check-and-create is atomic under httpsMu.
func (r *ingressRouter) ensureOwnerHTTPServer(owner types.NamespacedName) (*chanListener, error) {
	r.httpsMu.Lock()
	defer r.httpsMu.Unlock()

	if s, ok := r.httpsByOwner[owner]; ok && s != nil && s.ln != nil {
		return s.ln, nil
	}
	return r.buildOwnerHTTPServerLocked(owner)
}

func (r *ingressRouter) handleTerminateRoute(c *tcpproxy.Conn, b *serviceBinding) error {
	if r.cp == nil {
		return io.EOF
	}

	tlsConn := tls.Server(c, r.cp.TLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}

	if b.mode == modeHTTPS {
		ln, err := r.ensureOwnerHTTPServer(b.serviceRef)
		if err != nil {
			_ = tlsConn.Close()
			return err
		}
		if err := ln.pushConn(tlsConn); err != nil {
			_ = tlsConn.Close()
			return err
		}
		return nil
	}

	// TLS-termination mode: bidirectional copy with graceful drain support.
	r.drainWg.Add(1)
	defer r.drainWg.Done()
	defer func() { _ = tlsConn.Close() }()

	upstreamConn, err := net.Dial("tcp", b.targetAddr)
	if err != nil {
		return err
	}
	defer func() { _ = upstreamConn.Close() }()

	// When Close() is called, set immediate deadlines to unblock io.Copy.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-r.closeCh:
			_ = tlsConn.SetDeadline(time.Now())
			_ = upstreamConn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, tlsConn)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConn, upstreamConn)
	}()
	wg.Wait()
	return nil
}

const drainTimeout = 10 * time.Second

func (r *ingressRouter) Close() error {
	// Signal active TLS-termination connections to drain.
	select {
	case <-r.closeCh:
	default:
		close(r.closeCh)
	}

	r.httpsMu.Lock()
	owners := make([]types.NamespacedName, 0, len(r.httpsByOwner))
	for o := range r.httpsByOwner {
		owners = append(owners, o)
	}
	for _, o := range owners {
		r.stopOwnerHTTPServerLocked(o)
	}
	r.httpsByOwner = make(map[types.NamespacedName]*ownerHTTPSStack)
	r.httpsMu.Unlock()

	// Wait for TLS-termination connections to finish, with a timeout.
	ch := make(chan struct{})
	go func() {
		r.drainWg.Wait()
		close(ch)
	}()
	select {
	case <-ch:
	case <-time.After(drainTimeout):
		r.logger.Warn("tls termination drain timed out", "timeout", drainTimeout)
	}
	return nil
}

type chanListener struct {
	connCh    chan net.Conn
	closeOnce sync.Once
	closed    chan struct{}
	addr      net.Addr
}

func newChanListener() *chanListener {
	return &chanListener{
		connCh: make(chan net.Conn),
		closed: make(chan struct{}),
		addr:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0},
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

func (l *chanListener) pushConn(c net.Conn) error {
	select {
	case l.connCh <- c:
		return nil
	case <-l.closed:
		return net.ErrClosed
	}
}
