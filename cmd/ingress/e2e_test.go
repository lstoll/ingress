package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"inet.af/tcpproxy"
)

// E2E-style tests: fake Kubernetes client → ServiceReconciler → routedb → tcpproxy +
// director (+ optional HTTP→HTTPS redirect listener). Backends are real listeners
// (httptest or tls.Listen) on loopback; Service ClusterIP is 127.0.0.1 with the
// backend’s port. SNI / Host use *.localtest.me hostnames (they need not resolve:
// clients dial 127.0.0.1 with TLS ServerName set).

const e2EInstance = "e2e-ingress"

const e2ELoopbackClusterIP = "127.0.0.1"

type e2eStack struct {
	t     *testing.T
	ctx   context.Context
	stop  context.CancelFunc
	rdb   *routedb
	k8s   client.Client
	rec   *ServiceReconciler
	proxy *tcpproxy.Proxy

	proxyAddr       string
	tlsListenerPort string

	redirectSrv *http.Server
	redirectLn  net.Listener
}

func newE2EStack(t *testing.T, opts e2eStackOptions) *e2eStack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rdb := &routedb{
		logger: testLogger(),
		ctx:    ctx,
		routes: make(map[string]route),
	}
	if opts.authMiddlewareBuilder != nil {
		rdb.authMiddlewareBuilder = opts.authMiddlewareBuilder
	}

	cp, err := newCertProvider(certModeSelfSigned, certProviderConfig{})
	if err != nil {
		t.Fatalf("cert provider: %v", err)
	}
	d := &director{logger: testLogger(), ps: rdb, cp: cp}

	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, tlsPort, err := net.SplitHostPort(tl.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	_ = tl.Close()
	proxyAddr := net.JoinHostPort("127.0.0.1", tlsPort)

	p := &tcpproxy.Proxy{}
	p.AddSNIMatchRoute(proxyAddr, MatchAny, d)
	if err := p.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}

	k8s := fake.NewClientBuilder().WithScheme(scheme).Build()
	rec := &ServiceReconciler{
		Client:   k8s,
		logger:   testLogger(),
		rdb:      rdb,
		instance: e2EInstance,
	}

	h := &e2eStack{
		t:               t,
		ctx:             ctx,
		stop:            cancel,
		rdb:             rdb,
		k8s:             k8s,
		rec:             rec,
		proxy:           p,
		proxyAddr:       proxyAddr,
		tlsListenerPort: tlsPort,
	}

	if opts.withHTTPRedirect {
		rl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("redirect listen: %v", err)
		}
		h.redirectLn = rl
		h.redirectSrv = &http.Server{
			Handler:      httpsRedirectHandler(rdb, tlsPort, testLogger()),
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		}
		go func() { _ = h.redirectSrv.Serve(rl) }()
	}

	t.Cleanup(func() {
		cancel()
		if h.redirectSrv != nil {
			_ = h.redirectSrv.Close()
		}
		_ = p.Close()
	})

	return h
}

type e2eStackOptions struct {
	withHTTPRedirect      bool
	authMiddlewareBuilder func(context.Context, string, oidcConfig) (func(http.Handler) http.Handler, error)
}

func (h *e2eStack) redirectHTTPAddr() string {
	h.t.Helper()
	if h.redirectLn == nil {
		h.t.Fatal("redirect listener not started")
	}
	return h.redirectLn.Addr().String()
}

func (h *e2eStack) upsertAndReconcile(svc *corev1.Service) {
	h.t.Helper()
	ctx := context.Background()
	key := types.NamespacedName{Namespace: svc.Namespace, Name: svc.Name}

	var cur corev1.Service
	err := h.k8s.Get(ctx, key, &cur)
	switch {
	case apierrors.IsNotFound(err):
		if err := h.k8s.Create(ctx, svc.DeepCopy()); err != nil {
			h.t.Fatalf("create service: %v", err)
		}
	case err != nil:
		h.t.Fatalf("get service: %v", err)
	default:
		next := cur.DeepCopy()
		next.Labels = svc.Labels
		next.Annotations = svc.Annotations
		next.Spec = svc.Spec
		if err := h.k8s.Update(ctx, next); err != nil {
			h.t.Fatalf("update service: %v", err)
		}
	}
	if _, err := h.rec.Reconcile(ctx, reconcile.Request{NamespacedName: key}); err != nil {
		h.t.Fatalf("reconcile: %v", err)
	}
}

func e2eService(name, ns, mode, hostnames string, port int32) *corev1.Service {
	ann := map[string]string{annMode: mode}
	switch mode {
	case modeHTTPS:
		ann[annHTTPHostnames] = hostnames
	default:
		ann[annSNIHostnames] = hostnames
	}
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Labels:      map[string]string{labelIngressInstance: e2EInstance},
			Annotations: ann,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: e2ELoopbackClusterIP,
			Ports:     []corev1.ServicePort{{Port: port}},
		},
	}
}

func tlsClientFor(host string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
				MinVersion:         tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
}

func tlsClientHTTP2(host string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
				MinVersion:         tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
}

// e2eFrontTLSRow is one cell in the front-TLS routing matrix: reconciler + routedb
// + tcpproxy + director, one route, then an HTTP client through the ingress TLS listener.
type e2eFrontTLSRow struct {
	name       string
	mode       string
	svcName    string
	host       string
	newBackend func(t *testing.T, host string) (port int32)
	client     func(host string) *http.Client
	check      func(t *testing.T, resp *http.Response, body []byte)
}

func TestE2E_FrontTLS_matrix(t *testing.T) {
	plain := func(h http.Handler) func(t *testing.T, host string) int32 {
		return func(t *testing.T, _ string) int32 {
			t.Helper()
			srv := httptest.NewServer(h)
			t.Cleanup(srv.Close)
			return listenerPortInt32(t, srv.Listener.Addr())
		}
	}

	rows := []e2eFrontTLSRow{
		{
			name:    "HTTPS_client_HTTP1",
			mode:    modeHTTPS,
			svcName: "web-h1",
			host:    "e2e-h1.localtest.me",
			newBackend: plain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("h1-" + r.Proto))
			})),
			client: tlsClientFor,
			check: func(t *testing.T, _ *http.Response, body []byte) {
				t.Helper()
				if !strings.HasPrefix(string(body), "h1-HTTP/1.1") {
					t.Fatalf("body %q", body)
				}
			},
		},
		{
			name:    "HTTPS_client_HTTP2",
			mode:    modeHTTPS,
			svcName: "web-h2",
			host:    "e2e-h2.localtest.me",
			newBackend: plain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Reverse proxy dials the backend with HTTP/1.x even when the client used h2 to ingress.
				_, _ = w.Write([]byte("upstream-was-" + r.Proto))
			})),
			client: tlsClientHTTP2,
			check: func(t *testing.T, resp *http.Response, body []byte) {
				t.Helper()
				if resp.ProtoMajor != 2 {
					t.Fatalf("client↔ingress: want HTTP/2, got %s", resp.Proto)
				}
				if want := "upstream-was-HTTP/1.1"; string(body) != want {
					t.Fatalf("body %q want %q", body, want)
				}
			},
		},
		{
			name:    "TLS_termination_backend_plain_HTTP",
			mode:    modeTLSTermination,
			svcName: "term",
			host:    "e2e-term.localtest.me",
			newBackend: plain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = fmt.Fprintf(w, "plain-tls=%v-proto=%s", r.TLS != nil, r.Proto)
			})),
			client: tlsClientFor,
			check: func(t *testing.T, _ *http.Response, body []byte) {
				t.Helper()
				if want := "plain-tls=false-proto=HTTP/1.1"; string(body) != want {
					t.Fatalf("body %q want %q", body, want)
				}
			},
		},
		{
			name:    "TLS_passthrough_backend_speaks_TLS",
			mode:    modeTLSPassthrough,
			svcName: "pass",
			host:    "e2e-pass.localtest.me",
			newBackend: func(t *testing.T, host string) int32 {
				t.Helper()
				be := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte("pass-" + r.Proto))
				}))
				be.TLS = mustTLSCert(t, host)
				be.StartTLS()
				t.Cleanup(be.Close)
				return listenerPortInt32(t, be.Listener.Addr())
			},
			client: tlsClientFor,
			check: func(t *testing.T, _ *http.Response, body []byte) {
				t.Helper()
				if want := "pass-HTTP/1.1"; string(body) != want {
					t.Fatalf("body %q want %q", body, want)
				}
			},
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			h := newE2EStack(t, e2eStackOptions{})
			port := row.newBackend(t, row.host)
			h.upsertAndReconcile(e2eService(row.svcName, "default", row.mode, row.host, port))

			req, err := http.NewRequest(http.MethodGet, "https://"+h.proxyAddr+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = row.host
			resp, err := row.client(row.host).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			row.check(t, resp, body)
		})
	}
}

func listenerPortInt32(t *testing.T, addr net.Addr) int32 {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	return mustAtoi32(t, portStr)
}

func TestE2E_TLS_Passthrough_RawBytes(t *testing.T) {
	h := newE2EStack(t, e2eStackOptions{})

	host := "e2e-raw.localtest.me"
	msg := "ping-raw-tcp"

	beLn, err := tls.Listen("tcp", "127.0.0.1:0", mustTLSCert(t, host))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = beLn.Close() })

	go func() {
		c, err := beLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		buf := make([]byte, len(msg))
		_, _ = io.ReadFull(c, buf)
		_, _ = c.Write([]byte("ack:" + string(buf)))
	}()

	_, bp, err := net.SplitHostPort(beLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAtoi32(t, bp)
	h.upsertAndReconcile(e2eService("raw", "default", modeTLSPassthrough, host, port))

	conn, err := tls.Dial("tcp", h.proxyAddr, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "ack:"+msg {
		t.Fatalf("got %q want ack:%s", out, msg)
	}
}

func TestE2E_HTTPToHTTPSRedirect(t *testing.T) {
	h := newE2EStack(t, e2eStackOptions{withHTTPRedirect: true})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("after-redirect"))
	}))
	t.Cleanup(backend.Close)

	_, bp, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAtoi32(t, bp)

	host := "e2e-redir.localtest.me"
	h.upsertAndReconcile(e2eService("web", "default", modeHTTPS, host, port))

	// Unknown host → 404 on redirect listener
	{
		req, err := http.NewRequest(http.MethodGet, "http://"+h.redirectHTTPAddr()+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = "unknown.localtest.me"
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unknown host: status %d", resp.StatusCode)
		}
	}

	noFollow := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, "http://"+h.redirectHTTPAddr()+"/x?y=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	redirResp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = redirResp.Body.Close()
	if redirResp.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("redirect status %d", redirResp.StatusCode)
	}
	loc := redirResp.Header.Get("Location")
	if !strings.HasPrefix(loc, "https://") || !strings.Contains(loc, "/x?y=1") {
		t.Fatalf("unexpected Location %q", loc)
	}

	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
				MinVersion:         tls.VersionTLS12,
			},
		},
		Timeout: 10 * time.Second,
	}
	httpsReq, err := http.NewRequest(http.MethodGet, "https://"+h.proxyAddr+"/x?y=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	httpsReq.Host = host
	resp, err := tlsClient.Do(httpsReq)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "after-redirect" {
		t.Fatalf("body %q", body)
	}
}

func TestE2E_ServicePortUpdate(t *testing.T) {
	h := newE2EStack(t, e2eStackOptions{})

	host := "e2e-port.localtest.me"

	be1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-v1"))
	}))
	t.Cleanup(be1.Close)
	_, p1s, err := net.SplitHostPort(be1.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p1 := mustAtoi32(t, p1s)

	svc := e2eService("mutable", "default", modeHTTPS, host, p1)
	h.upsertAndReconcile(svc)

	get := func() string {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "https://"+h.proxyAddr+"/", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		resp, err := tlsClientFor(host).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}

	if got := get(); got != "backend-v1" {
		t.Fatalf("first backend: %q", got)
	}

	be1.Close()

	be2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("backend-v2"))
	}))
	t.Cleanup(be2.Close)
	_, p2s, err := net.SplitHostPort(be2.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	p2 := mustAtoi32(t, p2s)

	svc.Spec.Ports[0].Port = p2
	h.upsertAndReconcile(svc)

	if got := get(); got != "backend-v2" {
		t.Fatalf("after port change: got %q want backend-v2 (if this fails, route/db or proxy may be stale)", got)
	}
}

func TestE2E_AuthMiddleware_Stub(t *testing.T) {
	stub := func(_ context.Context, _ string, _ oidcConfig) (func(http.Handler) http.Handler, error) {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				r.Header.Set("X-E2E-Auth", "stub")
				next.ServeHTTP(w, r)
			})
		}, nil
	}
	h := newE2EStack(t, e2eStackOptions{authMiddlewareBuilder: stub})

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("auth-" + r.Header.Get("X-E2E-Auth")))
	}))
	t.Cleanup(backend.Close)

	_, bp, err := net.SplitHostPort(backend.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port := mustAtoi32(t, bp)

	host := "e2e-auth.localtest.me"
	svc := e2eService("auth", "default", modeHTTPS, host, port)
	svc.Annotations[annAuthMode] = authModeOIDC
	svc.Annotations[annOIDCDynamicClient] = "true"
	svc.Annotations[annOIDCIssuer] = "https://issuer.example.com"
	h.upsertAndReconcile(svc)

	req, err := http.NewRequest(http.MethodGet, "https://"+h.proxyAddr+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = host
	resp, err := tlsClientFor(host).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "auth-stub" {
		t.Fatalf("body %q", body)
	}
}

// TestE2E_FullOIDC_Middleware documents the gap: real OIDC uses discovery,
// dynamic registration, and the oauth2ext middleware. Replace the routedb stub
// with nil and stand up a fake issuer or use integration fixtures.
func TestE2E_FullOIDC_Middleware(t *testing.T) {
	t.Skip("full OIDC stack: requires issuer + registration; use authMiddlewareBuilder stub for routing tests until then")
}

func mustAtoi32(t *testing.T, s string) int32 {
	t.Helper()
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil || n <= 0 || n > 65535 {
		t.Fatalf("invalid port %q", s)
	}
	return int32(n)
}
