package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/armon/go-proxyproto"
	"github.com/gorilla/sessions"
	"github.com/oklog/run"
	"github.com/open-policy-agent/opa/rego"
	oidcm "github.com/pardot/oidc/middleware"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/hkdf"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	ctx := context.Background()

	cfg := struct {
		Listen             string
		PublicURL          string
		UpstreamURL        string
		DisableLetsencrypt bool
		KubeconfigPath     string
		Secret             string
		HTTPPolicyFile     string
		OIDCIssuer         string
		OIDCClientID       string
		OIDCClientSecret   string
		EncryptionKey      string
		ClientCAFile       string
	}{}

	flag.StringVar(&cfg.Listen, "listen", "localhost:8080", "host:port to listen on")
	flag.StringVar(&cfg.PublicURL, "public-url", "https://localhost:8080", "URL service is served on, for certificate management")
	flag.StringVar(&cfg.UpstreamURL, "upstream-url", "http://httpd", "URL of upstream service to proxy traffic to")
	flag.BoolVar(&cfg.DisableLetsencrypt, "disable-letsencrypt", false, "Don't manage certs with letsencrypt. Useful for local dev")
	flag.StringVar(&cfg.KubeconfigPath, "kubeconfig", filepath.Join(homedir.HomeDir(), ".kube", "config"), "Path to kubeconfig, if not set in-cluster config assumed")
	flag.StringVar(&cfg.Secret, "secret", "", "namespace/name formatted secret to use for TLS cert storage")
	flag.StringVar(&cfg.HTTPPolicyFile, "http-policy", "", "(optional) path to rego file, for policy to apply to connections")
	flag.StringVar(&cfg.OIDCIssuer, "oidc-issuer", "", "OIDC issuer to auth against")
	flag.StringVar(&cfg.OIDCClientID, "oidc-client-id", "", "OIDC client ID")
	flag.StringVar(&cfg.OIDCClientSecret, "oidc-client-secret", "", "OIDC client secret")
	flag.StringVar(&cfg.EncryptionKey, "encryption-key", "", "encryption key for securing session")
	flag.StringVar(&cfg.ClientCAFile, "client-ca-bundle", "", "(optional) path to bundle of PEM formatted CA certs, to request from clients. Non-enforcing, use policy")
	flag.Parse()

	usURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("parsing %s: %v", cfg.UpstreamURL, err)
	}
	pURL, err := url.Parse(cfg.PublicURL)
	if err != nil {
		log.Fatalf("parsing %s: %v", cfg.UpstreamURL, err)
	}

	if cfg.EncryptionKey == "" {
		log.Fatal("-encryption-key must be specified")
	}

	krdr := hkdf.New(sha256.New, []byte(cfg.EncryptionKey), nil, nil)
	scHashKey := make([]byte, 64)
	scEncryptKey := make([]byte, 32)
	if _, err := io.ReadFull(krdr, scHashKey); err != nil {
		log.Fatal(err)
	}
	if _, err := io.ReadFull(krdr, scEncryptKey); err != nil {
		log.Fatal(err)
	}

	sess := sessions.NewCookieStore(scHashKey, scEncryptKey)
	sess.Options.Path = "/"
	sess.Options.MaxAge = 12 * 60 * 60
	sess.Options.HttpOnly = true

	mux := http.NewServeMux()

	proxy := httputil.NewSingleHostReverseProxy(usURL)
	mux.Handle("/", proxy)

	// Start middleware section

	var (
		handler      http.Handler
		clientCAPool *x509.CertPool
	)

	if cfg.ClientCAFile != "" {
		ccaPEM, err := os.ReadFile(cfg.ClientCAFile)
		if err != nil {
			log.Fatalf("reading %s: %v", cfg.ClientCAFile, err)
		}

		clientCertPool := x509.NewCertPool()
		clientCertPool.AppendCertsFromPEM(ccaPEM)

		handler = captureClientCert(clientCertPool, handler)
	}

	if cfg.OIDCIssuer != "" {
		oidch := &oidcm.Handler{
			Issuer:       cfg.OIDCIssuer,
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			BaseURL:      pURL.String(),
			RedirectURL:  pURL.ResolveReference(&url.URL{Path: "/.ingress/oidc/callback"}).String(),
			SessionStore: sess,
			SessionName:  "ohp",
			// ACRValues:        []string{"http://schemas.openid.net/pape/policies/2007/06/multi-factor-physical"},
			// AdditionalScopes: []string{"groups"},
		}

		handler = oidch.Wrap(mux)
	}

	if cfg.HTTPPolicyFile != "" {
		httpPolicy, err := os.ReadFile(cfg.HTTPPolicyFile)
		if err != nil {
			log.Fatalf("reading %s: %v", cfg.HTTPPolicyFile, err)
		}

		query, err := rego.New(
			rego.Query("data.http.allow"),
			rego.Module("http.rego", string(httpPolicy)),
		).PrepareForEval(ctx)
		if err != nil {
			log.Fatalf("failed to prepare HTTP policy: %v", err)
		}

		handler = httpPolicyHandler(mux, AuthorizerFunc(func(r *http.Request) error {
			return regoAuthorize(r, query)
		}))
	}

	var tlsConfig *tls.Config

	if cfg.DisableLetsencrypt {
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{
				mustSelfCert(),
			},
		}
	} else {
		if cfg.Secret == "" {
			log.Fatal("-secret must be provided")
		}

		var kubeConfig *rest.Config
		if cfg.KubeconfigPath != "" {
			c, err := clientcmd.BuildConfigFromFlags("", cfg.KubeconfigPath)
			if err != nil {
				log.Fatalf("building kubeconfig from %s: %v", cfg.KubeconfigPath, err)
			}
			kubeConfig = c
		} else {
			c, err := rest.InClusterConfig()
			if err != nil {
				log.Fatalf("building in-cluster kubeconfig: %v", err)
			}
			kubeConfig = c
		}
		clientset, err := kubernetes.NewForConfig(kubeConfig)
		if err != nil {
			log.Fatalf("building kubernetes clientset: %v", err)
		}

		secretNamespace, secretName, err := splitKubernetesPath(cfg.Secret)
		if err != nil {
			log.Fatal(err)
		}

		h, _, err := net.SplitHostPort(pURL.Host)
		if err != nil {
			log.Fatalf("splitting %s: %v", pURL.Host, err)
		}
		acm := &autocert.Manager{
			Prompt: autocert.AcceptTOS,
			Cache: &autocertCache{
				clientset:       clientset,
				secretNamespace: secretNamespace,
				secretName:      secretName,
			},
			HostPolicy: autocert.HostWhitelist(h),
		}
		tlsConfig = acm.TLSConfig()
	}

	if clientCAPool != nil {
		tlsConfig.ClientAuth = tls.RequestClientCert
		tlsConfig.ClientCAs = clientCAPool
	}

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listening on %s: %v", cfg.Listen, err)
	}
	plis := &proxyproto.Listener{Listener: lis}
	tlis := tls.NewListener(plis, tlsConfig)

	var g run.Group
	g.Add(run.SignalHandler(ctx, os.Interrupt))

	hs := &http.Server{
		Handler: handler,
	}
	g.Add(func() error {
		log.Printf("Serving on %s", cfg.Listen)
		return hs.Serve(tlis)
	}, func(error) {
		// if we are here context probably already gone. use a new one with a timeout
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		hs.Shutdown(sctx)
	})

	log.Fatal(g.Run())
	if err := g.Run(); err != nil {
		log.Fatalf("running: %v", err)
	}
	log.Print("done")
}

func splitKubernetesPath(p string) (namespace, name string, err error) {
	sp := strings.Split(p, "/")
	if len(sp) != 2 {
		return "", "", fmt.Errorf("splitting %s on / yielded %d items, not 2", p, len(sp))
	}
	return sp[0], sp[1], nil
}
