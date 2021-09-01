package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
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
	"github.com/oklog/run"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/crypto/acme/autocert"
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
	}{}

	flag.StringVar(&cfg.Listen, "listen", "localhost:8080", "host:port to listen on")
	flag.StringVar(&cfg.PublicURL, "public-url", "http://localhost", "URL service is served on, for certificate management")
	flag.StringVar(&cfg.UpstreamURL, "upstream-url", "http://localhost:8080", "URL of upstream service to proxy traffic to")
	flag.BoolVar(&cfg.DisableLetsencrypt, "disable-letsencrypt", false, "Don't manage certs with letsencrypt. Useful for local dev")
	flag.StringVar(&cfg.KubeconfigPath, "kubeconfig", filepath.Join(homedir.HomeDir(), ".kube", "config"), "Path to kubeconfig, if not set in-cluster config assumed")
	flag.StringVar(&cfg.Secret, "secret", "", "namespace/name formatted secret to use for TLS cert storage")
	flag.StringVar(&cfg.HTTPPolicyFile, "http-policy", "", "(optional) path to rego file, for policy to apply to connections")

	flag.Parse()

	usURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("parsing %s: %v", cfg.UpstreamURL, err)
	}
	pURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("parsing %s: %v", cfg.UpstreamURL, err)
	}

	mux := http.NewServeMux()

	proxy := httputil.NewSingleHostReverseProxy(usURL)
	mux.Handle("/", proxy)

	// Start middleware section

	var handler http.Handler

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

	hs := &http.Server{
		Handler: handler,
	}

	if !cfg.DisableLetsencrypt {
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
		hs.TLSConfig = acm.TLSConfig()
	}

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listening on %s: %v", cfg.Listen, err)
	}
	plis := &proxyproto.Listener{Listener: lis}

	var g run.Group
	g.Add(run.SignalHandler(ctx, os.Interrupt))

	g.Add(func() error {
		log.Printf("Serving on %s", cfg.Listen)
		return hs.Serve(plis)
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
