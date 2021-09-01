package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/armon/go-proxyproto"
	"github.com/oklog/run"
)

func main() {
	ctx := context.Background()

	cfg := struct {
		Listen      string
		UpstreamURL string
	}{}

	flag.StringVar(&cfg.Listen, "listen", "localhost:8080", "host:port to listen on")
	flag.StringVar(&cfg.UpstreamURL, "upstream-url", "http://localhost:8080", "URL of upstream service to proxy traffic to")

	flag.Parse()

	rpURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatalf("parsing %s: %v", cfg.UpstreamURL, err)
	}

	mux := http.NewServeMux()

	proxy := httputil.NewSingleHostReverseProxy(rpURL)
	mux.Handle("/", proxy)

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Fatalf("listening on %s: %v", cfg.Listen, err)
	}
	plis := &proxyproto.Listener{Listener: lis}

	var g run.Group
	g.Add(run.SignalHandler(ctx, os.Interrupt))

	g.Add(func() error {
		log.Printf("Serving on %s", cfg.Listen)
		return http.Serve(plis, mux)
	}, func(error) {
		lis.Close()
	})

	log.Fatal(g.Run())
	if err := g.Run(); err != nil {
		log.Fatalf("running: %v", err)
	}
	log.Print("done")
}
