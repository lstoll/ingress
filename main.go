package main

import (
	"flag"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func main() {
	cfg := struct {
		UpstreamURL string
	}{}

	flag.StringVar(&cfg.UpstreamURL, "upstream-url", "http://localhost:8080", "URL of upstream service to proxy traffic to")

	flag.Parse()

	rpURL, err := url.Parse(cfg.UpstreamURL)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	proxy := httputil.NewSingleHostReverseProxy(rpURL)
	mux.Handle("/", proxy)

	log.Fatal(http.ListenAndServe(":8080", mux))
}
