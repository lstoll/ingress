package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"inet.af/tcpproxy"
	"k8s.io/apimachinery/pkg/types"
)

type route struct {
	Owner        types.NamespacedName
	TargetAddr   string
	Mode         string
	Proxy        *tcpproxy.DialProxy
	HTTPProxy    *httputil.ReverseProxy
	HTTPHandler  http.Handler
	OIDC         *oidcConfig
}

type routedb struct {
	logger *slog.Logger
	ctx    context.Context

	// authMiddlewareBuilder wires OIDC (or test doubles) in front of HTTPS reverse
	// proxies. When nil, buildMiddlewareForHost is used.
	authMiddlewareBuilder func(ctx context.Context, host string, cfg oidcConfig) (func(http.Handler) http.Handler, error)

	// map of hostnames to route
	routes   map[string]route
	routesMu sync.RWMutex
}

func (r *routedb) SetRoute(owner types.NamespacedName, hostnames []string, targetAddr, mode string, proxyProto bool, oidcCfg *oidcConfig) error {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()

	// Check for conflicts first
	for _, h := range hostnames {
		if rt, ok := r.routes[h]; ok && rt.Owner != owner {
			r.logger.Warn("route conflict", "hostname", h, "existing_owner", rt.Owner.String(), "new_owner", owner.String())
			return fmt.Errorf("host %s already in use", h)
		}
	}

	// Clean up old routes
	for h, rt := range r.routes {
		if rt.Owner == owner {
			delete(r.routes, h)
			r.logger.Debug("removed stale route", "owner", owner.String(), "hostname", h)
		}
	}

	ppVersion := 0
	if proxyProto {
		ppVersion = 1
	}

	for _, h := range hostnames {
		rt := route{
			Owner:      owner,
			TargetAddr: targetAddr,
			Mode:       mode,
		}
		switch mode {
		case modeTLSPassthrough:
			rt.Proxy = &tcpproxy.DialProxy{
				Addr:                 targetAddr,
				ProxyProtocolVersion: ppVersion,
			}
		case modeHTTPS:
			upstreamURL, err := url.Parse("http://" + targetAddr)
			if err != nil {
				return fmt.Errorf("parsing upstream url for host %s: %w", h, err)
			}
			rt.HTTPProxy = httputil.NewSingleHostReverseProxy(upstreamURL)
			rt.HTTPHandler = http.Handler(rt.HTTPProxy)
			if oidcCfg != nil {
				if r.ctx == nil {
					r.ctx = context.Background()
				}
				builder := r.authMiddlewareBuilder
				if builder == nil {
					builder = buildMiddlewareForHost
				}
				mw, err := builder(r.ctx, h, *oidcCfg)
				if err != nil {
					return fmt.Errorf("building oidc middleware for host %s: %w", h, err)
				}
				rt.HTTPHandler = mw(rt.HTTPHandler)
			}
			rt.OIDC = oidcCfg
		}
		r.routes[h] = route{
			Owner:       rt.Owner,
			TargetAddr:  rt.TargetAddr,
			Mode:        rt.Mode,
			Proxy:       rt.Proxy,
			HTTPProxy:   rt.HTTPProxy,
			HTTPHandler: rt.HTTPHandler,
			OIDC:        rt.OIDC,
		}
		r.logger.Info("set route", "hostname", h, "owner", owner.String(), "mode", mode, "target", targetAddr, "proxy_proto", proxyProto)
	}

	return nil
}

func (r *routedb) RemoveRoute(owner types.NamespacedName) {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()

	for h, rt := range r.routes {
		if rt.Owner == owner {
			delete(r.routes, h)
			r.logger.Info("removed route", "owner", owner.String(), "hostname", h)
		}
	}
}

func (r *routedb) RouteFor(hostName string) (route, bool) {
	r.routesMu.RLock()
	defer r.routesMu.RUnlock()

	rt, ok := r.routes[hostName]
	return rt, ok
}

func (r *routedb) HasHost(hostName string) bool {
	r.routesMu.RLock()
	defer r.routesMu.RUnlock()
	_, ok := r.routes[hostName]
	return ok
}

func (r *routedb) DialProxyFor(hostName string) (*tcpproxy.DialProxy, error) {
	rt, ok := r.RouteFor(hostName)
	if !ok {
		return nil, nil
	}
	return rt.Proxy, nil
}
