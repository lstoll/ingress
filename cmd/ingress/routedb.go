package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/go-logr/logr"
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
	logger logr.Logger
	ctx    context.Context

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
			return fmt.Errorf("host %s already in use", h)
		}
	}

	// Clean up old routes
	for h, rt := range r.routes {
		if rt.Owner == owner {
			delete(r.routes, h)
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
		if mode == modeTLSPassthrough {
			rt.Proxy = &tcpproxy.DialProxy{
				Addr:                 targetAddr,
				ProxyProtocolVersion: ppVersion,
			}
		} else if mode == modeHTTPS {
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
				mw, err := buildMiddlewareForHost(r.ctx, h, *oidcCfg)
				if err != nil {
					return fmt.Errorf("building oidc middleware for host %s: %w", h, err)
				}
				rt.HTTPHandler = mw(rt.HTTPHandler)
			}
			rt.OIDC = oidcCfg
		}
		r.routes[h] = route{
			Owner:      rt.Owner,
			TargetAddr: rt.TargetAddr,
			Mode:       rt.Mode,
			Proxy:      rt.Proxy,
			HTTPProxy:  rt.HTTPProxy,
			HTTPHandler: rt.HTTPHandler,
			OIDC:       rt.OIDC,
		}
	}

	return nil
}

func (r *routedb) RemoveRoute(owner types.NamespacedName) {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()

	for h, rt := range r.routes {
		if rt.Owner == owner {
			delete(r.routes, h)
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
