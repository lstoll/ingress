package main

import (
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	"inet.af/tcpproxy"
	"k8s.io/apimachinery/pkg/types"
)

type route struct {
	Owner        types.NamespacedName
	TargetAddr   string
	TerminateTLS bool
	Proxy        *tcpproxy.DialProxy
}

type routedb struct {
	logger logr.Logger

	// map of hostnames to route
	routes   map[string]route
	routesMu sync.RWMutex
}

func (r *routedb) SetRoute(owner types.NamespacedName, hostnames []string, targetAddr string, proxyProto bool, terminateTLS bool) error {
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
			Owner:        owner,
			TargetAddr:   targetAddr,
			TerminateTLS: terminateTLS,
		}
		if !terminateTLS {
			rt.Proxy = &tcpproxy.DialProxy{
				Addr:                 targetAddr,
				ProxyProtocolVersion: ppVersion,
			}
		}
		r.routes[h] = route{
			Owner:        rt.Owner,
			TargetAddr:   rt.TargetAddr,
			TerminateTLS: rt.TerminateTLS,
			Proxy:        rt.Proxy,
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

func (r *routedb) DialProxyFor(hostName string) (*tcpproxy.DialProxy, error) {
	rt, ok := r.RouteFor(hostName)
	if !ok {
		return nil, nil
	}
	return rt.Proxy, nil
}
