package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"inet.af/tcpproxy"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

type route struct {
	Owner types.NamespacedName
	Proxy *tcpproxy.DialProxy
}

type routedb struct {
	logger logr.Logger

	// map of hostnames to route
	routes   map[string]route
	routesMu sync.RWMutex
}

func (r *routedb) AddService(svc corev1.Service) error {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()

	hostnames, ok := svc.Annotations[hostnamesAnnotation]
	if !ok {
		return fmt.Errorf("%s annotation required", hostnamesAnnotation)
	}
	hosts := strings.Split(hostnames, ",")

	cip := svc.Spec.ClusterIP
	if cip == "" {
		return fmt.Errorf("service must have clusterIP")
	}

	if len(svc.Spec.Ports) != 1 {
		return fmt.Errorf("only 1 port on service supported")
	}

	var proxyProtoVersion int
	if _, ok := svc.Annotations[disableProxyProtoAnnotation]; !ok {
		proxyProtoVersion = 1
	}

	for _, h := range hosts {
		if _, ok := r.routes[h]; ok {
			return fmt.Errorf("host %s already in use", h)
		}

		r.routes[h] = route{
			Owner: types.NamespacedName{
				Namespace: svc.Namespace,
				Name:      svc.Name,
			},
			Proxy: &tcpproxy.DialProxy{
				Addr:                 net.JoinHostPort(cip, strconv.Itoa(int(svc.Spec.Ports[0].Port))),
				ProxyProtocolVersion: proxyProtoVersion,
			},
		}
	}

	return nil
}

func (r *routedb) DeleteService(nsn types.NamespacedName) error {
	r.routesMu.Lock()
	defer r.routesMu.Unlock()

	for h, rt := range r.routes {
		if rt.Owner == nsn {
			delete(r.routes, h)
		}
	}

	return nil
}

func (r *routedb) DialProxyFor(hostName string) (*tcpproxy.DialProxy, error) {
	r.routesMu.RLock()
	defer r.routesMu.RUnlock()

	// TODO - how do we indicate none vs error
	rt, ok := r.routes[hostName]
	if !ok {
		return nil, nil
	}
	return rt.Proxy, nil
}
