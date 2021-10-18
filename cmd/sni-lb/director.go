package main

import (
	"context"
	"net"

	"github.com/go-logr/logr"
	"inet.af/tcpproxy"
)

var _ tcpproxy.Target = (*director)(nil)

// director is a tcpproxy.Target that works around it not handling dynamic
// routes. it is intended to be a catch-all (i.e tcpproxy.AddSNIMatchRoute with
// MatchAny) handler. It can then dynamically look up the destination to connect
// to, and handle the connection via  DialProxy.
type director struct {
	logger logr.Logger

	// map of hostname -> addr to dial.
	targets map[string]string
}

func (d *director) HandleConn(c net.Conn) {
	uc, ok := c.(*tcpproxy.Conn)
	if !ok {
		d.logger.V(debugV).Info("non *tcpproxy.Conn received", "conn", c)
		d.writeConnErr(c)
		return
	}

	d.logger.V(debugV).Info("remote host", "host", uc.HostName)

	addr, ok := d.targets[uc.HostName]
	if !ok || addr == "" {
		d.logger.V(debugV).Info("no sni route", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}

	d.logger.V(debugV).Info("dialing", "hostName", uc.HostName, "dialAddr", addr)

	to := &tcpproxy.DialProxy{
		Addr: addr,
	}

	to.HandleConn(c)
}

// writeConnErr is used for handling conns we can't handle
//
// TODO - how do we do this? close is ugly. HTTP might be weird (unless we sniff
// it)
func (d *director) writeConnErr(c net.Conn) {
	_ = c.Close()
}

// MatchAny is a tcpproxy.Matcher that matches every route coming in, can be
// useful to force a wildcard SNI route
func MatchAny(_ context.Context, _ string) bool {
	return true
}
