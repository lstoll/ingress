package main

import (
	"context"
	"net"

	"go.uber.org/zap"
	"inet.af/tcpproxy"
)

var _ tcpproxy.Target = (*director)(nil)

// director is a tcpproxy.Target that works around it not handling dynamic
// routes. it is intended to be a catch-all (i.e tcpproxy.AddSNIMatchRoute with
// MatchAny) handler. It can then dynamically look up the destination to connect
// to, and handle the connection via  DialProxy.
type director struct {
	logger *zap.SugaredLogger

	// map of hostname -> addr to dial.
	targets map[string]string
}

func (d *director) HandleConn(c net.Conn) {
	uc, ok := c.(*tcpproxy.Conn)
	if !ok {
		d.logger.Debugf("non *tcpproxy.Conn received: %#v", c)
		d.writeConnErr(c)
		return
	}

	d.logger.Debugf("remote host: %v", uc.HostName)

	addr, ok := d.targets[uc.HostName]
	if !ok || addr == "" {
		d.logger.Debugf("no route for sni host: %v", uc.HostName)
		d.writeConnErr(c)
		return
	}

	d.logger.Debugf("remote host %s dialing %s", uc.HostName, addr)

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
