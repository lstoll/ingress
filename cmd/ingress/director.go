package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"sync"

	"github.com/go-logr/logr"
	"inet.af/tcpproxy"
)

var _ tcpproxy.Target = (*director)(nil)

type proxySource interface {
	RouteFor(hostName string) (route, bool)
	DialProxyFor(hostName string) (*tcpproxy.DialProxy, error)
}

// director is a tcpproxy.Target that works around it not handling dynamic
// routes. it is intended to be a catch-all (i.e tcpproxy.AddSNIMatchRoute with
// MatchAny) handler. It can then dynamically look up the destination to connect
// to, and handle the connection via  DialProxy.
type director struct {
	logger logr.Logger

	ps proxySource
	cp CertProvider

	// // map of hostname -> addr to dial.
	// targets map[string]string
}

func (d *director) HandleConn(c net.Conn) {
	uc, ok := c.(*tcpproxy.Conn)
	if !ok {
		d.logger.V(debugV).Info("non *tcpproxy.Conn received", "conn", c)
		d.writeConnErr(c)
		return
	}

	d.logger.V(debugV).Info("remote host", "host", uc.HostName)

	rt, ok := d.ps.RouteFor(uc.HostName)
	if !ok {
		d.logger.V(debugV).Info("no sni route", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}
	if rt.TerminateTLS {
		if err := d.handleTerminateRoute(uc, rt); err != nil {
			d.logger.Error(err, "handling terminated tls route", "host", uc.HostName)
			d.writeConnErr(c)
		}
		return
	}

	dp, err := d.ps.DialProxyFor(uc.HostName)
	if err != nil {
		d.logger.Error(err, "getting dial proxy", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}
	if dp == nil {
		d.logger.V(debugV).Info("no dial proxy for sni route", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}

	d.logger.V(debugV).Info("dialing", "hostName", uc.HostName, "dialAddr", dp.Addr)

	dp.HandleConn(c)
}

func (d *director) handleTerminateRoute(c *tcpproxy.Conn, rt route) error {
	if d.cp == nil {
		return io.EOF
	}

	tlsConn := tls.Server(c, &tls.Config{
		GetCertificate: d.cp.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	defer tlsConn.Close()

	upstreamConn, err := net.Dial("tcp", rt.TargetAddr)
	if err != nil {
		return err
	}
	defer upstreamConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamConn, tlsConn)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tlsConn, upstreamConn)
	}()
	wg.Wait()
	return nil
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
