package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"

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
	logger *slog.Logger

	ps proxySource
	cp CertProvider

	// // map of hostname -> addr to dial.
	// targets map[string]string
}

func (d *director) HandleConn(c net.Conn) {
	uc, ok := c.(*tcpproxy.Conn)
	if !ok {
		d.logger.Debug("non *tcpproxy.Conn received")
		d.writeConnErr(c)
		return
	}

	d.logger.Debug("incoming connection", "host", uc.HostName)

	rt, ok := d.ps.RouteFor(uc.HostName)
	if !ok {
		d.logger.Debug("no sni route", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}
	if rt.Mode == modeTLSTermination || rt.Mode == modeHTTPS {
		if err := d.handleTerminateRoute(uc, rt); err != nil {
			d.logger.Error("handling terminated tls route", "host", uc.HostName, "error", err)
			d.writeConnErr(c)
		}
		return
	}

	dp, err := d.ps.DialProxyFor(uc.HostName)
	if err != nil {
		d.logger.Error("getting dial proxy", "host", uc.HostName, "error", err)
		d.writeConnErr(c)
		return
	}
	if dp == nil {
		d.logger.Debug("no dial proxy for sni route", "host", uc.HostName)
		d.writeConnErr(c)
		return
	}

	d.logger.Debug("dialing passthrough target", "host", uc.HostName, "target", dp.Addr)

	dp.HandleConn(c)
}

func (d *director) handleTerminateRoute(c *tcpproxy.Conn, rt route) error {
	if d.cp == nil {
		return io.EOF
	}

	tlsConn := tls.Server(c, d.cp.TLSConfig())
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	defer func() {
		_ = tlsConn.Close()
	}()

	if rt.Mode == modeHTTPS {
		if rt.HTTPHandler == nil {
			return fmt.Errorf("missing http handler for route")
		}

		oneConnLn := newSingleConnListener(tlsConn)
		hs := &http.Server{Handler: rt.HTTPHandler}
		errCh := make(chan error, 1)
		go func() {
			errCh <- hs.Serve(oneConnLn)
		}()

		<-oneConnLn.done
		_ = hs.Close()
		err := <-errCh
		if err != nil && err != io.EOF && err != net.ErrClosed && err.Error() != "http: Server closed" {
			return err
		}
		return nil
	}

	upstreamConn, err := net.Dial("tcp", rt.TargetAddr)
	if err != nil {
		return err
	}
	defer func() {
		_ = upstreamConn.Close()
	}()

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

type singleConnListener struct {
	conn net.Conn
	used bool
	done chan struct{}
	once sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{
		conn: conn,
		done: make(chan struct{}),
	}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	if s.used || s.conn == nil {
		<-s.done
		return nil, net.ErrClosed
	}
	s.used = true
	return &notifyingConn{
		Conn: s.conn,
		onClose: func() {
			s.once.Do(func() {
				close(s.done)
			})
		},
	}, nil
}

func (s *singleConnListener) Close() error {
	s.once.Do(func() {
		close(s.done)
	})
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *singleConnListener) Addr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

type notifyingConn struct {
	net.Conn
	once    sync.Once
	onClose func()
}

func (n *notifyingConn) Close() error {
	n.once.Do(n.onClose)
	return n.Conn.Close()
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
