package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

func readInt16BE(data []byte, pos int) int {
	return int(binary.BigEndian.Uint16(data[pos : pos+2]))
}

type sniSniffListener struct {
	net.Listener
}

func (s *sniSniffListener) Accept() (net.Conn, error) {
	c, err := s.Listener.Accept()
	if err != nil {
		return nil, err
	}
	_, sc, err := SniffSNIHeader(c)
	log.Printf("sniff err: %v", err)
	return sc, err
}

// NewSNISniffListener creates a net.Listener, that sniffs the SNI header on all
// underlying connections received on the inner listener.
//
// Sadly this doesn't really work, as once the underlying conn goes through TLS
// we lose access to it, and it's context. Try again when fixed:
// * https://github.com/golang/go/issues/29257
// * https://go-review.googlesource.com/c/go/+/325250/
func NewSNISniffListener(inner net.Listener) net.Listener {
	return &sniSniffListener{inner}
}

// SniffSNIHeader finds the SNI header from the underConn if it exists, and
// returns it along with a connection that should be used going forward which
// replays the TLS header.
func SniffSNIHeader(underConn net.Conn) (serverName string, _ ServerNameConn, err error) {
	var (
		data      = make([]byte, 1024)
		sniHeader = ""
	)

	/* Read the SNI shizz
	This is all thanks to https://github.com/axiak/filternet - lib/sniparse.js */
	readLen, err := underConn.Read(data)
	if err != nil {
		return "", nil, fmt.Errorf("reading underlying connection: %w", err)
	}

	// Check if it's a TLS connection
	if data[0] != 22 {
		log.Print("not tls")
		// Not TLS handshake. Replay conn, pass through.
		return "", &sniffedConn{
			underConn,
			io.MultiReader(bytes.NewBuffer(data[0:readLen]), underConn),
			"",
		}, nil
	}

	// Session ID length
	currentPos := 43
	// skip Session IDs
	currentPos += 1 + int(data[currentPos])
	// skip cipher suites
	currentPos += 2 + readInt16BE(data, currentPos)
	// skip compression methods
	currentPos += 1 + int(data[currentPos])
	// skip extensions length
	currentPos += 2
	for currentPos < len(data) {
		if readInt16BE(data, currentPos) == 0 {
			sniLength := readInt16BE(data, currentPos+2)
			currentPos += 4
			if data[currentPos] != 0 {
				// RFC says this is a reserved host type, not DNS.
			}
			currentPos += 5
			sniHeader = string(data[currentPos:(currentPos + sniLength - 5)])
			break
		} else {
			// TODO - there's still some weirdness here - need to figure structure better.
			// For now, just break out if the first header isn't us
			break
			// currentPos += 4 + readInt16BE(data, currentPos+2)
		}

	}

	return sniHeader, &sniffedConn{
		Conn:       underConn,
		reader:     io.MultiReader(bytes.NewBuffer(data[0:readLen]), underConn),
		serverName: sniHeader,
	}, nil
}

// ServerNameConn is a type that connections with a sniffed SNI header can be
// cast to
type ServerNameConn interface {
	net.Conn
	// ServerName returns the SNI name that was sniffed from this connection, or
	// an empty string if none was found.
	ServerName() string
}

type sniffedConn struct {
	net.Conn
	// Data to be replayed stashed here
	reader     io.Reader
	serverName string
}

func (s *sniffedConn) Read(b []byte) (n int, err error) {
	n, err = s.reader.Read(b)
	log.Printf("n: %d err: %v", n, err)
	return n, err
	// log.Printf("read called")
	// if len(s.initialData) > 0 {
	// 	log.Printf("return initial data (len initial %d) (len b %d)", len(s.initialData), len(b))
	// 	// TODO handle len b < initialdata
	// 	n = copy(b, s.initialData)
	// 	s.initialData = nil
	// 	return n, io.EOF
	// }
	// log.Printf("pass through read")
	// return s.Conn.Read(b)
}

func (s *sniffedConn) ServerName() string {
	return s.serverName
}
