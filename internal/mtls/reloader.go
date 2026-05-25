package mtls

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

const DefaultReloadInterval = 5 * time.Minute

type reloaderRole int

const (
	reloaderClient reloaderRole = iota
	reloaderServer
)

// Reloader periodically reloads TLS material from disk. Failed reloads are logged
// and the previous material is kept.
type Reloader struct {
	role               reloaderRole
	logger             *slog.Logger
	interval           time.Duration
	certFile           string
	keyFile            string
	caFile             string
	expectedClientSVID string

	mu         sync.RWMutex
	clientCert tls.Certificate
	serverCert tls.Certificate
	caPool     *x509.CertPool
	fileFP     fileFingerprint

	// Shared with tls.Listener; ClientCAs is updated in place on reload.
	serverTLSConfig *tls.Config
}

type fileFingerprint struct {
	cert [sha256.Size]byte
	key  [sha256.Size]byte
	ca   [sha256.Size]byte
}

// NewClientReloader loads client certificate material and returns a reloader.
func NewClientReloader(logger *slog.Logger, certFile, keyFile, caFile string, interval time.Duration) (*Reloader, error) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	r := &Reloader{
		role:     reloaderClient,
		logger:   logger,
		interval: interval,
		certFile: certFile,
		keyFile:  keyFile,
		caFile:   caFile,
	}
	if err := r.reload(true); err != nil {
		return nil, err
	}
	return r, nil
}

// NewServerReloader loads server certificate material and returns a reloader.
func NewServerReloader(logger *slog.Logger, certFile, keyFile, clientCAFile, expectedClientSVID string, interval time.Duration) (*Reloader, error) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	r := &Reloader{
		role:               reloaderServer,
		logger:             logger,
		interval:           interval,
		certFile:           certFile,
		keyFile:            keyFile,
		caFile:             clientCAFile,
		expectedClientSVID: expectedClientSVID,
	}
	if err := r.reload(true); err != nil {
		return nil, err
	}
	r.serverTLSConfig = r.buildServerTLSConfig()
	return r, nil
}

// Start runs periodic reloads until ctx is cancelled.
func (r *Reloader) Start(ctx context.Context) {
	if r == nil {
		return
	}
	ticker := time.NewTicker(r.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := r.reload(false); err != nil {
					r.logger.Warn("certificate reload failed", "error", err)
				}
			}
		}
	}()
}

// ClientTLSConfig returns a tls.Config for dialing backends. serverName must
// match a DNS SAN on the backend server certificate.
func (r *Reloader) ClientTLSConfig(serverName string) *tls.Config {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg := &tls.Config{
		Certificates: []tls.Certificate{r.clientCert},
		RootCAs:      r.caPool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
	}
	return cfg
}

// ServerTLSConfig returns the tls.Config used by tls.Listen. Certificate and
// client CA material is served from the reloader and updated on reload.
func (r *Reloader) ServerTLSConfig() *tls.Config {
	if r.serverTLSConfig == nil {
		r.serverTLSConfig = r.buildServerTLSConfig()
	}
	return r.serverTLSConfig
}

func (r *Reloader) buildServerTLSConfig() *tls.Config {
	expected := r.expectedClientSVID
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			r.mu.RLock()
			defer r.mu.RUnlock()
			cert := r.serverCert
			return &cert, nil
		},
	}
	cfg.ClientCAs = r.currentCAPool()
	if expected != "" {
		cfg.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("no client certificate presented")
			}
			return VerifyClientSVID(state.PeerCertificates[0], expected)
		}
	}
	return cfg
}

func (r *Reloader) currentCAPool() *x509.CertPool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.caPool
}

func (r *Reloader) ReloadOnce() error {
	return r.reload(false)
}

func (r *Reloader) reload(initial bool) error {
	fp, err := fingerprintFiles(r.certFile, r.keyFile, r.caFile)
	if err != nil {
		return err
	}

	r.mu.RLock()
	unchanged := fp == r.fileFP
	r.mu.RUnlock()
	if unchanged && !initial {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("loading certificate: %w", err)
	}
	pool, err := loadCAPool(r.caFile)
	if err != nil {
		return fmt.Errorf("loading CA: %w", err)
	}

	r.mu.Lock()
	switch r.role {
	case reloaderClient:
		r.clientCert = cert
	case reloaderServer:
		r.serverCert = cert
	}
	r.caPool = pool
	r.fileFP = fp
	if r.serverTLSConfig != nil {
		r.serverTLSConfig.ClientCAs = pool
	}
	r.mu.Unlock()

	if !initial {
		r.logger.Info("reloaded TLS certificate material",
			"cert", r.certFile,
			"key", r.keyFile,
			"ca", r.caFile,
		)
	}
	return nil
}

func fingerprintFiles(certFile, keyFile, caFile string) (fileFingerprint, error) {
	var fp fileFingerprint
	certSum, err := hashFile(certFile)
	if err != nil {
		return fp, fmt.Errorf("hashing cert file: %w", err)
	}
	keySum, err := hashFile(keyFile)
	if err != nil {
		return fp, fmt.Errorf("hashing key file: %w", err)
	}
	caSum, err := hashFile(caFile)
	if err != nil {
		return fp, fmt.Errorf("hashing ca file: %w", err)
	}
	copy(fp.cert[:], certSum)
	copy(fp.key[:], keySum)
	copy(fp.ca[:], caSum)
	return fp, nil
}

func hashFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}
