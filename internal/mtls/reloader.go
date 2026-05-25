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
	identity           IdentityFiles
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
	identity [sha256.Size]byte
	ca       [sha256.Size]byte
}

// NewClientReloader loads client certificate material and returns a reloader.
func NewClientReloader(logger *slog.Logger, identity IdentityFiles, caFile string, interval time.Duration) (*Reloader, error) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	r := &Reloader{
		role:     reloaderClient,
		logger:   logger,
		interval: interval,
		identity: identity,
		caFile:     caFile,
	}
	if err := r.reload(true); err != nil {
		return nil, err
	}
	return r, nil
}

// NewServerReloader loads server certificate material and returns a reloader.
func NewServerReloader(logger *slog.Logger, identity IdentityFiles, clientCAFile, expectedClientSVID string, interval time.Duration) (*Reloader, error) {
	if interval <= 0 {
		interval = DefaultReloadInterval
	}
	r := &Reloader{
		role:               reloaderServer,
		logger:             logger,
		interval:           interval,
		identity:           identity,
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
	fp, err := fingerprintCredentials(r.identity, r.caFile)
	if err != nil {
		return err
	}

	r.mu.RLock()
	unchanged := fp == r.fileFP
	r.mu.RUnlock()
	if unchanged && !initial {
		return nil
	}

	cert, err := r.identity.Load()
	if err != nil {
		return fmt.Errorf("loading identity credential: %w", err)
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
		attrs := []any{"ca", r.caFile}
		if r.identity.BundleFile != "" {
			attrs = append([]any{"bundle", r.identity.BundleFile}, attrs...)
		} else {
			attrs = append([]any{"cert", r.identity.CertFile, "key", r.identity.KeyFile}, attrs...)
		}
		r.logger.Info("reloaded TLS certificate material", attrs...)
	}
	return nil
}

func fingerprintCredentials(identity IdentityFiles, caFile string) (fileFingerprint, error) {
	var fp fileFingerprint
	identitySum, err := fingerprintIdentity(identity)
	if err != nil {
		return fp, err
	}
	caSum, err := hashFile(caFile)
	if err != nil {
		return fp, fmt.Errorf("hashing ca file: %w", err)
	}
	copy(fp.identity[:], identitySum)
	copy(fp.ca[:], caSum)
	return fp, nil
}

func fingerprintIdentity(identity IdentityFiles) ([]byte, error) {
	if identity.BundleFile != "" {
		return hashFile(identity.BundleFile)
	}
	certSum, err := hashFile(identity.CertFile)
	if err != nil {
		return nil, fmt.Errorf("hashing cert file: %w", err)
	}
	keySum, err := hashFile(identity.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("hashing key file: %w", err)
	}
	sum := sha256.Sum256(append(certSum, keySum...))
	return sum[:], nil
}

func hashFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

func loadCAPool(caFile string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading CA file %s: %w", caFile, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in CA file %s", caFile)
	}
	return pool, nil
}
