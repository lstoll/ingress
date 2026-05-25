package mtls

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"os"
)

// IdentityFiles identifies a TLS identity from either a Kubernetes-style
// credential bundle or separate certificate and key PEM files.
type IdentityFiles struct {
	BundleFile string
	CertFile   string
	KeyFile    string
}

func (f IdentityFiles) Validate() error {
	hasBundle := f.BundleFile != ""
	hasCert := f.CertFile != ""
	hasKey := f.KeyFile != ""

	if hasBundle && (hasCert || hasKey) {
		return fmt.Errorf("credential bundle cannot be used together with separate cert and key paths")
	}
	if hasBundle {
		return nil
	}
	if hasCert != hasKey {
		return fmt.Errorf("cert and key paths must both be set")
	}
	if !hasCert {
		return fmt.Errorf("either credential bundle or cert and key paths are required")
	}
	return nil
}

// Load reads the identity credential from disk.
func (f IdentityFiles) Load() (tls.Certificate, error) {
	if err := f.Validate(); err != nil {
		return tls.Certificate{}, err
	}
	if f.BundleFile != "" {
		return LoadCredentialBundle(f.BundleFile)
	}
	cert, err := tls.LoadX509KeyPair(f.CertFile, f.KeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("loading certificate: %w", err)
	}
	return cert, nil
}

// LoadCredentialBundle reads a Kubernetes pod certificate credential bundle:
// the first PEM block is a private key and the remaining blocks are the
// certificate chain (leaf first).
func LoadCredentialBundle(path string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading credential bundle %s: %w", path, err)
	}
	return ParseCredentialBundle(data)
}

// ParseCredentialBundle parses credential bundle PEM bytes into a tls.Certificate.
func ParseCredentialBundle(data []byte) (tls.Certificate, error) {
	var keyBlock *pem.Block
	var certBlocks []*pem.Block

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		switch block.Type {
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			if keyBlock != nil {
				return tls.Certificate{}, fmt.Errorf("credential bundle contains multiple private keys")
			}
			keyBlock = block
		case "CERTIFICATE":
			certBlocks = append(certBlocks, block)
		default:
			return tls.Certificate{}, fmt.Errorf("unexpected PEM block type %q in credential bundle", block.Type)
		}
	}

	if keyBlock == nil {
		return tls.Certificate{}, fmt.Errorf("credential bundle contains no private key")
	}
	if len(certBlocks) == 0 {
		return tls.Certificate{}, fmt.Errorf("credential bundle contains no certificates")
	}

	keyPEM := pem.EncodeToMemory(keyBlock)
	leafPEM := pem.EncodeToMemory(certBlocks[0])
	cert, err := tls.X509KeyPair(leafPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("credential bundle leaf does not match private key: %w", err)
	}
	for _, block := range certBlocks[1:] {
		cert.Certificate = append(cert.Certificate, block.Bytes)
	}
	return cert, nil
}
