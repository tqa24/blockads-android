package tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// MITM Certificate Authority — Root CA generation and per-domain cert minting.
//
// • GenerateCA() creates a self-signed Root CA (ECDSA P-256, 10-year validity).
// • getCertForHost(host) generates a leaf cert signed by the CA on demand.
// • An in-memory cache avoids regenerating certs for the same domain.
//
// ECDSA P-256 is used instead of RSA-2048 because:
//   - Faster key generation (important on Android: ~1ms vs ~100ms)
//   - Smaller certs = less memory per cached entry
//   - Same security level as RSA-3072
// ─────────────────────────────────────────────────────────────────────────────

// CertManager handles Root CA lifecycle and per-host certificate generation.
type CertManager struct {
	mu      sync.RWMutex
	caCert  *x509.Certificate
	caKey   *ecdsa.PrivateKey
	caPEM   []byte // PEM-encoded CA cert for export to Android
	caKeyPEM []byte

	// Per-host cert cache (host → *tls.Certificate)
	certCache sync.Map
}

// NewCertManager creates a CertManager and generates a fresh Root CA.
func NewCertManager() (*CertManager, error) {
	cm := &CertManager{}
	if err := cm.generateCA(); err != nil {
		return nil, err
	}
	return cm, nil
}

// GetCACertPEM returns the PEM-encoded Root CA certificate.
// The user must install this on their Android device:
//   Settings → Security → Encryption & credentials → Install from storage
func (cm *CertManager) GetCACertPEM() string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return string(cm.caPEM)
}

// GetTLSConfigForHost returns a *tls.Config with a dynamically generated
// certificate for the given hostname, signed by the Root CA.
func (cm *CertManager) GetTLSConfigForHost(host string) (*tls.Config, error) {
	cert, err := cm.getCertForHost(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}, nil
}

// ── Internal ─────────────────────────────────────────────────────────────────

// generateCA creates a self-signed ECDSA P-256 Root CA.
func (cm *CertManager) generateCA() error {
	// Generate CA private key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate CA key: %w", err)
	}

	// Serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	// CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"BlockAds"},
			CommonName:   "BlockAds Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour), // 1 day grace
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("create CA cert: %w", err)
	}

	// Parse back to x509.Certificate
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}

	// Encode to PEM
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyDER})

	cm.mu.Lock()
	cm.caCert = caCert
	cm.caKey = caKey
	cm.caPEM = caPEM
	cm.caKeyPEM = caKeyPEM
	cm.mu.Unlock()

	logf("MITM CA generated: CN=%s, valid until %s", caCert.Subject.CommonName, caCert.NotAfter.Format("2006-01-02"))
	return nil
}

// getCertForHost returns a cached or freshly-generated TLS certificate
// for the given hostname, signed by the Root CA.
func (cm *CertManager) getCertForHost(host string) (*tls.Certificate, error) {
	// Check cache first
	if cached, ok := cm.certCache.Load(host); ok {
		return cached.(*tls.Certificate), nil
	}

	// Generate new leaf cert
	cm.mu.RLock()
	caCert := cm.caCert
	caKey := cm.caKey
	cm.mu.RUnlock()

	if caCert == nil || caKey == nil {
		return nil, fmt.Errorf("CA not initialized")
	}

	// Leaf key (ECDSA P-256 — fast generation)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", host, err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial for %s: %w", host, err)
	}

	// Build SANs: exact host + wildcard for subdomains.
	// e.g., host="www.example.com" → DNSNames=["www.example.com", "*.example.com"]
	// This prevents Chrome NET::ERR_CERT_COMMON_NAME_INVALID for sub-resources.
	dnsNames := []string{host}
	if parts := strings.SplitN(host, ".", 2); len(parts) == 2 && strings.Contains(parts[1], ".") {
		wildcard := "*." + parts[1]
		dnsNames = append(dnsNames, wildcard)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"BlockAds"},
			CommonName:   host,
		},
		DNSNames:              dnsNames,
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour), // Short-lived (24h)
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Sign with CA
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf cert for %s: %w", host, err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafCertDER, caCert.Raw},
		PrivateKey:  leafKey,
	}

	// Cache it
	cm.certCache.Store(host, tlsCert)
	return tlsCert, nil
}
