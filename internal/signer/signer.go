package signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"
	"time"

	"clm/internal/models"

	"github.com/google/uuid"
)

// Keystore manages private keys inside customer infrastructure (HSM/KMS/Software).
// Private keys never leave the keystore.
type Keystore interface {
	Type() string
	GenerateKey(tenantID, gatewayID, alias, algorithm string, bits int, nonExportable bool) (*models.KeyReference, error)
	CreateCSR(keyRef *models.KeyReference, subject pkix.Name, dnsNames []string) (string, error)
	Sign(keyRef *models.KeyReference, digest []byte, opts crypto.SignerOpts) ([]byte, error)
	GetPublicKeyPEM(keyRef *models.KeyReference) (string, error)
}

// SoftwareKeystore holds keys in-memory / local encrypted storage.
type SoftwareKeystore struct {
	mu   sync.RWMutex
	keys map[string]crypto.Signer
	refs map[string]*models.KeyReference
}

func NewSoftwareKeystore() *SoftwareKeystore {
	return &SoftwareKeystore{
		keys: make(map[string]crypto.Signer),
		refs: make(map[string]*models.KeyReference),
	}
}

func (s *SoftwareKeystore) Type() string {
	return "software"
}

func (s *SoftwareKeystore) GenerateKey(tenantID, gatewayID, alias, algorithm string, bits int, nonExportable bool) (*models.KeyReference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if alias == "" {
		alias = "key_" + uuid.New().String()[:8]
	}

	var signer crypto.Signer
	var err error

	switch algorithm {
	case "RSA", "RSA-2048", "RSA-3072", "RSA-4096":
		if bits < 2048 {
			bits = 2048
		}
		signer, err = rsa.GenerateKey(rand.Reader, bits)
	case "ECDSA", "ECDSA-P256":
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ECDSA-P384":
		signer, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "Ed25519", "EdDSA":
		_, priv, genErr := ed25519.GenerateKey(rand.Reader)
		signer = priv
		err = genErr
	default:
		// Default to ECDSA P-256 for modern crypto-agility
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		algorithm = "ECDSA-P256"
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate %s key: %w", algorithm, err)
	}

	ref := &models.KeyReference{
		ID:            "kref_" + uuid.New().String()[:8],
		TenantID:      tenantID,
		GatewayID:     gatewayID,
		KeyStore:      s.Type(),
		KeyAlias:      alias,
		Algorithm:     algorithm,
		Bits:          bits,
		NonExportable: nonExportable,
		CreatedAt:     time.Now().UTC(),
	}

	s.keys[ref.ID] = signer
	s.refs[ref.ID] = ref
	return ref, nil
}

func (s *SoftwareKeystore) CreateCSR(keyRef *models.KeyReference, subject pkix.Name, dnsNames []string) (string, error) {
	s.mu.RLock()
	signer, ok := s.keys[keyRef.ID]
	s.mu.RUnlock()

	if !ok {
		return "", errors.New("key not found in keystore")
	}

	template := x509.CertificateRequest{
		Subject:            subject,
		DNSNames:           dnsNames,
		SignatureAlgorithm: getSignatureAlgorithm(signer.Public()),
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, signer)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return string(csrPEM), nil
}

func (s *SoftwareKeystore) Sign(keyRef *models.KeyReference, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.RLock()
	signer, ok := s.keys[keyRef.ID]
	s.mu.RUnlock()

	if !ok {
		return nil, errors.New("key not found in keystore")
	}

	return signer.Sign(rand.Reader, digest, opts)
}

func (s *SoftwareKeystore) GetPublicKeyPEM(keyRef *models.KeyReference) (string, error) {
	s.mu.RLock()
	signer, ok := s.keys[keyRef.ID]
	s.mu.RUnlock()

	if !ok {
		return "", errors.New("key not found in keystore")
	}

	der, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return "", err
	}

	b := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	})
	return string(b), nil
}

// PKCS11Keystore represents an HSM/KMS hardware token simulator.
type PKCS11Keystore struct {
	*SoftwareKeystore
	modulePath string
	tokenLabel string
}

func NewPKCS11Keystore(modulePath, tokenLabel string) *PKCS11Keystore {
	return &PKCS11Keystore{
		SoftwareKeystore: NewSoftwareKeystore(),
		modulePath:       modulePath,
		tokenLabel:       tokenLabel,
	}
}

func (p *PKCS11Keystore) Type() string {
	return "pkcs11"
}

func getSignatureAlgorithm(pub crypto.PublicKey) x509.SignatureAlgorithm {
	switch pub.(type) {
	case *rsa.PublicKey:
		return x509.SHA256WithRSA
	case *ecdsa.PublicKey:
		return x509.ECDSAWithSHA256
	case ed25519.PublicKey:
		return x509.PureEd25519
	default:
		return x509.ECDSAWithSHA256
	}
}
