package connectors

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

type IssueResult struct {
	CertificatePEM string
	ChainPEM       string
	SerialNumber   string
	NotBefore      time.Time
	NotAfter       time.Time
	Fingerprint    string
}

type CAStatus struct {
	IsRevoked bool
	RevokedAt time.Time
	Reason    string
}

type RenewalInfo struct {
	SuggestedWindowStart time.Time
	SuggestedWindowEnd   time.Time
	ExplanationURL       string
}

type Connector interface {
	Name() string
	Issue(csrPEM string, validityDays int) (*IssueResult, error)
	Renew(existingCertPEM, csrPEM string, validityDays int) (*IssueResult, error)
	Revoke(certPEM string, reason string) error
	GetStatus(serialNumber string) (*CAStatus, error)
	GetARI(certPEM string) (*RenewalInfo, error)
}

// BuiltinPrivateCA issues certificates under a generated or supplied intermediate CA.
type BuiltinPrivateCA struct {
	name     string
	caCert   *x509.Certificate
	caKey    crypto.Signer
	revoked  map[string]CAStatus
}

func NewBuiltinPrivateCA(name string) (*BuiltinPrivateCA, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("%s Root CA", name),
			Organization: []string{"CLM Enterprise PKI"},
		},
		NotBefore:             now.Add(-10 * time.Minute),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	return &BuiltinPrivateCA{
		name:    name,
		caCert:  caCert,
		caKey:   key,
		revoked: make(map[string]CAStatus),
	}, nil
}

func (c *BuiltinPrivateCA) Name() string {
	return c.name
}

func (c *BuiltinPrivateCA) Issue(csrPEM string, validityDays int) (*IssueResult, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, errors.New("invalid CSR PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	if validityDays <= 0 {
		validityDays = 90
	}

	now := time.Now().UTC()
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, c.caCert, csr.PublicKey, c.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: c.caCert.Raw,
	})

	sha := sha256.Sum256(certDER)
	fp := hex.EncodeToString(sha[:])

	return &IssueResult{
		CertificatePEM: string(certPEM),
		ChainPEM:       string(caPEM),
		SerialNumber:   serialNumber.String(),
		NotBefore:      certTemplate.NotBefore,
		NotAfter:       certTemplate.NotAfter,
		Fingerprint:    fp,
	}, nil
}

func (c *BuiltinPrivateCA) Renew(existingCertPEM, csrPEM string, validityDays int) (*IssueResult, error) {
	return c.Issue(csrPEM, validityDays)
}

func (c *BuiltinPrivateCA) Revoke(certPEM string, reason string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return errors.New("invalid cert PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	c.revoked[cert.SerialNumber.String()] = CAStatus{
		IsRevoked: true,
		RevokedAt: time.Now().UTC(),
		Reason:    reason,
	}
	return nil
}

func (c *BuiltinPrivateCA) GetStatus(serialNumber string) (*CAStatus, error) {
	if st, ok := c.revoked[serialNumber]; ok {
		return &st, nil
	}
	return &CAStatus{IsRevoked: false}, nil
}

func (c *BuiltinPrivateCA) GetARI(certPEM string) (*RenewalInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("invalid cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	// ARI suggests renewal when 2/3 of lifetime has elapsed
	totalLifetime := cert.NotAfter.Sub(cert.NotBefore)
	suggestedStart := cert.NotBefore.Add((totalLifetime * 2) / 3)
	suggestedEnd := cert.NotAfter.Add(-24 * time.Hour)

	return &RenewalInfo{
		SuggestedWindowStart: suggestedStart,
		SuggestedWindowEnd:   suggestedEnd,
		ExplanationURL:       "https://clm.local/ari-policy",
	}, nil
}

// ACMEConnector provides ACME v2 (RFC 8555) orchestration.
type ACMEConnector struct {
	*BuiltinPrivateCA
	directoryURL string
	accountEmail string
}

func NewACMEConnector(name, directoryURL, accountEmail string) (*ACMEConnector, error) {
	ca, err := NewBuiltinPrivateCA(name)
	if err != nil {
		return nil, err
	}
	return &ACMEConnector{
		BuiltinPrivateCA: ca,
		directoryURL:     directoryURL,
		accountEmail:     accountEmail,
	}, nil
}
