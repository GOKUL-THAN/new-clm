package inventory

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

type TLSScanResult struct {
	Host         string
	Port         int
	Certificate  *x509.Certificate
	Fingerprint  string
	IssuerDN     string
	SubjectDN    string
	SANs         []string
	Algorithm    string
	KeyBits      int
	NotBefore    time.Time
	NotAfter     time.Time
	HandshakeErr error
}

type DialerFunc func(network, addr string) (net.Conn, error)

type NetworkScanner struct {
	Timeout time.Duration
	Dialer  DialerFunc
}

func NewNetworkScanner(timeout time.Duration) *NetworkScanner {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &NetworkScanner{
		Timeout: timeout,
	}
}

// ScanEndpoint performs a pure TLS handshake on host:port, extracting the leaf certificate.
func (s *NetworkScanner) ScanEndpoint(host string, port int, sni string) (*TLSScanResult, error) {
	if sni == "" {
		sni = host
	}

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var rawConn net.Conn
	var err error
	if s.Dialer != nil {
		rawConn, err = s.Dialer("tcp", addr)
	} else {
		dialer := &net.Dialer{Timeout: s.Timeout}
		rawConn, err = dialer.Dial("tcp", addr)
	}

	if err != nil {
		return &TLSScanResult{
			Host:         host,
			Port:         port,
			HandshakeErr: err,
		}, err
	}

	conf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Needed for discovery of internal/expired certs
	}

	conn := tls.Client(rawConn, conf)
	if err := conn.Handshake(); err != nil {
		_ = rawConn.Close()
		return &TLSScanResult{
			Host:         host,
			Port:         port,
			HandshakeErr: err,
		}, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no peer certificates returned by %s", addr)
	}

	leaf := state.PeerCertificates[0]
	sha := sha256.Sum256(leaf.Raw)
	fp := hex.EncodeToString(sha[:])

	alg := leaf.SignatureAlgorithm.String()
	keyBits := 0
	if rsaPub, ok := leaf.PublicKey.(*rsa.PublicKey); ok {
		keyBits = rsaPub.N.BitLen()
		alg = fmt.Sprintf("RSA-%d", keyBits)
	}

	return &TLSScanResult{
		Host:        host,
		Port:        port,
		Certificate: leaf,
		Fingerprint: fp,
		IssuerDN:    leaf.Issuer.String(),
		SubjectDN:   leaf.Subject.String(),
		SANs:        leaf.DNSNames,
		Algorithm:   alg,
		KeyBits:     keyBits,
		NotBefore:   leaf.NotBefore,
		NotAfter:    leaf.NotAfter,
	}, nil
}

// EvaluateRisk calculates risk score and factors for any certificate record or finding.
func EvaluateRisk(notAfter time.Time, alg string, keyBits int, isWildcard, isManaged bool, hasOwner bool) (int, []string) {
	score := 0
	var factors []string

	now := time.Now().UTC()
	daysLeft := int(notAfter.Sub(now).Hours() / 24)

	// Expiry risk
	if daysLeft <= 0 {
		score += 60
		factors = append(factors, "Expired")
	} else if daysLeft <= 7 {
		score += 40
		factors = append(factors, "Expiring_Under_7_Days")
	} else if daysLeft <= 30 {
		score += 20
		factors = append(factors, "Expiring_Under_30_Days")
	}

	// Algorithm risk
	upperAlg := strings.ToUpper(alg)
	if strings.Contains(upperAlg, "SHA1") || strings.Contains(upperAlg, "MD5") {
		score += 50
		factors = append(factors, "Deprecated_Digest_Algorithm")
	}
	if strings.Contains(upperAlg, "RSA") && keyBits > 0 && keyBits < 2048 {
		score += 50
		factors = append(factors, "Weak_RSA_Key_Below_2048")
	}

	// Wildcard sprawl
	if isWildcard {
		score += 15
		factors = append(factors, "Wildcard_Certificate")
	}

	// Governance & Ownership
	if !hasOwner {
		score += 20
		factors = append(factors, "Missing_Owner_Or_Team")
	}

	// Shadow Certificate
	if !isManaged {
		score += 30
		factors = append(factors, "Unmanaged_Shadow_Certificate")
	}

	if score > 100 {
		score = 100
	}
	return score, factors
}
