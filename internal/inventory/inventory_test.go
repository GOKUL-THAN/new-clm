package inventory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"clm/internal/models"
)

func TestNetworkDiscoveryAndRisk(t *testing.T) {
	// Setup a mock local TLS listener
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost.test"},
		DNSNames:     []string{"localhost.test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(5 * 24 * time.Hour), // Expiring in 5 days!
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	// In-memory TLS handshake using net.Pipe
	clientConn, serverConn := net.Pipe()
	go func() {
		sConn := tls.Server(serverConn, &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
		})
		_ = sConn.Handshake()
		_ = sConn.Close()
	}()

	scanner := NewNetworkScanner(2 * time.Second)
	scanner.Dialer = func(network, addr string) (net.Conn, error) {
		return clientConn, nil
	}

	res, err := scanner.ScanEndpoint("127.0.0.1", 443, "localhost.test")
	if err != nil {
		t.Fatalf("ScanEndpoint failed: %v", err)
	}

	if res.SubjectDN != "CN=localhost.test" {
		t.Errorf("got SubjectDN %s, want CN=localhost.test", res.SubjectDN)
	}
	if len(res.Fingerprint) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %s", res.Fingerprint)
	}

	// Risk evaluation test
	score, factors := EvaluateRisk(res.NotAfter, res.Algorithm, res.KeyBits, false, false, false)
	if score < 40 {
		t.Errorf("expected high risk score for expiring unmanaged cert without owner, got %d", score)
	}

	foundExpiringFactor := false
	for _, f := range factors {
		if f == "Expiring_Under_7_Days" {
			foundExpiringFactor = true
			break
		}
	}
	if !foundExpiringFactor {
		t.Errorf("expected Expiring_Under_7_Days factor in %v", factors)
	}

	// Test CBOM generation
	certRecord := &models.Certificate{
		SubjectDN:         res.SubjectDN,
		FingerprintSHA256: res.Fingerprint,
		KeyAlgorithm:      "RSA-2048",
		KeyBits:           2048,
		NotAfter:          res.NotAfter,
		IssuerDN:          res.IssuerDN,
	}
	cbom, err := GenerateCBOM("tenant_test", []*models.Certificate{certRecord})
	if err != nil {
		t.Fatalf("GenerateCBOM failed: %v", err)
	}
	if len(cbom.Components) != 1 {
		t.Fatalf("expected 1 CBOM component, got %d", len(cbom.Components))
	}
	if !cbom.Components[0].CryptoProperties.QuantumVulnerable {
		t.Errorf("expected RSA to be marked quantum vulnerable")
	}

	jsonStr, err := cbom.ToJSON()
	if err != nil || len(jsonStr) == 0 {
		t.Fatalf("ToJSON failed: %v", err)
	}
}
