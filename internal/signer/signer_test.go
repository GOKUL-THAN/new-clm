package signer

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestSignerKeyAndCSR(t *testing.T) {
	ks := NewSoftwareKeystore()

	testCases := []struct {
		name      string
		algorithm string
		bits      int
	}{
		{"RSA-2048", "RSA-2048", 2048},
		{"ECDSA-P256", "ECDSA-P256", 256},
		{"Ed25519", "Ed25519", 256},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := ks.GenerateKey("tenant_test", "gw_test", "alias_"+tc.name, tc.algorithm, tc.bits, true)
			if err != nil {
				t.Fatalf("GenerateKey failed for %s: %v", tc.name, err)
			}
			if ref.ID == "" {
				t.Fatal("expected non-empty key reference ID")
			}
			if !ref.NonExportable {
				t.Errorf("expected NonExportable to be true")
			}

			pubPEM, err := ks.GetPublicKeyPEM(ref)
			if err != nil {
				t.Fatalf("GetPublicKeyPEM failed: %v", err)
			}
			if len(pubPEM) == 0 {
				t.Fatal("expected non-empty public key PEM")
			}

			// Generate CSR
			subject := pkix.Name{
				CommonName:   "test." + tc.name + ".example.com",
				Organization: []string{"Acme Corp"},
			}
			dnsNames := []string{"test." + tc.name + ".example.com", "alt.example.com"}

			csrPEM, err := ks.CreateCSR(ref, subject, dnsNames)
			if err != nil {
				t.Fatalf("CreateCSR failed: %v", err)
			}

			block, _ := pem.Decode([]byte(csrPEM))
			if block == nil || block.Type != "CERTIFICATE REQUEST" {
				t.Fatalf("invalid CSR PEM block")
			}

			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse CSR: %v", err)
			}

			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("CSR signature check failed: %v", err)
			}

			if csr.Subject.CommonName != subject.CommonName {
				t.Errorf("got CommonName %s, want %s", csr.Subject.CommonName, subject.CommonName)
			}
		})
	}
}
