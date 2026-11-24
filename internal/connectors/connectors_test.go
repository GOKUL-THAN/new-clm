package connectors

import (
	"crypto/x509/pkix"
	"testing"

	"clm/internal/signer"
)

func TestBuiltinPrivateCAIssuanceAndARI(t *testing.T) {
	ca, err := NewBuiltinPrivateCA("Corp")
	if err != nil {
		t.Fatalf("failed to create builtin CA: %v", err)
	}

	ks := signer.NewSoftwareKeystore()
	ref, err := ks.GenerateKey("tenant_test", "gw_test", "key1", "ECDSA-P256", 256, true)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	csrPEM, err := ks.CreateCSR(ref, pkix.Name{CommonName: "secure.example.com"}, []string{"secure.example.com", "alt.example.com"})
	if err != nil {
		t.Fatalf("CreateCSR failed: %v", err)
	}

	res, err := ca.Issue(csrPEM, 30)
	if err != nil {
		t.Fatalf("Issue failed: %v", err)
	}

	if len(res.CertificatePEM) == 0 {
		t.Fatal("expected non-empty CertificatePEM")
	}
	if len(res.Fingerprint) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %s", res.Fingerprint)
	}

	// ARI check
	ari, err := ca.GetARI(res.CertificatePEM)
	if err != nil {
		t.Fatalf("GetARI failed: %v", err)
	}
	if ari.SuggestedWindowStart.IsZero() {
		t.Fatal("expected non-zero ARI window start")
	}

	// Revocation
	if err := ca.Revoke(res.CertificatePEM, "keyCompromise"); err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	status, err := ca.GetStatus(res.SerialNumber)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if !status.IsRevoked {
		t.Errorf("expected certificate to be revoked")
	}
}

func TestDCVAndCAA(t *testing.T) {
	dcv := NewDCVEngine("validation.example.net")

	// DNS-01 Challenge with CNAME delegation
	ch := dcv.GenerateDNS01Challenge("app.example.com", "token123", "thumbprint456")
	if ch.Type != DCVDNS01 {
		t.Errorf("expected DCVDNS01, got %s", ch.Type)
	}
	if ch.DNSResource != "app.example.com.validation.example.net" {
		t.Errorf("unexpected DNS resource: %s", ch.DNSResource)
	}

	// CAA test
	caaRecords := map[string][]string{
		"allowed.com": {"0 issue \"letsencrypt.org\""},
		"blocked.com": {"0 issue \"digicert.com\""},
	}

	ok, _ := dcv.CheckCAA("allowed.com", "letsencrypt.org", caaRecords)
	if !ok {
		t.Errorf("expected allowed.com to pass CAA check for letsencrypt.org")
	}

	ok, _ = dcv.CheckCAA("blocked.com", "letsencrypt.org", caaRecords)
	if ok {
		t.Errorf("expected blocked.com to fail CAA check for letsencrypt.org")
	}
}
