package storage

import (
	"testing"
	"time"

	"clm/internal/models"
)

func TestStorageLifecycle(t *testing.T) {
	s, err := NewSQLStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to create memory storage: %v", err)
	}
	defer s.Close()

	// 1. Tenant
	tenant := &models.Tenant{
		Name:   "Acme Corp",
		Slug:   "acme",
		Status: "active",
	}
	if err := s.CreateTenant(tenant); err != nil {
		t.Fatalf("CreateTenant failed: %v", err)
	}
	if tenant.ID == "" {
		t.Fatalf("expected tenant ID to be populated")
	}

	gotTenant, err := s.GetTenant(tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant failed: %v", err)
	}
	if gotTenant.Name != "Acme Corp" {
		t.Errorf("got tenant name %s, want Acme Corp", gotTenant.Name)
	}

	// 2. Environment
	env := &models.Environment{
		TenantID: tenant.ID,
		Name:     "aws-prod",
		Type:     "aws",
		Region:   "us-east-1",
		Tags:     []string{"pci", "prod"},
	}
	if err := s.CreateEnvironment(env); err != nil {
		t.Fatalf("CreateEnvironment failed: %v", err)
	}

	// 3. Profile
	prof := &models.CertificateProfile{
		TenantID:             tenant.ID,
		Name:                 "prod-web-tls",
		AllowedCAs:           []string{"lets-encrypt", "digicert"},
		Algorithms:           []string{"RSA-2048", "ECDSA-P256"},
		ValidityDaysMax:      90,
		AllowedSANPatterns:   []string{"*.acme.com", "acme.com"},
		RequireApproval:      true,
		RenewalThresholdDays: 30,
		CAAEnforce:           true,
	}
	if err := s.CreateProfile(prof); err != nil {
		t.Fatalf("CreateProfile failed: %v", err)
	}

	// 4. Certificate Request
	req := &models.CertificateRequest{
		TenantID:      tenant.ID,
		ProfileID:     prof.ID,
		EnvironmentID: env.ID,
		CommonName:    "api.acme.com",
		SANs:          []string{"api.acme.com", "www.acme.com"},
		KeyAlgorithm:  "RSA",
		KeyBits:       2048,
		Owner:         "alice",
		Team:          "platform",
		Requester:     "alice",
	}
	if err := s.CreateCertificateRequest(req); err != nil {
		t.Fatalf("CreateCertificateRequest failed: %v", err)
	}

	// 5. Certificate
	cert := &models.Certificate{
		TenantID:          tenant.ID,
		FingerprintSHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		SerialNumber:      "1001",
		SubjectDN:         "CN=api.acme.com",
		IssuerDN:          "CN=Let's Encrypt Authority X3",
		SANs:              []string{"api.acme.com"},
		NotBefore:         time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:          time.Now().UTC().Add(30 * 24 * time.Hour),
		KeyAlgorithm:      "RSA",
		KeyBits:           2048,
		RawPEM:            "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		Owner:             "alice",
		Team:              "platform",
		EnvironmentID:     env.ID,
		ProfileID:         prof.ID,
		KeyRefID:          "key_123",
		RequestID:         req.ID,
		AutoRenew:         true,
	}
	if err := s.CreateCertificate(cert); err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	// 6. Audit Event
	ev := &models.AuditEvent{
		TenantID:   tenant.ID,
		Actor:      "alice",
		Action:     "cert.issued",
		TargetType: "certificate",
		TargetID:   cert.ID,
		Hash:       "hash_abc_123",
	}
	if err := s.AppendAuditEvent(ev); err != nil {
		t.Fatalf("AppendAuditEvent failed: %v", err)
	}
	if ev.Sequence != 1 {
		t.Errorf("expected sequence 1, got %d", ev.Sequence)
	}
}
