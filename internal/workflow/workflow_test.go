package workflow

import (
	"testing"
	"time"

	"clm/internal/connectors"
	"clm/internal/models"
	"clm/internal/policy"
	"clm/internal/storage"
)

func TestFullCertificateLifecycle(t *testing.T) {
	s, err := storage.NewSQLStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to init storage: %v", err)
	}
	defer s.Close()

	ca, err := connectors.NewBuiltinPrivateCA("TestPKI")
	if err != nil {
		t.Fatalf("failed to create CA: %v", err)
	}

	pol := policy.NewPolicyEngine()
	wf := NewWorkflowEngine(s, pol, ca)

	tenantID := "tenant_acme"
	_ = s.CreateTenant(&models.Tenant{ID: tenantID, Name: "Acme", Slug: "acme", Status: "active"})

	env := &models.Environment{
		ID:       "env_prod",
		TenantID: tenantID,
		Name:     "prod",
		Type:     "aws",
	}
	_ = s.CreateEnvironment(env)

	prof := &models.CertificateProfile{
		ID:                 "prof_tls",
		TenantID:           tenantID,
		Name:               "web-tls",
		AllowedCAs:         []string{"TestPKI"},
		Algorithms:         []string{"RSA-2048", "ECDSA-P256"},
		ValidityDaysMax:    90,
		AllowedSANPatterns: []string{".acme.com"},
		RequireApproval:    true,
	}
	_ = s.CreateProfile(prof)

	target := &models.DeploymentTarget{
		ID:            "tgt_nginx",
		TenantID:      tenantID,
		EnvironmentID: env.ID,
		Name:          "web-lb",
		Type:          "nginx",
		HostAddress:   "10.0.1.5",
		Port:          443,
	}
	_ = s.CreateDeploymentTarget(target)

	// 1. Submit Request
	req := &models.CertificateRequest{
		ID:            "req_101",
		TenantID:      tenantID,
		ProfileID:     prof.ID,
		EnvironmentID: env.ID,
		CommonName:    "api.acme.com",
		SANs:          []string{"api.acme.com", "gateway.acme.com"},
		KeyAlgorithm:  "RSA-2048",
		KeyBits:       2048,
		Owner:         "alice",
		Team:          "platform",
		Requester:     "alice",
	}
	if err := s.CreateCertificateRequest(req); err != nil {
		t.Fatalf("CreateCertificateRequest failed: %v", err)
	}

	// 2. Process without approval -> must fail / require approval
	_, err = wf.ProcessRequest(req.ID, tenantID)
	if err == nil {
		t.Fatal("expected failure due to missing approval")
	}

	// 3. Approve by peer (Segregation of Duties)
	app := &models.Approval{
		TenantID:  tenantID,
		RequestID: req.ID,
		Approver:  "bob", // bob != alice
		Decision:  "approved",
		Comments:  "Verified DNS and production requirements",
	}
	if err := s.CreateApproval(app); err != nil {
		t.Fatalf("CreateApproval failed: %v", err)
	}

	// 4. Process with approval -> should succeed and issue cert
	cert, err := wf.ProcessRequest(req.ID, tenantID)
	if err != nil {
		t.Fatalf("ProcessRequest failed after approval: %v", err)
	}
	if cert.Status != models.StateIssued {
		t.Errorf("expected status Issued, got %s", cert.Status)
	}

	// 5. Deploy & Verify
	verifyRes, err := wf.DeployAndVerify(tenantID, cert.ID, target.ID)
	if err != nil {
		t.Fatalf("DeployAndVerify failed: %v", err)
	}
	if !verifyRes.Passed {
		t.Errorf("verification check failed: %v", verifyRes.Errors)
	}

	// Check certificate status is now Active
	updatedCert, _ := s.GetCertificate(tenantID, cert.ID)
	if updatedCert.Status != models.StateActive {
		t.Errorf("expected certificate to be Active, got %s", updatedCert.Status)
	}

	// 6. Test Automatic Rollback on Malformed/Expired cert
	badCert := &models.Certificate{
		ID:                "cert_bad",
		TenantID:          tenantID,
		FingerprintSHA256: "bad_fp",
		SerialNumber:      "999",
		RawPEM:            cert.RawPEM,
		NotBefore:         time.Now().Add(-48 * time.Hour),
		NotAfter:          time.Now().Add(-24 * time.Hour), // Expired!
		EnvironmentID:     env.ID,
		ProfileID:         prof.ID,
	}
	_ = s.CreateCertificate(badCert)

	rollbackRes, err := wf.DeployAndVerify(tenantID, badCert.ID, target.ID)
	if err == nil {
		t.Fatal("expected deployment failure and rollback for expired cert")
	}
	if rollbackRes.Passed {
		t.Error("expected rollback result Passed to be false")
	}

	rolledBackCert, _ := s.GetCertificate(tenantID, badCert.ID)
	if rolledBackCert.Status != models.StateDeployFailed {
		t.Errorf("expected bad cert status DeployFailed, got %s", rolledBackCert.Status)
	}

	// 7. Revocation
	if err := wf.RevokeCertificate(tenantID, cert.ID, "keyCompromise", "security-lead"); err != nil {
		t.Fatalf("RevokeCertificate failed: %v", err)
	}
	revokedCert, _ := s.GetCertificate(tenantID, cert.ID)
	if revokedCert.Status != models.StateRevoked {
		t.Errorf("expected cert to be Revoked, got %s", revokedCert.Status)
	}
}
