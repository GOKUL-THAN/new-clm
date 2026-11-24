package test

import (
	"crypto/x509/pkix"
	"testing"

	"clm/internal/audit"
	"clm/internal/connectors"
	"clm/internal/inventory"
	"clm/internal/models"
	"clm/internal/policy"
	"clm/internal/signer"
	"clm/internal/storage"
	"clm/internal/workflow"
)

func TestEndToEndLifecycleAndGovernance(t *testing.T) {
	// 1. Storage & Engine Initialization
	st, err := storage.NewSQLStorage("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("storage init failed: %v", err)
	}
	defer st.Close()

	ca, err := connectors.NewBuiltinPrivateCA("E2E Test Enterprise CA")
	if err != nil {
		t.Fatalf("CA init failed: %v", err)
	}

	pol := policy.NewPolicyEngine()
	wf := workflow.NewWorkflowEngine(st, pol, ca)

	// 2. Tenant & Environment Setup
	tenant := &models.Tenant{
		ID:     "tenant_e2e",
		Name:   "Enterprise Bank",
		Slug:   "enterprise-bank",
		Status: "active",
	}
	_ = st.CreateTenant(tenant)

	env := &models.Environment{
		ID:       "env_e2e_aws",
		TenantID: tenant.ID,
		Name:     "aws-banking-prod",
		Type:     "aws",
		Region:   "eu-west-1",
	}
	_ = st.CreateEnvironment(env)

	// 3. Profile & Governance Definition
	prof := &models.CertificateProfile{
		ID:                   "prof_banking_tls",
		TenantID:             tenant.ID,
		Name:                 "banking-web-tls",
		AllowedCAs:           []string{"E2E Test Enterprise CA"},
		Algorithms:           []string{"ECDSA-P256", "RSA-2048"},
		ValidityDaysMax:      90,
		AllowedSANPatterns:   []string{".bank.internal"},
		RequireApproval:      true,
		RenewalThresholdDays: 30,
		CAAEnforce:           true,
	}
	_ = st.CreateProfile(prof)

	// 4. Gateway Enrollment (Bootstrap)
	tok := &models.EnrollmentToken{
		TenantID:      tenant.ID,
		EnvironmentID: env.ID,
	}
	_ = st.CreateEnrollmentToken(tok)

	consumedTok, err := st.ConsumeEnrollmentToken(tok.Token)
	if err != nil {
		t.Fatalf("token consumption failed: %v", err)
	}

	gw := &models.Gateway{
		TenantID:      consumedTok.TenantID,
		EnvironmentID: consumedTok.EnvironmentID,
		Name:          "gw-eu-west-1a",
		Status:        "online",
		KeystoreType:  "pkcs11",
		Version:       "1.0.0",
	}
	_ = st.CreateGateway(gw)

	// 5. In-VPC Keystore operation (Local key custody)
	ks := signer.NewSoftwareKeystore()
	kref, err := ks.GenerateKey(tenant.ID, gw.ID, "bank-tls-key", "ECDSA-P256", 256, true)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	csrPEM, err := ks.CreateCSR(kref, pkix.Name{CommonName: "core.bank.internal"}, []string{"core.bank.internal"})
	if err != nil {
		t.Fatalf("CSR generation failed: %v", err)
	}

	// 6. Submit Certificate Request
	req := &models.CertificateRequest{
		ID:            "req_bank_01",
		TenantID:      tenant.ID,
		ProfileID:     prof.ID,
		EnvironmentID: env.ID,
		CommonName:    "core.bank.internal",
		SANs:          []string{"core.bank.internal"},
		KeyAlgorithm:  "ECDSA-P256",
		KeyBits:       256,
		Owner:         "alice.security@bank.internal",
		Team:          "core-banking",
		Requester:     "alice.security@bank.internal",
	}
	_ = st.CreateCertificateRequest(req)

	// 7. Segregation of Duties Check
	// Self-approval must fail
	selfApp := &models.Approval{
		TenantID:  tenant.ID,
		RequestID: req.ID,
		Approver:  "alice.security@bank.internal",
		Decision:  "approved",
	}
	if ok, _ := pol.EvaluateApproval(selfApp, req); ok {
		t.Fatal("expected self-approval to be rejected under SoD")
	}

	// Peer approval succeeds
	peerApp := &models.Approval{
		TenantID:  tenant.ID,
		RequestID: req.ID,
		Approver:  "bob.lead@bank.internal",
		Decision:  "approved",
	}
	if ok, _ := pol.EvaluateApproval(peerApp, req); !ok {
		t.Fatal("expected peer-approval to be accepted")
	}
	_ = st.CreateApproval(peerApp)

	// 8. Lifecycle Processing -> Issue
	cert, err := wf.ProcessRequest(req.ID, tenant.ID)
	if err != nil {
		t.Fatalf("ProcessRequest failed: %v", err)
	}
	if cert.Status != models.StateIssued {
		t.Errorf("expected Issued, got %s", cert.Status)
	}

	// 9. Deploy & Verify
	target := &models.DeploymentTarget{
		ID:            "tgt_core_gateway",
		TenantID:      tenant.ID,
		EnvironmentID: env.ID,
		GatewayID:     gw.ID,
		Name:          "core-envoy-ingress",
		Type:          "envoy",
	}
	_ = st.CreateDeploymentTarget(target)

	verifyRes, err := wf.DeployAndVerify(tenant.ID, cert.ID, target.ID)
	if err != nil {
		t.Fatalf("DeployAndVerify failed: %v", err)
	}
	if !verifyRes.Passed {
		t.Errorf("verification failed: %v", verifyRes.Errors)
	}

	activeCert, _ := st.GetCertificate(tenant.ID, cert.ID)
	if activeCert.Status != models.StateActive {
		t.Errorf("expected Active cert, got %s", activeCert.Status)
	}

	// 10. CBOM Generation
	cbom, err := inventory.GenerateCBOM(tenant.ID, []*models.Certificate{activeCert})
	if err != nil {
		t.Fatalf("CBOM generation failed: %v", err)
	}
	if len(cbom.Components) != 1 {
		t.Errorf("expected 1 CBOM component, got %d", len(cbom.Components))
	}

	// 11. Merkle Audit Ledger Integrity Verification
	events, err := st.ListAuditEvents(tenant.ID, 100)
	if err != nil {
		t.Fatalf("ListAuditEvents failed: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected audit events to be recorded")
	}

	auditReport := audit.VerifyLedger(tenant.ID, events, nil)
	if !auditReport.HashChainValid {
		t.Errorf("audit hash chain validation failed: %v", auditReport.TamperedEvents)
	}
	if auditReport.GapsDetected != 0 {
		t.Errorf("audit gaps detected: %d", auditReport.GapsDetected)
	}

	_ = csrPEM
}
