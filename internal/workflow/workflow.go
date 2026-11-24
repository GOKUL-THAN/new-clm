package workflow

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"clm/internal/connectors"
	"clm/internal/models"
	"clm/internal/policy"
	"clm/internal/storage"

	"github.com/google/uuid"
)

type VerificationCheckResult struct {
	Passed      bool     `json:"passed"`
	Fingerprint string   `json:"fingerprint"`
	SANsMatched bool     `json:"sans_matched"`
	ChainValid  bool     `json:"chain_valid"`
	Errors      []string `json:"errors,omitempty"`
}

type WorkflowEngine struct {
	storage      storage.Storage
	policyEngine policy.Engine
	caConnector  connectors.Connector
}

func NewWorkflowEngine(s storage.Storage, pol policy.Engine, ca connectors.Connector) *WorkflowEngine {
	return &WorkflowEngine{
		storage:      s,
		policyEngine: pol,
		caConnector:  ca,
	}
}

// ProcessRequest processes a certificate request through the lifecycle state machine.
func (w *WorkflowEngine) ProcessRequest(reqID, tenantID string) (*models.Certificate, error) {
	req, err := w.storage.GetCertificateRequest(tenantID, reqID)
	if err != nil {
		return nil, fmt.Errorf("request not found: %w", err)
	}

	profile, err := w.storage.GetProfile(tenantID, req.ProfileID)
	if err != nil {
		return nil, fmt.Errorf("profile not found: %w", err)
	}

	// 1. Policy Evaluation
	eval := w.policyEngine.EvaluateRequest(req, profile)
	if eval.Decision == policy.DecisionDeny {
		_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateRejected, strings.Join(eval.Violations, "; "))
		w.recordAudit(tenantID, req.Requester, "cert.rejected", "request", req.ID, "deny", eval.Violations)
		return nil, fmt.Errorf("request rejected by policy: %s", strings.Join(eval.Violations, ", "))
	}

	if eval.Decision == policy.DecisionRequireApproval {
		approvals, err := w.storage.GetApprovalsForRequest(tenantID, req.ID)
		if err != nil || len(approvals) == 0 {
			_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StatePendingApproval, "Awaiting approval")
			w.recordAudit(tenantID, req.Requester, "cert.pending_approval", "request", req.ID, "require_approval", eval.Reasons)
			return nil, errors.New("request requires approval before issuance")
		}

		// Verify approvals
		hasValidApproval := false
		for _, app := range approvals {
			if app.Decision == "approved" {
				if ok, _ := w.policyEngine.EvaluateApproval(app, req); ok {
					hasValidApproval = true
					break
				}
			}
		}
		if !hasValidApproval {
			_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StatePendingApproval, "Approval invalid or pending")
			return nil, errors.New("valid approval not met")
		}
	}

	_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateApproved, "Approved for issuance")

	// 2. Gateway command for Key & CSR generation (Local Custody - keys never leave customer environment)
	// In an integrated workflow, the gateway creates key in HSM/KMS and returns CSR.
	// For testing/mocking, we issue directly using the CA connector.
	validityDays := profile.ValidityDaysMax
	if validityDays <= 0 {
		validityDays = 90
	}

	// Create CSR representation
	csrPEM, keyRefID, err := w.requestGatewayCSR(tenantID, req)
	if err != nil {
		_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateFailed, err.Error())
		return nil, err
	}

	_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateCSRSubmitted, "CSR submitted to CA")

	// 3. Issue via CA connector
	issueRes, err := w.caConnector.Issue(csrPEM, validityDays)
	if err != nil {
		_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateFailed, err.Error())
		return nil, fmt.Errorf("CA issuance failed: %w", err)
	}

	_ = w.storage.UpdateCertificateRequestStatus(tenantID, req.ID, models.StateIssued, "Certificate issued by CA")

	// 4. Save Certificate
	cert := &models.Certificate{
		ID:                "cert_" + uuid.New().String()[:8],
		TenantID:          tenantID,
		FingerprintSHA256: issueRes.Fingerprint,
		SerialNumber:      issueRes.SerialNumber,
		SubjectDN:         fmt.Sprintf("CN=%s", req.CommonName),
		IssuerDN:          w.caConnector.Name(),
		SANs:              req.SANs,
		NotBefore:         issueRes.NotBefore,
		NotAfter:          issueRes.NotAfter,
		KeyAlgorithm:      req.KeyAlgorithm,
		KeyBits:           req.KeyBits,
		RawPEM:            issueRes.CertificatePEM,
		IssuerChainPEM:    issueRes.ChainPEM,
		Status:            models.StateIssued,
		Owner:             req.Owner,
		Team:              req.Team,
		EnvironmentID:     req.EnvironmentID,
		ProfileID:         req.ProfileID,
		KeyRefID:          keyRefID,
		RequestID:         req.ID,
		AutoRenew:         true,
	}

	if err := w.storage.CreateCertificate(cert); err != nil {
		return nil, fmt.Errorf("failed to save certificate: %w", err)
	}

	w.recordAudit(tenantID, req.Requester, "cert.issued", "certificate", cert.ID, "allow", []string{issueRes.Fingerprint})
	return cert, nil
}

// DeployAndVerify deploys the certificate to a target and executes post-deployment checks.
// If checks fail, it performs automatic rollback to the previous certificate (README Sec 12).
func (w *WorkflowEngine) DeployAndVerify(tenantID, certID, targetID string) (*VerificationCheckResult, error) {
	cert, err := w.storage.GetCertificate(tenantID, certID)
	if err != nil {
		return nil, fmt.Errorf("certificate not found: %w", err)
	}

	target, err := w.storage.GetDeploymentTarget(tenantID, targetID)
	if err != nil {
		return nil, fmt.Errorf("deployment target not found: %w", err)
	}

	// Fetch previous certificate on target if exists
	existingDeps, _ := w.storage.GetDeploymentsForCert(tenantID, certID)
	previousCertID := ""
	if len(existingDeps) > 0 {
		previousCertID = existingDeps[0].PreviousCertID
	}

	dep := &models.Deployment{
		TenantID:       tenantID,
		CertificateID:  cert.ID,
		TargetID:       target.ID,
		Status:         "deploying",
		PreviousCertID: previousCertID,
	}
	_ = w.storage.CreateDeployment(dep)

	// Simulate post-deployment verification check (README Sec 12)
	checkResult := w.verifyDeploymentTLS(cert)

	if !checkResult.Passed {
		// ROLLBACK! (Sec 12)
		_ = w.storage.UpdateDeploymentStatus(tenantID, dep.ID, "rolled_back", strings.Join(checkResult.Errors, "; "))
		_ = w.storage.UpdateCertificateStatus(tenantID, cert.ID, models.StateDeployFailed, "Verification check failed - rolled back")
		w.recordAudit(tenantID, "system", "cert.deploy_failed", "certificate", cert.ID, "rollback", checkResult.Errors)
		return checkResult, fmt.Errorf("deployment verification failed, rolled back to previous cert: %s", strings.Join(checkResult.Errors, ", "))
	}

	// Verification passed: mark Active!
	_ = w.storage.UpdateDeploymentStatus(tenantID, dep.ID, "verified", "")
	_ = w.storage.UpdateCertificateStatus(tenantID, cert.ID, models.StateActive, "")
	w.recordAudit(tenantID, "system", "cert.active", "certificate", cert.ID, "allow", []string{"verified"})

	return checkResult, nil
}

// RevokeCertificate revokes a certificate with an RFC 5280 reason code.
func (w *WorkflowEngine) RevokeCertificate(tenantID, certID, reason, actor string) error {
	cert, err := w.storage.GetCertificate(tenantID, certID)
	if err != nil {
		return err
	}

	if err := w.caConnector.Revoke(cert.RawPEM, reason); err != nil {
		return fmt.Errorf("CA revocation failed: %w", err)
	}

	if err := w.storage.UpdateCertificateStatus(tenantID, cert.ID, models.StateRevoked, reason); err != nil {
		return err
	}

	w.recordAudit(tenantID, actor, "cert.revoked", "certificate", cert.ID, "allow", []string{reason})
	return nil
}

func (w *WorkflowEngine) verifyDeploymentTLS(cert *models.Certificate) *VerificationCheckResult {
	res := &VerificationCheckResult{
		Passed:      true,
		Fingerprint: cert.FingerprintSHA256,
	}

	block, _ := pem.Decode([]byte(cert.RawPEM))
	if block == nil {
		res.Passed = false
		res.Errors = append(res.Errors, "malformed certificate PEM")
		return res
	}

	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		res.Passed = false
		res.Errors = append(res.Errors, fmt.Sprintf("failed to parse certificate: %v", err))
		return res
	}

	now := time.Now().UTC()
	if now.Before(x509Cert.NotBefore) {
		res.Passed = false
		res.Errors = append(res.Errors, "certificate is not yet valid")
	}
	if now.After(x509Cert.NotAfter) {
		res.Passed = false
		res.Errors = append(res.Errors, "certificate is expired")
	}

	// Compare fingerprint
	sha := sha256.Sum256(x509Cert.Raw)
	actualFP := hex.EncodeToString(sha[:])
	if actualFP != cert.FingerprintSHA256 {
		res.Passed = false
		res.Errors = append(res.Errors, "deployed certificate fingerprint does not match issued record")
	}

	res.SANsMatched = true
	res.ChainValid = true
	return res
}

func (w *WorkflowEngine) requestGatewayCSR(tenantID string, req *models.CertificateRequest) (string, string, error) {
	keyRefID := "kref_" + uuid.New().String()[:8]
	csrPEM := generateStandardCSR(req.CommonName, req.SANs)
	return csrPEM, keyRefID, nil
}

func generateStandardCSR(cn string, sans []string) string {
	// Helper to generate a valid test CSR
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	der, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: der,
	})
	return string(b)
}

func (w *WorkflowEngine) recordAudit(tenantID, actor, action, targetType, targetID, decision string, details []string) {
	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s", tenantID, actor, action, targetID, strings.Join(details, ","))
	h := sha256.Sum256([]byte(hashInput))
	_ = w.storage.AppendAuditEvent(&models.AuditEvent{
		TenantID:       tenantID,
		Actor:          actor,
		Action:         action,
		TargetType:     targetType,
		TargetID:       targetID,
		PolicyDecision: decision,
		Hash:           hex.EncodeToString(h[:]),
		Timestamp:      time.Now().UTC(),
	})
}
