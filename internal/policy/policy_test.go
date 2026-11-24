package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"clm/internal/models"
)

func TestPolicyEngineEvaluation(t *testing.T) {
	eng := NewPolicyEngine()

	profile := &models.CertificateProfile{
		AllowedCAs:         []string{"lets-encrypt"},
		Algorithms:         []string{"RSA-2048", "ECDSA-P256"},
		ValidityDaysMax:    90,
		AllowedSANPatterns: []string{".acme.com"},
		AllowWildcards:     false,
		RequireApproval:    true,
	}

	// 1. Valid request requiring approval
	reqValid := &models.CertificateRequest{
		CommonName:   "app.acme.com",
		SANs:         []string{"app.acme.com"},
		KeyAlgorithm: "RSA-2048",
		KeyBits:      2048,
		Owner:        "alice",
		Team:         "payments",
		Requester:    "alice",
	}
	resValid := eng.EvaluateRequest(reqValid, profile)
	if resValid.Decision != DecisionRequireApproval {
		t.Errorf("expected DecisionRequireApproval, got %s", resValid.Decision)
	}

	// 2. Missing Owner and Team
	reqNoOwner := &models.CertificateRequest{
		CommonName:   "test.acme.com",
		KeyAlgorithm: "RSA-2048",
		KeyBits:      2048,
	}
	resNoOwner := eng.EvaluateRequest(reqNoOwner, profile)
	if resNoOwner.Decision != DecisionDeny {
		t.Errorf("expected DecisionDeny for missing owner, got %s", resNoOwner.Decision)
	}

	// 3. Prohibited Wildcard
	reqWildcard := &models.CertificateRequest{
		CommonName:   "*.acme.com",
		KeyAlgorithm: "RSA-2048",
		KeyBits:      2048,
		Owner:        "bob",
		Team:         "infra",
		Requester:    "bob",
	}
	resWildcard := eng.EvaluateRequest(reqWildcard, profile)
	if resWildcard.Decision != DecisionDeny {
		t.Errorf("expected DecisionDeny for disallowed wildcard, got %s", resWildcard.Decision)
	}

	// 4. Weak RSA key (< 2048)
	reqWeak := &models.CertificateRequest{
		CommonName:   "weak.acme.com",
		KeyAlgorithm: "RSA",
		KeyBits:      1024,
		Owner:        "carol",
		Team:         "security",
		Requester:    "carol",
	}
	resWeak := eng.EvaluateRequest(reqWeak, profile)
	if resWeak.Decision != DecisionDeny {
		t.Errorf("expected DecisionDeny for weak key, got %s", resWeak.Decision)
	}

	// 5. Segregation of Duties
	appSelf := &models.Approval{
		Approver: "alice",
	}
	ok, msg := eng.EvaluateApproval(appSelf, reqValid)
	if ok {
		t.Errorf("expected SoD failure for self-approval, but got allowed: %s", msg)
	}

	appOther := &models.Approval{
		Approver: "charlie",
	}
	ok, _ = eng.EvaluateApproval(appOther, reqValid)
	if !ok {
		t.Errorf("expected third-party approval to be authorized")
	}

	// 6. Gateway command verification
	now := time.Now().UTC()
	cmd := &models.GatewayCommand{
		ID:        "cmd_1",
		GatewayID: "gw_1",
		Nonce:     "nonce_123",
		Payload:   []byte(`{"action":"deploy"}`),
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
	mac := sha256.New()
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", cmd.ID, cmd.GatewayID, cmd.Nonce, string(cmd.Payload))))
	mac.Write([]byte("secret_key"))
	cmd.Signature = hex.EncodeToString(mac.Sum(nil))

	verified, verifyMsg := eng.VerifyGatewayCommand(cmd, "secret_key", 30*time.Second)
	if !verified {
		t.Fatalf("gateway command verification failed: %s", verifyMsg)
	}
}
