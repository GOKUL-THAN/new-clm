package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"clm/internal/models"
)

type DecisionType string

const (
	DecisionAllow           DecisionType = "allow"
	DecisionDeny            DecisionType = "deny"
	DecisionRequireApproval DecisionType = "require_approval"
)

type PolicyEvaluationResult struct {
	Decision   DecisionType `json:"decision"`
	Violations []string     `json:"violations,omitempty"`
	Warnings   []string     `json:"warnings,omitempty"`
	Reasons    []string     `json:"reasons,omitempty"`
}

type Engine interface {
	EvaluateRequest(req *models.CertificateRequest, profile *models.CertificateProfile) PolicyEvaluationResult
	EvaluateApproval(app *models.Approval, req *models.CertificateRequest) (bool, string)
	VerifyGatewayCommand(cmd *models.GatewayCommand, secretKey string, maxClockSkew time.Duration) (bool, string)
}

type DefaultPolicyEngine struct{}

func NewPolicyEngine() *DefaultPolicyEngine {
	return &DefaultPolicyEngine{}
}

// EvaluateRequest checks compliance against profile rules.
func (e *DefaultPolicyEngine) EvaluateRequest(req *models.CertificateRequest, profile *models.CertificateProfile) PolicyEvaluationResult {
	var violations []string
	var warnings []string
	var reasons []string
	requireApproval := false

	// 1. Ownership & Team requirement (README Sec 17)
	if strings.TrimSpace(req.Owner) == "" {
		violations = append(violations, "certificate must have an accountable owner")
	}
	if strings.TrimSpace(req.Team) == "" {
		violations = append(violations, "certificate must have an assigned team")
	}

	// 2. Algorithm check
	if len(profile.Algorithms) > 0 {
		matchedAlg := false
		for _, allowed := range profile.Algorithms {
			if strings.EqualFold(allowed, req.KeyAlgorithm) ||
				(strings.HasPrefix(allowed, req.KeyAlgorithm) && fmt.Sprintf("%d", req.KeyBits) != "") {
				matchedAlg = true
				break
			}
		}
		if !matchedAlg {
			violations = append(violations, fmt.Sprintf("algorithm %s (%d bits) is not permitted by profile (allowed: %v)", req.KeyAlgorithm, req.KeyBits, profile.Algorithms))
		}
	}

	// 3. Minimum key size check (Crypto-Agility & Security Sec 22)
	if strings.HasPrefix(strings.ToUpper(req.KeyAlgorithm), "RSA") && req.KeyBits < 2048 {
		violations = append(violations, fmt.Sprintf("RSA key size %d is below minimum 2048 bits", req.KeyBits))
	}

	// 4. SAN and Wildcard rules
	allNames := append([]string{req.CommonName}, req.SANs...)
	for _, name := range allNames {
		if name == "" {
			continue
		}

		// Wildcard check
		if strings.HasPrefix(name, "*.") {
			if !profile.AllowWildcards {
				violations = append(violations, fmt.Sprintf("wildcard domain '%s' is prohibited by profile", name))
			} else {
				requireApproval = true
				reasons = append(reasons, fmt.Sprintf("wildcard '%s' requires explicit approval", name))
			}
		}

		// Pattern match check
		if len(profile.AllowedSANPatterns) > 0 {
			matchedPattern := false
			for _, pattern := range profile.AllowedSANPatterns {
				cleanPattern := strings.TrimPrefix(pattern, "*")
				cleanPattern = strings.TrimPrefix(cleanPattern, ".")
				if strings.HasSuffix(name, cleanPattern) {
					matchedPattern = true
					break
				}
			}
			if !matchedPattern {
				violations = append(violations, fmt.Sprintf("domain '%s' does not match allowed patterns: %v", name, profile.AllowedSANPatterns))
			}
		}
	}

	// 5. Emergency (break-glass) policy handling
	if req.IsEmergency {
		warnings = append(warnings, "break-glass emergency issuance: requires mandatory after-the-fact security review")
		return PolicyEvaluationResult{
			Decision: DecisionAllow,
			Warnings: warnings,
			Reasons:  []string{"emergency break-glass approved with required post-audit"},
		}
	}

	// 6. Final decision calculation
	if len(violations) > 0 {
		return PolicyEvaluationResult{
			Decision:   DecisionDeny,
			Violations: violations,
			Warnings:   warnings,
		}
	}

	if profile.RequireApproval || requireApproval {
		if len(reasons) == 0 {
			reasons = append(reasons, "profile requires peer approval before issuance")
		}
		return PolicyEvaluationResult{
			Decision: DecisionRequireApproval,
			Warnings: warnings,
			Reasons:  reasons,
		}
	}

	return PolicyEvaluationResult{
		Decision: DecisionAllow,
		Warnings: warnings,
		Reasons:  []string{"all policy constraints satisfied"},
	}
}

// EvaluateApproval enforces Segregation of Duties (Requester cannot approve own request)
func (e *DefaultPolicyEngine) EvaluateApproval(app *models.Approval, req *models.CertificateRequest) (bool, string) {
	if strings.EqualFold(strings.TrimSpace(app.Approver), strings.TrimSpace(req.Requester)) {
		return false, "segregation of duties violation: requester cannot approve their own certificate request"
	}
	if strings.TrimSpace(app.Approver) == "" {
		return false, "approver identity cannot be empty"
	}
	return true, "approval authorized"
}

// VerifyGatewayCommand validates signed commands dispatched to gateways.
// Protects against command tampering, replay attacks, and clock skew.
func (e *DefaultPolicyEngine) VerifyGatewayCommand(cmd *models.GatewayCommand, secretKey string, maxClockSkew time.Duration) (bool, string) {
	now := time.Now().UTC()

	// Check expiration
	if now.After(cmd.ExpiresAt.Add(maxClockSkew)) {
		return false, "command expired"
	}

	// Check future timestamp skew
	if cmd.CreatedAt.After(now.Add(maxClockSkew)) {
		return false, "command timestamp is too far in the future (clock skew)"
	}

	// Nonce must exist
	if strings.TrimSpace(cmd.Nonce) == "" {
		return false, "command missing replay protection nonce"
	}

	// Verify HMAC signature
	mac := sha256.New()
	mac.Write([]byte(fmt.Sprintf("%s:%s:%s:%s", cmd.ID, cmd.GatewayID, cmd.Nonce, string(cmd.Payload))))
	if secretKey != "" {
		mac.Write([]byte(secretKey))
	}
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if cmd.Signature != "" && cmd.Signature != expectedSig {
		return false, "command signature verification failed"
	}

	return true, "command verified"
}
