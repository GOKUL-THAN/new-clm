package models

import (
	"encoding/json"
	"time"
)

// CertificateLifecycleState represents the state of a certificate or request.
type CertificateLifecycleState string

const (
	StateRequested       CertificateLifecycleState = "Requested"
	StatePendingApproval CertificateLifecycleState = "PendingApproval"
	StateApproved        CertificateLifecycleState = "Approved"
	StateRejected        CertificateLifecycleState = "Rejected"
	StateExpiredRequest  CertificateLifecycleState = "Expired_Request"
	StateKeyGenerated    CertificateLifecycleState = "KeyGenerated"
	StateCSRSubmitted    CertificateLifecycleState = "CSRSubmitted"
	StateValidatingDomain CertificateLifecycleState = "ValidatingDomain"
	StateIssued          CertificateLifecycleState = "Issued"
	StateDeployed        CertificateLifecycleState = "Deployed"
	StateVerified        CertificateLifecycleState = "Verified"
	StateActive          CertificateLifecycleState = "Active"
	StateRenewalDue      CertificateLifecycleState = "RenewalDue"
	StateRenewalFailed   CertificateLifecycleState = "RenewalFailed"
	StateDeployFailed    CertificateLifecycleState = "DeployFailed"
	StateSuspended       CertificateLifecycleState = "Suspended"
	StateCompromised     CertificateLifecycleState = "Compromised"
	StateSuperseded      CertificateLifecycleState = "Superseded"
	StateRevoked         CertificateLifecycleState = "Revoked"
	StateExpired         CertificateLifecycleState = "Expired"
	StateArchived        CertificateLifecycleState = "Archived"
	StateFailed          CertificateLifecycleState = "Failed"
)

// Tenant defines the top-level isolation boundary.
type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"` // active, suspended
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Environment represents a cloud account, VPC, cluster, or on-prem DC.
type Environment struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"` // aws, azure, gcp, onprem, k8s
	Region    string    `json:"region"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Gateway represents an in-VPC Satellite Gateway daemon.
type Gateway struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EnvironmentID string    `json:"environment_id"`
	Name          string    `json:"name"`
	Status        string    `json:"status"` // online, offline, degraded
	Version       string    `json:"version"`
	KeystoreType  string    `json:"keystore_type"` // pkcs11, kms, software
	Fingerprint   string    `json:"fingerprint"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	PolicyGrace   string    `json:"policy_grace"`
	CreatedAt     time.Time `json:"created_at"`
}

// EnrollmentToken for bootstrapping new gateways.
type EnrollmentToken struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EnvironmentID string    `json:"environment_id"`
	Token         string    `json:"token"`
	Used          bool      `json:"used"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// KeyReference points to a key inside the customer's HSM/KMS.
type KeyReference struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	GatewayID     string    `json:"gateway_id"`
	KeyStore      string    `json:"key_store"`
	KeyAlias      string    `json:"key_alias"`
	Algorithm     string    `json:"algorithm"`
	Bits          int       `json:"bits"`
	NonExportable bool      `json:"non_exportable"`
	CreatedAt     time.Time `json:"created_at"`
}

// CertificateProfile templates what may be issued.
type CertificateProfile struct {
	ID                    string   `json:"id"`
	TenantID              string   `json:"tenant_id"`
	Name                  string   `json:"name"`
	Description           string   `json:"description"`
	AllowedCAs            []string `json:"allowed_cas"`
	Algorithms            []string `json:"algorithms"`
	ValidityDaysMax       int      `json:"validity_days_max"`
	AllowedSANPatterns    []string `json:"allowed_san_patterns"`
	AllowWildcards        bool     `json:"allow_wildcards"`
	RequireApproval       bool     `json:"require_approval"`
	ApproverRoles         []string `json:"approver_roles"`
	RenewalThresholdDays  int      `json:"renewal_threshold_days"`
	CAAEnforce            bool     `json:"caa_enforce"`
	NonExportableRequired bool     `json:"non_exportable_required"`
	CreatedAt             time.Time `json:"created_at"`
}

// Policy defines governance rules evaluated before issuance or renewal.
type Policy struct {
	ID          string          `json:"id"`
	TenantID    string          `json:"tenant_id"`
	Name        string          `json:"name"`
	Version     int             `json:"version"`
	Rules       json.RawMessage `json:"rules"`
	IsActive    bool            `json:"is_active"`
	SignedHash  string          `json:"signed_hash"`
	CreatedAt   time.Time       `json:"created_at"`
}

// CertificateRequest represents intent to obtain or renew a certificate.
type CertificateRequest struct {
	ID           string                    `json:"id"`
	TenantID     string                    `json:"tenant_id"`
	ProfileID    string                    `json:"profile_id"`
	EnvironmentID string                   `json:"environment_id"`
	CommonName   string                    `json:"common_name"`
	SANs         []string                  `json:"sans"`
	KeyAlgorithm string                    `json:"key_algorithm"`
	KeyBits      int                       `json:"key_bits"`
	Owner        string                    `json:"owner"`
	Team         string                    `json:"team"`
	Status       CertificateLifecycleState `json:"status"`
	Reason       string                    `json:"reason"`
	Requester    string                    `json:"requester"`
	IsEmergency  bool                      `json:"is_emergency"`
	CreatedAt    time.Time                 `json:"created_at"`
	UpdatedAt    time.Time                 `json:"updated_at"`
}

// Approval records an approver's decision on a request.
type Approval struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	RequestID string    `json:"request_id"`
	Approver  string    `json:"approver"`
	Decision  string    `json:"decision"` // approved, rejected
	Comments  string    `json:"comments"`
	CreatedAt time.Time `json:"created_at"`
}

// Certificate represents an issued X.509 certificate record.
type Certificate struct {
	ID                string                    `json:"id"`
	TenantID          string                    `json:"tenant_id"`
	FingerprintSHA256 string                    `json:"fingerprint_sha256"`
	SerialNumber      string                    `json:"serial_number"`
	SubjectDN         string                    `json:"subject_dn"`
	IssuerDN          string                    `json:"issuer_dn"`
	SANs              []string                  `json:"sans"`
	NotBefore         time.Time                 `json:"not_before"`
	NotAfter          time.Time                 `json:"not_after"`
	KeyAlgorithm      string                    `json:"key_algorithm"`
	KeyBits           int                       `json:"key_bits"`
	RawPEM            string                    `json:"raw_pem"`
	IssuerChainPEM    string                    `json:"issuer_chain_pem"`
	Status            CertificateLifecycleState `json:"status"`
	Owner             string                    `json:"owner"`
	Team              string                    `json:"team"`
	EnvironmentID     string                    `json:"environment_id"`
	ProfileID         string                    `json:"profile_id"`
	KeyRefID          string                    `json:"key_ref_id"`
	RequestID         string                    `json:"request_id"`
	RevocationReason  string                    `json:"revocation_reason,omitempty"`
	RiskScore         int                       `json:"risk_score"`
	RiskFactors       []string                  `json:"risk_factors"`
	AutoRenew         bool                      `json:"auto_renew"`
	CreatedAt         time.Time                 `json:"created_at"`
	UpdatedAt         time.Time                 `json:"updated_at"`
}

// DeploymentTarget defines where a certificate is deployed.
type DeploymentTarget struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EnvironmentID string    `json:"environment_id"`
	GatewayID     string    `json:"gateway_id"`
	Name          string    `json:"name"`
	Type          string    `json:"type"` // nginx, apache, k8s_secret, envoy, elb, etc.
	HostAddress   string    `json:"host_address"`
	Port          int       `json:"port"`
	ConfigJSON    string    `json:"config_json"`
	CreatedAt     time.Time `json:"created_at"`
}

// Deployment tracks certificate deployment to a target.
type Deployment struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	CertificateID  string    `json:"certificate_id"`
	TargetID       string    `json:"target_id"`
	Status         string    `json:"status"` // pending, deployed, verified, failed, rolled_back
	ErrorMessage   string    `json:"error_message,omitempty"`
	PreviousCertID string    `json:"previous_cert_id,omitempty"`
	DeployedAt     time.Time `json:"deployed_at"`
	VerifiedAt     time.Time `json:"verified_at"`
}

// AuditEvent represents a tamper-evident event in the append-only ledger.
type AuditEvent struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Sequence       int64     `json:"sequence"`
	Actor          string    `json:"actor"`
	Action         string    `json:"action"`
	TargetType     string    `json:"target_type"`
	TargetID       string    `json:"target_id"`
	BeforeHash     string    `json:"before_hash"`
	AfterHash      string    `json:"after_hash"`
	PolicyDecision string    `json:"policy_decision"`
	PrevHash       string    `json:"prev_hash"`
	Hash           string    `json:"hash"`
	Timestamp      time.Time `json:"timestamp"`
}

// AuditTreeHead represents a periodic root of the Merkle tree.
type AuditTreeHead struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	TreeSize       int64     `json:"tree_size"`
	RootHash       string    `json:"root_hash"`
	Signature      string    `json:"signature"`
	TimestampToken string    `json:"timestamp_token"` // RFC 3161 proof
	CreatedAt      time.Time `json:"created_at"`
}

// DiscoveryScan tracks a network or cloud discovery job.
type DiscoveryScan struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	EnvironmentID  string    `json:"environment_id"`
	GatewayID      string    `json:"gateway_id"`
	CIDRs          []string  `json:"cidrs"`
	Ports          []int     `json:"ports"`
	Status         string    `json:"status"` // pending, running, completed, failed
	TargetsScanned int       `json:"targets_scanned"`
	CertsFound     int       `json:"certs_found"`
	StartedAt      time.Time `json:"started_at"`
	CompletedAt    time.Time `json:"completed_at"`
}

// DiscoveryFinding records an identified certificate endpoint from scans.
type DiscoveryFinding struct {
	ID                string    `json:"id"`
	TenantID          string    `json:"tenant_id"`
	ScanID            string    `json:"scan_id"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	Host              string    `json:"host"`
	Port              int       `json:"port"`
	SubjectDN         string    `json:"subject_dn"`
	IssuerDN          string    `json:"issuer_dn"`
	SANs              []string  `json:"sans"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	KeyAlgorithm      string    `json:"key_algorithm"`
	KeyBits           int       `json:"key_bits"`
	IsManaged         bool      `json:"is_managed"`
	RiskScore         int       `json:"risk_score"`
	RiskFactors       []string  `json:"risk_factors"`
	Status            string    `json:"status"` // unmanaged, claimed, ignored
	CreatedAt         time.Time `json:"created_at"`
}

// WebhookSubscription for outbound event notifications.
type WebhookSubscription struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret"`
	Events    []string  `json:"events"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// GatewayCommand represents an instruction dispatched from SaaS to Gateway.
type GatewayCommand struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	GatewayID     string          `json:"gateway_id"`
	Type          string          `json:"type"` // generate_csr, deploy_cert, rollback, run_discovery
	Payload       json.RawMessage `json:"payload"`
	Nonce         string          `json:"nonce"`
	ExpiresAt     time.Time       `json:"expires_at"`
	Signature     string          `json:"signature"`
	Status        string          `json:"status"` // pending, acknowledged, completed, failed
	ResultPayload json.RawMessage `json:"result_payload,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}
