package models

import (
	"encoding/json"
	"time"
)

// CertificateLifecycleState represents the state of a certificate or request.
type CertificateLifecycleState string

const (
	StateRequested        CertificateLifecycleState = "Requested"
	StatePendingApproval  CertificateLifecycleState = "PendingApproval"
	StateApproved         CertificateLifecycleState = "Approved"
	StateRejected         CertificateLifecycleState = "Rejected"
	StateExpiredRequest   CertificateLifecycleState = "Expired_Request"
	StateKeyGenerated     CertificateLifecycleState = "KeyGenerated"
	StateCSRSubmitted     CertificateLifecycleState = "CSRSubmitted"
	StateValidatingDomain CertificateLifecycleState = "ValidatingDomain"
	StateIssued           CertificateLifecycleState = "Issued"
	StateDeployed         CertificateLifecycleState = "Deployed"
	StateVerified         CertificateLifecycleState = "Verified"
	StateActive           CertificateLifecycleState = "Active"
	StateRenewalDue       CertificateLifecycleState = "RenewalDue"
	StateRenewalFailed    CertificateLifecycleState = "RenewalFailed"
	StateDeployFailed     CertificateLifecycleState = "DeployFailed"
	StateSuspended        CertificateLifecycleState = "Suspended"
	StateCompromised      CertificateLifecycleState = "Compromised"
	StateSuperseded       CertificateLifecycleState = "Superseded"
	StateRevoked          CertificateLifecycleState = "Revoked"
	StateExpired          CertificateLifecycleState = "Expired"
	StateArchived         CertificateLifecycleState = "Archived"
	StateFailed           CertificateLifecycleState = "Failed"
)

// --- Module 1 & 3: Super Admin, Organization & Tenant Management ---

type Organization struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Slug               string    `json:"slug"`
	Domain             string    `json:"domain"`
	Status             string    `json:"status"` // pending_verification, active, suspended, deactivated
	VerificationStatus string    `json:"verification_status"` // verified, unverified, in_review, rejected
	RiskScore          int       `json:"risk_score"`
	Tier               string    `json:"tier"` // enterprise, standard, trial
	OwnerEmail         string    `json:"owner_email"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type OrganizationDocument struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Type       string    `json:"type"` // articles_of_incorporation, tax_id, domain_proof
	FileName   string    `json:"file_name"`
	Status     string    `json:"status"` // approved, pending, rejected
	UploadedAt time.Time `json:"uploaded_at"`
}

type Tenant struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"` // active, suspended, maintenance
	Region    string    `json:"region"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

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

// --- Module 2 & 14: Subscription, Billing & Usage Metering ---

type SubscriptionPlan struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Slug            string   `json:"slug"`
	PriceMonthly    float64  `json:"price_monthly"`
	PriceAnnual     float64  `json:"price_annual"`
	MaxCertificates int      `json:"max_certificates"`
	MaxGateways     int      `json:"max_gateways"`
	MaxUsers        int      `json:"max_users"`
	Features        []string `json:"features"`
}

type Subscription struct {
	ID                 string    `json:"id"`
	OrgID              string    `json:"org_id"`
	PlanID             string    `json:"plan_id"`
	Status             string    `json:"status"` // active, trialing, past_due, canceled
	CurrentPeriodStart time.Time `json:"current_period_start"`
	CurrentPeriodEnd   time.Time `json:"current_period_end"`
	CancelAtPeriodEnd  bool      `json:"cancel_at_period_end"`
}

type Invoice struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	InvoiceNumber string    `json:"invoice_number"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	Status        string    `json:"status"` // paid, open, void, uncollectible
	DueDate       time.Time `json:"due_date"`
	PaidAt        time.Time `json:"paid_at,omitempty"`
}

type Payment struct {
	ID            string    `json:"id"`
	OrgID         string    `json:"org_id"`
	InvoiceID     string    `json:"invoice_id"`
	Amount        float64   `json:"amount"`
	Currency      string    `json:"currency"`
	Gateway       string    `json:"gateway"` // stripe, adyen, bank_transfer
	Status        string    `json:"status"` // succeeded, failed, refunded
	TransactionID string    `json:"transaction_id"`
	CreatedAt     time.Time `json:"created_at"`
}

type UsageRecord struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	Metric     string    `json:"metric"` // certificates_active, discovery_scans, gateway_hours, api_requests
	Quantity   int64     `json:"quantity"`
	Unit       string    `json:"unit"`
	RecordedAt time.Time `json:"recorded_at"`
}

// --- Module 4 & 5: Users, Teams, RBAC & SSO ---

type Department struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	LeadEmail string    `json:"lead_email"`
	CreatedAt time.Time `json:"created_at"`
}

type Team struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	DepartmentID string    `json:"department_id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	CreatedAt    time.Time `json:"created_at"`
}

type User struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Email        string    `json:"email"`
	FullName     string    `json:"full_name"`
	Role         string    `json:"role"` // super_admin, tenant_admin, pki_admin, approver, requester, auditor
	DepartmentID string    `json:"department_id,omitempty"`
	TeamID       string    `json:"team_id,omitempty"`
	Status       string    `json:"status"` // active, invited, suspended
	MFAEnabled   bool      `json:"mfa_enabled"`
	LastLoginAt  time.Time `json:"last_login_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type IdentityProvider struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"` // keycloak, entra_id, okta, google, saml2
	Domain      string    `json:"domain"`
	IssuerURL   string    `json:"issuer_url"`
	ClientID    string    `json:"client_id"`
	SCIMEnabled bool      `json:"scim_enabled"`
	Status      string    `json:"status"` // active, testing, failed
	CreatedAt   time.Time `json:"created_at"`
}

// --- Module 6: Multi-Cloud Accounts (AWS, Azure, GCP) ---

type CloudAccount struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Provider     string    `json:"provider"` // aws, azure, gcp, cloudflare
	AccountID    string    `json:"account_id"`
	Name         string    `json:"name"`
	RoleARN      string    `json:"role_arn"`
	Region       string    `json:"region"`
	Status       string    `json:"status"` // connected, sync_failed, permissions_drift
	CertsCount   int       `json:"certs_count"`
	LastSyncAt   time.Time `json:"last_sync_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// --- Module 7: Satellite Gateway Fleet ---

type Gateway struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EnvironmentID string    `json:"environment_id"`
	Name          string    `json:"name"`
	Status        string    `json:"status"` // online, offline, degraded
	Version       string    `json:"version"`
	KeystoreType  string    `json:"keystore_type"` // pkcs11, kms, software
	Fingerprint   string    `json:"fingerprint"`
	CPULoad       float64   `json:"cpu_load"`
	MemoryMB      int64     `json:"memory_mb"`
	LastSeenAt    time.Time `json:"last_seen_at"`
	PolicyGrace   string    `json:"policy_grace"`
	CreatedAt     time.Time `json:"created_at"`
}

type EnrollmentToken struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	EnvironmentID string    `json:"environment_id"`
	Token         string    `json:"token"`
	Used          bool      `json:"used"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
}

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

// --- Module 8: Deployment Jobs ---

type DeploymentJob struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"`
	CertificateID string    `json:"certificate_id"`
	TargetID      string    `json:"target_id"`
	Strategy      string    `json:"strategy"` // canary, blue_green, rolling, direct
	Status        string    `json:"status"` // queued, executing, verified, failed, rolled_back
	Progress      int       `json:"progress"` // 0 to 100
	Logs          string    `json:"logs"`
	CreatedAt     time.Time `json:"created_at"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

// --- Module 9, 10, 11, 12: Certificates, CAs, Discovery & Policy ---

type CertificateProfile struct {
	ID                    string    `json:"id"`
	TenantID              string    `json:"tenant_id"`
	Name                  string    `json:"name"`
	Description           string    `json:"description"`
	AllowedCAs            []string  `json:"allowed_cas"`
	Algorithms            []string  `json:"algorithms"`
	ValidityDaysMax       int       `json:"validity_days_max"`
	AllowedSANPatterns    []string  `json:"allowed_san_patterns"`
	AllowWildcards        bool      `json:"allow_wildcards"`
	RequireApproval       bool      `json:"require_approval"`
	ApproverRoles         []string  `json:"approver_roles"`
	RenewalThresholdDays  int       `json:"renewal_threshold_days"`
	CAAEnforce            bool      `json:"caa_enforce"`
	NonExportableRequired bool      `json:"non_exportable_required"`
	CreatedAt             time.Time `json:"created_at"`
}

type Policy struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Name       string          `json:"name"`
	Version    int             `json:"version"`
	Rules      json.RawMessage `json:"rules"`
	IsActive   bool            `json:"is_active"`
	SignedHash string          `json:"signed_hash"`
	CreatedAt  time.Time       `json:"created_at"`
}

type CertificateRequest struct {
	ID            string                    `json:"id"`
	TenantID      string                    `json:"tenant_id"`
	ProfileID     string                    `json:"profile_id"`
	EnvironmentID string                    `json:"environment_id"`
	CommonName    string                    `json:"common_name"`
	SANs          []string                  `json:"sans"`
	KeyAlgorithm  string                    `json:"key_algorithm"`
	KeyBits       int                       `json:"key_bits"`
	Owner         string                    `json:"owner"`
	Team          string                    `json:"team"`
	Status        CertificateLifecycleState `json:"status"`
	Reason        string                    `json:"reason"`
	Requester     string                    `json:"requester"`
	IsEmergency   bool                      `json:"is_emergency"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
}

type Approval struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	RequestID string    `json:"request_id"`
	Approver  string    `json:"approver"`
	Decision  string    `json:"decision"` // approved, rejected
	Comments  string    `json:"comments"`
	CreatedAt time.Time `json:"created_at"`
}

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

// --- Module 13: Platform Health & Monitoring ---

type PlatformServiceHealth struct {
	ServiceName string    `json:"service_name"`
	Status      string    `json:"status"` // operational, degraded, outage
	UptimePct   float64   `json:"uptime_pct"`
	LatencyMs   float64   `json:"latency_ms"`
	LastCheckAt time.Time `json:"last_check_at"`
}

type PlatformIncident struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // critical, major, minor
	Status      string    `json:"status"` // investigating, identified, monitoring, resolved
	Impacted    []string  `json:"impacted"`
	CreatedAt   time.Time `json:"created_at"`
	ResolvedAt  time.Time `json:"resolved_at,omitempty"`
}

// --- Module 15: Security Operations ---

type SecurityEvent struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Severity    string    `json:"severity"` // critical, high, medium, low
	Category    string    `json:"category"` // suspicious_login, brute_force, key_compromise, drift
	Description string    `json:"description"`
	SourceIP    string    `json:"source_ip"`
	Status      string    `json:"status"` // new, investigating, resolved
	CreatedAt   time.Time `json:"created_at"`
}

// --- Module 16: Audit & Compliance ---

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

type AuditTreeHead struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	TreeSize       int64     `json:"tree_size"`
	RootHash       string    `json:"root_hash"`
	Signature      string    `json:"signature"`
	TimestampToken string    `json:"timestamp_token"` // RFC 3161 proof
	CreatedAt      time.Time `json:"created_at"`
}

type ComplianceControl struct {
	ID          string `json:"id"`
	Framework   string `json:"framework"` // SOC2, ISO27001, NIST800-53, PCIDSS
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Status      string `json:"status"` // compliant, in_review, non_compliant
	EvidenceRef string `json:"evidence_ref"`
}

// --- Module 17: Notifications & Alerting ---

type NotificationChannel struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Type      string    `json:"type"` // email, slack, teams, pagerduty, webhook
	Target    string    `json:"target"`
	Events    []string  `json:"events"`
	IsEnabled bool      `json:"is_enabled"`
	CreatedAt time.Time `json:"created_at"`
}

type WebhookSubscription struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	URL       string    `json:"url"`
	Secret    string    `json:"secret"`
	Events    []string  `json:"events"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// --- Module 18: Customer Support ---

type SupportTicket struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	UserEmail   string    `json:"user_email"`
	Subject     string    `json:"subject"`
	Description string    `json:"description"`
	Priority    string    `json:"priority"` // urgent, high, normal, low
	Status      string    `json:"status"` // open, in_progress, waiting_customer, resolved
	Category    string    `json:"category"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// --- Module 22: Backup & Disaster Recovery ---

type BackupRecord struct {
	ID              string    `json:"id"`
	TenantID        string    `json:"tenant_id"`
	Type            string    `json:"type"` // full, differential, metadata_only
	StorageLocation string    `json:"storage_location"`
	SizeBytes       int64     `json:"size_bytes"`
	Status          string    `json:"status"` // completed, failed, verifying
	CreatedAt       time.Time `json:"created_at"`
}

// --- Module 26: AI-Powered Features ---

type AIInsight struct {
	ID             string    `json:"id"`
	TenantID       string    `json:"tenant_id"`
	Category       string    `json:"category"` // risk_prediction, expiry_forecast, anomaly, ownership
	Title          string    `json:"title"`
	Recommendation string    `json:"recommendation"`
	ConfidencePct  int       `json:"confidence_pct"`
	Impact         string    `json:"impact"` // high, medium, low
	CreatedAt      time.Time `json:"created_at"`
}

// --- Module 27: Third-Party Integrations ---

type IntegrationItem struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"` // ServiceNow, Jira, Vault, Splunk, Intune, Datadog
	Category  string    `json:"category"` // ITSM, Secrets, SIEM, MDM, Observability
	Status    string    `json:"status"` // active, disconnected, error
	LastSyncAt time.Time `json:"last_sync_at"`
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
