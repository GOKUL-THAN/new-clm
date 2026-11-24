package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"clm/internal/models"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	_ "modernc.org/sqlite"
)

type Storage interface {
	Close() error

	// Tenants
	CreateTenant(t *models.Tenant) error
	GetTenant(id string) (*models.Tenant, error)
	ListTenants() ([]*models.Tenant, error)

	// Environments
	CreateEnvironment(env *models.Environment) error
	GetEnvironment(tenantID, id string) (*models.Environment, error)
	ListEnvironments(tenantID string) ([]*models.Environment, error)

	// Gateways
	CreateGateway(gw *models.Gateway) error
	GetGateway(tenantID, id string) (*models.Gateway, error)
	UpdateGatewayStatus(tenantID, id, status, version string) error
	ListGateways(tenantID string) ([]*models.Gateway, error)

	// Enrollment Tokens
	CreateEnrollmentToken(tok *models.EnrollmentToken) error
	ConsumeEnrollmentToken(tokenStr string) (*models.EnrollmentToken, error)

	// Gateway Commands
	QueueCommand(cmd *models.GatewayCommand) error
	GetPendingCommands(tenantID, gatewayID string) ([]*models.GatewayCommand, error)
	UpdateCommandResult(tenantID, cmdID, status string, result json.RawMessage) error

	// Profiles
	CreateProfile(p *models.CertificateProfile) error
	GetProfile(tenantID, id string) (*models.CertificateProfile, error)
	ListProfiles(tenantID string) ([]*models.CertificateProfile, error)

	// Policies
	CreatePolicy(pol *models.Policy) error
	GetActivePolicy(tenantID string) (*models.Policy, error)
	ListPolicies(tenantID string) ([]*models.Policy, error)

	// Certificate Requests
	CreateCertificateRequest(req *models.CertificateRequest) error
	GetCertificateRequest(tenantID, id string) (*models.CertificateRequest, error)
	UpdateCertificateRequestStatus(tenantID, id string, status models.CertificateLifecycleState, reason string) error
	ListCertificateRequests(tenantID string) ([]*models.CertificateRequest, error)

	// Approvals
	CreateApproval(app *models.Approval) error
	GetApprovalsForRequest(tenantID, requestID string) ([]*models.Approval, error)

	// Certificates
	CreateCertificate(cert *models.Certificate) error
	GetCertificate(tenantID, id string) (*models.Certificate, error)
	GetCertificateByFingerprint(tenantID, fp string) (*models.Certificate, error)
	UpdateCertificateStatus(tenantID, id string, status models.CertificateLifecycleState, revocationReason string) error
	ListCertificates(tenantID string) ([]*models.Certificate, error)
	ListExpiringCertificates(tenantID string, withinDays int) ([]*models.Certificate, error)

	// Deployment Targets & Deployments
	CreateDeploymentTarget(target *models.DeploymentTarget) error
	GetDeploymentTarget(tenantID, id string) (*models.DeploymentTarget, error)
	ListDeploymentTargets(tenantID string) ([]*models.DeploymentTarget, error)
	CreateDeployment(dep *models.Deployment) error
	UpdateDeploymentStatus(tenantID, id, status, errMsg string) error
	GetDeploymentsForCert(tenantID, certID string) ([]*models.Deployment, error)

	// Discovery
	CreateDiscoveryScan(scan *models.DiscoveryScan) error
	UpdateDiscoveryScan(tenantID, scanID, status string, scanned, certsFound int) error
	GetDiscoveryScan(tenantID, scanID string) (*models.DiscoveryScan, error)
	ListDiscoveryScans(tenantID string) ([]*models.DiscoveryScan, error)
	CreateDiscoveryFinding(f *models.DiscoveryFinding) error
	ListDiscoveryFindings(tenantID, scanID string) ([]*models.DiscoveryFinding, error)

	// Audit Ledger
	AppendAuditEvent(event *models.AuditEvent) error
	ListAuditEvents(tenantID string, limit int) ([]*models.AuditEvent, error)
	GetLastAuditEvent(tenantID string) (*models.AuditEvent, error)
	SaveAuditTreeHead(sth *models.AuditTreeHead) error
	GetLatestTreeHead(tenantID string) (*models.AuditTreeHead, error)
}

type sqlStorage struct {
	db     *sql.DB
	driver string
	mu     sync.RWMutex
}

func NewSQLStorage(driver, dsn string) (Storage, error) {
	if driver == "" {
		driver = "sqlite"
	}
	if dsn == "" {
		dsn = ":memory:"
	}

	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &sqlStorage{
		db:     db,
		driver: driver,
	}

	if err := s.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	return s, nil
}

func (s *sqlStorage) Close() error {
	return s.db.Close()
}

func (s *sqlStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		slug TEXT UNIQUE NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS environments (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		region TEXT NOT NULL,
		tags TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS gateways (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		name TEXT NOT NULL,
		status TEXT NOT NULL,
		version TEXT NOT NULL,
		keystore_type TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		last_seen_at TIMESTAMP NOT NULL,
		policy_grace TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS enrollment_tokens (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		token TEXT UNIQUE NOT NULL,
		used INTEGER NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS key_references (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		gateway_id TEXT NOT NULL,
		key_store TEXT NOT NULL,
		key_alias TEXT NOT NULL,
		algorithm TEXT NOT NULL,
		bits INTEGER NOT NULL,
		non_exportable INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS certificate_profiles (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		name TEXT NOT NULL,
		description TEXT NOT NULL,
		allowed_cas TEXT NOT NULL,
		algorithms TEXT NOT NULL,
		validity_days_max INTEGER NOT NULL,
		allowed_san_patterns TEXT NOT NULL,
		allow_wildcards INTEGER NOT NULL,
		require_approval INTEGER NOT NULL,
		approver_roles TEXT NOT NULL,
		renewal_threshold_days INTEGER NOT NULL,
		caa_enforce INTEGER NOT NULL,
		non_exportable_required INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS policies (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		name TEXT NOT NULL,
		version INTEGER NOT NULL,
		rules TEXT NOT NULL,
		is_active INTEGER NOT NULL,
		signed_hash TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS certificate_requests (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		profile_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		common_name TEXT NOT NULL,
		sans TEXT NOT NULL,
		key_algorithm TEXT NOT NULL,
		key_bits INTEGER NOT NULL,
		owner TEXT NOT NULL,
		team TEXT NOT NULL,
		status TEXT NOT NULL,
		reason TEXT NOT NULL,
		requester TEXT NOT NULL,
		is_emergency INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS approvals (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		request_id TEXT NOT NULL,
		approver TEXT NOT NULL,
		decision TEXT NOT NULL,
		comments TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS certificates (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		fingerprint_sha256 TEXT UNIQUE NOT NULL,
		serial_number TEXT NOT NULL,
		subject_dn TEXT NOT NULL,
		issuer_dn TEXT NOT NULL,
		sans TEXT NOT NULL,
		not_before TIMESTAMP NOT NULL,
		not_after TIMESTAMP NOT NULL,
		key_algorithm TEXT NOT NULL,
		key_bits INTEGER NOT NULL,
		raw_pem TEXT NOT NULL,
		issuer_chain_pem TEXT NOT NULL,
		status TEXT NOT NULL,
		owner TEXT NOT NULL,
		team TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		profile_id TEXT NOT NULL,
		key_ref_id TEXT NOT NULL,
		request_id TEXT NOT NULL,
		revocation_reason TEXT NOT NULL,
		risk_score INTEGER NOT NULL,
		risk_factors TEXT NOT NULL,
		auto_renew INTEGER NOT NULL,
		created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS deployment_targets (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		gateway_id TEXT NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		host_address TEXT NOT NULL,
		port INTEGER NOT NULL,
		config_json TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS deployments (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		certificate_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		status TEXT NOT NULL,
		error_message TEXT NOT NULL,
		previous_cert_id TEXT NOT NULL,
		deployed_at TIMESTAMP NOT NULL,
		verified_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		sequence INTEGER NOT NULL,
		actor TEXT NOT NULL,
		action TEXT NOT NULL,
		target_type TEXT NOT NULL,
		target_id TEXT NOT NULL,
		before_hash TEXT NOT NULL,
		after_hash TEXT NOT NULL,
		policy_decision TEXT NOT NULL,
		prev_hash TEXT NOT NULL,
		hash TEXT NOT NULL,
		timestamp TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS audit_tree_heads (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		tree_size INTEGER NOT NULL,
		root_hash TEXT NOT NULL,
		signature TEXT NOT NULL,
		timestamp_token TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS discovery_scans (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		environment_id TEXT NOT NULL,
		gateway_id TEXT NOT NULL,
		cidrs TEXT NOT NULL,
		ports TEXT NOT NULL,
		status TEXT NOT NULL,
		targets_scanned INTEGER NOT NULL,
		certs_found INTEGER NOT NULL,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS discovery_findings (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		scan_id TEXT NOT NULL,
		fingerprint_sha256 TEXT NOT NULL,
		host TEXT NOT NULL,
		port INTEGER NOT NULL,
		subject_dn TEXT NOT NULL,
		issuer_dn TEXT NOT NULL,
		sans TEXT NOT NULL,
		not_before TIMESTAMP NOT NULL,
		not_after TIMESTAMP NOT NULL,
		key_algorithm TEXT NOT NULL,
		key_bits INTEGER NOT NULL,
		is_managed INTEGER NOT NULL,
		risk_score INTEGER NOT NULL,
		risk_factors TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS gateway_commands (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		gateway_id TEXT NOT NULL,
		type TEXT NOT NULL,
		payload TEXT NOT NULL,
		nonce TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		signature TEXT NOT NULL,
		status TEXT NOT NULL,
		result_payload TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

// Helper serialization
func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func fromJSON(data string, v interface{}) {
	_ = json.Unmarshal([]byte(data), v)
}

// Tenants
func (s *sqlStorage) CreateTenant(t *models.Tenant) error {
	if t.ID == "" {
		t.ID = "tenant_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now

	q := `INSERT INTO tenants (id, name, slug, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO tenants (id, name, slug, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)`
	}
	_, err := s.db.Exec(q, t.ID, t.Name, t.Slug, t.Status, t.CreatedAt, t.UpdatedAt)
	return err
}

func (s *sqlStorage) GetTenant(id string) (*models.Tenant, error) {
	q := `SELECT id, name, slug, status, created_at, updated_at FROM tenants WHERE id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, name, slug, status, created_at, updated_at FROM tenants WHERE id = $1`
	}
	row := s.db.QueryRow(q, id)
	var t models.Tenant
	if err := row.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *sqlStorage) ListTenants() ([]*models.Tenant, error) {
	q := `SELECT id, name, slug, status, created_at, updated_at FROM tenants ORDER BY created_at DESC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Tenant
	for rows.Next() {
		var t models.Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, &t)
	}
	return list, nil
}

// Environments
func (s *sqlStorage) CreateEnvironment(env *models.Environment) error {
	if env.ID == "" {
		env.ID = "env_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	env.CreatedAt = now
	env.UpdatedAt = now

	q := `INSERT INTO environments (id, tenant_id, name, type, region, tags, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO environments (id, tenant_id, name, type, region, tags, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	}
	_, err := s.db.Exec(q, env.ID, env.TenantID, env.Name, env.Type, env.Region, toJSON(env.Tags), env.CreatedAt, env.UpdatedAt)
	return err
}

func (s *sqlStorage) GetEnvironment(tenantID, id string) (*models.Environment, error) {
	q := `SELECT id, tenant_id, name, type, region, tags, created_at, updated_at FROM environments WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, type, region, tags, created_at, updated_at FROM environments WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, id)
	var env models.Environment
	var tagsStr string
	if err := row.Scan(&env.ID, &env.TenantID, &env.Name, &env.Type, &env.Region, &tagsStr, &env.CreatedAt, &env.UpdatedAt); err != nil {
		return nil, err
	}
	fromJSON(tagsStr, &env.Tags)
	return &env, nil
}

func (s *sqlStorage) ListEnvironments(tenantID string) ([]*models.Environment, error) {
	q := `SELECT id, tenant_id, name, type, region, tags, created_at, updated_at FROM environments WHERE tenant_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, type, region, tags, created_at, updated_at FROM environments WHERE tenant_id = $1 ORDER BY created_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Environment
	for rows.Next() {
		var env models.Environment
		var tagsStr string
		if err := rows.Scan(&env.ID, &env.TenantID, &env.Name, &env.Type, &env.Region, &tagsStr, &env.CreatedAt, &env.UpdatedAt); err != nil {
			return nil, err
		}
		fromJSON(tagsStr, &env.Tags)
		list = append(list, &env)
	}
	return list, nil
}

// Gateways
func (s *sqlStorage) CreateGateway(gw *models.Gateway) error {
	if gw.ID == "" {
		gw.ID = "gw_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	gw.CreatedAt = now
	gw.LastSeenAt = now

	q := `INSERT INTO gateways (id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO gateways (id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	}
	_, err := s.db.Exec(q, gw.ID, gw.TenantID, gw.EnvironmentID, gw.Name, gw.Status, gw.Version, gw.KeystoreType, gw.Fingerprint, gw.LastSeenAt, gw.PolicyGrace, gw.CreatedAt)
	return err
}

func (s *sqlStorage) GetGateway(tenantID, id string) (*models.Gateway, error) {
	q := `SELECT id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at FROM gateways WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at FROM gateways WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, id)
	var gw models.Gateway
	if err := row.Scan(&gw.ID, &gw.TenantID, &gw.EnvironmentID, &gw.Name, &gw.Status, &gw.Version, &gw.KeystoreType, &gw.Fingerprint, &gw.LastSeenAt, &gw.PolicyGrace, &gw.CreatedAt); err != nil {
		return nil, err
	}
	return &gw, nil
}

func (s *sqlStorage) UpdateGatewayStatus(tenantID, id, status, version string) error {
	now := time.Now().UTC()
	q := `UPDATE gateways SET status = ?, version = ?, last_seen_at = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE gateways SET status = $1, version = $2, last_seen_at = $3 WHERE tenant_id = $4 AND id = $5`
	}
	_, err := s.db.Exec(q, status, version, now, tenantID, id)
	return err
}

func (s *sqlStorage) ListGateways(tenantID string) ([]*models.Gateway, error) {
	q := `SELECT id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at FROM gateways WHERE tenant_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, name, status, version, keystore_type, fingerprint, last_seen_at, policy_grace, created_at FROM gateways WHERE tenant_id = $1 ORDER BY created_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Gateway
	for rows.Next() {
		var gw models.Gateway
		if err := rows.Scan(&gw.ID, &gw.TenantID, &gw.EnvironmentID, &gw.Name, &gw.Status, &gw.Version, &gw.KeystoreType, &gw.Fingerprint, &gw.LastSeenAt, &gw.PolicyGrace, &gw.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &gw)
	}
	return list, nil
}

// Enrollment Tokens
func (s *sqlStorage) CreateEnrollmentToken(tok *models.EnrollmentToken) error {
	if tok.ID == "" {
		tok.ID = "tok_" + uuid.New().String()[:8]
	}
	if tok.Token == "" {
		tok.Token = "enroll_" + uuid.New().String()
	}
	tok.CreatedAt = time.Now().UTC()
	if tok.ExpiresAt.IsZero() {
		tok.ExpiresAt = tok.CreatedAt.Add(24 * time.Hour)
	}

	q := `INSERT INTO enrollment_tokens (id, tenant_id, environment_id, token, used, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO enrollment_tokens (id, tenant_id, environment_id, token, used, expires_at, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	}
	usedInt := 0
	if tok.Used {
		usedInt = 1
	}
	_, err := s.db.Exec(q, tok.ID, tok.TenantID, tok.EnvironmentID, tok.Token, usedInt, tok.ExpiresAt, tok.CreatedAt)
	return err
}

func (s *sqlStorage) ConsumeEnrollmentToken(tokenStr string) (*models.EnrollmentToken, error) {
	q := `SELECT id, tenant_id, environment_id, token, used, expires_at, created_at FROM enrollment_tokens WHERE token = ? AND used = 0 AND expires_at > ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, token, used, expires_at, created_at FROM enrollment_tokens WHERE token = $1 AND used = 0 AND expires_at > $2`
	}
	row := s.db.QueryRow(q, tokenStr, time.Now().UTC())
	var tok models.EnrollmentToken
	var usedInt int
	if err := row.Scan(&tok.ID, &tok.TenantID, &tok.EnvironmentID, &tok.Token, &usedInt, &tok.ExpiresAt, &tok.CreatedAt); err != nil {
		return nil, fmt.Errorf("invalid or expired enrollment token: %w", err)
	}
	tok.Used = (usedInt != 0)

	updateQ := `UPDATE enrollment_tokens SET used = 1 WHERE id = ?`
	if s.driver == "postgres" {
		updateQ = `UPDATE enrollment_tokens SET used = 1 WHERE id = $1`
	}
	_, _ = s.db.Exec(updateQ, tok.ID)
	tok.Used = true
	return &tok, nil
}

// Gateway Commands
func (s *sqlStorage) QueueCommand(cmd *models.GatewayCommand) error {
	if cmd.ID == "" {
		cmd.ID = "cmd_" + uuid.New().String()[:8]
	}
	cmd.CreatedAt = time.Now().UTC()
	if cmd.Status == "" {
		cmd.Status = "pending"
	}
	q := `INSERT INTO gateway_commands (id, tenant_id, gateway_id, type, payload, nonce, expires_at, signature, status, result_payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO gateway_commands (id, tenant_id, gateway_id, type, payload, nonce, expires_at, signature, status, result_payload, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	}
	_, err := s.db.Exec(q, cmd.ID, cmd.TenantID, cmd.GatewayID, cmd.Type, string(cmd.Payload), cmd.Nonce, cmd.ExpiresAt, cmd.Signature, cmd.Status, string(cmd.ResultPayload), cmd.CreatedAt)
	return err
}

func (s *sqlStorage) GetPendingCommands(tenantID, gatewayID string) ([]*models.GatewayCommand, error) {
	q := `SELECT id, tenant_id, gateway_id, type, payload, nonce, expires_at, signature, status, result_payload, created_at FROM gateway_commands WHERE tenant_id = ? AND gateway_id = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at ASC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, gateway_id, type, payload, nonce, expires_at, signature, status, result_payload, created_at FROM gateway_commands WHERE tenant_id = $1 AND gateway_id = $2 AND status = 'pending' AND expires_at > $3 ORDER BY created_at ASC`
	}
	rows, err := s.db.Query(q, tenantID, gatewayID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.GatewayCommand
	for rows.Next() {
		var cmd models.GatewayCommand
		var payloadStr, resultStr string
		if err := rows.Scan(&cmd.ID, &cmd.TenantID, &cmd.GatewayID, &cmd.Type, &payloadStr, &cmd.Nonce, &cmd.ExpiresAt, &cmd.Signature, &cmd.Status, &resultStr, &cmd.CreatedAt); err != nil {
			return nil, err
		}
		cmd.Payload = json.RawMessage(payloadStr)
		cmd.ResultPayload = json.RawMessage(resultStr)
		list = append(list, &cmd)
	}
	return list, nil
}

func (s *sqlStorage) UpdateCommandResult(tenantID, cmdID, status string, result json.RawMessage) error {
	q := `UPDATE gateway_commands SET status = ?, result_payload = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE gateway_commands SET status = $1, result_payload = $2 WHERE tenant_id = $3 AND id = $4`
	}
	_, err := s.db.Exec(q, status, string(result), tenantID, cmdID)
	return err
}

// Profiles
func (s *sqlStorage) CreateProfile(p *models.CertificateProfile) error {
	if p.ID == "" {
		p.ID = "prof_" + uuid.New().String()[:8]
	}
	p.CreatedAt = time.Now().UTC()

	q := `INSERT INTO certificate_profiles (id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO certificate_profiles (id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	}

	boolToInt := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}

	_, err := s.db.Exec(q, p.ID, p.TenantID, p.Name, p.Description, toJSON(p.AllowedCAs), toJSON(p.Algorithms), p.ValidityDaysMax, toJSON(p.AllowedSANPatterns), boolToInt(p.AllowWildcards), boolToInt(p.RequireApproval), toJSON(p.ApproverRoles), p.RenewalThresholdDays, boolToInt(p.CAAEnforce), boolToInt(p.NonExportableRequired), p.CreatedAt)
	return err
}

func (s *sqlStorage) GetProfile(tenantID, id string) (*models.CertificateProfile, error) {
	q := `SELECT id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at FROM certificate_profiles WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at FROM certificate_profiles WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, id)
	var p models.CertificateProfile
	var cas, algs, patterns, roles string
	var wildcards, approval, caa, nonExp int

	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &cas, &algs, &p.ValidityDaysMax, &patterns, &wildcards, &approval, &roles, &p.RenewalThresholdDays, &caa, &nonExp, &p.CreatedAt); err != nil {
		return nil, err
	}
	fromJSON(cas, &p.AllowedCAs)
	fromJSON(algs, &p.Algorithms)
	fromJSON(patterns, &p.AllowedSANPatterns)
	fromJSON(roles, &p.ApproverRoles)
	p.AllowWildcards = (wildcards != 0)
	p.RequireApproval = (approval != 0)
	p.CAAEnforce = (caa != 0)
	p.NonExportableRequired = (nonExp != 0)
	return &p, nil
}

func (s *sqlStorage) ListProfiles(tenantID string) ([]*models.CertificateProfile, error) {
	q := `SELECT id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at FROM certificate_profiles WHERE tenant_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, description, allowed_cas, algorithms, validity_days_max, allowed_san_patterns, allow_wildcards, require_approval, approver_roles, renewal_threshold_days, caa_enforce, non_exportable_required, created_at FROM certificate_profiles WHERE tenant_id = $1 ORDER BY created_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.CertificateProfile
	for rows.Next() {
		var p models.CertificateProfile
		var cas, algs, patterns, roles string
		var wildcards, approval, caa, nonExp int

		if err := rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description, &cas, &algs, &p.ValidityDaysMax, &patterns, &wildcards, &approval, &roles, &p.RenewalThresholdDays, &caa, &nonExp, &p.CreatedAt); err != nil {
			return nil, err
		}
		fromJSON(cas, &p.AllowedCAs)
		fromJSON(algs, &p.Algorithms)
		fromJSON(patterns, &p.AllowedSANPatterns)
		fromJSON(roles, &p.ApproverRoles)
		p.AllowWildcards = (wildcards != 0)
		p.RequireApproval = (approval != 0)
		p.CAAEnforce = (caa != 0)
		p.NonExportableRequired = (nonExp != 0)
		list = append(list, &p)
	}
	return list, nil
}

// Policies
func (s *sqlStorage) CreatePolicy(pol *models.Policy) error {
	if pol.ID == "" {
		pol.ID = "pol_" + uuid.New().String()[:8]
	}
	pol.CreatedAt = time.Now().UTC()

	q := `INSERT INTO policies (id, tenant_id, name, version, rules, is_active, signed_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO policies (id, tenant_id, name, version, rules, is_active, signed_hash, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	}
	activeInt := 0
	if pol.IsActive {
		activeInt = 1
	}
	_, err := s.db.Exec(q, pol.ID, pol.TenantID, pol.Name, pol.Version, string(pol.Rules), activeInt, pol.SignedHash, pol.CreatedAt)
	return err
}

func (s *sqlStorage) GetActivePolicy(tenantID string) (*models.Policy, error) {
	q := `SELECT id, tenant_id, name, version, rules, is_active, signed_hash, created_at FROM policies WHERE tenant_id = ? AND is_active = 1 ORDER BY version DESC LIMIT 1`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, version, rules, is_active, signed_hash, created_at FROM policies WHERE tenant_id = $1 AND is_active = 1 ORDER BY version DESC LIMIT 1`
	}
	row := s.db.QueryRow(q, tenantID)
	var pol models.Policy
	var rulesStr string
	var activeInt int
	if err := row.Scan(&pol.ID, &pol.TenantID, &pol.Name, &pol.Version, &rulesStr, &activeInt, &pol.SignedHash, &pol.CreatedAt); err != nil {
		return nil, err
	}
	pol.Rules = json.RawMessage(rulesStr)
	pol.IsActive = (activeInt != 0)
	return &pol, nil
}

func (s *sqlStorage) ListPolicies(tenantID string) ([]*models.Policy, error) {
	q := `SELECT id, tenant_id, name, version, rules, is_active, signed_hash, created_at FROM policies WHERE tenant_id = ? ORDER BY version DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, name, version, rules, is_active, signed_hash, created_at FROM policies WHERE tenant_id = $1 ORDER BY version DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Policy
	for rows.Next() {
		var pol models.Policy
		var rulesStr string
		var activeInt int
		if err := rows.Scan(&pol.ID, &pol.TenantID, &pol.Name, &pol.Version, &rulesStr, &activeInt, &pol.SignedHash, &pol.CreatedAt); err != nil {
			return nil, err
		}
		pol.Rules = json.RawMessage(rulesStr)
		pol.IsActive = (activeInt != 0)
		list = append(list, &pol)
	}
	return list, nil
}

// Certificate Requests
func (s *sqlStorage) CreateCertificateRequest(req *models.CertificateRequest) error {
	if req.ID == "" {
		req.ID = "req_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	req.CreatedAt = now
	req.UpdatedAt = now
	if req.Status == "" {
		req.Status = models.StateRequested
	}

	q := `INSERT INTO certificate_requests (id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO certificate_requests (id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`
	}

	emergInt := 0
	if req.IsEmergency {
		emergInt = 1
	}

	_, err := s.db.Exec(q, req.ID, req.TenantID, req.ProfileID, req.EnvironmentID, req.CommonName, toJSON(req.SANs), req.KeyAlgorithm, req.KeyBits, req.Owner, req.Team, string(req.Status), req.Reason, req.Requester, emergInt, req.CreatedAt, req.UpdatedAt)
	return err
}

func (s *sqlStorage) GetCertificateRequest(tenantID, id string) (*models.CertificateRequest, error) {
	q := `SELECT id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at FROM certificate_requests WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at FROM certificate_requests WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, id)
	var req models.CertificateRequest
	var sansStr, statusStr string
	var emergInt int
	if err := row.Scan(&req.ID, &req.TenantID, &req.ProfileID, &req.EnvironmentID, &req.CommonName, &sansStr, &req.KeyAlgorithm, &req.KeyBits, &req.Owner, &req.Team, &statusStr, &req.Reason, &req.Requester, &emergInt, &req.CreatedAt, &req.UpdatedAt); err != nil {
		return nil, err
	}
	fromJSON(sansStr, &req.SANs)
	req.Status = models.CertificateLifecycleState(statusStr)
	req.IsEmergency = (emergInt != 0)
	return &req, nil
}

func (s *sqlStorage) UpdateCertificateRequestStatus(tenantID, id string, status models.CertificateLifecycleState, reason string) error {
	now := time.Now().UTC()
	q := `UPDATE certificate_requests SET status = ?, reason = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE certificate_requests SET status = $1, reason = $2, updated_at = $3 WHERE tenant_id = $4 AND id = $5`
	}
	_, err := s.db.Exec(q, string(status), reason, now, tenantID, id)
	return err
}

func (s *sqlStorage) ListCertificateRequests(tenantID string) ([]*models.CertificateRequest, error) {
	q := `SELECT id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at FROM certificate_requests WHERE tenant_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, profile_id, environment_id, common_name, sans, key_algorithm, key_bits, owner, team, status, reason, requester, is_emergency, created_at, updated_at FROM certificate_requests WHERE tenant_id = $1 ORDER BY created_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.CertificateRequest
	for rows.Next() {
		var req models.CertificateRequest
		var sansStr, statusStr string
		var emergInt int
		if err := rows.Scan(&req.ID, &req.TenantID, &req.ProfileID, &req.EnvironmentID, &req.CommonName, &sansStr, &req.KeyAlgorithm, &req.KeyBits, &req.Owner, &req.Team, &statusStr, &req.Reason, &req.Requester, &emergInt, &req.CreatedAt, &req.UpdatedAt); err != nil {
			return nil, err
		}
		fromJSON(sansStr, &req.SANs)
		req.Status = models.CertificateLifecycleState(statusStr)
		req.IsEmergency = (emergInt != 0)
		list = append(list, &req)
	}
	return list, nil
}

// Approvals
func (s *sqlStorage) CreateApproval(app *models.Approval) error {
	if app.ID == "" {
		app.ID = "appr_" + uuid.New().String()[:8]
	}
	app.CreatedAt = time.Now().UTC()

	q := `INSERT INTO approvals (id, tenant_id, request_id, approver, decision, comments, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO approvals (id, tenant_id, request_id, approver, decision, comments, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	}
	_, err := s.db.Exec(q, app.ID, app.TenantID, app.RequestID, app.Approver, app.Decision, app.Comments, app.CreatedAt)
	return err
}

func (s *sqlStorage) GetApprovalsForRequest(tenantID, requestID string) ([]*models.Approval, error) {
	q := `SELECT id, tenant_id, request_id, approver, decision, comments, created_at FROM approvals WHERE tenant_id = ? AND request_id = ? ORDER BY created_at ASC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, request_id, approver, decision, comments, created_at FROM approvals WHERE tenant_id = $1 AND request_id = $2 ORDER BY created_at ASC`
	}
	rows, err := s.db.Query(q, tenantID, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Approval
	for rows.Next() {
		var app models.Approval
		if err := rows.Scan(&app.ID, &app.TenantID, &app.RequestID, &app.Approver, &app.Decision, &app.Comments, &app.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &app)
	}
	return list, nil
}

// Certificates
func (s *sqlStorage) CreateCertificate(cert *models.Certificate) error {
	if cert.ID == "" {
		cert.ID = "cert_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	cert.CreatedAt = now
	cert.UpdatedAt = now
	if cert.Status == "" {
		cert.Status = models.StateActive
	}

	q := `INSERT INTO certificates (id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO certificates (id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26)`
	}

	autoRenewInt := 0
	if cert.AutoRenew {
		autoRenewInt = 1
	}

	_, err := s.db.Exec(q, cert.ID, cert.TenantID, cert.FingerprintSHA256, cert.SerialNumber, cert.SubjectDN, cert.IssuerDN, toJSON(cert.SANs), cert.NotBefore, cert.NotAfter, cert.KeyAlgorithm, cert.KeyBits, cert.RawPEM, cert.IssuerChainPEM, string(cert.Status), cert.Owner, cert.Team, cert.EnvironmentID, cert.ProfileID, cert.KeyRefID, cert.RequestID, cert.RevocationReason, cert.RiskScore, toJSON(cert.RiskFactors), autoRenewInt, cert.CreatedAt, cert.UpdatedAt)
	return err
}

func (s *sqlStorage) GetCertificate(tenantID, id string) (*models.Certificate, error) {
	q := `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = $1 AND id = $2`
	}
	return s.scanCert(s.db.QueryRow(q, tenantID, id))
}

func (s *sqlStorage) GetCertificateByFingerprint(tenantID, fp string) (*models.Certificate, error) {
	q := `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = ? AND fingerprint_sha256 = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2`
	}
	return s.scanCert(s.db.QueryRow(q, tenantID, fp))
}

func (s *sqlStorage) scanCert(row *sql.Row) (*models.Certificate, error) {
	var c models.Certificate
	var sansStr, statusStr, riskStr string
	var autoRenewInt int
	if err := row.Scan(&c.ID, &c.TenantID, &c.FingerprintSHA256, &c.SerialNumber, &c.SubjectDN, &c.IssuerDN, &sansStr, &c.NotBefore, &c.NotAfter, &c.KeyAlgorithm, &c.KeyBits, &c.RawPEM, &c.IssuerChainPEM, &statusStr, &c.Owner, &c.Team, &c.EnvironmentID, &c.ProfileID, &c.KeyRefID, &c.RequestID, &c.RevocationReason, &c.RiskScore, &riskStr, &autoRenewInt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	fromJSON(sansStr, &c.SANs)
	fromJSON(riskStr, &c.RiskFactors)
	c.Status = models.CertificateLifecycleState(statusStr)
	c.AutoRenew = (autoRenewInt != 0)
	return &c, nil
}

func (s *sqlStorage) UpdateCertificateStatus(tenantID, id string, status models.CertificateLifecycleState, revocationReason string) error {
	now := time.Now().UTC()
	q := `UPDATE certificates SET status = ?, revocation_reason = ?, updated_at = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE certificates SET status = $1, revocation_reason = $2, updated_at = $3 WHERE tenant_id = $4 AND id = $5`
	}
	_, err := s.db.Exec(q, string(status), revocationReason, now, tenantID, id)
	return err
}

func (s *sqlStorage) ListCertificates(tenantID string) ([]*models.Certificate, error) {
	q := `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = ? ORDER BY not_after ASC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = $1 ORDER BY not_after ASC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Certificate
	for rows.Next() {
		var c models.Certificate
		var sansStr, statusStr, riskStr string
		var autoRenewInt int
		if err := rows.Scan(&c.ID, &c.TenantID, &c.FingerprintSHA256, &c.SerialNumber, &c.SubjectDN, &c.IssuerDN, &sansStr, &c.NotBefore, &c.NotAfter, &c.KeyAlgorithm, &c.KeyBits, &c.RawPEM, &c.IssuerChainPEM, &statusStr, &c.Owner, &c.Team, &c.EnvironmentID, &c.ProfileID, &c.KeyRefID, &c.RequestID, &c.RevocationReason, &c.RiskScore, &riskStr, &autoRenewInt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		fromJSON(sansStr, &c.SANs)
		fromJSON(riskStr, &c.RiskFactors)
		c.Status = models.CertificateLifecycleState(statusStr)
		c.AutoRenew = (autoRenewInt != 0)
		list = append(list, &c)
	}
	return list, nil
}

func (s *sqlStorage) ListExpiringCertificates(tenantID string, withinDays int) ([]*models.Certificate, error) {
	threshold := time.Now().UTC().Add(time.Duration(withinDays) * 24 * time.Hour)
	q := `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = ? AND not_after <= ? AND status = 'Active' ORDER BY not_after ASC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, fingerprint_sha256, serial_number, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, raw_pem, issuer_chain_pem, status, owner, team, environment_id, profile_id, key_ref_id, request_id, revocation_reason, risk_score, risk_factors, auto_renew, created_at, updated_at FROM certificates WHERE tenant_id = $1 AND not_after <= $2 AND status = 'Active' ORDER BY not_after ASC`
	}
	rows, err := s.db.Query(q, tenantID, threshold)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Certificate
	for rows.Next() {
		var c models.Certificate
		var sansStr, statusStr, riskStr string
		var autoRenewInt int
		if err := rows.Scan(&c.ID, &c.TenantID, &c.FingerprintSHA256, &c.SerialNumber, &c.SubjectDN, &c.IssuerDN, &sansStr, &c.NotBefore, &c.NotAfter, &c.KeyAlgorithm, &c.KeyBits, &c.RawPEM, &c.IssuerChainPEM, &statusStr, &c.Owner, &c.Team, &c.EnvironmentID, &c.ProfileID, &c.KeyRefID, &c.RequestID, &c.RevocationReason, &c.RiskScore, &riskStr, &autoRenewInt, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		fromJSON(sansStr, &c.SANs)
		fromJSON(riskStr, &c.RiskFactors)
		c.Status = models.CertificateLifecycleState(statusStr)
		c.AutoRenew = (autoRenewInt != 0)
		list = append(list, &c)
	}
	return list, nil
}

// Deployment Targets & Deployments
func (s *sqlStorage) CreateDeploymentTarget(target *models.DeploymentTarget) error {
	if target.ID == "" {
		target.ID = "tgt_" + uuid.New().String()[:8]
	}
	target.CreatedAt = time.Now().UTC()

	q := `INSERT INTO deployment_targets (id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO deployment_targets (id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`
	}
	_, err := s.db.Exec(q, target.ID, target.TenantID, target.EnvironmentID, target.GatewayID, target.Name, target.Type, target.HostAddress, target.Port, target.ConfigJSON, target.CreatedAt)
	return err
}

func (s *sqlStorage) GetDeploymentTarget(tenantID, id string) (*models.DeploymentTarget, error) {
	q := `SELECT id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at FROM deployment_targets WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at FROM deployment_targets WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, id)
	var t models.DeploymentTarget
	if err := row.Scan(&t.ID, &t.TenantID, &t.EnvironmentID, &t.GatewayID, &t.Name, &t.Type, &t.HostAddress, &t.Port, &t.ConfigJSON, &t.CreatedAt); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s *sqlStorage) ListDeploymentTargets(tenantID string) ([]*models.DeploymentTarget, error) {
	q := `SELECT id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at FROM deployment_targets WHERE tenant_id = ? ORDER BY created_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, gateway_id, name, type, host_address, port, config_json, created_at FROM deployment_targets WHERE tenant_id = $1 ORDER BY created_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.DeploymentTarget
	for rows.Next() {
		var t models.DeploymentTarget
		if err := rows.Scan(&t.ID, &t.TenantID, &t.EnvironmentID, &t.GatewayID, &t.Name, &t.Type, &t.HostAddress, &t.Port, &t.ConfigJSON, &t.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, &t)
	}
	return list, nil
}

func (s *sqlStorage) CreateDeployment(dep *models.Deployment) error {
	if dep.ID == "" {
		dep.ID = "dep_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	dep.DeployedAt = now
	dep.VerifiedAt = now

	q := `INSERT INTO deployments (id, tenant_id, certificate_id, target_id, status, error_message, previous_cert_id, deployed_at, verified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO deployments (id, tenant_id, certificate_id, target_id, status, error_message, previous_cert_id, deployed_at, verified_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	}
	_, err := s.db.Exec(q, dep.ID, dep.TenantID, dep.CertificateID, dep.TargetID, dep.Status, dep.ErrorMessage, dep.PreviousCertID, dep.DeployedAt, dep.VerifiedAt)
	return err
}

func (s *sqlStorage) UpdateDeploymentStatus(tenantID, id, status, errMsg string) error {
	now := time.Now().UTC()
	q := `UPDATE deployments SET status = ?, error_message = ?, verified_at = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE deployments SET status = $1, error_message = $2, verified_at = $3 WHERE tenant_id = $4 AND id = $5`
	}
	_, err := s.db.Exec(q, status, errMsg, now, tenantID, id)
	return err
}

func (s *sqlStorage) GetDeploymentsForCert(tenantID, certID string) ([]*models.Deployment, error) {
	q := `SELECT id, tenant_id, certificate_id, target_id, status, error_message, previous_cert_id, deployed_at, verified_at FROM deployments WHERE tenant_id = ? AND certificate_id = ? ORDER BY deployed_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, certificate_id, target_id, status, error_message, previous_cert_id, deployed_at, verified_at FROM deployments WHERE tenant_id = $1 AND certificate_id = $2 ORDER BY deployed_at DESC`
	}
	rows, err := s.db.Query(q, tenantID, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.Deployment
	for rows.Next() {
		var d models.Deployment
		if err := rows.Scan(&d.ID, &d.TenantID, &d.CertificateID, &d.TargetID, &d.Status, &d.ErrorMessage, &d.PreviousCertID, &d.DeployedAt, &d.VerifiedAt); err != nil {
			return nil, err
		}
		list = append(list, &d)
	}
	return list, nil
}

// Discovery
func (s *sqlStorage) CreateDiscoveryScan(scan *models.DiscoveryScan) error {
	if scan.ID == "" {
		scan.ID = "scan_" + uuid.New().String()[:8]
	}
	now := time.Now().UTC()
	scan.StartedAt = now
	scan.CompletedAt = now

	q := `INSERT INTO discovery_scans (id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO discovery_scans (id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	}
	_, err := s.db.Exec(q, scan.ID, scan.TenantID, scan.EnvironmentID, scan.GatewayID, toJSON(scan.CIDRs), toJSON(scan.Ports), scan.Status, scan.TargetsScanned, scan.CertsFound, scan.StartedAt, scan.CompletedAt)
	return err
}

func (s *sqlStorage) UpdateDiscoveryScan(tenantID, scanID, status string, scanned, certsFound int) error {
	now := time.Now().UTC()
	q := `UPDATE discovery_scans SET status = ?, targets_scanned = ?, certs_found = ?, completed_at = ? WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `UPDATE discovery_scans SET status = $1, targets_scanned = $2, certs_found = $3, completed_at = $4 WHERE tenant_id = $5 AND id = $6`
	}
	_, err := s.db.Exec(q, status, scanned, certsFound, now, tenantID, scanID)
	return err
}

func (s *sqlStorage) GetDiscoveryScan(tenantID, scanID string) (*models.DiscoveryScan, error) {
	q := `SELECT id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at FROM discovery_scans WHERE tenant_id = ? AND id = ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at FROM discovery_scans WHERE tenant_id = $1 AND id = $2`
	}
	row := s.db.QueryRow(q, tenantID, scanID)
	var sc models.DiscoveryScan
	var cidrsStr, portsStr string
	if err := row.Scan(&sc.ID, &sc.TenantID, &sc.EnvironmentID, &sc.GatewayID, &cidrsStr, &portsStr, &sc.Status, &sc.TargetsScanned, &sc.CertsFound, &sc.StartedAt, &sc.CompletedAt); err != nil {
		return nil, err
	}
	fromJSON(cidrsStr, &sc.CIDRs)
	fromJSON(portsStr, &sc.Ports)
	return &sc, nil
}

func (s *sqlStorage) ListDiscoveryScans(tenantID string) ([]*models.DiscoveryScan, error) {
	q := `SELECT id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at FROM discovery_scans WHERE tenant_id = ? ORDER BY started_at DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, environment_id, gateway_id, cidrs, ports, status, targets_scanned, certs_found, started_at, completed_at FROM discovery_scans WHERE tenant_id = $1 ORDER BY started_at DESC`
	}
	rows, err := s.db.Query(q, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.DiscoveryScan
	for rows.Next() {
		var sc models.DiscoveryScan
		var cidrsStr, portsStr string
		if err := rows.Scan(&sc.ID, &sc.TenantID, &sc.EnvironmentID, &sc.GatewayID, &cidrsStr, &portsStr, &sc.Status, &sc.TargetsScanned, &sc.CertsFound, &sc.StartedAt, &sc.CompletedAt); err != nil {
			return nil, err
		}
		fromJSON(cidrsStr, &sc.CIDRs)
		fromJSON(portsStr, &sc.Ports)
		list = append(list, &sc)
	}
	return list, nil
}

func (s *sqlStorage) CreateDiscoveryFinding(f *models.DiscoveryFinding) error {
	if f.ID == "" {
		f.ID = "find_" + uuid.New().String()[:8]
	}
	f.CreatedAt = time.Now().UTC()

	q := `INSERT INTO discovery_findings (id, tenant_id, scan_id, fingerprint_sha256, host, port, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, is_managed, risk_score, risk_factors, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO discovery_findings (id, tenant_id, scan_id, fingerprint_sha256, host, port, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, is_managed, risk_score, risk_factors, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`
	}

	managedInt := 0
	if f.IsManaged {
		managedInt = 1
	}

	_, err := s.db.Exec(q, f.ID, f.TenantID, f.ScanID, f.FingerprintSHA256, f.Host, f.Port, f.SubjectDN, f.IssuerDN, toJSON(f.SANs), f.NotBefore, f.NotAfter, f.KeyAlgorithm, f.KeyBits, managedInt, f.RiskScore, toJSON(f.RiskFactors), f.Status, f.CreatedAt)
	return err
}

func (s *sqlStorage) ListDiscoveryFindings(tenantID, scanID string) ([]*models.DiscoveryFinding, error) {
	q := `SELECT id, tenant_id, scan_id, fingerprint_sha256, host, port, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, is_managed, risk_score, risk_factors, status, created_at FROM discovery_findings WHERE tenant_id = ? AND (scan_id = ? OR ? = '') ORDER BY risk_score DESC`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, scan_id, fingerprint_sha256, host, port, subject_dn, issuer_dn, sans, not_before, not_after, key_algorithm, key_bits, is_managed, risk_score, risk_factors, status, created_at FROM discovery_findings WHERE tenant_id = $1 AND (scan_id = $2 OR $3 = '') ORDER BY risk_score DESC`
	}
	rows, err := s.db.Query(q, tenantID, scanID, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.DiscoveryFinding
	for rows.Next() {
		var f models.DiscoveryFinding
		var sansStr, riskStr string
		var managedInt int
		if err := rows.Scan(&f.ID, &f.TenantID, &f.ScanID, &f.FingerprintSHA256, &f.Host, &f.Port, &f.SubjectDN, &f.IssuerDN, &sansStr, &f.NotBefore, &f.NotAfter, &f.KeyAlgorithm, &f.KeyBits, &managedInt, &f.RiskScore, &riskStr, &f.Status, &f.CreatedAt); err != nil {
			return nil, err
		}
		fromJSON(sansStr, &f.SANs)
		fromJSON(riskStr, &f.RiskFactors)
		f.IsManaged = (managedInt != 0)
		list = append(list, &f)
	}
	return list, nil
}

// Audit Ledger
func (s *sqlStorage) AppendAuditEvent(event *models.AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if event.ID == "" {
		event.ID = "aud_" + uuid.New().String()[:8]
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	// Fetch highest sequence and previous hash
	last, _ := s.GetLastAuditEvent(event.TenantID)
	if last != nil {
		event.Sequence = last.Sequence + 1
		event.PrevHash = last.Hash
	} else {
		event.Sequence = 1
		event.PrevHash = "0000000000000000000000000000000000000000000000000000000000000000"
	}

	q := `INSERT INTO audit_events (id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO audit_events (id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`
	}
	_, err := s.db.Exec(q, event.ID, event.TenantID, event.Sequence, event.Actor, event.Action, event.TargetType, event.TargetID, event.BeforeHash, event.AfterHash, event.PolicyDecision, event.PrevHash, event.Hash, event.Timestamp)
	return err
}

func (s *sqlStorage) GetLastAuditEvent(tenantID string) (*models.AuditEvent, error) {
	q := `SELECT id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp FROM audit_events WHERE tenant_id = ? ORDER BY sequence DESC LIMIT 1`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp FROM audit_events WHERE tenant_id = $1 ORDER BY sequence DESC LIMIT 1`
	}
	row := s.db.QueryRow(q, tenantID)
	var ev models.AuditEvent
	if err := row.Scan(&ev.ID, &ev.TenantID, &ev.Sequence, &ev.Actor, &ev.Action, &ev.TargetType, &ev.TargetID, &ev.BeforeHash, &ev.AfterHash, &ev.PolicyDecision, &ev.PrevHash, &ev.Hash, &ev.Timestamp); err != nil {
		return nil, err
	}
	return &ev, nil
}

func (s *sqlStorage) ListAuditEvents(tenantID string, limit int) ([]*models.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp FROM audit_events WHERE tenant_id = ? ORDER BY sequence ASC LIMIT ?`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, sequence, actor, action, target_type, target_id, before_hash, after_hash, policy_decision, prev_hash, hash, timestamp FROM audit_events WHERE tenant_id = $1 ORDER BY sequence ASC LIMIT $2`
	}
	rows, err := s.db.Query(q, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.AuditEvent
	for rows.Next() {
		var ev models.AuditEvent
		if err := rows.Scan(&ev.ID, &ev.TenantID, &ev.Sequence, &ev.Actor, &ev.Action, &ev.TargetType, &ev.TargetID, &ev.BeforeHash, &ev.AfterHash, &ev.PolicyDecision, &ev.PrevHash, &ev.Hash, &ev.Timestamp); err != nil {
			return nil, err
		}
		list = append(list, &ev)
	}
	return list, nil
}

func (s *sqlStorage) SaveAuditTreeHead(sth *models.AuditTreeHead) error {
	if sth.ID == "" {
		sth.ID = "sth_" + uuid.New().String()[:8]
	}
	sth.CreatedAt = time.Now().UTC()

	q := `INSERT INTO audit_tree_heads (id, tenant_id, tree_size, root_hash, signature, timestamp_token, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.driver == "postgres" {
		q = `INSERT INTO audit_tree_heads (id, tenant_id, tree_size, root_hash, signature, timestamp_token, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	}
	_, err := s.db.Exec(q, sth.ID, sth.TenantID, sth.TreeSize, sth.RootHash, sth.Signature, sth.TimestampToken, sth.CreatedAt)
	return err
}

func (s *sqlStorage) GetLatestTreeHead(tenantID string) (*models.AuditTreeHead, error) {
	q := `SELECT id, tenant_id, tree_size, root_hash, signature, timestamp_token, created_at FROM audit_tree_heads WHERE tenant_id = ? ORDER BY tree_size DESC LIMIT 1`
	if s.driver == "postgres" {
		q = `SELECT id, tenant_id, tree_size, root_hash, signature, timestamp_token, created_at FROM audit_tree_heads WHERE tenant_id = $1 ORDER BY tree_size DESC LIMIT 1`
	}
	row := s.db.QueryRow(q, tenantID)
	var sth models.AuditTreeHead
	if err := row.Scan(&sth.ID, &sth.TenantID, &sth.TreeSize, &sth.RootHash, &sth.Signature, &sth.TimestampToken, &sth.CreatedAt); err != nil {
		return nil, err
	}
	return &sth, nil
}
