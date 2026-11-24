-- 001_initial_schema.sql
-- Production PostgreSQL Schema with Row-Level Security (RLS) for Certificate Lifecycle Management (CLM)

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(128) UNIQUE NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Environments
CREATE TABLE IF NOT EXISTS environments (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    type VARCHAR(32) NOT NULL,
    region VARCHAR(64) NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE environments ENABLE ROW LEVEL SECURITY;
ALTER TABLE environments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_environments ON environments
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Gateways
CREATE TABLE IF NOT EXISTS gateways (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'offline',
    version VARCHAR(32) NOT NULL DEFAULT '1.0.0',
    keystore_type VARCHAR(32) NOT NULL DEFAULT 'software',
    fingerprint VARCHAR(128) NOT NULL DEFAULT '',
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    policy_grace VARCHAR(32) NOT NULL DEFAULT '72h',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE gateways ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateways FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_gateways ON gateways
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Enrollment Tokens
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    token VARCHAR(128) UNIQUE NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_enrollment_tokens ON enrollment_tokens
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Key References
CREATE TABLE IF NOT EXISTS key_references (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    gateway_id VARCHAR(64) NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    key_store VARCHAR(64) NOT NULL,
    key_alias VARCHAR(128) NOT NULL,
    algorithm VARCHAR(32) NOT NULL,
    bits INT NOT NULL DEFAULT 2048,
    non_exportable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE key_references ENABLE ROW LEVEL SECURITY;
ALTER TABLE key_references FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_key_references ON key_references
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Certificate Profiles
CREATE TABLE IF NOT EXISTS certificate_profiles (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    allowed_cas TEXT NOT NULL DEFAULT '[]',
    algorithms TEXT NOT NULL DEFAULT '[]',
    validity_days_max INT NOT NULL DEFAULT 90,
    allowed_san_patterns TEXT NOT NULL DEFAULT '[]',
    allow_wildcards BOOLEAN NOT NULL DEFAULT FALSE,
    require_approval BOOLEAN NOT NULL DEFAULT FALSE,
    approver_roles TEXT NOT NULL DEFAULT '[]',
    renewal_threshold_days INT NOT NULL DEFAULT 30,
    caa_enforce BOOLEAN NOT NULL DEFAULT TRUE,
    non_exportable_required BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE certificate_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_profiles ON certificate_profiles
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Policies
CREATE TABLE IF NOT EXISTS policies (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(128) NOT NULL,
    version INT NOT NULL DEFAULT 1,
    rules JSONB NOT NULL DEFAULT '{}'::jsonb,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    signed_hash VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_policies ON policies
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Certificate Requests
CREATE TABLE IF NOT EXISTS certificate_requests (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id VARCHAR(64) NOT NULL REFERENCES certificate_profiles(id),
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id),
    common_name VARCHAR(255) NOT NULL,
    sans TEXT NOT NULL DEFAULT '[]',
    key_algorithm VARCHAR(32) NOT NULL DEFAULT 'RSA',
    key_bits INT NOT NULL DEFAULT 2048,
    owner VARCHAR(128) NOT NULL,
    team VARCHAR(128) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'Requested',
    reason TEXT NOT NULL DEFAULT '',
    requester VARCHAR(128) NOT NULL,
    is_emergency BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE certificate_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificate_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_requests ON certificate_requests
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Approvals
CREATE TABLE IF NOT EXISTS approvals (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    request_id VARCHAR(64) NOT NULL REFERENCES certificate_requests(id) ON DELETE CASCADE,
    approver VARCHAR(128) NOT NULL,
    decision VARCHAR(32) NOT NULL,
    comments TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_approvals ON approvals
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Certificates
CREATE TABLE IF NOT EXISTS certificates (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    fingerprint_sha256 VARCHAR(64) UNIQUE NOT NULL,
    serial_number VARCHAR(128) NOT NULL,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    sans TEXT NOT NULL DEFAULT '[]',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    key_algorithm VARCHAR(32) NOT NULL,
    key_bits INT NOT NULL DEFAULT 2048,
    raw_pem TEXT NOT NULL,
    issuer_chain_pem TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'Active',
    owner VARCHAR(128) NOT NULL,
    team VARCHAR(128) NOT NULL,
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id),
    profile_id VARCHAR(64) NOT NULL REFERENCES certificate_profiles(id),
    key_ref_id VARCHAR(64) NOT NULL,
    request_id VARCHAR(64) NOT NULL,
    revocation_reason VARCHAR(64) NOT NULL DEFAULT '',
    risk_score INT NOT NULL DEFAULT 0,
    risk_factors TEXT NOT NULL DEFAULT '[]',
    auto_renew BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_certificates ON certificates
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));
CREATE INDEX idx_certs_not_after ON certificates(tenant_id, not_after);
CREATE INDEX idx_certs_fingerprint ON certificates(fingerprint_sha256);

-- Deployment Targets
CREATE TABLE IF NOT EXISTS deployment_targets (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id),
    gateway_id VARCHAR(64) NOT NULL REFERENCES gateways(id),
    name VARCHAR(128) NOT NULL,
    type VARCHAR(32) NOT NULL,
    host_address VARCHAR(255) NOT NULL,
    port INT NOT NULL DEFAULT 443,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE deployment_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_targets ON deployment_targets
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Deployments
CREATE TABLE IF NOT EXISTS deployments (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    certificate_id VARCHAR(64) NOT NULL REFERENCES certificates(id),
    target_id VARCHAR(64) NOT NULL REFERENCES deployment_targets(id),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    error_message TEXT NOT NULL DEFAULT '',
    previous_cert_id VARCHAR(64) NOT NULL DEFAULT '',
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE deployments ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployments FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_deployments ON deployments
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Audit Ledger (Append-Only)
CREATE TABLE IF NOT EXISTS audit_events (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    sequence BIGSERIAL,
    actor VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    before_hash VARCHAR(64) NOT NULL DEFAULT '',
    after_hash VARCHAR(64) NOT NULL DEFAULT '',
    policy_decision VARCHAR(64) NOT NULL DEFAULT 'allow',
    prev_hash VARCHAR(64) NOT NULL DEFAULT '',
    hash VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit ON audit_events
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));
CREATE INDEX idx_audit_seq ON audit_events(tenant_id, sequence);

-- Audit Merkle Tree Heads
CREATE TABLE IF NOT EXISTS audit_tree_heads (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    tree_size BIGINT NOT NULL,
    root_hash VARCHAR(64) NOT NULL,
    signature TEXT NOT NULL DEFAULT '',
    timestamp_token TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE audit_tree_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_tree_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_tree_heads ON audit_tree_heads
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Discovery Scans
CREATE TABLE IF NOT EXISTS discovery_scans (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    environment_id VARCHAR(64) NOT NULL REFERENCES environments(id),
    gateway_id VARCHAR(64) NOT NULL REFERENCES gateways(id),
    cidrs TEXT NOT NULL DEFAULT '[]',
    ports TEXT NOT NULL DEFAULT '[]',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    targets_scanned INT NOT NULL DEFAULT 0,
    certs_found INT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE discovery_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_scans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_discovery_scans ON discovery_scans
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Discovery Findings
CREATE TABLE IF NOT EXISTS discovery_findings (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scan_id VARCHAR(64) NOT NULL REFERENCES discovery_scans(id),
    fingerprint_sha256 VARCHAR(64) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port INT NOT NULL DEFAULT 443,
    subject_dn TEXT NOT NULL,
    issuer_dn TEXT NOT NULL,
    sans TEXT NOT NULL DEFAULT '[]',
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    key_algorithm VARCHAR(32) NOT NULL DEFAULT '',
    key_bits INT NOT NULL DEFAULT 0,
    is_managed BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score INT NOT NULL DEFAULT 0,
    risk_factors TEXT NOT NULL DEFAULT '[]',
    status VARCHAR(32) NOT NULL DEFAULT 'unmanaged',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE discovery_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE discovery_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_discovery_findings ON discovery_findings
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));

-- Gateway Commands
CREATE TABLE IF NOT EXISTS gateway_commands (
    id VARCHAR(64) PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    gateway_id VARCHAR(64) NOT NULL REFERENCES gateways(id) ON DELETE CASCADE,
    type VARCHAR(64) NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    nonce VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    signature TEXT NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    result_payload TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
ALTER TABLE gateway_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_commands FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_gateway_commands ON gateway_commands
    FOR ALL USING (tenant_id = current_setting('app.tenant_id', true));
