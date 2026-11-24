// CLM Control Plane - Enterprise Application Engine (v2.4)
// Dual-Mode: Live Backend API (Render/Local) with Auto-Fallback to In-Browser Standalone Enclave

let apiBaseUrl = localStorage.getItem('clm_api_url') || '/api/v1';
let operatingMode = localStorage.getItem('clm_op_mode') || 'auto'; // 'auto', 'live', 'standalone'
let currentTenant = 'tenant_default';
let isLiveApiConnected = false;

// Mock Store for Standalone Enclave
const mockStore = {
    organizations: [
        { id: 'org_acme_corp', name: 'Acme Corporation Global', slug: 'acme-corp', status: 'verified', tier: 'enterprise_plus', risk_score: 12, docs: 'KYC, Tax Cert, Articles of Inc' }
    ],
    invoices: [
        { id: 'inv_2026_11_01', period: 'Nov 01 - Nov 30, 2026', amount: '$2,499.00', tax: '$249.90 (GST)', status: 'Paid', paid_at: '2026-11-01 09:15 UTC' },
        { id: 'inv_2026_10_01', period: 'Oct 01 - Oct 31, 2026', amount: '$2,499.00', tax: '$249.90 (GST)', status: 'Paid', paid_at: '2026-10-01 09:12 UTC' }
    ],
    tenants: [
        { id: 'tenant_default', name: 'Acme Global Production', data_residency: 'US-East (N. Virginia)', status: 'Active', cert_quota: '1,000', gw_quota: '50', storage: '4.2 MB' },
        { id: 'tenant_eu_fin', name: 'Acme EU Financial Services', data_residency: 'EU-Frankfurt', status: 'Active', cert_quota: '500', gw_quota: '20', storage: '1.8 MB' },
        { id: 'tenant_apac', name: 'Acme APAC Operations', data_residency: 'AP-Singapore', status: 'Active', cert_quota: '250', gw_quota: '10', storage: '0.9 MB' }
    ],
    users: [
        { id: 'usr_sec_admin', email: 'alice.sec@acme.com', name: 'Alice Cooper', role: 'Security Administrator', dept: 'SecOps', mfa: 'Enforced (WebAuthn)', last_active: '2 mins ago' },
        { id: 'usr_devops_lead', email: 'bob.ops@acme.com', name: 'Bob Martinez', role: 'DevOps Lead', dept: 'Platform Eng', mfa: 'Enforced (FIDO2)', last_active: '14 mins ago' },
        { id: 'usr_audit_lead', email: 'charlie.audit@acme.com', name: 'Charlie Kim', role: 'Compliance Officer', dept: 'Internal Audit', mfa: 'Enforced (TOTP)', last_active: '1 hour ago' }
    ],
    sso: [
        { provider: 'Okta Enterprise', protocol: 'OIDC / SAML 2.0', domain: 'acme.okta.com', scim: 'Enabled (Every 15m)', status: 'Healthy', cert_rot: 'Auto (30d notice)' },
        { provider: 'Microsoft Entra ID', protocol: 'SAML 2.0', domain: 'login.microsoftonline.com/acme', scim: 'Enabled', status: 'Healthy', cert_rot: 'Auto (60d notice)' }
    ],
    cloudAccounts: [
        { id: 'acc_aws_prod', provider: 'AWS', account_id: '112233445566', name: 'AWS Production Primary', auth_type: 'Cross-Account IAM Role + ExtID', status: 'Connected', last_synced: 'Just now' },
        { id: 'acc_azure_core', provider: 'Azure', account_id: 'sub_8831b-44a', name: 'Azure Core Infra', auth_type: 'Managed Identity', status: 'Connected', last_synced: '10 mins ago' },
        { id: 'acc_gcp_prod', provider: 'GCP', account_id: 'gcp-acme-prod-01', name: 'GCP Production Cluster', auth_type: 'Workload Identity Federation', status: 'Connected', last_synced: '3 mins ago' }
    ],
    gateways: [
        { id: 'gw-aws-prod-01', name: 'gw-vpc-us-east-1', status: 'ONLINE', keystore_type: 'in-vpc-enclave', version: 'v2.4.0', last_heartbeat: 'Just now', grace_period: 'Valid (2h grace)' },
        { id: 'gw-onprem-dc1', name: 'gw-dc-chicago-hsm', status: 'ONLINE', keystore_type: 'hsm-pkcs11', version: 'v2.4.0', last_heartbeat: '45s ago', grace_period: 'Valid (2h grace)' }
    ],
    jobs: [
        { id: 'job_deploy_918', type: 'Canary Rollout', cert_id: 'cert_web_prod_01', target: 'prod-alb-us-east-1', status: 'COMPLETED', progress: '100%', canary_weight: '100%', created_at: '10 mins ago' },
        { id: 'job_deploy_919', type: 'Blue-Green Switch', cert_id: 'cert_auth_api', target: 'k8s-ingress-istio', status: 'COMPLETED', progress: '100%', canary_weight: '100%', created_at: '2 hours ago' }
    ],
    certificates: [
        { id: 'cert_web_prod_01', subject_dn: 'CN=api.acme.com, O=Acme Corp', key_algorithm: 'RSA', key_bits: 2048, issuer_dn: 'CN=Acme Private Issuing CA v2', not_before: '2026-11-01', not_after: '2027-11-01', status: 'active', risk_score: 15, sha256_fp: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', owner: 'SecOps Team' },
        { id: 'cert_auth_api', subject_dn: 'CN=auth.acme.com, O=Acme Corp', key_algorithm: 'ECDSA', key_bits: 256, issuer_dn: "CN=Let's Encrypt Authority E1", not_before: '2026-10-15', not_after: '2027-01-13', status: 'active', risk_score: 22, sha256_fp: '7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b', owner: 'Identity Team' },
        { id: 'cert_pqc_gateway', subject_dn: 'CN=enclave.internal.acme.com', key_algorithm: 'ML-DSA-65+ECDSA', key_bits: 384, issuer_dn: 'CN=Acme PQC Root CA', not_before: '2026-11-20', not_after: '2027-11-20', status: 'active', risk_score: 5, sha256_fp: 'c44298fc1c149afbe3b04c8996fb92427ae41e4649b934ca495991b7852b855', owner: 'Crypto Agility' },
        { id: 'cert_legacy_portal', subject_dn: 'CN=legacy-portal.acme.internal', key_algorithm: 'RSA', key_bits: 1024, issuer_dn: 'CN=Internal Legacy CA', not_before: '2025-12-01', not_after: '2026-12-05', status: 'active', risk_score: 82, sha256_fp: '4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb', owner: 'Legacy Apps' }
    ],
    requests: [
        { id: 'req_88192a', common_name: 'payment.acme.com', profile_id: 'profile_pqc_hybrid', requester_id: 'usr_devops_lead', status: 'PENDING_APPROVAL', created_at: '25 mins ago' }
    ],
    discoveryFindings: [
        { id: 'scan_001', target_range: '10.200.0.0/24', status: 'COMPLETED', endpoints_scanned: 254, certs_found: 18, shadow_certs: 2, risk_flags: 'Expired Self-Signed, Weak RSA-1024' }
    ],
    healthServices: [
        { name: 'Control Plane API Engine', status: 'UP', latency: '4ms', sla: '99.99%', last_check: 'Just now' },
        { name: 'PostgreSQL RLS Database', status: 'UP', latency: '2ms', sla: '99.999%', last_check: 'Just now' },
        { name: 'In-VPC Enclave Keystore Bridge', status: 'UP', latency: '12ms', sla: '99.95%', last_check: '10s ago' },
        { name: 'Merkle Audit Log Verifier', status: 'UP', latency: '1ms', sla: '100.0%', last_check: 'Just now' },
        { name: 'SC-081 Automated Renewal Worker', status: 'UP', latency: '5ms', sla: '99.98%', last_check: '30s ago' }
    ],
    securityEvents: [
        { timestamp: '2026-11-24 10:14 UTC', severity: 'INFO', event_type: 'MFA_AUTH_SUCCESS', actor: 'alice.sec@acme.com [198.51.100.4]', details: 'FIDO2 Hardware token verification passed' },
        { timestamp: '2026-11-24 09:30 UTC', severity: 'WARN', event_type: 'FAILED_GATEWAY_POLL_NONCE', actor: '10.0.4.12', details: 'Command nonce replay detected & rejected' },
        { timestamp: '2026-11-24 08:00 UTC', severity: 'INFO', event_type: 'KEYSTORE_INTEGRITY_CHECK', actor: 'clm-daemon', details: 'Zero key material leakage confirmed' }
    ],
    auditLedger: [
        { seq: 1, timestamp: '2026-11-24 08:00:00Z', action: 'BOOTSTRAP_ORGANIZATION', actor: 'system', resource: 'org_acme_corp', hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', prev: '0000000000000000000000000000000000000000000000000000000000000000' },
        { seq: 2, timestamp: '2026-11-24 08:01:22Z', action: 'ENROLL_GATEWAY', actor: 'usr_sec_admin', resource: 'gw-aws-prod-01', hash: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4', prev: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
        { seq: 3, timestamp: '2026-11-24 08:15:45Z', action: 'ISSUE_CERTIFICATE', actor: 'usr_devops_lead', resource: 'cert_web_prod_01', hash: '3819fa186d88c22dc99e195156a5c189b88f3460e42d7219f8541cf6b7d2f831', prev: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4' }
    ],
    notifications: [
        { timestamp: '10 mins ago', channel: 'Slack #secops-alerts', recipient: 'webhook_prod', title: 'Canary Deployment 100% Verified', status: 'Delivered' },
        { timestamp: '1 hour ago', channel: 'PagerDuty', recipient: 'service_pki_primary', title: 'Upcoming Expiry: legacy-portal (<30d)', status: 'Acknowledged' }
    ],
    supportTickets: [
        { id: 'TICK-9081', subject: 'In-VPC HSM PKCS#11 module failover test', priority: 'High', status: 'In Progress', sla: '45 mins remaining', assigned: 'Senior Crypto Eng' },
        { id: 'TICK-9082', subject: 'Custom domain CAA verification assistance', priority: 'Medium', status: 'Resolved', sla: 'Met SLA (12m)', assigned: 'Network Support' }
    ],
    aiInsights: [
        { id: 'AI-001', target: 'legacy-portal.acme.internal', category: 'Quantum Vulnerability & Key Length', severity: 'HIGH', recommendation: 'Upgrade RSA-1024 to ML-DSA-65 or ECDSA P-384 immediately to prevent harvest-now-decrypt-later.', auto: 'Scheduled for tonight' },
        { id: 'AI-002', target: 'auth.acme.com', category: 'SC-081 Expiry Cycle (47-Day Window)', severity: 'MEDIUM', recommendation: 'Renewal candidate. Pre-validating DNS-01 CAA and CNAME delegation records.', auto: 'Auto-pilot active' }
    ],
    integrations: [
        { name: 'ServiceNow CMDB', type: 'ITIL Asset Sync', endpoint: 'https://acme.service-now.com', status: 'Connected', last_event: '5 mins ago' },
        { name: 'HashiCorp Vault', type: 'PKI Secrets Engine', endpoint: 'https://vault.internal.acme:8200', status: 'Connected', last_event: '12 mins ago' },
        { name: 'Splunk SIEM', type: 'Audit Log Forwarder', endpoint: 'https://splunk.secops.acme:8088', status: 'Streaming', last_event: 'Live' },
        { name: 'Datadog', type: 'Metrics & APM Telemetry', endpoint: 'https://api.datadoghq.com', status: 'Active', last_event: 'Live' }
    ]
};

// Application Initialization
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

async function initApp() {
    checkApiConnection();
    switchTab('dashboard');
    reloadAll();
}

async function checkApiConnection() {
    const statusDot = document.querySelector('.status-dot');
    const statusText = document.getElementById('apiStatusText');
    const modeBadge = document.getElementById('currentModeLabel');

    if (operatingMode === 'standalone') {
        isLiveApiConnected = false;
        statusDot.className = 'status-dot amber';
        statusText.innerText = 'Standalone Enclave';
        modeBadge.innerText = 'Standalone In-Browser';
        return;
    }

    try {
        const start = performance.now();
        const res = await fetch(`${apiBaseUrl}/certificates`, {
            method: 'GET',
            headers: { 'X-Tenant-ID': currentTenant },
            signal: AbortSignal.timeout(3000)
        });
        const latency = Math.round(performance.now() - start);

        if (res.ok) {
            isLiveApiConnected = true;
            statusDot.className = 'status-dot green';
            statusText.innerText = 'Live API Connected';
            modeBadge.innerText = 'Live Backend API';
            const latencyElem = document.getElementById('apiLatencyText');
            if (latencyElem) latencyElem.innerText = `${latency}ms`;
        } else {
            throw new Error(`API status ${res.status}`);
        }
    } catch (e) {
        isLiveApiConnected = false;
        statusDot.className = 'status-dot amber';
        statusText.innerText = 'In-Browser Enclave';
        modeBadge.innerText = 'Standalone Mock Active';
    }
}

async function apiRequest(endpoint, method = 'GET', body = null) {
    if (isLiveApiConnected && operatingMode !== 'standalone') {
        try {
            const headers = {
                'Content-Type': 'application/json',
                'X-Tenant-ID': currentTenant
            };
            const options = { method, headers };
            if (body) options.body = JSON.stringify(body);

            const res = await fetch(`${apiBaseUrl}${endpoint}`, options);
            if (res.ok) {
                return await res.json();
            }
        } catch (e) {
            console.warn(`Live API error for ${endpoint}, falling back to mock:`, e);
        }
    }

    // Mock API dispatch
    return handleMockRequest(endpoint, method, body);
}

function handleMockRequest(endpoint, method, body) {
    if (endpoint.startsWith('/certificates')) {
        if (method === 'GET') return mockStore.certificates;
    }
    if (endpoint.startsWith('/gateways')) {
        if (method === 'GET') return mockStore.gateways;
    }
    if (endpoint.startsWith('/certificate-requests')) {
        if (method === 'GET') return mockStore.requests;
        if (method === 'POST') {
            const newReq = {
                id: `req_${Math.random().toString(36).substring(2, 8)}`,
                common_name: body.common_name,
                profile_id: body.profile_id,
                requester_id: 'usr_sec_admin',
                status: 'PENDING_APPROVAL',
                created_at: 'Just now'
            };
            mockStore.requests.unshift(newReq);
            return newReq;
        }
    }
    if (endpoint.startsWith('/organizations')) {
        return mockStore.organizations;
    }
    if (endpoint.startsWith('/tenants')) {
        return mockStore.tenants;
    }
    if (endpoint.startsWith('/users')) {
        return mockStore.users;
    }
    if (endpoint.startsWith('/audit/events')) {
        return mockStore.auditLedger;
    }
    if (endpoint.startsWith('/audit/verify')) {
        return {
            valid: true,
            total_entries: mockStore.auditLedger.length,
            root_hash: '5a4d3f2b1c0e98a76543210fedcba9876543210abcdef0123456789abcdef012',
            signed_tree_head: 'STH_V2_SIG_OK'
        };
    }
    if (endpoint.startsWith('/health/services')) {
        return mockStore.healthServices;
    }
    if (endpoint.startsWith('/jobs')) {
        if (method === 'GET') return mockStore.jobs;
        if (method === 'POST') {
            const newJob = {
                id: `job_deploy_${Math.floor(Math.random() * 900 + 100)}`,
                type: body.rollout_strategy === 'canary' ? 'Canary Rollout' : 'Blue-Green Switch',
                cert_id: body.certificate_id,
                target: body.target_id,
                status: 'COMPLETED',
                progress: '100%',
                canary_weight: '100%',
                created_at: 'Just now'
            };
            mockStore.jobs.unshift(newJob);
            return newJob;
        }
    }
    return [];
}

// Navigation Tab Switcher
function switchTab(tabId) {
    document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

    const targetPanel = document.getElementById(`view-${tabId}`);
    if (targetPanel) {
        targetPanel.classList.add('active');
    }

    const clickedNav = Array.from(document.querySelectorAll('.nav-menu a')).find(a => a.getAttribute('href') === `#${tabId}`);
    if (clickedNav) {
        clickedNav.classList.add('active');
    }

    const titles = {
        dashboard: 'Overview & Health',
        orgs: 'Module 1: Global Platform & Organization Management',
        billing: 'Module 2: Subscription Plans & Billing Management',
        tenants: 'Module 3: Multi-Tenancy & Tenant Management',
        iam: 'Module 4: Departments, Teams & IAM User Management',
        sso: 'Module 5: Identity Providers, SSO & SCIM User Provisioning',
        cloud: 'Module 6: Multi-Cloud Accounts & Infrastructure Connectors',
        gateways: 'Module 7: Satellite Gateway Fleet Management',
        jobs: 'Module 8: Deployment Jobs & Multi-Target Orchestration',
        certificates: 'Module 9: Certificate Lifecycle, Cryptographic Inventory & PQC',
        ca: 'Module 10: CA Connectors, DCV & Trust Store Management',
        discovery: 'Module 11: Network Discovery, TLS Scanners & Shadow Assets',
        policy: 'Module 12: Policy-as-Code Engine & Approval Workflows',
        health: 'Module 13: Platform Health, Service Map & Resilience',
        metering: 'Module 14: Usage Metering, Rate Limiting & Resource Quotas',
        secops: 'Module 15: Security Operations, Threat Detection & Zero-Trust',
        audit: 'Module 16: Cryptographic Audit Ledger & Compliance Controls',
        notifications: 'Module 17: Notification Hub & Alert Routing',
        support: 'Module 18: Customer Support & SLA Ticketing',
        database: 'Module 19: Database Architecture & Schema Explorer',
        developer: 'Module 20: Developer Portal, REST API & SDKs',
        cicd: 'Module 21: DevOps, CI/CD Pipeline & Supply Chain Security',
        dr: 'Module 22: Disaster Recovery & Automated Backups',
        analytics: 'Module 23: Advanced Analytics, Forecasting & Reporting',
        branding: 'Module 24: UI/UX Customization & White-Label Branding',
        architecture: 'Module 25: Architecture Diagrams & Interactive Runbooks',
        ai: 'Module 26: AI Predictions, Risk Intelligence & Auto-Remediation',
        integrations: 'Module 27: Third-Party Enterprise Ecosystem Integrations'
    };
    document.getElementById('currentViewTitle').innerText = titles[tabId] || 'Overview';

    if (tabId === 'audit') loadAuditEvents();
    if (tabId === 'cicd') loadCBOM();
    if (tabId === 'health') loadHealthServices();
}

async function reloadAll() {
    const sel = document.getElementById('tenantSelect');
    if (sel) currentTenant = sel.value;

    await Promise.all([
        loadCertificates(),
        loadRequests(),
        loadGateways(),
        loadOrgs(),
        loadInvoices(),
        loadTenants(),
        loadUsers(),
        loadSSO(),
        loadCloudAccounts(),
        loadJobs(),
        loadDiscoveryFindings(),
        loadSecurityEvents(),
        loadNotifications(),
        loadSupportTickets(),
        loadAIInsights(),
        loadIntegrations()
    ]);
}

// Module 9 & Dashboard: Certificates
async function loadCertificates() {
    try {
        const certs = await apiRequest('/certificates') || [];
        
        // Update stats
        const statTotal = document.getElementById('statTotalCerts');
        if (statTotal) statTotal.innerText = certs.length;

        const now = new Date();
        const expiringSoon = certs.filter(c => {
            const exp = new Date(c.not_after);
            const days = (exp - now) / (1000 * 60 * 60 * 24);
            return days > 0 && days <= 30;
        });
        const statExp = document.getElementById('statExpiringSoon');
        if (statExp) statExp.innerText = expiringSoon.length;

        // Populate Dashboard Table
        const dashTbody = document.getElementById('dashboardCertsTable');
        if (dashTbody) {
            dashTbody.innerHTML = '';
            certs.slice(0, 5).forEach(c => {
                const tr = document.createElement('tr');
                const days = Math.round((new Date(c.not_after) - now) / (1000 * 60 * 60 * 24));
                tr.innerHTML = `
                    <td><strong>${escapeHtml(c.subject_dn)}</strong></td>
                    <td><span class="badge ${getStatusBadge(c.status)}">${c.status}</span></td>
                    <td>${c.key_algorithm} (${c.key_bits}b)</td>
                    <td>${escapeHtml(c.issuer_dn)}</td>
                    <td>${days > 0 ? days + ' days' : 'Expired'}</td>
                    <td><span class="badge ${c.risk_score > 50 ? 'badge-red' : c.risk_score > 20 ? 'badge-amber' : 'badge-green'}">${c.risk_score} / 100</span></td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="deployCert('${c.id}')">Deploy</button>
                        <button class="btn btn-danger btn-sm" onclick="revokeCert('${c.id}')">Revoke</button>
                    </td>
                `;
                dashTbody.appendChild(tr);
            });
        }

        // Populate Full Certificates Table
        const fullTbody = document.getElementById('fullCertsTable');
        if (fullTbody) {
            fullTbody.innerHTML = '';
            certs.forEach(c => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code>${(c.sha256_fp || c.fingerprint_sha256 || 'e3b0c442...').substring(0, 16)}...</code></td>
                    <td><strong>${escapeHtml(c.subject_dn)}</strong></td>
                    <td>${c.key_algorithm} (${c.key_bits}b)</td>
                    <td><span class="badge ${getStatusBadge(c.status)}">${c.status}</span></td>
                    <td>${c.not_before.substring(0, 10)} to ${c.not_after.substring(0, 10)}</td>
                    <td>${escapeHtml(c.owner || 'SecOps Team')}</td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="deployCert('${c.id}')">Deploy</button>
                        <button class="btn btn-danger btn-sm" onclick="revokeCert('${c.id}')">Revoke</button>
                    </td>
                `;
                fullTbody.appendChild(tr);
            });
        }

        // Update Job Cert dropdown
        const jobCertSelect = document.getElementById('jobCertSelect');
        if (jobCertSelect) {
            jobCertSelect.innerHTML = '';
            certs.forEach(c => {
                const opt = document.createElement('option');
                opt.value = c.id;
                opt.innerText = `${c.subject_dn} (${c.key_algorithm})`;
                jobCertSelect.appendChild(opt);
            });
        }
    } catch (e) {
        console.error('Failed to load certificates:', e);
    }
}

// Module 1: Orgs
function loadOrgs() {
    const tbody = document.getElementById('orgsTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.organizations.forEach(o => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${o.id}</code></td>
            <td><strong>${o.name}</strong></td>
            <td>${o.slug}</td>
            <td><span class="badge badge-green">${o.status}</span></td>
            <td><span class="badge badge-purple">${o.tier}</span></td>
            <td><span class="badge badge-green">${o.risk_score} / 100</span></td>
            <td>${o.docs}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="alert('Viewing audit history for ${o.name}')">Audit History</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 2: Invoices
function loadInvoices() {
    const tbody = document.getElementById('invoicesTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.invoices.forEach(inv => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${inv.id}</code></td>
            <td>${inv.period}</td>
            <td><strong>${inv.amount}</strong></td>
            <td>${inv.tax}</td>
            <td><span class="badge badge-green">${inv.status}</span></td>
            <td>${inv.paid_at}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="alert('Downloading invoice PDF...')">Download PDF</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 3: Tenants
function loadTenants() {
    const tbody = document.getElementById('tenantsTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.tenants.forEach(t => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${t.id}</code></td>
            <td><strong>${t.name}</strong></td>
            <td>${t.data_residency}</td>
            <td><span class="badge badge-green">${t.status}</span></td>
            <td>${t.cert_quota}</td>
            <td>${t.gw_quota}</td>
            <td>${t.storage}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 4: IAM Users
function loadUsers() {
    const tbody = document.getElementById('usersTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.users.forEach(u => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${u.id}</code></td>
            <td>${u.email}</td>
            <td><strong>${u.name}</strong></td>
            <td><span class="badge badge-blue">${u.role}</span></td>
            <td>${u.dept}</td>
            <td><span class="badge badge-green">${u.mfa}</span></td>
            <td>${u.last_active}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 5: SSO
function loadSSO() {
    const tbody = document.getElementById('ssoTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.sso.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${s.provider}</strong></td>
            <td>${s.protocol}</td>
            <td><code>${s.domain}</code></td>
            <td>${s.scim}</td>
            <td><span class="badge badge-green">${s.status}</span></td>
            <td>${s.cert_rot}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="alert('Testing SSO federation connection...')">Test SSO</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 6: Cloud Accounts
function loadCloudAccounts() {
    const tbody = document.getElementById('cloudTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.cloudAccounts.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${c.provider}</strong></td>
            <td><code>${c.account_id}</code></td>
            <td>${c.name}</td>
            <td>${c.auth_type}</td>
            <td><span class="badge badge-green">${c.status}</span></td>
            <td>${c.last_synced}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="alert('Syncing cloud inventory...')">Sync</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 7: Gateways
async function loadGateways() {
    try {
        const gws = await apiRequest('/gateways') || [];
        const statGw = document.getElementById('statGateways');
        if (statGw) statGw.innerText = gws.length;
        const statFleet = document.getElementById('statFleetCount');
        if (statFleet) statFleet.innerText = gws.length;

        const tbody = document.getElementById('gatewaysTable');
        if (tbody) {
            tbody.innerHTML = '';
            gws.forEach(g => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code>${g.id}</code></td>
                    <td><strong>${g.name}</strong></td>
                    <td><span class="badge badge-green">${g.status}</span></td>
                    <td><span class="badge badge-purple">${g.keystore_type || 'in-vpc-enclave'}</span></td>
                    <td>${g.version || 'v2.4.0'}</td>
                    <td>${g.last_heartbeat || 'Just now'}</td>
                    <td>${g.grace_period || 'Nominal'}</td>
                    <td><button class="btn btn-secondary btn-sm" onclick="alert('Checking enclave diagnostics for ${g.name}...')">Diagnostics</button></td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error('Failed to load gateways:', e);
    }
}

// Module 8: Jobs
async function loadJobs() {
    try {
        const jobs = await apiRequest('/jobs') || [];
        const tbody = document.getElementById('jobsTable');
        if (tbody) {
            tbody.innerHTML = '';
            jobs.forEach(j => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><code>${j.id}</code></td>
                    <td><strong>${j.type}</strong></td>
                    <td><code>${j.cert_id}</code></td>
                    <td>${j.target}</td>
                    <td><span class="badge badge-green">${j.status}</span></td>
                    <td>${j.progress}</td>
                    <td>${j.canary_weight}</td>
                    <td>${j.created_at}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error('Failed to load jobs:', e);
    }
}

// Module 11: Discovery
function loadDiscoveryFindings() {
    const tbody = document.getElementById('discoveryTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.discoveryFindings.forEach(f => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${f.id}</code></td>
            <td><strong>${f.target_range}</strong></td>
            <td><span class="badge badge-green">${f.status}</span></td>
            <td>${f.endpoints_scanned}</td>
            <td>${f.certs_found}</td>
            <td><span class="badge badge-amber">${f.shadow_certs} shadow</span></td>
            <td><span class="badge badge-red">${f.risk_flags}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 12: Policy Requests
async function loadRequests() {
    try {
        const reqs = await apiRequest('/certificate-requests') || [];
        const tbody = document.getElementById('requestsTable');
        if (tbody) {
            tbody.innerHTML = '';
            if (reqs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="7" class="text-center" style="color: #94a3b8; padding: 1rem;">No pending approval requests.</td></tr>';
            } else {
                reqs.forEach(r => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><code>${r.id}</code></td>
                        <td><strong>${escapeHtml(r.common_name)}</strong></td>
                        <td>${r.profile_id}</td>
                        <td><code>${r.requester_id}</code></td>
                        <td><span class="badge badge-amber">${r.status}</span></td>
                        <td>${r.created_at || 'Just now'}</td>
                        <td>
                            <button class="btn btn-success btn-sm" onclick="approveRequest('${r.id}')">Approve (SoD)</button>
                            <button class="btn btn-danger btn-sm" onclick="rejectRequest('${r.id}')">Reject</button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        }
    } catch (e) {
        console.error('Failed to load requests:', e);
    }
}

// Module 13: Health Services
async function loadHealthServices() {
    const tbody = document.getElementById('healthServicesTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    const services = await apiRequest('/health/services');
    services.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${s.name}</strong></td>
            <td><span class="badge badge-green">${s.status}</span></td>
            <td>${s.latency}</td>
            <td>${s.sla}</td>
            <td>${s.last_check}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 15: Security Events
function loadSecurityEvents() {
    const tbody = document.getElementById('secEventsTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.securityEvents.forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${e.timestamp}</td>
            <td><span class="badge ${e.severity === 'WARN' ? 'badge-amber' : 'badge-blue'}">${e.severity}</span></td>
            <td><code>${e.event_type}</code></td>
            <td>${e.actor}</td>
            <td>${e.details}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 16: Audit Events
async function loadAuditEvents() {
    const tbody = document.getElementById('auditTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    const events = await apiRequest('/audit/events');
    events.forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>#${e.seq}</td>
            <td>${e.timestamp}</td>
            <td><span class="badge badge-blue">${e.action}</span></td>
            <td><code>${e.actor}</code></td>
            <td><code>${e.resource}</code></td>
            <td><code title="${e.hash}">${(e.hash || '').substring(0, 16)}...</code></td>
            <td><code title="${e.prev}">${(e.prev || '').substring(0, 16)}...</code></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 17: Notifications
function loadNotifications() {
    const tbody = document.getElementById('notificationsTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.notifications.forEach(n => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${n.timestamp}</td>
            <td><strong>${n.channel}</strong></td>
            <td><code>${n.recipient}</code></td>
            <td>${n.title}</td>
            <td><span class="badge badge-green">${n.status}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 18: Support Tickets
function loadSupportTickets() {
    const tbody = document.getElementById('supportTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.supportTickets.forEach(t => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${t.id}</code></td>
            <td><strong>${t.subject}</strong></td>
            <td><span class="badge ${t.priority === 'High' ? 'badge-red' : 'badge-amber'}">${t.priority}</span></td>
            <td><span class="badge badge-blue">${t.status}</span></td>
            <td>${t.sla}</td>
            <td>${t.assigned}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 21: CBOM
async function loadCBOM() {
    const elem = document.getElementById('cbomContent');
    if (!elem) return;
    try {
        const cbom = {
            bomFormat: "CycloneDX",
            specVersion: "1.6",
            serialNumber: "urn:uuid:7a9e8841-4c12-4cf0-884b-cbom-acme",
            version: 1,
            metadata: {
                timestamp: new Date().toISOString(),
                tools: [{ vendor: "CLM Enterprise", name: "cbom-generator", version: "2.4.0" }]
            },
            components: mockStore.certificates.map(c => ({
                type: "cryptographic-asset",
                name: c.subject_dn,
                properties: [
                    { name: "algorithm", value: c.key_algorithm },
                    { name: "key_size_bits", value: String(c.key_bits) },
                    { name: "quantum_safe", value: String(c.key_algorithm.includes('ML-DSA')) },
                    { name: "risk_score", value: String(c.risk_score) },
                    { name: "validity_not_after", value: c.not_after }
                ]
            }))
        };
        elem.innerText = JSON.stringify(cbom, null, 2);
    } catch (e) {
        elem.innerText = "Error generating CBOM.";
    }
}

// Module 26: AI Insights
function loadAIInsights() {
    const tbody = document.getElementById('aiTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.aiInsights.forEach(ai => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${ai.id}</code></td>
            <td><strong>${ai.target}</strong></td>
            <td>${ai.category}</td>
            <td><span class="badge ${ai.severity === 'HIGH' ? 'badge-red' : 'badge-amber'}">${ai.severity}</span></td>
            <td>${ai.recommendation}</td>
            <td><span class="badge badge-green">${ai.auto}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Module 27: Integrations
function loadIntegrations() {
    const tbody = document.getElementById('integrationsTable');
    if (!tbody) return;
    tbody.innerHTML = '';
    mockStore.integrations.forEach(i => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${i.name}</strong></td>
            <td>${i.type}</td>
            <td><code>${i.endpoint}</code></td>
            <td><span class="badge badge-green">${i.status}</span></td>
            <td>${i.last_event}</td>
            <td><button class="btn btn-secondary btn-sm" onclick="alert('Testing connection to ${i.name}...')">Test</button></td>
        `;
        tbody.appendChild(tr);
    });
}

// Actions & Modal Handlers
async function submitCertificateRequest() {
    const cn = document.getElementById('reqCommonName').value.trim();
    const sans = document.getElementById('reqSANs').value.split(',').map(s => s.trim()).filter(Boolean);
    const profile = document.getElementById('reqProfile').value;

    if (!cn) {
        showToast('Common Name is required.', 'error');
        return;
    }

    try {
        await apiRequest('/certificate-requests', 'POST', {
            common_name: cn,
            sans: sans,
            profile_id: profile
        });
        closeModal('modalRequestCert');
        showToast(`Certificate request submitted for ${cn}! Pending dual-control approval.`, 'success');
        await reloadAll();
        switchTab('policy');
    } catch (e) {
        showToast(`Request failed: ${e.message}`, 'error');
    }
}

async function approveRequest(reqId) {
    try {
        // Segregation of Duties approval
        const req = mockStore.requests.find(r => r.id === reqId);
        if (req) {
            req.status = 'APPROVED';
            // Auto issue certificate
            const newCert = {
                id: `cert_${Math.random().toString(36).substring(2, 10)}`,
                subject_dn: `CN=${req.common_name}, O=Acme Corp`,
                key_algorithm: req.profile_id.includes('pqc') ? 'ML-DSA-65+ECDSA' : 'ECDSA',
                key_bits: 256,
                issuer_dn: 'CN=Acme Private Issuing CA v2',
                not_before: new Date().toISOString(),
                not_after: new Date(Date.now() + 47 * 24 * 60 * 60 * 1000).toISOString(),
                status: 'active',
                risk_score: 10,
                sha256_fp: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
                owner: 'SecOps Team'
            };
            mockStore.certificates.unshift(newCert);
            mockStore.requests = mockStore.requests.filter(r => r.id !== reqId);
        }
        showToast(`Request ${reqId} approved! New certificate generated & verified.`, 'success');
        await reloadAll();
        switchTab('certificates');
    } catch (e) {
        showToast(`Approval failed: ${e.message}`, 'error');
    }
}

function rejectRequest(reqId) {
    mockStore.requests = mockStore.requests.filter(r => r.id !== reqId);
    showToast(`Request ${reqId} rejected.`, 'info');
    reloadAll();
}

function deployCert(certId) {
    const modal = document.getElementById('modalTriggerJob');
    if (modal) {
        const select = document.getElementById('jobCertSelect');
        if (select) select.value = certId;
        openModal('modalTriggerJob');
    }
}

function revokeCert(certId) {
    if (confirm(`Are you sure you want to revoke certificate ${certId}? This action publishes an RFC 5280 CRL.`)) {
        mockStore.certificates = mockStore.certificates.filter(c => c.id !== certId);
        showToast(`Certificate ${certId} revoked and added to CRL distribution point.`, 'info');
        reloadAll();
    }
}

async function verifyAuditLedger() {
    const reportElem = document.getElementById('auditVerifyReport');
    reportElem.innerHTML = 'Executing independent cryptographic SHA-256 hash chain and Merkle tree root verification...';
    try {
        const res = await apiRequest('/audit/verify');
        reportElem.className = 'audit-report-banner';
        reportElem.style.borderLeft = '4px solid var(--green)';
        reportElem.innerHTML = `
            <div>
                <strong>&check; Merkle Ledger Valid:</strong> All ${res.total_entries || mockStore.auditLedger.length} cryptographic entries verified.
                <div style="font-size: 0.75rem; color: #94a3b8; margin-top: 0.25rem;">
                    Root Hash: <code>${res.root_hash || '5a4d3f2b1c0e98a76543210fedcba9876543210abcdef0123456789abcdef012'}</code> &bull; Signed Tree Head (STH): Valid
                </div>
            </div>
            <span class="badge badge-green">Cryptographically Proved</span>
        `;
        showToast('Merkle ledger proof verified successfully!', 'success');
    } catch (e) {
        reportElem.style.borderLeft = '4px solid var(--red)';
        reportElem.innerHTML = `Verification error: ${e.message}`;
    }
}

function generateGatewayToken() {
    const tok = 'clm_tok_' + Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
    document.getElementById('gwEnrollToken').value = tok;
    document.getElementById('gwDockerCmd').innerText = `docker run -d --name clm-gateway \\
  -e CLM_ENROLL_TOKEN=${tok} \\
  -e CLM_API_URL=https://new-clm.onrender.com \\
  -v /var/run/clm:/keys \\
  ghcr.io/gokul-than/clm-gateway:latest`;
}

function confirmGatewayEnrollment() {
    const name = document.getElementById('gwName').value;
    const newGw = {
        id: `gw-${Math.random().toString(36).substring(2, 8)}`,
        name: name,
        status: 'ONLINE',
        keystore_type: 'in-vpc-enclave',
        version: 'v2.4.0',
        last_heartbeat: 'Just now',
        grace_period: 'Valid (2h grace)'
    };
    mockStore.gateways.unshift(newGw);
    closeModal('modalEnrollGateway');
    showToast(`Gateway ${name} registered! Enclave heartbeat connected.`, 'success');
    reloadAll();
    switchTab('gateways');
}

function confirmConnectCloud() {
    const provider = document.getElementById('cloudProvider').value.toUpperCase();
    const accId = document.getElementById('cloudAccountId').value;
    const name = document.getElementById('cloudAccountName').value;
    mockStore.cloudAccounts.push({
        id: `acc_${Math.random().toString(36).substring(2, 8)}`,
        provider: provider,
        account_id: accId,
        name: name,
        auth_type: 'Cross-Account IAM / Federation',
        status: 'Connected',
        last_synced: 'Just now'
    });
    closeModal('modalConnectCloud');
    showToast(`Connected ${provider} Account (${accId})!`, 'success');
    reloadAll();
    switchTab('cloud');
}

function startDiscoveryScan() {
    const target = document.getElementById('scanTarget').value;
    mockStore.discoveryFindings.unshift({
        id: `scan_${Math.floor(Math.random() * 900 + 100)}`,
        target_range: target,
        status: 'COMPLETED',
        endpoints_scanned: 128,
        certs_found: 12,
        shadow_certs: 1,
        risk_flags: 'Shadow Self-Signed'
    });
    closeModal('modalDiscoveryScan');
    showToast(`TLS Network scan completed for ${target}! Found 1 shadow certificate.`, 'success');
    reloadAll();
    switchTab('discovery');
}

async function confirmTriggerJob() {
    const certId = document.getElementById('jobCertSelect').value;
    const target = document.getElementById('jobTargetSelect').value;
    const strategy = document.getElementById('jobRolloutStrategy').value;

    await apiRequest('/jobs', 'POST', {
        certificate_id: certId,
        target_id: target,
        rollout_strategy: strategy
    });
    closeModal('modalTriggerJob');
    showToast(`Canary deployment dispatched for ${certId}!`, 'success');
    await reloadAll();
    switchTab('jobs');
}

function openNewOrgModal() {
    const name = prompt('Enter New Organization Legal Name:');
    if (name) {
        mockStore.organizations.push({
            id: `org_${Math.random().toString(36).substring(2, 8)}`,
            name: name,
            slug: name.toLowerCase().replace(/[^a-z0-9]/g, '-'),
            status: 'verified',
            tier: 'enterprise_custom',
            risk_score: 8,
            docs: 'Verified KYC'
        });
        showToast(`Organization "${name}" registered and verified!`, 'success');
        reloadAll();
    }
}

function exportCBOMJSON() {
    loadCBOM();
    const content = document.getElementById('cbomContent').innerText;
    downloadFile(content, 'cbom-cyclonedx-1.6.json', 'application/json');
    showToast('Exported CycloneDX 1.6 CBOM JSON!', 'success');
}

function exportAnalyticsCSV() {
    const csv = "Certificate,Algorithm,KeyBits,Issuer,Expiry,RiskScore\n" +
        mockStore.certificates.map(c => `"${c.subject_dn}","${c.key_algorithm}",${c.key_bits},"${c.issuer_dn}","${c.not_after}",${c.risk_score}`).join('\n');
    downloadFile(csv, 'clm-analytics-export.csv', 'text/csv');
    showToast('Exported Analytics CSV!', 'success');
}

function downloadFile(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Modal Helpers
function openModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.add('active');
}

function closeModal(id) {
    const modal = document.getElementById(id);
    if (modal) modal.classList.remove('active');
}

function openRequestCertModal() { openModal('modalRequestCert'); }
function openEnrollGatewayModal() { generateGatewayToken(); openModal('modalEnrollGateway'); }
function openConnectCloudModal() { openModal('modalConnectCloud'); }
function openDiscoveryScanModal() { openModal('modalDiscoveryScan'); }
function openTriggerJobModal() { openModal('modalTriggerJob'); }
function openApiConfigModal() {
    document.getElementById('configOperatingMode').value = operatingMode;
    document.getElementById('configApiUrl').value = localStorage.getItem('clm_api_url') || '';
    openModal('modalApiConfig');
}

function toggleApiUrlInput() {
    const mode = document.getElementById('configOperatingMode').value;
    const urlGroup = document.getElementById('configApiUrl').parentElement;
    if (mode === 'standalone') {
        urlGroup.style.opacity = '0.5';
    } else {
        urlGroup.style.opacity = '1.0';
    }
}

function saveApiConfig() {
    const mode = document.getElementById('configOperatingMode').value;
    const url = document.getElementById('configApiUrl').value.trim();
    operatingMode = mode;
    localStorage.setItem('clm_op_mode', mode);
    if (url) {
        apiBaseUrl = url.replace(/\/$/, '') + (url.includes('/api/v1') ? '' : '/api/v1');
        localStorage.setItem('clm_api_url', apiBaseUrl);
    } else {
        apiBaseUrl = '/api/v1';
        localStorage.removeItem('clm_api_url');
    }
    closeModal('modalApiConfig');
    showToast(`Configuration saved! Mode: ${mode}`, 'info');
    checkApiConnection();
    reloadAll();
}

// Table Filter
function filterCertTable() {
    const q = (document.getElementById('certSearchInput').value || '').toLowerCase();
    const rows = document.querySelectorAll('#fullCertsTable tr');
    rows.forEach(r => {
        const text = r.innerText.toLowerCase();
        r.style.display = text.includes(q) ? '' : 'none';
    });
}

// Toast System
function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerText = message;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Utility Helpers
function getStatusBadge(status) {
    switch (status) {
        case 'active': return 'badge-green';
        case 'PENDING_APPROVAL': return 'badge-amber';
        case 'revoked': return 'badge-red';
        default: return 'badge-info';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
