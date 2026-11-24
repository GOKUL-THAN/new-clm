const API_BASE = '/api/v1';

let currentTenant = 'tenant_default';
let allCerts = [];

document.addEventListener('DOMContentLoaded', () => {
    reloadAll();
});

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
        certificates: 'Certificates Inventory',
        requests: 'Requests & Approvals',
        gateways: 'Satellite Gateways',
        cbom: 'CBOM & Post-Quantum',
        audit: 'Merkle Audit Ledger'
    };
    document.getElementById('currentViewTitle').innerText = titles[tabId] || 'Overview';

    if (tabId === 'cbom') loadCBOM();
    if (tabId === 'audit') loadAuditEvents();
}

async function apiRequest(endpoint, method = 'GET', body = null) {
    const headers = {
        'Content-Type': 'application/json',
        'X-Tenant-ID': currentTenant
    };
    const options = { method, headers };
    if (body) {
        options.body = JSON.stringify(body);
    }
    const res = await fetch(`${API_BASE}${endpoint}`, options);
    if (!res.ok) {
        const err = await res.json().catch(() => ({ title: 'Error', detail: res.statusText }));
        throw new Error(err.detail || err.title || 'API Request Failed');
    }
    return res.json();
}

async function reloadAll() {
    currentTenant = document.getElementById('tenantSelect').value;
    await Promise.all([
        loadCertificates(),
        loadRequests(),
        loadGateways()
    ]);
}

async function loadCertificates() {
    try {
        const certs = await apiRequest('/certificates') || [];
        allCerts = certs;

        // Update stats
        document.getElementById('statTotalCerts').innerText = certs.length;
        
        const now = new Date();
        const expiringSoon = certs.filter(c => {
            const exp = new Date(c.not_after);
            const days = (exp - now) / (1000 * 60 * 60 * 24);
            return days > 0 && days <= 30;
        });
        document.getElementById('statExpiringSoon').innerText = expiringSoon.length;

        // Render dashboard table
        const dashTbody = document.getElementById('dashboardCertsTable');
        dashTbody.innerHTML = '';
        if (certs.length === 0) {
            dashTbody.innerHTML = '<tr><td colspan="7" class="text-center" style="padding: 2rem; color: #94a3b8;">No certificates issued yet. Click "+ Request Certificate" to issue one.</td></tr>';
        } else {
            certs.slice(0, 5).forEach(c => {
                const tr = document.createElement('tr');
                const days = Math.round((new Date(c.not_after) - now) / (1000 * 60 * 60 * 24));
                tr.innerHTML = `
                    <td><strong>${escapeHtml(c.subject_dn)}</strong></td>
                    <td><span class="badge ${getStatusBadge(c.status)}">${c.status}</span></td>
                    <td>${c.key_algorithm} (${c.key_bits}b)</td>
                    <td>${escapeHtml(c.issuer_dn)}</td>
                    <td>${days > 0 ? days + ' days' : 'Expired'}</td>
                    <td><span class="badge ${c.risk_score > 30 ? 'badge-amber' : 'badge-green'}">${c.risk_score} / 100</span></td>
                    <td>
                        <button class="btn btn-secondary" onclick="deployCert('${c.id}')">Deploy</button>
                        <button class="btn btn-danger" onclick="revokeCert('${c.id}')">Revoke</button>
                    </td>
                `;
                dashTbody.appendChild(tr);
            });
        }

        // Render full table
        renderFullCertTable(certs);
    } catch (e) {
        console.error('Failed to load certificates:', e);
    }
}

function renderFullCertTable(certs) {
    const tbody = document.getElementById('fullCertsTable');
    tbody.innerHTML = '';
    if (certs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center">No certificates match query.</td></tr>';
        return;
    }

    certs.forEach(c => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><code>${c.fingerprint_sha256.substring(0, 16)}...</code></td>
            <td><strong>${escapeHtml(c.subject_dn)}</strong><br><small style="color: #94a3b8;">${(c.sans || []).join(', ')}</small></td>
            <td>${c.key_algorithm}</td>
            <td><span class="badge ${getStatusBadge(c.status)}">${c.status}</span></td>
            <td>${formatDate(c.not_before)} to ${formatDate(c.not_after)}</td>
            <td>${escapeHtml(c.owner)} (${escapeHtml(c.team)})</td>
            <td>
                <button class="btn btn-danger" onclick="revokeCert('${c.id}')">Revoke</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterCertTable() {
    const query = document.getElementById('certSearchInput').value.toLowerCase();
    const filtered = allCerts.filter(c => 
        c.subject_dn.toLowerCase().includes(query) ||
        (c.sans && c.sans.some(s => s.toLowerCase().includes(query))) ||
        (c.owner && c.owner.toLowerCase().includes(query))
    );
    renderFullCertTable(filtered);
}

async function loadRequests() {
    try {
        const reqs = await apiRequest('/certificate-requests') || [];
        const tbody = document.getElementById('requestsTable');
        tbody.innerHTML = '';

        if (reqs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No pending or active requests.</td></tr>';
            return;
        }

        reqs.forEach(r => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code>${r.id}</code></td>
                <td><strong>${escapeHtml(r.common_name)}</strong></td>
                <td>${r.profile_id}</td>
                <td>${escapeHtml(r.requester)} (${escapeHtml(r.team)})</td>
                <td><span class="badge ${getStatusBadge(r.status)}">${r.status}</span></td>
                <td>${formatDate(r.created_at)}</td>
                <td>
                    ${r.status === 'PendingApproval' ? `
                        <button class="btn btn-success" onclick="approveRequest('${r.id}', 'bob')">Approve (SoD: bob)</button>
                    ` : '<span style="color: #94a3b8;">Processed</span>'}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to load requests:', e);
    }
}

async function loadGateways() {
    try {
        const gateways = await apiRequest('/gateways') || [];
        document.getElementById('statGateways').innerText = gateways.length;

        const tbody = document.getElementById('gatewaysTable');
        tbody.innerHTML = '';
        if (gateways.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No Satellite Gateways registered yet. Click "+ Enroll Gateway".</td></tr>';
            return;
        }

        gateways.forEach(g => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><code>${g.id}</code></td>
                <td><strong>${escapeHtml(g.name)}</strong></td>
                <td><span class="badge badge-green">${g.status}</span></td>
                <td><span class="badge badge-purple">${g.keystore_type}</span></td>
                <td>v${g.version}</td>
                <td>${formatDate(g.last_seen_at)}</td>
                <td>${g.policy_grace || '72h'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to load gateways:', e);
    }
}

async function loadCBOM() {
    try {
        const cbom = await apiRequest('/reports/cbom');
        document.getElementById('cbomContent').innerText = JSON.stringify(cbom, null, 2);
    } catch (e) {
        document.getElementById('cbomContent').innerText = 'Failed to load CBOM: ' + e.message;
    }
}

async function loadAuditEvents() {
    try {
        const events = await apiRequest('/audit/events') || [];
        const tbody = document.getElementById('auditTable');
        tbody.innerHTML = '';

        events.forEach(ev => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>#${ev.sequence}</td>
                <td>${formatDate(ev.timestamp)}</td>
                <td><strong>${escapeHtml(ev.actor)}</strong></td>
                <td><code>${ev.action}</code></td>
                <td>${ev.target_type} (${ev.target_id})</td>
                <td><span class="badge ${ev.policy_decision === 'allow' ? 'badge-green' : 'badge-amber'}">${ev.policy_decision}</span></td>
                <td><code>${(ev.hash || '').substring(0, 16)}...</code></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Failed to load audit events:', e);
    }
}

async function verifyAuditLedger() {
    const banner = document.getElementById('auditVerifyReport');
    banner.innerText = 'Calculating Merkle proofs and verifying cryptographic hash chain...';
    try {
        const res = await apiRequest('/audit/verify');
        banner.innerHTML = `
            <strong>Audit Verification Report (Tenant: ${res.tenant_id})</strong><br>
            Events checked: <strong>${res.events_checked}</strong><br>
            Hash chain integrity: <strong style="color: #10b981;">${res.hash_chain_valid ? 'OK (Unbroken)' : 'FAILED'}</strong><br>
            Signed Tree Heads: <strong style="color: #10b981;">${res.signed_tree_heads_valid ? 'OK (Anchored)' : 'FAILED'}</strong><br>
            Gaps or deletions: <strong>${res.gaps_detected}</strong><br>
            Merkle Root: <code>${res.root_hash}</code>
        `;
    } catch (e) {
        banner.innerText = 'Verification failed: ' + e.message;
    }
}

// Modal and Form actions
function openRequestCertModal() {
    document.getElementById('requestModal').classList.add('open');
}

function openEnrollGatewayModal() {
    document.getElementById('enrollGatewayModal').classList.add('open');
}

function closeModal(id) {
    document.getElementById(id).classList.remove('open');
}

async function submitCertRequest() {
    const cn = document.getElementById('reqCN').value;
    const sansStr = document.getElementById('reqSANs').value;
    const owner = document.getElementById('reqOwner').value;
    const team = document.getElementById('reqTeam').value;
    const profile = document.getElementById('reqProfile').value;
    const alg = document.getElementById('reqAlg').value;

    if (!cn || !owner || !team) {
        alert('Please fill in Common Name, Accountable Owner, and Team (mandatory governance rules).');
        return;
    }

    const sans = sansStr ? sansStr.split(',').map(s => s.trim()) : [cn];

    const body = {
        profile_id: profile,
        environment_id: 'env_aws_prod',
        common_name: cn,
        sans: sans,
        key_algorithm: alg,
        key_bits: alg.includes('2048') ? 2048 : 256,
        owner: owner,
        team: team,
        requester: owner
    };

    try {
        const res = await apiRequest('/certificate-requests', 'POST', body);
        closeModal('requestModal');
        alert(res.message || 'Certificate request processed successfully!');
        reloadAll();
    } catch (e) {
        alert('Request submission failed: ' + e.message);
    }
}

async function approveRequest(reqID, approver) {
    try {
        const res = await apiRequest('/approvals', 'POST', {
            request_id: reqID,
            approver: approver,
            decision: 'approved',
            comments: 'Approved by authorized peer'
        });
        alert('Request approved! Certificate issued.');
        reloadAll();
    } catch (e) {
        alert('Approval failed: ' + e.message);
    }
}

async function revokeCert(certID) {
    if (!confirm('Are you sure you want to revoke this certificate?')) return;
    try {
        await apiRequest(`/certificates/${certID}/revoke`, 'POST', {
            reason: 'keyCompromise',
            actor: 'admin'
        });
        alert('Certificate revoked successfully.');
        reloadAll();
    } catch (e) {
        alert('Revocation failed: ' + e.message);
    }
}

async function deployCert(certID) {
    try {
        const res = await apiRequest(`/certificates/${certID}/deploy`, 'POST', {
            target_id: 'tgt_prod_lb'
        });
        alert('Deployment and post-TLS verification passed! Status: Active');
        reloadAll();
    } catch (e) {
        alert('Deployment failed: ' + e.message);
    }
}

async function createEnrollmentToken() {
    try {
        const res = await apiRequest('/gateways/enrollment-tokens', 'POST', {
            environment_id: 'env_aws_prod'
        });
        document.getElementById('enrollTokenDisplay').style.display = 'block';
        document.getElementById('tokenText').value = res.token;
        document.getElementById('helmCommand').innerText = `helm install clm-gateway ./deploy/helm/gateway \\\n  --set controlPlane.url=${window.location.origin} \\\n  --set enrollment.token=${res.token}`;
    } catch (e) {
        alert('Failed to generate token: ' + e.message);
    }
}

function exportCBOMJSON() {
    const text = document.getElementById('cbomContent').innerText;
    const blob = new Blob([text], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cbom-${currentTenant}.json`;
    a.click();
}

// Helpers
function getStatusBadge(status) {
    switch (status) {
        case 'Active': return 'badge-green';
        case 'Issued': return 'badge-info';
        case 'PendingApproval': return 'badge-amber';
        case 'Revoked': return 'badge-red';
        case 'DeployFailed': return 'badge-red';
        default: return 'badge-purple';
    }
}

function formatDate(isoStr) {
    if (!isoStr) return '-';
    const d = new Date(isoStr);
    return d.toISOString().split('T')[0];
}

function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>"']/g, m => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    })[m]);
}
