/* SecureScan Pro - Frontend Logic */

let currentScan = null;
let pollInterval = null;
let currentScanData = null;
const API_BASE = '';

/* Check rate limit on page load */
(async function checkRateLimit() {
    try {
        const hdrs = {};
        const tk = localStorage.getItem('ssp_token');
        if (tk) hdrs['Authorization'] = 'Bearer ' + tk;
        const resp = await fetch(`${API_BASE}/api/rate-limit`, { headers: hdrs });
        const data = await resp.json();
        const banner = document.getElementById('rateLimitBanner');
        if (banner && data.plan === 'free') {
            document.getElementById('scansRemaining').textContent = data.remaining;
            if (data.remaining <= data.limit) banner.style.display = 'flex';
            if (data.remaining <= 0) {
                banner.innerHTML = '<span>Free plan limit reached. <a href="/pricing">Upgrade to Pro ($29/mo)</a> for unlimited scans.</span>';
                banner.style.display = 'flex';
            }
        }
    } catch(e) {}
})();

/* Scan Options Toggle */
document.querySelectorAll('.scan-option').forEach(opt => {
    opt.addEventListener('click', () => {
        opt.classList.toggle('active');
        const cb = opt.querySelector('input');
        cb.checked = !cb.checked;
    });
});

/* URL Input Enter Key */
document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') startScan();
});

/* Start Scan */
async function startScan() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
        document.getElementById('urlInput').focus();
        return;
    }

    const scanTypes = [];
    document.querySelectorAll('.scan-option.active').forEach(opt => {
        scanTypes.push(opt.dataset.type);
    });

    if (scanTypes.length === 0) {
        alert('Please select at least one scan type.');
        return;
    }
    if (!scanTypes.includes('threat_intel')) scanTypes.push('threat_intel');
    if (!scanTypes.includes('subdomains')) scanTypes.push('subdomains');

    const btn = document.getElementById('scanBtn');
    btn.disabled = true;
    document.getElementById('scanBtnText').textContent = 'Scanning...';
    document.getElementById('scanBtnIcon').textContent = '\u23F3';

    document.getElementById('resultsSection').classList.remove('active');
    document.getElementById('progressSection').classList.add('active');
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressPercent').textContent = '0%';
    document.getElementById('progressModule').textContent = 'Starting scan...';

    try {
        const hdrs = { 'Content-Type': 'application/json' };
        const tk = localStorage.getItem('ssp_token');
        if (tk) hdrs['Authorization'] = 'Bearer ' + tk;
        const resp = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST',
            headers: hdrs,
            body: JSON.stringify({ url, scan_types: scanTypes }),
        });
        if (resp.status === 429) {
            const err = await resp.json();
            alert(err.detail || 'Rate limit reached. Please upgrade to Pro.');
            resetScanBtn();
            document.getElementById('progressSection').classList.remove('active');
            return;
        }
        const data = await resp.json();
        currentScan = data.scan_id;
        pollScanStatus();
    } catch (err) {
        alert('Failed to start scan: ' + err.message);
        resetScanBtn();
    }
}

/* Poll Scan Status */
function pollScanStatus() {
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(async () => {
        try {
            const resp = await fetch(`${API_BASE}/api/scan/${currentScan}`);
            const data = await resp.json();

            document.getElementById('progressBar').style.width = data.progress + '%';
            document.getElementById('progressPercent').textContent = data.progress + '%';

            if (data.current_module) {
                document.getElementById('progressModule').textContent = `Scanning: ${data.current_module}`;
            }

            if (data.status === 'completed') {
                clearInterval(pollInterval);
                document.getElementById('progressSection').classList.remove('active');
                resetScanBtn();
                currentScanData = data;
                renderResults(data);
            } else if (data.status === 'error') {
                clearInterval(pollInterval);
                document.getElementById('progressModule').textContent = 'Error: ' + data.error;
                resetScanBtn();
            }
        } catch (err) {
            console.error('Poll error:', err);
        }
    }, 1000);
}

function resetScanBtn() {
    const btn = document.getElementById('scanBtn');
    btn.disabled = false;
    document.getElementById('scanBtnText').textContent = 'Start Scan';
    document.getElementById('scanBtnIcon').textContent = '\uD83D\uDD0D';
}

/* Render Results */
function renderResults(data) {
    const section = document.getElementById('resultsSection');
    section.classList.add('active');
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    renderSummary(data);
    renderTabContents(data);
}

function renderSummary(data) {
    const grid = document.getElementById('summaryGrid');
    const s = data.summary;
    const sev = s.by_severity || {};

    grid.innerHTML = `
        <div class="summary-card grade-card grade-${s.grade}">
            <div class="number">${s.grade}</div>
            <div class="label">Security Grade</div>
        </div>
        <div class="summary-card">
            <div class="number">${s.total_issues || 0}</div>
            <div class="label">Total Issues</div>
        </div>
        <div class="summary-card">
            <div class="number severity-critical">${sev.critical || 0}</div>
            <div class="label">Critical</div>
        </div>
        <div class="summary-card">
            <div class="number severity-high">${sev.high || 0}</div>
            <div class="label">High</div>
        </div>
        <div class="summary-card">
            <div class="number severity-medium">${sev.medium || 0}</div>
            <div class="label">Medium</div>
        </div>
        <div class="summary-card">
            <div class="number severity-low">${sev.low || 0}</div>
            <div class="label">Low</div>
        </div>
    `;
}

function renderTabContents(data) {
    const container = document.getElementById('tabContents');
    container.innerHTML = `
        <div class="tab-content active" id="tab-overview">${renderOverview(data)}</div>
        <div class="tab-content" id="tab-ssl">${renderSSL(data.results.ssl)}</div>
        <div class="tab-content" id="tab-headers">${renderHeaders(data.results.headers)}</div>
        <div class="tab-content" id="tab-ports">${renderPorts(data.results.ports)}</div>
        <div class="tab-content" id="tab-dns">${renderDNS(data.results.dns)}</div>
        <div class="tab-content" id="tab-tech">${renderTech(data.results.tech)}</div>
        <div class="tab-content" id="tab-vulns">${renderVulns(data.results.vulns)}</div>
        <div class="tab-content" id="tab-enterprise">${renderEnterprise(data.results.enterprise)}</div>
        <div class="tab-content" id="tab-threat_intel">${renderThreatIntel(data.results.threat_intel)}</div>
        <div class="tab-content" id="tab-compliance">${renderCompliance(data.results.compliance, data.all_issues)}</div>
        <div class="tab-content" id="tab-subdomains">${renderSubdomains(data.results.subdomains)}</div>
        <div class="tab-content" id="tab-credentials">${renderCredentials(data.credential_tests)}</div>
        <div class="tab-content" id="tab-pricing">${renderPricing(data.agency_pricing)}</div>
    `;
}

function switchTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelector(`.tab[data-tab="${tabId}"]`).classList.add('active');
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.getElementById(`tab-${tabId}`).classList.add('active');
}

function issueCard(issue) {
    const sevClass = `sev-${issue.severity || 'info'}`;
    return `
        <div class="issue-card">
            <span class="issue-severity ${sevClass}">${(issue.severity || 'info').toUpperCase()}</span>
            <div class="issue-body">
                <div class="issue-title">${esc(issue.title || '')}</div>
                <div class="issue-desc">${esc(issue.description || '')}</div>
                ${issue.recommendation ? `<div class="issue-recommendation">\u2705 ${esc(issue.recommendation)}</div>` : ''}
            </div>
        </div>
    `;
}

function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

/* Tab Renderers */
function renderOverview(data) {
    const issues = data.all_issues || [];
    if (issues.length === 0) return '<div class="empty-state"><div class="empty-state-icon">\u2705</div><div class="empty-state-text">No issues found! Your website looks secure.</div></div>';

    const sorted = [...issues].sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity] ?? 4) - (order[b.severity] ?? 4);
    });

    return `
        <div class="section-header">
            <h2 class="section-title">All Issues (${issues.length})</h2>
        </div>
        <div class="issue-list">${sorted.map(issueCard).join('')}</div>
    `;
}

function renderSSL(ssl) {
    if (!ssl) return '<div class="empty-state"><div class="empty-state-text">SSL scan not performed.</div></div>';
    if (ssl.error && !ssl.valid) return `<div class="issue-card"><span class="issue-severity sev-critical">ERROR</span><div class="issue-body"><div class="issue-title">SSL Check Failed</div><div class="issue-desc">${esc(ssl.error)}</div></div></div>`;

    let html = `
        <table class="detail-table">
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Valid</td><td><span class="tag ${ssl.valid ? 'tag-present' : 'tag-missing'}">${ssl.valid ? 'Yes' : 'No'}</span></td></tr>
            <tr><td>Issuer</td><td>${esc(ssl.issuer)}</td></tr>
            <tr><td>Subject</td><td>${esc(ssl.subject)}</td></tr>
            <tr><td>Expires</td><td>${esc(ssl.expires)} (${ssl.days_until_expiry} days)</td></tr>
            <tr><td>Protocol</td><td>${esc(ssl.protocol)}</td></tr>
            <tr><td>Cipher</td><td>${esc(ssl.cipher)}</td></tr>
            <tr><td>Key Size</td><td>${ssl.key_size} bits</td></tr>
            <tr><td>SAN Domains</td><td>${(ssl.san_domains || []).map(d => `<span class="tag tag-tech">${esc(d)}</span> `).join('')}</td></tr>
        </table>
    `;

    if (ssl.issues && ssl.issues.length > 0) {
        html += `<div class="issue-list">${ssl.issues.map(issueCard).join('')}</div>`;
    }
    return html;
}

function renderHeaders(headers) {
    if (!headers) return '<div class="empty-state"><div class="empty-state-text">Header scan not performed.</div></div>';

    let html = `
        <div class="summary-grid" style="margin-bottom:24px;">
            <div class="summary-card grade-card grade-${headers.grade}">
                <div class="number">${headers.grade}</div>
                <div class="label">Header Score: ${headers.score}/100</div>
            </div>
        </div>
        <h3 style="margin-bottom:12px;font-size:16px;">Present Security Headers</h3>
        <table class="detail-table">
            <tr><th>Header</th><th>Value</th><th>Status</th></tr>
    `;

    const present = headers.present_headers || {};
    for (const [name, val] of Object.entries(present)) {
        html += `<tr><td>${esc(name)}</td><td style="max-width:400px;word-break:break-all;font-size:12px;">${esc(val)}</td><td><span class="tag tag-present">Present</span></td></tr>`;
    }

    const missing = headers.missing_headers || [];
    for (const m of missing) {
        html += `<tr><td>${esc(m.title.replace('Missing ', ''))}</td><td style="font-size:12px;color:var(--text-muted);">${esc(m.description)}</td><td><span class="tag tag-missing">Missing</span></td></tr>`;
    }

    html += '</table>';

    if (headers.issues && headers.issues.length > 0) {
        html += `<h3 style="margin:24px 0 12px;font-size:16px;">Issues (${headers.issues.length})</h3><div class="issue-list">${headers.issues.map(issueCard).join('')}</div>`;
    }
    return html;
}

function renderPorts(ports) {
    if (!ports) return '<div class="empty-state"><div class="empty-state-text">Port scan not performed.</div></div>';

    let html = `
        <div class="summary-grid" style="margin-bottom:24px;">
            <div class="summary-card"><div class="number">${ports.total_scanned || 0}</div><div class="label">Ports Scanned</div></div>
            <div class="summary-card"><div class="number severity-high">${(ports.open_ports || []).length}</div><div class="label">Open Ports</div></div>
        </div>
        <p style="margin-bottom:12px;color:var(--text-secondary);">IP: <strong>${esc(ports.ip_address || 'N/A')}</strong></p>
        <table class="detail-table">
            <tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr>
    `;

    for (const p of (ports.open_ports || [])) {
        html += `<tr><td><strong>${p.port}</strong></td><td>${esc(p.service)}</td><td><span class="tag tag-open">Open</span></td><td style="font-size:12px;">${esc(p.banner || '-')}</td></tr>`;
    }

    html += '</table>';

    if (ports.issues && ports.issues.length > 0) {
        html += `<div class="issue-list" style="margin-top:20px;">${ports.issues.map(issueCard).join('')}</div>`;
    }
    return html;
}

function renderDNS(dns) {
    if (!dns) return '<div class="empty-state"><div class="empty-state-text">DNS scan not performed.</div></div>';

    let html = `
        <table class="detail-table">
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Hostname</td><td>${esc(dns.hostname)}</td></tr>
            <tr><td>IP Addresses</td><td>${(dns.ip_addresses || []).map(ip => `<span class="tag tag-tech">${esc(ip)}</span> `).join('')}</td></tr>
            <tr><td>Reverse DNS</td><td>${esc(dns.reverse_dns || 'N/A')}</td></tr>
            <tr><td>SPF Record</td><td><span class="tag ${dns.has_spf ? 'tag-present' : 'tag-missing'}">${dns.has_spf ? 'Found' : 'Missing'}</span></td></tr>
            <tr><td>DMARC Record</td><td><span class="tag ${dns.has_dmarc ? 'tag-present' : 'tag-missing'}">${dns.has_dmarc ? 'Found' : 'Missing'}</span></td></tr>
            <tr><td>DKIM</td><td><span class="tag ${dns.has_dkim ? 'tag-present' : 'tag-missing'}">${dns.has_dkim ? 'Found' : 'Missing'}</span></td></tr>
        </table>
    `;

    if (dns.ping_result) {
        const p = dns.ping_result;
        html += `
            <h3 style="margin:20px 0 12px;font-size:16px;">Ping Results</h3>
            <table class="detail-table">
                <tr><th>Property</th><th>Value</th></tr>
                <tr><td>Reachable</td><td><span class="tag ${p.reachable ? 'tag-present' : 'tag-missing'}">${p.reachable ? 'Yes' : 'No'}</span></td></tr>
                ${p.transmitted ? `<tr><td>Packets</td><td>${p.transmitted} sent / ${p.received} received (${p.packet_loss} loss)</td></tr>` : ''}
                ${p.avg_ms ? `<tr><td>Latency</td><td>min: ${p.min_ms}ms / avg: ${p.avg_ms}ms / max: ${p.max_ms}ms</td></tr>` : ''}
            </table>
        `;
    }

    if (dns.records && dns.records.length > 0) {
        html += `
            <h3 style="margin:20px 0 12px;font-size:16px;">DNS Records (${dns.records.length})</h3>
            <table class="detail-table">
                <tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr>
        `;
        for (const r of dns.records) {
            html += `<tr><td><span class="tag tag-tech">${esc(r.record_type)}</span></td><td>${esc(r.name)}</td><td style="max-width:400px;word-break:break-all;font-size:12px;">${esc(r.value)}</td><td>${r.ttl}</td></tr>`;
        }
        html += '</table>';
    }

    if (dns.issues && dns.issues.length > 0) {
        html += `<div class="issue-list" style="margin-top:20px;">${dns.issues.map(issueCard).join('')}</div>`;
    }
    return html;
}

function renderTech(tech) {
    if (!tech) return '<div class="empty-state"><div class="empty-state-text">Technology scan not performed.</div></div>';

    let html = '';

    if (tech.cms) {
        html += `<div class="summary-card" style="display:inline-block;margin-bottom:20px;"><div class="number" style="font-size:24px;color:var(--accent);">${esc(tech.cms)}</div><div class="label">Detected CMS</div></div> `;
    }
    if (tech.server) {
        html += `<div class="summary-card" style="display:inline-block;margin-bottom:20px;"><div class="number" style="font-size:24px;color:var(--accent);">${esc(tech.server)}</div><div class="label">Web Server</div></div> `;
    }

    if (tech.technologies && tech.technologies.length > 0) {
        html += `
            <h3 style="margin:20px 0 12px;font-size:16px;">Detected Technologies</h3>
            <table class="detail-table">
                <tr><th>Technology</th><th>Category</th><th>Version</th><th>Confidence</th></tr>
        `;
        for (const t of tech.technologies) {
            html += `<tr><td><strong>${esc(t.name)}</strong></td><td><span class="tag tag-tech">${esc(t.category)}</span></td><td>${esc(t.version || '-')}</td><td>${esc(t.confidence)}</td></tr>`;
        }
        html += '</table>';
    }

    if (tech.js_libraries && tech.js_libraries.length > 0) {
        html += `
            <h3 style="margin:20px 0 12px;font-size:16px;">JavaScript Libraries</h3>
            <table class="detail-table">
                <tr><th>Library</th><th>Version</th></tr>
        `;
        for (const lib of tech.js_libraries) {
            html += `<tr><td>${esc(lib.name)}</td><td>${esc(lib.version || 'Unknown')}</td></tr>`;
        }
        html += '</table>';
    }

    if (tech.meta_tags && Object.keys(tech.meta_tags).length > 0) {
        html += `
            <h3 style="margin:20px 0 12px;font-size:16px;">Meta Tags</h3>
            <table class="detail-table">
                <tr><th>Name</th><th>Content</th></tr>
        `;
        for (const [k, v] of Object.entries(tech.meta_tags)) {
            html += `<tr><td>${esc(k)}</td><td style="max-width:400px;word-break:break-all;font-size:12px;">${esc(v)}</td></tr>`;
        }
        html += '</table>';
    }

    if (tech.issues && tech.issues.length > 0) {
        html += `<div class="issue-list" style="margin-top:20px;">${tech.issues.map(issueCard).join('')}</div>`;
    }
    return html;
}

function renderVulns(vulns) {
    if (!vulns) return '<div class="empty-state"><div class="empty-state-text">Vulnerability scan not performed.</div></div>';

    let html = '';

    if (vulns.exposed_paths && vulns.exposed_paths.length > 0) {
        html += `
            <h3 style="margin-bottom:12px;font-size:16px;">Exposed Paths (${vulns.exposed_paths.length})</h3>
            <table class="detail-table">
                <tr><th>Path</th><th>Description</th><th>Status</th><th>Severity</th></tr>
        `;
        for (const p of vulns.exposed_paths) {
            const sevClass = `sev-${p.severity || 'info'}`;
            html += `<tr><td><strong>${esc(p.path)}</strong></td><td>${esc(p.description)}</td><td>${p.status}</td><td><span class="issue-severity ${sevClass}" style="font-size:10px;">${(p.severity || 'info').toUpperCase()}</span></td></tr>`;
        }
        html += '</table>';
    }

    if (vulns.form_issues && vulns.form_issues.length > 0) {
        html += `<h3 style="margin:24px 0 12px;font-size:16px;">Form Security Issues</h3><div class="issue-list">${vulns.form_issues.map(issueCard).join('')}</div>`;
    }

    if (vulns.mixed_content && vulns.mixed_content.length > 0) {
        html += `
            <h3 style="margin:24px 0 12px;font-size:16px;">Mixed Content (${vulns.mixed_content.length})</h3>
            <ul style="padding-left:20px;color:var(--text-secondary);font-size:13px;">
                ${vulns.mixed_content.map(mc => `<li style="margin-bottom:4px;word-break:break-all;">${esc(mc)}</li>`).join('')}
            </ul>
        `;
    }

    if (vulns.email_addresses && vulns.email_addresses.length > 0) {
        html += `
            <h3 style="margin:24px 0 12px;font-size:16px;">Exposed Email Addresses</h3>
            <div style="display:flex;flex-wrap:wrap;gap:8px;">
                ${vulns.email_addresses.map(e => `<span class="tag tag-tech">${esc(e)}</span>`).join('')}
            </div>
        `;
    }

    if (vulns.issues && vulns.issues.length > 0) {
        html += `<h3 style="margin:24px 0 12px;font-size:16px;">All Issues</h3><div class="issue-list">${vulns.issues.map(issueCard).join('')}</div>`;
    }

    return html || '<div class="empty-state"><div class="empty-state-icon">\u2705</div><div class="empty-state-text">No vulnerabilities detected in passive scan.</div></div>';
}

/* Compliance & CVSS Tab */
function renderCompliance(comp, issues) {
    if (!comp) return '<div class="empty-state"><div class="empty-state-text">Compliance analysis not available.</div></div>';

    let html = '';
    const cs = comp.compliance_status || {};
    const owasp = cs.owasp || {};
    const pci = cs.pci_dss || {};

    // Risk + Compliance Summary Cards
    html += '<div class="summary-grid" style="margin-bottom:24px;">';
    const riskColor = comp.risk_level==='Critical'?'var(--critical)':comp.risk_level==='High'?'var(--danger)':comp.risk_level==='Medium'?'var(--warning)':'var(--success)';
    html += `<div class="summary-card"><div class="number" style="font-size:32px;color:${riskColor};">${comp.risk_score}</div><div class="label">Avg CVSS Score</div><div style="font-size:11px;color:${riskColor};margin-top:4px;">${comp.risk_level} Risk</div></div>`;
    const owaspColor = owasp.status==='FAIL'?'var(--danger)':owasp.status==='WARN'?'var(--warning)':'var(--success)';
    html += `<div class="summary-card"><div class="number" style="font-size:32px;color:${owaspColor};">${owasp.score||0}%</div><div class="label">OWASP Top 10</div><div style="font-size:11px;color:${owaspColor};margin-top:4px;">${owasp.categories_affected||0}/10 categories affected</div></div>`;
    const pciColor = pci.status==='FAIL'?'var(--danger)':pci.status==='WARN'?'var(--warning)':'var(--success)';
    html += `<div class="summary-card"><div class="number" style="font-size:32px;color:${pciColor};">${pci.score||0}%</div><div class="label">PCI DSS v4.0</div><div style="font-size:11px;color:${pciColor};margin-top:4px;">${pci.requirements_affected||0}/${pci.total_checked||14} requirements affected</div></div>`;
    html += '</div>';

    // CVSS Enriched Issues Table
    if (issues && issues.length > 0) {
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">CVSS v3.1 Scored Issues</h3>';
        html += '<table class="detail-table"><tr><th>CVSS</th><th>Severity</th><th>Issue</th><th>OWASP</th><th>PCI DSS</th><th>Vector</th></tr>';
        for (const issue of issues) {
            const score = issue.cvss_score || 0;
            const scoreColor = score>=9?'var(--critical)':score>=7?'var(--danger)':score>=4?'var(--warning)':'var(--info)';
            const sevClass = `sev-${(issue.severity||'info')}`;
            html += `<tr>
                <td><strong style="color:${scoreColor};font-size:16px;">${score}</strong></td>
                <td><span class="issue-severity ${sevClass}" style="font-size:10px;">${(issue.cvss_severity||issue.severity||'info').toUpperCase()}</span></td>
                <td style="max-width:250px;">${esc(issue.title||'')}</td>
                <td style="font-size:11px;color:var(--accent);">${esc(issue.owasp_category||'-')}</td>
                <td style="font-size:11px;">${(issue.pci_dss_requirements||[]).join(', ')||'-'}</td>
                <td style="font-size:10px;color:var(--text-muted);max-width:180px;word-break:break-all;">${esc(issue.cvss_vector||'-')}</td>
            </tr>`;
        }
        html += '</table>';
    }

    // OWASP Top 10 Coverage
    const owaspCov = comp.owasp_coverage || [];
    if (owaspCov.length > 0) {
        html += '<h3 style="margin:24px 0 12px;font-size:16px;">OWASP Top 10 (2021) Coverage</h3>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;">';
        for (const o of owaspCov) {
            const statusColor = o.status==='FAIL'?'var(--danger)':'var(--success)';
            const statusBg = o.status==='FAIL'?'rgba(239,68,68,0.08)':'rgba(34,197,94,0.08)';
            html += `<div style="padding:14px 16px;background:${statusBg};border:1px solid var(--border);border-left:3px solid ${statusColor};border-radius:8px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <strong style="font-size:13px;">${esc(o.code)}</strong>
                    <span class="tag" style="background:${statusColor};color:#fff;font-size:10px;padding:2px 8px;">${o.status}</span>
                </div>
                <div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">${esc(o.name)}</div>
                ${o.issues_count>0?`<div style="font-size:11px;color:var(--danger);">${o.issues_count} issue(s) found</div>`:'<div style="font-size:11px;color:var(--success);">No issues detected</div>'}
            </div>`;
        }
        html += '</div>';
    }

    // PCI DSS Coverage
    const pciCov = comp.pci_dss_coverage || [];
    if (pciCov.length > 0) {
        html += '<h3 style="margin:24px 0 12px;font-size:16px;">PCI DSS v4.0 Requirements</h3>';
        html += '<table class="detail-table"><tr><th>Req #</th><th>Description</th><th>Status</th><th>Issues</th></tr>';
        for (const p of pciCov) {
            const sc = p.status==='FAIL'?'var(--danger)':'var(--success)';
            html += `<tr>
                <td><strong>${esc(p.requirement)}</strong></td>
                <td style="font-size:12px;">${esc(p.description)}</td>
                <td><span class="tag" style="background:${sc};color:#fff;font-size:10px;padding:2px 8px;">${p.status}</span></td>
                <td style="font-size:12px;">${p.issues_count>0?`<span style="color:var(--danger);">${p.issues_count}</span>`:'-'}</td>
            </tr>`;
        }
        html += '</table>';
    }

    return html;
}

/* Subdomain Discovery Tab */
function renderSubdomains(sub) {
    if (!sub) return '<div class="empty-state"><div class="empty-state-text">Subdomain scan not performed.</div></div>';

    let html = '';

    // Summary cards
    html += '<div class="summary-grid" style="margin-bottom:24px;">';
    html += `<div class="summary-card"><div class="number" style="font-size:32px;color:var(--accent);">${sub.total_found || 0}</div><div class="label">Subdomains Found</div></div>`;
    const srcList = (sub.sources || []).join(', ') || 'None';
    html += `<div class="summary-card"><div class="number" style="font-size:16px;color:var(--text);">${srcList}</div><div class="label">Sources Used</div></div>`;
    html += `<div class="summary-card"><div class="number" style="font-size:32px;color:${(sub.issues||[]).length>0?'var(--warning)':'var(--success)'};">${(sub.issues||[]).length}</div><div class="label">Issues Found</div></div>`;
    html += '</div>';

    // Subdomains table
    const subs = sub.subdomains || [];
    if (subs.length > 0) {
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">Discovered Subdomains</h3>';
        html += '<table class="detail-table"><tr><th>Subdomain</th><th>IP Address</th><th>Source</th></tr>';
        for (const s of subs) {
            html += `<tr>
                <td style="font-family:monospace;font-size:13px;">${esc(s.subdomain)}</td>
                <td style="font-family:monospace;font-size:13px;color:var(--text-secondary);">${s.ip || 'N/A'}</td>
                <td style="font-size:12px;">${esc(s.source)}</td>
            </tr>`;
        }
        html += '</table>';
    } else {
        html += '<div class="empty-state"><div class="empty-state-text">No subdomains discovered for this domain.</div></div>';
    }

    return html;
}

/* Threat Intelligence Tab */
function renderThreatIntel(ti) {
    if (!ti) return '<div class="empty-state"><div class="empty-state-text">Threat intelligence scan not performed.</div></div>';

    let html = '';

    // APIs used / skipped summary
    html += '<div class="summary-grid" style="margin-bottom:24px;">';
    html += `<div class="summary-card"><div class="number" style="font-size:28px;color:var(--success);">${(ti.apis_used||[]).length}</div><div class="label">APIs Connected</div></div>`;
    html += `<div class="summary-card"><div class="number" style="font-size:28px;color:var(--text-muted);">${(ti.apis_skipped||[]).length}</div><div class="label">APIs Skipped (No Key)</div></div>`;
    html += `<div class="summary-card"><div class="number" style="font-size:28px;color:var(--danger);">${(ti.cve_matches||[]).length}</div><div class="label">CVEs Found</div></div>`;
    html += '</div>';

    if (ti.apis_used && ti.apis_used.length > 0) {
        html += '<div style="margin-bottom:16px;"><strong style="font-size:13px;color:var(--text-muted);">Active APIs:</strong> ';
        html += ti.apis_used.map(a => `<span class="tag tag-present" style="margin:2px;">${esc(a)}</span>`).join(' ');
        html += '</div>';
    }
    if (ti.apis_skipped && ti.apis_skipped.length > 0) {
        html += '<div style="margin-bottom:20px;"><strong style="font-size:13px;color:var(--text-muted);">Skipped:</strong> ';
        html += ti.apis_skipped.map(a => `<span class="tag" style="margin:2px;background:rgba(100,116,139,0.1);color:var(--text-muted);">${esc(a)}</span>`).join(' ');
        html += '</div>';
    }

    // CVE Matches
    if (ti.cve_matches && ti.cve_matches.length > 0) {
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f6a8; Known CVE Vulnerabilities</h3>';
        html += '<table class="detail-table"><tr><th>CVE ID</th><th>Technology</th><th>CVSS Score</th><th>Severity</th><th>Description</th></tr>';
        for (const cve of ti.cve_matches) {
            const sevClass = `sev-${cve.severity||'info'}`;
            const scoreColor = cve.cvss_score >= 9 ? 'var(--critical)' : cve.cvss_score >= 7 ? 'var(--danger)' : cve.cvss_score >= 4 ? 'var(--warning)' : 'var(--info)';
            html += `<tr><td><strong style="color:var(--accent);">${esc(cve.cve_id)}</strong></td><td>${esc(cve.technology)} ${cve.version!=='Unknown'?esc(cve.version):''}</td><td><span style="color:${scoreColor};font-weight:700;">${cve.cvss_score||'N/A'}</span></td><td><span class="issue-severity ${sevClass}" style="font-size:10px;">${(cve.severity||'info').toUpperCase()}</span></td><td style="font-size:12px;max-width:300px;">${esc(cve.description)}</td></tr>`;
        }
        html += '</table>';
    }

    // Safe Browsing
    if (ti.safe_browsing && ti.safe_browsing.status !== 'skipped') {
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f6e1; Google Safe Browsing</h3>';
        if (ti.safe_browsing.status === 'clean') {
            html += '<div style="padding:14px 16px;background:var(--bg-input);border-left:3px solid var(--success);border-radius:8px;"><span class="tag tag-present">CLEAN</span> <span style="margin-left:8px;font-size:14px;">No threats detected by Google Safe Browsing</span></div>';
        } else if (ti.safe_browsing.status === 'threats_found') {
            for (const t of (ti.safe_browsing.threats||[])) {
                html += `<div style="padding:14px 16px;background:var(--bg-input);border-left:3px solid var(--danger);border-radius:8px;margin-bottom:8px;"><span class="tag tag-missing">${esc(t.type)}</span> <span style="margin-left:8px;font-size:13px;">Platform: ${esc(t.platform)}</span></div>`;
            }
        }
    }

    // Shodan
    if (ti.shodan_data && ti.shodan_data.status === 'found') {
        const s = ti.shodan_data;
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f50d; Shodan Intelligence</h3>';
        html += `<table class="detail-table"><tr><th>Property</th><th>Value</th></tr>`;
        html += `<tr><td>IP Address</td><td><strong>${esc(s.ip)}</strong></td></tr>`;
        html += `<tr><td>Organization</td><td>${esc(s.org)}</td></tr>`;
        html += `<tr><td>ISP</td><td>${esc(s.isp)}</td></tr>`;
        html += `<tr><td>Operating System</td><td>${esc(s.os||'Unknown')}</td></tr>`;
        html += `<tr><td>Open Ports</td><td>${(s.ports||[]).map(p=>`<span class="tag tag-open" style="margin:2px;">${p}</span>`).join(' ')}</td></tr>`;
        html += `<tr><td>Known Vulns</td><td><span style="color:${s.vulns_count>0?'var(--danger)':'var(--success)'};">${s.vulns_count} CVE(s)</span></td></tr>`;
        html += '</table>';
        if (s.services && s.services.length > 0) {
            html += '<h4 style="margin:16px 0 8px;font-size:14px;">Services Detected</h4>';
            html += '<table class="detail-table"><tr><th>Port</th><th>Product</th><th>Version</th><th>Banner</th></tr>';
            for (const svc of s.services) {
                html += `<tr><td>${svc.port}/${esc(svc.transport)}</td><td>${esc(svc.product||'-')}</td><td>${esc(svc.version||'-')}</td><td style="font-size:11px;max-width:250px;word-break:break-all;">${esc(svc.banner||'-')}</td></tr>`;
            }
            html += '</table>';
        }
    }

    // VirusTotal
    if (ti.virustotal_data && ti.virustotal_data.status === 'found') {
        const vt = ti.virustotal_data;
        const stats = vt.analysis_stats || {};
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f9ea; VirusTotal Analysis</h3>';
        html += '<div class="summary-grid" style="margin-bottom:16px;">';
        html += `<div class="summary-card"><div class="number" style="color:var(--danger);">${stats.malicious||0}</div><div class="label">Malicious</div></div>`;
        html += `<div class="summary-card"><div class="number" style="color:var(--warning);">${stats.suspicious||0}</div><div class="label">Suspicious</div></div>`;
        html += `<div class="summary-card"><div class="number" style="color:var(--success);">${stats.harmless||0}</div><div class="label">Clean</div></div>`;
        html += `<div class="summary-card"><div class="number" style="color:var(--text-muted);">${stats.undetected||0}</div><div class="label">Undetected</div></div>`;
        html += '</div>';
        html += `<div style="font-size:13px;color:var(--text-secondary);">Reputation Score: <strong>${vt.reputation_score}</strong></div>`;
    }

    // Breaches
    if (ti.breach_data && ti.breach_data.status !== 'skipped') {
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f4a5; Data Breach History</h3>';
        if (ti.breach_data.status === 'clean') {
            html += '<div style="padding:14px 16px;background:var(--bg-input);border-left:3px solid var(--success);border-radius:8px;"><span class="tag tag-present">NO BREACHES</span> <span style="margin-left:8px;font-size:14px;">No known data breaches for this domain</span></div>';
        } else if (ti.breach_data.breaches && ti.breach_data.breaches.length > 0) {
            html += `<p style="color:var(--danger);font-size:14px;margin-bottom:12px;font-weight:600;">${ti.breach_data.total_breaches} breach(es) found!</p>`;
            for (const b of ti.breach_data.breaches) {
                html += `<div style="padding:14px 16px;background:var(--bg-input);border:1px solid var(--border);border-left:3px solid var(--danger);border-radius:8px;margin-bottom:8px;">
                    <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><strong>${esc(b.title||b.name)}</strong><span style="font-size:12px;color:var(--text-muted);">${esc(b.date)}</span></div>
                    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:4px;">${esc(b.description)}</div>
                    <div style="font-size:11px;"><span style="color:var(--warning);">${(b.pwn_count||0).toLocaleString()} accounts</span> | ${(b.data_classes||[]).slice(0,5).map(d=>`<span class="tag" style="font-size:10px;padding:1px 6px;background:rgba(100,116,139,0.1);color:var(--text-muted);">${esc(d)}</span>`).join(' ')}</div>
                </div>`;
            }
        }
    }

    // Subdomains
    if (ti.subdomain_data && ti.subdomain_data.status === 'found') {
        const sd = ti.subdomain_data;
        html += '<h3 style="margin:20px 0 12px;font-size:16px;">&#x1f310; Subdomain Discovery</h3>';
        html += `<p style="font-size:14px;color:var(--text-secondary);margin-bottom:12px;"><strong>${sd.total_subdomains}</strong> subdomains found for <strong>${esc(sd.domain)}</strong></p>`;
        if (sd.risky_subdomains && sd.risky_subdomains.length > 0) {
            html += '<p style="font-size:13px;color:var(--warning);margin-bottom:8px;">&#x26a0; Potentially sensitive subdomains:</p>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;">';
            for (const r of sd.risky_subdomains) html += `<span class="tag" style="background:var(--warning-bg);color:var(--warning);">${esc(r)}</span>`;
            html += '</div>';
        }
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
        for (const s of (sd.subdomains||[]).slice(0,30)) html += `<span class="tag tag-tech">${esc(s)}</span>`;
        if (sd.total_subdomains > 30) html += `<span class="tag" style="background:rgba(100,116,139,0.1);color:var(--text-muted);">+${sd.total_subdomains-30} more</span>`;
        html += '</div>';
    }

    return html || '<div class="empty-state"><div class="empty-state-text">No threat intelligence data available.</div></div>';
}

function renderCredentials(creds) {
    if (!creds || creds.length === 0) return '<div class="empty-state"><div class="empty-state-text">No credential-dependent tests available.</div></div>';

    let html = `
        <div class="cred-section" style="background:transparent;border:none;padding:0;">
            <div class="cred-title">\uD83D\uDD10 Tests Requiring Authentication</div>
            <p style="color:var(--text-secondary);margin-bottom:20px;font-size:14px;">
                The following deep-scan tests require login credentials or API keys. Provide authentication to unlock these advanced security checks.
            </p>
            <div class="cred-list">
    `;

    for (const c of creds) {
        html += `
            <div class="cred-item">
                <div class="cred-item-title">${esc(c.test)}</div>
                <div class="cred-item-desc">${esc(c.description)}</div>
                <div class="cred-item-req">\uD83D\uDD11 Requires: ${esc(c.requires)}</div>
                <div class="cred-item-depth">Depth: ${esc(c.depth)}</div>
            </div>
        `;
    }

    html += '</div></div>';
    return html;
}

/* Export Functions */
async function exportJSON() {
    if (!currentScan) return;
    const resp = await fetch(`${API_BASE}/api/scan/${currentScan}/report`);
    const data = await resp.json();
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `security-report-${currentScan}.json`);
}

function exportCSV() {
    if (!currentScan) return;
    const issues = document.querySelectorAll('.issue-card');
    let csv = 'Severity,Title,Description,Recommendation\n';
    issues.forEach(card => {
        const sev = card.querySelector('.issue-severity')?.textContent?.trim() || '';
        const title = card.querySelector('.issue-title')?.textContent?.trim() || '';
        const desc = card.querySelector('.issue-desc')?.textContent?.trim() || '';
        const rec = card.querySelector('.issue-recommendation')?.textContent?.trim() || '';
        csv += `"${sev}","${title}","${desc}","${rec}"\n`;
    });
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, `security-report-${currentScan}.csv`);
}

function downloadBlob(blob, filename) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
    URL.revokeObjectURL(a.href);
}

function printReport() {
    window.print();
}

function newScan() {
    document.getElementById('resultsSection').classList.remove('active');
    document.getElementById('urlInput').value = '';
    document.getElementById('urlInput').focus();
    currentScan = null;
}

/* Embed Modal */
function showEmbedModal() {
    const host = window.location.origin;
    const code = `<!-- SecureScan Pro - Security Scanner Widget -->
<iframe
  src="${host}/embed"
  width="100%"
  height="600"
  frameborder="0"
  style="border: 1px solid #2d3a50; border-radius: 12px;"
  title="Security Scanner"
  allow="clipboard-write"
></iframe>

<!-- Or use as SEO Audit Module -->
<script>
  (function() {
    var s = document.createElement('script');
    s.src = '${host}/static/js/embed-widget.js';
    s.setAttribute('data-host', '${host}');
    document.head.appendChild(s);
  })();
</script>`;

    document.getElementById('embedCode').textContent = code;
    document.getElementById('embedModal').classList.add('active');
}

function closeEmbedModal() {
    document.getElementById('embedModal').classList.remove('active');
}

function copyEmbed() {
    const code = document.getElementById('embedCode').textContent;
    navigator.clipboard.writeText(code).then(() => {
        alert('Embed code copied to clipboard!');
    });
}

/* Enterprise CRM Tab */
function renderEnterprise(ent) {
    if (!ent) return '<div class="empty-state"><div class="empty-state-text">Enterprise scan not performed.</div></div>';
    let html = '';
    const sections = [
        {title: 'A. API Security', data: ent.api_security, icon: '\uD83D\uDD12'},
        {title: 'B. Database Security', data: ent.db_security, icon: '\uD83D\uDDC4'},
        {title: 'C. Application Security (OWASP)', data: ent.app_security, icon: '\uD83D\uDEE1'},
        {title: 'D. Infrastructure Security', data: ent.infra_security, icon: '\u2601'},
    ];
    for (const s of sections) {
        if (!s.data || !s.data.length) continue;
        html += `<h3 style="margin:20px 0 10px;font-size:16px;">${s.icon} ${s.title}</h3>`;
        for (const item of s.data) {
            const color = ['protected','active','detected','hidden','configured'].includes(item.status) ? 'var(--success)' : ['vulnerable','exposed'].includes(item.status) ? 'var(--danger)' : 'var(--warning)';
            const badgeCls = ['protected','active','detected','hidden','configured'].includes(item.status) ? 'tag-present' : ['vulnerable','exposed'].includes(item.status) ? 'tag-missing' : 'tag-tech';
            html += `
                <div style="padding:14px 16px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;margin-bottom:8px;border-left:3px solid ${color};">
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                        <strong style="font-size:14px;">${esc(item.check)}</strong>
                        <span class="tag ${badgeCls}" style="text-transform:uppercase;">${esc(item.status)}</span>
                    </div>
                    <div style="font-size:12px;color:var(--text-secondary);margin-bottom:6px;">${esc(item.detail)}</div>
                    <div style="font-size:11px;color:var(--success);">\uD83D\uDD27 ${esc(item.solution)}</div>
                    ${item.fix_code ? `<pre style="margin-top:6px;background:var(--bg-primary);padding:8px;border-radius:6px;font-size:11px;color:var(--accent);overflow-x:auto;">${esc(item.fix_code)}</pre>` : ''}
                </div>`;
        }
    }
    if (ent.api_integrations && ent.api_integrations.length > 0) {
        html += `<h3 style="margin:20px 0 10px;font-size:16px;">\uD83D\uDD17 Detected API Integrations (GoHighLevel-type)</h3>`;
        html += `<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:16px;">`;
        for (const api of ent.api_integrations) {
            html += `<span class="tag tag-tech" style="padding:5px 12px;font-size:13px;">${esc(api.name)}</span>`;
        }
        html += '</div>';
    }
    return html || '<div class="empty-state"><div class="empty-state-text">No enterprise data available.</div></div>';
}

/* Pricing Tab */
function renderPricing(pricing) {
    if (!pricing || pricing.length === 0) return '<div class="empty-state"><div class="empty-state-text">Run a scan to see agency pricing.</div></div>';
    let html = '<h3 style="margin-bottom:16px;font-size:16px;">\uD83D\uDCB0 Agency Security Testing Pricing Guide</h3>';
    html += '<p style="color:var(--text-secondary);margin-bottom:16px;font-size:13px;">Industry-standard pricing for professional security assessments. Use these as reference for your agency billing.</p>';
    for (const p of pricing) {
        html += `<div style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;margin-bottom:6px;"><span style="font-size:14px;font-weight:500;">${esc(p.service)}</span><span style="font-size:14px;color:var(--accent);font-weight:600;">${esc(p.price_range)}</span></div>`;
    }
    return html;
}

/* PDF Report Generation */
function generatePDF() {
    if (!currentScanData) return;
    const s = currentScanData.summary, sv = s.by_severity || {};
    const ent = currentScanData.results.enterprise || {};

    let html = `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Security Report</title>
    <style>
    *{margin:0;padding:0;box-sizing:border-box}body{font-family:Arial,sans-serif;background:#fff;color:#1a1a1a;padding:40px;font-size:13px;line-height:1.6}
    .hdr{text-align:center;margin-bottom:30px;padding-bottom:20px;border-bottom:3px solid #3b82f6}
    .hdr h1{font-size:28px;color:#3b82f6;margin-bottom:4px}.hdr p{color:#666;font-size:14px}
    .grade{text-align:center;font-size:72px;font-weight:800;margin:20px 0;color:${s.grade==='A'?'#10b981':s.grade==='B'?'#06b6d4':s.grade==='C'?'#f59e0b':'#ef4444'}}
    .stats{display:flex;justify-content:center;gap:30px;margin-bottom:30px;flex-wrap:wrap}
    .stat{text-align:center;padding:15px 25px;border:2px solid #e5e7eb;border-radius:8px;min-width:100px}
    .stat .num{font-size:28px;font-weight:700}.stat .lbl{font-size:11px;color:#666;text-transform:uppercase}
    .stat-c .num{color:#dc2626}.stat-h .num{color:#ef4444}.stat-m .num{color:#f59e0b}.stat-l .num{color:#6366f1}
    h2{font-size:18px;color:#3b82f6;margin:30px 0 12px;padding-bottom:6px;border-bottom:1px solid #e5e7eb}
    h3{font-size:15px;color:#1a1a1a;margin:20px 0 8px}
    .issue{padding:12px 14px;margin-bottom:8px;border-radius:6px;border-left:4px solid #ccc;background:#f9fafb}
    .issue-c{border-left-color:#dc2626;background:#fef2f2}.issue-h{border-left-color:#ef4444;background:#fef2f2}
    .issue-m{border-left-color:#f59e0b;background:#fffbeb}.issue-l{border-left-color:#6366f1;background:#eef2ff}
    .issue .sev{font-size:10px;font-weight:700;text-transform:uppercase;margin-bottom:2px}
    .issue .sev-c{color:#dc2626}.issue .sev-h{color:#ef4444}.issue .sev-m{color:#f59e0b}.issue .sev-l{color:#6366f1}
    .issue .t{font-weight:600;font-size:14px;margin-bottom:2px}.issue .d{font-size:12px;color:#666;margin-bottom:4px}
    .issue .fix{font-size:11px;color:#10b981;background:#ecfdf5;padding:4px 8px;border-radius:4px;display:inline-block}
    .issue .cat{font-size:10px;color:#3b82f6;background:#eff6ff;padding:2px 6px;border-radius:3px;margin-left:6px}
    .ent{padding:10px;margin-bottom:6px;border-radius:4px;background:#f9fafb}
    .ent .st{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:600}
    .st-ok{background:#dcfce7;color:#16a34a}.st-err{background:#fee2e2;color:#dc2626}.st-w{background:#fef3c7;color:#d97706}
    .price{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #f1f5f9;font-size:13px}
    .price .amt{color:#3b82f6;font-weight:600}
    .footer{margin-top:40px;padding-top:16px;border-top:2px solid #e5e7eb;text-align:center;color:#94a3b8;font-size:11px}
    @media print{body{padding:20px}}
    </style></head><body>
    <div class="hdr"><h1>Security Assessment Report</h1><p>Target: ${esc(currentScanData.url)} | Generated: ${new Date().toLocaleString()}</p></div>
    <div class="grade">${s.grade}</div>
    <div class="stats">
        <div class="stat"><div class="num">${s.total_issues||0}</div><div class="lbl">Total Issues</div></div>
        <div class="stat stat-c"><div class="num">${sv.critical||0}</div><div class="lbl">Critical</div></div>
        <div class="stat stat-h"><div class="num">${sv.high||0}</div><div class="lbl">High</div></div>
        <div class="stat stat-m"><div class="num">${sv.medium||0}</div><div class="lbl">Medium</div></div>
        <div class="stat stat-l"><div class="num">${sv.low||0}</div><div class="lbl">Low</div></div>
    </div>`;

    const sorted = [...(currentScanData.all_issues||[])].sort((a,b)=>({critical:0,high:1,medium:2,low:3,info:4}[a.severity]??4)-({critical:0,high:1,medium:2,low:3,info:4}[b.severity]??4));
    html += `<h2>Security Findings (${sorted.length})</h2>`;
    for (const i of sorted) {
        const cls = i.severity==='critical'?'c':i.severity==='high'?'h':i.severity==='medium'?'m':'l';
        html += `<div class="issue issue-${cls}"><div class="sev sev-${cls}">${(i.severity||'info').toUpperCase()}${i.category?`<span class="cat">${esc(i.category)}</span>`:''}</div><div class="t">${esc(i.title)}</div><div class="d">${esc(i.description)}</div>${i.recommendation?`<div class="fix">Fix: ${esc(i.recommendation)}</div>`:''}</div>`;
    }

    // Enterprise
    if(ent.api_security?.length||ent.app_security?.length||ent.db_security?.length||ent.infra_security?.length) {
        const sections = [{t:'A. API Security',d:ent.api_security},{t:'B. Database Security',d:ent.db_security},{t:'C. Application Security',d:ent.app_security},{t:'D. Infrastructure Security',d:ent.infra_security}];
        html += '<h2>Enterprise CRM Security Assessment</h2>';
        for (const sec of sections) {
            if(!sec.d?.length) continue;
            html += `<h3>${sec.t}</h3>`;
            for (const item of sec.d) {
                const st = ['protected','active','detected','hidden'].includes(item.status)?'ok':['vulnerable','exposed'].includes(item.status)?'err':'w';
                html += `<div class="ent" style="border-left:3px solid ${st==='ok'?'#10b981':st==='err'?'#ef4444':'#f59e0b'};"><div style="display:flex;justify-content:space-between;"><strong>${esc(item.check)}</strong><span class="st st-${st}">${esc(item.status)}</span></div><div style="font-size:12px;color:#666;margin:4px 0;">${esc(item.detail)}</div><div style="font-size:11px;color:#10b981;">Fix: ${esc(item.solution)}</div></div>`;
            }
        }
    }

    // Pricing
    const pricing = currentScanData.agency_pricing || ent.agency_pricing || [];
    if (pricing.length > 0) {
        html += '<h2>Agency Pricing Reference</h2>';
        for (const p of pricing) html += `<div class="price"><span>${esc(p.service)}</span><span class="amt">${esc(p.price_range)}</span></div>`;
    }

    html += `<div class="footer"><p>Generated by SecureScan Pro | ${new Date().toLocaleString()}</p><p>For authorized security assessment purposes only.</p></div></body></html>`;

    const win = window.open('','_blank');
    win.document.write(html);
    win.document.close();
    setTimeout(() => { win.print(); }, 500);
}

/* Server-side PDF Report (Whitelabel + Executive Summary) */
async function downloadServerPDF(lang) {
    if (!currentScan) { alert('No scan available.'); return; }
    const language = lang || 'en';
    try {
        const resp = await fetch(`${API_BASE}/api/scan/${currentScan}/pdf`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                language: language,
                include_executive_summary: true,
                whitelabel: null,
            }),
        });
        if (!resp.ok) {
            const err = await resp.json();
            alert(err.detail || 'PDF generation failed.');
            return;
        }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `securescan-report-${currentScan.substring(0, 8)}.pdf`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert('PDF generation failed: ' + e.message);
    }
}

/* Email Modal */
function showEmailModal() {
    document.getElementById('emailModal').classList.add('active');
    document.getElementById('emailSubject').value = `Security Report - ${currentScanData?.url || 'Website'}`;
}

function closeEmailModal() {
    document.getElementById('emailModal').classList.remove('active');
}

function sendEmail() {
    const to = document.getElementById('emailTo').value;
    const subject = document.getElementById('emailSubject').value;
    const body = document.getElementById('emailBody').value || `Security Assessment Report for ${currentScanData?.url || 'website'}. Grade: ${currentScanData?.summary?.grade || 'N/A'}. Total Issues: ${currentScanData?.summary?.total_issues || 0}.`;
    window.open(`mailto:${to}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`);
    closeEmailModal();
}
