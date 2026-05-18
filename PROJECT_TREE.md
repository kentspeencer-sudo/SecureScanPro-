# SecureScan Pro — Project Tree & Architecture Guide

> **Purpose**: This document gives any AI model (or developer) a complete map of the project — what each file does, how they connect, and what to modify for any feature change.

---

## Quick Start

```bash
pip install fastapi uvicorn httpx beautifulsoup4 jinja2 python-multipart dnspython
uvicorn app:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000/` in browser.

---

## Directory Structure

```
SecureScanPro-/
├── app.py                          # [420 lines] FastAPI main — routes, auth, scan orchestration, CVSS enrichment
├── main.py                         # [5 lines]   Entry point: `uvicorn app:app`
├── database.py                     # [280 lines] SQLite backend — users, scans, scan history, scheduled scans
├── pyproject.toml                  # Project metadata & dependencies
├── Dockerfile                      # Docker build for Fly.io deployment
├── fly.toml                        # Fly.io deployment config with persistent volume
├── securescan-pro.html             # [~47KB] Standalone single-file scanner (embed anywhere)
├── README.md                       # Documentation & setup guide
├── PROJECT_TREE.md                 # THIS FILE — architecture reference
├── NEXT_STEPS.md                   # Remaining phases guide for AI models
├── SecureScanPro-Implementation-Roadmap.md  # Next steps roadmap: 5 phases, timelines, revenue
├── SecureScanPro-Competitor-Analysis.md     # Top 10 competitor deep analysis with pricing
│
├── modules/                        # Backend scanning modules (each returns a dataclass)
│   ├── __init__.py                 # Empty init
│   ├── ssl_checker.py              # [90 lines]  SSL/TLS certificate validation
│   ├── header_checker.py           # [171 lines] HTTP security headers analysis (9+ headers)
│   ├── port_scanner.py             # [148 lines] TCP port scanning (26 common ports)
│   ├── dns_checker.py              # [173 lines] DNS records, SPF/DMARC/DKIM, ping
│   ├── tech_detector.py            # [220 lines] CMS detection, JS libs, server stack
│   ├── vuln_checker.py             # [212 lines] Exposed paths, form security, mixed content
│   ├── enterprise_checker.py       # [365 lines] Enterprise CRM: API/DB/App/Infra security
│   ├── deep_scanner.py             # [450 lines] Authenticated deep scan: API/DB/Admin/Session
│   ├── threat_intel.py             # [420 lines] Threat Intelligence: NVD CVE, Shodan, VirusTotal, HIBP, Safe Browsing, SecurityTrails
│   ├── cvss_engine.py              # [320 lines] CVSS v3.1 scoring + OWASP Top 10 + PCI DSS compliance mapping
│   └── subdomain_scanner.py        # [140 lines] Passive subdomain discovery: crt.sh + DNS brute-force
│
├── templates/                      # Jinja2 HTML templates
│   ├── dashboard.html              # [141 lines] Main scanner dashboard UI (12 tabs including Subdomains)
│   ├── authenticated.html          # [339 lines] Credential-gated deep scan page with tabbed results
│   ├── pricing.html                # [545 lines] Professional services & pricing page
│   ├── auth.html                   # [280 lines] Login/Signup forms with validation + password strength
│   ├── user_dashboard.html         # [210 lines] User dashboard: stats, scan history, continuous monitoring
│   ├── privacy.html                # Privacy Policy page (GDPR compliant)
│   ├── terms.html                  # Terms of Service page
│   ├── refund.html                 # Refund Policy page
│   ├── api_management.html         # API key management dashboard (usage/hits/cost tracking)
│   ├── embed.html                  # [120 lines] Embeddable widget (iframe/JS)
│   └── report.html                 # [165 lines] Report viewer page
│
└── static/                         # Frontend assets
    ├── css/
    │   ├── style.css               # [628 lines] Dark theme, responsive, severity colors
    │   └── pricing.css             # [380 lines] Pricing tiers, services grid, comparison table
    └── js/
        ├── scanner.js              # [940 lines] Main frontend logic — scan, render, subdomains, CVSS, compliance, PDF, email
        └── embed-widget.js         # [24 lines]  Embed widget loader script
```

**Total: ~8,500+ lines of code across 32 files**

---

## Architecture Flow

```
User enters URL → dashboard.html
        ↓
    scanner.js → POST /api/scan {url, scan_types[]}
        ↓
    app.py → creates scan_id, starts async run_scan()
        ↓
    run_scan() calls each module sequentially:
        ├── ssl_checker.check_ssl(hostname)        → SSLResult
        ├── header_checker.check_headers(url)      → HeaderResult
        ├── port_scanner.scan_ports(hostname)       → PortResult
        ├── dns_checker.check_dns(hostname)         → DNSResult
        ├── tech_detector.detect_technologies(url)  → TechResult
        ├── vuln_checker.check_vulnerabilities(url) → VulnResult
        ├── enterprise_checker.check_enterprise_security(url) → EnterpriseResult
        ├── threat_intel.run_threat_intel(url, hostname, techs) → ThreatIntelResult
        ├── subdomain_scanner.discover_subdomains(hostname)  → SubdomainResult
        └── cvss_engine.enrich_issues_with_cvss(all_issues) → ComplianceResult
        ↓
    Results saved to SQLite database (database.py)
        ↓
    scanner.js polls GET /api/scan/{id} every 1s
        ↓
    When status=completed → renderResults(data)
        ├── renderSummary()     → Grade card + severity counts
        ├── renderOverview()    → All issues sorted by severity
        ├── renderSSL()         → Certificate details table
        ├── renderHeaders()     → Present/missing headers table
        ├── renderPorts()       → Open ports table
        ├── renderDNS()         → DNS records + ping results
        ├── renderTech()        → CMS, JS libs, meta tags
        ├── renderVulns()       → Exposed paths, form issues
        ├── renderEnterprise()  → 4 security layers (API/DB/App/Infra)
        ├── renderThreatIntel() → CVE table, API status, breach data
        ├── renderCompliance()  → CVSS scores, OWASP grid, PCI DSS table
        ├── renderSubdomains()  → Discovered subdomains table (crt.sh + DNS brute-force)
        ├── renderCredentials() → Auth-required tests list
        └── renderPricing()     → Agency pricing reference
```

---

## File-by-File Details

### `app.py` — Main Application (FastAPI)

**Routes:**
| Route | Method | Description |
|-------|--------|-------------|
| `/` | GET | Dashboard page (main scanner) |
| `/authenticated` | GET | Credential-gated deep scan page |
| `/pricing` | GET | Professional services & pricing page |
| `/login` | GET | Login/Signup page |
| `/signup` | GET | Login/Signup page (redirects to auth.html) |
| `/dashboard` | GET | User dashboard (scan history, monitors, API key) |
| `/report/{scan_id}` | GET | Report viewer |
| `/api/auth/signup` | POST | Register new user (body: `{email, password, full_name, company, phone}`) |
| `/api/auth/login` | POST | Login (body: `{email, password}`) → returns JWT-like token |
| `/api/auth/verify` | GET | Verify email with token |
| `/api/user/dashboard` | GET | Get user stats, scan history, monitors (auth required) |
| `/api/user/monitors` | POST | Add scheduled scan monitor (auth required) |
| `/api/user/monitors/{id}` | DELETE | Delete monitor (auth required) |
| `/api/scan` | POST | Start new scan (body: `{url, scan_types}`) |
| `/api/scan/{scan_id}` | GET | Poll scan status/results |
| `/api/scan/{scan_id}/report` | GET | Get completed report data |

**Key Functions:**
- `normalize_url(url)` — Adds `https://` if missing
- `extract_hostname(url)` — Extracts hostname from URL
- `count_by_severity(issues)` — Counts critical/high/medium/low/info
- `overall_grade(issues)` — Returns A-F grade based on severity counts
- `run_scan(scan_id, url, scan_types, user_id)` — Async orchestrator, calls all modules
- `get_current_user(authorization)` — Extract user from Bearer token
- `require_auth(authorization)` — Require authentication for protected routes

**Data Flow:**
- `scans` dict stores active scan data in memory
- Completed scans saved to SQLite database (`database.py`)
- Each scan has: `scan_id`, `url`, `hostname`, `status`, `progress`, `results`, `summary`, `all_issues`, `credential_tests`, `agency_pricing`
- Scan types: `["ssl", "headers", "ports", "dns", "tech", "vulns", "enterprise", "threat_intel", "subdomains"]`
- After all scans: `enrich_issues_with_cvss(all_issues)` adds CVSS scores, OWASP mapping, PCI DSS mapping

### `database.py` — SQLite Backend

**Tables:**
- `users` — id, email, password_hash, full_name, company, phone, role, is_verified, verification_token, api_key, scan_count
- `scan_history` — id, user_id, url, hostname, scan_types, status, grade, total_issues, severity counts, risk_score, results_json
- `scheduled_scans` — id, user_id, url, hostname, scan_types, interval (daily/weekly/monthly), is_active, next_run

**Key Functions:**
- `init_db()` — Create tables and indexes
- `create_user()` / `authenticate_user()` — Registration and login with PBKDF2 password hashing
- `verify_user_email(token)` — Email verification with expiry
- `save_scan()` — Save completed scan results to database
- `get_user_scans()` — Get user's scan history
- `create_scheduled_scan()` / `get_due_scheduled_scans()` — Continuous monitoring
- `get_dashboard_stats()` — Aggregate stats for user dashboard

**Grading Logic (line 88-102):**
- F = any critical issue
- D = 3+ high issues
- C = 1+ high OR 3+ medium
- B = 1+ medium OR 3+ low
- A = everything else

---

### `modules/ssl_checker.py` — SSL/TLS Analysis

**Function:** `check_ssl(hostname) → SSLResult`
**Returns:** `SSLResult(valid, issuer, subject, expires, days_until_expiry, protocol, cipher, key_size, san_domains, issues, error)`
**Checks:** Certificate validity, expiry (<30 days warning), weak ciphers, protocol version
**Note:** Synchronous — called via `run_in_executor()`

---

### `modules/header_checker.py` — Security Headers

**Function:** `check_headers(url) → HeaderResult` (async)
**Returns:** `HeaderResult(url, present_headers, missing_headers, cookie_flags, score, grade, issues)`
**Headers Checked (9):** Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy, Cross-Origin-Resource-Policy
**Scoring:** 100 points, deducts for each missing header → Grade A-F

---

### `modules/port_scanner.py` — Port Scanning

**Function:** `scan_ports(hostname) → PortResult` (async)
**Returns:** `PortResult(hostname, ip_address, total_scanned, open_ports[], issues)`
**Ports Scanned (26):** 21(FTP), 22(SSH), 23(Telnet), 25(SMTP), 53(DNS), 80(HTTP), 110(POP3), 143(IMAP), 443(HTTPS), 445(SMB), 993, 995, 1433(MSSQL), 3306(MySQL), 3389(RDP), 5432(PostgreSQL), 5900(VNC), 6379(Redis), 8080, 8443, 8888, 9090, 27017(MongoDB), 11211(Memcached), 2049(NFS), 5672(RabbitMQ)
**Risk Assessment:** Risky ports (Telnet, FTP, RDP, database, Redis, MongoDB etc.) flagged as high severity

---

### `modules/dns_checker.py` — DNS Analysis

**Function:** `check_dns(hostname) → DNSResult`
**Returns:** `DNSResult(hostname, ip_addresses, reverse_dns, records[], has_spf, has_dmarc, has_dkim, ping_result, issues)`
**Checks:** A, AAAA, MX, NS, TXT, CNAME records; SPF/DMARC/DKIM presence; ping latency
**Note:** Synchronous — called via `run_in_executor()`

---

### `modules/tech_detector.py` — Technology Detection

**Function:** `detect_technologies(url) → TechResult` (async)
**Returns:** `TechResult(url, cms, server, technologies[], js_libraries[], meta_tags{}, issues)`
**Detects:**
- CMS: WordPress, Joomla, Drupal, Shopify, Wix, Squarespace, Magento, Laravel, Django, Rails, Next.js, Nuxt.js, Gatsby
- JS Libraries: jQuery, React, Vue, Angular, Bootstrap, Tailwind, Lodash, Moment, Axios
- Server: From Server header
- Technologies: Programming language indicators (PHP, ASP.NET, Python, Ruby, Java)

---

### `modules/vuln_checker.py` — Vulnerability Assessment

**Function:** `check_vulnerabilities(url) → VulnResult` (async)
**Returns:** `VulnResult(url, exposed_paths[], form_issues[], mixed_content[], email_addresses[], issues[], credential_tests[])`
**Checks:**
- Exposed paths: `.env`, `.git/config`, `wp-admin`, `phpmyadmin`, `server-status`, `.DS_Store`, `backup.sql`, `debug/`, `api/docs`, `.well-known/security.txt`
- Form security: CSRF tokens, password autocomplete, action URLs
- Mixed content detection
- Email address exposure
- Lists 8 credential-required tests (RBAC, API auth, session mgmt, etc.)

---

### `modules/deep_scanner.py` — Authenticated Deep Scanner

**Function:** `run_deep_scan(url, auth_type, credential) → DeepScanResult` (async)
**Returns:** `DeepScanResult(url, auth_type, api_deep[], db_deep[], admin_deep[], session_deep[], all_issues[], error)`

**4 Deep Scan Layers (using provided credentials):**

**1. API Deep Scan (`_api_deep_scan`):**
- Authentication validation (compare auth vs non-auth responses)
- Rate limiting test (5 rapid requests, check for 429)
- API endpoint discovery (13 common paths: /api, /graphql, /swagger.json, etc.)
- Auth bypass test (try endpoints without credentials)
- IDOR guidance (Insecure Direct Object Reference)

**2. Database Audit (`_db_deep_scan`):**
- Database admin panel discovery (14 paths: phpMyAdmin, Adminer, pgAdmin, Mongo Express, Redis Commander, etc.)
- SQL injection detection (error-based, 4 payloads, 12 error patterns)
- Data export endpoint discovery (12 paths: /api/users, /api/export, /backup, etc.)

**3. Admin Panel Audit (`_admin_deep_scan`):**
- Admin panel discovery (18 common paths)
- Login requirement detection (password input detection)
- RBAC / privilege escalation test (9 higher-privilege paths)
- Sensitive file exposure (15 files: .env, config.json, .git/config, Dockerfile, etc.)

**4. Session Security (`_session_deep_scan`):**
- Cookie security analysis (HttpOnly, Secure, SameSite flags)
- Token/key exposure in response body (7 patterns: JWT, Stripe, AWS, GitHub, Slack)
- Session fixation test
- CORS with credentials reflection test
- Cache control analysis for authenticated pages

**Auth Types Supported:** `cookie`, `bearer`, `apikey`, `basic`
**Helper:** `_build_headers(auth_type, credential)` — builds HTTP headers for each auth type

---

### `modules/enterprise_checker.py` — Enterprise CRM Security

**Function:** `check_enterprise_security(url) → EnterpriseResult` (async)
**Returns:** `EnterpriseResult(url, api_security[], db_security[], app_security[], infra_security[], api_integrations[], all_issues[], agency_pricing[])`

**4 Security Layers:**

**A. API Security:**
- Rate limiting (X-RateLimit headers)
- DDoS protection (Cloudflare/CDN detection)
- API authentication (JWT/Bearer/OAuth detection)
- Encryption (HTTPS + HSTS)
- CORS policy analysis

**B. Database Security:**
- DB info disclosure (MySQL/PostgreSQL/MongoDB/Redis references in HTML)
- DB admin panel exposure (phpMyAdmin, Adminer, pgAdmin)
- SQL injection indicators (passive)
- Row-level security (RLS) recommendations

**C. Application Security (OWASP):**
- XSS protection (CSP + X-XSS-Protection)
- CSRF protection (form token detection)
- Clickjacking (X-Frame-Options + CSP frame-ancestors)
- SSRF protection assessment
- Bot/brute force protection (CAPTCHA detection)

**D. Infrastructure Security:**
- CDN/WAF detection (Cloudflare, Akamai, Fastly, CloudFront)
- Server information disclosure
- Container/orchestration indicators
- Security monitoring tools detection

**API Integration Detection (GoHighLevel-type):**
Detects references to: SendGrid, Mailgun, Amazon SES, Postmark, Twilio, Stripe, PayPal, Square, Braintree, OpenAI, Anthropic, ElevenLabs, Google Analytics, Facebook Pixel, Segment, Mixpanel, HubSpot, Salesforce, Zendesk, Intercom

**Exposed API Key Patterns:**
Regex detection for: Stripe (`sk_live_`, `sk_test_`), OpenAI (`sk-`), SendGrid (`SG.`), AWS (`AKIA`), Google (`AIza`), Twilio (`SK`), Mailgun (`key-`)

**Agency Pricing (14 services):**
Basic Security Audit ($500-$1,500) → Incident Response Retainer ($3,000-$10,000/mo)

---

### `static/js/scanner.js` — Frontend Logic

**Key Variables:**
- `currentScan` — Active scan ID
- `pollInterval` — Polling timer reference
- `currentScanData` — Stored scan results (used by PDF/email)
- `API_BASE` — Backend URL (empty = same origin)

**Key Functions:**
| Function | Purpose |
|----------|---------|
| `startScan()` | Collects URL + scan types, POST to /api/scan |
| `pollScanStatus()` | Polls /api/scan/{id} every 1s until completed |
| `renderResults(data)` | Master render — calls summary + tabs |
| `renderSummary(data)` | Grade card + severity count cards |
| `renderTabContents(data)` | Renders all 10 tab panels |
| `switchTab(tabId)` | Tab switching logic |
| `renderOverview(data)` | All issues sorted by severity |
| `renderSSL(ssl)` | SSL certificate details table |
| `renderHeaders(headers)` | Present/missing headers table |
| `renderPorts(ports)` | Open ports table |
| `renderDNS(dns)` | DNS records + ping results |
| `renderTech(tech)` | CMS, JS libs, meta tags |
| `renderVulns(vulns)` | Exposed paths, form issues |
| `renderEnterprise(ent)` | 4 security layers with status badges + fix code |
| `renderCredentials(creds)` | Auth-required tests list |
| `renderPricing(pricing)` | Agency pricing table |
| `generatePDF()` | Opens new window with styled HTML report, triggers print |
| `showEmailModal()` | Opens email modal |
| `sendEmail()` | Creates mailto: link with report summary |
| `exportJSON()` | Downloads scan data as JSON |
| `exportCSV()` | Downloads issues as CSV |

---

### `templates/dashboard.html` — Main Dashboard

**Structure:**
- Header: Logo + "Auth Scan" link + "Embed Code" button
- Scanner section: URL input + 7 scan type checkboxes + Start button + progress bar
- Results section: Export bar (JSON/CSV/PDF/Email/Print/New) + Summary cards + 9 tabs + tab content
- Embed modal: iframe/JS embed code
- Email modal: To/Subject/Body fields + Send button

**Tabs (9):** Overview, SSL/TLS, Headers, Ports, DNS, Technology, Vulnerabilities, Enterprise CRM, Auth Required, Agency Pricing

---

### `templates/authenticated.html` — Authenticated Deep Scan

**Structure:**
- Header with "Back to Scanner" link
- Form: Target URL + Auth Type dropdown (Cookie/Bearer/API Key/Basic Auth) + Credential input
- "What Deep Scan Checks" info box showing 4 scan types
- "Start Authenticated Deep Scan" button with progress bar
- Results section with tabbed interface:
  - **Overview** — all issues sorted by severity with category badges
  - **API Deep Scan** — auth validation, rate limiting, endpoint discovery, IDOR
  - **Database Audit** — admin panels, SQL injection, data export
  - **Admin Panel** — RBAC, privilege escalation, sensitive files
  - **Session Security** — cookies, tokens, CORS, cache control
  - **Enterprise CRM** — API/DB/App/Infra security layers
- PDF report generation for deep scan results
- Security note about credential handling

**Key JS Functions:**
- `startAuthScan()` — sends URL + auth_type + credential to `/api/scan` with `deep` scan type
- `renderAuthResults(data)` — renders summary + tabbed deep scan results
- `renderDeepSection(title, items, icon)` — renders check items with status badges + fix code
- `generateDeepPDF()` — generates printable PDF with all deep scan findings
- `switchDeepTab(tabId)` — tab navigation

---

### `securescan-pro.html` — Standalone File (~47KB)

**Self-contained single HTML file with embedded CSS + JS.**
- Set `const API = 'https://your-backend-url'` to connect to backend
- Contains: Scanner form, tab system, PDF generation, email modal
- Tabs: Scanner, Auth Scan, Agency Pricing
- Can be hosted on any static server or opened locally

---

## Common Modification Scenarios

### Add a new scanning module:
1. Create `modules/new_checker.py` with async function returning a dataclass
2. Import in `app.py` line ~28
3. Add to `run_scan()` function (~line 105) with progress tracking
4. Add to default `scan_types` in `start_scan()` line 208
5. Add checkbox in `dashboard.html` line ~62
6. Add tab button in `dashboard.html` line ~104
7. Add `renderNewModule()` function in `scanner.js`
8. Add to `renderTabContents()` in `scanner.js` line ~148

### Change grading logic:
- Edit `overall_grade()` in `app.py` lines 88-102

### Add new agency pricing service:
- Edit `AGENCY_PRICING` dict in `modules/enterprise_checker.py` lines 12-27

### Change UI theme/colors:
- Edit `static/css/style.css` — CSS variables at top of file

### Add new API integration detection:
- Edit `enterprise_checker.py` — `api_integration_patterns` list (~line 250)

### Add new exposed path check:
- Edit `vuln_checker.py` — `sensitive_paths` list

### Change scan polling interval:
- Edit `scanner.js` line 95 — `setInterval(..., 1000)` (currently 1 second)

---

## API Reference

### POST /api/scan
```json
Request: {"url": "https://example.com", "scan_types": ["ssl","headers","ports","dns","tech","vulns","enterprise"]}
Response: {"scan_id": "abc12345", "status": "queued", "url": "https://example.com"}
```

### GET /api/scan/{scan_id}
```json
Response: {
  "scan_id": "abc12345",
  "status": "running|completed|error",
  "progress": 57,
  "current_module": "Port Scanning",
  "results": { "ssl": {...}, "headers": {...}, ... },
  "summary": { "grade": "D", "total_issues": 14, "by_severity": {...} },
  "all_issues": [...],
  "credential_tests": [...],
  "agency_pricing": [...]
}
```

---

## Dependencies

```
fastapi        — Web framework
uvicorn        — ASGI server
httpx          — Async HTTP client
beautifulsoup4 — HTML parsing
jinja2         — Template engine
python-multipart — Form handling
dnspython      — DNS resolution
```

---

## New: `templates/pricing.html` — Professional Services & Pricing Page

**Route:** `GET /pricing`
**CSS:** `static/css/pricing.css` (380 lines)

**Features:**
- **4 SaaS Tiers:** Free ($0), Pro ($49/mo), Business ($149/mo), Enterprise ($499/mo)
- **Monthly/Annual toggle:** 40% discount on annual (JS `toggleBilling()`)
- **16 Professional Services** with market rates ($200-$75,000)
- **Competitor Comparison Table:** SecureScan Pro vs HostedScan, Detectify, Intruder, Pentest-Tools
- **Contact Sales Modal:** mailto: integration for enterprise inquiries
- **Navigation:** Links to Scanner (`/`), Auth Scan (`/authenticated`), Pricing (`/pricing`)

**To modify pricing:**
- Tiers: Edit `<div class="tier-card">` blocks in `pricing.html`
- Services: Edit `<div class="service-card">` blocks in `pricing.html`
- Comparison: Edit `<table class="comparison-table">` in `pricing.html`
- Styling: Edit `static/css/pricing.css`

---

## Documentation Files (in repo root)

### `SecureScanPro-Implementation-Roadmap.md`
- **Phase 1:** Professional Services & Pricing (DONE)
- **Phase 2:** Third-party API integrations — NVD CVE, Shodan, VirusTotal, HIBP, SecurityTrails, Safe Browsing (DONE)
- **Phase 3:** CVSS v3.1 scoring + OWASP Top 10 + PCI DSS compliance mapping (DONE — core complete, monitoring & subdomain pending)
- **Phase 4:** Report & UI (whitelabel branding, executive summary, multi-language)
- **Phase 5:** Infrastructure (database, user auth, webhooks, CI/CD, rate limiting)
- Revenue projections: $2,700-$64,000/month

### `SecureScanPro-Competitor-Analysis.md`
- Top 10 competitors analyzed: Qualys SSL Labs, Mozilla Observatory, Sucuri, HostedScan, Pentest-Tools, ImmuniWeb, Detectify, Intruder.io, SecScanner.app, Nuclei
- Each competitor: how it works, APIs used internally, report formats, pricing, vs SecureScan Pro
- Feature comparison matrix

---

## Notes for AI Models

- **No database** — all scan data in-memory dict (`scans` in app.py). Restarting server clears data.
- **No authentication** on the scanner itself — anyone with access can scan.
- **Passive scanning only** — no actual exploitation, safe to run against any site.
- **Deep scanner** accepts credentials (Cookie/Bearer/API Key/Basic Auth) and makes authenticated requests for deeper checks.
- **PDF** is generated client-side via `window.open()` + `window.print()`, not server-side.
- **Email** uses `mailto:` protocol, no SMTP integration.
- **securescan-pro.html** needs `API` variable set to backend URL to work.
- **Pricing page** is static HTML — no backend payment processing. Contact Sales uses mailto:.
- **Fly.io deployment:** https://security-scanner-kuaqjqeo.fly.dev/ (requires `fastapi[standard]` in pyproject.toml)

### `modules/threat_intel.py` — Threat Intelligence (6 APIs)

**Function:** `run_threat_intel(url, hostname, detected_techs) → ThreatIntelResult` (async)
**Returns:** `ThreatIntelResult(cve_matches, safe_browsing, shodan_data, virustotal_data, breach_data, subdomain_data, all_issues, apis_used, apis_skipped)`

**6 Integrations:**
| API | Env Variable | Free? | What it does |
|-----|-------------|-------|--------------|
| NVD CVE Database | None needed | YES | Matches detected technologies to known CVEs with CVSS scores |
| Google Safe Browsing | `GOOGLE_SAFE_BROWSING_KEY` | Optional | Checks URL against malware/phishing/social engineering lists |
| Shodan | `SHODAN_API_KEY` | Optional | IP intelligence — open ports, services, OS, known vulns |
| VirusTotal | `VIRUSTOTAL_API_KEY` | Optional | Multi-engine domain reputation (70+ antivirus engines) |
| Have I Been Pwned | `HIBP_API_KEY` | Optional | Data breach history for the domain |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | Optional | Subdomain discovery and DNS history |

**Graceful Degradation:** If no API key → adds to `apis_skipped`, returns empty result for that API. NVD always works (no key needed).

---

### `modules/cvss_engine.py` — CVSS v3.1 + Compliance

**Function:** `enrich_issues_with_cvss(issues) → ComplianceResult`
**Returns:** `ComplianceResult(cvss_enriched, owasp_summary, pci_dss_summary, risk_score, risk_level, compliance_status, owasp_coverage, pci_dss_coverage)`

**What it does:**
1. Maps each vulnerability title to a CVSS v3.1 vector (30+ mappings)
2. Calculates base score using CVSS v3.1 formula
3. Maps to OWASP Top 10 (2021) categories
4. Maps to PCI DSS v4.0 requirements (14 requirements)
5. Calculates overall risk score (avg CVSS) and risk level
6. Generates compliance coverage grids for both OWASP and PCI DSS

**CVSS Calculator:** `calculate_cvss_score(vector) → (score, severity)`
- Uses all 8 base metrics: AV, AC, PR, UI, S, C, I, A
- Returns score 0.0-10.0 and severity label (None/Low/Medium/High/Critical)

---

## Next Steps (for new chat sessions)

Read `NEXT_STEPS.md` for the complete plan with instructions. Quick summary:
1. **Phase 3 (remaining):** Continuous monitoring (scheduled scans), passive subdomain discovery
2. **Phase 4:** Whitelabel branded reports, executive summary, multi-language
3. **Phase 5:** Database (PostgreSQL), user auth, webhooks, CI/CD, rate limiting
4. **Phase 5:** Database (PostgreSQL) + user authentication + scheduled scans
