# SecureScan Pro - Enterprise Security Scanner

DNA-Level Web Security Analysis Platform with Enterprise CRM Security Checks.

## Features

### 7 Scanning Modules (No Credentials Required)
1. **SSL/TLS Analysis** — Certificate validation, expiry, protocol, cipher strength
2. **Security Headers** — 9+ headers checked, cookie flags, A-F grading
3. **Port Scanner** — 26 common ports, risky service detection, banner grabbing
4. **DNS Analyzer** — Full DNS records, SPF/DMARC/DKIM, reverse DNS, ping stats
5. **Technology Detection** — CMS (WordPress, Laravel, Shopify), JS libraries, server stack
6. **Vulnerability Assessment** — Exposed paths (.env, .git, admin), form security, mixed content
7. **Enterprise CRM Security** — API security, DB security, App security (OWASP), Infrastructure checks

### Enterprise CRM Security Checks
- **API Security**: Rate limiting, DDoS/CDN, JWT/Auth, HTTPS/TLS, CORS policy
- **Database Security**: Info disclosure, admin panel exposure, SQL injection indicators, RLS
- **Application Security**: XSS/CSP, CSRF, clickjacking, SSRF, bot protection
- **Infrastructure Security**: CDN/WAF, server disclosure, container/K8s, monitoring
- **API Integration Detection**: SendGrid, Twilio, Stripe, PayPal, OpenAI, Google Analytics, Facebook Pixel, etc.

### Export & Reporting
- **PDF Report** — Colorful, printable report with severity grading, findings, and fix recommendations
- **JSON Export** — Full structured data
- **CSV Export** — Spreadsheet-ready
- **Email Sharing** — Send reports directly to clients
- **Agency Pricing Reference** — Industry-standard pricing for 14 security services

### Deployment Options
1. **Full Dashboard** — Main scanner at `/`
2. **Authenticated Deep Scan** — Credential-gated advanced testing at `/authenticated`
3. **Embeddable Widget** — Compact scanner for SEO CMS sites at `/embed`
4. **Standalone HTML** — `securescan-pro.html` — single file, host anywhere

## Quick Start

```bash
# Install dependencies
pip install fastapi uvicorn httpx beautifulsoup4 jinja2 python-multipart dnspython

# Run server
uvicorn app:app --host 0.0.0.0 --port 8000

# Open browser
# http://localhost:8000
```

## API

```bash
# Start scan
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Get results
curl http://localhost:8000/api/scan/{scan_id}

# Get report
curl http://localhost:8000/api/scan/{scan_id}/report
```

## Project Structure

```
├── app.py                    # FastAPI application (routes + scan orchestration)
├── main.py                   # Entry point
├── pyproject.toml            # Python dependencies
├── securescan-pro.html       # Standalone HTML file (host on any website)
├── modules/
│   ├── ssl_checker.py        # SSL/TLS certificate analysis
│   ├── header_checker.py     # Security headers grading
│   ├── port_scanner.py       # Network port scanning
│   ├── dns_checker.py        # DNS records & email auth
│   ├── tech_detector.py      # Technology/CMS detection
│   ├── vuln_checker.py       # Vulnerability assessment
│   └── enterprise_checker.py # Enterprise CRM security + API integrations
├── templates/
│   ├── dashboard.html        # Main scanner UI
│   ├── authenticated.html    # Credential-gated deep scan
│   ├── embed.html            # Embeddable widget
│   └── report.html           # Report page
└── static/
    ├── css/style.css         # Dark theme styles
    └── js/
        ├── scanner.js        # Dashboard logic + PDF + Email
        └── embed-widget.js   # Embed widget script
```

## Embed in Your Website

### iframe
```html
<iframe src="YOUR_URL/embed" width="100%" height="600" frameborder="0"></iframe>
```

### Standalone Page
Copy `securescan-pro.html` to your website. Update the `API` variable to point to your backend URL.

## Agency Pricing Reference

| Service | Price Range |
|---------|-------------|
| Basic Security Audit | $500 - $1,500 |
| SSL/TLS Assessment | $200 - $500 |
| API Security Assessment | $2,000 - $5,000 |
| Application Pentest (OWASP) | $5,000 - $15,000 |
| Full Penetration Test | $10,000 - $30,000 |
| Compliance Audit (PCI/GDPR/SOC2) | $8,000 - $25,000 |

## License

MIT
