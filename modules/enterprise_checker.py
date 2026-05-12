"""Enterprise CRM Security Checker - API, Database, App, Infrastructure checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


AGENCY_PRICING = {
    "basic_scan": {"label": "Basic Security Audit", "price_range": "$500 - $1,500"},
    "header_audit": {"label": "Security Headers Audit", "price_range": "$300 - $800"},
    "ssl_audit": {"label": "SSL/TLS Assessment", "price_range": "$200 - $500"},
    "port_scan": {"label": "Network Port Scan", "price_range": "$500 - $1,200"},
    "dns_audit": {"label": "DNS Security Audit", "price_range": "$300 - $700"},
    "api_security": {"label": "API Security Assessment", "price_range": "$2,000 - $5,000"},
    "db_security": {"label": "Database Security Audit", "price_range": "$3,000 - $8,000"},
    "app_security": {"label": "Application Pentest (OWASP)", "price_range": "$5,000 - $15,000"},
    "infra_security": {"label": "Infrastructure Security Audit", "price_range": "$4,000 - $12,000"},
    "full_pentest": {"label": "Full Penetration Test", "price_range": "$10,000 - $30,000"},
    "compliance_audit": {"label": "Compliance Audit (PCI/GDPR/SOC2)", "price_range": "$8,000 - $25,000"},
    "crm_security": {"label": "CRM/SaaS Security Assessment", "price_range": "$5,000 - $15,000"},
    "api_integration": {"label": "API Integration Security Review", "price_range": "$2,000 - $6,000"},
    "incident_response": {"label": "Incident Response Retainer", "price_range": "$3,000 - $10,000/mo"},
}


@dataclass
class EnterpriseResult:
    url: str = ""
    api_security: list[dict] = field(default_factory=list)
    db_security: list[dict] = field(default_factory=list)
    app_security: list[dict] = field(default_factory=list)
    infra_security: list[dict] = field(default_factory=list)
    api_integrations: list[dict] = field(default_factory=list)
    all_issues: list[dict] = field(default_factory=list)
    agency_pricing: list[dict] = field(default_factory=list)
    error: str = ""


async def check_enterprise_security(url: str, timeout: int = 15) -> EnterpriseResult:
    result = EnterpriseResult(url=url)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=timeout
        ) as client:
            resp = await client.get(url)
            html = resp.text
            headers = resp.headers
            soup = BeautifulSoup(html, "html.parser")

            # ── A. API SECURITY CHECKS ──
            # Rate limiting
            rate_headers = ["x-ratelimit-limit", "x-ratelimit-remaining", "retry-after",
                           "x-rate-limit-limit", "ratelimit-limit"]
            has_rate_limit = any(h in headers for h in rate_headers)
            result.api_security.append({
                "check": "Rate Limiting",
                "method": "HTTP Header Detection",
                "status": "protected" if has_rate_limit else "vulnerable",
                "severity": "high" if not has_rate_limit else "info",
                "detail": "Rate limiting headers detected" if has_rate_limit else "No rate limiting headers found. DDoS and brute force attacks possible.",
                "solution": "Implement rate limiting using Redis, Nginx, or API gateway. Set X-RateLimit-* headers.",
                "fix_code": "# Express.js example\nconst rateLimit = require('express-rate-limit');\napp.use(rateLimit({ windowMs: 15*60*1000, max: 100 }));",
            })
            if not has_rate_limit:
                result.all_issues.append({"severity": "high", "title": "No Rate Limiting", "description": "API has no rate limiting. Vulnerable to DDoS/brute force.", "recommendation": "Implement rate limiting with Redis or API gateway.", "category": "API Security"})

            # DDoS Protection (Cloudflare/CDN)
            cf_headers = ["cf-ray", "cf-cache-status", "cf-request-id", "server"]
            has_cloudflare = any(
                "cloudflare" in headers.get(h, "").lower() for h in cf_headers
            ) or "cf-ray" in headers
            has_cdn = has_cloudflare or any(
                cdn in headers.get("server", "").lower()
                for cdn in ["akamai", "fastly", "cloudfront", "incapsula", "sucuri"]
            )
            result.api_security.append({
                "check": "DDoS Protection",
                "method": "CDN/WAF Detection",
                "status": "protected" if has_cdn else "vulnerable",
                "severity": "high" if not has_cdn else "info",
                "detail": f"CDN/WAF detected: {'Cloudflare' if has_cloudflare else 'Other CDN'}" if has_cdn else "No CDN/WAF protection detected.",
                "solution": "Use Cloudflare, AWS CloudFront, or Akamai for DDoS protection and WAF.",
            })
            if not has_cdn:
                result.all_issues.append({"severity": "high", "title": "No DDoS Protection", "description": "No CDN/WAF detected. Server directly exposed to attacks.", "recommendation": "Deploy behind Cloudflare or similar CDN with WAF.", "category": "API Security"})

            # JWT / Auth detection
            auth_header = headers.get("www-authenticate", "")
            has_jwt_refs = bool(re.search(r"(jwt|bearer|oauth|token)", html.lower()))
            result.api_security.append({
                "check": "API Authentication",
                "method": "Auth Header/JWT Detection",
                "status": "detected" if (auth_header or has_jwt_refs) else "unknown",
                "severity": "info",
                "detail": f"Auth mechanism: {auth_header}" if auth_header else ("JWT/Token references found in page" if has_jwt_refs else "No authentication mechanism detected publicly."),
                "solution": "Use JWT with short expiry + refresh token rotation. Never expose tokens in HTML.",
            })

            # HTTPS / TLS
            is_https = url.startswith("https://")
            hsts = headers.get("strict-transport-security", "")
            result.api_security.append({
                "check": "Encryption (HTTPS/TLS)",
                "method": "Protocol Check",
                "status": "protected" if is_https else "vulnerable",
                "severity": "critical" if not is_https else ("medium" if not hsts else "info"),
                "detail": f"HTTPS: {'Yes' if is_https else 'No'}, HSTS: {'Yes' if hsts else 'No'}",
                "solution": "Enforce HTTPS with TLS 1.3. Add HSTS header with max-age=31536000.",
            })
            if not is_https:
                result.all_issues.append({"severity": "critical", "title": "No HTTPS", "description": "Site not using HTTPS. All traffic is unencrypted.", "recommendation": "Enable HTTPS with TLS 1.3 and enforce HSTS.", "category": "API Security"})

            # CORS check
            cors = headers.get("access-control-allow-origin", "")
            cors_unsafe = cors == "*"
            result.api_security.append({
                "check": "CORS Policy",
                "method": "Header Analysis",
                "status": "vulnerable" if cors_unsafe else ("configured" if cors else "not_set"),
                "severity": "medium" if cors_unsafe else "info",
                "detail": f"CORS: {cors}" if cors else "No CORS header (may be fine for non-API pages).",
                "solution": "Set Access-Control-Allow-Origin to specific trusted domains only. Never use '*' in production.",
            })
            if cors_unsafe:
                result.all_issues.append({"severity": "medium", "title": "CORS Wildcard", "description": "CORS allows all origins (*). Any website can make requests.", "recommendation": "Restrict CORS to specific trusted domains.", "category": "API Security"})

            # ── B. DATABASE SECURITY CHECKS ──
            # Check for exposed database info
            db_exposure_patterns = [
                (r"(mysql|postgresql|mongodb|redis|sqlite)", "Database technology exposed in source"),
                (r"(db_host|db_pass|db_user|database_url)", "Database credentials reference found"),
                (r"(phpmyadmin|adminer|pgadmin)", "Database admin tool reference"),
            ]
            for pattern, desc in db_exposure_patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    result.db_security.append({
                        "check": "Database Information Disclosure",
                        "status": "vulnerable",
                        "severity": "high",
                        "detail": desc,
                        "solution": "Remove all database references from frontend code. Use environment variables.",
                    })
                    result.all_issues.append({"severity": "high", "title": "Database Info Exposed", "description": desc, "recommendation": "Remove database references from public code.", "category": "Database Security"})

            # Check for common DB admin paths
            db_admin_paths = ["/phpmyadmin", "/adminer.php", "/pgadmin", "/_profiler"]
            for path in db_admin_paths:
                try:
                    r = await client.get(f"{url.rstrip('/')}{path}")
                    if r.status_code == 200 and len(r.text) > 100:
                        result.db_security.append({
                            "check": f"DB Admin Panel Exposed: {path}",
                            "status": "vulnerable",
                            "severity": "critical",
                            "detail": f"Database admin panel accessible at {path}",
                            "solution": f"Restrict access to {path} via IP whitelist or VPN. Remove from public access.",
                        })
                        result.all_issues.append({"severity": "critical", "title": f"DB Admin Exposed: {path}", "description": f"Database admin panel publicly accessible at {path}", "recommendation": "Block public access immediately. Use IP whitelist.", "category": "Database Security"})
                except Exception:
                    pass

            result.db_security.append({
                "check": "SQL Injection Indicators",
                "status": "check_required",
                "severity": "info",
                "detail": "Passive check cannot fully test SQL injection. Active testing with credentials recommended.",
                "solution": "Use parameterized queries (ORM like Prisma/SQLAlchemy). Never concatenate user input into SQL.",
                "fix_code": "# Use ORM\nuser = db.query(User).filter(User.id == user_id).first()\n# NEVER: db.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            })

            result.db_security.append({
                "check": "Row-Level Security (RLS)",
                "status": "requires_auth",
                "severity": "info",
                "detail": "RLS check requires database access. Recommend PostgreSQL RLS for multi-tenant apps.",
                "solution": "Enable PostgreSQL RLS policies. Each tenant should only see their own data.",
            })

            # ── C. APPLICATION SECURITY CHECKS ──
            # XSS checks
            csp = headers.get("content-security-policy", "")
            xss_protection = headers.get("x-xss-protection", "")
            result.app_security.append({
                "check": "XSS Protection",
                "status": "protected" if csp else ("partial" if xss_protection else "vulnerable"),
                "severity": "high" if not csp and not xss_protection else ("medium" if not csp else "info"),
                "detail": f"CSP: {'Set' if csp else 'Missing'}, X-XSS-Protection: {'Set' if xss_protection else 'Missing'}",
                "solution": "Implement Content-Security-Policy header. Sanitize all user input. Use DOMPurify for frontend.",
                "fix_code": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            })
            if not csp:
                result.all_issues.append({"severity": "high", "title": "XSS Vulnerability Risk", "description": "No Content-Security-Policy. XSS attacks possible.", "recommendation": "Add CSP header to prevent inline script execution.", "category": "App Security"})

            # CSRF
            forms = soup.find_all("form")
            csrf_found = False
            for form in forms:
                inputs = form.find_all("input")
                if any("csrf" in (inp.get("name", "") + inp.get("id", "")).lower() for inp in inputs):
                    csrf_found = True
            result.app_security.append({
                "check": "CSRF Protection",
                "status": "detected" if csrf_found else ("no_forms" if not forms else "vulnerable"),
                "severity": "high" if forms and not csrf_found else "info",
                "detail": "CSRF tokens found in forms" if csrf_found else ("No forms found" if not forms else "Forms without CSRF tokens detected"),
                "solution": "Add CSRF tokens to all forms. Use SameSite=Strict cookies.",
            })
            if forms and not csrf_found:
                result.all_issues.append({"severity": "high", "title": "CSRF Not Detected", "description": "Forms found without CSRF token protection.", "recommendation": "Add CSRF tokens to all POST forms.", "category": "App Security"})

            # Clickjacking
            x_frame = headers.get("x-frame-options", "")
            csp_frame = "frame-ancestors" in csp if csp else False
            result.app_security.append({
                "check": "Clickjacking Protection",
                "status": "protected" if (x_frame or csp_frame) else "vulnerable",
                "severity": "medium" if not (x_frame or csp_frame) else "info",
                "detail": f"X-Frame-Options: {x_frame or 'Missing'}, CSP frame-ancestors: {'Set' if csp_frame else 'Missing'}",
                "solution": "Add X-Frame-Options: DENY and CSP frame-ancestors 'self'.",
            })

            # SSRF indicators
            result.app_security.append({
                "check": "SSRF Protection",
                "status": "requires_testing",
                "severity": "info",
                "detail": "SSRF requires active testing. Check URL parameters that fetch external resources.",
                "solution": "Validate and whitelist allowed URLs. Block internal IPs (127.0.0.1, 10.x, 192.168.x).",
            })

            # Bot/Brute Force
            captcha_found = bool(re.search(r"(recaptcha|hcaptcha|captcha|turnstile)", html, re.IGNORECASE))
            result.app_security.append({
                "check": "Bot/Brute Force Protection",
                "status": "detected" if captcha_found else "not_detected",
                "severity": "medium" if not captcha_found else "info",
                "detail": "CAPTCHA detected" if captcha_found else "No CAPTCHA or bot protection detected.",
                "solution": "Add reCAPTCHA/Turnstile on login/signup forms. Implement account lockout after failed attempts.",
            })
            if not captcha_found:
                result.all_issues.append({"severity": "medium", "title": "No Bot Protection", "description": "No CAPTCHA detected. Brute force attacks possible.", "recommendation": "Add Cloudflare Turnstile or Google reCAPTCHA.", "category": "App Security"})

            # ── D. INFRASTRUCTURE SECURITY CHECKS ──
            server = headers.get("server", "")
            powered_by = headers.get("x-powered-by", "")

            # CDN/WAF already checked above
            result.infra_security.append({
                "check": "CDN / WAF",
                "status": "active" if has_cdn else "not_detected",
                "severity": "high" if not has_cdn else "info",
                "detail": f"CDN: {'Cloudflare' if has_cloudflare else ('Detected' if has_cdn else 'None')}, WAF: {'Active' if has_cloudflare else 'Unknown'}",
                "solution": "Deploy behind Cloudflare (free tier available). Enable WAF rules.",
            })

            # Server info disclosure
            result.infra_security.append({
                "check": "Server Information Disclosure",
                "status": "exposed" if server else "hidden",
                "severity": "low" if server else "info",
                "detail": f"Server: {server}" if server else "Server header suppressed (good).",
                "solution": "Remove or mask Server header. Eg: nginx: server_tokens off;",
            })

            if powered_by:
                result.infra_security.append({
                    "check": "Technology Stack Disclosure",
                    "status": "exposed",
                    "severity": "low",
                    "detail": f"X-Powered-By: {powered_by}",
                    "solution": "Remove X-Powered-By header. Eg Express: app.disable('x-powered-by');",
                })

            # Container/K8s indicators
            k8s_headers = ["x-kubernetes", "x-envoy", "x-istio"]
            has_k8s = any(h in headers for h in k8s_headers)
            result.infra_security.append({
                "check": "Container/Orchestration",
                "status": "detected" if has_k8s else "not_detected",
                "severity": "info",
                "detail": "Kubernetes/Envoy indicators found" if has_k8s else "No container orchestration indicators detected publicly.",
                "solution": "Use Docker + Kubernetes. Scan container images with Trivy. Use network policies.",
            })

            # Monitoring
            monitoring_patterns = [r"datadog", r"newrelic", r"sentry", r"bugsnag", r"logrocket"]
            has_monitoring = any(re.search(p, html, re.IGNORECASE) for p in monitoring_patterns)
            result.infra_security.append({
                "check": "Security Monitoring",
                "status": "detected" if has_monitoring else "not_detected",
                "severity": "medium" if not has_monitoring else "info",
                "detail": "Monitoring/error tracking detected" if has_monitoring else "No monitoring tools detected.",
                "solution": "Use Datadog, Sentry, or New Relic for monitoring. Set up alerts for anomalies.",
            })

            # ── E. API INTEGRATION CHECKS (GoHighLevel-type) ──
            api_patterns = {
                "SendGrid": [r"sendgrid", r"sg\."],
                "Mailgun": [r"mailgun"],
                "Amazon SES": [r"ses\.amazonaws", r"aws-ses"],
                "Postmark": [r"postmark"],
                "Twilio": [r"twilio", r"twilio\.com"],
                "Telnyx": [r"telnyx"],
                "Meta WhatsApp": [r"graph\.facebook", r"whatsapp", r"wa\.me"],
                "Stripe": [r"stripe\.com", r"stripe\.js", r"pk_live", r"pk_test"],
                "PayPal": [r"paypal\.com", r"paypalobjects"],
                "OpenAI": [r"openai", r"chatgpt"],
                "Anthropic": [r"anthropic", r"claude"],
                "Google Calendar": [r"calendar\.google", r"googleapis.*calendar"],
                "Google Analytics": [r"google-analytics", r"gtag", r"ga\.js", r"googletagmanager"],
                "Facebook Pixel": [r"facebook\.net", r"fbevents", r"fb-pixel"],
                "TikTok": [r"tiktok\.com", r"analytics\.tiktok"],
                "LinkedIn": [r"linkedin\.com/"],
                "YouTube": [r"youtube\.com", r"ytimg"],
                "reCAPTCHA": [r"recaptcha", r"google\.com/recaptcha"],
                "Cloudflare Turnstile": [r"turnstile", r"challenges\.cloudflare"],
            }

            for api_name, patterns in api_patterns.items():
                detected = any(re.search(p, html, re.IGNORECASE) for p in patterns)
                if detected:
                    result.api_integrations.append({
                        "name": api_name,
                        "status": "detected",
                        "detail": f"{api_name} integration detected in page source.",
                        "security_note": f"Ensure {api_name} API keys are server-side only. Never expose secret keys in frontend.",
                    })

            # Check for exposed API keys in source
            key_patterns = [
                (r"sk_live_[a-zA-Z0-9]{20,}", "Stripe Secret Key EXPOSED"),
                (r"sk_test_[a-zA-Z0-9]{20,}", "Stripe Test Secret Key exposed"),
                (r"pk_live_[a-zA-Z0-9]{20,}", "Stripe Publishable Key (OK for frontend)"),
                (r"sk-[a-zA-Z0-9]{40,}", "Possible OpenAI/API Secret Key EXPOSED"),
                (r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}", "SendGrid API Key EXPOSED"),
                (r"key-[a-zA-Z0-9]{32}", "Possible Mailgun Key EXPOSED"),
                (r"AKIA[A-Z0-9]{16}", "AWS Access Key EXPOSED"),
                (r"AIza[a-zA-Z0-9_-]{35}", "Google API Key exposed"),
            ]
            for pattern, desc in key_patterns:
                if re.search(pattern, html):
                    is_public_ok = "Publishable" in desc
                    result.all_issues.append({
                        "severity": "info" if is_public_ok else "critical",
                        "title": desc,
                        "description": f"API key matching pattern found in page source: {desc}",
                        "recommendation": "Immediately rotate this key. Move to server-side environment variables.",
                        "category": "API Security",
                    })

            # Agency pricing
            result.agency_pricing = [
                {"service": v["label"], "price_range": v["price_range"]}
                for v in AGENCY_PRICING.values()
            ]

    except Exception as e:
        result.error = str(e)

    return result
