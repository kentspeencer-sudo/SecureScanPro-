"""Vulnerability & Misconfiguration Checker (Passive/Defensive Only)."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup


SENSITIVE_PATHS = [
    ("/.env", "Environment file exposed"),
    ("/.git/config", "Git repository exposed"),
    ("/.git/HEAD", "Git repository exposed"),
    ("/wp-admin/", "WordPress admin panel"),
    ("/wp-login.php", "WordPress login page"),
    ("/administrator/", "Joomla admin panel"),
    ("/admin/", "Admin panel"),
    ("/phpmyadmin/", "phpMyAdmin exposed"),
    ("/server-status", "Apache server-status"),
    ("/server-info", "Apache server-info"),
    ("/.htaccess", ".htaccess file accessible"),
    ("/.htpasswd", ".htpasswd file accessible"),
    ("/robots.txt", "Robots.txt"),
    ("/sitemap.xml", "Sitemap.xml"),
    ("/crossdomain.xml", "Flash cross-domain policy"),
    ("/xmlrpc.php", "WordPress XML-RPC"),
    ("/api/", "API endpoint"),
    ("/swagger/", "Swagger UI"),
    ("/api-docs/", "API Documentation"),
    ("/graphql", "GraphQL endpoint"),
    ("/debug/", "Debug endpoint"),
    ("/info.php", "PHP info page"),
    ("/phpinfo.php", "PHP info page"),
    ("/backup/", "Backup directory"),
    ("/config.php", "Config file exposed"),
    ("/wp-config.php.bak", "WordPress config backup"),
    ("/.DS_Store", "macOS directory listing"),
    ("/web.config", "IIS web.config"),
]


@dataclass
class VulnResult:
    url: str = ""
    exposed_paths: list[dict] = field(default_factory=list)
    form_issues: list[dict] = field(default_factory=list)
    mixed_content: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    credential_tests: list[dict] = field(default_factory=list)
    error: str = ""


async def check_vulnerabilities(url: str, timeout: int = 10) -> VulnResult:
    result = VulnResult(url=url)

    try:
        base = url.rstrip("/")

        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=timeout
        ) as client:
            resp = await client.get(url)
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            for path, desc in SENSITIVE_PATHS:
                try:
                    check_url = f"{base}{path}"
                    r = await client.get(check_url)
                    if r.status_code == 200 and len(r.text) > 50:
                        is_sensitive = path not in ("/robots.txt", "/sitemap.xml")
                        severity = "critical" if path in (
                            "/.env", "/.git/config", "/.git/HEAD",
                            "/.htpasswd", "/config.php", "/wp-config.php.bak",
                        ) else "high" if is_sensitive else "info"

                        entry = {
                            "path": path,
                            "status": r.status_code,
                            "description": desc,
                            "severity": severity,
                        }
                        result.exposed_paths.append(entry)

                        if severity in ("critical", "high"):
                            result.issues.append({
                                "severity": severity,
                                "title": f"Sensitive Path Exposed: {path}",
                                "description": f"{desc} is publicly accessible at {check_url}",
                                "recommendation": "Restrict access to this path via server configuration.",
                            })
                except Exception:
                    pass

            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action", "")
                method = (form.get("method", "get")).upper()

                inputs = form.find_all("input")
                has_password = any(
                    inp.get("type", "").lower() == "password" for inp in inputs
                )
                has_csrf = any(
                    "csrf" in (inp.get("name", "") + inp.get("id", "")).lower()
                    for inp in inputs
                )

                if has_password and not has_csrf:
                    result.form_issues.append({
                        "severity": "high",
                        "title": "Login Form Without CSRF Protection",
                        "description": f"Form action='{action}' method={method} has password field but no CSRF token.",
                        "recommendation": "Add CSRF token protection to all forms.",
                    })
                    result.issues.append(result.form_issues[-1])

                if has_password and method == "GET":
                    result.form_issues.append({
                        "severity": "high",
                        "title": "Password Sent via GET",
                        "description": f"Form action='{action}' sends password via GET request.",
                        "recommendation": "Use POST method for forms with sensitive data.",
                    })
                    result.issues.append(result.form_issues[-1])

                if has_password and url.startswith("http://"):
                    result.form_issues.append({
                        "severity": "critical",
                        "title": "Login Over Unencrypted HTTP",
                        "description": "Password field on page served over HTTP (not HTTPS).",
                        "recommendation": "Serve login pages over HTTPS only.",
                    })
                    result.issues.append(result.form_issues[-1])

            if url.startswith("https://"):
                for tag in soup.find_all(["img", "script", "link"]):
                    src = tag.get("src") or tag.get("href") or ""
                    if src.startswith("http://"):
                        result.mixed_content.append(src)

                if result.mixed_content:
                    result.issues.append({
                        "severity": "medium",
                        "title": "Mixed Content Detected",
                        "description": f"Found {len(result.mixed_content)} resource(s) loaded over HTTP on HTTPS page.",
                        "recommendation": "Load all resources over HTTPS.",
                    })

            import re
            emails = set(re.findall(
                r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", html
            ))
            result.email_addresses = list(emails)

            result.credential_tests = [
                {
                    "test": "Authenticated Page Crawling",
                    "description": "Crawl all pages behind login to find hidden vulnerabilities.",
                    "requires": "Login credentials (username/password or session cookie)",
                    "depth": "Deep",
                },
                {
                    "test": "Admin Panel Security Audit",
                    "description": "Test admin panel for privilege escalation, IDOR, and auth bypass.",
                    "requires": "Admin credentials",
                    "depth": "Deep",
                },
                {
                    "test": "API Endpoint Testing",
                    "description": "Test API endpoints for authentication bypass and data exposure.",
                    "requires": "API key or JWT token",
                    "depth": "Deep",
                },
                {
                    "test": "Session Management Testing",
                    "description": "Test session handling, timeout, fixation, and hijacking.",
                    "requires": "Valid session/login credentials",
                    "depth": "Medium",
                },
                {
                    "test": "Role-Based Access Control (RBAC)",
                    "description": "Test if users can access resources beyond their role.",
                    "requires": "Multiple user accounts with different roles",
                    "depth": "Deep",
                },
                {
                    "test": "File Upload Security",
                    "description": "Test file upload for malicious file execution.",
                    "requires": "Account with upload permissions",
                    "depth": "Medium",
                },
                {
                    "test": "Payment/Transaction Flow",
                    "description": "Test payment flow for price manipulation and bypass.",
                    "requires": "Account with payment access, test payment credentials",
                    "depth": "Deep",
                },
                {
                    "test": "Database Query Analysis",
                    "description": "Analyze database queries for injection points behind auth.",
                    "requires": "Application credentials",
                    "depth": "Expert",
                },
            ]

    except Exception as e:
        result.error = str(e)

    return result
