"""Authenticated Deep Scanner — performs security checks using provided credentials."""

from __future__ import annotations

import re
import base64
from dataclasses import dataclass, field

import httpx


@dataclass
class DeepScanResult:
    url: str = ""
    auth_type: str = ""
    api_deep: list[dict] = field(default_factory=list)
    db_deep: list[dict] = field(default_factory=list)
    admin_deep: list[dict] = field(default_factory=list)
    session_deep: list[dict] = field(default_factory=list)
    all_issues: list[dict] = field(default_factory=list)
    error: str = ""


def _build_headers(auth_type: str, credential: str) -> dict[str, str]:
    """Build HTTP headers from credential type."""
    headers: dict[str, str] = {
        "User-Agent": "SecureScan-Pro/1.0 DeepScanner",
    }
    if auth_type == "bearer":
        headers["Authorization"] = f"Bearer {credential}"
    elif auth_type == "apikey":
        headers["X-API-Key"] = credential
        headers["Authorization"] = f"ApiKey {credential}"
    elif auth_type == "cookie":
        headers["Cookie"] = credential
    elif auth_type == "basic":
        if ":" in credential:
            encoded = base64.b64encode(credential.encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"
        else:
            headers["Authorization"] = f"Basic {credential}"
    return headers


async def run_deep_scan(
    url: str, auth_type: str, credential: str, timeout: int = 15
) -> DeepScanResult:
    result = DeepScanResult(url=url, auth_type=auth_type)
    headers = _build_headers(auth_type, credential)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=timeout, headers=headers
        ) as client:
            # ── 1. API DEEP SCAN ──
            await _api_deep_scan(client, url, headers, result)

            # ── 2. DATABASE DEEP SCAN ──
            await _db_deep_scan(client, url, result)

            # ── 3. ADMIN PANEL AUDIT ──
            await _admin_deep_scan(client, url, result)

            # ── 4. SESSION SECURITY ──
            await _session_deep_scan(client, url, headers, result)

    except Exception as e:
        result.error = str(e)

    return result


async def _api_deep_scan(
    client: httpx.AsyncClient, url: str, headers: dict, result: DeepScanResult
) -> None:
    """Test API endpoints with authentication."""
    base = url.rstrip("/")

    # --- Auth validation: hit root with and without credentials ---
    try:
        auth_resp = await client.get(base)
        no_auth_client = httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=10
        )
        async with no_auth_client as nac:
            no_auth_resp = await nac.get(base)

        auth_works = auth_resp.status_code != no_auth_resp.status_code or (
            auth_resp.status_code == 200
            and len(auth_resp.text) != len(no_auth_resp.text)
        )
        result.api_deep.append({
            "check": "Authentication Validation",
            "status": "authenticated" if auth_works else "no_difference",
            "severity": "info" if auth_works else "medium",
            "detail": "Authenticated response differs from unauthenticated — credentials accepted."
            if auth_works
            else "Authenticated and unauthenticated responses are identical. Credentials may not be reaching the application.",
            "solution": "Ensure API requires valid auth on protected endpoints. Return 401/403 for unauthenticated requests.",
        })
    except Exception:
        result.api_deep.append({
            "check": "Authentication Validation",
            "status": "error",
            "severity": "info",
            "detail": "Could not validate authentication — connection issue.",
            "solution": "Check that the URL is reachable and credentials are correct.",
        })

    # --- Rate limit testing (5 rapid requests) ---
    rate_limited = False
    try:
        for _ in range(5):
            r = await client.get(base)
            if r.status_code == 429:
                rate_limited = True
                break
        result.api_deep.append({
            "check": "Rate Limiting (Authenticated)",
            "status": "protected" if rate_limited else "vulnerable",
            "severity": "info" if rate_limited else "high",
            "detail": "Rate limiting triggered after rapid requests."
            if rate_limited
            else "No rate limiting detected even with rapid authenticated requests.",
            "solution": "Implement per-user rate limiting. Use sliding window algorithm with Redis.",
            "fix_code": "# Redis rate limiter\nimport redis, time\nr = redis.Redis()\ndef check_rate(user_id, limit=100, window=60):\n    key = f'rate:{user_id}'\n    current = r.incr(key)\n    if current == 1: r.expire(key, window)\n    return current <= limit",
        })
    except Exception:
        pass

    # --- Common API endpoints probe ---
    api_paths = [
        ("/api", "API root"),
        ("/api/v1", "API v1 root"),
        ("/api/v2", "API v2 root"),
        ("/api/users", "Users endpoint"),
        ("/api/admin", "Admin API"),
        ("/api/config", "Config endpoint"),
        ("/api/settings", "Settings endpoint"),
        ("/api/health", "Health check"),
        ("/api/status", "Status endpoint"),
        ("/graphql", "GraphQL endpoint"),
        ("/api/docs", "API documentation"),
        ("/swagger.json", "Swagger spec"),
        ("/openapi.json", "OpenAPI spec"),
    ]
    accessible_apis = []
    for path, desc in api_paths:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code in (200, 201, 301, 302) and len(r.text) > 50:
                accessible_apis.append({"path": path, "desc": desc, "status": r.status_code})
        except Exception:
            pass

    if accessible_apis:
        paths_str = ", ".join(a["path"] for a in accessible_apis)
        result.api_deep.append({
            "check": "Accessible API Endpoints",
            "status": "exposed",
            "severity": "medium",
            "detail": f"Found {len(accessible_apis)} accessible endpoints: {paths_str}",
            "solution": "Review each endpoint. Ensure proper authorization checks. Remove unused endpoints.",
        })
        result.all_issues.append({
            "severity": "medium",
            "title": "API Endpoints Accessible",
            "description": f"{len(accessible_apis)} API endpoints accessible with provided credentials: {paths_str}",
            "recommendation": "Review authorization on each endpoint.",
            "category": "API Deep Scan",
        })
    else:
        result.api_deep.append({
            "check": "Accessible API Endpoints",
            "status": "secure",
            "severity": "info",
            "detail": "No common API endpoints found accessible.",
            "solution": "Good — no unnecessary API endpoints exposed.",
        })

    # --- Auth bypass test (remove auth header) ---
    try:
        if accessible_apis:
            test_path = accessible_apis[0]["path"]
            async with httpx.AsyncClient(
                follow_redirects=True, verify=False, timeout=10
            ) as nac:
                r = await nac.get(f"{base}{test_path}")
                if r.status_code == 200 and len(r.text) > 50:
                    result.api_deep.append({
                        "check": "Auth Bypass Test",
                        "status": "vulnerable",
                        "severity": "critical",
                        "detail": f"Endpoint {test_path} accessible WITHOUT authentication!",
                        "solution": "Add authentication middleware to all API routes. Return 401 for unauthenticated requests.",
                        "fix_code": "# Express middleware\nconst authMiddleware = (req, res, next) => {\n  const token = req.headers.authorization;\n  if (!token) return res.status(401).json({error: 'Unauthorized'});\n  try { req.user = jwt.verify(token.split(' ')[1], SECRET); next(); }\n  catch(e) { res.status(401).json({error: 'Invalid token'}); }\n};",
                    })
                    result.all_issues.append({
                        "severity": "critical",
                        "title": "Authentication Bypass Detected",
                        "description": f"API endpoint {test_path} is accessible without any credentials.",
                        "recommendation": "Add authentication middleware to all protected routes.",
                        "category": "API Deep Scan",
                    })
                else:
                    result.api_deep.append({
                        "check": "Auth Bypass Test",
                        "status": "protected",
                        "severity": "info",
                        "detail": f"Endpoint {test_path} properly blocks unauthenticated access.",
                        "solution": "Good — endpoint requires authentication.",
                    })
    except Exception:
        pass

    # --- IDOR test (try modifying IDs) ---
    result.api_deep.append({
        "check": "IDOR (Insecure Direct Object Reference)",
        "status": "requires_manual",
        "severity": "medium",
        "detail": "IDOR testing requires knowledge of resource IDs. Try changing /user/1 to /user/2 to check for unauthorized data access.",
        "solution": "Implement object-level authorization. Check ownership before returning data.",
        "fix_code": "# Python/FastAPI IDOR protection\n@app.get('/api/users/{user_id}')\nasync def get_user(user_id: int, current_user = Depends(get_current_user)):\n    if current_user.id != user_id and not current_user.is_admin:\n        raise HTTPException(403, 'Forbidden')\n    return db.get(User, user_id)",
    })


async def _db_deep_scan(
    client: httpx.AsyncClient, url: str, result: DeepScanResult
) -> None:
    """Check for database exposure and admin tools."""
    base = url.rstrip("/")

    # --- Database admin panels (authenticated access) ---
    db_panels = [
        ("/phpmyadmin", "phpMyAdmin", "critical"),
        ("/adminer.php", "Adminer", "critical"),
        ("/adminer", "Adminer", "critical"),
        ("/pgadmin", "pgAdmin", "critical"),
        ("/pgadmin4", "pgAdmin 4", "critical"),
        ("/_profiler", "Symfony Profiler (DB queries visible)", "high"),
        ("/debug", "Debug panel", "high"),
        ("/debug/sql", "SQL Debug panel", "critical"),
        ("/phpinfo.php", "PHP Info (DB config exposed)", "high"),
        ("/server-info", "Server Info", "medium"),
        ("/db", "Database endpoint", "high"),
        ("/database", "Database endpoint", "high"),
        ("/mongo-express", "Mongo Express", "critical"),
        ("/redis-commander", "Redis Commander", "critical"),
    ]

    exposed_panels = []
    for path, name, severity in db_panels:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code == 200 and len(r.text) > 200:
                exposed_panels.append(name)
                result.db_deep.append({
                    "check": f"DB Admin Panel: {name}",
                    "status": "exposed",
                    "severity": severity,
                    "detail": f"{name} is accessible at {path}. Database may be directly manageable.",
                    "solution": f"Restrict {path} access via IP whitelist, VPN, or remove from production.",
                })
                result.all_issues.append({
                    "severity": severity,
                    "title": f"Database Admin Panel Exposed: {name}",
                    "description": f"{name} accessible at {path} — direct database access possible.",
                    "recommendation": f"Remove or restrict {path} from public access immediately.",
                    "category": "Database Deep Scan",
                })
        except Exception:
            pass

    if not exposed_panels:
        result.db_deep.append({
            "check": "Database Admin Panels",
            "status": "secure",
            "severity": "info",
            "detail": "No database admin panels found accessible.",
            "solution": "Good — no database management tools exposed publicly.",
        })

    # --- SQL error detection (parameter fuzzing) ---
    sql_test_params = ["'", "1' OR '1'='1", "1; DROP TABLE test--", "\" OR \"\"=\""]
    sql_errors_found = False
    sql_error_patterns = [
        r"sql syntax",
        r"mysql_",
        r"pg_query",
        r"sqlite3\.",
        r"ORA-\d{5}",
        r"unclosed quotation",
        r"unterminated string",
        r"SQLSTATE",
        r"SQL Server",
        r"mysql_fetch",
        r"PDOException",
        r"Syntax error.*SQL",
    ]

    try:
        for param in sql_test_params:
            r = await client.get(f"{base}?id={param}&q={param}&search={param}")
            body = r.text.lower()
            for pattern in sql_error_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    sql_errors_found = True
                    break
            if sql_errors_found:
                break
    except Exception:
        pass

    result.db_deep.append({
        "check": "SQL Injection (Error-Based Detection)",
        "status": "vulnerable" if sql_errors_found else "no_errors",
        "severity": "critical" if sql_errors_found else "info",
        "detail": "SQL error messages detected in response! Application may be vulnerable to SQL injection."
        if sql_errors_found
        else "No SQL error messages detected with test payloads. Deeper testing may still reveal issues.",
        "solution": "Use parameterized queries/ORM. Never concatenate user input into SQL. Enable error suppression in production.",
        "fix_code": "# SAFE: Parameterized query\ncursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n\n# UNSAFE: String concatenation\n# cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')  # NEVER DO THIS",
    })
    if sql_errors_found:
        result.all_issues.append({
            "severity": "critical",
            "title": "SQL Injection Vulnerability Detected",
            "description": "SQL error messages appear in responses when injecting test payloads.",
            "recommendation": "Use parameterized queries. Enable error suppression in production.",
            "category": "Database Deep Scan",
        })

    # --- Data exposure check ---
    data_endpoints = [
        "/api/users", "/api/customers", "/api/data", "/api/export",
        "/api/backup", "/api/dump", "/api/db", "/data",
        "/export", "/backup", "/users.json", "/data.json",
    ]
    exposed_data = []
    for path in data_endpoints:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code == 200:
                content_type = r.headers.get("content-type", "")
                if "json" in content_type or "csv" in content_type or "xml" in content_type:
                    exposed_data.append(path)
        except Exception:
            pass

    if exposed_data:
        result.db_deep.append({
            "check": "Data Export Endpoints",
            "status": "exposed",
            "severity": "high",
            "detail": f"Data endpoints found: {', '.join(exposed_data)}. May expose sensitive records.",
            "solution": "Add authorization checks. Limit data export to admin users only. Add audit logging.",
        })
        result.all_issues.append({
            "severity": "high",
            "title": "Data Export Endpoints Exposed",
            "description": f"Accessible data endpoints: {', '.join(exposed_data)}",
            "recommendation": "Restrict data export endpoints to authorized admin users.",
            "category": "Database Deep Scan",
        })
    else:
        result.db_deep.append({
            "check": "Data Export Endpoints",
            "status": "secure",
            "severity": "info",
            "detail": "No data export endpoints found accessible.",
            "solution": "Good — no bulk data endpoints exposed.",
        })


async def _admin_deep_scan(
    client: httpx.AsyncClient, url: str, result: DeepScanResult
) -> None:
    """Audit admin panel access and RBAC."""
    base = url.rstrip("/")

    # --- Admin panel discovery ---
    admin_paths = [
        ("/admin", "Admin Panel"),
        ("/admin/", "Admin Panel"),
        ("/administrator", "Administrator"),
        ("/wp-admin", "WordPress Admin"),
        ("/wp-login.php", "WordPress Login"),
        ("/admin/login", "Admin Login"),
        ("/admin/dashboard", "Admin Dashboard"),
        ("/dashboard", "Dashboard"),
        ("/panel", "Control Panel"),
        ("/manage", "Management Panel"),
        ("/console", "Console"),
        ("/backstage", "Backstage"),
        ("/cms", "CMS Admin"),
        ("/cpanel", "cPanel"),
        ("/admin/config", "Admin Config"),
        ("/admin/settings", "Admin Settings"),
        ("/admin/users", "Admin Users"),
        ("/settings", "Settings Page"),
    ]

    found_panels = []
    for path, name in admin_paths:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code == 200 and len(r.text) > 200:
                is_login = bool(re.search(
                    r'<input[^>]*type=["\']password["\']|login|sign.?in',
                    r.text, re.IGNORECASE
                ))
                found_panels.append({
                    "path": path,
                    "name": name,
                    "has_login": is_login,
                    "accessible": not is_login,
                })
        except Exception:
            pass

    accessible_panels = [p for p in found_panels if p["accessible"]]
    login_panels = [p for p in found_panels if p["has_login"]]

    if accessible_panels:
        paths = ", ".join(p["path"] for p in accessible_panels)
        result.admin_deep.append({
            "check": "Admin Panel Access (No Login Required)",
            "status": "vulnerable",
            "severity": "critical",
            "detail": f"Admin panels accessible without login: {paths}",
            "solution": "Add authentication to all admin routes. Use middleware to enforce login.",
            "fix_code": "# Django admin protection\nfrom django.contrib.admin.views.decorators import staff_member_required\n\n@staff_member_required\ndef admin_view(request):\n    ...",
        })
        result.all_issues.append({
            "severity": "critical",
            "title": "Admin Panel Accessible Without Login",
            "description": f"Admin areas accessible without authentication: {paths}",
            "recommendation": "Add authentication to admin routes immediately.",
            "category": "Admin Audit",
        })
    elif login_panels:
        paths = ", ".join(p["path"] for p in login_panels)
        result.admin_deep.append({
            "check": "Admin Panel Access",
            "status": "protected",
            "severity": "info",
            "detail": f"Admin panels found but login-protected: {paths}",
            "solution": "Good — admin panels require authentication. Ensure brute force protection is in place.",
        })
    else:
        result.admin_deep.append({
            "check": "Admin Panel Discovery",
            "status": "hidden",
            "severity": "info",
            "detail": "No admin panels found at common paths.",
            "solution": "Good — admin panel is hidden or uses a custom path.",
        })

    # --- RBAC / Privilege Escalation Check ---
    priv_paths = [
        "/admin/users", "/api/admin", "/api/users/all",
        "/admin/config", "/admin/settings", "/internal",
        "/api/internal", "/superadmin", "/root",
    ]
    priv_accessible = []
    for path in priv_paths:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code == 200 and len(r.text) > 100:
                priv_accessible.append(path)
        except Exception:
            pass

    if priv_accessible:
        result.admin_deep.append({
            "check": "Privilege Escalation Risk",
            "status": "vulnerable",
            "severity": "high",
            "detail": f"Higher-privilege paths accessible with current credentials: {', '.join(priv_accessible)}",
            "solution": "Implement role-based access control (RBAC). Verify user role on every request.",
            "fix_code": "# RBAC middleware\ndef require_role(role):\n    def decorator(f):\n        @wraps(f)\n        def wrapped(*args, **kwargs):\n            if current_user.role != role:\n                abort(403)\n            return f(*args, **kwargs)\n        return wrapped\n    return decorator\n\n@app.route('/admin')\n@require_role('admin')\ndef admin_panel(): ...",
        })
        result.all_issues.append({
            "severity": "high",
            "title": "Privilege Escalation Risk",
            "description": f"Admin-level paths accessible: {', '.join(priv_accessible)}",
            "recommendation": "Implement RBAC — verify user permissions on each request.",
            "category": "Admin Audit",
        })
    else:
        result.admin_deep.append({
            "check": "Privilege Escalation Test",
            "status": "secure",
            "severity": "info",
            "detail": "No higher-privilege paths accessible with current credentials.",
            "solution": "Good — RBAC appears to be working correctly.",
        })

    # --- Sensitive file exposure ---
    sensitive_files = [
        ("/.env", "Environment variables"),
        ("/.env.production", "Production env"),
        ("/.env.local", "Local env"),
        ("/config.json", "Config file"),
        ("/config.yml", "Config YAML"),
        ("/secrets.json", "Secrets file"),
        ("/wp-config.php", "WordPress config"),
        ("/web.config", "IIS config"),
        ("/.htaccess", "Apache config"),
        ("/composer.json", "PHP dependencies"),
        ("/package.json", "Node dependencies"),
        ("/.git/config", "Git config"),
        ("/.svn/entries", "SVN entries"),
        ("/Dockerfile", "Docker config"),
        ("/docker-compose.yml", "Docker compose"),
    ]
    exposed_files = []
    for path, desc in sensitive_files:
        try:
            r = await client.get(f"{base}{path}")
            if r.status_code == 200 and len(r.text) > 10:
                if not r.text.strip().startswith("<!DOCTYPE") and not r.text.strip().startswith("<html"):
                    exposed_files.append(f"{path} ({desc})")
        except Exception:
            pass

    if exposed_files:
        result.admin_deep.append({
            "check": "Sensitive Files Exposed",
            "status": "exposed",
            "severity": "critical",
            "detail": f"Sensitive files accessible: {', '.join(exposed_files[:5])}",
            "solution": "Block access to sensitive files via web server config. Add to .gitignore.",
            "fix_code": "# Nginx: block sensitive files\nlocation ~ /\\. {\n    deny all;\n}\nlocation ~ \\.(env|json|yml|yaml|xml|sql|log|bak)$ {\n    deny all;\n}",
        })
        result.all_issues.append({
            "severity": "critical",
            "title": "Sensitive Files Exposed",
            "description": f"Configuration/secret files publicly accessible: {', '.join(exposed_files[:5])}",
            "recommendation": "Block access to sensitive files in web server configuration.",
            "category": "Admin Audit",
        })
    else:
        result.admin_deep.append({
            "check": "Sensitive Files",
            "status": "secure",
            "severity": "info",
            "detail": "No sensitive configuration files found accessible.",
            "solution": "Good — sensitive files are properly protected.",
        })


async def _session_deep_scan(
    client: httpx.AsyncClient, url: str, headers: dict, result: DeepScanResult
) -> None:
    """Test session/token security."""
    base = url.rstrip("/")

    # --- Cookie security analysis ---
    try:
        r = await client.get(base)
        cookies = r.headers.get_list("set-cookie")

        if cookies:
            for cookie_str in cookies:
                cookie_lower = cookie_str.lower()
                issues = []
                if "httponly" not in cookie_lower:
                    issues.append("Missing HttpOnly flag (XSS can steal cookie)")
                if "secure" not in cookie_lower:
                    issues.append("Missing Secure flag (sent over HTTP)")
                if "samesite" not in cookie_lower:
                    issues.append("Missing SameSite (CSRF risk)")

                cookie_name = cookie_str.split("=")[0].strip()
                if issues:
                    result.session_deep.append({
                        "check": f"Cookie Security: {cookie_name}",
                        "status": "vulnerable",
                        "severity": "high",
                        "detail": "; ".join(issues),
                        "solution": "Set HttpOnly, Secure, and SameSite=Strict on all session cookies.",
                        "fix_code": f"# Secure cookie settings\nSet-Cookie: {cookie_name}=value; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=3600",
                    })
                    result.all_issues.append({
                        "severity": "high",
                        "title": f"Insecure Cookie: {cookie_name}",
                        "description": "; ".join(issues),
                        "recommendation": "Add HttpOnly, Secure, and SameSite flags to all cookies.",
                        "category": "Session Security",
                    })
                else:
                    result.session_deep.append({
                        "check": f"Cookie Security: {cookie_name}",
                        "status": "protected",
                        "severity": "info",
                        "detail": "Cookie has HttpOnly, Secure, and SameSite flags.",
                        "solution": "Good — cookie security flags are properly set.",
                    })
        else:
            result.session_deep.append({
                "check": "Cookie Analysis",
                "status": "no_cookies",
                "severity": "info",
                "detail": "No Set-Cookie headers found in response.",
                "solution": "If using token-based auth (JWT), ensure tokens are stored securely (not in localStorage).",
            })
    except Exception:
        pass

    # --- Token in response body check ---
    try:
        r = await client.get(base)
        body = r.text
        token_patterns = [
            (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', "JWT token"),
            (r'sk_live_[a-zA-Z0-9]{20,}', "Stripe live key"),
            (r'sk_test_[a-zA-Z0-9]{20,}', "Stripe test key"),
            (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API key"),
            (r'AKIA[A-Z0-9]{16}', "AWS access key"),
            (r'ghp_[a-zA-Z0-9]{36}', "GitHub token"),
            (r'xoxb-[a-zA-Z0-9-]+', "Slack bot token"),
        ]
        exposed_tokens = []
        for pattern, name in token_patterns:
            if re.search(pattern, body):
                exposed_tokens.append(name)

        if exposed_tokens:
            result.session_deep.append({
                "check": "Token/Key Exposure in Response",
                "status": "exposed",
                "severity": "critical",
                "detail": f"Tokens/keys found in response body: {', '.join(exposed_tokens)}",
                "solution": "Never expose tokens in HTML responses. Use HTTP-only cookies or secure token storage.",
            })
            result.all_issues.append({
                "severity": "critical",
                "title": "API Keys/Tokens Exposed in Response",
                "description": f"Found in page source: {', '.join(exposed_tokens)}",
                "recommendation": "Remove tokens from HTML. Use server-side session management.",
                "category": "Session Security",
            })
        else:
            result.session_deep.append({
                "check": "Token/Key Exposure in Response",
                "status": "secure",
                "severity": "info",
                "detail": "No tokens or API keys found exposed in response body.",
                "solution": "Good — no sensitive credentials in page source.",
            })
    except Exception:
        pass

    # --- Session fixation test ---
    try:
        r1 = await client.get(base)
        cookies1 = {c.name: c.value for c in client.cookies.jar}
        r2 = await client.get(base)
        cookies2 = {c.name: c.value for c in client.cookies.jar}

        if cookies1 and cookies1 == cookies2:
            result.session_deep.append({
                "check": "Session Fixation Test",
                "status": "check_required",
                "severity": "medium",
                "detail": "Session ID remains the same across requests. May be vulnerable to session fixation after login.",
                "solution": "Regenerate session ID after successful authentication. Invalidate old sessions.",
                "fix_code": "# Python Flask\n@app.route('/login', methods=['POST'])\ndef login():\n    if validate_credentials(request.form):\n        session.regenerate()  # IMPORTANT: regenerate after login\n        session['user'] = user.id\n        return redirect('/dashboard')",
            })
        else:
            result.session_deep.append({
                "check": "Session Fixation Test",
                "status": "protected",
                "severity": "info",
                "detail": "Session tokens change between requests — good session management.",
                "solution": "Good — session rotation appears to be in place.",
            })
    except Exception:
        pass

    # --- CORS with credentials check ---
    try:
        cors_headers = {"Origin": "https://evil-site.com"}
        cors_headers.update(headers)
        r = await client.get(base, headers=cors_headers)
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")

        if acao == "https://evil-site.com" and acac.lower() == "true":
            result.session_deep.append({
                "check": "CORS Credential Reflection",
                "status": "vulnerable",
                "severity": "critical",
                "detail": "Server reflects any Origin with Allow-Credentials. Sessions can be hijacked via CORS.",
                "solution": "Whitelist specific origins. Never reflect arbitrary origins with credentials.",
                "fix_code": "# Secure CORS config\nALLOWED_ORIGINS = ['https://yourdomain.com', 'https://app.yourdomain.com']\n\n@app.middleware('http')\nasync def cors(request, call_next):\n    origin = request.headers.get('origin', '')\n    response = await call_next(request)\n    if origin in ALLOWED_ORIGINS:\n        response.headers['Access-Control-Allow-Origin'] = origin\n        response.headers['Access-Control-Allow-Credentials'] = 'true'\n    return response",
            })
            result.all_issues.append({
                "severity": "critical",
                "title": "CORS Credential Reflection Vulnerability",
                "description": "Server reflects any Origin with Allow-Credentials — session hijack possible.",
                "recommendation": "Whitelist specific trusted origins for CORS.",
                "category": "Session Security",
            })
        elif acao == "*":
            result.session_deep.append({
                "check": "CORS Policy (Authenticated)",
                "status": "vulnerable",
                "severity": "medium",
                "detail": "CORS allows all origins (*). Credentials cannot be sent but data may leak.",
                "solution": "Restrict CORS to specific trusted domains.",
            })
        else:
            result.session_deep.append({
                "check": "CORS Policy (Authenticated)",
                "status": "protected",
                "severity": "info",
                "detail": f"CORS properly configured. Allow-Origin: {acao or 'Not set'}",
                "solution": "Good — CORS is properly restricted.",
            })
    except Exception:
        pass

    # --- Cache control check ---
    try:
        r = await client.get(base)
        cache_control = r.headers.get("cache-control", "")
        pragma = r.headers.get("pragma", "")

        if "no-store" not in cache_control and "no-cache" not in cache_control:
            result.session_deep.append({
                "check": "Cache Control (Authenticated Pages)",
                "status": "vulnerable",
                "severity": "medium",
                "detail": "Authenticated pages may be cached by browser/proxy. Sensitive data could be stored in cache.",
                "solution": "Set Cache-Control: no-store, no-cache, must-revalidate on authenticated responses.",
                "fix_code": "# Add to all authenticated responses\nCache-Control: no-store, no-cache, must-revalidate, private\nPragma: no-cache\nExpires: 0",
            })
        else:
            result.session_deep.append({
                "check": "Cache Control (Authenticated Pages)",
                "status": "protected",
                "severity": "info",
                "detail": f"Cache-Control properly set: {cache_control}",
                "solution": "Good — authenticated pages are not cached.",
            })
    except Exception:
        pass
