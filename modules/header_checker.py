"""HTTP Security Headers Analyzer."""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "high",
        "description": "HSTS not set. Browser can be tricked into using HTTP.",
        "recommendation": "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity": "high",
        "description": "No CSP header. Site is more vulnerable to XSS attacks.",
        "recommendation": "Implement a Content-Security-Policy header.",
    },
    "X-Content-Type-Options": {
        "severity": "medium",
        "description": "Missing X-Content-Type-Options. Browser may MIME-sniff responses.",
        "recommendation": "Add X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "medium",
        "description": "Missing X-Frame-Options. Site may be vulnerable to clickjacking.",
        "recommendation": "Add X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-XSS-Protection": {
        "severity": "low",
        "description": "Missing X-XSS-Protection header.",
        "recommendation": "Add X-XSS-Protection: 1; mode=block (legacy browsers).",
    },
    "Referrer-Policy": {
        "severity": "low",
        "description": "No Referrer-Policy. Full URLs may leak in Referer header.",
        "recommendation": "Add Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "low",
        "description": "No Permissions-Policy set. Browser features unrestricted.",
        "recommendation": "Add Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
    "Cross-Origin-Opener-Policy": {
        "severity": "low",
        "description": "No COOP header. May be vulnerable to cross-origin attacks.",
        "recommendation": "Add Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Resource-Policy": {
        "severity": "low",
        "description": "No CORP header. Resources may be loaded by any origin.",
        "recommendation": "Add Cross-Origin-Resource-Policy: same-origin",
    },
}

DANGEROUS_HEADERS = {
    "Server": "Server header exposes web server software and version.",
    "X-Powered-By": "X-Powered-By exposes backend technology.",
    "X-AspNet-Version": "Exposes ASP.NET version.",
    "X-AspNetMvc-Version": "Exposes ASP.NET MVC version.",
}


@dataclass
class HeaderResult:
    url: str = ""
    status_code: int = 0
    present_headers: dict[str, str] = field(default_factory=dict)
    missing_headers: list[dict] = field(default_factory=list)
    information_disclosure: list[dict] = field(default_factory=list)
    cookie_issues: list[dict] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    score: int = 0
    grade: str = "F"
    error: str = ""


async def check_headers(url: str, timeout: int = 15) -> HeaderResult:
    result = HeaderResult(url=url)
    try:
        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=timeout
        ) as client:
            resp = await client.get(url)
            result.status_code = resp.status_code
            headers = resp.headers

            points = 100

            for name, info in SECURITY_HEADERS.items():
                val = headers.get(name)
                if val:
                    result.present_headers[name] = val
                else:
                    penalty = {"critical": 25, "high": 15, "medium": 10, "low": 5}.get(
                        info["severity"], 5
                    )
                    points -= penalty
                    issue = {
                        "severity": info["severity"],
                        "title": f"Missing {name}",
                        "description": info["description"],
                        "recommendation": info["recommendation"],
                    }
                    result.missing_headers.append(issue)
                    result.issues.append(issue)

            for name, desc in DANGEROUS_HEADERS.items():
                val = headers.get(name)
                if val:
                    issue = {
                        "severity": "low",
                        "title": f"Information Disclosure: {name}",
                        "description": f"{desc} Value: {val}",
                        "recommendation": f"Remove or suppress the {name} header.",
                    }
                    result.information_disclosure.append(issue)
                    result.issues.append(issue)
                    points -= 3

            for cookie_header in resp.headers.get_list("set-cookie"):
                cl = cookie_header.lower()
                cookie_name = cookie_header.split("=")[0].strip()
                if "secure" not in cl:
                    issue = {
                        "severity": "medium",
                        "title": f"Cookie '{cookie_name}' missing Secure flag",
                        "description": "Cookie can be sent over unencrypted HTTP.",
                        "recommendation": "Add the Secure flag to this cookie.",
                    }
                    result.cookie_issues.append(issue)
                    result.issues.append(issue)
                    points -= 5
                if "httponly" not in cl:
                    issue = {
                        "severity": "medium",
                        "title": f"Cookie '{cookie_name}' missing HttpOnly flag",
                        "description": "Cookie accessible via JavaScript (XSS risk).",
                        "recommendation": "Add the HttpOnly flag to this cookie.",
                    }
                    result.cookie_issues.append(issue)
                    result.issues.append(issue)
                    points -= 5
                if "samesite" not in cl:
                    issue = {
                        "severity": "low",
                        "title": f"Cookie '{cookie_name}' missing SameSite attribute",
                        "description": "Cookie may be sent with cross-site requests (CSRF risk).",
                        "recommendation": "Add SameSite=Lax or SameSite=Strict.",
                    }
                    result.cookie_issues.append(issue)
                    result.issues.append(issue)
                    points -= 3

            result.score = max(0, min(100, points))
            if result.score >= 90:
                result.grade = "A"
            elif result.score >= 75:
                result.grade = "B"
            elif result.score >= 60:
                result.grade = "C"
            elif result.score >= 40:
                result.grade = "D"
            else:
                result.grade = "F"

    except Exception as e:
        result.error = str(e)

    return result
