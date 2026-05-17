"""CVSS v3.1 Scoring Engine & Compliance Mapping Module.

Provides:
1. CVSS v3.1 base score calculation for all scan findings
2. OWASP Top 10 (2021) mapping
3. PCI DSS v4.0 compliance mapping
4. CIS Controls mapping
5. Risk scoring and prioritization
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# CVSS v3.1 Base Score Calculator
# ---------------------------------------------------------------------------

CVSS_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": "unchanged", "C": "changed"},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def calculate_cvss_score(vector: dict) -> tuple[float, str]:
    av = CVSS_WEIGHTS["AV"].get(vector.get("AV", "N"), 0.85)
    ac = CVSS_WEIGHTS["AC"].get(vector.get("AC", "L"), 0.77)
    scope = vector.get("S", "U")
    pr_scope = "C" if scope == "C" else "U"
    pr = CVSS_WEIGHTS["PR"].get(vector.get("PR", "N"), {}).get(pr_scope, 0.85)
    ui = CVSS_WEIGHTS["UI"].get(vector.get("UI", "N"), 0.85)
    c = CVSS_WEIGHTS["C"].get(vector.get("C", "N"), 0.0)
    i = CVSS_WEIGHTS["I"].get(vector.get("I", "N"), 0.0)
    a = CVSS_WEIGHTS["A"].get(vector.get("A", "N"), 0.0)

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))

    if scope == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        return 0.0, "None"

    if scope == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    score = _roundup(score)

    if score >= 9.0:
        severity = "Critical"
    elif score >= 7.0:
        severity = "High"
    elif score >= 4.0:
        severity = "Medium"
    elif score > 0.0:
        severity = "Low"
    else:
        severity = "None"

    return score, severity


def _roundup(val: float) -> float:
    import math
    return math.ceil(val * 10) / 10


# ---------------------------------------------------------------------------
# CVSS Vector Mapping for Common Vulnerabilities
# ---------------------------------------------------------------------------

VULN_CVSS_MAP: dict[str, dict] = {
    "Missing Strict-Transport-Security": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4", "4.1"],
        "cis": "9.2",
    },
    "Missing Content-Security-Policy": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
        "owasp": "A03:2021 Injection",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing X-Content-Type-Options": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing X-Frame-Options": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing X-XSS-Protection": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "owasp": "A03:2021 Injection",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing Referrer-Policy": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing Permissions-Policy": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing Cross-Origin-Opener-Policy": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "Missing Cross-Origin-Resource-Policy": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["6.2.4"],
        "cis": "9.2",
    },
    "No Rate Limiting": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "H"},
        "owasp": "A04:2021 Insecure Design",
        "pci_dss": ["6.2.4", "11.3"],
        "cis": "9.4",
    },
    "XSS Vulnerability Risk": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
        "owasp": "A03:2021 Injection",
        "pci_dss": ["6.2.4", "6.5.7"],
        "cis": "9.2",
    },
    "No Bot Protection": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "L", "A": "L"},
        "owasp": "A07:2021 Identification and Authentication Failures",
        "pci_dss": ["6.2.4", "8.1"],
        "cis": "9.4",
    },
    "Server Software Disclosed": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4"],
        "cis": "18.3",
    },
    "Information Disclosure": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4"],
        "cis": "18.3",
    },
    "SSL Certificate Expiring Soon": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["4.1", "4.2"],
        "cis": "9.1",
    },
    "SSL Certificate Expired": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["4.1", "4.2"],
        "cis": "9.1",
    },
    "Weak SSL Cipher": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["4.1", "2.3"],
        "cis": "9.1",
    },
    "Risky Port Open": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["1.3", "2.2.2"],
        "cis": "9.4",
    },
    "FTP Open": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["1.3", "2.3", "4.1"],
        "cis": "9.2",
    },
    "Telnet Open": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["1.3", "2.3", "4.1"],
        "cis": "9.2",
    },
    "Database Port Open": {
        "vector": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["1.3", "2.2.2"],
        "cis": "9.4",
    },
    "Missing SPF Record": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4"],
        "cis": "9.2",
    },
    "Missing DMARC Record": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4"],
        "cis": "9.2",
    },
    "Environment file exposed": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "owasp": "A05:2021 Security Misconfiguration",
        "pci_dss": ["2.2.4", "6.2.4"],
        "cis": "18.3",
    },
    "Git repository exposed": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": ["6.2.4", "6.3.2"],
        "cis": "18.3",
    },
    "Admin panel": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"},
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": ["7.1", "8.1"],
        "cis": "6.2",
    },
    "phpMyAdmin exposed": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "owasp": "A01:2021 Broken Access Control",
        "pci_dss": ["2.2.4", "7.1"],
        "cis": "6.2",
    },
    "Mixed Content": {
        "vector": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
        "owasp": "A02:2021 Cryptographic Failures",
        "pci_dss": ["4.1"],
        "cis": "9.1",
    },
    "SQL Injection": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "owasp": "A03:2021 Injection",
        "pci_dss": ["6.2.4", "6.5.1"],
        "cis": "16.2",
    },
    "Known CVE": {
        "vector": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
        "owasp": "A06:2021 Vulnerable and Outdated Components",
        "pci_dss": ["6.3.3", "11.3"],
        "cis": "7.1",
    },
}


# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) Reference
# ---------------------------------------------------------------------------

OWASP_TOP_10 = {
    "A01:2021": {"name": "Broken Access Control", "description": "Restrictions on authenticated users not enforced. Attackers can access unauthorized data."},
    "A02:2021": {"name": "Cryptographic Failures", "description": "Failures related to cryptography, often leading to sensitive data exposure."},
    "A03:2021": {"name": "Injection", "description": "User-supplied data sent to interpreter as a command/query. Includes SQL, NoSQL, OS, LDAP injection."},
    "A04:2021": {"name": "Insecure Design", "description": "Missing or ineffective control design. Focuses on design and architectural flaws."},
    "A05:2021": {"name": "Security Misconfiguration", "description": "Missing security hardening, default configs, open cloud storage, verbose error messages."},
    "A06:2021": {"name": "Vulnerable and Outdated Components", "description": "Using components with known vulnerabilities or unsupported/out-of-date software."},
    "A07:2021": {"name": "Identification and Authentication Failures", "description": "Session management weaknesses, credential stuffing, brute force."},
    "A08:2021": {"name": "Software and Data Integrity Failures", "description": "Code and infrastructure without integrity verification. Insecure CI/CD pipelines."},
    "A09:2021": {"name": "Security Logging and Monitoring Failures", "description": "Insufficient logging, detection, monitoring, and active response."},
    "A10:2021": {"name": "Server-Side Request Forgery", "description": "SSRF flaws when web app fetches remote resource without validating user-supplied URL."},
}


# ---------------------------------------------------------------------------
# PCI DSS v4.0 Requirements Reference
# ---------------------------------------------------------------------------

PCI_DSS_REQUIREMENTS = {
    "1.3": "Restrict inbound and outbound network traffic",
    "2.2.2": "Disable unnecessary services, protocols, and ports",
    "2.2.4": "Configure security parameters to prevent misuse",
    "2.3": "Encrypt non-console administrative access",
    "4.1": "Use strong cryptography to safeguard data during transmission",
    "4.2": "Protect PAN with strong cryptography during transmission",
    "6.2.4": "Software engineering techniques to prevent common vulnerabilities",
    "6.3.2": "Maintain inventory of custom software and third-party components",
    "6.3.3": "Patch known security vulnerabilities",
    "6.5.1": "Address common coding vulnerabilities (injection)",
    "6.5.7": "Address common coding vulnerabilities (XSS)",
    "7.1": "Limit access to system components by business need-to-know",
    "8.1": "Define and assign user identification management processes",
    "11.3": "External and internal vulnerabilities regularly tested",
}


# ---------------------------------------------------------------------------
# Enrichment Functions
# ---------------------------------------------------------------------------

@dataclass
class ComplianceResult:
    total_issues: int = 0
    cvss_enriched: list[dict] = field(default_factory=list)
    owasp_summary: dict[str, list] = field(default_factory=dict)
    pci_dss_summary: dict[str, list] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: str = "Unknown"
    compliance_status: dict = field(default_factory=dict)
    owasp_coverage: list[dict] = field(default_factory=list)
    pci_dss_coverage: list[dict] = field(default_factory=list)


def enrich_issues_with_cvss(issues: list[dict]) -> ComplianceResult:
    result = ComplianceResult(total_issues=len(issues))
    owasp_map: dict[str, list] = {}
    pci_map: dict[str, list] = {}
    total_cvss = 0.0

    for issue in issues:
        title = issue.get("title", "")
        enriched = dict(issue)

        mapping = _find_mapping(title)
        if mapping:
            vector = mapping["vector"]
            score, severity = calculate_cvss_score(vector)
            vector_str = _vector_to_string(vector)

            enriched["cvss_score"] = score
            enriched["cvss_severity"] = severity
            enriched["cvss_vector"] = vector_str
            enriched["owasp_category"] = mapping.get("owasp", "")
            enriched["pci_dss_requirements"] = mapping.get("pci_dss", [])
            enriched["cis_control"] = mapping.get("cis", "")

            owasp_cat = mapping.get("owasp", "")
            if owasp_cat:
                owasp_key = owasp_cat.split(" ")[0]
                if owasp_key not in owasp_map:
                    owasp_map[owasp_key] = []
                owasp_map[owasp_key].append(enriched)

            for pci_req in mapping.get("pci_dss", []):
                if pci_req not in pci_map:
                    pci_map[pci_req] = []
                pci_map[pci_req].append(enriched)

            total_cvss += score
        else:
            sev = issue.get("severity", "info")
            fallback_score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(sev, 0.0)
            enriched["cvss_score"] = fallback_score
            enriched["cvss_severity"] = sev.capitalize()
            enriched["cvss_vector"] = ""
            enriched["owasp_category"] = ""
            enriched["pci_dss_requirements"] = []
            enriched["cis_control"] = ""
            total_cvss += fallback_score

        result.cvss_enriched.append(enriched)

    result.cvss_enriched.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
    result.owasp_summary = owasp_map
    result.pci_dss_summary = pci_map

    if len(issues) > 0:
        avg_cvss = total_cvss / len(issues)
        result.risk_score = round(avg_cvss, 1)
        if avg_cvss >= 7.0:
            result.risk_level = "Critical"
        elif avg_cvss >= 5.0:
            result.risk_level = "High"
        elif avg_cvss >= 3.0:
            result.risk_level = "Medium"
        else:
            result.risk_level = "Low"

    result.owasp_coverage = _build_owasp_coverage(owasp_map)
    result.pci_dss_coverage = _build_pci_coverage(pci_map)

    owasp_fail = len(owasp_map)
    pci_fail = len(pci_map)
    result.compliance_status = {
        "owasp": {
            "categories_affected": owasp_fail,
            "total_categories": 10,
            "status": "FAIL" if owasp_fail > 3 else "WARN" if owasp_fail > 0 else "PASS",
            "score": round((10 - owasp_fail) / 10 * 100),
        },
        "pci_dss": {
            "requirements_affected": pci_fail,
            "total_checked": len(PCI_DSS_REQUIREMENTS),
            "status": "FAIL" if pci_fail > 3 else "WARN" if pci_fail > 0 else "PASS",
            "score": round((len(PCI_DSS_REQUIREMENTS) - pci_fail) / len(PCI_DSS_REQUIREMENTS) * 100),
        },
    }

    return result


def _find_mapping(title: str) -> dict | None:
    for key, mapping in VULN_CVSS_MAP.items():
        if key.lower() in title.lower():
            return mapping
    return None


def _vector_to_string(vector: dict) -> str:
    parts = []
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    for k in order:
        if k in vector:
            parts.append(f"{k}:{vector[k]}")
    return "CVSS:3.1/" + "/".join(parts)


def _build_owasp_coverage(owasp_map: dict) -> list[dict]:
    coverage = []
    for code, info in OWASP_TOP_10.items():
        issues = owasp_map.get(code, [])
        coverage.append({
            "code": code,
            "name": info["name"],
            "description": info["description"],
            "status": "FAIL" if issues else "PASS",
            "issues_count": len(issues),
            "issues": [{"title": i["title"], "cvss_score": i.get("cvss_score", 0)} for i in issues[:5]],
        })
    return coverage


def _build_pci_coverage(pci_map: dict) -> list[dict]:
    coverage = []
    for req, desc in PCI_DSS_REQUIREMENTS.items():
        issues = pci_map.get(req, [])
        coverage.append({
            "requirement": req,
            "description": desc,
            "status": "FAIL" if issues else "PASS",
            "issues_count": len(issues),
            "issues": [{"title": i["title"], "cvss_score": i.get("cvss_score", 0)} for i in issues[:5]],
        })
    return coverage
