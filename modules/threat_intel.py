"""Threat Intelligence Module — Third-party API integrations.

Integrates with:
1. NVD CVE Database (FREE — no API key)
2. Google Safe Browsing API (optional key)
3. Shodan API (optional key)
4. VirusTotal API (optional key)
5. Have I Been Pwned API (optional key)
6. SecurityTrails API (optional key)

All integrations degrade gracefully if API keys are not provided.
"""

from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import httpx

TIMEOUT = httpx.Timeout(15.0, connect=10.0)


@dataclass
class ThreatIntelResult:
    cve_matches: list[dict] = field(default_factory=list)
    safe_browsing: dict = field(default_factory=dict)
    shodan_data: dict = field(default_factory=dict)
    virustotal_data: dict = field(default_factory=dict)
    breach_data: dict = field(default_factory=dict)
    subdomain_data: dict = field(default_factory=dict)
    all_issues: list[dict] = field(default_factory=list)
    apis_used: list[str] = field(default_factory=list)
    apis_skipped: list[str] = field(default_factory=list)


async def run_threat_intel(
    url: str,
    hostname: str,
    detected_techs: list[dict] | None = None,
) -> ThreatIntelResult:
    result = ThreatIntelResult()

    tasks = [
        _check_nvd_cves(result, detected_techs or []),
        _check_safe_browsing(result, url),
        _check_shodan(result, hostname),
        _check_virustotal(result, url, hostname),
        _check_breaches(result, hostname),
        _check_subdomains(result, hostname),
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    return result


# ---------------------------------------------------------------------------
# 1. NVD CVE Database (FREE — no API key required)
# ---------------------------------------------------------------------------

async def _check_nvd_cves(result: ThreatIntelResult, techs: list[dict]) -> None:
    if not techs:
        result.apis_skipped.append("NVD CVE (no technologies detected)")
        return

    result.apis_used.append("NVD CVE Database")
    cve_matches = []

    async with httpx.AsyncClient(timeout=TIMEOUT) as client:
        for tech in techs[:8]:
            name = tech.get("name", "")
            version = tech.get("version", "")
            if not name:
                continue

            keyword = name.lower()
            if version and version != "Unknown":
                keyword = f"{name} {version}"

            try:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={
                        "keywordSearch": keyword,
                        "resultsPerPage": 5,
                    },
                    headers={"Accept": "application/json"},
                )
                if resp.status_code != 200:
                    continue

                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                for v in vulns[:3]:
                    cve_item = v.get("cve", {})
                    cve_id = cve_item.get("id", "")
                    descriptions = cve_item.get("descriptions", [])
                    desc = ""
                    for d in descriptions:
                        if d.get("lang") == "en":
                            desc = d.get("value", "")
                            break

                    metrics = cve_item.get("metrics", {})
                    cvss_score = None
                    cvss_severity = None

                    cvss31 = metrics.get("cvssMetricV31", [])
                    if cvss31:
                        cvss_data = cvss31[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore")
                        cvss_severity = cvss_data.get("baseSeverity", "").lower()

                    if not cvss_score:
                        cvss2 = metrics.get("cvssMetricV2", [])
                        if cvss2:
                            cvss_data = cvss2[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")

                    if not cve_id:
                        continue

                    severity = "info"
                    if cvss_severity:
                        severity_map = {
                            "critical": "critical",
                            "high": "high",
                            "medium": "medium",
                            "low": "low",
                        }
                        severity = severity_map.get(cvss_severity, "medium")
                    elif cvss_score:
                        if cvss_score >= 9.0:
                            severity = "critical"
                        elif cvss_score >= 7.0:
                            severity = "high"
                        elif cvss_score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"

                    cve_entry = {
                        "cve_id": cve_id,
                        "technology": name,
                        "version": version or "Unknown",
                        "description": desc[:300] if desc else "No description available",
                        "cvss_score": cvss_score,
                        "severity": severity,
                    }
                    cve_matches.append(cve_entry)

                    result.all_issues.append({
                        "title": f"Known CVE: {cve_id} ({name})",
                        "description": desc[:200] if desc else f"Vulnerability found in {name}",
                        "severity": severity,
                        "category": "CVE",
                        "recommendation": f"Update {name} to latest version. Check {cve_id} for patches.",
                    })

            except Exception:
                continue

            await asyncio.sleep(0.6)

    result.cve_matches = cve_matches


# ---------------------------------------------------------------------------
# 2. Google Safe Browsing API
# ---------------------------------------------------------------------------

async def _check_safe_browsing(result: ThreatIntelResult, url: str) -> None:
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_KEY", "")
    if not api_key:
        result.apis_skipped.append("Google Safe Browsing (no API key)")
        result.safe_browsing = {"status": "skipped", "reason": "No API key configured"}
        return

    result.apis_used.append("Google Safe Browsing")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json={
                    "client": {"clientId": "securescanpro", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            data = resp.json()
            matches = data.get("matches", [])

            if matches:
                result.safe_browsing = {
                    "status": "threats_found",
                    "threats": [
                        {
                            "type": m.get("threatType", ""),
                            "platform": m.get("platformType", ""),
                        }
                        for m in matches
                    ],
                }
                for m in matches:
                    result.all_issues.append({
                        "title": f"Google Safe Browsing: {m.get('threatType', 'Threat')} detected",
                        "description": f"URL flagged as {m.get('threatType', 'malicious')} by Google Safe Browsing",
                        "severity": "critical",
                        "category": "Safe Browsing",
                        "recommendation": "Investigate and clean the site immediately. Submit for review at https://safebrowsing.google.com/",
                    })
            else:
                result.safe_browsing = {"status": "clean", "message": "No threats found"}

    except Exception as e:
        result.safe_browsing = {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# 3. Shodan API
# ---------------------------------------------------------------------------

async def _check_shodan(result: ThreatIntelResult, hostname: str) -> None:
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        result.apis_skipped.append("Shodan (no API key)")
        result.shodan_data = {"status": "skipped", "reason": "No API key configured"}
        return

    result.apis_used.append("Shodan")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            dns_resp = await client.get(
                f"https://api.shodan.io/dns/resolve?hostnames={hostname}&key={api_key}"
            )
            dns_data = dns_resp.json()
            ip = dns_data.get(hostname, "")

            if not ip:
                result.shodan_data = {"status": "no_ip", "message": "Could not resolve IP"}
                return

            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            )

            if resp.status_code == 404:
                result.shodan_data = {"status": "not_found", "ip": ip, "message": "No Shodan data for this IP"}
                return

            data = resp.json()
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            os_info = data.get("os", "Unknown")
            org = data.get("org", "Unknown")
            isp = data.get("isp", "Unknown")

            services = []
            for item in data.get("data", [])[:10]:
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport", "tcp"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": (item.get("data", "")[:200] if item.get("data") else ""),
                })

            result.shodan_data = {
                "status": "found",
                "ip": ip,
                "os": os_info,
                "org": org,
                "isp": isp,
                "ports": ports,
                "vulns_count": len(vulns),
                "vulns": vulns[:20],
                "services": services,
            }

            for v in vulns[:5]:
                result.all_issues.append({
                    "title": f"Shodan CVE: {v}",
                    "description": f"Shodan detected known vulnerability {v} on {ip}",
                    "severity": "high",
                    "category": "Shodan",
                    "recommendation": f"Investigate and patch {v}. Check NVD for details.",
                })

    except Exception as e:
        result.shodan_data = {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# 4. VirusTotal API
# ---------------------------------------------------------------------------

async def _check_virustotal(result: ThreatIntelResult, url: str, hostname: str) -> None:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        result.apis_skipped.append("VirusTotal (no API key)")
        result.virustotal_data = {"status": "skipped", "reason": "No API key configured"}
        return

    result.apis_used.append("VirusTotal")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{hostname}",
                headers={"x-apikey": api_key},
            )

            if resp.status_code != 200:
                result.virustotal_data = {
                    "status": "error",
                    "message": f"API returned {resp.status_code}",
                }
                return

            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})

            last_analysis = attrs.get("last_analysis_stats", {})
            malicious = last_analysis.get("malicious", 0)
            suspicious = last_analysis.get("suspicious", 0)
            harmless = last_analysis.get("harmless", 0)
            undetected = last_analysis.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            reputation = attrs.get("reputation", 0)
            categories = attrs.get("categories", {})

            result.virustotal_data = {
                "status": "found",
                "domain": hostname,
                "reputation_score": reputation,
                "analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": undetected,
                    "total": total,
                },
                "categories": categories,
                "last_analysis_date": attrs.get("last_analysis_date", ""),
            }

            if malicious > 0:
                result.all_issues.append({
                    "title": f"VirusTotal: {malicious} engines flagged domain as malicious",
                    "description": f"{malicious}/{total} security vendors flagged {hostname} as malicious",
                    "severity": "critical" if malicious >= 3 else "high",
                    "category": "VirusTotal",
                    "recommendation": "Investigate malware/phishing indicators. Check VirusTotal report for details.",
                })
            if suspicious > 0:
                result.all_issues.append({
                    "title": f"VirusTotal: {suspicious} engines flagged domain as suspicious",
                    "description": f"{suspicious}/{total} vendors flagged {hostname} as suspicious",
                    "severity": "medium",
                    "category": "VirusTotal",
                    "recommendation": "Review domain reputation and investigate suspicious indicators.",
                })

    except Exception as e:
        result.virustotal_data = {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# 5. Have I Been Pwned API
# ---------------------------------------------------------------------------

async def _check_breaches(result: ThreatIntelResult, hostname: str) -> None:
    api_key = os.environ.get("HIBP_API_KEY", "")
    if not api_key:
        result.apis_skipped.append("Have I Been Pwned (no API key)")
        result.breach_data = {"status": "skipped", "reason": "No API key configured"}
        return

    result.apis_used.append("Have I Been Pwned")
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={hostname}",
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "SecureScanPro",
                },
            )

            if resp.status_code == 404:
                result.breach_data = {
                    "status": "clean",
                    "message": "No breaches found for this domain",
                    "breaches": [],
                }
                return

            if resp.status_code != 200:
                result.breach_data = {
                    "status": "error",
                    "message": f"API returned {resp.status_code}",
                }
                return

            breaches = resp.json()
            breach_list = []
            for b in breaches[:10]:
                breach_list.append({
                    "name": b.get("Name", ""),
                    "title": b.get("Title", ""),
                    "date": b.get("BreachDate", ""),
                    "pwn_count": b.get("PwnCount", 0),
                    "data_classes": b.get("DataClasses", []),
                    "description": re.sub(r"<[^>]+>", "", b.get("Description", ""))[:200],
                })

            result.breach_data = {
                "status": "breaches_found" if breach_list else "clean",
                "total_breaches": len(breaches),
                "breaches": breach_list,
            }

            if breach_list:
                total_pwned = sum(b.get("pwn_count", 0) for b in breach_list)
                result.all_issues.append({
                    "title": f"Data Breaches: {len(breaches)} breach(es) found for {hostname}",
                    "description": f"{total_pwned:,} accounts compromised across {len(breaches)} known breaches",
                    "severity": "high" if len(breaches) >= 3 else "medium",
                    "category": "Breach Data",
                    "recommendation": "Enforce password resets, enable MFA, and notify affected users per compliance requirements.",
                })

    except Exception as e:
        result.breach_data = {"status": "error", "error": str(e)}


# ---------------------------------------------------------------------------
# 6. SecurityTrails API (Subdomain Discovery)
# ---------------------------------------------------------------------------

async def _check_subdomains(result: ThreatIntelResult, hostname: str) -> None:
    api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
    if not api_key:
        result.apis_skipped.append("SecurityTrails (no API key)")
        result.subdomain_data = {"status": "skipped", "reason": "No API key configured"}
        return

    result.apis_used.append("SecurityTrails")
    try:
        base_domain = _get_base_domain(hostname)

        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(
                f"https://api.securitytrails.com/v1/domain/{base_domain}/subdomains",
                headers={"APIKEY": api_key, "Accept": "application/json"},
            )

            if resp.status_code != 200:
                result.subdomain_data = {
                    "status": "error",
                    "message": f"API returned {resp.status_code}",
                }
                return

            data = resp.json()
            subdomains = data.get("subdomains", [])

            full_subdomains = [f"{s}.{base_domain}" for s in subdomains[:50]]

            sensitive_prefixes = [
                "admin", "staging", "dev", "test", "api", "internal",
                "vpn", "mail", "ftp", "db", "database", "jenkins",
                "gitlab", "jira", "confluence", "grafana", "kibana",
                "elastic", "redis", "mongo", "phpmyadmin", "backup",
            ]
            risky_subdomains = [
                s for s in full_subdomains
                if any(s.startswith(p + ".") for p in sensitive_prefixes)
            ]

            result.subdomain_data = {
                "status": "found",
                "domain": base_domain,
                "total_subdomains": len(subdomains),
                "subdomains": full_subdomains,
                "risky_subdomains": risky_subdomains,
            }

            if risky_subdomains:
                result.all_issues.append({
                    "title": f"Sensitive subdomains exposed ({len(risky_subdomains)} found)",
                    "description": f"Subdomains like {', '.join(risky_subdomains[:3])} may expose internal services",
                    "severity": "medium",
                    "category": "Subdomain Discovery",
                    "recommendation": "Review exposed subdomains. Restrict access to internal/staging/dev subdomains.",
                })

    except Exception as e:
        result.subdomain_data = {"status": "error", "error": str(e)}


def _get_base_domain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname
