"""Passive Subdomain Discovery — crt.sh + DNS brute-force (no API key needed)."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

import httpx

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
    "test", "old", "admin", "portal", "blog", "dev", "www2", "ns3", "ns4",
    "vpn", "api", "cdn", "cloud", "staging", "app", "git", "server",
    "mx1", "mx2", "remote", "secure", "beta", "demo", "shop", "store",
    "support", "docs", "wiki", "status", "monitor", "dashboard", "login",
    "sso", "auth", "img", "images", "static", "assets", "media",
    "db", "database", "sql", "mysql", "postgres", "redis", "elastic",
    "jenkins", "ci", "deploy", "build", "registry", "docker",
    "prometheus", "grafana", "kibana", "sentry", "vault",
]


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[dict] = field(default_factory=list)
    total_found: int = 0
    sources: list[str] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    error: str = ""


async def _query_crtsh(domain: str) -> list[str]:
    found = set()
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers={"User-Agent": "SecureScanPro/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") or sub == domain:
                            if "*" not in sub:
                                found.add(sub)
    except Exception:
        pass
    return list(found)


async def _dns_bruteforce(domain: str) -> list[str]:
    found = []
    loop = asyncio.get_event_loop()

    async def check_sub(prefix: str):
        fqdn = f"{prefix}.{domain}"
        try:
            await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            found.append(fqdn)
        except socket.gaierror:
            pass

    tasks = [check_sub(sub) for sub in COMMON_SUBDOMAINS]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found


async def _resolve_ip(subdomain: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        ip = await loop.run_in_executor(None, socket.gethostbyname, subdomain)
        return ip
    except Exception:
        return ""


async def discover_subdomains(domain: str) -> SubdomainResult:
    result = SubdomainResult(domain=domain)

    try:
        crtsh_task = _query_crtsh(domain)
        dns_task = _dns_bruteforce(domain)
        crtsh_subs, dns_subs = await asyncio.gather(crtsh_task, dns_task)

        all_subs = set(crtsh_subs) | set(dns_subs)
        all_subs.discard(domain)

        if crtsh_subs:
            result.sources.append(f"crt.sh ({len(crtsh_subs)} found)")
        if dns_subs:
            result.sources.append(f"DNS Brute-force ({len(dns_subs)} found)")

        resolve_tasks = {sub: _resolve_ip(sub) for sub in sorted(all_subs)}
        ips = await asyncio.gather(*resolve_tasks.values())

        for sub, ip in zip(sorted(all_subs), ips):
            source = []
            if sub in crtsh_subs:
                source.append("crt.sh")
            if sub in dns_subs:
                source.append("DNS")
            result.subdomains.append({
                "subdomain": sub,
                "ip": ip,
                "source": ", ".join(source),
            })

        result.total_found = len(result.subdomains)

        if result.total_found > 20:
            result.issues.append({
                "severity": "medium",
                "title": f"Large Attack Surface: {result.total_found} Subdomains Discovered",
                "description": f"Found {result.total_found} subdomains for {domain}. "
                               "Large number of subdomains increases the attack surface.",
                "recommendation": "Audit all subdomains. Remove unused ones. Ensure all are patched and monitored.",
            })
        elif result.total_found > 5:
            result.issues.append({
                "severity": "low",
                "title": f"{result.total_found} Subdomains Discovered",
                "description": f"Found {result.total_found} subdomains for {domain}.",
                "recommendation": "Review all subdomains and ensure they are properly secured.",
            })

        dev_keywords = ["dev", "staging", "test", "beta", "demo", "old", "temp"]
        for sub_info in result.subdomains:
            sub = sub_info["subdomain"]
            prefix = sub.replace(f".{domain}", "")
            if any(kw in prefix for kw in dev_keywords):
                result.issues.append({
                    "severity": "medium",
                    "title": f"Development/Staging Subdomain Exposed: {sub}",
                    "description": f"Subdomain '{sub}' appears to be a dev/staging environment "
                                   "that may be publicly accessible.",
                    "recommendation": f"Restrict access to {sub} via IP whitelist or VPN. "
                                      "Remove if not needed.",
                })

    except Exception as e:
        result.error = str(e)

    return result
