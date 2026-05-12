"""DNS Record Analyzer - Deep DNS-level inspection."""

from __future__ import annotations

import socket
import subprocess
from dataclasses import dataclass, field

try:
    import dns.resolver
    import dns.reversename
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    hostname: str = ""
    ip_addresses: list[str] = field(default_factory=list)
    records: list[DNSRecord] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    has_spf: bool = False
    has_dmarc: bool = False
    has_dkim: bool = False
    dnssec_enabled: bool = False
    reverse_dns: str = ""
    issues: list[dict] = field(default_factory=list)
    error: str = ""
    ping_result: dict = field(default_factory=dict)


def _ping_host(hostname: str) -> dict:
    try:
        result = subprocess.run(
            ["ping", "-c", "4", "-W", "5", hostname],
            capture_output=True, text=True, timeout=20,
        )
        lines = result.stdout.strip().split("\n")
        stats = {}
        for line in lines:
            if "packets transmitted" in line:
                parts = line.split(",")
                for p in parts:
                    p = p.strip()
                    if "transmitted" in p:
                        stats["transmitted"] = int(p.split()[0])
                    elif "received" in p:
                        stats["received"] = int(p.split()[0])
                    elif "loss" in p:
                        stats["packet_loss"] = p.split()[0]
            if "rtt" in line or "round-trip" in line:
                vals = line.split("=")[-1].strip().split("/")
                if len(vals) >= 3:
                    stats["min_ms"] = vals[0].strip()
                    stats["avg_ms"] = vals[1].strip()
                    stats["max_ms"] = vals[2].strip().split()[0]
        stats["reachable"] = result.returncode == 0
        return stats
    except Exception as e:
        return {"reachable": False, "error": str(e)}


def check_dns(hostname: str) -> DNSResult:
    result = DNSResult(hostname=hostname)

    try:
        ips = socket.getaddrinfo(hostname, None)
        result.ip_addresses = list({addr[4][0] for addr in ips})
    except socket.gaierror as e:
        result.error = f"DNS resolution failed: {e}"
        return result

    if not HAS_DNSPYTHON:
        result.error = "dnspython not installed; limited DNS info available."
        result.ping_result = _ping_host(hostname)
        return result

    resolver = dns.resolver.Resolver()
    resolver.timeout = 10
    resolver.lifetime = 10

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype)
            for rdata in answers:
                val = rdata.to_text()
                rec = DNSRecord(
                    record_type=rtype,
                    name=hostname,
                    value=val,
                    ttl=answers.rrset.ttl if answers.rrset else 0,
                )
                result.records.append(rec)

                if rtype == "NS":
                    result.nameservers.append(val)
                elif rtype == "MX":
                    result.mx_records.append(val)
                elif rtype == "TXT":
                    clean = val.strip('"')
                    result.txt_records.append(clean)
                    if clean.startswith("v=spf1"):
                        result.has_spf = True
        except Exception:
            pass

    try:
        answers = resolver.resolve(f"_dmarc.{hostname}", "TXT")
        for rdata in answers:
            val = rdata.to_text().strip('"')
            if "v=DMARC1" in val:
                result.has_dmarc = True
                result.txt_records.append(f"_dmarc: {val}")
    except Exception:
        pass

    try:
        answers = resolver.resolve(f"default._domainkey.{hostname}", "TXT")
        if answers:
            result.has_dkim = True
    except Exception:
        pass

    if result.ip_addresses:
        try:
            rev_name = dns.reversename.from_address(result.ip_addresses[0])
            answers = resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                result.reverse_dns = rdata.to_text()
                break
        except Exception:
            pass

    if not result.has_spf:
        result.issues.append({
            "severity": "medium",
            "title": "Missing SPF Record",
            "description": "No SPF record found. Email spoofing may be possible.",
            "recommendation": "Add an SPF TXT record to your DNS.",
        })

    if not result.has_dmarc:
        result.issues.append({
            "severity": "medium",
            "title": "Missing DMARC Record",
            "description": "No DMARC record found. Email authentication not enforced.",
            "recommendation": "Add a _dmarc TXT record to your DNS.",
        })

    if not result.has_dkim:
        result.issues.append({
            "severity": "low",
            "title": "DKIM Not Detected",
            "description": "Could not verify DKIM record (default selector).",
            "recommendation": "Ensure DKIM signing is configured for outgoing email.",
        })

    result.ping_result = _ping_host(hostname)

    return result
