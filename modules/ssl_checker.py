"""SSL/TLS Certificate & Configuration Checker."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timezone
from dataclasses import dataclass, field


@dataclass
class SSLResult:
    valid: bool = False
    issuer: str = ""
    subject: str = ""
    expires: str = ""
    days_until_expiry: int = 0
    protocol: str = ""
    cipher: str = ""
    key_size: int = 0
    san_domains: list[str] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    error: str = ""


def check_ssl(hostname: str, port: int = 443, timeout: int = 10) -> SSLResult:
    result = SSLResult()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_info = ssock.cipher()
                result.protocol = ssock.version() or ""

                if cipher_info:
                    result.cipher = cipher_info[0]
                    result.key_size = cipher_info[2]

                if cert:
                    result.valid = True
                    subj = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    result.subject = subj.get("commonName", "")
                    result.issuer = issuer.get("organizationName", issuer.get("commonName", ""))

                    not_after = cert.get("notAfter", "")
                    if not_after:
                        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                        result.expires = exp.isoformat()
                        result.days_until_expiry = (exp - datetime.now(timezone.utc)).days

                        if result.days_until_expiry < 0:
                            result.issues.append(
                                {"severity": "critical", "title": "SSL Certificate Expired",
                                 "description": f"Certificate expired {abs(result.days_until_expiry)} days ago."}
                            )
                        elif result.days_until_expiry < 30:
                            result.issues.append(
                                {"severity": "high", "title": "SSL Certificate Expiring Soon",
                                 "description": f"Certificate expires in {result.days_until_expiry} days."}
                            )

                    san = cert.get("subjectAltName", ())
                    result.san_domains = [v for t, v in san if t == "DNS"]

                if result.protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    result.issues.append(
                        {"severity": "high", "title": "Deprecated TLS Version",
                         "description": f"Server uses deprecated protocol {result.protocol}."}
                    )

                if result.key_size and result.key_size < 128:
                    result.issues.append(
                        {"severity": "medium", "title": "Weak Cipher Key Size",
                         "description": f"Cipher key size is only {result.key_size} bits."}
                    )

    except ssl.SSLCertVerificationError as e:
        result.error = f"SSL Verification Failed: {e}"
        result.issues.append(
            {"severity": "critical", "title": "SSL Certificate Invalid",
             "description": str(e)}
        )
    except Exception as e:
        result.error = str(e)

    return result
