"""TCP Port Scanner - checks common service ports."""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt2",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

RISKY_PORTS = {21, 23, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 27017}


@dataclass
class PortInfo:
    port: int
    service: str
    state: str  # open, closed, filtered
    banner: str = ""


@dataclass
class PortScanResult:
    hostname: str = ""
    ip_address: str = ""
    open_ports: list[PortInfo] = field(default_factory=list)
    issues: list[dict] = field(default_factory=list)
    total_scanned: int = 0
    error: str = ""


async def scan_port(host: str, port: int, timeout: float = 3.0) -> PortInfo:
    service = COMMON_PORTS.get(port, "Unknown")
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        banner = ""
        try:
            data = await asyncio.wait_for(
                asyncio.ensure_future(_read_banner(host, port)),
                timeout=2.0,
            )
            banner = data.strip()
        except Exception:
            pass
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return PortInfo(port=port, service=service, state="open", banner=banner)
    except asyncio.TimeoutError:
        return PortInfo(port=port, service=service, state="filtered")
    except (ConnectionRefusedError, OSError):
        return PortInfo(port=port, service=service, state="closed")


async def _read_banner(host: str, port: int) -> str:
    try:
        reader, writer = await asyncio.open_connection(host, port)
        data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


async def scan_ports(
    hostname: str,
    ports: list[int] | None = None,
    concurrency: int = 50,
) -> PortScanResult:
    result = PortScanResult(hostname=hostname)

    try:
        result.ip_address = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        result.error = f"DNS resolution failed: {e}"
        return result

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    result.total_scanned = len(ports)

    sem = asyncio.Semaphore(concurrency)

    async def limited_scan(p: int) -> PortInfo:
        async with sem:
            return await scan_port(result.ip_address, p)

    tasks = [limited_scan(p) for p in ports]
    results = await asyncio.gather(*tasks)

    for pi in results:
        if pi.state == "open":
            result.open_ports.append(pi)

            if pi.port in RISKY_PORTS:
                result.issues.append({
                    "severity": "high",
                    "title": f"Sensitive Port Open: {pi.port}/{pi.service}",
                    "description": f"Port {pi.port} ({pi.service}) is open and publicly accessible. "
                                   "This service should not typically be exposed to the internet.",
                    "recommendation": f"Restrict access to port {pi.port} using firewall rules or VPN.",
                })

            if pi.banner:
                result.issues.append({
                    "severity": "low",
                    "title": f"Banner Disclosure on Port {pi.port}",
                    "description": f"Port {pi.port} reveals: {pi.banner[:200]}",
                    "recommendation": "Suppress service banners to reduce information disclosure.",
                })

    return result
