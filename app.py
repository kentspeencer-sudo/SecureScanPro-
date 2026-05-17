"""Security Scanner - FastAPI Application."""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from modules.ssl_checker import check_ssl
from modules.header_checker import check_headers
from modules.port_scanner import scan_ports
from modules.dns_checker import check_dns
from modules.tech_detector import detect_technologies
from modules.vuln_checker import check_vulnerabilities
from modules.enterprise_checker import check_enterprise_security
from modules.deep_scanner import run_deep_scan

app = FastAPI(title="Security Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

scans: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    url: str
    scan_types: list[str] | None = None
    auth_type: str | None = None
    credential: str | None = None


@dataclass
class ScanProgress:
    scan_id: str
    url: str
    hostname: str
    status: str = "queued"
    started_at: str = ""
    completed_at: str = ""
    progress: int = 0
    current_module: str = ""
    results: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    all_issues: list[dict] = field(default_factory=list)
    credential_tests: list[dict] = field(default_factory=list)
    error: str = ""


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url


def extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or ""


def count_by_severity(issues: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in issues:
        sev = issue.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def overall_grade(issues: list[dict]) -> str:
    counts = count_by_severity(issues)
    if counts["critical"] > 0:
        return "F"
    if counts["high"] >= 3:
        return "D"
    if counts["high"] >= 1:
        return "C"
    if counts["medium"] >= 3:
        return "C"
    if counts["medium"] >= 1:
        return "B"
    if counts["low"] >= 3:
        return "B"
    return "A"


async def run_scan(scan_id: str, url: str, scan_types: list[str]) -> None:
    scan = scans[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.now(timezone.utc).isoformat()
    hostname = scan["hostname"]
    all_issues: list[dict] = []

    total_modules = len(scan_types)
    completed = 0

    try:
        if "ssl" in scan_types:
            scan["current_module"] = "SSL/TLS Analysis"
            ssl_result = await asyncio.get_event_loop().run_in_executor(
                None, check_ssl, hostname
            )
            scan["results"]["ssl"] = asdict(ssl_result)
            all_issues.extend(ssl_result.issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "headers" in scan_types:
            scan["current_module"] = "Security Headers"
            header_result = await check_headers(url)
            scan["results"]["headers"] = asdict(header_result)
            all_issues.extend(header_result.issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "ports" in scan_types:
            scan["current_module"] = "Port Scanning"
            port_result = await scan_ports(hostname)
            result_dict = asdict(port_result)
            scan["results"]["ports"] = result_dict
            all_issues.extend(port_result.issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "dns" in scan_types:
            scan["current_module"] = "DNS Analysis"
            dns_result = await asyncio.get_event_loop().run_in_executor(
                None, check_dns, hostname
            )
            scan["results"]["dns"] = asdict(dns_result)
            all_issues.extend(dns_result.issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "tech" in scan_types:
            scan["current_module"] = "Technology Detection"
            tech_result = await detect_technologies(url)
            result_dict = asdict(tech_result)
            scan["results"]["tech"] = result_dict
            all_issues.extend(tech_result.issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "vulns" in scan_types:
            scan["current_module"] = "Vulnerability Assessment"
            vuln_result = await check_vulnerabilities(url)
            result_dict = asdict(vuln_result)
            scan["results"]["vulns"] = result_dict
            all_issues.extend(vuln_result.issues)
            scan["credential_tests"] = vuln_result.credential_tests
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "enterprise" in scan_types:
            scan["current_module"] = "Enterprise CRM Security"
            ent_result = await check_enterprise_security(url)
            result_dict = asdict(ent_result)
            scan["results"]["enterprise"] = result_dict
            all_issues.extend(ent_result.all_issues)
            scan["agency_pricing"] = ent_result.agency_pricing
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "deep" in scan_types and scan.get("auth_type") and scan.get("credential"):
            scan["current_module"] = "Authenticated Deep Scan"
            deep_result = await run_deep_scan(
                url, scan["auth_type"], scan["credential"]
            )
            result_dict = asdict(deep_result)
            scan["results"]["deep"] = result_dict
            all_issues.extend(deep_result.all_issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        scan["all_issues"] = all_issues
        scan["summary"] = {
            "total_issues": len(all_issues),
            "by_severity": count_by_severity(all_issues),
            "grade": overall_grade(all_issues),
            "modules_completed": completed,
        }
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["current_module"] = ""

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)

    scan["completed_at"] = datetime.now(timezone.utc).isoformat()


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    url = normalize_url(req.url)
    hostname = extract_hostname(url)
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    scan_id = str(uuid.uuid4())[:8]
    scan_types = req.scan_types or ["ssl", "headers", "ports", "dns", "tech", "vulns", "enterprise"]

    scan_data = {
        "scan_id": scan_id,
        "url": url,
        "hostname": hostname,
        "status": "queued",
        "started_at": "",
        "completed_at": "",
        "progress": 0,
        "current_module": "",
        "results": {},
        "summary": {},
        "all_issues": [],
        "credential_tests": [],
        "agency_pricing": [],
        "error": "",
    }
    scans[scan_id] = scan_data

    if req.auth_type and req.credential:
        scan_data["auth_type"] = req.auth_type
        scan_data["credential"] = req.credential
        if "deep" not in scan_types:
            scan_types.append("deep")

    asyncio.create_task(run_scan(scan_id, url, scan_types))

    return {"scan_id": scan_id, "status": "queued", "url": url}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]
    if scan["status"] != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")
    return {
        "scan_id": scan_id,
        "url": scan["url"],
        "hostname": scan["hostname"],
        "started_at": scan["started_at"],
        "completed_at": scan["completed_at"],
        "summary": scan["summary"],
        "all_issues": scan["all_issues"],
        "credential_tests": scan["credential_tests"],
        "agency_pricing": scan.get("agency_pricing", []),
        "results": scan["results"],
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/embed", response_class=HTMLResponse)
async def embed_widget(request: Request):
    return templates.TemplateResponse(request, "embed.html")


@app.get("/report/{scan_id}", response_class=HTMLResponse)
async def report_page(request: Request, scan_id: str):
    return templates.TemplateResponse(
        request, "report.html", {"scan_id": scan_id}
    )


@app.get("/pricing", response_class=HTMLResponse)
async def pricing_page(request: Request):
    return templates.TemplateResponse(request, "pricing.html")


@app.get("/authenticated", response_class=HTMLResponse)
async def authenticated_page(request: Request):
    return templates.TemplateResponse(request, "authenticated.html")
