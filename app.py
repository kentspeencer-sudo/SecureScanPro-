"""Security Scanner - FastAPI Application."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent

from fastapi import FastAPI, HTTPException, Request, Header
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
from modules.threat_intel import run_threat_intel
from modules.cvss_engine import enrich_issues_with_cvss
from modules.subdomain_scanner import discover_subdomains
from database import (
    init_db, create_user, authenticate_user, verify_user_email,
    get_user_by_id, save_scan, get_user_scans, get_scan_detail,
    get_url_scan_history, create_scheduled_scan, get_user_scheduled_scans,
    delete_scheduled_scan, get_dashboard_stats, get_user_by_api_key,
)

app = FastAPI(title="Security Scanner API", version="2.0.0")

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

# Simple token store (in-memory, maps token -> user_id)
auth_tokens: dict[str, str] = {}

# Rate limiting (IP -> list of scan timestamps)
rate_limit_store: dict[str, list[float]] = defaultdict(list)
FREE_SCAN_LIMIT = 3  # scans per day for unauthenticated users
PRO_SCAN_LIMIT = 50
AGENCY_SCAN_LIMIT = 999999  # unlimited


# --- Pydantic Models ---

class ScanRequest(BaseModel):
    url: str
    scan_types: list[str] | None = None
    auth_type: str | None = None
    credential: str | None = None


class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: str
    company: str = ""
    phone: str = ""


class LoginRequest(BaseModel):
    email: str
    password: str


class MonitorRequest(BaseModel):
    url: str
    interval: str = "weekly"


# --- Dataclasses ---

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


# --- Helpers ---

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


def get_current_user(authorization: str | None) -> dict | None:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "")
    user_id = auth_tokens.get(token)
    if not user_id:
        return None
    return get_user_by_id(user_id)


def require_auth(authorization: str | None = Header(None)) -> dict:
    user = get_current_user(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


# --- Scan Engine ---

async def run_scan(scan_id: str, url: str, scan_types: list[str], user_id: str | None = None) -> None:
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

        if "threat_intel" in scan_types:
            scan["current_module"] = "Threat Intelligence"
            detected_techs = []
            tech_data = scan["results"].get("tech", {})
            if tech_data:
                detected_techs = tech_data.get("technologies", [])
            threat_result = await run_threat_intel(url, hostname, detected_techs)
            result_dict = {
                "cve_matches": threat_result.cve_matches,
                "safe_browsing": threat_result.safe_browsing,
                "shodan_data": threat_result.shodan_data,
                "virustotal_data": threat_result.virustotal_data,
                "breach_data": threat_result.breach_data,
                "subdomain_data": threat_result.subdomain_data,
                "apis_used": threat_result.apis_used,
                "apis_skipped": threat_result.apis_skipped,
            }
            scan["results"]["threat_intel"] = result_dict
            all_issues.extend(threat_result.all_issues)
            completed += 1
            scan["progress"] = int(completed / total_modules * 100)

        if "subdomains" in scan_types:
            scan["current_module"] = "Subdomain Discovery"
            sub_result = await discover_subdomains(hostname)
            scan["results"]["subdomains"] = asdict(sub_result)
            all_issues.extend(sub_result.issues)
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
        # CVSS & Compliance enrichment
        scan["current_module"] = "CVSS & Compliance Analysis"
        compliance = enrich_issues_with_cvss(all_issues)
        scan["all_issues"] = compliance.cvss_enriched
        scan["results"]["compliance"] = {
            "owasp_coverage": compliance.owasp_coverage,
            "pci_dss_coverage": compliance.pci_dss_coverage,
            "compliance_status": compliance.compliance_status,
            "risk_score": compliance.risk_score,
            "risk_level": compliance.risk_level,
        }

        scan["summary"] = {
            "total_issues": len(all_issues),
            "by_severity": count_by_severity(all_issues),
            "grade": overall_grade(all_issues),
            "modules_completed": completed,
            "risk_score": compliance.risk_score,
            "risk_level": compliance.risk_level,
        }
        scan["status"] = "completed"
        scan["progress"] = 100
        scan["current_module"] = ""

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)

    scan["completed_at"] = datetime.now(timezone.utc).isoformat()

    # Save to database
    try:
        save_scan(scan, user_id)
    except Exception:
        pass


# --- Auth API ---

@app.post("/api/auth/signup")
async def api_signup(req: SignupRequest):
    if not req.email or not req.password or not req.full_name:
        raise HTTPException(status_code=400, detail="Email, password and full name are required")
    if len(req.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not any(c.isupper() for c in req.password):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 uppercase letter")
    if not any(c.isdigit() for c in req.password):
        raise HTTPException(status_code=400, detail="Password must contain at least 1 number")

    user = create_user(req.email, req.password, req.full_name, req.company, req.phone)
    if not user:
        raise HTTPException(status_code=400, detail="Email already registered")

    return {
        "message": "Account created successfully",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
        },
    }


@app.post("/api/auth/login")
async def api_login(req: LoginRequest):
    user = authenticate_user(req.email, req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = secrets.token_urlsafe(32)
    auth_tokens[token] = user["id"]

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user["full_name"],
            "company": user["company"],
            "api_key": user["api_key"],
            "is_verified": bool(user["is_verified"]),
        },
    }


@app.get("/api/auth/verify")
async def api_verify_email(token: str):
    if verify_user_email(token):
        return {"message": "Email verified successfully"}
    raise HTTPException(status_code=400, detail="Invalid or expired verification token")


# --- User Dashboard API ---

@app.get("/api/user/dashboard")
async def api_user_dashboard(authorization: str | None = Header(None)):
    user = require_auth(authorization)
    stats = get_dashboard_stats(user["id"])
    scan_list = get_user_scans(user["id"])
    monitors = get_user_scheduled_scans(user["id"])
    return {"stats": stats, "scans": scan_list, "monitors": monitors}


@app.post("/api/user/monitors")
async def api_add_monitor(req: MonitorRequest, authorization: str | None = Header(None)):
    user = require_auth(authorization)
    url = normalize_url(req.url)
    hostname = extract_hostname(url)
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")
    if req.interval not in ("daily", "weekly", "monthly"):
        raise HTTPException(status_code=400, detail="Interval must be daily, weekly, or monthly")
    scan_id = create_scheduled_scan(
        user["id"], url, hostname,
        ["ssl", "headers", "ports", "dns", "tech", "vulns", "enterprise", "threat_intel", "subdomains"],
        req.interval,
    )
    return {"id": scan_id, "message": "Monitor added"}


@app.delete("/api/user/monitors/{monitor_id}")
async def api_delete_monitor(monitor_id: str, authorization: str | None = Header(None)):
    user = require_auth(authorization)
    if not delete_scheduled_scan(monitor_id, user["id"]):
        raise HTTPException(status_code=404, detail="Monitor not found")
    return {"message": "Monitor deleted"}


@app.get("/api/user/scan-history")
async def api_scan_history(url: str, authorization: str | None = Header(None)):
    require_auth(authorization)
    history = get_url_scan_history(url)
    return {"history": history}


# --- Scan API ---

@app.get("/api/rate-limit")
async def get_rate_limit(request: Request, authorization: str | None = Header(None)):
    user = get_current_user(authorization)
    if user:
        return {"limit": PRO_SCAN_LIMIT, "remaining": PRO_SCAN_LIMIT, "plan": "pro"}
    client_ip = request.client.host if request.client else "unknown"
    now = datetime.now(timezone.utc).timestamp()
    day_ago = now - 86400
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if t > day_ago]
    used = len(rate_limit_store[client_ip])
    return {"limit": FREE_SCAN_LIMIT, "remaining": max(0, FREE_SCAN_LIMIT - used), "plan": "free"}


@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request, authorization: str | None = Header(None)):
    url = normalize_url(req.url)
    hostname = extract_hostname(url)
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL")

    user = get_current_user(authorization)
    user_id = user["id"] if user else None

    # Rate limiting for unauthenticated users
    if not user:
        client_ip = request.client.host if request.client else "unknown"
        now = datetime.now(timezone.utc).timestamp()
        day_ago = now - 86400
        rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if t > day_ago]
        if len(rate_limit_store[client_ip]) >= FREE_SCAN_LIMIT:
            raise HTTPException(
                status_code=429,
                detail=f"Free plan limit reached ({FREE_SCAN_LIMIT} scans/day). Login or upgrade to Pro for more scans."
            )
        rate_limit_store[client_ip].append(now)

    scan_id = str(uuid.uuid4())[:8]
    scan_types = req.scan_types or [
        "ssl", "headers", "ports", "dns", "tech", "vulns",
        "enterprise", "threat_intel", "subdomains",
    ]

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

    asyncio.create_task(run_scan(scan_id, url, scan_types, user_id))

    return {"scan_id": scan_id, "status": "queued", "url": url}


@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    if scan_id not in scans:
        db_scan = get_scan_detail(scan_id)
        if db_scan:
            return db_scan
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]


@app.get("/api/scan/{scan_id}/report")
async def get_report(scan_id: str):
    if scan_id not in scans:
        db_scan = get_scan_detail(scan_id)
        if db_scan:
            return db_scan
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


# --- Page Routes ---

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "dashboard.html")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(request, "auth.html")


@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse(request, "auth.html")


@app.get("/dashboard", response_class=HTMLResponse)
async def user_dashboard_page(request: Request):
    return templates.TemplateResponse(request, "user_dashboard.html")


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


@app.get("/privacy", response_class=HTMLResponse)
async def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html")


@app.get("/terms", response_class=HTMLResponse)
async def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html")


@app.get("/refund", response_class=HTMLResponse)
async def refund_page(request: Request):
    return templates.TemplateResponse(request, "refund.html")


@app.get("/api-management", response_class=HTMLResponse)
async def api_management_page(request: Request):
    return templates.TemplateResponse(request, "api_management.html")


# --- PDF Report API ---

class PDFReportRequest(BaseModel):
    whitelabel: dict[str, str] | None = None
    language: str = "en"
    include_executive_summary: bool = True


@app.post("/api/scan/{scan_id}/pdf")
async def generate_pdf(scan_id: str, req: PDFReportRequest | None = None):
    from fastapi.responses import Response
    from modules.pdf_report import generate_pdf_report

    scan = scans.get(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.get("status") != "completed":
        raise HTTPException(status_code=400, detail="Scan not yet completed")

    body = req or PDFReportRequest()
    pdf_bytes = generate_pdf_report(
        scan_data=scan,
        whitelabel=body.whitelabel,
        include_executive_summary=body.include_executive_summary,
        language=body.language,
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="securescan-report-{scan_id[:8]}.pdf"'},
    )


@app.get("/api/languages")
async def get_languages():
    from modules.pdf_report import TRANSLATIONS
    return {
        "languages": [
            {"code": "en", "name": "English", "direction": "ltr"},
            {"code": "ur", "name": "اردو (Urdu)", "direction": "rtl"},
            {"code": "ar", "name": "العربية (Arabic)", "direction": "rtl"},
            {"code": "es", "name": "Español (Spanish)", "direction": "ltr"},
        ]
    }


# --- Startup ---

@app.on_event("startup")
async def startup_event():
    init_db()
