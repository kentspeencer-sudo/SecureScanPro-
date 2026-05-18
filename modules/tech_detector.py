"""Technology & CMS Detection Module."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx
from bs4 import BeautifulSoup

CMS_SIGNATURES = {
    "WordPress": {
        "html": [r"wp-content", r"wp-includes", r"wp-json", r"wordpress"],
        "headers": {"x-powered-by": "WordPress"},
        "meta": {"generator": "WordPress"},
    },
    "Drupal": {
        "html": [r"Drupal\.settings", r"sites/default/files", r"drupal\.js"],
        "headers": {"x-generator": "Drupal"},
        "meta": {"generator": "Drupal"},
    },
    "Joomla": {
        "html": [r"/media/jui/", r"joomla", r"/components/com_"],
        "meta": {"generator": "Joomla"},
    },
    "Shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopid": ""},
    },
    "Wix": {
        "html": [r"wix\.com", r"X-Wix-"],
    },
    "Squarespace": {
        "html": [r"squarespace\.com", r"squarespace-cdn"],
    },
    "Laravel": {
        "headers": {"x-powered-by": "Laravel"},
        "html": [r"laravel", r"csrf-token"],
    },
    "Django": {
        "headers": {"x-frame-options": ""},
        "html": [r"csrfmiddlewaretoken", r"django"],
    },
    "Next.js": {
        "html": [r"__next", r"_next/static", r"next/dist"],
        "headers": {"x-powered-by": "Next.js"},
    },
    "Nuxt.js": {
        "html": [r"__nuxt", r"_nuxt/"],
    },
    "React": {
        "html": [r"react\.production", r"react-dom", r"__react"],
    },
    "Angular": {
        "html": [r"ng-version", r"angular\.js", r"ng-app"],
    },
    "Vue.js": {
        "html": [r"vue\.js", r"vue\.min\.js", r"v-app", r"vue-router"],
    },
}

JS_LIBRARIES = {
    "jQuery": r"jquery[\.-](\d+\.\d+\.\d+)",
    "Bootstrap": r"bootstrap[\.-](\d+\.\d+\.\d+)",
    "Lodash": r"lodash[\.-](\d+\.\d+\.\d+)",
    "Moment.js": r"moment[\.-](\d+\.\d+\.\d+)",
    "D3.js": r"d3[\.-]v?(\d+\.\d+\.\d+)",
    "Axios": r"axios[\.-](\d+\.\d+\.\d+)",
    "Three.js": r"three[\.-](\d+\.\d+\.\d+)",
}

SERVER_SIGNATURES = {
    "nginx": "Nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "iis": "Microsoft IIS",
    "litespeed": "LiteSpeed",
    "gunicorn": "Gunicorn",
    "express": "Express.js",
    "openresty": "OpenResty",
    "caddy": "Caddy",
}


@dataclass
class TechInfo:
    name: str
    category: str  # cms, framework, library, server, cdn, analytics
    version: str = ""
    confidence: str = "medium"  # low, medium, high


@dataclass
class TechResult:
    url: str = ""
    technologies: list[TechInfo] = field(default_factory=list)
    cms: str = ""
    server: str = ""
    programming_language: str = ""
    js_libraries: list[dict] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)
    issues: list[dict] = field(default_factory=list)
    error: str = ""


async def detect_technologies(url: str, timeout: int = 15) -> TechResult:
    result = TechResult(url=url)

    try:
        async with httpx.AsyncClient(
            follow_redirects=True, verify=False, timeout=timeout
        ) as client:
            resp = await client.get(url)
            html = resp.text
            headers = resp.headers
            soup = BeautifulSoup(html, "html.parser")

            server = headers.get("server", "")
            if server:
                result.server = server
                for sig, name in SERVER_SIGNATURES.items():
                    if sig.lower() in server.lower():
                        result.technologies.append(
                            TechInfo(name=name, category="server", confidence="high")
                        )
                        break

            powered_by = headers.get("x-powered-by", "")
            if powered_by:
                result.technologies.append(
                    TechInfo(name=powered_by, category="framework", confidence="high")
                )
                if "php" in powered_by.lower():
                    result.programming_language = "PHP"
                elif "asp.net" in powered_by.lower():
                    result.programming_language = "ASP.NET"
                elif "express" in powered_by.lower():
                    result.programming_language = "Node.js"

            for meta in soup.find_all("meta"):
                name = meta.get("name", "").lower()
                content = meta.get("content", "")
                if name and content:
                    result.meta_tags[name] = content

            generator = result.meta_tags.get("generator", "")

            for cms_name, signatures in CMS_SIGNATURES.items():
                detected = False

                if "meta" in signatures and generator:
                    for key, val in signatures["meta"].items():
                        if val.lower() in generator.lower():
                            detected = True
                            break

                if not detected and "html" in signatures:
                    for pattern in signatures["html"]:
                        if re.search(pattern, html, re.IGNORECASE):
                            detected = True
                            break

                if not detected and "headers" in signatures:
                    for hname, hval in signatures["headers"].items():
                        hdr_val = headers.get(hname, "")
                        if hdr_val and (not hval or hval.lower() in hdr_val.lower()):
                            detected = True
                            break

                if detected:
                    result.cms = result.cms or cms_name
                    result.technologies.append(
                        TechInfo(name=cms_name, category="cms", confidence="high")
                    )

            for lib_name, pattern in JS_LIBRARIES.items():
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    result.js_libraries.append({"name": lib_name, "version": version})
                    result.technologies.append(
                        TechInfo(name=lib_name, category="library", version=version)
                    )

            scripts = soup.find_all("script", src=True)
            for script in scripts:
                src = script["src"]
                if "analytics" in src.lower() or "gtag" in src.lower() or "ga.js" in src.lower():
                    result.technologies.append(
                        TechInfo(name="Google Analytics", category="analytics", confidence="high")
                    )
                if "gtm" in src.lower():
                    result.technologies.append(
                        TechInfo(name="Google Tag Manager", category="analytics", confidence="high")
                    )
                if "facebook" in src.lower() or "fbevents" in src.lower():
                    result.technologies.append(
                        TechInfo(name="Facebook Pixel", category="analytics", confidence="high")
                    )

            if server and any(sig in server.lower() for sig in SERVER_SIGNATURES):
                result.issues.append({
                    "severity": "low",
                    "title": "Server Software Disclosed",
                    "description": f"Server header reveals: {server}",
                    "recommendation": "Suppress the Server header or use a generic value.",
                })

            if powered_by:
                result.issues.append({
                    "severity": "low",
                    "title": "Technology Stack Disclosed",
                    "description": f"X-Powered-By header reveals: {powered_by}",
                    "recommendation": "Remove the X-Powered-By header.",
                })

    except Exception as e:
        result.error = str(e)

    return result
