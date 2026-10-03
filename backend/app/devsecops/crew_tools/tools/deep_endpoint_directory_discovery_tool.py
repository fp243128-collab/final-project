try:
    from app.devsecops.crew_tools.tools.base import BaseTool
except Exception:
    try:
        from .base import BaseTool
    except Exception:
        from pydantic import BaseModel
        class BaseTool(BaseModel):  # type: ignore
            pass

from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional
import requests
import re


# ── Input Schema ─────────────────────────────────────────────────────────────

class DeepEndpointDiscoveryInput(BaseModel):
    """Input schema for the Deep Endpoint and Directory Discovery Tool."""
    base_url: str = Field(
        ...,
        description=(
            "The base URL of the target to probe (e.g. https://example.com). "
            "Must include the scheme (http:// or https://)."
        ),
    )


# ── Constants ─────────────────────────────────────────────────────────────────

SENSITIVE_PATHS: List[str] = [
    # Admin panels
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/cpanel", "/phpmyadmin", "/adminer",
    # API endpoints
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/graphql", "/swagger", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/docs",
    # Config / sensitive files
    "/robots.txt", "/sitemap.xml", "/.env", "/config.php",
    "/web.config", "/phpinfo.php", "/.git/config", "/.git/HEAD",
    "/config.json", "/package.json", "/.htaccess",
    "/backup.zip", "/dump.sql", "/database.sql",
    # Authentication
    "/login", "/register", "/signup", "/forgot-password",
    "/reset-password", "/logout", "/auth", "/oauth", "/token", "/refresh",
    # User data
    "/users", "/profile", "/account", "/settings", "/dashboard",
    # Health / debug
    "/health", "/status", "/debug", "/info", "/metrics",
    "/actuator", "/actuator/health", "/actuator/env", "/server-status",
]

HIGH_RISK_PATTERNS: List[str] = [
    ".env", ".git", "phpinfo", "backup", "dump.sql",
    "database.sql", "actuator/env",
]

TIMEOUT = 8  # seconds per request


# ── Helper Functions ──────────────────────────────────────────────────────────

def _normalise_base(base_url: str) -> str:
    """Strip trailing slash from the base URL."""
    return base_url.rstrip("/")


def _classify(status: int) -> str:
    if status == 200:
        return "EXPOSED"
    if status in (301, 302, 303, 307, 308):
        return "REDIRECTED"
    if status == 403:
        return "FORBIDDEN"
    if status == 404:
        return "NOT FOUND"
    if status >= 500:
        return "ERROR"
    return f"OTHER ({status})"


def _is_high_risk(path: str, status: int) -> bool:
    if status != 200:
        return False
    path_lower = path.lower()
    return any(pattern in path_lower for pattern in HIGH_RISK_PATTERNS)


def _probe(session: requests.Session, url: str) -> Dict[str, Any]:
    """Probe a single URL and return a result dict."""
    try:
        response = session.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=False,  # capture redirects manually
            verify=False,           # allow self-signed certs in pentesting contexts
        )
        redirect_location: Optional[str] = response.headers.get("Location")
        return {
            "url": url,
            "status": response.status_code,
            "size": len(response.content),
            "redirect": redirect_location,
            "classification": _classify(response.status_code),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {"url": url, "status": None, "size": 0,
                "redirect": None, "classification": "TIMEOUT", "error": "Request timed out"}
    except requests.exceptions.ConnectionError as exc:
        return {"url": url, "status": None, "size": 0,
                "redirect": None, "classification": "CONNECTION ERROR", "error": str(exc)[:120]}
    except requests.exceptions.RequestException as exc:
        return {"url": url, "status": None, "size": 0,
                "redirect": None, "classification": "REQUEST ERROR", "error": str(exc)[:120]}


def _discover_js_files(session: requests.Session, base_url: str) -> List[str]:
    """Fetch the main page and extract all .js file references."""
    js_files: List[str] = []
    try:
        response = session.get(base_url, timeout=TIMEOUT, verify=False)
        # Match src="..." and href="..." attributes ending in .js
        pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
        matches = re.findall(pattern, response.text, re.IGNORECASE)
        seen = set()
        for match in matches:
            match = match.strip()
            if not match:
                continue
            # Resolve relative paths
            if match.startswith("http://") or match.startswith("https://"):
                full = match
            elif match.startswith("//"):
                scheme = base_url.split("://")[0]
                full = f"{scheme}:{match}"
            elif match.startswith("/"):
                full = base_url + match
            else:
                full = base_url + "/" + match
            if full not in seen:
                seen.add(full)
                js_files.append(full)
    except requests.exceptions.RequestException:
        pass  # silently skip JS discovery if main page is unreachable
    return js_files


# ── Risk Ordering ─────────────────────────────────────────────────────────────

_RISK_ORDER = {
    "EXPOSED": 0,
    "REDIRECTED": 1,
    "FORBIDDEN": 2,
    "ERROR": 3,
    "OTHER": 4,
    "TIMEOUT": 5,
    "CONNECTION ERROR": 6,
    "REQUEST ERROR": 7,
    "NOT FOUND": 8,
}


def _sort_key(result: Dict[str, Any]) -> int:
    cls = result["classification"]
    # Normalise "OTHER (xxx)" keys
    base_cls = cls if cls in _RISK_ORDER else "OTHER"
    base_order = _RISK_ORDER.get(base_cls, 9)
    # HIGH RISK items bubble to the very top within EXPOSED
    if result.get("high_risk"):
        return -1
    return base_order


# ── Report Builder ────────────────────────────────────────────────────────────

def _build_report(base_url: str, results: List[Dict[str, Any]], js_files: List[str]) -> str:
    lines: List[str] = []

    lines.append(f"# 🔍 Deep Endpoint & Directory Discovery Report")
    lines.append(f"\n**Target:** `{base_url}`\n")

    # ── Summary ──
    total = len(results)
    exposed = [r for r in results if r["classification"] == "EXPOSED"]
    forbidden = [r for r in results if r["classification"] == "FORBIDDEN"]
    redirected = [r for r in results if r["classification"] == "REDIRECTED"]
    high_risk = [r for r in results if r.get("high_risk")]
    errors = [r for r in results if r["classification"] in ("TIMEOUT", "CONNECTION ERROR", "REQUEST ERROR")]

    lines.append("## 📊 Summary\n")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total probed | {total} |")
    lines.append(f"| ⚠️ HIGH RISK (200 sensitive) | {len(high_risk)} |")
    lines.append(f"| 🟢 Exposed (200) | {len(exposed)} |")
    lines.append(f"| 🔴 Forbidden (403) | {len(forbidden)} |")
    lines.append(f"| 🔀 Redirected (3xx) | {len(redirected)} |")
    lines.append(f"| ❌ Errors / Timeouts | {len(errors)} |")
    lines.append(f"| 📜 JS files discovered | {len(js_files)} |")

    # ── High Risk ──
    if high_risk:
        lines.append("\n---\n## 🚨 HIGH RISK — Sensitive Files Exposed (HTTP 200)\n")
        lines.append("| URL | Size (bytes) |")
        lines.append("|-----|-------------|")
        for r in high_risk:
            lines.append(f"| `{r['url']}` | {r['size']} |")

    # ── All Results sorted by risk ──
    sorted_results = sorted(results, key=_sort_key)

    lines.append("\n---\n## 📋 Full Probe Results (Sorted by Risk)\n")
    lines.append("| Status | Classification | URL | Size (bytes) | Redirect / Note |")
    lines.append("|--------|----------------|-----|-------------|-----------------|")

    for r in sorted_results:
        status_str = str(r["status"]) if r["status"] is not None else "—"
        redirect_str = f"`{r['redirect']}`" if r["redirect"] else (r["error"] or "—")
        risk_badge = " 🚨" if r.get("high_risk") else ""
        cls = r["classification"] + risk_badge
        lines.append(
            f"| {status_str} | {cls} | `{r['url']}` | {r['size']} | {redirect_str} |"
        )

    # ── JS Files ──
    lines.append("\n---\n## 📜 JavaScript Files Discovered\n")
    if js_files:
        lines.append("> These files may contain hardcoded API keys, secret endpoints, or application logic.\n")
        lines.append("| # | JS File URL |")
        lines.append("|---|------------|")
        for idx, js in enumerate(js_files, 1):
            lines.append(f"| {idx} | `{js}` |")
    else:
        lines.append("_No JavaScript file references found on the main page._")

    lines.append("\n---\n_Report generated by Deep Endpoint and Directory Discovery Tool_")
    return "\n".join(lines)


# ── Tool Class ────────────────────────────────────────────────────────────────

class DeepEndpointDirectoryDiscoveryTool(BaseTool):
    """
    Probes a target base URL for common sensitive endpoints, configuration
    files, admin panels, API routes, and JavaScript file references.
    Returns a structured markdown report sorted by risk level.
    """

    name: str = "Deep Endpoint and Directory Discovery Tool"
    description: str = (
        "Accepts a base URL and probes it for common sensitive endpoints, "
        "admin panels, API routes, config/secret files, and JavaScript "
        "references. Returns a markdown report with HTTP status codes, "
        "response sizes, redirect locations, and HIGH RISK flags for "
        "dangerously exposed files (e.g. .env, .git, phpinfo, backups)."
    )
    args_schema: Type[BaseModel] = DeepEndpointDiscoveryInput

    def _run(self, base_url: str) -> str:  # noqa: D401
        """Execute the endpoint discovery probe and return a markdown report."""
        base_url = _normalise_base(base_url)

        # Suppress InsecureRequestWarning for self-signed certs
        try:
            import urllib3  # bundled with requests
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        results: List[Dict[str, Any]] = []

        with requests.Session() as session:
            session.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (compatible; EndpointDiscoveryBot/1.0)"
                )
            })

            # ── Probe all sensitive paths ──
            for path in SENSITIVE_PATHS:
                url = base_url + path
                result = _probe(session, url)
                result["high_risk"] = _is_high_risk(path, result["status"] or 0)
                results.append(result)

            # ── Discover JS files ──
            js_files = _discover_js_files(session, base_url)

        return _build_report(base_url, results, js_files)
