from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional
import requests
import re
import time
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


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


# ── Target Paths ──────────────────────────────────────────────────────────────

ADMIN_PATHS: List[str] = [
    "/admin", "/administrator", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/cpanel", "/phpmyadmin", "/adminer",
]

API_PATHS: List[str] = [
    "/api", "/api/v1", "/api/v2", "/api/v3", "/api/users", "/api/admin",
    "/graphql", "/swagger", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/docs", "/v1/api-docs", "/v2/api-docs",
]

SENSITIVE_CONFIG_PATHS: List[str] = [
    "/.env", "/config.php", "/web.config", "/phpinfo.php",
    "/.git/config", "/.git/HEAD", "/config.json", "/package.json",
    "/.htaccess", "/backup.zip", "/dump.sql", "/database.sql",
    "/server-status", "/actuator/env", "/actuator/health",
]

AUTH_PATHS: List[str] = [
    "/login", "/signin", "/register", "/signup", "/forgot-password",
    "/reset-password", "/logout", "/auth", "/oauth", "/oauth/token",
    "/token", "/refresh", "/sso",
]

PUBLIC_CORE_PATHS: List[str] = [
    "/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
    "/health", "/status", "/ping", "/version",
]

ALL_CORE_PATHS: List[str] = (
    ADMIN_PATHS + API_PATHS + SENSITIVE_CONFIG_PATHS + AUTH_PATHS + PUBLIC_CORE_PATHS
)

CRITICAL_PATTERNS = [
    ".env", ".git", "phpinfo", "backup", "dump.sql", "database.sql",
    "actuator/env", "config.json", "web.config"
]


# ── Probing Engine ────────────────────────────────────────────────────────────

def _classify_status(status: Optional[int]) -> str:
    if status is None:
        return "Connection Failed"
    if status == 200:
        return "Exposed (200 OK)"
    if status == 201:
        return "Created (201)"
    if status in (301, 302, 303, 307, 308):
        return f"Redirected ({status})"
    if status == 401:
        return "Unauthorized (401)"
    if status == 403:
        return "Forbidden (403)"
    if status == 404:
        return "Not Found (404)"
    if status == 405:
        return "Method Not Allowed (405)"
    if status == 429:
        return "Rate Limited (429)"
    if status >= 500:
        return f"Server Error ({status})"
    return f"HTTP {status}"


def _assess_risk(path: str, status: Optional[int]) -> str:
    if status is None:
        return "Low"
    path_lower = path.lower()
    
    # Critical files exposed directly
    if status == 200 and any(pat in path_lower for pat in CRITICAL_PATTERNS):
        return "Critical"
    
    # Admin panels or configs accessible
    if status == 200 and any(p in path_lower for p in ["/admin", "/wp-admin", "/phpmyadmin", "/actuator"]):
        return "High"
    
    # API docs or swagger exposed without auth
    if status == 200 and any(p in path_lower for p in ["/swagger", "/openapi.json", "/api-docs", "/graphql"]):
        return "Medium"
        
    # Forbidden admin/config endpoints indicate valid routes behind WAF/auth
    if status == 403 and any(p in path_lower for p in ["/admin", "/.git", "/.env", "/cpanel"]):
        return "Medium"
        
    if status == 200:
        return "Low"
        
    return "Info"


def _probe_single(base_url: str, path: str, timeout: float = 6.0) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    start_time = time.time()
    try:
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }
        )
        latency_ms = int((time.time() - start_time) * 1000)
        content_type = resp.headers.get("Content-Type", "—").split(";")[0].strip()
        location = resp.headers.get("Location", "—")
        server = resp.headers.get("Server", "—")
        
        return {
            "path": path,
            "url": url,
            "status": resp.status_code,
            "classification": _classify_status(resp.status_code),
            "size": len(resp.content),
            "latency_ms": latency_ms,
            "content_type": content_type,
            "location": location,
            "server": server,
            "risk": _assess_risk(path, resp.status_code),
            "error": None,
        }
    except requests.exceptions.Timeout:
        return {
            "path": path,
            "url": url,
            "status": None,
            "classification": "Request Timeout",
            "size": 0,
            "latency_ms": int((time.time() - start_time) * 1000),
            "content_type": "—",
            "location": "—",
            "server": "—",
            "risk": "Low",
            "error": "Timeout after 6s",
        }
    except Exception as e:
        return {
            "path": path,
            "url": url,
            "status": None,
            "classification": "Connection Error",
            "size": 0,
            "latency_ms": int((time.time() - start_time) * 1000),
            "content_type": "—",
            "location": "—",
            "server": "—",
            "risk": "Low",
            "error": str(e)[:60],
        }


def _extract_robots_paths(base_url: str) -> List[str]:
    discovered = []
    try:
        url = f"{base_url.rstrip('/')}/robots.txt"
        resp = requests.get(url, timeout=5, verify=False)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                line = line.strip()
                if line.lower().startswith(("disallow:", "allow:")):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        target_p = parts[1].strip()
                        if target_p and target_p.startswith("/") and "*" not in target_p and target_p not in discovered:
                            discovered.append(target_p)
    except Exception:
        pass
    return discovered[:15]


def _extract_js_bundles(base_url: str) -> List[Dict[str, str]]:
    js_records: List[Dict[str, str]] = []
    try:
        resp = requests.get(base_url, timeout=8, verify=False)
        if resp.status_code == 200:
            pattern = r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
            matches = re.findall(pattern, resp.text, re.IGNORECASE)
            seen = set()
            base_domain = urlparse(base_url).netloc.lower()
            for m in matches:
                m = m.strip()
                if not m or m in seen:
                    continue
                seen.add(m)
                
                # Resolve full URL
                full_url = urljoin(base_url, m)
                js_domain = urlparse(full_url).netloc.lower()
                is_internal = (base_domain in js_domain or js_domain in base_domain or not js_domain)
                
                # Classify bundle type
                filename = full_url.split("/")[-1].split("?")[0]
                if any(x in filename.lower() for x in ["vendor", "chunk-vendors", "npm", "libs"]):
                    b_type = "Vendor / Dependency"
                elif any(x in filename.lower() for x in ["app", "main", "bundle", "index", "_app"]):
                    b_type = "Core Application Bundle"
                elif any(x in filename.lower() for x in ["gtm", "analytics", "pixel", "tracking"]):
                    b_type = "Telemetry & Analytics"
                else:
                    b_type = "Client Script"
                    
                js_records.append({
                    "url": full_url,
                    "filename": filename or "script.js",
                    "origin": "Internal" if is_internal else "Third-Party / CDN",
                    "type": b_type,
                })
    except Exception:
        pass
    return js_records[:25]


# ── Report Generation ─────────────────────────────────────────────────────────

def _format_table(rows: List[Dict[str, Any]]) -> str:
    if not rows:
        return "| Endpoint Path | HTTP Status | Classification | Latency | Size | Redirect / Target | Risk Level |\n|---|---|---|---|---|---|---|\n| _No endpoints identified in this category_ | — | — | — | — | — | Info |\n"
    
    out = [
        "| Endpoint Path | HTTP Status | Classification | Latency | Size | Content-Type / Redirect | Risk Level |",
        "|---|---|---|---|---|---|---|"
    ]
    for r in rows:
        status_code = str(r["status"]) if r["status"] is not None else "ERR"
        extra = r["location"] if r["location"] != "—" else (r["content_type"] if r["content_type"] != "—" else r["error"] or "—")
        if len(extra) > 40:
            extra = extra[:37] + "..."
        out.append(
            f"| `{r['path']}` | `{status_code}` | {r['classification']} | `{r['latency_ms']}ms` | `{r['size']} B` | `{extra}` | {r['risk']} |"
        )
    return "\n".join(out)


def _build_discovery_report(base_url: str, all_results: List[Dict[str, Any]], js_bundles: List[Dict[str, str]], robots_paths: List[str]) -> str:
    # Categorize results
    admin_results = [r for r in all_results if r["path"] in ADMIN_PATHS or any(p in r["path"].lower() for p in ["admin", "cpanel", "phpmyadmin"])]
    api_results = [r for r in all_results if r["path"] in API_PATHS or any(p in r["path"].lower() for p in ["api", "graphql", "swagger", "docs"])]
    config_results = [r for r in all_results if r["path"] in SENSITIVE_CONFIG_PATHS or any(p in r["path"].lower() for p in [".env", ".git", "backup", "sql", "config"])]
    auth_results = [r for r in all_results if r["path"] in AUTH_PATHS or any(p in r["path"].lower() for p in ["login", "auth", "token", "signup"])]
    core_results = [r for r in all_results if r["path"] in PUBLIC_CORE_PATHS or r["path"] in robots_paths]

    total_probed = len(all_results)
    exposed_200 = sum(1 for r in all_results if r["status"] == 200)
    redirects_3xx = sum(1 for r in all_results if r["status"] in (301, 302, 303, 307, 308))
    forbidden_403 = sum(1 for r in all_results if r["status"] == 403)
    critical_exposures = [r for r in all_results if r["risk"] in ("Critical", "High") and r["status"] == 200]

    sections = []
    sections.append("# Deep Endpoint & Directory Discovery Audit")
    sections.append(f"**Target System Base URL:** `{base_url}`\n")

    # 1. Summary Matrix
    sections.append("## Endpoint Discovery Overview\n")
    sections.append("| Discovery Metric | Quantitative Result | Security Interpretation | Status |")
    sections.append("|---|---|---|---|")
    sections.append(f"| Total Route Paths Probed | `{total_probed}` Target Vectors | Comprehensive surface enumeration | Configured |")
    sections.append(f"| Publicly Accessible (200 OK) | `{exposed_200}` Active Endpoints | Publicly reachable routes and assets | {'Warning' if exposed_200 > 15 else 'Normal'} |")
    sections.append(f"| Access Restricted (403 Forbidden) | `{forbidden_403}` Routes Protected | Endpoint discovered but perimeter access denied | Protected |")
    sections.append(f"| Route Redirects (3xx Series) | `{redirects_3xx}` Routed Endpoints | Path forwarded to canonical or auth location | Routed |")
    sections.append(f"| High / Critical Exposures | `{len(critical_exposures)}` Endpoints Identified | Sensitive config/admin panels directly readable | {'Critical' if len(critical_exposures) > 0 else 'Clean'} |")
    sections.append(f"| Discovered JavaScript Bundles | `{len(js_bundles)}` Client Script Files | Front-end static assets subject to analysis | Cataloged |")
    if robots_paths:
        sections.append(f"| Robots.txt Route Directives | `{len(robots_paths)}` Disallowed Paths | Paths intentionally hidden from crawler indexing | Analyzed |")

    # 2. Critical & Sensitive Exposure Table
    sections.append("\n## Sensitive Files & Configuration Exposures\n")
    if critical_exposures:
        sections.append("> Critical Alert: One or more highly sensitive configuration files, version control trees, or backup dumps were found accessible without authentication.\n")
    sections.append(_format_table(config_results))

    # 3. Administrative Portals & Management Consoles
    sections.append("\n## Administrative Portals & Control Consoles\n")
    sections.append(_format_table(admin_results))

    # 4. API Endpoints & Service Gateways
    sections.append("\n## API Routes & Service Gateways\n")
    sections.append(_format_table(api_results))

    # 5. Authentication & Identity Endpoints
    sections.append("\n## Authentication & Session Management Routes\n")
    sections.append(_format_table(auth_results))

    # 6. JavaScript Client-Side Assets
    sections.append("\n## Discovered JavaScript Assets & Bundles\n")
    if js_bundles:
        sections.append("| Bundle Identifier | Origin Type | Classification | Asset Source URL |")
        sections.append("|---|---|---|---|")
        for js in js_bundles:
            sections.append(f"| `{js['filename']}` | {js['origin']} | {js['type']} | `{js['url']}` |")
    else:
        sections.append("| Bundle Identifier | Origin Type | Classification | Asset Source URL |")
        sections.append("|---|---|---|---|")
        sections.append("| _No script bundles detected on target root_ | — | — | — |")

    # 7. Action Items
    sections.append("\n## Endpoint Hardening Action Items\n")
    sections.append("| Finding Focus | Risk Level | Target Route / Vector | Remediation Strategy |")
    sections.append("|---|---|---|---|")
    if critical_exposures:
        for ce in critical_exposures:
            sections.append(f"| Exposed Sensitive Asset | Critical | `{ce['path']}` | Restrict web server access immediately via Nginx/Apache configuration or WAF block rule. |")
    else:
        sections.append("| Configuration Hardening | Low | `/.env`, `/.git`, `/backup.zip` | Confirm web server denies all dotfiles and backup extensions at root directory. |")
    sections.append("| Administrative Perimeter | Medium | `/admin`, `/wp-admin` | Enforce multi-factor authentication, IP allowlisting, or VPN gateway requirement. |")
    sections.append("| API Documentation Gate | Low | `/swagger`, `/openapi.json` | Restrict public swagger/OpenAPI UI availability in production environments. |")
    sections.append("| Client-side Secret Audit | Medium | JavaScript Bundles | Ensure no private API tokens, staging credentials, or unreleased routes are embedded in build. |")

    return "\n".join(sections)


# ── Tool Class ────────────────────────────────────────────────────────────────

class DeepEndpointDirectoryDiscoveryTool(BaseTool):
    """
    Probes target base URL for common sensitive endpoints, configuration
    files, admin panels, API routes, and JavaScript file references.
    Returns a clean, executive tabular security report.
    """

    name: str = "Deep Endpoint and Directory Discovery Tool"
    description: str = (
        "Accepts a base URL and performs high-performance concurrent discovery of "
        "sensitive endpoints, admin panels, API routes, config files, robots.txt directives, "
        "and client-side JavaScript assets. Returns a structured dual-axis tabular audit report."
    )
    args_schema: Type[BaseModel] = DeepEndpointDiscoveryInput

    def _run(self, base_url: str) -> str:
        """Execute concurrent endpoint discovery probe and build clean markdown report."""
        if not base_url.startswith(("http://", "https://")):
            base_url = f"https://{base_url}"
        base_url = base_url.rstrip("/")

        # Suppress SSL warnings for pentesting
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        # 1. Extract paths from robots.txt if present
        robots_paths = _extract_robots_paths(base_url)
        all_paths_to_probe = list(dict.fromkeys(ALL_CORE_PATHS + robots_paths))

        # 2. Concurrently probe paths with ThreadPoolExecutor
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=12) as executor:
            future_to_path = {
                executor.submit(_probe_single, base_url, path): path
                for path in all_paths_to_probe
            }
            for future in as_completed(future_to_path):
                try:
                    res = future.result()
                    results.append(res)
                except Exception:
                    path = future_to_path[future]
                    results.append({
                        "path": path,
                        "url": f"{base_url}{path}",
                        "status": None,
                        "classification": "Scan Error",
                        "size": 0,
                        "latency_ms": 0,
                        "content_type": "—",
                        "location": "—",
                        "server": "—",
                        "risk": "Low",
                        "error": "Thread execution error",
                    })

        # 3. Extract JavaScript bundles
        js_bundles = _extract_js_bundles(base_url)

        return _build_discovery_report(base_url, results, js_bundles, robots_paths)
