from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional
from urllib.parse import urlparse
import requests

class HttpSecurityHeadersInspectorInput(BaseModel):
    """Input schema for HTTP Security Headers Inspector Tool."""
    url: str = Field(
        ...,
        description="The full URL (e.g. https://example.com) to inspect for security headers and transport posture.",
    )


# Comprehensive list of standard security headers with evaluation criteria
SECURITY_HEADERS_DEF = [
    {
        "header": "Strict-Transport-Security",
        "alias": "HSTS",
        "severity": "High",
        "category": "Transport Security",
        "description": "Enforces HTTPS connections and prevents SSL/TLS downgrade attacks (e.g. SSLStrip).",
        "recommendation": "Deploy `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
    },
    {
        "header": "Content-Security-Policy",
        "alias": "CSP",
        "severity": "High",
        "category": "Injection Defense",
        "description": "Restricts sources from which scripts, styles, and media can be loaded, mitigating XSS and data exfiltration.",
        "recommendation": "Configure a strict Content-Security-Policy without `unsafe-inline` or `unsafe-eval`.",
    },
    {
        "header": "X-Frame-Options",
        "alias": "Clickjacking Protection",
        "severity": "High",
        "category": "UI Redress Defense",
        "description": "Prevents the web page from being rendered inside an iframe on malicious sites (Clickjacking).",
        "recommendation": "Set `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`.",
    },
    {
        "header": "X-Content-Type-Options",
        "alias": "MIME Sniffing Guard",
        "severity": "Medium",
        "category": "Content Integrity",
        "description": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "recommendation": "Add `X-Content-Type-Options: nosniff` across all responses.",
    },
    {
        "header": "Referrer-Policy",
        "alias": "Referrer Privacy",
        "severity": "Medium",
        "category": "Information Privacy",
        "description": "Controls how much referrer information (URL parameters and path) is included with outgoing requests.",
        "recommendation": "Configure `Referrer-Policy: strict-origin-when-cross-origin`.",
    },
    {
        "header": "Permissions-Policy",
        "alias": "Feature Permissions",
        "severity": "Low",
        "category": "Client Sandboxing",
        "description": "Explicitly disables browser hardware APIs such as camera, microphone, USB, and geolocation.",
        "recommendation": "Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`.",
    },
    {
        "header": "Cross-Origin-Opener-Policy",
        "alias": "COOP",
        "severity": "Medium",
        "category": "Cross-Origin Isolation",
        "description": "Isolates the browsing context to prevent cross-origin window tampering and Spectre-type attacks.",
        "recommendation": "Set `Cross-Origin-Opener-Policy: same-origin`.",
    },
    {
        "header": "Cross-Origin-Embedder-Policy",
        "alias": "COEP",
        "severity": "Low",
        "category": "Cross-Origin Isolation",
        "description": "Prevents the document from loading any cross-origin resources that do not explicitly grant permission.",
        "recommendation": "Set `Cross-Origin-Embedder-Policy: require-corp` if cross-origin isolation is required.",
    },
    {
        "header": "Cross-Origin-Resource-Policy",
        "alias": "CORP",
        "severity": "Low",
        "category": "Cross-Origin Isolation",
        "description": "Protects against cross-origin data theft by declaring who can read the resource.",
        "recommendation": "Configure `Cross-Origin-Resource-Policy: same-site` or `same-origin`.",
    },
    {
        "header": "Access-Control-Allow-Origin",
        "alias": "CORS Policy",
        "severity": "Medium",
        "category": "API Security",
        "description": "Defines which origins are authorized to read API responses.",
        "recommendation": "Ensure CORS is restricted to trusted whitelisted domains instead of wildcard `*`.",
    },
]

# Information disclosure headers that should be removed or masked
DISCLOSURE_HEADERS_DEF = [
    {"header": "Server", "label": "Web Server Software Banner"},
    {"header": "X-Powered-By", "label": "Application Framework Fingerprint"},
    {"header": "X-AspNet-Version", "label": "ASP.NET Runtime Version"},
    {"header": "X-AspNetMvc-Version", "label": "ASP.NET MVC Version"},
    {"header": "X-Generator", "label": "CMS / Generator Fingerprint"},
    {"header": "Via", "label": "Intermediate Proxy / Cache Banner"},
]


class HttpSecurityHeadersInspectorTool(BaseTool):
    """Tool for deep inspection and analysis of HTTP security headers and server banners."""

    name: str = "HTTP Security Headers Inspector"
    description: str = (
        "Inspects and evaluates HTTP security headers, CORS policies, transport redirects, "
        "and server information disclosure headers for a target URL. "
        "Returns an executive, structured markdown report with compliance matrices and remediation guidance."
    )
    args_schema: Type[BaseModel] = HttpSecurityHeadersInspectorInput

    def _normalize_url(self, raw_url: str) -> str:
        """Ensure URL has scheme and clean path."""
        url = raw_url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"
        return url

    def _evaluate_csp(self, value: Optional[str]) -> Tuple[str, str, str]:
        """Deep analysis of Content-Security-Policy directives."""
        if not value:
            return "Missing", "High", "No Content-Security-Policy header defined. Vulnerable to XSS and script injections."
        val_lower = value.lower()
        flaws = []
        if "unsafe-inline" in val_lower:
            flaws.append("allows `unsafe-inline` scripts")
        if "unsafe-eval" in val_lower:
            flaws.append("allows `unsafe-eval` execution")
        if "data:" in val_lower and "script-src" in val_lower:
            flaws.append("allows data: URI script execution")
        if "*" in val_lower and ("default-src *" in val_lower or "script-src *" in val_lower):
            flaws.append("wildcard `*` source allowed")

        if flaws:
            return "Warning", "Medium", f"CSP is active but contains permissive directives: {', '.join(flaws)}."
        return "Compliant", "Low", "Strict Content-Security-Policy configured without unsafe directives."

    def _evaluate_hsts(self, value: Optional[str]) -> Tuple[str, str, str]:
        """Deep analysis of HSTS directives."""
        if not value:
            return "Missing", "High", "HSTS header missing. User sessions vulnerable to SSL stripping and plaintext downgrades."
        val_lower = value.lower()
        if "max-age" not in val_lower:
            return "Warning", "Medium", "HSTS is malformed: missing `max-age` directive."
        
        # Extract max-age number
        try:
            import re
            m = re.search(r"max-age=(\d+)", val_lower)
            max_age = int(m.group(1)) if m else 0
            if max_age < 15552000: # < 180 days
                return "Warning", "Medium", f"HSTS max-age ({max_age}s) is below recommended 1-year threshold (31536000s)."
        except Exception:
            pass

        notes = []
        if "includesubdomains" in val_lower:
            notes.append("includeSubDomains enabled")
        if "preload" in val_lower:
            notes.append("preload enabled")
        
        extra = f" ({', '.join(notes)})" if notes else ""
        return "Compliant", "Low", f"Strict HSTS policy enforced{extra}."

    def _build_report(
        self,
        url: str,
        final_url: str,
        status_code: int,
        redirect_chain: List[str],
        resp_headers: Dict[str, str],
    ) -> str:
        lines: List[str] = []

        # ── Section 1: Target Overview & Transport ──
        lines.append("## HTTP Transport & Security Headers Matrix")
        lines.append("")
        lines.append("| Parameter | Configured Value | Status | Operational Context |")
        lines.append("|---|---|---|---|")
        lines.append(f"| Target URL | `{url}` | Active | Initial audit probe destination |")
        lines.append(f"| Final Resolved URL | `{final_url}` | Active | Endpoint reached after redirects |")
        lines.append(f"| HTTP Status Code | `{status_code}` | {'Passed' if status_code < 400 else 'Warning'} | Response code returned by origin server |")
        
        if redirect_chain:
            chain_str = " -> ".join(redirect_chain)
            lines.append(f"| Redirect Chain | `{chain_str}` | Active | Automated HTTPS/Host redirect sequence |")
        else:
            lines.append(f"| Redirect Chain | `Direct Connection (0 hops)` | Normal | Direct single-hop response |")

        lines.append("")

        # ── Section 2: Security Headers Matrix ──
        lines.append("## Security Headers Defense Matrix")
        lines.append("")
        lines.append("| Security Header | Policy / Value | Category | Severity | Status | Risk Assessment & Remediation |")
        lines.append("|---|---|---|---|---|---|")

        missing_count = 0
        warning_count = 0

        for hdef in SECURITY_HEADERS_DEF:
            hdr_name = hdef["header"]
            raw_val = resp_headers.get(hdr_name.lower())

            if hdr_name == "Content-Security-Policy":
                status, sev, assessment = self._evaluate_csp(raw_val)
            elif hdr_name == "Strict-Transport-Security":
                status, sev, assessment = self._evaluate_hsts(raw_val)
            elif hdr_name == "Access-Control-Allow-Origin":
                if raw_val:
                    if raw_val.strip() == "*":
                        status, sev, assessment = "Warning", "Medium", "Wildcard CORS `*` enables any origin to read API responses."
                    else:
                        status, sev, assessment = "Compliant", "Low", f"CORS constrained to trusted domain: `{raw_val}`."
                else:
                    status, sev, assessment = "Normal", "Low", "No cross-origin resource sharing header configured."
            else:
                if raw_val:
                    status = "Compliant"
                    sev = "Low"
                    val_preview = raw_val[:55] + "..." if len(raw_val) > 55 else raw_val
                    assessment = f"Header enforced with value: `{val_preview}`."
                else:
                    status = "Missing"
                    sev = hdef["severity"]
                    assessment = f"{hdef['description']} {hdef['recommendation']}"

            if status == "Missing":
                missing_count += 1
            elif status == "Warning":
                warning_count += 1

            disp_val = (raw_val[:48] + "..." if len(raw_val) > 48 else raw_val) if raw_val else "Not Configured"
            lines.append(f"| `{hdr_name}` | `{disp_val}` | {hdef['category']} | {sev} | {status} | {assessment} |")

        lines.append("")

        # ── Section 3: Information Disclosure & Server Fingerprints ──
        lines.append("## Server Banners & Technology Fingerprints")
        lines.append("")
        lines.append("| Fingerprint Header | Disclosed Value | Severity | Status | Exposure Impact |")
        lines.append("|---|---|---|---|---|")

        found_disclosure = False
        for ddef in DISCLOSURE_HEADERS_DEF:
            hdr_name = ddef["header"]
            val = resp_headers.get(hdr_name.lower())
            if val:
                found_disclosure = True
                lines.append(f"| `{hdr_name}` ({ddef['label']}) | `{val}` | Medium | Warning | Server leaks software/framework details. Enables targeted exploit scanning. |")

        if not found_disclosure:
            lines.append("| Server Software Banners | None Disclosed | Low | Clean | Origin server properly suppresses Server, X-Powered-By, and runtime headers. |")

        lines.append("")

        # ── Section 4: Hardening Action Plan ──
        lines.append("## Header Hardening & Action Items")
        lines.append("")
        lines.append("| Priority | Defense Category | Recommended Security Directive | Implementation Target |")
        lines.append("|---|---|---|---|")

        action_idx = 0
        if not resp_headers.get("strict-transport-security"):
            action_idx += 1
            lines.append(f"| Priority {action_idx} | Transport Hardening | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` | Reverse Proxy / CDN / Edge Router |")

        if not resp_headers.get("content-security-policy"):
            action_idx += 1
            lines.append(f"| Priority {action_idx} | XSS & Injection Mitigation | Configure strict `Content-Security-Policy: default-src 'self'; script-src 'self'` | Web Application Middleware |")

        if not resp_headers.get("x-frame-options"):
            action_idx += 1
            lines.append(f"| Priority {action_idx} | Clickjacking Prevention | Add `X-Frame-Options: DENY` or `SAMEORIGIN` | Global HTTP Response Filter |")

        if not resp_headers.get("x-content-type-options"):
            action_idx += 1
            lines.append(f"| Priority {action_idx} | MIME Type Sniffing Guard | Add `X-Content-Type-Options: nosniff` | Web Server Configuration |")

        if not resp_headers.get("permissions-policy"):
            action_idx += 1
            lines.append(f"| Priority {action_idx} | Client API Sandbox | Configure `Permissions-Policy: camera=(), microphone=(), geolocation=()` | HTTP Header Layer |")

        if found_disclosure:
            action_idx += 1
            lines.append(f"| Priority {action_idx} | Information Leakage Defense | Strip `Server` and `X-Powered-By` headers in proxy configuration | Nginx / Apache / Cloudflare Rules |")

        if action_idx == 0:
            lines.append("| Standard | Defense-in-Depth | All essential HTTP security headers are correctly deployed. Maintain regular configuration audits. | Production Environment |")

        lines.append("")
        return "\n".join(lines)

    def _run(self, url: str) -> str:
        """Execute deep HTTP security headers inspection on target URL."""
        target_url = self._normalize_url(url)

        try:
            resp = requests.get(
                target_url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "CyberShield-SecurityHeaders/2.0"},
            )
        except requests.exceptions.SSLError as exc:
            return f"## HTTP Transport Security Assessment\n\n| Parameter | Value | Status | Context |\n|---|---|---|---|\n| SSL Connection | Failed | Error | Target failed TLS handshake: {str(exc)} |\n"
        except requests.exceptions.RequestException as exc:
            return f"## HTTP Transport Security Assessment\n\n| Parameter | Value | Status | Context |\n|---|---|---|---|\n| HTTP Connection | Failed | Error | Could not connect to target URL: {str(exc)} |\n"

        redirect_chain = [f"{r.status_code} ({r.url})" for r in resp.history]
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        return self._build_report(
            url=target_url,
            final_url=resp.url,
            status_code=resp.status_code,
            redirect_chain=redirect_chain,
            resp_headers=resp_headers,
        )
