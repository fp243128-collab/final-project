
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
from typing import Type, List, Optional
import requests


class HttpSecurityHeadersInspectorInput(BaseModel):
    """Input schema for HTTP Security Headers Inspector Tool."""
    url: str = Field(
        ...,
        description="The full URL (including scheme, e.g. https://example.com) to inspect for security headers.",
    )


# Security header definitions: name, severity if missing, and a short recommendation
SECURITY_HEADERS = [
    {
        "header": "Strict-Transport-Security",
        "alias": "HSTS",
        "severity": "Critical",
        "recommendation": "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` to enforce HTTPS.",
    },
    {
        "header": "Content-Security-Policy",
        "alias": "CSP",
        "severity": "High",
        "recommendation": "Define a Content-Security-Policy to mitigate XSS and data injection attacks.",
    },
    {
        "header": "X-Frame-Options",
        "alias": "X-Frame-Options",
        "severity": "High",
        "recommendation": "Add `X-Frame-Options: DENY` or `SAMEORIGIN` to prevent clickjacking.",
    },
    {
        "header": "X-Content-Type-Options",
        "alias": "X-Content-Type-Options",
        "severity": "Medium",
        "recommendation": "Add `X-Content-Type-Options: nosniff` to prevent MIME-type sniffing.",
    },
    {
        "header": "X-XSS-Protection",
        "alias": "X-XSS-Protection",
        "severity": "Medium",
        "recommendation": "Add `X-XSS-Protection: 1; mode=block` to enable browser XSS filters (legacy support).",
    },
    {
        "header": "Referrer-Policy",
        "alias": "Referrer-Policy",
        "severity": "Medium",
        "recommendation": "Add `Referrer-Policy: strict-origin-when-cross-origin` to control referrer information leakage.",
    },
    {
        "header": "Permissions-Policy",
        "alias": "Permissions-Policy",
        "severity": "Low",
        "recommendation": "Add `Permissions-Policy` to restrict browser features like camera, microphone, and geolocation.",
    },
    {
        "header": "Access-Control-Allow-Origin",
        "alias": "CORS",
        "severity": "Info",
        "recommendation": "If CORS is required, restrict `Access-Control-Allow-Origin` to trusted domains instead of `*`.",
    },
    {
        "header": "Server",
        "alias": "Server (Info Disclosure)",
        "severity": "Low",
        "recommendation": "Remove or obscure the `Server` header to avoid exposing server software details.",
    },
    {
        "header": "X-Powered-By",
        "alias": "X-Powered-By (Info Disclosure)",
        "severity": "Low",
        "recommendation": "Remove the `X-Powered-By` header to avoid exposing technology stack information.",
    },
]

# Severity emoji badges for readability
SEVERITY_BADGE = {
    "Critical": "🔴 Critical",
    "High":     "🟠 High",
    "Medium":   "🟡 Medium",
    "Low":      "🔵 Low",
    "Info":     "⚪ Info",
}


class HttpSecurityHeadersInspectorTool(BaseTool):
    """Tool for inspecting and analyzing HTTP security headers of a target URL."""

    name: str = "HTTP Security Headers Inspector"
    description: str = (
        "Inspects the HTTP security headers of a given URL. "
        "Reports presence/absence, values, and severity ratings for key security headers "
        "such as HSTS, CSP, X-Frame-Options, CORS, and more. "
        "Also reports the response status code, redirect chain, and final URL. "
        "Returns a structured Markdown security report."
    )
    args_schema: Type[BaseModel] = HttpSecurityHeadersInspectorInput

    def _run(self, url: str) -> str:
        """
        Perform the HTTP request and analyze security headers.

        Args:
            url: The target URL to inspect.

        Returns:
            A Markdown-formatted security report string.
        """
        # ── 1. Make the HTTP request ──────────────────────────────────────────
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "SecurityHeadersInspector/1.0"},
            )
        except requests.exceptions.MissingSchema:
            return (
                "❌ **Error:** Invalid URL provided. "
                "Please include the scheme (e.g., `https://example.com`)."
            )
        except requests.exceptions.ConnectionError as exc:
            return f"❌ **Connection Error:** Unable to reach `{url}`.\n\nDetails: `{exc}`"
        except requests.exceptions.Timeout:
            return f"❌ **Timeout Error:** The request to `{url}` timed out after 10 seconds."
        except requests.exceptions.TooManyRedirects:
            return f"❌ **Redirect Error:** Too many redirects while accessing `{url}`."
        except requests.exceptions.RequestException as exc:
            return f"❌ **Request Error:** An unexpected error occurred.\n\nDetails: `{exc}`"

        # ── 2. Gather redirect chain ──────────────────────────────────────────
        redirect_chain: List[str] = []
        for hist_resp in response.history:
            redirect_chain.append(
                f"  - `{hist_resp.url}` → **{hist_resp.status_code}**"
            )

        final_url   = response.url
        status_code = response.status_code
        resp_headers = {k.lower(): v for k, v in response.headers.items()}

        # ── 3. Analyse each security header ───────────────────────────────────
        present_rows: List[str] = []
        missing_rows: List[str] = []
        warnings:     List[str] = []

        for hdef in SECURITY_HEADERS:
            raw_name  = hdef["header"]
            alias     = hdef["alias"]
            severity  = hdef["severity"]
            rec       = hdef["recommendation"]
            value     = resp_headers.get(raw_name.lower())

            if raw_name == "Server" and value:
                # Server header present = potential info disclosure
                warnings.append(
                    f"- ⚠️ **Server** header exposes software info: `{value}` — consider removing or obscuring it."
                )
                present_rows.append(
                    f"| `{raw_name}` | ✅ Present | `{value}` | {SEVERITY_BADGE['Low']} (Info Disclosure) |"
                )
            elif raw_name == "X-Powered-By" and value:
                # X-Powered-By present = potential tech stack disclosure
                warnings.append(
                    f"- ⚠️ **X-Powered-By** header exposes tech stack: `{value}` — consider removing it."
                )
                present_rows.append(
                    f"| `{raw_name}` | ✅ Present | `{value}` | {SEVERITY_BADGE['Low']} (Info Disclosure) |"
                )
            elif raw_name == "Access-Control-Allow-Origin" and value:
                cors_note = " ⚠️ Wildcard CORS!" if value.strip() == "*" else ""
                present_rows.append(
                    f"| `{raw_name}` | ✅ Present | `{value}`{cors_note} | {SEVERITY_BADGE['Info']} |"
                )
                if value.strip() == "*":
                    warnings.append(
                        "- ⚠️ **CORS** is set to `*` — this allows any origin to access the resource. "
                        "Restrict it to trusted domains."
                    )
            elif value:
                present_rows.append(
                    f"| `{raw_name}` ({alias}) | ✅ Present | `{value}` | — |"
                )
            else:
                missing_rows.append(
                    f"| `{raw_name}` ({alias}) | ❌ Missing | — | {SEVERITY_BADGE[severity]} |"
                )

        # ── 4. Compute an overall risk level ──────────────────────────────────
        severity_order = ["Critical", "High", "Medium", "Low", "Info"]
        worst = "Info"
        for hdef in SECURITY_HEADERS:
            if not resp_headers.get(hdef["header"].lower()):
                if severity_order.index(hdef["severity"]) < severity_order.index(worst):
                    worst = hdef["severity"]

        overall_badge = SEVERITY_BADGE.get(worst, worst)

        # ── 5. Build the Markdown report ───────────────────────────────────────
        lines: List[str] = []

        lines.append("# 🔐 HTTP Security Headers Inspection Report")
        lines.append("")
        lines.append("## 📋 Request Summary")
        lines.append(f"| Field         | Value |")
        lines.append(f"|---------------|-------|")
        lines.append(f"| **Target URL**  | `{url}` |")
        lines.append(f"| **Final URL**   | `{final_url}` |")
        lines.append(f"| **Status Code** | `{status_code}` |")
        lines.append(f"| **Overall Risk**| {overall_badge} |")
        lines.append("")

        # Redirect chain
        if redirect_chain:
            lines.append("## 🔀 Redirect Chain")
            lines.extend(redirect_chain)
            lines.append("")
        else:
            lines.append("## 🔀 Redirect Chain")
            lines.append("_No redirects detected — direct response._")
            lines.append("")

        # Header table header
        table_header = (
            "| Header | Status | Value | Severity (if missing) |"
        )
        table_sep = (
            "|--------|--------|-------|-----------------------|"
        )

        # Present headers
        lines.append("## ✅ Present Security Headers")
        if present_rows:
            lines.append(table_header)
            lines.append(table_sep)
            lines.extend(present_rows)
        else:
            lines.append("_No security headers found in the response._")
        lines.append("")

        # Missing headers
        lines.append("## ❌ Missing Security Headers")
        if missing_rows:
            lines.append(table_header)
            lines.append(table_sep)
            lines.extend(missing_rows)
        else:
            lines.append("_All inspected security headers are present. Great job!_ 🎉")
        lines.append("")

        # Warnings
        if warnings:
            lines.append("## ⚠️ Warnings & Observations")
            lines.extend(warnings)
            lines.append("")

        # Recommendations for missing headers
        missing_defs = [
            hdef for hdef in SECURITY_HEADERS
            if not resp_headers.get(hdef["header"].lower())
        ]
        if missing_defs:
            lines.append("## 🛠️ Recommendations")
            for hdef in missing_defs:
                lines.append(f"- **{hdef['alias']}**: {hdef['recommendation']}")
            lines.append("")

        lines.append("---")
        lines.append(
            "_Report generated by HTTP Security Headers Inspector — "
            "for educational and audit purposes only._"
        )

        return "\n".join(lines)
