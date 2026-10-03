from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, Dict, Any, List, Optional
import requests
import json
import base64
import re
from datetime import datetime, timezone

# ─── Sensitive cookie name patterns ───────────────────────────────────────────
SENSITIVE_PATTERNS = re.compile(
    r"(sess|session|token|auth|jwt|access|refresh|secret|key|pass|credential|bearer|sid|uid|user|csrf|xsrf|connect\.sid|phpsessid|jsessionid)",
    re.IGNORECASE,
)

# ─── JWT detection: three base64url segments separated by dots ────────────────
JWT_PATTERN = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")


class CookieSecurityAnalyzerInput(BaseModel):
    """Input schema for the Cookie Security Analyzer Tool."""
    url: str = Field(
        ...,
        description="The full URL (e.g. https://example.com) to analyze for cookie flags, session security, and JWT tokens.",
    )


class CookieSecurityAnalyzerTool(BaseTool):
    """Tool for analyzing HTTP cookies, session tokens, JWTs, and storage flags."""

    name: str = "Cookie Security Analyzer"
    description: str = (
        "Inspects cookies returned across the HTTP request and redirect chain for security flags: "
        "HttpOnly, Secure, SameSite, domain scope, and persistence. "
        "Detects and decodes JWT tokens and unmasks cryptographic risks. "
        "Returns a structured executive security report."
    )
    args_schema: Type[BaseModel] = CookieSecurityAnalyzerInput

    def _mask_value(self, name: str, value: str) -> str:
        """Mask sensitive session/auth token values."""
        if SENSITIVE_PATTERNS.search(name) or len(value) > 24:
            visible = value[:4] if len(value) >= 4 else value
            return f"{visible}*** (masked)"
        return value

    def _decode_jwt(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode JWT header and payload without verifying signature."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            def _b64_decode(segment: str) -> dict:
                padding = 4 - len(segment) % 4
                segment += "=" * (padding % 4)
                decoded = base64.urlsafe_b64decode(segment)
                return json.loads(decoded)

            header = _b64_decode(parts[0])
            payload = _b64_decode(parts[1])
            return {"header": header, "payload": payload}
        except Exception:
            return None

    def _analyze_cookie(self, name: str, cookie: Any) -> Dict[str, Any]:
        """Analyze individual cookie attributes and risk score."""
        value = cookie.value or ""
        is_sensitive = bool(SENSITIVE_PATTERNS.search(name))
        is_jwt = bool(JWT_PATTERN.match(value))

        secure = bool(cookie.secure)
        http_only = False
        same_site = None
        domain = cookie.domain or "Origin Host"
        path = cookie.path or "/"
        expires_str = "Session (Browser close)"

        try:
            http_only = cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")
        except Exception:
            http_only = False

        try:
            same_site = cookie.get_nonstandard_attr("SameSite") or cookie.get_nonstandard_attr("samesite")
        except Exception:
            same_site = None

        try:
            if cookie.expires:
                dt = datetime.fromtimestamp(cookie.expires, timezone.utc)
                expires_str = dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            pass

        # Calculate severity and status
        flaws = []
        if not secure:
            flaws.append("Missing `Secure` flag (plaintext transmission risk)")
        if not http_only:
            flaws.append("Missing `HttpOnly` flag (vulnerable to XSS theft)")
        if not same_site:
            flaws.append("Missing `SameSite` attribute (CSRF exposure)")
        elif str(same_site).lower() == "none" and not secure:
            flaws.append("`SameSite=None` without `Secure` is rejected by modern browsers")

        if not secure and not http_only and is_sensitive:
            severity = "Critical"
            status = "Failed"
        elif not secure or (not http_only and is_sensitive):
            severity = "High"
            status = "Warning"
        elif not same_site or not http_only:
            severity = "Medium"
            status = "Warning"
        else:
            severity = "Low"
            status = "Compliant"

        jwt_details = self._decode_jwt(value) if is_jwt else None

        return {
            "name": name,
            "masked_value": self._mask_value(name, value),
            "secure": secure,
            "http_only": http_only,
            "same_site": same_site or "None",
            "domain": domain,
            "path": path,
            "expires": expires_str,
            "is_sensitive": is_sensitive,
            "is_jwt": is_jwt,
            "jwt_details": jwt_details,
            "severity": severity,
            "status": status,
            "flaws": flaws,
        }

    def _build_report(self, url: str, cookies: List[Dict[str, Any]]) -> str:
        lines: List[str] = []

        # ── Section 1: Cookie Governance Matrix ──
        lines.append("## Cookie Governance & Security Matrix")
        lines.append("")

        if not cookies:
            lines.append("| Security Check | Assessment Result | Status | Operational Context |")
            lines.append("|---|---|---|---|")
            lines.append(f"| Session & Cookie Storage | `Stateless / Zero Cookies` | Compliant | Target returned no `Set-Cookie` response headers across redirect chain. No client-side session state stored in browser cookies. |")
            lines.append("")
            return "\n".join(lines)

        lines.append("| Cookie Identifier | Domain / Scope | Flags (Sec / Http / SameSite) | Lifetime | Severity | Status | Security Assessment & Finding |")
        lines.append("|---|---|---|---|---|---|---|")

        jwt_cookies = []

        for c in cookies:
            sec_flag = "Secure" if c["secure"] else "No-Secure"
            http_flag = "HttpOnly" if c["http_only"] else "No-HttpOnly"
            ss_flag = f"SameSite={c['same_site']}"
            flags_summary = f"`{sec_flag}` | `{http_flag}` | `{ss_flag}`"

            flaw_desc = "; ".join(c["flaws"]) if c["flaws"] else "All standard cookie protection flags properly configured."
            lines.append(f"| `{c['name']}` | `{c['domain']}` | {flags_summary} | `{c['expires']}` | {c['severity']} | {c['status']} | {flaw_desc} |")

            if c["is_jwt"] and c["jwt_details"]:
                jwt_cookies.append(c)

        lines.append("")

        # ── Section 2: JWT Tokens & Cryptography ──
        if jwt_cookies:
            lines.append("## JWT Token Cryptographic Posture")
            lines.append("")
            lines.append("| Cookie Name | Signing Algorithm | Token Type | Key Claims | Security Evaluation |")
            lines.append("|---|---|---|---|---|")

            for c in jwt_cookies:
                jwt = c["jwt_details"]
                alg = jwt["header"].get("alg", "Unknown")
                typ = jwt["header"].get("typ", "JWT")
                claims = list(jwt["payload"].keys())[:4]
                claims_str = ", ".join(claims) if claims else "None"

                if alg.lower() == "none":
                    eval_msg = "CRITICAL: Algorithm is set to `none`. Signature verification is completely disabled."
                    sev = "Critical"
                elif alg.upper().startswith("HS"):
                    eval_msg = f"Symmetric HMAC ({alg}) detected. Vulnerable if shared secret is weak or brute-forceable."
                    sev = "Medium"
                else:
                    eval_msg = f"Asymmetric signature ({alg}) detected. Recommended enterprise signing."
                    sev = "Low"

                lines.append(f"| `{c['name']}` | `{alg}` | `{typ}` | `{claims_str}` | {eval_msg} |")
            lines.append("")

        # ── Section 3: Cookie Action Items ──
        lines.append("## Cookie Hardening Action Plan")
        lines.append("")
        lines.append("| Priority | Impacted Cookie | Missing Control | Recommended Configuration |")
        lines.append("|---|---|---|---|")

        action_count = 0
        for c in cookies:
            if c["status"] != "Compliant":
                action_count += 1
                recs = []
                if not c["secure"]:
                    recs.append("Add `Secure` flag")
                if not c["http_only"]:
                    recs.append("Add `HttpOnly` flag")
                if c["same_site"] == "None":
                    recs.append("Add `SameSite=Lax` or `SameSite=Strict`")
                rec_str = " + ".join(recs)
                lines.append(f"| Priority {action_count} | `{c['name']}` | {', '.join(c['flaws'])} | Set `{c['name']}=...; {rec_str}` in application cookie policy |")

        if action_count == 0:
            lines.append("| Standard | All Cookies | Full Compliance | All active cookies adhere to OWASP defense-in-depth storage guidelines. |")

        lines.append("")
        return "\n".join(lines)

    def _run(self, url: str) -> str:
        """Execute cookie security analysis."""
        target_url = url.strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        try:
            resp = requests.get(
                target_url,
                timeout=10,
                allow_redirects=True,
                headers={"User-Agent": "CyberShield-CookieAnalyzer/2.0"},
            )
        except requests.exceptions.RequestException as exc:
            return f"## Cookie Security Analysis\n\n| Parameter | Value | Status | Operational Context |\n|---|---|---|---|\n| Cookie Audit | Incomplete | Error | Request to target URL failed: {str(exc)} |\n"

        all_cookies: Dict[str, Any] = {}
        for hist_resp in resp.history:
            for cookie in hist_resp.cookies:
                all_cookies[cookie.name] = cookie

        for cookie in resp.cookies:
            all_cookies[cookie.name] = cookie

        cookies_analysis = [
            self._analyze_cookie(name, cookie)
            for name, cookie in all_cookies.items()
        ]

        return self._build_report(target_url, cookies_analysis)
