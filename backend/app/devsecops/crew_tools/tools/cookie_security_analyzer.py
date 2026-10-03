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
from typing import Type, Dict, Any, List, Optional
import requests
import json
import base64
import re
from datetime import datetime


# ─── Sensitive cookie name patterns ───────────────────────────────────────────
SENSITIVE_PATTERNS = re.compile(
    r"(sess|session|token|auth|jwt|access|refresh|secret|key|pass|credential|bearer|sid|uid|user)",
    re.IGNORECASE,
)

# ─── JWT detection: three base64url segments separated by dots ────────────────
JWT_PATTERN = re.compile(r"^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$")


# ─── Input Schema ─────────────────────────────────────────────────────────────
class CookieSecurityAnalyzerInput(BaseModel):
    """Input schema for the Cookie Security Analyzer Tool."""

    url: str = Field(
        ...,
        description="The full URL (including scheme, e.g. https://example.com) to analyze for cookie security.",
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _mask_value(name: str, value: str) -> str:
    """Mask the cookie value if it looks sensitive."""
    if SENSITIVE_PATTERNS.search(name) or len(value) > 30:
        visible = value[:4] if len(value) >= 4 else value
        return f"{visible}{'*' * min(len(value) - 4, 20)}  *(masked)*"
    return value


def _decode_jwt(token: str) -> Optional[Dict[str, Any]]:
    """
    Decode a JWT token's header and payload without signature verification.
    Returns a dict with 'header' and 'payload', or None on failure.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        def _b64_decode(segment: str) -> dict:
            # Add padding
            padding = 4 - len(segment) % 4
            segment += "=" * (padding % 4)
            decoded = base64.urlsafe_b64decode(segment)
            return json.loads(decoded)

        header = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        return {"header": header, "payload": payload}
    except Exception:
        return None


def _compute_risk(cookie_info: Dict[str, Any]) -> str:
    """
    Compute a risk level: Critical / High / Medium / Low.
    Logic:
      - Missing Secure + Missing HttpOnly + sensitive name → Critical
      - Missing Secure OR (Missing HttpOnly AND sensitive) → High
      - Missing SameSite → Medium at minimum
      - All flags present → Low
    """
    score = 0

    if not cookie_info["secure"]:
        score += 3
    if not cookie_info["http_only"]:
        score += 2
    if not cookie_info["same_site"]:
        score += 1
    if cookie_info["is_sensitive"]:
        score += 2
    if cookie_info["is_jwt"]:
        score += 1  # JWT in cookie without flags is extra risky

    if score >= 7:
        return "🔴 Critical"
    elif score >= 5:
        return "🟠 High"
    elif score >= 2:
        return "🟡 Medium"
    else:
        return "🟢 Low"


def _analyze_cookie(name: str, cookie: requests.cookies.RequestsCookieJar) -> Dict[str, Any]:
    """Extract and analyze a single cookie."""
    value = cookie.value or ""
    is_sensitive = bool(SENSITIVE_PATTERNS.search(name))
    is_jwt = bool(JWT_PATTERN.match(value))

    # requests stores these in the underlying cookiejar
    secure = bool(cookie.secure)

    # Access underlying http.cookiejar.Cookie attributes
    _c = cookie
    http_only = False
    same_site = None
    domain = cookie.domain or "N/A"
    path = cookie.path or "/"
    expires = None
    max_age = None

    # Try to get extended attributes from the underlying morsel/cookie
    try:
        http_only = _c.has_nonstandard_attr("HttpOnly") or _c.has_nonstandard_attr("httponly")
    except Exception:
        http_only = False

    try:
        same_site = (
            _c.get_nonstandard_attr("SameSite")
            or _c.get_nonstandard_attr("samesite")
        )
    except Exception:
        same_site = None

    try:
        if _c.expires:
            expires = datetime.utcfromtimestamp(_c.expires).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        expires = None

    jwt_details = _decode_jwt(value) if is_jwt else None

    return {
        "name": name,
        "value": value,
        "masked_value": _mask_value(name, value),
        "secure": secure,
        "http_only": http_only,
        "same_site": same_site,
        "domain": domain,
        "path": path,
        "expires": expires,
        "max_age": max_age,
        "is_sensitive": is_sensitive,
        "is_jwt": is_jwt,
        "jwt_details": jwt_details,
    }


def _build_report(url: str, cookies_analysis: List[Dict[str, Any]], response_url: str, status_code: int) -> str:
    """Build the final markdown report."""
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    total = len(cookies_analysis)

    risk_counts = {"🔴 Critical": 0, "🟠 High": 0, "🟡 Medium": 0, "🟢 Low": 0}

    lines: List[str] = []
    lines.append("# 🍪 Cookie Security Analysis Report")
    lines.append(f"\n**Target URL:** `{url}`")
    lines.append(f"**Final URL (after redirects):** `{response_url}`")
    lines.append(f"**HTTP Status:** `{status_code}`")
    lines.append(f"**Analysis Date:** {now}")
    lines.append(f"**Total Cookies Found:** `{total}`")

    if total == 0:
        lines.append("\n> ⚠️ No cookies were returned in the HTTP response.")
        return "\n".join(lines)

    lines.append("\n---\n")
    lines.append("## 📋 Individual Cookie Analysis\n")

    for idx, info in enumerate(cookies_analysis, start=1):
        risk = _compute_risk(info)
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

        lines.append(f"### {idx}. `{info['name']}` — {risk}\n")
        lines.append(f"| Property | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| **Name** | `{info['name']}` |")
        lines.append(f"| **Value** | `{info['masked_value']}` |")
        lines.append(f"| **Domain** | `{info['domain']}` |")
        lines.append(f"| **Path** | `{info['path']}` |")

        # HttpOnly
        if info["http_only"]:
            lines.append(f"| **HttpOnly** | ✅ Present |")
        else:
            lines.append(f"| **HttpOnly** | ❌ MISSING — *Risk: XSS cookie theft* |")

        # Secure
        if info["secure"]:
            lines.append(f"| **Secure** | ✅ Present |")
        else:
            lines.append(f"| **Secure** | ❌ MISSING — *Risk: transmitted over HTTP* |")

        # SameSite
        if info["same_site"]:
            lines.append(f"| **SameSite** | ✅ `{info['same_site']}` |")
        else:
            lines.append(f"| **SameSite** | ❌ MISSING — *Risk: CSRF attacks* |")

        # Expiry
        if info["expires"]:
            lines.append(f"| **Expires** | 📅 Persistent — `{info['expires']}` |")
        else:
            lines.append(f"| **Expires** | 🔄 Session cookie (cleared on browser close) |")

        # Sensitive
        lines.append(f"| **Sensitive Name Pattern** | {'⚠️ Yes' if info['is_sensitive'] else 'No'} |")

        # JWT
        lines.append(f"| **JWT Detected** | {'🔑 Yes' if info['is_jwt'] else 'No'} |")

        lines.append("")

        # JWT details block
        if info["is_jwt"] and info["jwt_details"]:
            jwt = info["jwt_details"]
            lines.append("#### 🔑 JWT Token Details (decoded without verification)\n")
            alg = jwt["header"].get("alg", "N/A")
            typ = jwt["header"].get("typ", "N/A")
            lines.append(f"- **Algorithm:** `{alg}`")
            lines.append(f"- **Type:** `{typ}`")
            lines.append(f"\n**Header:**\n```json\n{json.dumps(jwt['header'], indent=2)}\n```")
            lines.append(f"**Payload Claims:**\n```json\n{json.dumps(jwt['payload'], indent=2)}\n```")
            if alg.upper() == "NONE":
                lines.append("> 🚨 **CRITICAL:** Algorithm is `none` — token has NO signature verification!")
            elif alg.upper().startswith("HS"):
                lines.append("> ⚠️ **Warning:** HMAC symmetric algorithm detected. Key management is critical.")
            lines.append("")

        # Recommendations per cookie
        recs = []
        if not info["http_only"]:
            recs.append("- Add `HttpOnly` flag to prevent JavaScript access.")
        if not info["secure"]:
            recs.append("- Add `Secure` flag to enforce HTTPS-only transmission.")
        if not info["same_site"]:
            recs.append("- Set `SameSite=Strict` or `SameSite=Lax` to mitigate CSRF.")
        if recs:
            lines.append("**Recommendations:**")
            lines.extend(recs)
            lines.append("")

    # ── Summary ──────────────────────────────────────────────────────────────
    lines.append("---\n")
    lines.append("## 📊 Overall Security Posture\n")
    lines.append("| Risk Level | Count |")
    lines.append("|---|---|")
    for level, count in risk_counts.items():
        lines.append(f"| {level} | {count} |")

    # Flags summary
    missing_secure = sum(1 for i in cookies_analysis if not i["secure"])
    missing_http_only = sum(1 for i in cookies_analysis if not i["http_only"])
    missing_same_site = sum(1 for i in cookies_analysis if not i["same_site"])
    jwt_count = sum(1 for i in cookies_analysis if i["is_jwt"])
    sensitive_count = sum(1 for i in cookies_analysis if i["is_sensitive"])

    lines.append(f"\n| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Cookies missing `Secure` flag | {missing_secure}/{total} |")
    lines.append(f"| Cookies missing `HttpOnly` flag | {missing_http_only}/{total} |")
    lines.append(f"| Cookies missing `SameSite` attribute | {missing_same_site}/{total} |")
    lines.append(f"| Sensitive session/auth cookies | {sensitive_count}/{total} |")
    lines.append(f"| JWT tokens detected | {jwt_count}/{total} |")

    # Overall verdict
    lines.append("\n### 🏁 Verdict\n")
    if risk_counts.get("🔴 Critical", 0) > 0:
        lines.append("> 🔴 **CRITICAL** — One or more cookies have critical security misconfigurations. Immediate remediation required.")
    elif risk_counts.get("🟠 High", 0) > 0:
        lines.append("> 🟠 **HIGH RISK** — Significant cookie security issues detected. Prompt action recommended.")
    elif risk_counts.get("🟡 Medium", 0) > 0:
        lines.append("> 🟡 **MEDIUM RISK** — Some cookie security improvements needed.")
    else:
        lines.append("> 🟢 **LOW RISK** — Cookie security posture looks good. Continue monitoring.")

    lines.append("\n---")
    lines.append("*Report generated by Cookie Security Analyzer — for authorized security testing only.*")

    return "\n".join(lines)


# ─── Tool Class ───────────────────────────────────────────────────────────────

class CookieSecurityAnalyzerTool(BaseTool):
    """Tool for analyzing HTTP cookies for security misconfigurations."""

    name: str = "Cookie Security Analyzer"
    description: str = (
        "Analyzes all cookies returned by a URL for security issues including missing HttpOnly, "
        "Secure, and SameSite flags. Detects JWT tokens, session/auth patterns, computes per-cookie "
        "risk scores (Critical/High/Medium/Low), and returns a structured markdown security report."
    )
    args_schema: Type[BaseModel] = CookieSecurityAnalyzerInput

    def _run(self, url: str) -> str:
        """Fetch the URL, extract cookies, and return a security analysis report."""
        # ── Fetch the URL ─────────────────────────────────────────────────────
        try:
            response = requests.get(
                url,
                allow_redirects=True,
                timeout=10,
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (compatible; CookieSecurityAnalyzer/1.0)"
                    )
                },
            )
        except requests.exceptions.SSLError as e:
            return f"## ❌ SSL Error\n\nCould not establish a secure connection to `{url}`.\n\n**Details:** `{e}`"
        except requests.exceptions.ConnectionError as e:
            return f"## ❌ Connection Error\n\nFailed to connect to `{url}`.\n\n**Details:** `{e}`"
        except requests.exceptions.Timeout:
            return f"## ❌ Timeout\n\nThe request to `{url}` timed out after 10 seconds."
        except requests.exceptions.InvalidURL:
            return f"## ❌ Invalid URL\n\n`{url}` is not a valid URL. Please include the scheme (e.g., `https://`)."
        except requests.exceptions.RequestException as e:
            return f"## ❌ Request Failed\n\n**Details:** `{e}`"

        # ── Collect cookies from the entire redirect chain + final response ───
        all_cookies: Dict[str, Any] = {}

        # Cookies from redirect history
        for hist_resp in response.history:
            for cookie in hist_resp.cookies:
                all_cookies[cookie.name] = cookie

        # Cookies from final response (overwrite/merge)
        for cookie in response.cookies:
            all_cookies[cookie.name] = cookie

        # ── Analyze each cookie ───────────────────────────────────────────────
        cookies_analysis = [
            _analyze_cookie(name, cookie)
            for name, cookie in all_cookies.items()
        ]

        # ── Build and return the report ───────────────────────────────────────
        return _build_report(
            url=url,
            cookies_analysis=cookies_analysis,
            response_url=response.url,
            status_code=response.status_code,
        )
