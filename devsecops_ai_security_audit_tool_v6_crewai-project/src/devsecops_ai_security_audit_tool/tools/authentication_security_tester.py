
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional, Tuple
import requests
import time
import re
import json


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------

class AuthSecTesterInput(BaseModel):
    """Input schema for Authentication Security Tester Tool."""
    url: str = Field(
        ...,
        description="The full URL of the login page to test (e.g. https://example.com/login).",
    )


# ---------------------------------------------------------------------------
# Helper data
# ---------------------------------------------------------------------------

DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("test", "test"),
    ("root", "root"),
    ("administrator", "administrator"),
]

WEAK_PASSWORDS: List[str] = ["123456", "password"]

SUCCESS_KEYWORDS = ["dashboard", "welcome", "logout", "sign out", "my account", "profile"]
FAILURE_KEYWORDS = ["invalid", "incorrect", "failed", "error", "wrong", "unauthorized"]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "High",
    "X-Frame-Options": "Medium",
    "X-Content-Type-Options": "Medium",
    "Content-Security-Policy": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}

TIMEOUT = 10


# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class AuthenticationSecurityTesterTool(BaseTool):
    """Tool for performing authentication security checks on a login page URL."""

    name: str = "Authentication Security Tester"
    description: str = (
        "Analyzes a login page for authentication security vulnerabilities including "
        "form security, default credentials, account enumeration, rate limiting, "
        "security headers, and password policy. Returns a structured markdown report "
        "with severity ratings."
    )
    args_schema: Type[BaseModel] = AuthSecTesterInput

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def _run(self, url: str) -> str:  # noqa: C901
        findings: List[Dict[str, Any]] = []

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityAudit/1.0) AuthSecTester",
        })

        # Fetch the login page once and reuse
        login_html, login_response = self._fetch_page(session, url)

        # ── A. Login Form Analysis ──────────────────────────────────────
        findings += self._check_login_form(url, login_html, login_response, session)

        # ── B. Default Credential Check ─────────────────────────────────
        findings += self._check_default_credentials(session, url)

        # ── C. Password Policy Indicators ───────────────────────────────
        findings += self._check_password_policy(session, url, login_html)

        # ── D. Security Headers ──────────────────────────────────────────
        findings += self._check_security_headers(login_response)

        # ── E. Account Enumeration ───────────────────────────────────────
        findings += self._check_account_enumeration(session, url)

        # ── F. Rate Limiting ─────────────────────────────────────────────
        findings += self._check_rate_limiting(session, url)

        return self._render_report(url, findings)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_page(
        self, session: requests.Session, url: str
    ) -> Tuple[str, Optional[requests.Response]]:
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
            return resp.text, resp
        except Exception as exc:
            return "", None

    # ── A ──────────────────────────────────────────────────────────────

    def _check_login_form(
        self,
        url: str,
        html: str,
        response: Optional[requests.Response],
        session: requests.Session,
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lower = html.lower()

        # HTTPS check
        if not url.startswith("https://"):
            findings.append({
                "category": "Login Form",
                "title": "Login page served over HTTP (not HTTPS)",
                "detail": "Credentials are transmitted in plaintext, exposing them to interception.",
                "severity": "Critical",
            })
        else:
            findings.append({
                "category": "Login Form",
                "title": "Login page served over HTTPS",
                "detail": "Transport encryption is in place.",
                "severity": "Pass",
            })

        # Detect form fields
        has_password = bool(re.search(r'type=["\']password["\']', html, re.IGNORECASE))
        has_username = bool(
            re.search(r'(type=["\']email["\']|name=["\']user|name=["\']email|name=["\']login)', html, re.IGNORECASE)
        )
        if not has_password:
            findings.append({
                "category": "Login Form",
                "title": "No password field detected on login page",
                "detail": "Could not locate a password input field. The form may be dynamically rendered.",
                "severity": "Medium",
            })
        if not has_username:
            findings.append({
                "category": "Login Form",
                "title": "No username/email field clearly identified",
                "detail": "Heuristic detection did not find a standard username or email field.",
                "severity": "Low",
            })

        # CSRF token
        has_csrf = bool(
            re.search(
                r'(csrf|_token|authenticity_token|__requestverificationtoken)',
                html,
                re.IGNORECASE,
            )
        )
        if not has_csrf:
            findings.append({
                "category": "Login Form",
                "title": "No CSRF token detected in login form",
                "detail": "Missing CSRF protection may allow cross-site request forgery attacks against the login endpoint.",
                "severity": "High",
            })
        else:
            findings.append({
                "category": "Login Form",
                "title": "CSRF token present in login form",
                "detail": "A CSRF protection token was detected.",
                "severity": "Pass",
            })

        # autocomplete="off" on password
        pw_autocomplete_off = bool(
            re.search(r'type=["\']password["\'][^>]*autocomplete=["\']off["\']', html, re.IGNORECASE)
            or re.search(r'autocomplete=["\']off["\'][^>]*type=["\']password["\']', html, re.IGNORECASE)
            or re.search(r'autocomplete=["\']new-password["\']', html, re.IGNORECASE)
            or re.search(r'autocomplete=["\']current-password["\']', html, re.IGNORECASE)
        )
        if not pw_autocomplete_off:
            findings.append({
                "category": "Login Form",
                "title": "Password field does not have autocomplete disabled",
                "detail": (
                    "Browsers may cache the password locally. Consider adding "
                    "autocomplete=\"off\" or autocomplete=\"current-password\" to the password field."
                ),
                "severity": "Low",
            })
        else:
            findings.append({
                "category": "Login Form",
                "title": "Password field has autocomplete attribute set",
                "detail": "Autocomplete is configured on the password field.",
                "severity": "Pass",
            })

        # Account lockout — 5 rapid invalid attempts
        locked_out = False
        lockout_codes = {401, 403, 423, 429}
        lockout_keywords = ["locked", "blocked", "too many", "suspended", "captcha", "disabled"]
        for _ in range(5):
            try:
                r = session.post(
                    url,
                    data={"username": "test@test.com", "password": "wrongpassword_xyz987"},
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
                body_lower = r.text.lower()
                if r.status_code in lockout_codes or any(kw in body_lower for kw in lockout_keywords):
                    locked_out = True
                    break
            except Exception:
                break

        if locked_out:
            findings.append({
                "category": "Login Form",
                "title": "Account lockout / rate limiting detected after repeated failures",
                "detail": "The server responded with a lockout or rate-limit signal after rapid failed attempts. This is a positive security indicator.",
                "severity": "Pass",
            })
        else:
            findings.append({
                "category": "Login Form",
                "title": "No account lockout detected after 5 rapid invalid login attempts",
                "detail": "The application did not appear to lock out or throttle the account after 5 consecutive failed login attempts, potentially allowing brute-force attacks.",
                "severity": "High",
            })

        return findings

    # ── B ──────────────────────────────────────────────────────────────

    def _check_default_credentials(
        self, session: requests.Session, url: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        working_creds: List[str] = []

        for username, password in DEFAULT_CREDENTIALS:
            try:
                r = session.post(
                    url,
                    data={"username": username, "password": password},
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )
                body_lower = r.text.lower()
                is_redirect_success = r.history and r.history[-1].status_code == 302
                has_success = any(kw in body_lower for kw in SUCCESS_KEYWORDS)
                has_failure = any(kw in body_lower for kw in FAILURE_KEYWORDS)

                if (is_redirect_success or has_success) and not has_failure:
                    working_creds.append(f"{username}/{password}")
            except Exception:
                continue

        if working_creds:
            findings.append({
                "category": "Default Credentials",
                "title": "Default credentials appear to work",
                "detail": (
                    f"The following credential pairs produced a success-like response: "
                    f"{', '.join(working_creds)}. Immediately change or disable these accounts."
                ),
                "severity": "Critical",
            })
        else:
            findings.append({
                "category": "Default Credentials",
                "title": "No default credentials accepted",
                "detail": "Tested 6 common default credential pairs — none produced a success response.",
                "severity": "Pass",
            })

        return findings

    # ── C ──────────────────────────────────────────────────────────────

    def _check_password_policy(
        self, session: requests.Session, url: str, login_html: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        lower = login_html.lower()

        # Look for signup/registration links
        signup_urls: List[str] = re.findall(
            r'href=["\']([^"\']*(?:register|signup|sign[-_]?up|create[-_]?account)[^"\']*)["\']',
            login_html,
            re.IGNORECASE,
        )

        base = url.rstrip("/")
        policy_keywords = ["must contain", "at least", "minimum", "uppercase", "lowercase",
                           "special character", "length", "requirements"]

        found_policy = False
        if signup_urls:
            signup_url = signup_urls[0]
            if not signup_url.startswith("http"):
                # Resolve relative URL naively
                signup_url = base.rsplit("/", 1)[0] + "/" + signup_url.lstrip("/")
            try:
                r = session.get(signup_url, timeout=TIMEOUT)
                signup_lower = r.text.lower()
                found_policy = any(kw in signup_lower for kw in policy_keywords)
            except Exception:
                pass

        if found_policy:
            findings.append({
                "category": "Password Policy",
                "title": "Password policy / requirements text found on registration page",
                "detail": "The registration page appears to communicate password complexity requirements to users.",
                "severity": "Pass",
            })
        else:
            findings.append({
                "category": "Password Policy",
                "title": "No password policy indicators found",
                "detail": (
                    "Could not detect password complexity requirements on the registration page "
                    "(or no registration link found). Ensure strong password policies are enforced server-side."
                ),
                "severity": "Medium",
            })

        # Test weak passwords against the login endpoint (observe response, not acceptance)
        weak_accepted: List[str] = []
        for wp in WEAK_PASSWORDS:
            try:
                r = session.post(
                    url,
                    data={"username": "admin", "password": wp},
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )
                body_lower = r.text.lower()
                has_success = any(kw in body_lower for kw in SUCCESS_KEYWORDS)
                has_failure = any(kw in body_lower for kw in FAILURE_KEYWORDS)
                is_redirect = r.history and r.history[-1].status_code == 302
                if (has_success or is_redirect) and not has_failure:
                    weak_accepted.append(wp)
            except Exception:
                continue

        if weak_accepted:
            findings.append({
                "category": "Password Policy",
                "title": "Weak password(s) appear accepted",
                "detail": (
                    f"Login attempts with weak passwords ({', '.join(weak_accepted)}) produced "
                    "success-like responses for the 'admin' username. Enforce minimum password strength."
                ),
                "severity": "Critical",
            })
        else:
            findings.append({
                "category": "Password Policy",
                "title": "Weak password test — no success response detected",
                "detail": "Weak passwords (123456, password) did not produce a success response.",
                "severity": "Pass",
            })

        return findings

    # ── D ──────────────────────────────────────────────────────────────

    def _check_security_headers(
        self, response: Optional[requests.Response]
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        if response is None:
            findings.append({
                "category": "Security Headers",
                "title": "Could not fetch login page to inspect headers",
                "detail": "The login page was unreachable; header analysis skipped.",
                "severity": "High",
            })
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        # Auth-page specific: Cache-Control
        cache_control = headers.get("cache-control", "")
        if "no-store" not in cache_control:
            findings.append({
                "category": "Security Headers",
                "title": "Cache-Control: no-store missing on login page",
                "detail": (
                    f"Current value: '{cache_control or 'not set'}'. "
                    "Without no-store, browsers may cache sensitive login page content."
                ),
                "severity": "Medium",
            })
        else:
            findings.append({
                "category": "Security Headers",
                "title": "Cache-Control: no-store is set",
                "detail": "Browser caching of the login page is restricted.",
                "severity": "Pass",
            })

        # Pragma
        pragma = headers.get("pragma", "")
        if "no-cache" not in pragma:
            findings.append({
                "category": "Security Headers",
                "title": "Pragma: no-cache missing on login page",
                "detail": f"Current value: '{pragma or 'not set'}'. Legacy caching directive is absent.",
                "severity": "Low",
            })
        else:
            findings.append({
                "category": "Security Headers",
                "title": "Pragma: no-cache is set",
                "detail": "Legacy no-cache directive is present.",
                "severity": "Pass",
            })

        # General security headers
        for header, severity in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "category": "Security Headers",
                    "title": f"Missing header: {header}",
                    "detail": f"The '{header}' header was not found in the login page response.",
                    "severity": severity,
                })
            else:
                findings.append({
                    "category": "Security Headers",
                    "title": f"Header present: {header}",
                    "detail": f"Value: {headers[header.lower()]}",
                    "severity": "Pass",
                })

        return findings

    # ── E ──────────────────────────────────────────────────────────────

    def _check_account_enumeration(
        self, session: requests.Session, url: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        valid_looking = "admin@example.com"
        invalid_looking = "zzzzxxx_nonexistent_9874@nope.invalid"
        same_password = "WrongPass_xyz_9999!"

        try:
            t0 = time.time()
            r_valid = session.post(
                url,
                data={"username": valid_looking, "password": same_password},
                timeout=TIMEOUT,
                allow_redirects=False,
            )
            t_valid = time.time() - t0

            t0 = time.time()
            r_invalid = session.post(
                url,
                data={"username": invalid_looking, "password": same_password},
                timeout=TIMEOUT,
                allow_redirects=False,
            )
            t_invalid = time.time() - t0

            body_valid = r_valid.text.lower()
            body_invalid = r_invalid.text.lower()

            status_diff = r_valid.status_code != r_invalid.status_code
            content_diff = body_valid != body_invalid
            time_diff = abs(t_valid - t_invalid) > 0.5  # 500 ms threshold

            enum_flags: List[str] = []
            if status_diff:
                enum_flags.append(
                    f"Different HTTP status codes ({r_valid.status_code} vs {r_invalid.status_code})"
                )
            if content_diff:
                # Check for specific enumeration clues
                valid_specific = any(
                    kw in body_valid for kw in ["password", "incorrect password", "wrong password"]
                )
                invalid_specific = any(
                    kw in body_invalid for kw in ["not found", "no account", "doesn't exist", "user not found"]
                )
                if valid_specific or invalid_specific:
                    enum_flags.append("Response body reveals different error messages for valid vs invalid usernames")
                elif content_diff:
                    enum_flags.append("Response body content differs between valid-looking and invalid usernames")
            if time_diff:
                enum_flags.append(
                    f"Significant response time difference ({t_valid:.2f}s vs {t_invalid:.2f}s) may indicate timing-based enumeration"
                )

            if enum_flags:
                findings.append({
                    "category": "Account Enumeration",
                    "title": "Potential username enumeration vulnerability detected",
                    "detail": "Differences observed:\n" + "\n".join(f"  - {f}" for f in enum_flags),
                    "severity": "High",
                })
            else:
                findings.append({
                    "category": "Account Enumeration",
                    "title": "No obvious username enumeration detected",
                    "detail": (
                        "Responses for valid-looking and invalid usernames appear consistent "
                        "in status code, content, and response time."
                    ),
                    "severity": "Pass",
                })

        except Exception as exc:
            findings.append({
                "category": "Account Enumeration",
                "title": "Account enumeration check failed",
                "detail": f"An error occurred during the enumeration test: {exc}",
                "severity": "Low",
            })

        return findings

    # ── F ──────────────────────────────────────────────────────────────

    def _check_rate_limiting(
        self, session: requests.Session, url: str
    ) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []

        rate_limited = False
        captcha_detected = False
        captcha_keywords = ["captcha", "recaptcha", "hcaptcha", "i am not a robot", "verify you are human"]

        for i in range(10):
            try:
                r = session.post(
                    url,
                    data={"username": f"ratetest{i}@test.com", "password": "testpass_ratecheck"},
                    timeout=TIMEOUT,
                    allow_redirects=False,
                )
                if r.status_code == 429:
                    rate_limited = True
                    break
                body_lower = r.text.lower()
                if any(kw in body_lower for kw in captcha_keywords):
                    captcha_detected = True
                    break
            except Exception:
                break

        if rate_limited:
            findings.append({
                "category": "Rate Limiting",
                "title": "HTTP 429 Too Many Requests received after rapid requests",
                "detail": "The server enforces rate limiting on the login endpoint. This is a positive security control.",
                "severity": "Pass",
            })
        elif captcha_detected:
            findings.append({
                "category": "Rate Limiting",
                "title": "CAPTCHA challenge detected after rapid requests",
                "detail": "A CAPTCHA challenge appeared after repeated rapid login attempts, indicating bot mitigation is in place.",
                "severity": "Pass",
            })
        else:
            findings.append({
                "category": "Rate Limiting",
                "title": "No rate limiting or CAPTCHA detected after 10 rapid requests",
                "detail": (
                    "The login endpoint accepted 10 rapid consecutive POST requests without "
                    "returning HTTP 429 or presenting a CAPTCHA. This leaves the endpoint "
                    "vulnerable to automated credential stuffing and brute-force attacks."
                ),
                "severity": "High",
            })

        return findings

    # ------------------------------------------------------------------
    # Report renderer
    # ------------------------------------------------------------------

    def _render_report(self, url: str, findings: List[Dict[str, Any]]) -> str:
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Pass": 4}
        severity_emoji = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🔵",
            "Pass": "✅",
        }

        counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Pass": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x["severity"], 99))

        lines: List[str] = [
            "# 🔐 Authentication Security Test Report",
            "",
            f"**Target URL:** `{url}`",
            f"**Scan Time:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "",
            "---",
            "",
            "## 📊 Summary",
            "",
            f"| Severity | Count |",
            f"|----------|-------|",
            f"| 🔴 Critical | {counts['Critical']} |",
            f"| 🟠 High     | {counts['High']} |",
            f"| 🟡 Medium   | {counts['Medium']} |",
            f"| 🔵 Low      | {counts['Low']} |",
            f"| ✅ Pass      | {counts['Pass']} |",
            "",
            "---",
            "",
            "## 🔍 Detailed Findings",
            "",
        ]

        categories_seen: List[str] = []
        for f in sorted_findings:
            cat = f["category"]
            if cat not in categories_seen:
                categories_seen.append(cat)
                lines.append(f"### 📂 {cat}")
                lines.append("")

            emoji = severity_emoji.get(f["severity"], "⚪")
            lines.append(f"#### {emoji} [{f['severity']}] {f['title']}")
            lines.append("")
            lines.append(f"{f['detail']}")
            lines.append("")

        lines += [
            "---",
            "",
            "## ⚠️ Disclaimer",
            "",
            "> This report was generated by automated heuristic testing. Results may include "
            "false positives or miss vulnerabilities that require manual verification. "
            "Only run this tool against systems you own or have explicit written permission to test.",
            "",
        ]

        return "\n".join(lines)
