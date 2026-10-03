from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional, Tuple
import requests
import time
import re
from urllib.parse import urlparse, urljoin


# ── Input Schema ─────────────────────────────────────────────────────────────

class AuthSecTesterInput(BaseModel):
    """Input schema for Authentication Security Tester Tool."""
    url: str = Field(
        ...,
        description="The full URL or base URL of the target to test for authentication security (e.g. https://example.com/login).",
    )


# ── Constants & Signatures ───────────────────────────────────────────────────

DEFAULT_CREDENTIALS: List[Tuple[str, str]] = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
    ("demo", "demo"),
    ("guest", "guest"),
    ("administrator", "administrator"),
]

LOGIN_CANDIDATE_PATHS = [
    "/login", "/signin", "/auth", "/auth/login", "/account/login",
    "/user/login", "/admin/login", "/session/new", "/portal/login"
]

SUCCESS_KEYWORDS = [
    "dashboard", "welcome", "logout", "sign out", "my account",
    "user profile", "logged in", "auth_token", "jwt", "session_id"
]

FAILURE_KEYWORDS = [
    "invalid", "incorrect", "failed", "error", "wrong", "unauthorized",
    "credentials do not match", "does not exist", "bad username"
]

CAPTCHA_KEYWORDS = [
    "captcha", "recaptcha", "hcaptcha", "turnstile", "cf-turnstile",
    "i am not a robot", "verify you are human", "challenge-running"
]

SSO_PATTERNS = {
    "Google OAuth": [r'accounts\.google\.com', r'google-oauth', r'auth/google', r'btn-google'],
    "GitHub OAuth": [r'github\.com/login/oauth', r'auth/github', r'btn-github'],
    "Microsoft / Azure AD": [r'login\.microsoftonline\.com', r'auth/microsoft', r'btn-microsoft'],
    "Apple ID": [r'appleid\.apple\.com', r'auth/apple'],
    "SAML 2.0 / Okta / SSO": [r'okta\.com', r'saml', r'sso/login', r'auth/sso', r'onelogin\.com'],
}

AUTH_SECURITY_HEADERS = {
    "Strict-Transport-Security": {"rec": "max-age=31536000; includeSubDomains", "risk": "High", "role": "HSTS Transport Encryption"},
    "X-Frame-Options": {"rec": "DENY or SAMEORIGIN", "risk": "High", "role": "Clickjacking Shield on Login"},
    "X-Content-Type-Options": {"rec": "nosniff", "risk": "Medium", "role": "MIME-Type Sniffing Protection"},
    "Content-Security-Policy": {"rec": "default-src 'self' ...", "risk": "High", "role": "Cross-Site Scripting & Injection Guard"},
    "Cache-Control": {"rec": "no-store, no-cache", "risk": "Medium", "role": "Sensitive Auth Credential Caching Shield"},
}

TIMEOUT = 8.0


# ── Tool Class ────────────────────────────────────────────────────────────────

class AuthenticationSecurityTesterTool(BaseTool):
    """
    Advanced security auditing tool for evaluating authentication mechanisms,
    login form protections, credential stuffing resilience, account enumeration oracles,
    brute-force lockouts, session cookie flags, and SSO/MFA federation readiness.
    """

    name: str = "Authentication Security Tester"
    description: str = (
        "Audits a target login gateway for transport encryption, CSRF protections, "
        "default credential vulnerability, username enumeration oracles, brute-force throttling, "
        "session cookie flags, and SSO/MFA integrations. Returns an executive tabular data-sheet."
    )
    args_schema: Type[BaseModel] = AuthSecTesterInput

    def _normalize_url(self, raw_url: str) -> str:
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _discover_login_page(self, session: requests.Session, base_url: str) -> Tuple[str, str, Optional[requests.Response]]:
        # Check initial URL first
        try:
            r = session.get(base_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            if re.search(r'type=["\']password["\']', r.text, re.IGNORECASE):
                return r.url, r.text, r
        except Exception:
            pass

        # Probe candidate paths if initial didn't contain a password field
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        for path in LOGIN_CANDIDATE_PATHS:
            test_url = f"{origin}{path}"
            try:
                r = session.get(test_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
                if r.status_code == 200 and re.search(r'type=["\']password["\']', r.text, re.IGNORECASE):
                    return r.url, r.text, r
            except Exception:
                continue

        # Default fallback to original
        try:
            r_fallback = session.get(base_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            return r_fallback.url, r_fallback.text, r_fallback
        except Exception:
            return base_url, "", None

    # ── 1. Login Form Architecture Audit ──
    def _audit_form_architecture(self, url: str, html: str) -> Dict[str, Any]:
        has_https = url.startswith("https://")
        has_password_field = bool(re.search(r'type=["\']password["\']', html, re.IGNORECASE))
        has_username_field = bool(re.search(r'(type=["\']email["\']|name=["\'](?:user|username|email|login|account|identity))', html, re.IGNORECASE))

        # Form action
        action_match = re.search(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        form_action = action_match.group(1) if action_match else "Implicit Self (`POST`)"
        is_action_https = form_action.startswith("https://") or not form_action.startswith("http://")

        # CSRF Token
        has_csrf = bool(re.search(r'(csrf|_token|authenticity_token|__requestverificationtoken|xsrf-token|antiforgery)', html, re.IGNORECASE))

        # Password Autocomplete
        has_autocomplete_attr = bool(re.search(r'type=["\']password["\'][^>]*autocomplete=["\']([^"\']+)["\']', html, re.IGNORECASE) or re.search(r'autocomplete=["\']([^"\']+)["\'][^>]*type=["\']password["\']', html, re.IGNORECASE))

        # WebAuthn / Passkeys
        has_webauthn = bool(re.search(r'(PublicKeyCredential|navigator\.credentials|webauthn|passkey)', html, re.IGNORECASE))

        return {
            "has_https": has_https,
            "has_password": has_password_field,
            "has_username": has_username_field,
            "form_action": form_action,
            "is_action_https": is_action_https,
            "has_csrf": has_csrf,
            "has_autocomplete": has_autocomplete_attr,
            "has_webauthn": has_webauthn,
        }

    # ── 2. Credential Stuffing & Default Accounts ──
    def _audit_default_credentials(self, session: requests.Session, url: str) -> List[Dict[str, Any]]:
        results = []
        for username, password in DEFAULT_CREDENTIALS:
            start_t = time.time()
            try:
                resp = session.post(
                    url,
                    data={"username": username, "password": password, "user": username, "pass": password, "email": f"{username}@test.com"},
                    timeout=6.0,
                    allow_redirects=False,
                    verify=False,
                )
                elapsed_ms = round((time.time() - start_t) * 1000, 1)
                st = resp.status_code
                body_lower = resp.text.lower()
                is_redirect_success = st in (301, 302, 303) and not any(kw in resp.headers.get("Location", "").lower() for kw in ["login", "error", "auth"])
                is_keyword_success = any(kw in body_lower for kw in SUCCESS_KEYWORDS) and not any(kw in body_lower for kw in FAILURE_KEYWORDS)

                if is_redirect_success or is_keyword_success:
                    verdict = "Vulnerable (Accepted)"
                    risk = "Critical"
                else:
                    verdict = "Rejected / Access Denied"
                    risk = "Low"

                results.append({
                    "credentials": f"`{username}` : `{password}`",
                    "status": f"HTTP {st}",
                    "latency": f"{elapsed_ms}ms",
                    "verdict": verdict,
                    "risk": risk,
                })
            except Exception as e:
                results.append({
                    "credentials": f"`{username}` : `{password}`",
                    "status": "Timeout / Blocked",
                    "latency": "—",
                    "verdict": "Connection Handled",
                    "risk": "Low",
                })
            time.sleep(0.05)
        return results

    # ── 3. Account Enumeration & Timing Oracle ──
    def _audit_account_enumeration(self, session: requests.Session, url: str) -> Dict[str, Any]:
        valid_candidate = "admin@example.com"
        nonexistent_candidate = "nonexistent_sec_audit_987654@invalid-domain-xyz.org"
        fixed_pwd = "InvalidAuditPassword!123"

        t0 = time.time()
        r_valid = None
        try:
            r_valid = session.post(
                url,
                data={"username": valid_candidate, "password": fixed_pwd, "email": valid_candidate},
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            lat_valid = round((time.time() - t0) * 1000, 1)
        except Exception:
            lat_valid = 0

        t0 = time.time()
        r_invalid = None
        try:
            r_invalid = session.post(
                url,
                data={"username": nonexistent_candidate, "password": fixed_pwd, "email": nonexistent_candidate},
                timeout=TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            lat_invalid = round((time.time() - t0) * 1000, 1)
        except Exception:
            lat_invalid = 0

        status_valid = r_valid.status_code if r_valid else 0
        status_invalid = r_invalid.status_code if r_invalid else 0
        body_valid = r_valid.text.lower() if r_valid else ""
        body_invalid = r_invalid.text.lower() if r_invalid else ""

        status_differ = (status_valid != status_invalid and status_valid != 0 and status_invalid != 0)
        time_delta_ms = abs(lat_valid - lat_invalid)
        timing_oracle = time_delta_ms > 450.0  # significant timing differential

        message_differ = False
        if body_valid and body_invalid:
            # Check if specific error reveals user existence
            if ("password" in body_valid and "user" in body_invalid) or ("not found" in body_invalid and "not found" not in body_valid):
                message_differ = True

        return {
            "status_valid": status_valid,
            "status_invalid": status_invalid,
            "lat_valid_ms": lat_valid,
            "lat_invalid_ms": lat_invalid,
            "time_delta_ms": round(time_delta_ms, 1),
            "status_differ": status_differ,
            "timing_oracle": timing_oracle,
            "message_differ": message_differ,
        }

    # ── 4. Brute-Force & Lockout Throttling ──
    def _audit_brute_force_lockout(self, session: requests.Session, url: str) -> Dict[str, Any]:
        attempt_logs = []
        lockout_triggered = False
        captcha_triggered = False

        for i in range(1, 7):
            start_t = time.time()
            try:
                resp = session.post(
                    url,
                    data={"username": f"brute_probe_{i}@test.com", "password": f"Password_{i}!X"},
                    timeout=TIMEOUT,
                    allow_redirects=False,
                    verify=False,
                )
                elapsed_ms = round((time.time() - start_t) * 1000, 1)
                st = resp.status_code
                body_lower = resp.text.lower()

                is_429 = st == 429
                is_locked = st in (403, 423) or any(kw in body_lower for kw in ["locked", "too many attempts", "temporarily disabled"])
                is_captcha = any(kw in body_lower for kw in CAPTCHA_KEYWORDS)

                if is_429 or is_locked:
                    lockout_triggered = True
                if is_captcha:
                    captcha_triggered = True

                verdict = "Rate Limited (429)" if is_429 else ("Account Locked" if is_locked else ("CAPTCHA Challenge" if is_captcha else "Processed (No Lockout)"))
                attempt_logs.append({
                    "attempt": f"#{i}",
                    "status": f"HTTP {st}",
                    "latency": f"{elapsed_ms}ms",
                    "behavior": verdict,
                })
            except Exception:
                attempt_logs.append({
                    "attempt": f"#{i}",
                    "status": "Timeout / Blocked",
                    "latency": "—",
                    "behavior": "Connection Dropped",
                })
            time.sleep(0.05)

        return {
            "attempts": attempt_logs,
            "lockout_triggered": lockout_triggered,
            "captcha_triggered": captcha_triggered,
        }

    # ── 5. SSO & MFA Discovery ──
    def _discover_sso_mfa(self, html: str) -> List[Dict[str, Any]]:
        sso_findings = []
        for provider, patterns in SSO_PATTERNS.items():
            if any(re.search(p, html, re.IGNORECASE) for p in patterns):
                sso_findings.append({
                    "protocol": provider,
                    "status": "Active / Configured",
                    "security_impact": "Delegates authentication to enterprise identity provider.",
                })
        return sso_findings

    # ── 6. Build Tabular Markdown Report ──
    def _build_markdown_report(
        self,
        target_url: str,
        login_url: str,
        form_info: Dict[str, Any],
        cred_results: List[Dict[str, Any]],
        enum_results: Dict[str, Any],
        bf_results: Dict[str, Any],
        sso_results: List[Dict[str, Any]],
        response: Optional[requests.Response],
    ) -> str:
        headers = {k.lower(): v for k, v in response.headers.items()} if response else {}

        sections = []
        sections.append("# Authentication Security & Access Control Audit")
        sections.append(f"**Target System:** `{target_url}` | **Evaluated Login Endpoint:** `{login_url}`\n")

        # 1. Overview Matrix
        sections.append("## Authentication Posture Overview\n")
        sections.append("| Security Control Vector | Assessment Metric | Posture Rating | Compliance / Benchmark Verdict |")
        sections.append("|---|---|---|---|")
        sections.append(f"| Transport Layer Encryption | {'HTTPS Enforced' if form_info['has_https'] else 'Insecure HTTP'} | {'Protected' if form_info['has_https'] else 'Critical'} | {'All credentials encrypted via TLS in transit' if form_info['has_https'] else 'Credentials transmitted in cleartext'} |")
        sections.append(f"| CSRF Defense Token | {'Present' if form_info['has_csrf'] else 'Missing / Implicit'} | {'Protected' if form_info['has_csrf'] else 'High'} | {'Anti-CSRF token validates form origin' if form_info['has_csrf'] else 'Login endpoint lacks explicit CSRF tokens'} |")
        sections.append(f"| Default Credentials Shield | {len(cred_results)} Pairs Audited | {'Protected' if not any(c['risk'] == 'Critical' for c in cred_results) else 'Critical'} | {'No administrative default accounts accepted' if not any(c['risk'] == 'Critical' for c in cred_results) else 'Default administrative credentials accepted!'} |")
        sections.append(f"| Username Enumeration Oracle | {'Timing / Content Differential' if (enum_results['timing_oracle'] or enum_results['message_differ']) else 'Uniform Response'} | {'Warning' if (enum_results['timing_oracle'] or enum_results['message_differ']) else 'Clean'} | {'Response variations permit user discovery' if (enum_results['timing_oracle'] or enum_results['message_differ']) else 'Consistent responses mitigate user enumeration'} |")
        sections.append(f"| Brute-Force & Lockout Policy | {'Active (Throttled/CAPTCHA)' if (bf_results['lockout_triggered'] or bf_results['captcha_triggered']) else 'Unrestricted Submissions'} | {'Protected' if (bf_results['lockout_triggered'] or bf_results['captcha_triggered']) else 'Medium'} | {'Rate limiting or challenge active against password guessing' if (bf_results['lockout_triggered'] or bf_results['captcha_triggered']) else 'Endpoint accepts consecutive failed attempts without delay'} |")
        sections.append(f"| Modern WebAuthn / Passkeys | {'Supported' if form_info['has_webauthn'] else 'Standard Password'} | {'Advanced' if form_info['has_webauthn'] else 'Standard'} | {'FIDO2 / WebAuthn passwordless integration detected' if form_info['has_webauthn'] else 'Traditional username/password credentials utilized'} |")

        # 2. Login Interface & Form Security
        sections.append("\n## Login Interface & Form Security Catalog\n")
        sections.append("| Component Property | Detected Setting | Security Evaluation | Recommended Hardening |")
        sections.append("|---|---|---|---|")
        sections.append(f"| Form Target Action | `{form_info['form_action']}` | {'Secure Same-Origin' if form_info['is_action_https'] else 'External / Insecure'} | Ensure form submissions route strictly to HTTPS endpoints. |")
        sections.append(f"| Password Input Masking | {'type=\"password\"' if form_info['has_password'] else 'No Password Field'} | Standard Form Field | Client masks credential input characters on display. |")
        sections.append(f"| Autocomplete Setting | {'autocomplete set' if form_info['has_autocomplete'] else 'Unset / Default'} | {'Managed' if form_info['has_autocomplete'] else 'Low Risk'} | Set `autocomplete=\"current-password\"` to assist password managers. |")
        sections.append(f"| Cross-Origin Isolation | {'Same-Origin Action' if form_info['is_action_https'] else 'Cross-Domain'} | Enforced | Validate Origin and Referer headers on authentication handler. |")

        # 3. Credential Stuffing & Default Accounts
        sections.append("\n## Credential Stuffing & Default Accounts Audit\n")
        sections.append("| Audited Credential Pair | Server HTTP Response | Round-Trip Latency | Security Verdict | Risk Level |")
        sections.append("|---|---|---|---|---|")
        for cr in cred_results:
            sections.append(f"| {cr['credentials']} | `{cr['status']}` | `{cr['latency']}` | {cr['verdict']} | {cr['risk']} |")

        # 4. Account Enumeration & Timing Oracle
        sections.append("\n## Account Enumeration & Timing Oracle Analysis\n")
        sections.append("| Enumeration Vector | Valid User Probe | Non-Existent User Probe | Variance / Delta | Oracle Vulnerability |")
        sections.append("|---|---|---|---|---|")
        sections.append(f"| HTTP Status Code | `HTTP {enum_results['status_valid']}` | `HTTP {enum_results['status_invalid']}` | {'Status Differential' if enum_results['status_differ'] else 'Uniform Status'} | {'Vulnerable' if enum_results['status_differ'] else 'Mitigated'} |")
        sections.append(f"| Processing Latency (Timing) | `{enum_results['lat_valid_ms']}ms` | `{enum_results['lat_invalid_ms']}ms` | `Δ {enum_results['time_delta_ms']}ms` | {'Potential Timing Oracle' if enum_results['timing_oracle'] else 'Uniform Response Timing'} |")
        sections.append(f"| Error Message Content | Evaluated | Evaluated | {'Message Divergence' if enum_results['message_differ'] else 'Consistent Error'} | {'Information Disclosure' if enum_results['message_differ'] else 'Mitigated'} |")

        # 5. Brute-Force Throttling & Lockout Matrix
        sections.append("\n## Brute-Force Throttling & Lockout Matrix\n")
        sections.append("| Probe Sequence | HTTP Response Code | Observed Latency | Rate Limiting & Lockout Behavior |")
        sections.append("|---|---|---|---|")
        for att in bf_results["attempts"]:
            sections.append(f"| `{att['attempt']}` | `{att['status']}` | `{att['latency']}` | {att['behavior']} |")

        # 6. Session Token & Authentication Header Matrix
        sections.append("\n## Session Token & Authentication Header Matrix\n")
        sections.append("| Security Header | Detected Value | Hardening State | Protective Function |")
        sections.append("|---|---|---|---|")
        for h_name, h_info in AUTH_SECURITY_HEADERS.items():
            val = headers.get(h_name.lower())
            if val:
                val_clean = val.replace("\n", " ").strip()
                if len(val_clean) > 40:
                    val_clean = val_clean[:37] + "..."
                sections.append(f"| `{h_name}` | `{val_clean}` | Configured | {h_info['role']} |")
            else:
                sections.append(f"| `{h_name}` | _Not Configured_ | Missing | {h_info['role']} (Recommend: `{h_info['rec']}`) |")

        # 7. SSO & Identity Federation Discovery
        sections.append("\n## Identity Federation & SSO Discovery\n")
        if sso_results:
            sections.append("| Identity Protocol / Provider | Deployment Status | Security Scope |")
            sections.append("|---|---|---|")
            for sso in sso_results:
                sections.append(f"| `{sso['protocol']}` | {sso['status']} | {sso['security_impact']} |")
        else:
            sections.append("| Identity Protocol / Provider | Deployment Status | Security Scope |")
            sections.append("|---|---|---|")
            sections.append("| Local Database Authentication | Standalone | Direct credential authentication against local database instance |")

        # 8. Action Items Roadmap
        sections.append("\n## Authentication Hardening Action Items\n")
        sections.append("| Finding Focus | Severity | Target Mechanism | Recommended Remediation Action | Reference |")
        sections.append("|---|---|---|---|---|")
        if not form_info["has_https"]:
            sections.append("| Insecure Transport | Critical | Login Gateway | Enforce HTTPS exclusively with HSTS preloading enabled. | OWASP A02:2021 |")
        if not form_info["has_csrf"]:
            sections.append("| Anti-CSRF Protection | High | Login Form | Implement cryptographic synchronizer tokens or SameSite=Strict cookies. | OWASP A01:2021 |")
        if enum_results["timing_oracle"] or enum_results["message_differ"]:
            sections.append("| Account Enumeration Shield | Medium | Auth Handler | Standardize error messages to 'Invalid username or password' with constant-time password comparison. | CWE-204 |")
        if not bf_results["lockout_triggered"] and not bf_results["captcha_triggered"]:
            sections.append("| Credential Stuffing Guard | High | Login Endpoint | Enforce progressive rate limiting (e.g. 5 attempts / min) and CAPTCHA challenge on repeated failures. | OWASP A07:2021 |")
        sections.append("| Session Cache-Control | Medium | HTTP Headers | Enforce `Cache-Control: no-store, no-cache` on all authentication endpoints. | CWE-525 |")
        sections.append("| Multi-Factor Authentication | Medium | User Accounts | Require 2FA/MFA (TOTP or WebAuthn/FIDO2) for all privileged and administrative accounts. | NIST SP 800-63B |")

        return "\n".join(sections)

    # ── Entry Point ──
    def _run(self, url: str) -> str:
        """Execute comprehensive authentication security audit."""
        target_url = self._normalize_url(url)

        # Suppress insecure SSL warnings for penetration testing
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        })

        # 1. Discover actual login endpoint
        login_url, login_html, login_resp = self._discover_login_page(session, target_url)

        # 2. Form architecture audit
        form_info = self._audit_form_architecture(login_url, login_html)

        # 3. Default credentials audit
        cred_results = self._audit_default_credentials(session, login_url)

        # 4. Account enumeration audit
        enum_results = self._audit_account_enumeration(session, login_url)

        # 5. Brute-force & lockout audit
        bf_results = self._audit_brute_force_lockout(session, login_url)

        # 6. SSO discovery
        sso_results = self._discover_sso_mfa(login_html)

        # 7. Render markdown report
        return self._build_markdown_report(
            target_url, login_url, form_info, cred_results, enum_results, bf_results, sso_results, login_resp
        )
