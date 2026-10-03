from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, Optional, List, Dict
import requests
from datetime import datetime, timezone


class SslTlsCertificateInspectorInput(BaseModel):
    """Input schema for SSL TLS Certificate Inspector Tool."""
    domain: str = Field(..., description="The domain name to inspect (e.g., example.com or https://example.com)")


class SslTlsCertificateInspectorTool(BaseTool):
    """Tool for inspecting SSL/TLS certificates and HTTPS security headers for a given domain."""

    name: str = "SSL TLS Certificate Inspector"
    description: str = (
        "Inspects SSL/TLS certificates and HTTPS security posture for a given domain. "
        "Uses crt.sh for certificate transparency logs and direct HTTPS requests to check "
        "TLS connectivity and security headers. Returns a structured markdown report with "
        "certificate expiry, wildcard detection, HSTS, CSP, X-Frame-Options, and recommendations."
    )
    args_schema: Type[BaseModel] = SslTlsCertificateInspectorInput

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    def _clean_domain(self, domain: str) -> str:
        """Strip protocol and path, return bare hostname."""
        domain = domain.strip().lower()
        for prefix in ("https://", "http://"):
            if domain.startswith(prefix):
                domain = domain[len(prefix):]
        return domain.split("/")[0].split("?")[0]

    def _days_until(self, date_str: str) -> Optional[int]:
        """Return days from now until the given ISO-ish date string."""
        if not date_str:
            return None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(date_str[:19], fmt).replace(tzinfo=timezone.utc)
                return (dt - datetime.now(timezone.utc)).days
            except ValueError:
                continue
        return None

    def _expiry_badge(self, days: Optional[int]) -> str:
        """Return a coloured severity badge based on days remaining."""
        if days is None:
            return "⚪ Unknown"
        if days < 0:
            return "🔴 CRITICAL — EXPIRED"
        if days < 30:
            return "🔴 CRITICAL (< 30 days)"
        if days < 60:
            return "🟠 HIGH (< 60 days)"
        if days < 90:
            return "🟡 MEDIUM (< 90 days)"
        return "🟢 OK"

    def _fetch_crtsh(self, domain: str) -> List[dict]:
        """Query crt.sh and return up to 5 most recent unique certificates."""
        url = f"https://crt.sh/?q={domain}&output=json"
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            raw: List[dict] = resp.json()
        except requests.exceptions.Timeout:
            return []
        except Exception:
            return []

        # De-duplicate by cert ID, keep most recent first
        seen: set = set()
        unique: List[dict] = []
        for cert in raw:
            cid = cert.get("id")
            if cid not in seen:
                seen.add(cid)
                unique.append(cert)

        # Sort descending by not_before (most recently issued first)
        unique.sort(key=lambda c: c.get("not_before") or "", reverse=True)
        return unique[:5]

    def _fetch_https(self, domain: str) -> Dict:
        """
        Attempt a direct HTTPS GET to the domain.
        Returns a dict with: success, headers, ssl_error, timeout_error, error_msg.
        """
        result = {
            "success": False,
            "headers": {},
            "ssl_error": False,
            "timeout_error": False,
            "error_msg": "",
        }
        try:
            resp = requests.get(
                f"https://{domain}",
                timeout=10,
                verify=True,
                allow_redirects=True,
            )
            result["success"] = True
            result["headers"] = dict(resp.headers)
        except requests.exceptions.SSLError as e:
            result["ssl_error"] = True
            result["error_msg"] = str(e)[:200]
        except requests.exceptions.Timeout:
            result["timeout_error"] = True
            result["error_msg"] = "Connection timed out after 10 seconds."
        except Exception as e:
            result["error_msg"] = str(e)[:200]
        return result

    def _check_security_headers(self, headers: Dict[str, str]) -> List[Dict]:
        """
        Evaluate a fixed set of security headers.
        Returns a list of findings with: header, present, severity, note.
        """
        checks = [
            {
                "header": "Strict-Transport-Security",
                "severity_if_missing": "🔴 HIGH",
                "note_if_missing": "HSTS not set — browsers may fall back to HTTP.",
                "note_if_present": "HSTS enforced.",
            },
            {
                "header": "Content-Security-Policy",
                "severity_if_missing": "🟠 MEDIUM",
                "note_if_missing": "CSP absent — XSS risk increased.",
                "note_if_present": "CSP header present.",
            },
            {
                "header": "X-Frame-Options",
                "severity_if_missing": "🟡 LOW",
                "note_if_missing": "X-Frame-Options missing — potential clickjacking exposure.",
                "note_if_present": "Clickjacking protection header present.",
            },
        ]
        # Normalise header names to lowercase for comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}
        findings = []
        for chk in checks:
            hdr_lower = chk["header"].lower()
            present = hdr_lower in lower_headers
            value = lower_headers.get(hdr_lower, "")
            findings.append({
                "header": chk["header"],
                "present": present,
                "value": value,
                "severity": "✅ OK" if present else chk["severity_if_missing"],
                "note": chk["note_if_present"] if present else chk["note_if_missing"],
            })
        return findings

    # ------------------------------------------------------------------ #
    #  Main run                                                            #
    # ------------------------------------------------------------------ #

    def _run(self, domain: str) -> str:
        domain = self._clean_domain(domain)
        scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # ── Parallel-ish: fetch crt.sh then HTTPS (sequential but both fast) ──
        crtsh_certs = self._fetch_crtsh(domain)
        https_result = self._fetch_https(domain)

        # ── Derive top-level SSL status ──
        if https_result["ssl_error"]:
            tls_status = "🔴 INSECURE"
            tls_summary = "HTTPS connection failed due to an SSL/TLS error."
        elif https_result["timeout_error"]:
            tls_status = "⚪ UNKNOWN"
            tls_summary = "HTTPS connection timed out — could not verify TLS."
        elif not https_result["success"]:
            tls_status = "🔴 INSECURE"
            tls_summary = f"HTTPS connection failed — {https_result['error_msg']}"
        else:
            tls_status = "🟢 SECURE"
            tls_summary = "HTTPS connection succeeded — TLS handshake valid."

        # ── Security header findings ──
        header_findings = self._check_security_headers(https_result["headers"]) if https_result["success"] else []

        # ── Most recent cert from crt.sh for summary ──
        top_cert = crtsh_certs[0] if crtsh_certs else None

        # ================================================================
        # Build markdown report
        # ================================================================
        L = []

        L.append(f"# 🔐 SSL/TLS Certificate Inspection Report")
        L.append(f"**Domain:** `{domain}`  ")
        L.append(f"**Scan Time:** {scan_time}")
        L.append("")

        # ── Section 1: SSL/TLS Status ────────────────────────────────────
        L.append("---")
        L.append(f"## SSL/TLS Status: {tls_status}")
        L.append(f"> {tls_summary}")
        if https_result["ssl_error"]:
            L.append(">")
            L.append(f"> 🔴 **CRITICAL — SSL Error:** `{https_result['error_msg']}`")
        L.append("")

        # ── Section 2: Certificate Information ──────────────────────────
        L.append("---")
        L.append("## 📜 Certificate Information")
        if not crtsh_certs:
            L.append("> ⚠️ Certificate transparency data unavailable — crt.sh did not return results.")
        else:
            c = top_cert
            common_name = c.get("common_name", "N/A")
            issuer = c.get("issuer_name", c.get("name_value", "N/A"))
            not_before = c.get("not_before", "N/A")
            not_after = c.get("not_after", "N/A")
            days = self._days_until(not_after)
            L.append(f"*(Most recently issued certificate from Certificate Transparency logs)*")
            L.append("")
            L.append(f"| Field | Value |")
            L.append(f"|-------|-------|")
            L.append(f"| **Common Name** | `{common_name}` |")
            L.append(f"| **Issuer** | `{issuer}` |")
            L.append(f"| **Valid From** | `{not_before}` |")
            L.append(f"| **Valid Until** | `{not_after}` |")
            days_label = f"{days} days" if days is not None else "N/A"
            L.append(f"| **Days Remaining** | {days_label} |")
        L.append("")

        # ── Section 3: Certificate Expiry Status ────────────────────────
        L.append("---")
        L.append("## ⏱️ Certificate Expiry Status")
        if not crtsh_certs:
            L.append("> ⚠️ Certificate transparency data unavailable — expiry status cannot be determined.")
        else:
            c = top_cert
            not_after = c.get("not_after", "")
            days = self._days_until(not_after)
            badge = self._expiry_badge(days)
            days_label = f"{days} days remaining" if days is not None else "expiry date unavailable"
            L.append(f"**Severity:** {badge}")
            L.append(f"**Expiry:** `{not_after or 'N/A'}` — {days_label}")
            if days is not None and days < 0:
                L.append("")
                L.append("🔴 **CRITICAL: This certificate has already EXPIRED.**")
        L.append("")

        # ── Section 4: Recent Certificate History ───────────────────────
        L.append("---")
        L.append("## 🗂️ Recent Certificate History (Last 5 from crt.sh)")
        if not crtsh_certs:
            L.append("> ⚠️ Certificate transparency data unavailable.")
        else:
            for i, cert in enumerate(crtsh_certs, 1):
                cn = cert.get("common_name", "N/A")
                issuer = cert.get("issuer_name", cert.get("name_value", "N/A"))
                not_before = cert.get("not_before", "N/A")
                not_after = cert.get("not_after", "N/A")
                days = self._days_until(not_after)
                badge = self._expiry_badge(days)
                days_label = f"{days}d" if days is not None else "N/A"
                is_wildcard = str(cn).startswith("*.")
                wild_tag = " ⚠️ Wildcard" if is_wildcard else ""
                L.append(f"### #{i} — `{cn}`{wild_tag}")
                L.append(f"- **Issuer:** `{issuer}`")
                L.append(f"- **Valid:** `{not_before}` → `{not_after}`")
                L.append(f"- **Expiry:** {badge} ({days_label} remaining)")
                L.append("")

        # ── Section 5: Wildcard Certificate Detection ───────────────────
        L.append("---")
        L.append("## 🃏 Wildcard Certificate Detection")
        if not crtsh_certs:
            L.append("> ⚠️ Cannot determine wildcard status — certificate transparency data unavailable.")
        else:
            wildcards = [c for c in crtsh_certs if str(c.get("common_name", "")).startswith("*.")]
            if wildcards:
                L.append(f"⚠️ **{len(wildcards)} wildcard certificate(s) detected** in the last 5 records:")
                for wc in wildcards:
                    L.append(f"- `{wc.get('common_name', 'N/A')}` (expires: `{wc.get('not_after', 'N/A')}`)")
                L.append("")
                L.append("> Wildcard certificates cover all subdomains (e.g., `*.example.com`). "
                         "If the private key is compromised, **all subdomains are at risk**.")
            else:
                L.append("✅ No wildcard certificates detected in recent certificate history.")
        L.append("")

        # ── Section 6: HTTPS Security Headers ───────────────────────────
        L.append("---")
        L.append("## 🛡️ HTTPS Security Headers")
        if not https_result["success"]:
            if https_result["ssl_error"]:
                L.append("> 🔴 **CRITICAL** — HTTPS connection failed due to SSL/TLS error. Headers could not be retrieved.")
            elif https_result["timeout_error"]:
                L.append("> ⚠️ HTTPS connection timed out — headers could not be retrieved.")
            else:
                L.append("> ⚠️ HTTPS connection failed — headers could not be retrieved.")
        else:
            L.append("| Header | Status | Notes |")
            L.append("|--------|--------|-------|")
            for f in header_findings:
                value_snippet = f" (`{f['value'][:60]}{'…' if len(f['value']) > 60 else ''}`)" if f["present"] and f["value"] else ""
                L.append(f"| `{f['header']}` | {f['severity']} | {f['note']}{value_snippet} |")
        L.append("")

        # ── Section 7: Recommendations ──────────────────────────────────
        L.append("---")
        L.append("## 💡 Recommendations")
        recs = []

        # SSL/TLS failure
        if https_result["ssl_error"]:
            recs.append("🔴 **CRITICAL — Fix SSL/TLS certificate immediately.** The HTTPS connection is broken. "
                        "Check certificate validity, chain completeness, and hostname match.")
        elif not https_result["success"] and not https_result["timeout_error"]:
            recs.append("🔴 **HTTPS is not functioning.** Investigate server configuration and ensure a valid TLS certificate is installed.")
        elif https_result["timeout_error"]:
            recs.append("⚠️ **HTTPS connection timed out.** Verify the server is reachable and firewall rules allow port 443.")

        # Expiry recommendations
        if crtsh_certs:
            c = crtsh_certs[0]
            days = self._days_until(c.get("not_after", ""))
            if days is not None:
                if days < 0:
                    recs.append("🔴 **Certificate EXPIRED — renew immediately!** All visitors will see security warnings.")
                elif days < 30:
                    recs.append("🔴 **Certificate expires in < 30 days — renew NOW (Critical).** "
                                "Consider enabling auto-renewal via Let's Encrypt / ACME.")
                elif days < 60:
                    recs.append("🟠 **Certificate expires in < 60 days — schedule renewal soon (High).**")
                elif days < 90:
                    recs.append("🟡 **Certificate expires in < 90 days — plan renewal (Medium).**")

        # Wildcard recommendation
        if crtsh_certs:
            wildcards = [c for c in crtsh_certs if str(c.get("common_name", "")).startswith("*.")]
            if wildcards:
                recs.append("🟡 **Consider replacing wildcard certificates with domain-specific ones** "
                            "to reduce blast radius if the private key is compromised.")

        # Security header recommendations
        for f in header_findings:
            if not f["present"]:
                if "Strict-Transport-Security" in f["header"]:
                    recs.append("🔴 **Add HSTS header** (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`) "
                                "to enforce HTTPS and prevent protocol downgrade attacks.")
                elif "Content-Security-Policy" in f["header"]:
                    recs.append("🟠 **Implement a Content-Security-Policy header** to restrict resource loading and mitigate XSS attacks.")
                elif "X-Frame-Options" in f["header"]:
                    recs.append("🟡 **Add X-Frame-Options: DENY or SAMEORIGIN** to protect against clickjacking attacks.")

        # crt.sh unavailable
        if not crtsh_certs:
            recs.append("⚠️ **Certificate transparency data was unavailable.** Retry later or manually check https://crt.sh.")

        if not recs:
            recs.append("✅ **Everything looks good!** Continue monitoring certificate expiry and security headers regularly.")

        for r in recs:
            L.append(f"- {r}")

        L.append("")
        L.append("---")
        L.append("*Report generated by SSL TLS Certificate Inspector — Powered by crt.sh & direct HTTPS inspection*")

        return "\n".join(L)
