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
from typing import Type, List, Optional, Dict, Any
import requests


# ──────────────────────────────────────────────
# Known services whose unclaimed CNAMEs indicate
# a potential subdomain takeover vulnerability
# ──────────────────────────────────────────────
TAKEOVER_INDICATORS: Dict[str, str] = {
    "amazonaws.com": "AWS S3 / Elastic Beanstalk",
    "azurewebsites.net": "Azure Web Apps",
    "cloudapp.net": "Azure Cloud App",
    "github.io": "GitHub Pages",
    "fastly.net": "Fastly CDN",
    "herokudns.com": "Heroku",
    "herokussl.com": "Heroku SSL",
    "pantheonsite.io": "Pantheon",
    "shopify.com": "Shopify",
    "squarespace.com": "Squarespace",
    "wpengine.com": "WP Engine",
    "netlify.app": "Netlify",
    "netlify.com": "Netlify",
    "surge.sh": "Surge.sh",
    "bitbucket.io": "Bitbucket Pages",
    "ghost.io": "Ghost",
    "helpscoutdocs.com": "HelpScout",
    "readme.io": "ReadMe",
    "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage",
    "freshdesk.com": "Freshdesk",
    "intercom.io": "Intercom",
}


class DnsIpReconInput(BaseModel):
    """Input schema for DNS and IP Reconnaissance Tool."""
    target: str = Field(
        ...,
        description=(
            "A domain name (e.g. 'example.com') or IP address (e.g. '1.2.3.4') "
            "to perform DNS and IP reconnaissance on."
        ),
    )


class DnsIpReconTool(BaseTool):
    """Tool for DNS and IP reconnaissance using Google DNS API and ipapi.co."""

    name: str = "DNS and IP Reconnaissance Tool"
    description: str = (
        "Performs DNS and IP reconnaissance on a given domain or IP address. "
        "Queries Google Public DNS for A, MX, TXT, NS, and CNAME records, "
        "fetches IP geolocation and ASN info from ipapi.co, checks for "
        "subdomain takeover indicators, and analyzes SPF/DMARC strictness. "
        "Returns a structured markdown report with all findings and security warnings."
    )
    args_schema: Type[BaseModel] = DnsIpReconInput

    # ── Internal helpers ────────────────────────────────────────────────────

    def _query_dns(self, name: str, record_type: str) -> Optional[Dict[str, Any]]:
        """Query Google DNS-over-HTTPS API for the given record type."""
        url = f"https://dns.google/resolve?name={name}&type={record_type}"
        try:
            response = requests.get(url, timeout=10, headers={"Accept": "application/json"})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            return {"error": f"Timeout querying {record_type} records for {name}"}
        except requests.exceptions.RequestException as exc:
            return {"error": str(exc)}

    def _query_ipapi(self, ip: str) -> Dict[str, Any]:
        """Fetch geolocation and ASN information from ipapi.co."""
        url = f"https://ipapi.co/{ip}/json/"
        try:
            response = requests.get(url, timeout=10, headers={"User-Agent": "dns-recon-tool/1.0"})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            return {"error": f"Timeout querying IP info for {ip}"}
        except requests.exceptions.RequestException as exc:
            return {"error": str(exc)}

    def _extract_answers(self, dns_data: Optional[Dict[str, Any]]) -> List[str]:
        """Extract data strings from DNS API answer section."""
        if not dns_data or "error" in dns_data:
            return []
        return [ans.get("data", "") for ans in dns_data.get("Answer", [])]

    def _is_ip_address(self, value: str) -> bool:
        """Simple check to determine if the value looks like an IPv4 address."""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ── SPF / DMARC analysis ────────────────────────────────────────────────

    def _analyze_spf(self, txt_records: List[str]) -> Dict[str, Any]:
        """Find SPF record and analyze its strictness."""
        spf_record = next((r for r in txt_records if "v=spf1" in r.lower()), None)
        if not spf_record:
            return {"found": False, "record": None, "issues": [" No SPF record found — domain is vulnerable to email spoofing."]}

        issues: List[str] = []
        if "~all" in spf_record:
            issues.append("SPF uses '~all' (SoftFail) — consider upgrading to '-all' (HardFail) for stricter enforcement.")
        elif "+all" in spf_record:
            issues.append("SPF uses '+all' — this allows ANY server to send mail. Extremely permissive and dangerous!")
        elif "?all" in spf_record:
            issues.append("SPF uses '?all' (Neutral) — provides no meaningful protection.")
        elif "-all" in spf_record:
            issues.append("SPF uses '-all' (HardFail) — good strict configuration.")

        if "redirect=" in spf_record:
            issues.append("SPF uses a 'redirect' modifier — ensure the target domain has a valid SPF policy.")

        return {"found": True, "record": spf_record, "issues": issues}

    def _analyze_dmarc(self, domain: str, txt_records: List[str]) -> Dict[str, Any]:
        """Find DMARC record and analyze its policy."""
        # DMARC lives at _dmarc.<domain>
        dmarc_record = next((r for r in txt_records if "v=dmarc1" in r.lower()), None)
        if not dmarc_record:
            return {"found": False, "record": None, "issues": ["⚠️ No DMARC record found — domain has no DMARC protection."]}

        issues: List[str] = []
        if "p=none" in dmarc_record.lower():
            issues.append("⚠️ DMARC policy is 'none' — monitoring only, no enforcement. Consider 'quarantine' or 'reject'.")
        elif "p=quarantine" in dmarc_record.lower():
            issues.append("⚠️ DMARC policy is 'quarantine' — good, but 'reject' provides stronger protection.")
        elif "p=reject" in dmarc_record.lower():
            issues.append("✅ DMARC policy is 'reject' — strongest enforcement level.")

        if "rua=" not in dmarc_record.lower():
            issues.append(" No aggregate report URI (rua=) — consider adding one for visibility.")
        if "ruf=" not in dmarc_record.lower():
            issues.append("No forensic report URI (ruf=) — optional but useful for incident investigation.")

        return {"found": True, "record": dmarc_record, "issues": issues}

    # ── Subdomain takeover check ────────────────────────────────────────────

    def _check_takeover(self, cname_records: List[str]) -> List[str]:
        """Identify CNAME targets that match known takeover-prone services."""
        warnings: List[str] = []
        for cname in cname_records:
            cname_lower = cname.rstrip(".").lower()
            for indicator, service in TAKEOVER_INDICATORS.items():
                if cname_lower.endswith(indicator):
                    warnings.append(
                        f"🚨 Potential subdomain takeover: CNAME points to **{cname.rstrip('.')}** "
                        f"({service}). If this resource is unclaimed, the subdomain may be hijackable."
                    )
        return warnings

    # ── Report builder ──────────────────────────────────────────────────────

    def _build_report(
        self,
        target: str,
        domain: str,
        a_data: Dict, mx_data: Dict, txt_data: Dict,
        ns_data: Dict, cname_data: Dict,
        dmarc_txt_data: Dict,
        ip_info: Optional[Dict],
        resolved_ip: Optional[str],
    ) -> str:
        a_records      = self._extract_answers(a_data)
        mx_records     = self._extract_answers(mx_data)
        txt_records    = self._extract_answers(txt_data)
        ns_records     = self._extract_answers(ns_data)
        cname_records  = self._extract_answers(cname_data)
        dmarc_records  = self._extract_answers(dmarc_txt_data)

        spf_analysis   = self._analyze_spf(txt_records)
        dmarc_analysis = self._analyze_dmarc(domain, dmarc_records)
        takeover_warns = self._check_takeover(cname_records)

        lines: List[str] = []

        # ── Header ──
        lines.append(f"#  DNS & IP Reconnaissance Report")
        lines.append(f"\n**Target:** `{target}`  ")
        lines.append(f"**Resolved Domain:** `{domain}`  ")
        if resolved_ip:
            lines.append(f"**Resolved IP (A record):** `{resolved_ip}`")
        lines.append("")

        # ── DNS Records ──
        lines.append("---")
        lines.append("##  DNS Records")

        # A Records
        lines.append("\n###  A Records")
        if a_data and "error" in a_data:
            lines.append(f"> Error: {a_data['error']}")
        elif a_records:
            for r in a_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No A records found)*")

        # MX Records
        lines.append("\n###  MX Records")
        if mx_data and "error" in mx_data:
            lines.append(f"> Error: {mx_data['error']}")
        elif mx_records:
            for r in mx_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No MX records found)*")

        # NS Records
        lines.append("\n###  NS Records")
        if ns_data and "error" in ns_data:
            lines.append(f"> Error: {ns_data['error']}")
        elif ns_records:
            for r in ns_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No NS records found)*")

        # CNAME Records
        lines.append("\n###  CNAME Records")
        if cname_data and "error" in cname_data:
            lines.append(f"> Error: {cname_data['error']}")
        elif cname_records:
            for r in cname_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No CNAME records found)*")

        # TXT Records
        lines.append("\n###  TXT Records")
        if txt_data and "error" in txt_data:
            lines.append(f"> Error: {txt_data['error']}")
        elif txt_records:
            for r in txt_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No TXT records found)*")

        # DMARC TXT (separate subdomain)
        lines.append("\n### DMARC TXT Records (`_dmarc` subdomain)")
        if dmarc_txt_data and "error" in dmarc_txt_data:
            lines.append(f"> Error: {dmarc_txt_data['error']}")
        elif dmarc_records:
            for r in dmarc_records:
                lines.append(f"- `{r}`")
        else:
            lines.append("- *(No DMARC TXT records found at `_dmarc` subdomain)*")

        # ── IP & Geo Info ──
        lines.append("\n---")
        lines.append("## IP Geolocation & ASN Info")
        if ip_info:
            if "error" in ip_info:
                lines.append(f"> Error fetching IP info: {ip_info['error']}")
            else:
                def _val(key: str, label: str) -> str:
                    v = ip_info.get(key)
                    return f"| {label} | `{v}` |" if v else f"| {label} | *(unavailable)* |"

                lines.append("")
                lines.append("| Field | Value |")
                lines.append("|-------|-------|")
                lines.append(_val("ip",          "IP Address"))
                lines.append(_val("city",        "City"))
                lines.append(_val("region",      "Region"))
                lines.append(_val("country_name","Country"))
                lines.append(_val("postal",      "Postal Code"))
                lines.append(_val("latitude",    "Latitude"))
                lines.append(_val("longitude",   "Longitude"))
                lines.append(_val("timezone",    "Timezone"))
                lines.append(_val("org",         "Organization / ASN"))
                lines.append(_val("asn",         "ASN Number"))
                lines.append(_val("isp",         "ISP"))
                lines.append(_val("network",     "Network CIDR"))
        else:
            lines.append("> *(No IP was resolved — skipping geolocation lookup.)*")

        # ── Security Findings ──
        lines.append("\n---")
        lines.append("## Security Findings")

        all_issues: List[str] = []

        # SPF
        lines.append("\n### SPF Analysis")
        if spf_analysis["found"]:
            lines.append(f"**Record:** `{spf_analysis['record']}`")
        for issue in spf_analysis["issues"]:
            lines.append(f"- {issue}")
            if "🚨" in issue or "⚠️" in issue:
                all_issues.append(issue)

        # DMARC
        lines.append("\n### DMARC Analysis")
        if dmarc_analysis["found"]:
            lines.append(f"**Record:** `{dmarc_analysis['record']}`")
        for issue in dmarc_analysis["issues"]:
            lines.append(f"- {issue}")
            if "🚨" in issue or "⚠️" in issue:
                all_issues.append(issue)

        # Subdomain Takeover
        lines.append("\n### Subdomain Takeover Check")
        if takeover_warns:
            for w in takeover_warns:
                lines.append(f"- {w}")
                all_issues.append(w)
        else:
            lines.append("- No subdomain takeover indicators detected in CNAME records.")

        # ── Summary ──
        lines.append("\n---")
        lines.append("## Summary")
        if all_issues:
            lines.append(f"\n**{len(all_issues)} security issue(s) found:**\n")
            for i, issue in enumerate(all_issues, 1):
                lines.append(f"{i}. {issue}")
        else:
            lines.append("\n **No critical security issues detected.** DNS configuration looks healthy.")

        lines.append("\n---")
        lines.append("*Report generated by DNS and IP Reconnaissance Tool via Google Public DNS & ipapi.co*")

        return "\n".join(lines)

    # ── Main entry point ────────────────────────────────────────────────────

    def _run(self, target: str) -> str:
        """
        Perform full DNS and IP reconnaissance on the given domain or IP address.
        Returns a structured markdown report.
        """
        target = target.strip().rstrip("/")

        # Determine if input is an IP or domain
        if self._is_ip_address(target):
            # For bare IPs we can skip A-record lookup and go straight to geo
            domain = target
            resolved_ip = target
        else:
            domain = target
            resolved_ip = None

        # ── Fetch all DNS record types ──
        a_data     = self._query_dns(domain, "A")
        mx_data    = self._query_dns(domain, "MX")
        txt_data   = self._query_dns(domain, "TXT")
        ns_data    = self._query_dns(domain, "NS")
        cname_data = self._query_dns(domain, "CNAME")

        # DMARC is published under _dmarc.<domain>
        dmarc_subdomain = f"_dmarc.{domain}" if not self._is_ip_address(domain) else domain
        dmarc_txt_data  = self._query_dns(dmarc_subdomain, "TXT")

        # ── Resolve IP from A record if not already an IP ──
        if not resolved_ip and a_data and "Answer" in a_data:
            a_answers = [ans.get("data", "") for ans in a_data.get("Answer", [])]
            # Pick first proper IPv4 address
            for ans in a_answers:
                if self._is_ip_address(ans):
                    resolved_ip = ans
                    break

        # ── Fetch IP geolocation ──
        ip_info: Optional[Dict[str, Any]] = None
        if resolved_ip:
            ip_info = self._query_ipapi(resolved_ip)

        # ── Build and return the report ──
        return self._build_report(
            target=target,
            domain=domain,
            a_data=a_data,
            mx_data=mx_data,
            txt_data=txt_data,
            ns_data=ns_data,
            cname_data=cname_data,
            dmarc_txt_data=dmarc_txt_data,
            ip_info=ip_info,
            resolved_ip=resolved_ip,
        )
