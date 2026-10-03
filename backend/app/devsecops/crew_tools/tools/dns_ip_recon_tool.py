from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Optional, Dict, Any
from urllib.parse import urlparse
import requests
import socket

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
    "vercel.app": "Vercel",
    "webflow.io": "Webflow",
    "fly.dev": "Fly.io",
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
    """Tool for DNS and IP reconnaissance using Google DNS API and IP geolocation."""

    name: str = "DNS and IP Reconnaissance Tool"
    description: str = (
        "Performs deep DNS and IP reconnaissance on a target domain or IP. "
        "Queries Google Public DNS for A, AAAA, MX, TXT, NS, CNAME, SOA, and DMARC records, "
        "resolves reverse PTR, retrieves IP geolocation and ASN data, "
        "evaluates SPF/DMARC strictness, and checks for subdomain takeover indicators. "
        "Returns a professional, structured executive markdown report."
    )
    args_schema: Type[BaseModel] = DnsIpReconInput

    # ── Target Cleaning Helper ──────────────────────────────────────────────

    def _clean_target(self, target: str) -> str:
        """Extract clean hostname or IP from target string."""
        raw = target.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            host = parsed.netloc or parsed.path
        else:
            host = raw.split("/")[0]
        # Remove port if present
        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        return host.strip().lower()

    # ── DNS Query Helpers ───────────────────────────────────────────────────

    def _query_dns(self, name: str, record_type: str) -> Optional[Dict[str, Any]]:
        """Query Google DNS-over-HTTPS API for the given record type."""
        url = f"https://dns.google/resolve?name={name}&type={record_type}"
        try:
            response = requests.get(url, timeout=8, headers={"Accept": "application/json"})
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            return {"error": f"Timeout querying {record_type} records for {name}"}
        except requests.exceptions.RequestException as exc:
            return {"error": str(exc)}

    def _extract_answers(self, dns_data: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract answer records from DNS API response."""
        if not dns_data or "error" in dns_data:
            return []
        answers = []
        for ans in dns_data.get("Answer", []):
            data = ans.get("data", "").strip('"')
            ttl = ans.get("TTL", 300)
            name = ans.get("name", "").rstrip(".")
            if data:
                answers.append({"data": data, "ttl": ttl, "name": name})
        return answers

    def _is_ipv4(self, value: str) -> bool:
        """Check if value is a valid IPv4 address."""
        parts = value.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    # ── IP Geolocation & ASN ────────────────────────────────────────────────

    def _query_ip_geo(self, ip: str) -> Dict[str, Any]:
        """Fetch geolocation and ASN information from ipapi.co with fallback to ip-api.com."""
        # Primary: ipapi.co
        try:
            url = f"https://ipapi.co/{ip}/json/"
            resp = requests.get(url, timeout=6, headers={"User-Agent": "CyberShield-Recon/2.0"})
            if resp.status_code == 200:
                data = resp.json()
                if "error" not in data:
                    return {
                        "ip": data.get("ip", ip),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "country": data.get("country_name", "Unknown"),
                        "country_code": data.get("country_code", "XX"),
                        "postal": data.get("postal", "N/A"),
                        "latitude": str(data.get("latitude", "N/A")),
                        "longitude": str(data.get("longitude", "N/A")),
                        "timezone": data.get("timezone", "UTC"),
                        "org": data.get("org", "N/A"),
                        "asn": data.get("asn", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "network": data.get("network", "N/A"),
                    }
        except Exception:
            pass

        # Fallback: ip-api.com
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            resp = requests.get(url, timeout=6)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query", ip),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("regionName", "Unknown"),
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "postal": data.get("zip", "N/A"),
                        "latitude": str(data.get("lat", "N/A")),
                        "longitude": str(data.get("lon", "N/A")),
                        "timezone": data.get("timezone", "UTC"),
                        "org": data.get("org", "N/A"),
                        "asn": data.get("as", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "network": "N/A",
                    }
        except Exception:
            pass

        return {
            "ip": ip,
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "country_code": "XX",
            "postal": "N/A",
            "latitude": "N/A",
            "longitude": "N/A",
            "timezone": "UTC",
            "org": "N/A",
            "asn": "N/A",
            "isp": "N/A",
            "network": "N/A",
        }

    def _query_ptr(self, ip: str) -> str:
        """Perform reverse DNS (PTR) lookup."""
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except Exception:
            return "No PTR record configured"

    # ── Security Policy Analysis ────────────────────────────────────────────

    def _analyze_spf(self, txt_records: List[str]) -> Dict[str, Any]:
        """Evaluate SPF policy and enforcement strength."""
        spf_record = next((r for r in txt_records if "v=spf1" in r.lower()), None)
        if not spf_record:
            return {
                "found": False,
                "record": "None",
                "severity": "High",
                "status": "Missing",
                "finding": "No SPF record published. Domain is unprotected against email sender spoofing.",
                "recommendation": "Deploy a strict SPF record (e.g. `v=spf1 include:_spf.example.com -all`)."
            }

        rec_lower = spf_record.lower()
        if "+all" in rec_lower:
            return {
                "found": True,
                "record": spf_record,
                "severity": "Critical",
                "status": "Failed",
                "finding": "SPF policy uses `+all` (Pass All), allowing any mail server on the internet to send authorized mail.",
                "recommendation": "Immediately replace `+all` with `-all` (HardFail)."
            }
        elif "?all" in rec_lower:
            return {
                "found": True,
                "record": spf_record,
                "severity": "Medium",
                "status": "Warning",
                "finding": "SPF policy uses `?all` (Neutral), offering no spoofing prevention enforcement.",
                "recommendation": "Upgrade qualifier to `-all` (HardFail)."
            }
        elif "~all" in rec_lower:
            return {
                "found": True,
                "record": spf_record,
                "severity": "Low",
                "status": "Warning",
                "finding": "SPF policy uses `~all` (SoftFail). Mail may still be delivered to junk folders rather than rejected.",
                "recommendation": "Upgrade to `-all` (HardFail) once all legitimate sending IPs are cataloged."
            }
        elif "-all" in rec_lower:
            return {
                "found": True,
                "record": spf_record,
                "severity": "Low",
                "status": "Compliant",
                "finding": "Strict `-all` (HardFail) enforcement active. Unauthorized senders will be rejected.",
                "recommendation": "Maintain SPF inclusion list and monitor authentication logs."
            }

        return {
            "found": True,
            "record": spf_record,
            "severity": "Low",
            "status": "Compliant",
            "finding": "SPF record present and active.",
            "recommendation": "Review SPF syntax periodically."
        }

    def _analyze_dmarc(self, domain: str, dmarc_records: List[str]) -> Dict[str, Any]:
        """Evaluate DMARC policy and enforcement strength."""
        dmarc_record = next((r for r in dmarc_records if "v=dmarc1" in r.lower()), None)
        if not dmarc_record:
            return {
                "found": False,
                "record": "None",
                "severity": "High",
                "status": "Missing",
                "finding": f"No DMARC policy record found at `_dmarc.{domain}`. Phishing and domain spoofing cannot be monitored or blocked.",
                "recommendation": f"Publish a DMARC TXT record at `_dmarc.{domain}` with `p=quarantine` or `p=reject`."
            }

        rec_lower = dmarc_record.lower()
        if "p=reject" in rec_lower:
            return {
                "found": True,
                "record": dmarc_record,
                "severity": "Low",
                "status": "Compliant",
                "finding": "DMARC policy is set to `p=reject` (Strict Enforcement). Spoofed emails are blocked at receiving mail servers.",
                "recommendation": "Ensure `rua=` aggregate reporting URI is actively monitored for delivery anomalies."
            }
        elif "p=quarantine" in rec_lower:
            return {
                "found": True,
                "record": dmarc_record,
                "severity": "Medium",
                "status": "Warning",
                "finding": "DMARC policy is set to `p=quarantine`. Spoofed emails are moved to spam folders rather than rejected.",
                "recommendation": "Gradually transition policy from `p=quarantine` to `p=reject`."
            }
        elif "p=none" in rec_lower:
            return {
                "found": True,
                "record": dmarc_record,
                "severity": "Medium",
                "status": "Warning",
                "finding": "DMARC policy is set to `p=none` (Monitoring Only). No enforcement or quarantine takes place on spoofed emails.",
                "recommendation": "Upgrade DMARC policy from `p=none` to `p=quarantine` or `p=reject`."
            }

        return {
            "found": True,
            "record": dmarc_record,
            "severity": "Low",
            "status": "Compliant",
            "finding": "DMARC record present.",
            "recommendation": "Verify report recipient endpoints."
        }

    def _analyze_takeover(self, cname_records: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Identify CNAME targets that point to third-party services susceptible to subdomain takeover."""
        findings = []
        for cname_obj in cname_records:
            cname = cname_obj.get("data", "").rstrip(".").lower()
            name = cname_obj.get("name", "")
            for indicator, service in TAKEOVER_INDICATORS.items():
                if cname.endswith(indicator):
                    findings.append({
                        "subdomain": name or "Target Host",
                        "cname": cname,
                        "service": service,
                        "severity": "High",
                        "status": "Warning",
                        "finding": f"Points to {service} ({cname}). If this external resource is deleted or unclaimed, an attacker can claim it to hijack the subdomain.",
                        "recommendation": f"Verify ownership in {service} console or remove obsolete CNAME pointer."
                    })
        return findings

    # ── Report Builder ──────────────────────────────────────────────────────

    def _build_report(
        self,
        target: str,
        domain: str,
        a_records: List[Dict[str, Any]],
        aaaa_records: List[Dict[str, Any]],
        mx_records: List[Dict[str, Any]],
        txt_records: List[Dict[str, Any]],
        ns_records: List[Dict[str, Any]],
        cname_records: List[Dict[str, Any]],
        soa_records: List[Dict[str, Any]],
        dmarc_records: List[Dict[str, Any]],
        ip_info: Dict[str, Any],
        resolved_ip: Optional[str],
        ptr_host: str,
    ) -> str:
        lines: List[str] = []

        # ── Executive Header ──
        lines.append(f"# Network Reconnaissance Intelligence Report")
        lines.append("")
        lines.append(f"**Target Host:** `{domain}`  ")
        lines.append(f"**Primary IPv4 Origin:** `{resolved_ip or 'Unresolved'}`  ")
        lines.append(f"**Autonomous System:** `{ip_info.get('asn', 'N/A')} ({ip_info.get('org', 'N/A')})`  ")
        lines.append(f"**Hosting Location:** `{ip_info.get('city', 'Unknown')}, {ip_info.get('country', 'Unknown')}`  ")
        lines.append("")

        # ── Section 1: DNS Records & Infrastructure Matrix ──
        lines.append("## DNS Configuration & Infrastructure Matrix")
        lines.append("")
        lines.append("| Record Type | Subdomain / Name | Resolved Target / Data | TTL | Status |")
        lines.append("|---|---|---|---|---|")

        has_dns_records = False

        for r in a_records:
            has_dns_records = True
            lines.append(f"| A (IPv4) | `{r.get('name', domain)}` | `{r.get('data')}` | {r.get('ttl')}s | Active |")

        for r in aaaa_records:
            has_dns_records = True
            lines.append(f"| AAAA (IPv6) | `{r.get('name', domain)}` | `{r.get('data')}` | {r.get('ttl')}s | Active |")

        for r in mx_records:
            has_dns_records = True
            lines.append(f"| MX (Mail Exchanger) | `{r.get('name', domain)}` | `{r.get('data')}` | {r.get('ttl')}s | Active |")

        for r in ns_records:
            has_dns_records = True
            lines.append(f"| NS (Nameserver) | `{r.get('name', domain)}` | `{r.get('data')}` | {r.get('ttl')}s | Active |")

        for r in cname_records:
            has_dns_records = True
            lines.append(f"| CNAME (Canonical) | `{r.get('name', domain)}` | `{r.get('data')}` | {r.get('ttl')}s | Active |")

        for r in soa_records:
            has_dns_records = True
            soa_preview = r.get('data', '')[:48] + "..." if len(r.get('data', '')) > 48 else r.get('data', '')
            lines.append(f"| SOA (Zone Authority) | `{r.get('name', domain)}` | `{soa_preview}` | {r.get('ttl')}s | Active |")

        for r in txt_records:
            has_dns_records = True
            txt_preview = r.get('data', '')[:65] + "..." if len(r.get('data', '')) > 65 else r.get('data', '')
            lines.append(f"| TXT (Text Record) | `{r.get('name', domain)}` | `{txt_preview}` | {r.get('ttl')}s | Active |")

        if not has_dns_records:
            lines.append(f"| DNS Records | `{domain}` | No public DNS records found | N/A | Missing |")

        lines.append("")

        # ── Section 2: IP Geolocation & ASN Intelligence ──
        lines.append("## Geolocation & ASN Intelligence")
        lines.append("")
        lines.append("| Intelligence Attribute | Resolved Value | Operational & Security Context |")
        lines.append("|---|---|---|")
        lines.append(f"| Primary IPv4 Address | `{resolved_ip or 'N/A'}` | Origin gateway resolved via authoritative DNS |")
        lines.append(f"| Reverse DNS (PTR) | `{ptr_host}` | PTR hostname verification for origin IP |")
        lines.append(f"| Autonomous System (ASN) | `{ip_info.get('asn', 'N/A')}` | Network routing autonomous system identifier |")
        lines.append(f"| Organization / Cloud | `{ip_info.get('org', 'N/A')}` | Infrastructure provider hosting origin servers |")
        lines.append(f"| Internet Service Provider (ISP) | `{ip_info.get('isp', 'N/A')}` | Upstream network carrier |")
        lines.append(f"| Geographic Location | `{ip_info.get('city', 'Unknown')}, {ip_info.get('region', 'Unknown')}, {ip_info.get('country', 'Unknown')}` | Origin datacenter regional jurisdiction |")
        lines.append(f"| Geographic Coordinates | `Lat: {ip_info.get('latitude', 'N/A')}, Lon: {ip_info.get('longitude', 'N/A')}` | Approximate point of presence coordinates |")
        lines.append(f"| Timezone | `{ip_info.get('timezone', 'UTC')}` | Local server operations timezone |")
        lines.append(f"| Network Subnet CIDR | `{ip_info.get('network', 'N/A')}` | Border Gateway Protocol (BGP) routing block |")
        lines.append("")

        # ── Section 3: Email Security & Domain Defense Posture ──
        raw_txt_strings = [r.get("data", "") for r in txt_records]
        raw_dmarc_strings = [r.get("data", "") for r in dmarc_records]

        spf_eval = self._analyze_spf(raw_txt_strings)
        dmarc_eval = self._analyze_dmarc(domain, raw_dmarc_strings)
        takeover_eval = self._analyze_takeover(cname_records)

        lines.append("## Email & Domain Security Posture")
        lines.append("")
        lines.append("| Security Control | Configured Policy / Record | Severity | Compliance Status | Risk Impact & Hardening Recommendation |")
        lines.append("|---|---|---|---|---|")

        # SPF Row
        spf_display = spf_eval['record'][:45] + "..." if len(spf_eval['record']) > 45 else spf_eval['record']
        lines.append(f"| SPF (Sender Policy Framework) | `{spf_display}` | {spf_eval['severity']} | {spf_eval['status']} | {spf_eval['finding']} {spf_eval['recommendation']} |")

        # DMARC Row
        dmarc_display = dmarc_eval['record'][:45] + "..." if len(dmarc_eval['record']) > 45 else dmarc_eval['record']
        lines.append(f"| DMARC Policy (`_dmarc`) | `{dmarc_display}` | {dmarc_eval['severity']} | {dmarc_eval['status']} | {dmarc_eval['finding']} {dmarc_eval['recommendation']} |")

        # Subdomain Takeover Rows
        if takeover_eval:
            for item in takeover_eval:
                lines.append(f"| Subdomain Takeover Check | `{item['cname']}` ({item['service']}) | {item['severity']} | {item['status']} | {item['finding']} {item['recommendation']} |")
        else:
            lines.append(f"| Subdomain Takeover Check | `No dangling CNAMEs` | Low | Compliant | All canonical names point to active internal services. No dangling indicators found. |")

        lines.append("")

        # ── Section 4: Executive Findings & Remediation ──
        lines.append("## Reconnaissance Summary & Action Items")
        lines.append("")
        lines.append("| Priority | Vulnerability / Exposure Area | Impact Description | Remediation Step |")
        lines.append("|---|---|---|---|")

        findings_count = 0
        if spf_eval["status"] != "Compliant":
            findings_count += 1
            lines.append(f"| Priority {findings_count} | SPF Policy Configuration | {spf_eval['finding']} | {spf_eval['recommendation']} |")

        if dmarc_eval["status"] != "Compliant":
            findings_count += 1
            lines.append(f"| Priority {findings_count} | DMARC Email Security | {dmarc_eval['finding']} | {dmarc_eval['recommendation']} |")

        for item in takeover_eval:
            findings_count += 1
            lines.append(f"| Priority {findings_count} | Subdomain Takeover Risk ({item['service']}) | {item['finding']} | {item['recommendation']} |")

        if findings_count == 0:
            lines.append(f"| Standard | DNS & Perimeter Hardening | Zero critical DNS or email routing vulnerabilities identified during reconnaissance. | Continue monitoring DNS zones and certificate expiries periodically. |")

        lines.append("")
        return "\n".join(lines)

    # ── Main Entry Point ────────────────────────────────────────────────────

    def _run(self, target: str) -> str:
        """
        Perform complete DNS and IP reconnaissance on the given domain or IP address.
        Returns a clean, structured executive markdown report.
        """
        clean_host = self._clean_target(target)
        if not clean_host:
            clean_host = target.strip()

        is_ip = self._is_ipv4(clean_host)
        domain = clean_host
        resolved_ip = clean_host if is_ip else None

        # Query all DNS record types
        a_data     = self._query_dns(domain, "A")
        aaaa_data  = self._query_dns(domain, "AAAA")
        mx_data    = self._query_dns(domain, "MX")
        txt_data   = self._query_dns(domain, "TXT")
        ns_data    = self._query_dns(domain, "NS")
        cname_data = self._query_dns(domain, "CNAME")
        soa_data   = self._query_dns(domain, "SOA")

        dmarc_sub = f"_dmarc.{domain}" if not is_ip else domain
        dmarc_data = self._query_dns(dmarc_sub, "TXT")

        a_records     = self._extract_answers(a_data)
        aaaa_records  = self._extract_answers(aaaa_data)
        mx_records    = self._extract_answers(mx_data)
        txt_records   = self._extract_answers(txt_data)
        ns_records    = self._extract_answers(ns_data)
        cname_records = self._extract_answers(cname_data)
        soa_records   = self._extract_answers(soa_data)
        dmarc_records = self._extract_answers(dmarc_data)

        # Resolve primary IPv4 if domain
        if not resolved_ip and a_records:
            for r in a_records:
                ip_cand = r.get("data", "")
                if self._is_ipv4(ip_cand):
                    resolved_ip = ip_cand
                    break

        # If DNS API didn't return IPv4, try socket
        if not resolved_ip and not is_ip:
            try:
                resolved_ip = socket.gethostbyname(domain)
            except Exception:
                resolved_ip = None

        # IP Geolocation & ASN
        ip_info = self._query_ip_geo(resolved_ip) if resolved_ip else {
            "ip": "Unresolved",
            "city": "Unknown",
            "region": "Unknown",
            "country": "Unknown",
            "country_code": "XX",
            "postal": "N/A",
            "latitude": "N/A",
            "longitude": "N/A",
            "timezone": "UTC",
            "org": "N/A",
            "asn": "N/A",
            "isp": "N/A",
            "network": "N/A",
        }

        # Reverse PTR
        ptr_host = self._query_ptr(resolved_ip) if resolved_ip else "N/A"

        return self._build_report(
            target=target,
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
            mx_records=mx_records,
            txt_records=txt_records,
            ns_records=ns_records,
            cname_records=cname_records,
            soa_records=soa_records,
            dmarc_records=dmarc_records,
            ip_info=ip_info,
            resolved_ip=resolved_ip,
            ptr_host=ptr_host,
        )
