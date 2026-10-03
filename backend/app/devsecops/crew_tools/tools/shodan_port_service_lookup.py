from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Tuple
from urllib.parse import urlparse
import requests
import socket

# --- Port-to-service name mapping ---
PORT_SERVICE_MAP: Dict[int, str] = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Shell)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name Service)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail Access)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Encrypted Web Traffic)",
    465: "SMTPS (Secure Mail)",
    587: "SMTP Submission",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    2052: "Cloudflare HTTP",
    2082: "cPanel HTTP",
    2083: "cPanel HTTPS",
    2086: "WHM HTTP",
    2087: "WHM HTTPS",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Database",
    8080: "HTTP Proxy / Alternate Web",
    8443: "HTTPS Alternate Web",
    9200: "Elasticsearch REST API",
    27017: "MongoDB Database",
}

# --- High-risk ports with severity and actionable recommendations ---
HIGH_RISK_PORTS: Dict[int, Tuple[str, str, str, str]] = {
    21: ("FTP", "Medium", "Plaintext authentication protocol; credentials and transferred files transmitted unencrypted.", "Disable FTP and migrate to SFTP (port 22) or FTPS with enforced TLS."),
    23: ("Telnet", "Critical", "Telnet transmits all sessions in cleartext. Trivial credential capture and session hijacking.", "Immediately disable Telnet daemon and replace with SSH."),
    3306: ("MySQL", "High", "Database port exposed directly to the public internet. High risk of brute-force and credential stuffing.", "Restrict access to internal VPC subnet or use SSH bastion / VPN tunnels."),
    3389: ("RDP", "High", "Remote Desktop Protocol exposed publicly. Primary target for automated ransomware and brute-force attacks.", "Place RDP behind MFA-protected VPN or Remote Desktop Gateway."),
    5432: ("PostgreSQL", "High", "PostgreSQL database port accessible publicly. Direct attack surface for database exploitation.", "Bind PostgreSQL to localhost or private network interfaces only."),
    6379: ("Redis", "Critical", "Redis cache/database exposed publicly. Frequently runs unauthenticated, allowing arbitrary data dumps or remote code execution.", "Enforce AUTH passwords, bind to 127.0.0.1, or place behind firewall."),
    9200: ("Elasticsearch", "Critical", "Elasticsearch API endpoint exposed. Unauthenticated access may leak all indexed documents and cluster metadata.", "Enable Elastic Security (TLS & Role-Based Auth) and restrict to private network."),
    27017: ("MongoDB", "Critical", "MongoDB port exposed to internet. Major target for automated database wiping and ransom campaigns.", "Enable authentication (`--auth`) and bind only to internal loopback / VPC."),
}

NVD_BASE_URL = "https://nvd.nist.gov/vuln/detail/"
SHODAN_INTERNETDB = "https://internetdb.shodan.io/{ip}"
GOOGLE_DNS_URL = "https://dns.google/resolve?name={domain}&type=A"


class ShodanPortServiceLookupInput(BaseModel):
    """Input schema for Shodan Port and Service Lookup Tool."""
    host: str = Field(
        ...,
        description="The target host to investigate. Can be an IPv4 address (e.g. '8.8.8.8') or a domain name (e.g. 'example.com').",
    )


class ShodanPortServiceLookupTool(BaseTool):
    """Tool for querying Shodan InternetDB to retrieve open ports, services, CVEs, and tags for a host."""

    name: str = "Shodan Port and Service Lookup"
    description: str = (
        "Queries Shodan InternetDB for a given IP or domain. "
        "Reports open ports, identified services, software CPEs, known CVEs with NVD links, "
        "hostnames, and risk tags. Returns a structured executive markdown table report."
    )
    args_schema: Type[BaseModel] = ShodanPortServiceLookupInput

    # ──────────────────────────────────────────────────────────────────
    #  Internal helpers
    # ──────────────────────────────────────────────────────────────────

    def _clean_host(self, host: str) -> str:
        """Extract clean domain or IP from input string."""
        raw = host.strip()
        if "://" in raw:
            parsed = urlparse(raw)
            clean = parsed.netloc or parsed.path
        else:
            clean = raw.split("/")[0]
        if ":" in clean and not clean.startswith("["):
            clean = clean.split(":")[0]
        return clean.strip().lower()

    def _is_ip(self, host: str) -> bool:
        """Return True if host is an IPv4 address."""
        parts = host.split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    def _resolve_domain(self, domain: str) -> str:
        """Resolve domain to IPv4 address."""
        url = GOOGLE_DNS_URL.format(domain=domain)
        try:
            resp = requests.get(url, timeout=8)
            resp.raise_for_status()
            data = resp.json()
            answers = data.get("Answer", [])
            a_records = [a["data"] for a in answers if a.get("type") == 1]
            if a_records:
                return a_records[0]
        except Exception:
            pass

        # Fallback to standard socket resolution
        try:
            return socket.gethostbyname(domain)
        except Exception as exc:
            raise ConnectionError(f"DNS resolution failed for '{domain}': {exc}") from exc

    def _query_internetdb(self, ip: str) -> dict:
        """Fetch Shodan InternetDB data for IP."""
        url = SHODAN_INTERNETDB.format(ip=ip)
        try:
            resp = requests.get(url, timeout=8, headers={"User-Agent": "CyberShield-Shodan/2.0"})
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as exc:
            raise ConnectionError(f"Shodan InternetDB query failed for '{ip}': {exc}") from exc

    # ──────────────────────────────────────────────────────────────────
    #  Report builder
    # ──────────────────────────────────────────────────────────────────

    def _build_report(self, host: str, ip: str, data: dict) -> str:
        lines: List[str] = []

        # ── Executive Header ──
        lines.append("# Perimeter Attack Surface & Shodan Intelligence")
        lines.append("")
        lines.append(f"**Target Host:** `{host}`  ")
        lines.append(f"**Resolved Endpoint IP:** `{ip}`  ")
        lines.append(f"**Database Feed:** `Shodan InternetDB Threat Intelligence`  ")
        lines.append("")

        # ── Case: No Open Ports / Shielded Host ──
        if not data:
            lines.append("## Public Port Exposure & Network Perimeter")
            lines.append("")
            lines.append("| Security Parameter | Assessment Result | Architectural & Defense Context |")
            lines.append("|---|---|---|")
            lines.append(f"| Perimeter Status | `Clean` | Normal | No public open listening ports exposed in Shodan global telemetry |")
            lines.append(f"| Edge Protection | `Protected` | Normal | Origin IP is filtered, offline, or shielded behind an edge CDN / WAF |")
            lines.append(f"| Public CVE Exposure | `Clean` | Normal | Zero public CVEs tied to exposed network daemons on this IP |")
            lines.append("")
            return "\n".join(lines)

        ports = sorted(data.get("ports", []))
        hostnames = data.get("hostnames", [])
        tags = data.get("tags", [])
        cpes = data.get("cpes", [])
        vulns = sorted(data.get("vulns", []))

        # ── Section 1: Open Ports Matrix ──
        lines.append("## Public Port Exposure & Network Perimeter")
        lines.append("")
        lines.append("| Port | Protocol & Service | Risk Level | Status | Exposure Analysis & Recommendation |")
        lines.append("|---|---|---|---|---|")

        if ports:
            for port in ports:
                service = PORT_SERVICE_MAP.get(port, f"Port {port}")
                if port in HIGH_RISK_PORTS:
                    _, severity, desc, rec = HIGH_RISK_PORTS[port]
                    lines.append(f"| `{port}` | {service} | {severity} | Warning | {desc} {rec} |")
                elif port in (80, 443, 8080, 8443, 2052, 2082, 2083, 2086, 2087):
                    lines.append(f"| `{port}` | {service} | Low | Active | Standard web application traffic. Ensure TLS encryption and HTTP to HTTPS redirection. |")
                elif port in (22, 53, 123):
                    lines.append(f"| `{port}` | {service} | Low | Active | Administrative / core network service. Ensure strong authentication and disable root login. |")
                else:
                    lines.append(f"| `{port}` | {service} | Medium | Active | Non-standard exposed port. Verify whether this service must remain publicly accessible. |")
        else:
            lines.append("| Open Ports | None Detected | Low | Clean | No open ports cataloged on public InternetDB scan. |")

        lines.append("")

        # ── Section 2: Detected Software & CPEs ──
        if cpes:
            lines.append("## Software Fingerprints & CPE Identifiers")
            lines.append("")
            lines.append("| Component / Vendor | CPE Identifier | Status | Security Posture |")
            lines.append("|---|---|---|---|")
            for cpe in cpes:
                parts = cpe.split(":")
                vendor = parts[2] if len(parts) > 2 else "Unknown"
                product = parts[3] if len(parts) > 3 else "Unknown"
                version = parts[4] if len(parts) > 4 else "N/A"
                label = f"{vendor.capitalize()} {product}" if vendor != "Unknown" else cpe
                if version != "N/A":
                    label += f" ({version})"
                lines.append(f"| {label} | `{cpe}` | Monitored | Detected in perimeter network banner |")
            lines.append("")

        # ── Section 3: Known CVE Vulnerabilities ──
        if vulns:
            lines.append("## Known Vulnerabilities & CVE Advisories")
            lines.append("")
            lines.append("| CVE Identifier | Severity | Advisory Context | Reference Link |")
            lines.append("|---|---|---|---|")
            for cve in vulns[:15]:  # Show top 15 CVEs cleanly
                lines.append(f"| `{cve}` | High | Known security advisory cataloged against running daemon | [NVD Advisory ({cve})]({NVD_BASE_URL}{cve}) |")
            if len(vulns) > 15:
                lines.append(f"| `+{len(vulns) - 15} Additional CVEs` | Medium | Additional known vulnerabilities associated with outdated software stack | Review full NVD catalog |")
            lines.append("")
        else:
            lines.append("## Known Vulnerabilities & CVE Advisories")
            lines.append("")
            lines.append("| Vulnerability Check | Assessment Result | Status | Security Impact |")
            lines.append("|---|---|---|---|")
            lines.append("| Perimeter CVE Audit | Zero Known Exploits | Clean | No public CVEs associated with running network software in Shodan database |")
            lines.append("")

        # ── Section 4: Hostnames & Threat Tags ──
        if hostnames or tags:
            lines.append("## Hostnames & Threat Classification")
            lines.append("")
            lines.append("| Category | Identifier / Value | Classification | Context |")
            lines.append("|---|---|---|---|")
            for hn in hostnames:
                lines.append(f"| Associated Hostname | `{hn}` | Network Alias | DNS reverse mapping detected by internet crawlers |")
            for tag in tags:
                lines.append(f"| Threat Tag | `{tag}` | Fingerprint | Shodan automated categorization flag |")
            lines.append("")

        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────
    #  Entry point
    # ──────────────────────────────────────────────────────────────────

    def _run(self, host: str) -> str:
        """
        Resolve host to IP, query Shodan InternetDB, and return a clean structured report.
        """
        clean_target = self._clean_host(host)
        if not clean_target:
            clean_target = host.strip()

        # Step 1: Resolve domain to IP if necessary
        try:
            if self._is_ip(clean_target):
                ip = clean_target
            else:
                ip = self._resolve_domain(clean_target)
        except Exception as exc:
            return f"""# Perimeter Attack Surface & Shodan Intelligence

**Target Host:** `{clean_target}`  
**Status:** `Resolution Failure`  

## Perimeter Assessment
| Parameter | Value | Status | Operational Context |
|---|---|---|---|
| Domain Resolution | Failed | Error | Could not resolve domain to IPv4: {str(exc)} |
"""

        # Step 2: Query Shodan InternetDB
        try:
            data = self._query_internetdb(ip)
        except Exception as exc:
            return f"""# Perimeter Attack Surface & Shodan Intelligence

**Target Host:** `{clean_target}`  
**Resolved IP:** `{ip}`  

## Perimeter Assessment
| Parameter | Value | Status | Operational Context |
|---|---|---|---|
| Shodan Lookup | Failed | Error | Shodan API lookup encountered an error: {str(exc)} |
"""

        # Step 3: Build and return structured report
        return self._build_report(clean_target, ip, data)
