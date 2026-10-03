
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type
import requests


# --- Port-to-service name mapping ---
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

# --- High-risk ports with severity ---
HIGH_RISK_PORTS = {
    23:    ("Telnet",        "🔴 CRITICAL – Telnet transmits data in plaintext; immediately exploitable."),
    6379:  ("Redis",         "🔴 CRITICAL – Redis often runs unauthenticated; full data exposure risk."),
    9200:  ("Elasticsearch", "🔴 CRITICAL – Elasticsearch may expose all indexed data without auth."),
    27017: ("MongoDB",       "🔴 CRITICAL – MongoDB can be openly readable/writable without auth."),
    3389:  ("RDP",           "🟠 HIGH – RDP is a frequent target for brute-force and ransomware attacks."),
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
        "Queries the free Shodan InternetDB API (no API key needed) for a given IP or domain. "
        "Resolves domains via Google DNS, then reports open ports (with service names), "
        "detected software (CPEs), known CVEs (with NVD links), hostnames, and risk tags. "
        "High-risk ports such as Telnet, Redis, Elasticsearch, MongoDB, and RDP are flagged "
        "with severity ratings. Returns a structured Markdown security report."
    )
    args_schema: Type[BaseModel] = ShodanPortServiceLookupInput

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _is_ip(self, host: str) -> bool:
        """Return True if *host* looks like an IPv4 address."""
        parts = host.strip().split(".")
        if len(parts) != 4:
            return False
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

    def _resolve_domain(self, domain: str) -> str:
        """Resolve *domain* to an IPv4 address via Google's DNS-over-HTTPS API."""
        url = GOOGLE_DNS_URL.format(domain=domain)
        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            answers = data.get("Answer", [])
            # Filter for A records (type 1)
            a_records = [a["data"] for a in answers if a.get("type") == 1]
            if not a_records:
                raise ValueError(f"No A records found for domain '{domain}'.")
            return a_records[0]
        except requests.exceptions.RequestException as exc:
            raise ConnectionError(f"DNS resolution failed for '{domain}': {exc}") from exc

    def _query_internetdb(self, ip: str) -> dict:
        """Fetch Shodan InternetDB data for *ip*."""
        url = SHODAN_INTERNETDB.format(ip=ip)
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 404:
                return {}   # No data for this IP
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.RequestException as exc:
            raise ConnectionError(f"Shodan InternetDB query failed for '{ip}': {exc}") from exc

    # ------------------------------------------------------------------ #
    #  Report builder                                                      #
    # ------------------------------------------------------------------ #

    def _build_report(self, host: str, ip: str, data: dict) -> str:
        lines: list[str] = []

        lines.append("# 🔍 Shodan Port & Service Lookup Report")
        lines.append("")
        lines.append(f"| Field        | Value |")
        lines.append(f"|--------------|-------|")
        lines.append(f"| **Target**   | `{host}` |")
        lines.append(f"| **Resolved IP** | `{ip}` |")
        lines.append("")

        # ── No data ────────────────────────────────────────────────────
        if not data:
            lines.append("> ℹ️ **No information found in Shodan InternetDB for this IP.**")
            lines.append(">")
            lines.append("> The host may be offline, not indexed, or have no open ports detected.")
            return "\n".join(lines)

        # ── Hostnames ──────────────────────────────────────────────────
        hostnames = data.get("hostnames", [])
        lines.append("## 🌐 Hostnames")
        if hostnames:
            for hn in hostnames:
                lines.append(f"- `{hn}`")
        else:
            lines.append("- *(none detected)*")
        lines.append("")

        # ── Tags ───────────────────────────────────────────────────────
        tags = data.get("tags", [])
        lines.append("## 🏷️ Tags")
        if tags:
            lines.append(" ".join(f"`{t}`" for t in tags))
        else:
            lines.append("*(none)*")
        lines.append("")

        # ── Open Ports ─────────────────────────────────────────────────
        ports = sorted(data.get("ports", []))
        lines.append("## 🔓 Open Ports")
        if ports:
            lines.append("| Port | Service | Risk |")
            lines.append("|------|---------|------|")
            for port in ports:
                service = PORT_SERVICE_MAP.get(port, "Unknown")
                if port in HIGH_RISK_PORTS:
                    _, risk_msg = HIGH_RISK_PORTS[port]
                    risk_cell = risk_msg
                else:
                    risk_cell = "✅ Normal"
                lines.append(f"| `{port}` | {service} | {risk_cell} |")
        else:
            lines.append("*(no open ports detected)*")
        lines.append("")

        # ── High-Risk Summary ──────────────────────────────────────────
        risky = [p for p in ports if p in HIGH_RISK_PORTS]
        if risky:
            lines.append("## ⚠️ High-Risk Port Summary")
            for port in risky:
                svc, msg = HIGH_RISK_PORTS[port]
                lines.append(f"- **Port {port} ({svc})**: {msg}")
            lines.append("")

        # ── CPEs / Software ────────────────────────────────────────────
        cpes = data.get("cpes", [])
        lines.append("## 🧩 Detected Software / CPEs")
        if cpes:
            for cpe in cpes:
                lines.append(f"- `{cpe}`")
        else:
            lines.append("*(no CPE data available)*")
        lines.append("")

        # ── CVEs ───────────────────────────────────────────────────────
        vulns = data.get("vulns", [])
        lines.append("## 🛡️ Known Vulnerabilities (CVEs)")
        if vulns:
            lines.append(f"> **{len(vulns)} CVE(s) associated with this host.**")
            lines.append("")
            lines.append("| CVE ID | NVD Link |")
            lines.append("|--------|----------|")
            for cve in sorted(vulns):
                nvd_link = f"[{cve}]({NVD_BASE_URL}{cve})"
                lines.append(f"| `{cve}` | {nvd_link} |")
        else:
            lines.append("✅ No known CVEs associated with this IP in Shodan InternetDB.")
        lines.append("")

        # ── Footer ─────────────────────────────────────────────────────
        lines.append("---")
        lines.append("*Data sourced from [Shodan InternetDB](https://internetdb.shodan.io) — no API key required.*")

        return "\n".join(lines)

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def _run(self, host: str) -> str:
        """
        Resolve *host* to an IP (if needed), query Shodan InternetDB,
        and return a structured Markdown security report.
        """
        host = host.strip()

        # Step 1 – Resolve domain to IP if necessary
        try:
            if self._is_ip(host):
                ip = host
            else:
                ip = self._resolve_domain(host)
        except (ValueError, ConnectionError) as exc:
            return f"❌ **DNS Resolution Error:** {exc}"

        # Step 2 – Query Shodan InternetDB
        try:
            data = self._query_internetdb(ip)
        except ConnectionError as exc:
            return f"❌ **Shodan Query Error:** {exc}"

        # Step 3 – Build and return the Markdown report
        return self._build_report(host, ip, data)
