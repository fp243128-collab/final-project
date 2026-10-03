from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Set, Any
import requests
import re
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------------------------
# Input Schema
# ---------------------------------------------------------------------------

class MetadataExtractorInput(BaseModel):
    """Input schema for Metadata and Information Disclosure Extractor Tool."""
    url: str = Field(..., description="The target URL to analyse (e.g. https://example.com)")


# ---------------------------------------------------------------------------
# Regex Patterns & Dictionaries
# ---------------------------------------------------------------------------

FLAGGED_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-aspnet-version",
    "via", "cf-ray", "x-cache", "www-authenticate", "x-runtime",
    "x-backend-server", "x-served-by", "x-version",
]

TECH_KEYWORDS: Dict[str, Dict[str, Any]] = {
    "WordPress": {
        "signals": ["wp-content", "wp-includes", "wordpress"],
        "category": "Content Management System (CMS)",
        "implication": "Verify plugin and theme versions for known CVEs.",
    },
    "Drupal": {
        "signals": ["drupal", "/sites/default/files/"],
        "category": "Content Management System (CMS)",
        "implication": "Review Drupal core update level and module permissions.",
    },
    "Joomla": {
        "signals": ["joomla", "/components/com_"],
        "category": "Content Management System (CMS)",
        "implication": "Ensure administrative backend directory is shielded.",
    },
    "Laravel": {
        "signals": ["laravel", "laravel_session", "XSRF-TOKEN"],
        "category": "Backend Framework (PHP)",
        "implication": "Ensure APP_DEBUG is set to false in production.",
    },
    "Django": {
        "signals": ["django", "csrfmiddlewaretoken", "sessionid"],
        "category": "Backend Framework (Python)",
        "implication": "Verify DEBUG=False and allowed hosts are strictly defined.",
    },
    "Next.js": {
        "signals": ["_next/static", "__NEXT_DATA__", "_next/image"],
        "category": "Fullstack Framework (React/SSR)",
        "implication": "Ensure server actions and API routes enforce authorization.",
    },
    "React": {
        "signals": ["react.js", "react.min.js", "react-dom", "data-reactroot"],
        "category": "Frontend UI Library",
        "implication": "Audit client-side bundles for hardcoded API keys and secrets.",
    },
    "Angular": {
        "signals": ["ng-version", "angular.js", "angular.min.js", "ng-app"],
        "category": "Frontend Framework (Google)",
        "implication": "Review template expressions for client-side XSS vectors.",
    },
    "Vue.js": {
        "signals": ["vue.js", "vue.min.js", "__vue__", "data-v-"],
        "category": "Frontend UI Framework",
        "implication": "Validate component data binding and router guards.",
    },
    "jQuery": {
        "signals": ["jquery.js", "jquery.min.js", "jquery-"],
        "category": "JavaScript Utility Library",
        "implication": "Ensure jQuery is >= 3.5.0 to mitigate DOM XSS flaws.",
    },
    "Bootstrap": {
        "signals": ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
        "category": "CSS / UI Component Framework",
        "implication": "Standard UI framework; low risk.",
    },
    "Tailwind CSS": {
        "signals": ["tailwindcss", "tailwind.css"],
        "category": "Utility-First CSS Framework",
        "implication": "Standard CSS framework; no direct vulnerability.",
    },
}

VERSION_PATTERN  = re.compile(r'(jquery|bootstrap|react|vue|angular|lodash|moment|axios)[.\-](\d+\.\d+(?:\.\d+)?)', re.IGNORECASE)
META_TAG_PATTERN = re.compile(r'<meta\s+([^>]+)>', re.IGNORECASE)
TITLE_PATTERN    = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
ATTR_PATTERN     = re.compile(r'(\w[\w\-:]*)=["\']([^"\']*)["\']')

EMAIL_PATTERN    = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
AWS_KEY_PATTERN  = re.compile(r'AKIA[0-9A-Z]{16}')
JWT_PATTERN      = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+')
IP_PATTERN       = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMENT_PATTERN  = re.compile(r'<!--(.*?)-->', re.DOTALL)
PRIVKEY_PATTERN  = re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')
APIKEY_PATTERN   = re.compile(r'(?:api_key|apikey|api-key|secret_key|app_secret|auth_token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})', re.IGNORECASE)
GA_PATTERN       = re.compile(r'\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,})\b')
FB_PIXEL_PATTERN = re.compile(r'facebook\.com/tr\?|fbq\(|_fbq')
GTM_PATTERN      = re.compile(r'\b(GTM-[A-Z0-9]{4,10})\b')
HREF_SRC_PATTERN = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.IGNORECASE)

IP_FALSE_POSITIVES = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.0", "1.1.1.1", "8.8.8.8"
}

def _is_valid_ipv4(ip_str: str) -> bool:
    try:
        parts = ip_str.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or not (0 <= int(p) <= 255):
                return False
            if len(p) > 1 and p.startswith("0"):  # leading zero like 037 is not standard IP
                return False
        return ip_str not in IP_FALSE_POSITIVES
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tool Class
# ---------------------------------------------------------------------------

class MetadataInformationDisclosureExtractorTool(BaseTool):
    """Tool for extracting metadata and sensitive information disclosures from a URL."""

    name: str = "Metadata and Information Disclosure Extractor"
    description: str = (
        "Performs comprehensive metadata and information-disclosure analysis on a given URL. "
        "Audits HTTP headers, HTML meta tags, technology fingerprints, sensitive data patterns "
        "(emails, AWS keys, JWTs, private keys, API keys, IPs), HTML comments, and link inventory. "
        "Returns a structured dual-axis tabular security report."
    )
    args_schema: Type[BaseModel] = MetadataExtractorInput

    def _mask_secret(self, val: str) -> str:
        if len(val) <= 8:
            return "********"
        return f"{val[:4]}{'*' * (len(val) - 8)}{val[-4:]}"

    def _run(self, url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc.lower()

        try:
            response = requests.get(
                url,
                timeout=12,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                },
                allow_redirects=True,
                verify=False,
            )
        except Exception as exc:
            return f"""# Metadata & Information Disclosure Report
**Target System:** `{url}`

## Inspection Status Matrix
| Metric | Status | Detail |
|---|---|---|
| Scan Execution | Failed | Unable to establish connection: {str(exc)[:100]} |
| Target Reachability | Unreachable | Target server did not respond within timeout |
"""

        raw_html = response.text
        headers = response.headers
        status = response.status_code
        final_url = response.url

        # 1. Parse Meta Tags
        meta_tags_raw = META_TAG_PATTERN.findall(raw_html)
        named_metas: Dict[str, str] = {}
        for tag_attr_str in meta_tags_raw:
            attrs = dict(ATTR_PATTERN.findall(tag_attr_str))
            name = attrs.get("name") or attrs.get("property") or attrs.get("http-equiv") or ""
            content = attrs.get("content") or ""
            if name and content:
                named_metas[name.lower()] = content

        title_match = TITLE_PATTERN.search(raw_html)
        page_title = title_match.group(1).strip() if title_match else "None / Undefined"

        # 2. Technology Fingerprints
        combined_text = raw_html.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        detected_tech = []
        for tech_name, tech_info in TECH_KEYWORDS.items():
            if any(sig.lower() in combined_text for sig in tech_info["signals"]):
                detected_tech.append({
                    "name": tech_name,
                    "category": tech_info["category"],
                    "vector": "DOM Markers & Headers",
                    "confidence": "High",
                    "implication": tech_info["implication"]
                })

        # Library versions
        detected_versions = []
        for match in VERSION_PATTERN.finditer(raw_html):
            lib, ver = match.groups()
            detected_versions.append({
                "library": lib.capitalize(),
                "version": ver,
                "vector": "Script Filename Pattern",
                "risk": "Check against CVE database"
            })
        # Deduplicate versions
        seen_libs = set()
        unique_versions = []
        for v in detected_versions:
            key = f"{v['library']}-{v['version']}"
            if key not in seen_libs:
                seen_libs.add(key)
                unique_versions.append(v)

        # 3. Sensitive Data Scanner
        emails = list(set(EMAIL_PATTERN.findall(raw_html)))
        aws_keys = list(set(AWS_KEY_PATTERN.findall(raw_html)))
        jwts = list(set(JWT_PATTERN.findall(raw_html)))
        ips = [ip for ip in set(IP_PATTERN.findall(raw_html)) if _is_valid_ipv4(ip)]
        privkeys = list(set(PRIVKEY_PATTERN.findall(raw_html)))
        api_keys = list(set(APIKEY_PATTERN.findall(raw_html)))

        # Trackers
        ga_ids = list(set(GA_PATTERN.findall(raw_html)))
        gtm_ids = list(set(GTM_PATTERN.findall(raw_html)))
        has_fb_pixel = bool(FB_PIXEL_PATTERN.search(raw_html))

        # 4. Comments
        comments_raw = [c.strip() for c in COMMENT_PATTERN.findall(raw_html) if c.strip() and len(c.strip()) > 5]
        # Filter comments (ignore conditional IE comments)
        meaningful_comments = [c for c in comments_raw if not c.startswith("[if") and not c.startswith("<![if")]

        # 5. External Assets & Domains
        all_refs = HREF_SRC_PATTERN.findall(raw_html)
        internal_links = []
        external_links = []
        external_domains = set()

        for ref in all_refs:
            ref = ref.strip()
            if ref.startswith(("http://", "https://", "//")):
                link_domain = urlparse(ref if "://" in ref else f"https:{ref}").netloc.lower()
                if base_domain in link_domain or link_domain in base_domain:
                    internal_links.append(ref)
                else:
                    external_links.append(ref)
                    if link_domain:
                        external_domains.add(link_domain)
            elif ref and not ref.startswith(("#", "javascript:", "data:")):
                internal_links.append(ref)

        # 6. Flagged Server Headers
        exposed_headers = []
        for k, v in headers.items():
            if k.lower() in FLAGGED_HEADERS:
                exposed_headers.append({
                    "header": k,
                    "value": v,
                    "risk": "Medium" if k.lower() in ("server", "x-powered-by", "x-aspnet-version") else "Low",
                    "recommendation": f"Remove or obfuscate '{k}' in production web server configuration."
                })

        # -------------------------------------------------------------------
        # Build Dual-Axis Tabular Markdown Report
        # -------------------------------------------------------------------
        sections = []
        sections.append("# Metadata & Information Disclosure Security Audit")
        sections.append(f"**Target URL:** `{url}` | **Final URL:** `{final_url}` | **Status:** `{status} OK`\n")

        # 1. Summary Matrix
        sections.append("## Information Disclosure Overview\n")
        sections.append("| Audit Domain | Detected Quantity | Risk Classification | Evaluation Summary |")
        sections.append("|---|---|---|---|")
        sections.append(f"| Sensitive Secrets & Keys | `{len(aws_keys) + len(privkeys) + len(api_keys)}` Exposures | {'Critical' if (aws_keys or privkeys or api_keys) else 'Clean'} | {'Live secrets identified in DOM/Source' if (aws_keys or privkeys or api_keys) else 'No AWS keys, private keys, or API tokens detected'} |")
        sections.append(f"| Technology Fingerprints | `{len(detected_tech)}` Frameworks | {'Medium' if len(detected_tech) > 2 else 'Low'} | {'Framework stack revealed via page markers' if detected_tech else 'Generic stack; minimal fingerprint disclosure'} |")
        sections.append(f"| Versioned JS Libraries | `{len(unique_versions)}` Discovered | {'Medium' if unique_versions else 'Clean'} | {'Client libraries with exposed semantic version strings' if unique_versions else 'Bundled/minified without explicit version leaks'} |")
        sections.append(f"| Server Banner Headers | `{len(exposed_headers)}` Disclosures | {'Medium' if exposed_headers else 'Clean'} | {'Server or runtime stack exposed in HTTP headers' if exposed_headers else 'Clean header profile; server tokens suppressed'} |")
        sections.append(f"| PII & Email Addresses | `{len(emails)}` Addresses | {'Low' if emails else 'Clean'} | {'Email addresses harvestable via automated crawler' if emails else 'No email addresses directly exposed in root markup'} |")
        sections.append(f"| HTML Source Comments | `{len(meaningful_comments)}` Snippets | {'Medium' if len(meaningful_comments) > 5 else 'Low'} | {'Developer comments retained in production build' if meaningful_comments else 'Clean build; minified without comments'} |")
        sections.append(f"| Outbound Third-Party Domains | `{len(external_domains)}` Domains | Cataloged | External service dependencies and asset CDNs mapped |")

        # 2. Technology Stack & Framework Fingerprints
        sections.append("\n## Technology Stack & Framework Fingerprints\n")
        if detected_tech:
            sections.append("| Technology / Framework | Category | Detection Vector | Confidence | Security Implication |")
            sections.append("|---|---|---|---|---|")
            for t in detected_tech:
                sections.append(f"| `{t['name']}` | {t['category']} | {t['vector']} | {t['confidence']} | {t['implication']} |")
        else:
            sections.append("| Technology / Framework | Category | Detection Vector | Confidence | Security Implication |")
            sections.append("|---|---|---|---|---|")
            sections.append("| _No framework signatures detected_ | Generic Web Application | Header / DOM Scan | High | Target employs obfuscated or customized build pipeline. |")

        if unique_versions:
            sections.append("\n### Detected Third-Party Library Versions\n")
            sections.append("| Library Identifier | Detected Version | Detection Method | Vulnerability Status |")
            sections.append("|---|---|---|---|")
            for v in unique_versions:
                sections.append(f"| `{v['library']}` | `{v['version']}` | {v['vector']} | {v['risk']} |")

        # 3. Secret Leakage & Information Disclosure Audit
        sections.append("\n## Secret Leakage & Information Disclosure Audit\n")
        secrets_found = False
        secret_rows = []
        if aws_keys:
            secrets_found = True
            for k in aws_keys:
                secret_rows.append(f"| AWS Access Key ID | Regex Match (`AKIA...`) | `{self._mask_secret(k)}` | Critical | Revoke and rotate AWS IAM credentials immediately. |")
        if privkeys:
            secrets_found = True
            for pk in privkeys:
                secret_rows.append(f"| Private Key Material | RSA / EC / DSA Header | `-----BEGIN PRIVATE KEY-----` | Critical | Immediate incident response: key compromised. |")
        if api_keys:
            secrets_found = True
            for ak in api_keys:
                secret_rows.append(f"| API Token / Secret | Assignment Pattern | `{self._mask_secret(ak)}` | High | Move token to secure server-side environment variable. |")
        if jwts:
            secrets_found = True
            for j in jwts[:5]:
                secret_rows.append(f"| JSON Web Token (JWT) | Bearer Pattern | `{self._mask_secret(j)}` | Medium | Verify JWT does not contain unencrypted sensitive claims. |")
        if emails:
            for e in emails[:10]:
                secret_rows.append(f"| Harvestable Email | RFC 5322 Pattern | `{e}` | Low | Use contact form instead of exposing raw mailto/text. |")
        if ips:
            for ip in ips[:8]:
                secret_rows.append(f"| Internal / Public IP | IPv4 Address Pattern | `{ip}` | Low | Check if IP discloses internal network infrastructure. |")

        if secret_rows:
            sections.append("| Leakage Category | Pattern Classifier | Sample Value | Risk Level | Remediation Guideline |")
            sections.append("|---|---|---|---|---|")
            sections.extend(secret_rows)
        else:
            sections.append("| Leakage Category | Pattern Classifier | Sample Value | Risk Level | Remediation Guideline |")
            sections.append("|---|---|---|---|---|")
            sections.append("| _No High-Risk Secrets Detected_ | Automated Scanner | Clean | Low | No AWS keys, JWTs, or private keys disclosed in page source. |")

        # 4. Server Response Headers
        sections.append("\n## Server Banner & Header Information Disclosures\n")
        if exposed_headers:
            sections.append("| Header Name | Header Value Disclosed | Risk Classification | Hardening Recommendation |")
            sections.append("|---|---|---|---|")
            for h in exposed_headers:
                sections.append(f"| `{h['header']}` | `{h['value']}` | {h['risk']} | {h['recommendation']} |")
        else:
            sections.append("| Header Name | Header Value Disclosed | Risk Classification | Hardening Recommendation |")
            sections.append("|---|---|---|---|")
            sections.append("| _No Leaking Headers Identified_ | — | Clean | Web server successfully masks internal versioning and server tokens. |")

        # 5. HTML Metadata & OpenGraph Catalog
        sections.append("\n## HTML Metadata & OpenGraph Catalog\n")
        sections.append("| Metadata Attribute | Disclosed Content | Classification | Exposure Impact |")
        sections.append("|---|---|---|---|")
        sections.append(f"| `title` | {page_title[:60]} | Document Title | Standard Public Identifier |")
        
        important_meta_keys = ["description", "keywords", "generator", "author", "viewport", "og:title", "og:description", "og:image", "twitter:card"]
        for mk in important_meta_keys:
            if mk in named_metas:
                val = named_metas[mk]
                val_clean = val.replace("\n", " ").strip()
                if len(val_clean) > 70:
                    val_clean = val_clean[:67] + "..."
                impact = "Reveals CMS/generator version" if mk == "generator" else "Public search/social indexing"
                sections.append(f"| `{mk}` | {val_clean} | Meta Tag | {impact} |")
        
        if not any(mk in named_metas for mk in important_meta_keys):
            sections.append("| `meta` | _No standard SEO/OpenGraph tags found_ | Uncataloged | Page lacks structured social or metadata headers |")

        # 6. HTML Comments & Source Code Review
        sections.append("\n## HTML Comments & Development Notes\n")
        if meaningful_comments:
            sections.append("| Comment Index | Extracted Snippet | Length | Risk Assessment |")
            sections.append("|---|---|---|---|")
            for idx, c in enumerate(meaningful_comments[:8], 1):
                clean_c = c.replace("\n", " ").replace("|", "/").strip()
                if len(clean_c) > 75:
                    clean_c = clean_c[:72] + "..."
                risk = "Medium" if any(w in clean_c.lower() for w in ["todo", "fixme", "test", "pass", "debug", "dev"]) else "Low"
                sections.append(f"| `#{idx}` | `{clean_c}` | `{len(c)} chars` | {risk} |")
        else:
            sections.append("| Comment Index | Extracted Snippet | Length | Risk Assessment |")
            sections.append("|---|---|---|---|")
            sections.append("| _No Comments Found_ | Page markup is stripped and minified | 0 chars | Clean |")

        # 7. Telemetry & Analytics Integrations
        sections.append("\n## Telemetry & Third-Party Outbound References\n")
        sections.append("| Integration Type | Identifier / Domain | Tracking Classification | Privacy & Security Review |")
        sections.append("|---|---|---|---|")
        if ga_ids:
            for g in ga_ids:
                sections.append(f"| Google Analytics | `{g}` | User Telemetry | Ensure IP anonymization is active in consent manager. |")
        if gtm_ids:
            for g in gtm_ids:
                sections.append(f"| Google Tag Manager | `{g}` | Container Injector | Audit container triggers for unauthorized third-party scripts. |")
        if has_fb_pixel:
            sections.append("| Meta Facebook Pixel | Active Tracker | Behavioral Advertising | Review cookie consent alignment under GDPR/CCPA. |")
        
        if external_domains:
            for d in sorted(external_domains)[:12]:
                sections.append(f"| External Asset Domain | `{d}` | Outbound Asset Dependency | Confirm subresource integrity (SRI) for external scripts. |")
        
        if not ga_ids and not gtm_ids and not has_fb_pixel and not external_domains:
            sections.append("| _No Third-Party References_ | Self-Contained | Isolated | Target does not load external tracking or third-party assets. |")

        # 8. Action Items Roadmap
        sections.append("\n## Information Disclosure Remediation Roadmap\n")
        sections.append("| Finding Focus | Severity | Affected Vector | Recommended Remediation Action | Reference |")
        sections.append("|---|---|---|---|---|")
        if secrets_found:
            sections.append("| Live Credentials in Source | Critical | DOM / Client JavaScript | Immediately revoke exposed keys and implement automated secret scanning in CI/CD. | OWASP A01:2021 |")
        if exposed_headers:
            sections.append("| Server Header Disclosure | Medium | HTTP Response Headers | Configure reverse proxy (Nginx/Cloudflare) to strip `Server` and `X-Powered-By` headers. | CWE-200 |")
        if meaningful_comments:
            sections.append("| Source Code Comments | Low | Production HTML Markup | Configure production bundler/minifier (Webpack/Vite) to strip all HTML comments during build. | CWE-615 |")
        sections.append("| Third-Party Script Supply Chain | Medium | Outbound Asset CDNs | Implement Subresource Integrity (SRI) hashes on all external `<script>` and `<link>` tags. | CWE-353 |")
        sections.append("| Public Email Harvester Shield | Low | Mailto / Text Disclosures | Implement obfuscation or backend contact form gateways to mitigate automated spam harvesting. | NIST SP 800-53 |")

        return "\n".join(sections)
