from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Set
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
# Helper utilities
# ---------------------------------------------------------------------------

FLAGGED_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-aspnet-version",
    "via", "cf-ray", "x-cache", "www-authenticate",
]

TECH_KEYWORDS: Dict[str, List[str]] = {
    "WordPress":  ["wp-content", "wp-includes", "wordpress"],
    "Drupal":     ["drupal", "/sites/default/files/"],
    "Joomla":     ["joomla", "/components/com_"],
    "Laravel":    ["laravel", "laravel_session"],
    "Django":     ["django", "csrfmiddlewaretoken"],
    "Next.js":    ["_next/static", "__NEXT_DATA__"],
    "React":      ["react.js", "react.min.js", "react-dom"],
    "Angular":    ["ng-version", "angular.js", "angular.min.js"],
    "Vue":        ["vue.js", "vue.min.js", "__vue__"],
    "jQuery":     ["jquery.js", "jquery.min.js"],
    "Bootstrap":  ["bootstrap.css", "bootstrap.min.css", "bootstrap.js"],
}

VERSION_PATTERN   = re.compile(r'(jquery|bootstrap|react|vue|angular)[.\-](\d+\.\d+[\.\d]*)', re.IGNORECASE)
META_TAG_PATTERN  = re.compile(r'<meta\s+([^>]+)>', re.IGNORECASE)
TITLE_PATTERN     = re.compile(r'<title[^>]*>(.*?)</title>', re.IGNORECASE | re.DOTALL)
ATTR_PATTERN      = re.compile(r'(\w[\w\-]*)=["\']([^"\']*)["\']')

EMAIL_PATTERN     = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
AWS_KEY_PATTERN   = re.compile(r'AKIA[0-9A-Z]{16}')
JWT_PATTERN       = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+')
IP_PATTERN        = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
COMMENT_PATTERN   = re.compile(r'<!--(.*?)-->', re.DOTALL)
PRIVKEY_PATTERN   = re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----')
APIKEY_PATTERN    = re.compile(r'(?:api_key|apikey|api-key|secret|token)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', re.IGNORECASE)
GA_PATTERN        = re.compile(r'\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{10,})\b')
FB_PIXEL_PATTERN  = re.compile(r'facebook\.com/tr\?|fbq\(|_fbq')

HREF_SRC_PATTERN  = re.compile(r'(?:href|src)=["\']([^"\']+)["\']', re.IGNORECASE)

IP_FALSE_POSITIVES = {"0.0.0.0", "127.0.0.1", "255.255.255.255", "192.168.0.0"}

# ---------------------------------------------------------------------------
# Tool
# ---------------------------------------------------------------------------

class MetadataInformationDisclosureExtractorTool(BaseTool):
    """Tool for extracting metadata and sensitive information disclosures from a URL."""

    name: str = "Metadata and Information Disclosure Extractor"
    description: str = (
        "Performs comprehensive metadata and information-disclosure analysis on a given URL. "
        "Analyses HTTP headers, HTML meta tags, technology fingerprints, sensitive data patterns "
        "(emails, AWS keys, JWTs, private keys, API keys, IPs), HTML comments, and link inventory. "
        "Returns a structured Markdown security report."
    )
    args_schema: Type[BaseModel] = MetadataExtractorInput

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def _run(self, url: str) -> str:
        # Ensure the URL has a scheme
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed_base = urlparse(url)
        base_domain = parsed_base.netloc.lower()

        try:
            response = requests.get(
                url,
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (compatible; MetadataExtractor/1.0)"},
                allow_redirects=True,
            )
        except requests.exceptions.Timeout:
            return f"❌ **Error:** Request to `{url}` timed out after 15 seconds."
        except requests.exceptions.SSLError as exc:
            return f"❌ **SSL Error** for `{url}`: {exc}"
        except requests.exceptions.ConnectionError as exc:
            return f"❌ **Connection Error** for `{url}`: {exc}"
        except Exception as exc:
            return f"❌ **Unexpected Error** for `{url}`: {exc}"

        raw_html   = response.text
        headers    = response.headers
        status     = response.status_code
        final_url  = response.url

        sections: List[str] = []

        # ── Title ──────────────────────────────────────────────────────
        sections.append(f"# 🔍 Metadata & Information Disclosure Report\n")
        sections.append(f"- **Target URL:** `{url}`")
        sections.append(f"- **Final URL (after redirects):** `{final_url}`")
        sections.append(f"- **HTTP Status:** `{status}`\n")

        # ── A. HTTP Headers ────────────────────────────────────────────
        sections.append("## A. HTTP Response Headers\n")
        sections.append("### All Headers\n")
        sections.append("| Header | Value |")
        sections.append("|--------|-------|")
        for k, v in headers.items():
            sections.append(f"| `{k}` | `{v}` |")

        sections.append("\n### 🚩 Flagged Headers\n")
        flagged_found = False
        for k, v in headers.items():
            if k.lower() in FLAGGED_HEADERS:
                sections.append(f"- **{k}:** `{v}`")
                flagged_found = True
        if not flagged_found:
            sections.append("_No flagged headers detected._")

        # ── B. HTML Metadata ───────────────────────────────────────────
        sections.append("\n## B. HTML Metadata\n")

        title_match = TITLE_PATTERN.search(raw_html)
        page_title  = title_match.group(1).strip() if title_match else "_Not found_"
        sections.append(f"### Page Title\n`{page_title}`\n")

        sections.append("### Meta Tags\n")
        meta_tags = META_TAG_PATTERN.findall(raw_html)
        if meta_tags:
            sections.append("| Attributes |")
            sections.append("|------------|")
            for tag_attrs in meta_tags[:40]:          # cap at 40 to avoid noise
                clean = tag_attrs.replace("\n", " ").strip()
                sections.append(f"| `{clean}` |")
        else:
            sections.append("_No meta tags found._")

        # Named meta tags
        named_metas = self._extract_named_metas(meta_tags)
        interesting = ["generator", "author", "description", "keywords",
                       "og:title", "og:site_name", "og:type"]
        sections.append("\n### Key Meta / Open Graph Values\n")
        found_any = False
        for key in interesting:
            val = named_metas.get(key)
            if val:
                sections.append(f"- **{key}:** `{val}`")
                found_any = True
        if not found_any:
            sections.append("_None of the key meta tags were present._")

        # ── C. Technology Fingerprinting ───────────────────────────────
        sections.append("\n## C. Technology Fingerprinting\n")
        combined = raw_html.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

        detected_tech: List[str] = []
        for tech, signals in TECH_KEYWORDS.items():
            if any(sig.lower() in combined for sig in signals):
                detected_tech.append(tech)

        if detected_tech:
            for t in detected_tech:
                sections.append(f"- ✅ **{t}** detected")
        else:
            sections.append("_No common technologies fingerprinted._")

        sections.append("\n### Library Versions (from script src)\n")
        versions = VERSION_PATTERN.findall(raw_html)
        if versions:
            seen: Set[str] = set()
            for lib, ver in versions:
                entry = f"{lib.capitalize()} v{ver}"
                if entry not in seen:
                    sections.append(f"- `{entry}`")
                    seen.add(entry)
        else:
            sections.append("_No versioned library references found._")

        sections.append("\n### Analytics & Tracking\n")
        ga_ids = list(set(GA_PATTERN.findall(raw_html)))
        if ga_ids:
            for ga in ga_ids:
                sections.append(f"- **Google Analytics ID:** `{ga}`")
        else:
            sections.append("- Google Analytics: _not detected_")

        if FB_PIXEL_PATTERN.search(raw_html):
            sections.append("- **Facebook Pixel:** ✅ detected")
        else:
            sections.append("- Facebook Pixel: _not detected_")

        # ── D. Sensitive Information Scanner ──────────────────────────
        sections.append("\n## D. Sensitive Information Scanner\n")

        # Emails
        emails = list(set(EMAIL_PATTERN.findall(raw_html)))
        self._append_findings(sections, "📧 Email Addresses", emails, mask=False)

        # AWS Keys
        aws_keys = list(set(AWS_KEY_PATTERN.findall(raw_html)))
        self._append_findings(sections, "🔑 AWS Access Keys", aws_keys, mask=True)

        # JWT Tokens
        jwts = list(set(JWT_PATTERN.findall(raw_html)))
        self._append_findings(sections, "🪙 JWT Tokens", jwts, mask=True, max_show=5)

        # IP Addresses
        ips = [ip for ip in set(IP_PATTERN.findall(raw_html)) if ip not in IP_FALSE_POSITIVES]
        self._append_findings(sections, "🌐 IP Addresses", ips, mask=False)

        # Private Keys
        privkeys = list(set(PRIVKEY_PATTERN.findall(raw_html)))
        if privkeys:
            sections.append(f"\n### ⚠️ Private Key Indicators\n")
            for pk in privkeys:
                sections.append(f"- `-----BEGIN {pk}PRIVATE KEY-----` — **CRITICAL EXPOSURE!**")
        else:
            sections.append("\n### ⚠️ Private Key Indicators\n_None detected._")

        # API Keys
        api_keys = list(set(APIKEY_PATTERN.findall(raw_html)))
        self._append_findings(sections, "🗝️ API Key / Secret Patterns", api_keys, mask=True)

        # HTML Comments
        comments = [c.strip() for c in COMMENT_PATTERN.findall(raw_html) if c.strip()]
        sections.append(f"\n### 💬 HTML Comments ({len(comments)} found)\n")
        if comments:
            for c in comments[:10]:              # show first 10
                short = (c[:200] + "…") if len(c) > 200 else c
                sections.append(f"```\n{short}\n```")
            if len(comments) > 10:
                sections.append(f"_…and {len(comments) - 10} more comment(s) not shown._")
        else:
            sections.append("_No HTML comments detected._")

        # ── E. Links & External Resources ─────────────────────────────
        sections.append("\n## E. Links & External Resources\n")

        all_refs = HREF_SRC_PATTERN.findall(raw_html)
        internal_links: List[str] = []
        external_links: List[str] = []
        mailto_links:   List[str] = []
        tel_links:      List[str] = []

        for ref in all_refs:
            ref = ref.strip()
            if ref.startswith("mailto:"):
                mailto_links.append(ref[7:])
            elif ref.startswith("tel:"):
                tel_links.append(ref[4:])
            elif ref.startswith("http://") or ref.startswith("https://"):
                link_domain = urlparse(ref).netloc.lower()
                if base_domain in link_domain or link_domain in base_domain:
                    internal_links.append(ref)
                else:
                    external_links.append(ref)
            elif ref.startswith("//"):
                external_links.append(ref)
            elif ref and not ref.startswith("#") and not ref.startswith("javascript:"):
                internal_links.append(ref)

        # Deduplicate
        internal_links = list(set(internal_links))
        external_links = list(set(external_links))
        mailto_links   = list(set(mailto_links))
        tel_links      = list(set(tel_links))

        sections.append(f"- **Internal links:** {len(internal_links)}")
        sections.append(f"- **External links:** {len(external_links)}")
        sections.append(f"- **Mailto disclosures:** {len(mailto_links)}")
        sections.append(f"- **Tel disclosures:** {len(tel_links)}\n")

        if external_links:
            sections.append("### External Domains Detected\n")
            ext_domains = list(set(urlparse(l).netloc for l in external_links if l.startswith("http")))
            for d in sorted(ext_domains)[:30]:
                sections.append(f"- `{d}`")

        if mailto_links:
            sections.append("\n### 📧 Mailto Links (Email Disclosure)\n")
            for m in mailto_links:
                sections.append(f"- `{m}`")

        if tel_links:
            sections.append("\n### 📞 Tel Links (Phone Disclosure)\n")
            for t in tel_links:
                sections.append(f"- `{t}`")

        # ── Summary ────────────────────────────────────────────────────
        sections.append("\n---\n## 📋 Summary\n")
        risk_flags: List[str] = []
        if aws_keys:
            risk_flags.append(f"🔴 **{len(aws_keys)} AWS key(s) exposed**")
        if privkeys:
            risk_flags.append(f"🔴 **Private key material exposed**")
        if api_keys:
            risk_flags.append(f"🟠 **{len(api_keys)} API key/secret pattern(s) found**")
        if jwts:
            risk_flags.append(f"🟠 **{len(jwts)} JWT token(s) found**")
        if emails:
            risk_flags.append(f"🟡 **{len(emails)} email address(es) disclosed**")
        if flagged_found:
            risk_flags.append("🟡 **Sensitive HTTP headers present**")
        if comments:
            risk_flags.append(f"🔵 **{len(comments)} HTML comment(s) — review manually**")

        if risk_flags:
            for f in risk_flags:
                sections.append(f"- {f}")
        else:
            sections.append("✅ _No critical findings detected. Manual review still recommended._")

        return "\n".join(sections)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_named_metas(self, meta_tags: List[str]) -> Dict[str, str]:
        """Parse meta tag attribute strings into a name→content dict."""
        result: Dict[str, str] = {}
        for tag_attrs in meta_tags:
            attrs = dict(ATTR_PATTERN.findall(tag_attrs))
            name    = attrs.get("name", attrs.get("property", "")).lower()
            content = attrs.get("content", "")
            if name and content:
                result[name] = content
        return result

    def _append_findings(
        self,
        sections: List[str],
        label: str,
        items: List[str],
        mask: bool = False,
        max_show: int = 20,
    ) -> None:
        """Append a finding section, optionally masking sensitive values."""
        sections.append(f"\n### {label}\n")
        if items:
            for item in items[:max_show]:
                display = self._mask(item) if mask else f"`{item}`"
                sections.append(f"- {display}")
            if len(items) > max_show:
                sections.append(f"_…and {len(items) - max_show} more not shown._")
        else:
            sections.append("_None detected._")

    @staticmethod
    def _mask(value: str) -> str:
        """Partially mask a sensitive value for safe reporting."""
        if len(value) <= 8:
            return "`****`"
        return f"`{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}`"
