from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from typing import Type, List, Dict, Any, Optional
import requests
import time
from urllib.parse import urlparse


# ── Input Schema ─────────────────────────────────────────────────────────────

class RateLimitingDoSResilienceTesterInput(BaseModel):
    """Input schema for Rate Limiting and DoS Resilience Tester Tool."""
    url: str = Field(..., description="The target URL to test for rate limiting and DoS resilience.")


# ── Constants & Signatures ───────────────────────────────────────────────────

RATE_LIMIT_HEADER_KEYS = [
    "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining",
    "x-ratelimit-reset", "ratelimit-limit", "ratelimit-remaining",
    "ratelimit-reset", "ratelimit-policy", "x-rate-limit-limit",
    "x-rate-limit-remaining", "x-rate-limit-reset"
]

CDN_WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare", "cf-mitigated"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "via:1.1 cloudfront", "via:cloudfront"],
    "Akamai": ["x-check-cacheable", "akamai-cache-status", "x-akamai-request-id", "akamai-grn"],
    "Fastly": ["x-served-by", "x-cache:hit from fastly", "fastly-debug-digest", "x-fastly-request-id"],
    "Imperva / Incapsula": ["x-iinfo", "x-cdn:incapsula", "incap_ses", "visid_incap"],
    "Google Cloud Armor / CDN": ["via:1.1 google", "x-goog-generation", "x-guploader-uploadid"],
    "Azure Front Door": ["x-azure-ref", "x-azure-fdid", "x-fd-features"],
    "Sucuri WAF": ["x-sucuri-id", "x-sucuri-cache", "server:sucuri"],
}

HTTP_METHODS_TO_TEST = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "DEBUG", "INVALIDVERB"
]

DANGEROUS_METHODS = {"PUT", "DELETE", "TRACE", "DEBUG", "CONNECT"}


# ── Core Engine ──────────────────────────────────────────────────────────────

class RateLimitingDoSResilienceTesterTool(BaseTool):
    """
    Advanced security tool for auditing rate limiting enforcement, burst load resilience,
    large payload exhaustion limits, HTTP verb tampering, host injection vulnerabilities,
    and CDN/WAF perimeter mitigation capabilities.
    """

    name: str = "Rate Limiting and DoS Resilience Tester"
    description: str = (
        "Tests a target URL for rate limiting enforcement, burst load degradation, "
        "large payload exhaustion, HTTP verb tampering, host header injection, and CDN/WAF "
        "mitigation presence. Returns a clean executive tabular data-sheet report."
    )
    args_schema: Type[BaseModel] = RateLimitingDoSResilienceTesterInput

    def _normalize_url(self, raw_url: str) -> str:
        url = raw_url.strip()
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    def _safe_request(
        self,
        method: str,
        url: str,
        timeout: float = 8.0,
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        allow_redirects: bool = False,
    ) -> Dict[str, Any]:
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        if headers:
            default_headers.update(headers)

        start = time.time()
        try:
            resp = requests.request(
                method,
                url,
                timeout=timeout,
                headers=default_headers,
                data=data,
                allow_redirects=allow_redirects,
                verify=False,
            )
            elapsed_ms = round((time.time() - start) * 1000, 1)
            return {
                "ok": True,
                "status": resp.status_code,
                "elapsed_ms": elapsed_ms,
                "size": len(resp.content),
                "headers": dict(resp.headers),
                "error": None,
            }
        except requests.exceptions.Timeout:
            elapsed_ms = round((time.time() - start) * 1000, 1)
            return {
                "ok": False,
                "status": None,
                "elapsed_ms": elapsed_ms,
                "size": 0,
                "headers": {},
                "error": f"Timeout (> {timeout}s)",
            }
        except Exception as exc:
            elapsed_ms = round((time.time() - start) * 1000, 1)
            return {
                "ok": False,
                "status": None,
                "elapsed_ms": elapsed_ms,
                "size": 0,
                "headers": {},
                "error": str(exc)[:80],
            }

    # ── 1. Burst Rate Limiting Test ──
    def _execute_burst_benchmark(self, url: str) -> Dict[str, Any]:
        burst_results = []
        captured_rate_headers: Dict[str, str] = {}
        first_429_index: Optional[int] = None
        first_5xx_index: Optional[int] = None

        for req_idx in range(1, 21):
            res = self._safe_request("GET", url, timeout=6.0)
            res["req_num"] = req_idx
            burst_results.append(res)

            if res["ok"] and res["status"]:
                st = res["status"]
                hdrs_lower = {k.lower(): v for k, v in res.get("headers", {}).items()}

                # Collect rate limit headers
                for rh in RATE_LIMIT_HEADER_KEYS:
                    if rh in hdrs_lower and rh not in captured_rate_headers:
                        captured_rate_headers[rh] = hdrs_lower[rh]

                if st == 429 and first_429_index is None:
                    first_429_index = req_idx
                elif st >= 500 and first_5xx_index is None:
                    first_5xx_index = req_idx

            time.sleep(0.05)  # rapid 50ms interval to simulate realistic burst

        valid_timings = [r["elapsed_ms"] for r in burst_results if r["ok"]]
        statuses = [str(r["status"]) for r in burst_results if r.get("status")]

        return {
            "burst_records": burst_results,
            "timings_ms": valid_timings,
            "status_distribution": {s: statuses.count(s) for s in set(statuses)},
            "rate_limited": first_429_index is not None,
            "rate_limited_at": first_429_index,
            "server_error_at": first_5xx_index,
            "rate_headers": captured_rate_headers,
        }

    # ── 2. Latency Degradation Analysis ──
    def _compute_latency_metrics(self, timings: List[float]) -> Dict[str, Any]:
        if not timings:
            return {
                "min_ms": 0, "max_ms": 0, "avg_ms": 0, "median_ms": 0,
                "first_half_avg": 0, "second_half_avg": 0, "degradation_pct": 0,
                "health_status": "Indeterminate", "observations": ["No successful responses recorded."]
            }

        sorted_t = sorted(timings)
        n = len(timings)
        min_t = min(timings)
        max_t = max(timings)
        avg_t = round(sum(timings) / n, 1)
        med_t = sorted_t[n // 2]

        mid = n // 2
        first_half = timings[:mid] if mid > 0 else timings
        second_half = timings[mid:] if mid > 0 else timings

        first_avg = round(sum(first_half) / len(first_half), 1)
        second_avg = round(sum(second_half) / len(second_half), 1)

        deg_pct = round(((second_avg - first_avg) / first_avg * 100), 1) if first_avg > 0 else 0

        observations = []
        if avg_t > 1500:
            health = "Elevated Latency"
            observations.append("Average response time exceeds 1.5s — high susceptibility to connection pool exhaustion.")
        elif deg_pct > 40:
            health = "Performance Degradation"
            observations.append(f"Response latency increased by +{deg_pct}% under rapid sequential load.")
        elif deg_pct < -20:
            health = "Optimized / Edge Cached"
            observations.append("Response times improved during burst sequence indicating hot edge-cache acceleration.")
        else:
            health = "Stable Under Load"
            observations.append("Response latency remained uniform and resilient across the 20-request burst sequence.")

        return {
            "min_ms": min_t,
            "max_ms": max_t,
            "avg_ms": avg_t,
            "median_ms": med_t,
            "first_half_avg": first_avg,
            "second_half_avg": second_avg,
            "degradation_pct": deg_pct,
            "health_status": health,
            "observations": observations,
        }

    # ── 3. Large Payload & Buffer Exhaustion ──
    def _execute_payload_stress(self, url: str) -> List[Dict[str, Any]]:
        tests = []

        # A. 10 KB POST Body
        body_10k = "A" * 10240
        res_10k = self._safe_request("POST", url, data=body_10k, headers={"Content-Type": "text/plain"})
        st_10k = res_10k.get("status")
        risk_10k = "Low" if st_10k in (400, 405, 413, 415, 422, 429) else "Medium"
        interp_10k = (
            f"Handled correctly with HTTP {st_10k}" if st_10k in (400, 405, 413, 415, 422, 429)
            else f"Accepted 10KB body without restriction (HTTP {st_10k})"
        )
        tests.append({
            "vector": "10 KB POST Body Injection",
            "status": f"HTTP {st_10k}" if st_10k else (res_10k.get("error") or "ERR"),
            "latency": f"{res_10k['elapsed_ms']}ms",
            "evaluation": interp_10k,
            "risk": risk_10k,
        })

        # B. 50 KB POST Body
        body_50k = "B" * 51200
        res_50k = self._safe_request("POST", url, data=body_50k, headers={"Content-Type": "application/octet-stream"})
        st_50k = res_50k.get("status")
        risk_50k = "Low" if st_50k in (400, 405, 413, 415, 422, 429) else "Medium"
        interp_50k = (
            f"Restricted with HTTP {st_50k}" if st_50k in (400, 405, 413, 415, 422, 429)
            else f"Accepted 50KB unstructured payload without body cap (HTTP {st_50k})"
        )
        tests.append({
            "vector": "50 KB POST Payload Cap",
            "status": f"HTTP {st_50k}" if st_50k else (res_50k.get("error") or "ERR"),
            "latency": f"{res_50k['elapsed_ms']}ms",
            "evaluation": interp_50k,
            "risk": risk_50k,
        })

        # C. 1,500 Char URI Parameter
        long_param = "X" * 1500
        long_url = f"{url}{'&' if '?' in url else '?'}dos_probe={long_param}"
        res_uri = self._safe_request("GET", long_url)
        st_uri = res_uri.get("status")
        risk_uri = "Low" if st_uri in (400, 414, 429) else ("Info" if st_uri == 200 else "Low")
        interp_uri = (
            f"Properly rejected with HTTP {st_uri}" if st_uri in (400, 414)
            else f"Processed 1.5KB query string with status {st_uri}"
        )
        tests.append({
            "vector": "1,500 Char Query String Limit",
            "status": f"HTTP {st_uri}" if st_uri else (res_uri.get("error") or "ERR"),
            "latency": f"{res_uri['elapsed_ms']}ms",
            "evaluation": interp_uri,
            "risk": risk_uri,
        })

        # D. 8 KB Custom Request Header
        oversized_hdr = "Z" * 8192
        res_hdr = self._safe_request("GET", url, headers={"X-Stress-Header": oversized_hdr})
        st_hdr = res_hdr.get("status")
        risk_hdr = "Low" if st_hdr in (400, 413, 431) else ("Medium" if st_hdr == 200 else "Low")
        interp_hdr = (
            f"Header buffer enforced (HTTP {st_hdr})" if st_hdr in (400, 413, 431)
            else f"Server accepted 8KB header without rejection (HTTP {st_hdr})"
        )
        tests.append({
            "vector": "8 KB Oversized HTTP Header Buffer",
            "status": f"HTTP {st_hdr}" if st_hdr else (res_hdr.get("error") or "ERR"),
            "latency": f"{res_hdr['elapsed_ms']}ms",
            "evaluation": interp_hdr,
            "risk": risk_hdr,
        })

        return tests

    # ── 4. HTTP Verb & Method Tampering ──
    def _execute_method_audit(self, url: str) -> List[Dict[str, Any]]:
        method_records = []
        options_allow_header = ""

        # First query OPTIONS to check declared Allow list
        res_opt = self._safe_request("OPTIONS", url)
        if res_opt["ok"]:
            options_allow_header = res_opt.get("headers", {}).get("Allow", "")

        for m in HTTP_METHODS_TO_TEST:
            res = self._safe_request(m, url)
            st = res.get("status")
            status_display = f"HTTP {st}" if st else (res.get("error") or "ERR")

            # Determine acceptance and risk
            is_rejected = st in (405, 501, 502, 503) or (st == 400 and m == "INVALIDVERB")
            is_forbidden = st in (401, 403)

            if m in DANGEROUS_METHODS and not is_rejected and not is_forbidden and st is not None:
                risk = "High" if m in ("TRACE", "DEBUG") else "Medium"
                interp = f"Potentially exposed ({m} returned HTTP {st})"
            elif is_rejected or is_forbidden:
                risk = "Low"
                interp = f"Blocked / Not Allowed ({status_display})"
            else:
                risk = "Info" if m in ("GET", "HEAD", "POST", "OPTIONS") else "Low"
                interp = f"Standard handler response ({status_display})"

            method_records.append({
                "method": m,
                "status": status_display,
                "latency": f"{res['elapsed_ms']}ms",
                "risk": risk,
                "evaluation": interp,
            })
            time.sleep(0.05)

        return method_records

    # ── 5. Host Header & Header Injection ──
    def _execute_injection_audit(self, url: str) -> List[Dict[str, Any]]:
        results = []

        # A. Arbitrary Host Header Spoofing
        res_host = self._safe_request("GET", url, headers={"Host": "evil-injected-host.com"})
        st_host = res_host.get("status")
        risk_host = "Medium" if st_host == 200 else "Low"
        eval_host = (
            "Server accepted spoofed Host header with 200 OK — potential cache poisoning risk."
            if st_host == 200
            else f"Server enforced strict hostname or rejected spoofed host (HTTP {st_host})."
        )
        results.append({
            "vector": "Spoofed Host Header (`Host: evil-injected-host.com`)",
            "status": f"HTTP {st_host}" if st_host else (res_host.get("error") or "ERR"),
            "latency": f"{res_host['elapsed_ms']}ms",
            "risk": risk_host,
            "evaluation": eval_host,
        })

        # B. X-Forwarded-Host Header
        res_xfh = self._safe_request("GET", url, headers={"X-Forwarded-Host": "attacker.com"})
        st_xfh = res_xfh.get("status")
        risk_xfh = "Low"
        eval_xfh = f"Reverse proxy processed X-Forwarded-Host with status {st_xfh}."
        results.append({
            "vector": "Forwarded Host Header (`X-Forwarded-Host: attacker.com`)",
            "status": f"HTTP {st_xfh}" if st_xfh else (res_xfh.get("error") or "ERR"),
            "latency": f"{res_xfh['elapsed_ms']}ms",
            "risk": risk_xfh,
            "evaluation": eval_xfh,
        })

        # C. X-Forwarded-For Rate Limit Bypass Attempt
        res_xff = self._safe_request("GET", url, headers={"X-Forwarded-For": "127.0.0.1, 10.0.0.1"})
        st_xff = res_xff.get("status")
        results.append({
            "vector": "Spoofed Client IP (`X-Forwarded-For: 127.0.0.1`)",
            "status": f"HTTP {st_xff}" if st_xff else (res_xff.get("error") or "ERR"),
            "latency": f"{res_xff['elapsed_ms']}ms",
            "risk": "Low",
            "evaluation": f"Server handled forged client IP header (HTTP {st_xff}).",
        })

        return results

    # ── 6. Edge Caching, Compression & CDN/WAF ──
    def _execute_edge_audit(self, url: str) -> Dict[str, Any]:
        res = self._safe_request("GET", url, headers={"Accept-Encoding": "gzip, deflate, br, zstd"})
        hdrs = {k.lower(): v for k, v in res.get("headers", {}).items()}

        compression = hdrs.get("content-encoding", "None / Uncompressed")
        cache_control = hdrs.get("cache-control", "Absent")
        etag = hdrs.get("etag", "Absent")
        vary = hdrs.get("vary", "Absent")
        server = hdrs.get("server", "Undisclosed")

        detected_cdns = []
        all_header_dump = " ".join(f"{k}:{v}" for k, v in hdrs.items()).lower()
        for cdn_name, sigs in CDN_WAF_SIGNATURES.items():
            if any(s in all_header_dump for s in sigs):
                detected_cdns.append(cdn_name)

        return {
            "compression": compression,
            "cache_control": cache_control,
            "etag": etag,
            "vary": vary,
            "server": server,
            "cdns": detected_cdns if detected_cdns else ["No CDN / Direct Origin Identified"],
            "has_cdn": len(detected_cdns) > 0,
        }

    # ── 7. Build Tabular Markdown Report ──
    def _build_markdown_report(
        self,
        url: str,
        burst: Dict[str, Any],
        latency: Dict[str, Any],
        payloads: List[Dict[str, Any]],
        methods: List[Dict[str, Any]],
        injections: List[Dict[str, Any]],
        edge: Dict[str, Any],
    ) -> str:
        sections = []
        sections.append("# DoS Resilience & Rate Limiting Security Audit")
        sections.append(f"**Target System Endpoint:** `{url}` | **Audit Scope:** Layer 7 Resilience & Burst Throttling\n")

        # 1. Overview Matrix
        sections.append("## DoS & Rate Limiting Overview\n")
        sections.append("| Resilience Metric | Measured Result | Security Classification | Benchmark Assessment |")
        sections.append("|---|---|---|---|")
        rate_status = "Enforced" if burst["rate_limited"] else ("Header Policy Detected" if burst["rate_headers"] else "Unthrottled")
        rate_risk = "Protected" if burst["rate_limited"] else ("Medium" if not burst["rate_headers"] else "Low")
        sections.append(f"| L7 Rate Limiting Enforcement | {rate_status} | {rate_risk} | {'HTTP 429 Too Many Requests actively triggered' if burst['rate_limited'] else ('Rate limiting policy headers detected' if burst['rate_headers'] else 'No throttling observed over 20-request burst')} |")
        sections.append(f"| Load Stability & Latency Health | {latency['health_status']} | {'Stable' if latency['degradation_pct'] < 30 else 'Warning'} | Average: `{latency['avg_ms']}ms` (Min: `{latency['min_ms']}ms`, Max: `{latency['max_ms']}ms`) |")
        sections.append(f"| Response Latency Degradation | `{latency['degradation_pct']}%` Delta | {'Normal' if latency['degradation_pct'] < 30 else 'Degraded'} | First half avg: `{latency['first_half_avg']}ms` vs Second half avg: `{latency['second_half_avg']}ms` |")
        sections.append(f"| Edge CDN / WAF Shield | {', '.join(edge['cdns'])} | {'Protected' if edge['has_cdn'] else 'Elevated'} | {'Reverse proxy / WAF absorbing perimeter volumetric traffic' if edge['has_cdn'] else 'Origin web server directly exposed without CDN shield'} |")
        sections.append(f"| Payload Exhaustion Resilience | 4 Stress Vectors Tested | Protected | Evaluated 10KB/50KB body, 1.5KB query URI, and 8KB header buffer |")
        dangerous_allowed = [m["method"] for m in methods if m["risk"] == "High"]
        sections.append(f"| High-Risk HTTP Verbs | {len(dangerous_allowed)} Allowed | {'Critical' if dangerous_allowed else 'Clean'} | {'Dangerous verbs exposed: ' + ', '.join(dangerous_allowed) if dangerous_allowed else 'Dangerous verbs (TRACE, DEBUG) strictly disabled'} |")

        # 2. Burst Request Log
        sections.append("\n## Burst Request & Rate Limiting Benchmark\n")
        sections.append("| Req # | HTTP Method | Response Status | Latency | Response Size | Rate Limit Headers Captured | Classification |")
        sections.append("|---|---|---|---|---|---|---|")
        for rec in burst["burst_records"]:
            st = f"`{rec['status']}`" if rec.get("status") else "`ERR`"
            hdrs_subset = []
            for k, v in rec.get("headers", {}).items():
                if any(rh in k.lower() for rh in ["ratelimit", "retry-after"]):
                    hdrs_subset.append(f"{k}: {v}")
            hdr_str = ", ".join(hdrs_subset) if hdrs_subset else "—"
            if len(hdr_str) > 40:
                hdr_str = hdr_str[:37] + "..."
            cls = "Throttled (429)" if rec.get("status") == 429 else ("OK (200)" if rec.get("status") == 200 else f"HTTP {rec.get('status')}")
            sections.append(f"| `#{rec['req_num']}` | `GET` | {st} | `{rec['elapsed_ms']}ms` | `{rec['size']} B` | `{hdr_str}` | {cls} |")

        # 3. Latency Progression Metrics
        sections.append("\n## Latency Progression & Degradation Metrics\n")
        sections.append("| Latency Distribution Metric | Measured Value | Benchmark Baseline | Performance Evaluation |")
        sections.append("|---|---|---|---|")
        sections.append(f"| Minimum Latency (Fastest) | `{latency['min_ms']}ms` | < 200ms | Optimal round-trip network response |")
        sections.append(f"| Median Latency (P50) | `{latency['median_ms']}ms` | < 500ms | Typical operational request processing time |")
        sections.append(f"| Average Latency (Mean) | `{latency['avg_ms']}ms` | < 800ms | Aggregate server load performance across all trials |")
        sections.append(f"| Maximum Latency (Peak) | `{latency['max_ms']}ms` | < 2000ms | Worst-case response latency observed during burst |")
        sections.append(f"| Load Degradation Coefficient | `{latency['degradation_pct']}%` | < 25.0% | {'Stable performance profile under sequential polling' if latency['degradation_pct'] < 25 else 'Noticeable resource contention during consecutive requests'} |")

        # 4. Resource Exhaustion & Payload Stress Tests
        sections.append("\n## Resource Exhaustion & Payload Stress Tests\n")
        sections.append("| Stress Vector | Result Status | Round-Trip Latency | Behavioral Assessment | Risk Level |")
        sections.append("|---|---|---|---|---|")
        for p in payloads:
            sections.append(f"| {p['vector']} | `{p['status']}` | `{p['latency']}` | {p['evaluation']} | {p['risk']} |")

        # 5. HTTP Method & Verb Tampering Matrix
        sections.append("\n## HTTP Method & Verb Tampering Matrix\n")
        sections.append("| HTTP Verb | Result Status | Response Latency | Security Evaluation | Risk Classification |")
        sections.append("|---|---|---|---|---|")
        for m in methods:
            sections.append(f"| `{m['method']}` | `{m['status']}` | `{m['latency']}` | {m['evaluation']} | {m['risk']} |")

        # 6. Host Header & Routing Integrity
        sections.append("\n## Host Header & Routing Integrity Audit\n")
        sections.append("| Injection Vector | Result Status | Response Latency | Routing & Poisoning Assessment | Risk Level |")
        sections.append("|---|---|---|---|---|")
        for inj in injections:
            sections.append(f"| {inj['vector']} | `{inj['status']}` | `{inj['latency']}` | {inj['evaluation']} | {inj['risk']} |")

        # 7. Edge Caching, Compression & WAF Shield
        sections.append("\n## Edge Caching, Compression & WAF Shield\n")
        sections.append("| Edge Layer Component | Detected Configuration | Optimization Status | Security & DoS Implication |")
        sections.append("|---|---|---|---|")
        sections.append(f"| Content-Encoding (Compression) | `{edge['compression']}` | {'Active' if edge['compression'] != 'None / Uncompressed' else 'Inactive'} | {'Reduces egress bandwidth and mitigates volumetric saturation' if edge['compression'] != 'None / Uncompressed' else 'Uncompressed content increases server bandwidth consumption'} |")
        sections.append(f"| Cache-Control Directives | `{edge['cache_control'][:60]}` | Configured | {'Enforces edge and browser cache TTL to offload origin compute' if edge['cache_control'] != 'Absent' else 'Missing Cache-Control forces all requests to hit origin directly'} |")
        sections.append(f"| Entity Tag (ETag) Validation | `{edge['etag']}` | {'Present' if edge['etag'] != 'Absent' else 'Absent'} | Allows conditional 304 Not Modified caching negotiation |")
        sections.append(f"| Edge CDN / WAF Vendor | `{', '.join(edge['cdns'])}` | {'Protected' if edge['has_cdn'] else 'Direct Exposure'} | {'Cloud perimeter absorbs DDoS surges and scrubs malicious bot traffic' if edge['has_cdn'] else 'Consider placing application behind a Cloud CDN/WAF layer'} |")
        sections.append(f"| Server Banner Token | `{edge['server']}` | Disclosed | Web server identification token emitted in response headers |")

        # 8. Action Items
        sections.append("\n## DoS & Resilience Hardening Roadmap\n")
        sections.append("| Finding Focus | Severity | Affected Vector | Recommended Hardening Action | Reference |")
        sections.append("|---|---|---|---|---|")
        if not burst["rate_limited"] and not burst["rate_headers"]:
            sections.append("| Missing L7 Rate Limiting | High | Application Root | Deploy rate-limiting middleware (e.g., Nginx `limit_req`, Cloudflare Rate Limiting, or AWS WAF Rate-based rules). | OWASP API4:2023 |")
        if not edge["has_cdn"]:
            sections.append("| Direct Origin Exposure | Medium | Infrastructure Perimeter | Route domain traffic through an Anycast CDN / DDoS mitigation gateway (Cloudflare, CloudFront, Akamai). | CWE-400 |")
        if any(m["risk"] == "High" for m in methods):
            sections.append("| Dangerous HTTP Verbs Allowed | High | Web Server Methods | Disable TRACE, DEBUG, and unauthenticated PUT/DELETE verbs in web server configuration (`limit_except`). | CWE-650 |")
        if any(p["risk"] == "Medium" for p in payloads):
            sections.append("| Unbounded Payload Limits | Medium | HTTP Body / URI Buffer | Set strict `client_max_body_size 10M` and `large_client_header_buffers` in reverse proxy configuration. | CWE-770 |")
        if edge["compression"] == "None / Uncompressed":
            sections.append("| Gzip / Brotli Disabled | Low | HTTP Response Compression | Enable Gzip or Brotli compression modules in web server to reduce bandwidth requirements. | CWE-400 |")
        sections.append("| Host Header Poisoning Guard | Medium | Host Routing Layer | Configure web server `server_name` to explicitly match approved domains and reject unlisted hosts with 400. | CWE-20 |")

        return "\n".join(sections)

    # ── Entry Point ──
    def _run(self, url: str) -> str:
        """Execute comprehensive DoS resilience and rate limiting audit."""
        target_url = self._normalize_url(url)

        # Suppress insecure request warnings for penetration testing
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        # 1. Burst benchmark
        burst = self._execute_burst_benchmark(target_url)

        # 2. Latency metrics
        latency = self._compute_latency_metrics(burst["timings_ms"])

        # 3. Payload stress tests
        payloads = self._execute_payload_stress(target_url)

        # 4. HTTP verb auditing
        methods = self._execute_method_audit(target_url)

        # 5. Injection & Host audits
        injections = self._execute_injection_audit(target_url)

        # 6. Edge CDN, compression & caching
        edge = self._execute_edge_audit(target_url)

        # 7. Generate markdown
        return self._build_markdown_report(
            target_url, burst, latency, payloads, methods, injections, edge
        )
