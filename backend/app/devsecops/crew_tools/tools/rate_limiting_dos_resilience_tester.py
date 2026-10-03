
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
from typing import Type, List, Dict, Any
import requests
import time
import json


class RateLimitingDoSResilienceTesterInput(BaseModel):
    """Input schema for Rate Limiting and DoS Resilience Tester Tool."""
    url: str = Field(..., description="The target URL to test for rate limiting and DoS resilience.")


class RateLimitingDoSResilienceTesterTool(BaseTool):
    """Tool for testing rate limiting and DoS resilience of a given URL."""

    name: str = "Rate Limiting and DoS Resilience Tester"
    description: str = (
        "Tests a URL for rate limiting enforcement, DoS resilience, large payload handling, "
        "HTTP method exposure, header injection behavior, and compression/caching/CDN presence. "
        "Runs all tests sequentially with ethical delays and returns a full security report."
    )
    args_schema: Type[BaseModel] = RateLimitingDoSResilienceTesterInput

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _safe_get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Perform a GET request and return a normalised result dict."""
        start = time.time()
        try:
            resp = requests.get(url, timeout=10, allow_redirects=True, **kwargs)
            elapsed = (time.time() - start) * 1000  # ms
            return {
                "ok": True,
                "status": resp.status_code,
                "elapsed_ms": round(elapsed, 2),
                "headers": dict(resp.headers),
            }
        except requests.exceptions.Timeout:
            return {"ok": False, "error": "Timeout", "elapsed_ms": 10000}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "elapsed_ms": 0}

    def _safe_request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        """Generic request helper for arbitrary HTTP methods."""
        start = time.time()
        try:
            resp = requests.request(method, url, timeout=10, allow_redirects=False, **kwargs)
            elapsed = (time.time() - start) * 1000
            return {
                "ok": True,
                "status": resp.status_code,
                "elapsed_ms": round(elapsed, 2),
                "headers": dict(resp.headers),
            }
        except requests.exceptions.Timeout:
            return {"ok": False, "error": "Timeout", "elapsed_ms": 10000}
        except Exception as exc:
            return {"ok": False, "error": str(exc), "elapsed_ms": 0}

    # ------------------------------------------------------------------ #
    #  Section A – Rate Limiting Detection                                 #
    # ------------------------------------------------------------------ #

    def _test_rate_limiting(self, url: str) -> Dict[str, Any]:
        results = []
        rate_limit_headers_seen = {}
        rate_limited_at = None
        error_after = None

        RATE_LIMIT_HEADER_KEYS = [
            "Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining",
            "X-RateLimit-Reset", "RateLimit-Limit", "RateLimit-Remaining",
            "RateLimit-Reset", "X-Rate-Limit-Limit", "X-Rate-Limit-Remaining",
        ]

        for i in range(1, 21):
            result = self._safe_get(url)
            result["request_num"] = i
            results.append(result)

            if result.get("ok"):
                status = result["status"]
                hdrs = result.get("headers", {})

                # Collect rate-limit headers (case-insensitive match)
                hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
                for rh in RATE_LIMIT_HEADER_KEYS:
                    val = hdrs_lower.get(rh.lower())
                    if val and rh not in rate_limit_headers_seen:
                        rate_limit_headers_seen[rh] = val

                if status == 429 and rate_limited_at is None:
                    rate_limited_at = i
                if status >= 500 and error_after is None:
                    error_after = i

            time.sleep(0.1)

        statuses = [r["status"] for r in results if r.get("ok")]
        return {
            "total_requests": 20,
            "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
            "rate_limit_detected": rate_limited_at is not None,
            "rate_limited_at_request": rate_limited_at,
            "server_error_after_request": error_after,
            "rate_limit_headers_found": rate_limit_headers_seen,
            "raw_timings_ms": [r.get("elapsed_ms", 0) for r in results],
        }

    # ------------------------------------------------------------------ #
    #  Section B – Response Time Analysis                                  #
    # ------------------------------------------------------------------ #

    def _analyse_response_times(self, timings: List[float]) -> Dict[str, Any]:
        if not timings:
            return {"error": "No timings available"}

        avg = sum(timings) / len(timings)
        mn = min(timings)
        mx = max(timings)

        # Degradation: compare first-half avg vs second-half avg
        mid = len(timings) // 2
        first_half_avg = sum(timings[:mid]) / mid if mid else avg
        second_half_avg = sum(timings[mid:]) / (len(timings) - mid) if (len(timings) - mid) else avg
        degradation_pct = ((second_half_avg - first_half_avg) / first_half_avg * 100) if first_half_avg else 0

        flags = []
        if avg > 2000:
            flags.append(f"SLOW SERVER: average response time {round(avg, 1)}ms > 2000ms — elevated DoS risk")
        if degradation_pct > 30:
            flags.append(
                f"PERFORMANCE DEGRADATION: response times increased ~{round(degradation_pct, 1)}% "
                "over the request sequence — server may be degrading under load"
            )

        return {
            "min_ms": round(mn, 2),
            "max_ms": round(mx, 2),
            "avg_ms": round(avg, 2),
            "first_half_avg_ms": round(first_half_avg, 2),
            "second_half_avg_ms": round(second_half_avg, 2),
            "degradation_pct": round(degradation_pct, 2),
            "flags": flags,
        }

    # ------------------------------------------------------------------ #
    #  Section C – Large Payload Test                                      #
    # ------------------------------------------------------------------ #

    def _test_large_payload(self, url: str) -> Dict[str, Any]:
        findings = []

        # POST with 10 KB body
        large_body = "A" * 10240
        post_result = self._safe_request("POST", url, data=large_body,
                                         headers={"Content-Type": "text/plain"})
        post_status = post_result.get("status") if post_result.get("ok") else post_result.get("error")
        if post_result.get("ok") and post_result["status"] not in (400, 413, 414, 415, 422, 429, 431):
            findings.append(
                f"MISSING REQUEST SIZE LIMIT: server accepted 10KB POST body without error "
                f"(HTTP {post_result['status']})"
            )

        # GET with very long query parameter (1000 chars)
        long_param = "B" * 1000
        long_url = f"{url}{'&' if '?' in url else '?'}test={long_param}"
        get_result = self._safe_get(long_url)
        get_status = get_result.get("status") if get_result.get("ok") else get_result.get("error")
        if get_result.get("ok") and get_result["status"] not in (400, 414):
            findings.append(
                f"LONG URL ACCEPTED: server accepted 1000-char query param without 414/400 "
                f"(HTTP {get_result['status']})"
            )

        return {
            "post_10kb_status": post_status,
            "get_long_param_status": get_status,
            "findings": findings,
        }

    # ------------------------------------------------------------------ #
    #  Section D – HTTP Method Testing                                     #
    # ------------------------------------------------------------------ #

    def _test_http_methods(self, url: str) -> Dict[str, Any]:
        methods_to_test = ["OPTIONS", "HEAD", "PUT", "DELETE", "PATCH", "TRACE"]
        dangerous_methods = {"PUT", "DELETE", "TRACE"}
        results = {}
        allowed_methods = []
        dangerous_allowed = []

        for method in methods_to_test:
            r = self._safe_request(method, url)
            status = r.get("status") if r.get("ok") else r.get("error")
            results[method] = status

            # A response that isn't 405/501 typically means the method is accepted
            if r.get("ok") and r["status"] not in (405, 501, 502, 503):
                allowed_methods.append(method)
                if method in dangerous_methods:
                    dangerous_allowed.append(method)

            # Also parse Allow header from OPTIONS
            if method == "OPTIONS" and r.get("ok"):
                allow_hdr = r.get("headers", {}).get("Allow", "")
                if allow_hdr:
                    for m in dangerous_methods:
                        if m in allow_hdr and m not in dangerous_allowed:
                            dangerous_allowed.append(m)

            time.sleep(0.1)

        flags = []
        for dm in dangerous_allowed:
            tips = {
                "PUT": "PUT allowed — attackers may upload arbitrary files",
                "DELETE": "DELETE allowed — attackers may delete resources",
                "TRACE": "TRACE allowed — Cross-Site Tracing (XST) attack vector",
            }
            flags.append(tips.get(dm, f"{dm} allowed — review necessity"))

        return {
            "method_status_codes": results,
            "apparently_allowed": allowed_methods,
            "dangerous_methods_allowed": dangerous_allowed,
            "flags": flags,
        }

    # ------------------------------------------------------------------ #
    #  Section E – Header Injection Test                                   #
    # ------------------------------------------------------------------ #

    def _test_header_injection(self, url: str) -> Dict[str, Any]:
        findings = []

        # Oversized header value (8 KB)
        big_header_val = "X" * 8192
        r1 = self._safe_request("GET", url, headers={"X-Custom-Test": big_header_val})
        status_big = r1.get("status") if r1.get("ok") else r1.get("error")
        if r1.get("ok") and r1["status"] not in (400, 413, 431):
            findings.append(
                f"OVERSIZED HEADER ACCEPTED: server did not reject 8KB header value "
                f"(HTTP {r1['status']}) — potential header-based DoS vector"
            )

        # Host header injection
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            original_host = parsed.netloc or parsed.path
        except Exception:
            original_host = "target.com"

        r2 = self._safe_request("GET", url, headers={"Host": "evil-injected-host.com"})
        status_host = r2.get("status") if r2.get("ok") else r2.get("error")
        if r2.get("ok") and r2["status"] == 200:
            findings.append(
                "HOST HEADER INJECTION: server returned 200 with a spoofed Host header — "
                "may be vulnerable to cache poisoning or password-reset poisoning"
            )

        return {
            "oversized_header_status": status_big,
            "host_injection_status": status_host,
            "findings": findings,
        }

    # ------------------------------------------------------------------ #
    #  Section F – Compression, Caching, and CDN/WAF Detection            #
    # ------------------------------------------------------------------ #

    def _test_compression_caching_cdn(self, url: str) -> Dict[str, Any]:
        r = self._safe_request(
            "GET", url,
            headers={"Accept-Encoding": "gzip, deflate, br"},
        )
        findings = []
        details = {}

        if not r.get("ok"):
            return {"error": r.get("error"), "findings": []}

        hdrs = {k.lower(): v for k, v in r.get("headers", {}).items()}

        # Compression
        encoding = hdrs.get("content-encoding", "")
        details["compression"] = encoding if encoding else "none"
        if not encoding:
            findings.append(
                "NO COMPRESSION: server does not use gzip/brotli — "
                "increases bandwidth and reduces DoS resilience"
            )

        # Cache-Control
        cache_control = hdrs.get("cache-control", "")
        details["cache_control"] = cache_control if cache_control else "absent"
        if not cache_control:
            findings.append(
                "MISSING Cache-Control: no caching policy found — "
                "every request hits the origin server, increasing load"
            )
        elif "no-store" in cache_control or "no-cache" in cache_control:
            findings.append(
                "CACHING DISABLED (no-store/no-cache): all requests bypass cache — "
                "consider enabling caching for static resources"
            )

        # CDN / WAF fingerprinting
        cdn_waf_indicators = {
            "cloudflare": ["cf-ray", "cf-cache-status", "server:cloudflare"],
            "akamai": ["x-check-cacheable", "akamai-cache-status", "x-akamai-request-id"],
            "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "via:cloudfront"],
            "fastly": ["x-served-by", "x-cache:hit from fastly"],
            "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        }
        detected_cdn = []
        all_header_str = " ".join(f"{k}:{v}" for k, v in hdrs.items()).lower()
        for cdn, signals in cdn_waf_indicators.items():
            for sig in signals:
                if sig in all_header_str:
                    detected_cdn.append(cdn.upper().replace("_", " "))
                    break

        details["cdn_waf_detected"] = detected_cdn if detected_cdn else ["None detected"]
        if not detected_cdn:
            findings.append(
                "NO CDN/WAF DETECTED: origin server appears to be directly exposed — "
                "consider adding a CDN or WAF for DoS/DDoS protection"
            )

        return {"details": details, "findings": findings}

    # ------------------------------------------------------------------ #
    #  Recommendations engine                                              #
    # ------------------------------------------------------------------ #

    def _build_recommendations(
        self, rate: dict, timing: dict, payload: dict,
        methods: dict, headers_inj: dict, compression: dict
    ) -> List[str]:
        recs = []

        if not rate.get("rate_limit_detected") and not rate.get("rate_limit_headers_found"):
            recs.append("🔴 Implement rate limiting (e.g., nginx limit_req, API Gateway throttling, or a WAF rule) to prevent brute-force and DoS attacks.")

        if timing.get("flags"):
            recs.append("🟠 Investigate server capacity. Consider horizontal scaling, load balancers, or caching layers to reduce average response times.")

        if payload.get("findings"):
            recs.append("🔴 Enforce request size limits: set `client_max_body_size` (nginx) or equivalent, and reject oversized query strings with a 414 response.")

        if methods.get("dangerous_methods_allowed"):
            recs.append(f"🔴 Disable dangerous HTTP methods: {', '.join(methods['dangerous_methods_allowed'])}. Use `LimitExcept` (Apache) or `limit_except` (nginx) directives.")

        if headers_inj.get("findings"):
            recs.append("🟠 Configure your server/proxy to validate and restrict the Host header and reject oversized headers (e.g., `large_client_header_buffers` in nginx).")

        for f in compression.get("findings", []):
            if "COMPRESSION" in f:
                recs.append("🟡 Enable gzip/brotli compression to reduce bandwidth consumption and improve resilience under load.")
            if "Cache-Control" in f or "CACHING" in f:
                recs.append("🟡 Set appropriate Cache-Control headers for static assets to offload repeated requests from the origin server.")
            if "CDN/WAF" in f:
                recs.append("🟠 Deploy a CDN (Cloudflare, AWS CloudFront, Akamai) or WAF to absorb volumetric attacks before they reach your origin.")

        if not recs:
            recs.append("✅ No critical issues detected. Continue monitoring and review rate limit thresholds periodically.")

        return recs

    # ------------------------------------------------------------------ #
    #  Main _run                                                           #
    # ------------------------------------------------------------------ #

    def _run(self, url: str) -> str:
        report_lines = [
            "=" * 70,
            "  RATE LIMITING & DoS RESILIENCE TESTER — SECURITY REPORT",
            "=" * 70,
            f"  Target URL : {url}",
            f"  Timestamp  : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}",
            "=" * 70,
        ]

        # ── A: Rate Limiting ──────────────────────────────────────────── #
        report_lines.append("\n[A] RATE LIMITING DETECTION (20 sequential GET requests)")
        report_lines.append("-" * 60)
        try:
            rate = self._test_rate_limiting(url)
            report_lines.append(f"  Status distribution       : {rate['status_distribution']}")
            report_lines.append(f"  Rate limiting detected    : {'YES ✅' if rate['rate_limit_detected'] else 'NO ❌'}")
            if rate["rate_limited_at_request"]:
                report_lines.append(f"  Rate-limited at request # : {rate['rate_limited_at_request']}")
            if rate["server_error_after_request"]:
                report_lines.append(f"  Server errors started at  : request #{rate['server_error_after_request']}")
            if rate["rate_limit_headers_found"]:
                report_lines.append(f"  Rate-limit headers found  :")
                for h, v in rate["rate_limit_headers_found"].items():
                    report_lines.append(f"    {h}: {v}")
            else:
                report_lines.append("  Rate-limit headers found  : None ❌")
        except Exception as exc:
            rate = {"rate_limit_detected": False, "rate_limit_headers_found": {}, "raw_timings_ms": []}
            report_lines.append(f"  ERROR running rate limit test: {exc}")

        # ── B: Response Time Analysis ─────────────────────────────────── #
        report_lines.append("\n[B] RESPONSE TIME ANALYSIS")
        report_lines.append("-" * 60)
        try:
            timings = rate.get("raw_timings_ms", [])
            timing = self._analyse_response_times(timings) if timings else {"error": "No data"}
            if "error" not in timing:
                report_lines.append(f"  Min response time  : {timing['min_ms']} ms")
                report_lines.append(f"  Max response time  : {timing['max_ms']} ms")
                report_lines.append(f"  Avg response time  : {timing['avg_ms']} ms")
                report_lines.append(f"  First-half avg     : {timing['first_half_avg_ms']} ms")
                report_lines.append(f"  Second-half avg    : {timing['second_half_avg_ms']} ms")
                report_lines.append(f"  Degradation        : {timing['degradation_pct']}%")
                if timing["flags"]:
                    for flag in timing["flags"]:
                        report_lines.append(f"  ⚠️  {flag}")
                else:
                    report_lines.append("  Response times appear stable ✅")
            else:
                report_lines.append(f"  {timing['error']}")
        except Exception as exc:
            timing = {"flags": []}
            report_lines.append(f"  ERROR: {exc}")

        # ── C: Large Payload ──────────────────────────────────────────── #
        report_lines.append("\n[C] LARGE PAYLOAD TEST")
        report_lines.append("-" * 60)
        try:
            payload = self._test_large_payload(url)
            report_lines.append(f"  POST 10KB body status      : {payload['post_10kb_status']}")
            report_lines.append(f"  GET long param (1000) stat : {payload['get_long_param_status']}")
            if payload["findings"]:
                for f in payload["findings"]:
                    report_lines.append(f"  ⚠️  {f}")
            else:
                report_lines.append("  Server correctly rejected oversized payloads ✅")
        except Exception as exc:
            payload = {"findings": []}
            report_lines.append(f"  ERROR: {exc}")

        # ── D: HTTP Method Testing ────────────────────────────────────── #
        report_lines.append("\n[D] HTTP METHOD TESTING")
        report_lines.append("-" * 60)
        try:
            methods = self._test_http_methods(url)
            for m, s in methods["method_status_codes"].items():
                report_lines.append(f"  {m:<10}: HTTP {s}")
            report_lines.append(f"  Apparently allowed : {', '.join(methods['apparently_allowed']) or 'None'}")
            if methods["dangerous_methods_allowed"]:
                report_lines.append(f"  ⚠️  DANGEROUS METHODS: {', '.join(methods['dangerous_methods_allowed'])}")
                for flag in methods["flags"]:
                    report_lines.append(f"      → {flag}")
            else:
                report_lines.append("  No dangerous methods detected ✅")
        except Exception as exc:
            methods = {"dangerous_methods_allowed": [], "flags": []}
            report_lines.append(f"  ERROR: {exc}")

        # ── E: Header Injection ───────────────────────────────────────── #
        report_lines.append("\n[E] HEADER INJECTION TEST")
        report_lines.append("-" * 60)
        try:
            headers_inj = self._test_header_injection(url)
            report_lines.append(f"  Oversized header (8KB) status  : {headers_inj['oversized_header_status']}")
            report_lines.append(f"  Host header injection status   : {headers_inj['host_injection_status']}")
            if headers_inj["findings"]:
                for f in headers_inj["findings"]:
                    report_lines.append(f"  ⚠️  {f}")
            else:
                report_lines.append("  No header injection issues detected ✅")
        except Exception as exc:
            headers_inj = {"findings": []}
            report_lines.append(f"  ERROR: {exc}")

        # ── F: Compression / Caching / CDN ────────────────────────────── #
        report_lines.append("\n[F] COMPRESSION, CACHING & CDN/WAF DETECTION")
        report_lines.append("-" * 60)
        try:
            compression = self._test_compression_caching_cdn(url)
            if "error" in compression:
                report_lines.append(f"  ERROR: {compression['error']}")
            else:
                d = compression.get("details", {})
                report_lines.append(f"  Content-Encoding (compression) : {d.get('compression', 'n/a')}")
                report_lines.append(f"  Cache-Control                  : {d.get('cache_control', 'n/a')}")
                report_lines.append(f"  CDN / WAF detected             : {', '.join(d.get('cdn_waf_detected', []))}")
                if compression["findings"]:
                    for f in compression["findings"]:
                        report_lines.append(f"  ⚠️  {f}")
                else:
                    report_lines.append("  Compression, caching, and CDN/WAF look good ✅")
        except Exception as exc:
            compression = {"findings": []}
            report_lines.append(f"  ERROR: {exc}")

        # ── Recommendations ───────────────────────────────────────────── #
        report_lines.append("\n[HARDENING RECOMMENDATIONS]")
        report_lines.append("-" * 60)
        try:
            recs = self._build_recommendations(rate, timing, payload, methods, headers_inj, compression)
            for i, rec in enumerate(recs, 1):
                report_lines.append(f"  {i}. {rec}")
        except Exception as exc:
            report_lines.append(f"  ERROR generating recommendations: {exc}")

        report_lines.append("\n" + "=" * 70)
        report_lines.append("  END OF REPORT")
        report_lines.append("=" * 70)

        return "\n".join(report_lines)
