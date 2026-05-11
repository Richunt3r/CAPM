# Context-Aware Payload Mutator (CAPM)

A red team tool that **analyzes HTTP response context** and generates intelligent, context-specific payloads — instead of spraying generic wordlists.

---

## What Makes This Different

Most fuzzing tools send static payloads blindly. **CAPM**:
1. Sends a probe string to the target
2. Analyzes exactly WHERE it's reflected (HTML tag, JS string, JSON, SQL error, etc.)
3. Generates payloads **specific to that context**
4. Detects WAFs and automatically adds bypass variants

---

## Features

- **13 context types detected**: HTML tags, JS strings (single/double/template), JSON, XML, CSS, SQL, URL params, HTML comments
- **WAF detection**: Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, F5, Barracuda, Sucuri, Nginx
- **Auto WAF bypass payloads**: Case mutation, null bytes, comment insertion, hex/URL/base64 encoding
- **Vulnerability coverage**: XSS, SQLi, XXE, LFI, SSRF, Open Redirect
- **Export options**: Terminal output, JSON, Markdown report, raw payload list (for ffuf/Burp import)
- **Proxy support**: Route through Burp Suite

---

## Installation

```bash
pip install requests colorama
```

---

## Usage

### Basic scan (GET)
```bash
python3 mutator.py -u "http://target.com/search?q=test" -p q
```

### POST parameter
```bash
python3 mutator.py -u "http://target.com/login" -p username -m POST
```

### Through Burp Suite proxy
```bash
python3 mutator.py -u "http://target.com/page?input=x" -p input --proxy http://127.0.0.1:8080
```

### JSON output (pipe to jq)
```bash
python3 mutator.py -u "http://target.com/?s=x" -p s --output json | jq '.payloads[].payload'
```

### Save payload list + markdown report
```bash
python3 mutator.py -u "http://target.com/?q=x" -p q \
  --save-payloads payloads.txt \
  --export-report report.md
```

### Custom headers (e.g., authenticated session)
```bash
python3 mutator.py -u "http://target.com/api?q=x" -p q \
  --header "Authorization: Bearer TOKEN" \
  --header "Cookie: session=abc123"
```

---

## Arguments

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-p` | Parameter to test |
| `-m` | HTTP method: GET or POST (default: GET) |
| `--proxy` | Proxy URL (e.g. http://127.0.0.1:8080) |
| `--delay` | Seconds between requests (default: 0.5) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--header` | Custom header K:V (repeatable) |
| `--output` | terminal or json |
| `--save-payloads` | Save raw payload list to file |
| `--export-report` | Export markdown report to file |

---

## Workflow Integration

Payloads saved with `--save-payloads` can be imported directly into:
- **ffuf**: `ffuf -w payloads.txt -u http://target.com/?q=FUZZ`
- **Burp Intruder**: Load as payload list
- **sqlmap**: Use as custom tamper input

---

## Legal

For authorized penetration testing only. Always obtain written permission before testing.
