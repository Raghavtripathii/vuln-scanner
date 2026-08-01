# VulnScan — A Lightweight Python Web Vulnerability Scanner

A CLI security scanner I built from scratch in Python, targeting the same class of
checks tools like Nikto and Nessus perform — missing security headers, reflected XSS,
exposed sensitive paths, TLS certificate issues, and server banner disclosure.

This exists to demonstrate the ability to *build* a security tool, not just run one.
Anyone can screenshot a Nessus scan output; very few beginners write the scanning logic
themselves, understand exactly what each check is looking for, and back it with
automated tests.

## Why this project

Most beginner security portfolios show output from an existing scanner run against a
known target. This project instead shows the actual implementation: five independent
check modules, a shared HTTP client, three output formats, and a real automated test
suite — all written and understood at the code level, not just operated.

## What it checks

| Check | What it looks for | Maps to |
|---|---|---|
| Missing Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | OWASP Secure Headers Project |
| Reflected XSS Probing | Unescaped reflection of a unique test payload across common query parameters | OWASP Top 10 — A03:2021 Injection |
| Exposed Sensitive Paths | `.git/`, `.env`, `/admin`, backup files, and other commonly-forgotten exposed paths | OWASP Top 10 — A05:2021 Security Misconfiguration |
| robots.txt Disclosure | Parses `Disallow` entries that reveal hidden application structure | Information Disclosure |
| TLS Certificate & Cipher | Certificate expiry, and detection of known-weak negotiated ciphers | OWASP Top 10 — A02:2021 Cryptographic Failures |
| Server Banner Disclosure | `Server`, `X-Powered-By`, and similar version-revealing headers | Information Disclosure |

## Tech Stack

Python 3, `requests`, `cryptography` (for correct TLS certificate parsing regardless of
validity), `colorama` (cross-platform colored terminal output), `pytest` (automated
test suite), `argparse` (CLI interface).

## A real safeguard, not just a README warning

The tool itself will not run a scan without an explicit authorization confirmation:

```
================================================================
  WARNING: Only scan targets you own or have explicit, written
  permission to test. Scanning systems without authorization is
  illegal in most jurisdictions (e.g., the Computer Fraud and
  Abuse Act in the US, or the Computer Misuse Act in the UK).
================================================================
Do you own or have explicit permission to scan 'target'? [y/N]:
```

This is enforced in code (`cli.py`), not just written guidance — the scan simply does
not proceed without confirmation (or the explicit `--yes` flag for automation/re-runs
against a target already confirmed).

## Automated Tests

7 pytest tests across the headers, banner, and exposure checks, using lightweight fake
response objects so tests run instantly with no real network calls:

```
collected 7 items
tests/test_checks_banner.py::test_flags_disclosed_server_header PASSED
tests/test_checks_banner.py::test_no_findings_when_no_banner_headers_present PASSED
tests/test_checks_exposure.py::test_extracts_disallowed_paths_from_robots_txt PASSED
tests/test_checks_exposure.py::test_no_findings_when_robots_txt_missing PASSED
tests/test_checks_headers.py::test_flags_all_missing_headers_when_none_present PASSED
tests/test_checks_headers.py::test_no_findings_when_all_headers_present PASSED
tests/test_checks_headers.py::test_returns_empty_list_when_response_is_none PASSED
7 passed in 0.02s
```

## Example Scans (Real, Authorized Targets)

Two real scans are included in [`reports/`](./reports), both against explicitly
authorized targets:

- **[Vault Notes](./reports/vault-notes-scan.json)** ([HTML](./reports/vault-notes-scan.html))
  — my own deployed application from a separate project
  ([vault-notes-vapt](https://github.com/Raghavtripathii/vault-notes-vapt)) — 7 findings
- **[OWASP Juice Shop](./reports/juice-shop-scan.json)** ([HTML](./reports/juice-shop-scan.html))
  — OWASP's own public demo instance, explicitly built and hosted for security testing
  practice — 7 findings

Sample terminal output from the Vault Notes scan:
```
VulnScan Report - https://vault-notes-frontend-gules.vercel.app
Scanned at: 2026-08-01T13:58:04.205248+00:00
Total findings: 7

[Medium] Missing Security Header
    header: Content-Security-Policy
    description: Missing CSP allows a broader range of injection attacks (XSS, data injection) to succeed unmitigated.
...
JSON report written to reports/vault-notes-scan.json
HTML report written to reports/vault-notes-scan.html
```

## Running It Locally

```bash
git clone https://github.com/Raghavtripathii/vuln-scanner.git
cd vuln-scanner
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt

python cli.py https://your-authorized-target.com --json reports/scan.json --html reports/scan.html
```

Run the test suite:
```bash
pytest -v
```

> ⚠️ **Only scan targets you own or have explicit written permission to test.** This
> tool includes a runtime confirmation gate for exactly this reason — use it
> responsibly. Good authorized practice targets: your own deployed apps, OWASP Juice
> Shop, DVWA, or PortSwigger's Web Security Academy labs.

## Honest Limitations

- The XSS check only probes GET query parameters on the homepage — it doesn't crawl
  the site or test POST forms.
- The exposed-paths check tests a fixed list of common paths — it isn't a full
  directory brute-forcer/fuzzer.
- No CVE-matching or version-vulnerability database lookup — the banner check flags
  *disclosure* of version info, not specific known vulnerabilities in that version.
- Tests currently cover 3 of the 5 check modules (headers, banner, exposure). The XSS
  and TLS checks are covered by real-world runs against authorized targets, but not
  yet by unit tests.

## Possible Extensions

- Add tests for the XSS and TLS check modules
- Cookie security attribute checks (`Secure`, `HttpOnly`, `SameSite`)
- A `--verbose` flag and configurable custom path/parameter lists via a config file

## Author

**Raghvendra Tripathi**
[github.com/Raghavtripathii](https://github.com/Raghavtripathii)