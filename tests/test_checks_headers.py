from scanner.checks.headers import check_security_headers, SECURITY_HEADERS


class FakeResponse:
    """A minimal stand-in for a real requests.Response object, just
    enough for this check to work with — this is what lets us test
    the check's logic without making any real network calls."""
    def __init__(self, headers):
        self.headers = headers


def test_flags_all_missing_headers_when_none_present():
    resp = FakeResponse({})
    findings = check_security_headers(resp)
    assert len(findings) == len(SECURITY_HEADERS)


def test_no_findings_when_all_headers_present():
    resp = FakeResponse({
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=63072000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    })
    findings = check_security_headers(resp)
    assert findings == []


def test_returns_empty_list_when_response_is_none():
    findings = check_security_headers(None)
    assert findings == []