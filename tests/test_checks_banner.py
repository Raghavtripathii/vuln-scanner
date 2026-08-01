from scanner.checks.banner import check_server_banners


class FakeResponse:
    def __init__(self, headers):
        self.headers = headers


def test_flags_disclosed_server_header():
    resp = FakeResponse({"Server": "nginx/1.18.0"})
    findings = check_server_banners(resp)
    assert len(findings) == 1
    assert findings[0]["value"] == "nginx/1.18.0"


def test_no_findings_when_no_banner_headers_present():
    resp = FakeResponse({})
    findings = check_server_banners(resp)
    assert findings == []