from scanner.checks.exposure import check_robots_txt


class FakeResponse:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class FakeClient:
    """Stands in for HttpClient so we can control exactly what response
    comes back, without a real network call."""
    def __init__(self, response):
        self._response = response

    def get(self, path="", params=None):
        return self._response


def test_extracts_disallowed_paths_from_robots_txt():
    fake_text = "User-agent: *\nDisallow: /admin\nDisallow: /internal-api"
    client = FakeClient(FakeResponse(200, fake_text))
    findings = check_robots_txt(client)
    assert len(findings) == 1
    assert "/admin" in findings[0]["disallowed_paths"]
    assert "/internal-api" in findings[0]["disallowed_paths"]


def test_no_findings_when_robots_txt_missing():
    client = FakeClient(FakeResponse(404))
    findings = check_robots_txt(client)
    assert findings == []