import requests

DEFAULT_TIMEOUT = 8
DEFAULT_HEADERS = {
    "User-Agent": "VulnScan/1.0 (Educational security scanner - authorized use only)"
}


class HttpClient:

    def __init__(self, base_url, timeout=DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def get(self, path="", params=None):
        url = f"{self.base_url}{path}"
        try:
            return self.session.get(
                url, params=params, timeout=self.timeout, allow_redirects=True
            )
        except requests.exceptions.RequestException:
            return None