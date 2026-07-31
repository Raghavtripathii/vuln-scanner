from urllib.parse import urlparse

from .http_client import HttpClient
from .checks import headers as headers_check
from .checks import banner as banner_check
from .checks import xss as xss_check
from .checks import exposure as exposure_check
from .checks import tls as tls_check


def run_scan(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    client = HttpClient(target_url)
    root_response = client.get("/")

    all_findings = []
    all_findings += headers_check.check_security_headers(root_response)
    all_findings += banner_check.check_server_banners(root_response)
    all_findings += xss_check.check_reflected_xss(client)
    all_findings += exposure_check.check_exposed_paths(client)
    all_findings += exposure_check.check_robots_txt(client)

    if parsed.scheme == "https":
        all_findings += tls_check.check_tls(hostname, port)

    return {
        "target": target_url,
        "findings": all_findings,
    }